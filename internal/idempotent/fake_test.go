package idempotent

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// fakeClient is a scriptable Client, shared by every Op's tests in this
// package — no network, no pve package dependency beyond the plain
// proxmox types it already needs to hold.
type fakeClient struct {
	node string

	// getVMResults is indexed by call number (0-based); a call beyond the
	// end repeats the last entry. Lets a test script "first read sees X,
	// second read (after a retry) sees Y".
	getVMResults []*proxmox.VirtualMachine
	getVMErr     error
	getVMCalls   int

	// setFieldErrs is indexed by call number the same way.
	setFieldErrs  []error
	setFieldCalls int
	lastVMID      int
	lastField     string
	lastValue     string
	lastDigest    string
	casCalls      []casCall

	// setFieldPlainErrs/setFieldPlainCalls track the unconditional
	// (non-CAS) SetVMConfigField — VMFieldsEnsure's own tests (unlike
	// VMTagEnsure's) exercise this, for root-only fields and the
	// PVE-rejects-as-root-only fallback.
	setFieldPlainErrs  []error
	setFieldPlainCalls int
	lastPlainField     string
	lastPlainValue     string

	// deletes records every delete in order: CAS ones with their digest,
	// plain (SSH-routed) ones with cas=false.
	deletes []deleteCall
	// sshSets records every SetVMConfigFieldOverSSH, in order.
	sshSets       []casCall
	deleteCASErrs []error
	deleteCASN    int
	deleteErrs    []error
	deleteN       int

	// rawRequestResults is indexed by call number the same way as
	// getVMResults — VMFieldsEnsure.readConfig calls RawRequest once per
	// Read and once more per REST-CAS field write in Apply (a fresh
	// digest for each), so a test scripting a multi-field batch scripts
	// one entry per expected call.
	rawRequestResults []json.RawMessage
	rawRequestErr     error
	rawRequestCalls   int
	lastRawMethod     string
	lastRawPath       string
	// rawCalls records every RawRequest in order: "METHOD path?query".
	rawCalls []string

	// pendingResults answers VMFieldsEnsure.PostApply's GET .../pending,
	// indexed by call like rawRequestResults, and apart from it: a pending
	// read neither consumes a config answer nor counts in rawRequestCalls.
	// Unscripted, it is "[]" — nothing pending — so a test that scripts only
	// config answers never hands PostApply a config object to reject.
	pendingResults []json.RawMessage
	pendingCalls   int
	// pendingErr fails the /pending read only (P3's no-op check).
	pendingErr error

	// cloudInitResults and cloudInitErr answer PostApply's GET .../cloudinit
	// (P2′) the same way, apart from both queues: unscripted it is "[]" —
	// nothing stale on the drive — and cloudInitErr fails only that read.
	cloudInitResults []json.RawMessage
	cloudInitErr     error
	cloudInitCalls   int
}

func (f *fakeClient) Node() string { return f.node }

func (f *fakeClient) GetVM(_ context.Context, _ string, _ int) (*proxmox.VirtualMachine, error) {
	idx := f.getVMCalls
	f.getVMCalls++
	if f.getVMErr != nil {
		return nil, f.getVMErr
	}
	if len(f.getVMResults) == 0 {
		return &proxmox.VirtualMachine{VirtualMachineConfig: &proxmox.VirtualMachineConfig{}}, nil
	}
	if idx >= len(f.getVMResults) {
		idx = len(f.getVMResults) - 1
	}
	return f.getVMResults[idx], nil
}

// casCall is one recorded SetVMConfigFieldCAS invocation — casCalls holds
// full history (not just the last, unlike lastField/lastValue/lastDigest
// above) so a test can prove what digest EACH of several field writes in
// one Apply used, not just the final one.
type casCall struct {
	field, value, digest string
}

func (f *fakeClient) SetVMConfigFieldCAS(_ context.Context, vmid int, field, value, expectDigest string) error {
	f.lastVMID = vmid
	f.lastField = field
	f.lastValue = value
	f.lastDigest = expectDigest
	f.casCalls = append(f.casCalls, casCall{field: field, value: value, digest: expectDigest})
	idx := f.setFieldCalls
	f.setFieldCalls++
	if idx < len(f.setFieldErrs) {
		return f.setFieldErrs[idx]
	}
	return nil
}

func (f *fakeClient) SetVMConfigField(_ context.Context, vmid int, field, value string) error {
	f.lastVMID = vmid
	f.lastPlainField = field
	f.lastPlainValue = value
	idx := f.setFieldPlainCalls
	f.setFieldPlainCalls++
	if idx < len(f.setFieldPlainErrs) {
		return f.setFieldPlainErrs[idx]
	}
	return nil
}

type deleteCall struct {
	field, digest string
	cas           bool
	overSSH       bool // DeleteVMConfigFieldOverSSH: SSH only, never REST
}

func (f *fakeClient) SetVMConfigFieldOverSSH(_ context.Context, vmid int, field, value string) error {
	f.lastVMID = vmid
	f.sshSets = append(f.sshSets, casCall{field: field, value: value})
	return nil
}

func (f *fakeClient) DeleteVMConfigFieldOverSSH(_ context.Context, vmid int, field string) error {
	f.lastVMID = vmid
	f.deletes = append(f.deletes, deleteCall{field: field, overSSH: true})
	return nil
}

func (f *fakeClient) DeleteVMConfigFieldCAS(_ context.Context, vmid int, field, expectDigest string) error {
	f.lastVMID = vmid
	f.deletes = append(f.deletes, deleteCall{field: field, digest: expectDigest, cas: true})
	idx := f.deleteCASN
	f.deleteCASN++
	if idx < len(f.deleteCASErrs) {
		return f.deleteCASErrs[idx]
	}
	return nil
}

func (f *fakeClient) DeleteVMConfigField(_ context.Context, vmid int, field string) error {
	f.lastVMID = vmid
	f.deletes = append(f.deletes, deleteCall{field: field})
	idx := f.deleteN
	f.deleteN++
	if idx < len(f.deleteErrs) {
		return f.deleteErrs[idx]
	}
	return nil
}

func (f *fakeClient) RawRequest(_ context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	f.lastRawMethod = method
	f.lastRawPath = path
	f.rawCalls = append(f.rawCalls, method+" "+path+"?"+params.Encode())
	if strings.HasSuffix(path, "/cloudinit") {
		idx := f.cloudInitCalls
		f.cloudInitCalls++
		if f.cloudInitErr != nil {
			return nil, f.cloudInitErr
		}
		if len(f.cloudInitResults) == 0 {
			return json.RawMessage(`[]`), nil
		}
		return f.cloudInitResults[min(idx, len(f.cloudInitResults)-1)], nil
	}
	if strings.HasSuffix(path, "/pending") {
		idx := f.pendingCalls
		f.pendingCalls++
		if f.rawRequestErr != nil {
			return nil, f.rawRequestErr
		}
		if f.pendingErr != nil {
			return nil, f.pendingErr
		}
		if len(f.pendingResults) == 0 {
			return json.RawMessage(`[]`), nil
		}
		return f.pendingResults[min(idx, len(f.pendingResults)-1)], nil
	}
	idx := f.rawRequestCalls
	f.rawRequestCalls++
	if f.rawRequestErr != nil {
		return nil, f.rawRequestErr
	}
	if len(f.rawRequestResults) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if idx >= len(f.rawRequestResults) {
		idx = len(f.rawRequestResults) - 1
	}
	return f.rawRequestResults[idx], nil
}

func testRosterPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "roster.toml")
}
