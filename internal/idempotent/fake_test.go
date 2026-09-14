package idempotent

import (
	"context"
	"path/filepath"
	"testing"

	proxmox "github.com/luthermonson/go-proxmox"
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

func (f *fakeClient) SetVMConfigFieldCAS(_ context.Context, vmid int, field, value, expectDigest string) error {
	f.lastVMID = vmid
	f.lastField = field
	f.lastValue = value
	f.lastDigest = expectDigest
	idx := f.setFieldCalls
	f.setFieldCalls++
	if idx < len(f.setFieldErrs) {
		return f.setFieldErrs[idx]
	}
	return nil
}

func testRosterPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "roster.toml")
}
