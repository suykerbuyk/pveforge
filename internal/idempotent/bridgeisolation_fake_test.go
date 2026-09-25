package idempotent

import (
	"context"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// fakeBridgeClient is a scriptable BridgeIsolationClient, mirroring
// fakeClient's own "indexed by call number" shape for the VM-config calls,
// plus per-tap maps for the tap-specific calls (which BridgeIsolationEnsure
// addresses by tap name, not call order).
type fakeBridgeClient struct {
	node string

	// sshSetValues records every SetVMConfigFieldOverSSH value, in order.
	sshSetValues []string
	sshSetErr    error // returned by SetVMConfigFieldOverSSH

	getVMResults []*proxmox.VirtualMachine
	getVMErr     error
	getVMCalls   int

	setFieldCASErrs  []error
	setFieldCASCalls int
	lastCASField     string
	lastCASValue     string
	lastCASDigest    string

	setFieldErrs   []error
	setFieldCalls  int
	lastFieldValue string

	uploadSnippetErr    error
	uploadSnippetErrs   []error // by call number, before uploadSnippetErr
	uploadSnippetCalls  int
	lastSnippetStorage  string
	lastSnippetFilename string
	lastSnippetContent  string

	tapStates    map[string]sshexec.TapLinkState
	tapStateErrs map[string]error
	tapLinkCalls int

	setIsolatedErrs      map[string]error
	setIsolatedCalls     map[string]int
	lastIsolatedRequests map[string]bool
}

func (f *fakeBridgeClient) Node() string { return f.node }

func (f *fakeBridgeClient) GetVM(_ context.Context, _ string, _ int) (*proxmox.VirtualMachine, error) {
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

func (f *fakeBridgeClient) SetVMConfigFieldCAS(_ context.Context, _ int, field, value, expectDigest string) error {
	f.lastCASField = field
	f.lastCASValue = value
	f.lastCASDigest = expectDigest
	idx := f.setFieldCASCalls
	f.setFieldCASCalls++
	if idx < len(f.setFieldCASErrs) {
		return f.setFieldCASErrs[idx]
	}
	return nil
}

func (f *fakeBridgeClient) DeleteVMConfigFieldCAS(context.Context, int, string, string) error {
	return nil
}
func (f *fakeBridgeClient) DeleteVMConfigField(context.Context, int, string) error { return nil }
func (f *fakeBridgeClient) DeleteVMConfigFieldOverSSH(context.Context, int, string) error {
	return nil
}

// SetVMConfigFieldOverSSH records its value in sshSetValues: the SSH-only
// fallback is told apart from a plain (REST-first) SetVMConfigField.
func (f *fakeBridgeClient) SetVMConfigFieldOverSSH(_ context.Context, _ int, _, value string) error {
	f.sshSetValues = append(f.sshSetValues, value)
	return f.sshSetErr
}

func (f *fakeBridgeClient) SetVMConfigField(_ context.Context, _ int, _, value string) error {
	f.lastFieldValue = value
	idx := f.setFieldCalls
	f.setFieldCalls++
	if idx < len(f.setFieldErrs) {
		return f.setFieldErrs[idx]
	}
	return nil
}

func (f *fakeBridgeClient) UploadSnippet(_ context.Context, storageID, filename string, content []byte) error {
	idx := f.uploadSnippetCalls
	f.uploadSnippetCalls++
	f.lastSnippetStorage = storageID
	f.lastSnippetFilename = filename
	f.lastSnippetContent = string(content)
	if idx < len(f.uploadSnippetErrs) {
		return f.uploadSnippetErrs[idx]
	}
	return f.uploadSnippetErr
}

func (f *fakeBridgeClient) TapLinkState(_ context.Context, tap string) (sshexec.TapLinkState, error) {
	f.tapLinkCalls++
	if err, ok := f.tapStateErrs[tap]; ok {
		return sshexec.TapLinkState{}, err
	}
	if st, ok := f.tapStates[tap]; ok {
		return st, nil
	}
	return sshexec.TapLinkState{}, nil
}

func (f *fakeBridgeClient) SetBridgePortIsolated(_ context.Context, tap string, isolated bool) error {
	if f.setIsolatedCalls == nil {
		f.setIsolatedCalls = map[string]int{}
	}
	f.setIsolatedCalls[tap]++
	if f.lastIsolatedRequests == nil {
		f.lastIsolatedRequests = map[string]bool{}
	}
	f.lastIsolatedRequests[tap] = isolated
	if err, ok := f.setIsolatedErrs[tap]; ok {
		return err
	}
	return nil
}

func vmWithHookscript(hookscript, digest, status string) *proxmox.VirtualMachine {
	return &proxmox.VirtualMachine{
		Status:               status,
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{Hookscript: hookscript, Digest: digest},
	}
}
