package idempotent

import (
	"context"
	"errors"
	"slices"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// BridgeIsolationEnsure's own writes, across a Run's attempts
// (pveforge-bridge-isolation-partial-write-changed): Applied accumulates what
// Apply wrote, the way VMFieldsEnsure.Applied does, so Wrote holds even when
// a conflict retry ends on the no-op path.

var errDigestConflict = errors.New("update rejected: digest mismatch")

func bridgeKey() lock.ObjectKey {
	return lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
}

// B1: attempt 1 uploads the snippet, then its hookscript CAS write hits a
// digest conflict; an outside writer set the hookscript, so attempt 2 finds
// the VM (stopped) as wanted and Run takes the no-op path. This Run still
// uploaded the snippet.
func TestBridgeIsolationEnsure_ConflictThenNoop_ReportsThisRunsWrites(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{
			vmWithHookscript("", "d1", "stopped"),                    // attempt 1's Read
			vmWithHookscript(op.wantedHookscript(), "d2", "stopped"), // attempt 2's Read: set by an outside writer
		},
		setFieldCASErrs: []error{errDigestConflict},
	}
	op.Client = client
	res, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false)
	if err != nil || res.Changed {
		t.Fatalf("Run = %+v, %v; want a clean no-op", res, err)
	}
	if !op.Wrote() || !slices.Equal(op.Applied, []string{"snippet"}) {
		t.Errorf("Wrote %t, Applied %q; want the snippet, uploaded on the superseded attempt", op.Wrote(), op.Applied)
	}
	if client.uploadSnippetCalls != 1 || client.setFieldCASCalls != 1 || client.getVMCalls != 2 {
		t.Errorf("uploads %d, CAS writes %d, reads %d; want 1, 1, 2", client.uploadSnippetCalls, client.setFieldCASCalls, client.getVMCalls)
	}
}

// B2: the same on a running VM whose tap an outside writer also isolated.
func TestBridgeIsolationEnsure_ConflictThenNoop_RunningVM(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{
			vmWithHookscript("", "d1", "running"),
			vmWithHookscript(op.wantedHookscript(), "d2", "running"),
		},
		setFieldCASErrs: []error{errDigestConflict},
		tapStates:       map[string]sshexec.TapLinkState{"tap100i0": {Exists: true, Isolated: true}},
	}
	op.Client = client
	res, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false)
	if err != nil || res.Changed {
		t.Fatalf("Run = %+v, %v; want a clean no-op", res, err)
	}
	if !op.Wrote() || !slices.Equal(op.Applied, []string{"snippet"}) {
		t.Errorf("Wrote %t, Applied %q; want [snippet]", op.Wrote(), op.Applied)
	}
	if len(client.setIsolatedCalls) != 0 {
		t.Errorf("isolated %v; the tap was already isolated", client.setIsolatedCalls)
	}
}

// B3: attempt 1 uploads, then conflicts; attempt 2 is not satisfied, and its
// own upload fails. The Run fails, and what attempt 1 wrote is still this
// Run's write.
func TestBridgeIsolationEnsure_LaterAttemptFails_KeepsEarlierWrites(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults:      []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "stopped"), vmWithHookscript("", "d2", "stopped")},
		setFieldCASErrs:   []error{errDigestConflict},
		uploadSnippetErrs: []error{nil, errors.New("storage full")},
	}
	op.Client = client
	if _, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false); err == nil {
		t.Fatal("Run succeeded; want the second upload's failure")
	}
	if !op.Wrote() || !slices.Equal(op.Applied, []string{"snippet"}) {
		t.Errorf("Wrote %t, Applied %q; want the first attempt's snippet", op.Wrote(), op.Applied)
	}
	if client.uploadSnippetCalls != 2 {
		t.Errorf("uploads %d, want 2", client.uploadSnippetCalls)
	}
}

// B4: a full apply on a running VM records every write, in order.
func TestBridgeIsolationEnsure_Applied_FullRunningApply(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "running")},
		tapStates: map[string]sshexec.TapLinkState{
			"tap100i0": {Exists: true}, "tap100i1": {Exists: true},
		},
	}
	op.Client = client
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"snippet", "hookscript", "tap100i0", "tap100i1"}; !slices.Equal(op.Applied, want) {
		t.Errorf("Applied %q, want %q", op.Applied, want)
	}
}

// B5: a hookscript already correct is skipped, and never recorded.
func TestBridgeIsolationEnsure_Applied_SkippedHookscriptNotRecorded(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript(op.wantedHookscript(), "d1", "running")},
		tapStates:    map[string]sshexec.TapLinkState{"tap100i0": {Exists: true}},
	}
	op.Client = client
	res, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false)
	if err != nil || !res.Changed {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if want := []string{"snippet", "tap100i0"}; !slices.Equal(op.Applied, want) {
		t.Errorf("Applied %q, want %q", op.Applied, want)
	}
	if client.setFieldCASCalls != 0 {
		t.Errorf("CAS writes %d, want 0", client.setFieldCASCalls)
	}
}

// B6: the root-only fallback's write over SSH is the hookscript's write; a
// failed fallback wrote nothing, and a failed tap write is not recorded.
func TestBridgeIsolationEnsure_Applied_RootOnlyFallback(t *testing.T) {
	rootOnly := errors.New("only root can set 'hookscript' config")
	if !sshexec.IsRootOnlyWriteError(rootOnly) {
		t.Fatalf("%q is not a root-only write error", rootOnly)
	}
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults:    []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "stopped")},
		setFieldCASErrs: []error{rootOnly},
	}
	op.Client = client
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"snippet", "hookscript"}; !slices.Equal(op.Applied, want) || len(client.sshSetValues) != 1 {
		t.Errorf("Applied %q (want %q), SSH writes %q", op.Applied, want, client.sshSetValues)
	}

	op = &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client = &fakeBridgeClient{
		getVMResults:    []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "stopped")},
		setFieldCASErrs: []error{rootOnly},
		sshSetErr:       errors.New("ssh: connection refused"),
	}
	op.Client = client
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("Apply succeeded; want the fallback's failure")
	}
	if want := []string{"snippet"}; !slices.Equal(op.Applied, want) {
		t.Errorf("Applied %q, want %q: a failed fallback wrote nothing", op.Applied, want)
	}

	op = &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client = &fakeBridgeClient{
		getVMResults:    []*proxmox.VirtualMachine{vmWithHookscript(op.wantedHookscript(), "d1", "running")},
		tapStates:       map[string]sshexec.TapLinkState{"tap100i0": {Exists: true}},
		setIsolatedErrs: map[string]error{"tap100i0": errors.New("bridge: no such device")},
	}
	op.Client = client
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("Apply succeeded; want the tap's failure")
	}
	if want := []string{"snippet"}; !slices.Equal(op.Applied, want) {
		t.Errorf("Applied %q, want %q: a failed tap write wrote nothing", op.Applied, want)
	}
}

// B7: satisfied at the first Read: nothing written, nothing recorded.
func TestBridgeIsolationEnsure_Noop_WroteNothing(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{getVMResults: []*proxmox.VirtualMachine{vmWithHookscript(op.wantedHookscript(), "d1", "stopped")}}
	op.Client = client
	res, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false)
	if err != nil || res.Changed {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if op.Wrote() || op.Applied != nil || client.uploadSnippetCalls != 0 {
		t.Errorf("Wrote %t, Applied %q, uploads %d; want nothing", op.Wrote(), op.Applied, client.uploadSnippetCalls)
	}
}

// B3b: the first upload fails: the Run wrote nothing.
func TestBridgeIsolationEnsure_FailedUpload_WroteNothing(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults:     []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "stopped")},
		uploadSnippetErr: errors.New("storage full"),
	}
	op.Client = client
	if _, err := Run(context.Background(), testRosterPath(t), bridgeKey(), op, false); err == nil {
		t.Fatal("Run succeeded; want the upload's failure")
	}
	if op.Wrote() || op.Applied != nil {
		t.Errorf("Wrote %t, Applied %q; want nothing: the upload failed", op.Wrote(), op.Applied)
	}
}
