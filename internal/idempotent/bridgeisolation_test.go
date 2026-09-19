package idempotent

import (
	"context"
	"errors"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

func TestBridgeIsolationEnsure_Validate(t *testing.T) {
	cases := []struct {
		name    string
		op      BridgeIsolationEnsure
		wantErr bool
	}{
		{"valid", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}, false},
		{"valid multiple indices", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}, false},
		{"zero vmid", BridgeIsolationEnsure{VMID: 0, NetIndices: []int{0}, StorageID: "local"}, true},
		{"negative vmid", BridgeIsolationEnsure{VMID: -1, NetIndices: []int{0}, StorageID: "local"}, true},
		{"no net indices", BridgeIsolationEnsure{VMID: 100, NetIndices: nil, StorageID: "local"}, true},
		{"negative net index", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{-1}, StorageID: "local"}, true},
		{"duplicate net index", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 0}, StorageID: "local"}, true},
		{"empty storage id", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: ""}, true},
		{"unsafe storage id", BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local/../etc"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.op.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBridgeIsolationEnsure_Read_StoppedVM_NoTapCalls(t *testing.T) {
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "stopped")},
	}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if client.tapLinkCalls != 0 {
		t.Errorf("expected no tap link calls while the vm is stopped, got %d", client.tapLinkCalls)
	}
	state := parseBridgeIsolationState(current)
	if state.Running {
		t.Errorf("expected Running=false in current state, got %q", current)
	}
	if op.digest != "d1" || op.hookscript != "" || op.running {
		t.Errorf("op fields = digest=%q hookscript=%q running=%v", op.digest, op.hookscript, op.running)
	}
}

func TestBridgeIsolationEnsure_Read_RunningVM_QueriesEachTap(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript(op.wantedHookscript(), "d1", "running")},
		tapStates: map[string]sshexec.TapLinkState{
			"tap100i0": {Exists: true, Isolated: true},
			"tap100i1": {Exists: true, Isolated: false},
		},
	}
	op.Client = client

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if client.tapLinkCalls != 2 {
		t.Errorf("expected 2 tap link calls, got %d", client.tapLinkCalls)
	}
	if !op.running {
		t.Error("expected op.running = true")
	}
	// Round-trip through the actual encode/decode, not a hand-written
	// literal: proves Read populates both taps with the right per-net-index
	// exists/isolated values, without pinning this test to the exact wire
	// format (JSON — see bridgeIsolationState.String's own doc comment).
	state := parseBridgeIsolationState(current)
	if state.Hookscript != op.wantedHookscript() || !state.Running {
		t.Errorf("state = %+v", state)
	}
	taps := make(map[int]tapObservation, len(state.Taps))
	for _, tap := range state.Taps {
		taps[tap.NetIndex] = tap
	}
	if tap, ok := taps[0]; !ok || !tap.Exists || !tap.Isolated {
		t.Errorf("net0 tap = %+v, want {Exists:true Isolated:true}", tap)
	}
	if tap, ok := taps[1]; !ok || !tap.Exists || tap.Isolated {
		t.Errorf("net1 tap = %+v, want {Exists:true Isolated:false}", tap)
	}
}

func TestBridgeIsolationEnsure_Read_PropagatesGetVMError(t *testing.T) {
	client := &fakeBridgeClient{getVMErr: errors.New("network down")}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when GetVM fails")
	}
}

// TestBridgeIsolationEnsure_Read_NilVirtualMachineConfig mirrors
// VMTagEnsure's own regression test (vmtag_test.go): a VM with no
// VirtualMachineConfig must surface as an error, not be silently treated
// as digest="" (which would disable SetVMConfigFieldCAS's compare-and-swap
// guard entirely — pveforge-nil-vmconfig-digest-gap).
func TestBridgeIsolationEnsure_Read_NilVirtualMachineConfig(t *testing.T) {
	client := &fakeBridgeClient{getVMResults: []*proxmox.VirtualMachine{{}}}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when VirtualMachineConfig is nil")
	}
	if op.digest != "" {
		t.Errorf("op.digest = %q, want empty", op.digest)
	}
	if op.hookscript != "" {
		t.Errorf("op.hookscript = %q, want empty", op.hookscript)
	}
}

func TestBridgeIsolationEnsure_Read_PropagatesTapLinkStateError(t *testing.T) {
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript("", "d1", "running")},
		tapStateErrs: map[string]error{"tap100i0": errors.New("ssh down")},
	}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when TapLinkState fails")
	}
}

func TestBridgeIsolationEnsure_Satisfied(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}
	wanted := op.wantedHookscript()

	cases := []struct {
		name  string
		state bridgeIsolationState
		want  bool
	}{
		{"wrong hookscript, not running", bridgeIsolationState{Hookscript: "other", Running: false}, false},
		{"right hookscript, not running: satisfied regardless of taps", bridgeIsolationState{Hookscript: wanted, Running: false}, true},
		{
			"right hookscript, running, all taps isolated",
			bridgeIsolationState{Hookscript: wanted, Running: true, Taps: []tapObservation{
				{NetIndex: 0, Exists: true, Isolated: true},
				{NetIndex: 1, Exists: true, Isolated: true},
			}},
			true,
		},
		{
			"right hookscript, running, one tap not isolated",
			bridgeIsolationState{Hookscript: wanted, Running: true, Taps: []tapObservation{
				{NetIndex: 0, Exists: true, Isolated: true},
				{NetIndex: 1, Exists: true, Isolated: false},
			}},
			false,
		},
		{
			"right hookscript, running, a tap missing entirely",
			bridgeIsolationState{Hookscript: wanted, Running: true, Taps: []tapObservation{
				{NetIndex: 0, Exists: true, Isolated: true},
			}},
			false,
		},
		{
			"right hookscript, running, a tap not existing",
			bridgeIsolationState{Hookscript: wanted, Running: true, Taps: []tapObservation{
				{NetIndex: 0, Exists: false, Isolated: false},
				{NetIndex: 1, Exists: true, Isolated: true},
			}},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := op.Satisfied(c.state.String()); got != c.want {
				t.Errorf("Satisfied(%q) = %v, want %v", c.state.String(), got, c.want)
			}
		})
	}
}

// TestBridgeIsolationEnsure_Satisfied_StoppedVM_NetIndicesChanged is the
// DEFECT 1 regression test: a stopped VM whose hookscript was wired for an
// OLDER NetIndices set must NOT read as satisfied against a Op configured
// with a DIFFERENT NetIndices set — wantedHookscript must depend on
// NetIndices, or a NetIndices change on an already-wired, stopped VM would
// silently never redeploy the script (see snippetFilename's own doc
// comment).
func TestBridgeIsolationEnsure_Satisfied_StoppedVM_NetIndicesChanged(t *testing.T) {
	oldOp := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	current := bridgeIsolationState{Hookscript: oldOp.wantedHookscript(), Running: false}.String()

	newOp := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}
	if newOp.Satisfied(current) {
		t.Fatal("expected Satisfied=false: the deployed hookscript was wired for the OLD NetIndices set, not the new one")
	}
}

// TestBridgeIsolationEnsure_StateStringRoundTrip_HookscriptWithDelimiterCharacters
// is the DEFECT 2 regression test: Hookscript is sourced directly from
// PVE's live, externally-controlled VirtualMachineConfig.Hookscript — a
// value containing literal ';'/'=' characters (which a hand-rolled
// delimited encoding would misparse) must still round-trip through
// String/parseBridgeIsolationState exactly, with Satisfied correctly
// distinguishing it from the wanted value.
func TestBridgeIsolationEnsure_StateStringRoundTrip_HookscriptWithDelimiterCharacters(t *testing.T) {
	tricky := `local:snippets/weird;name=value.sh`
	state := bridgeIsolationState{Hookscript: tricky, Running: false}
	encoded := state.String()

	decoded := parseBridgeIsolationState(encoded)
	if decoded.Hookscript != tricky {
		t.Fatalf("round-tripped hookscript = %q, want %q (encoded form: %s)", decoded.Hookscript, tricky, encoded)
	}

	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	if op.Satisfied(encoded) {
		t.Fatal("expected Satisfied=false: the tricky hookscript value does not equal this op's wanted value")
	}
}

func TestBridgeIsolationEnsure_Apply_RejectsInvalidOpBeforeTouchingClient(t *testing.T) {
	client := &fakeBridgeClient{}
	op := &BridgeIsolationEnsure{Client: client, VMID: 0, NetIndices: []int{0}, StorageID: "local"}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected an error for an invalid op")
	}
	if client.uploadSnippetCalls != 0 {
		t.Error("UploadSnippet must not be called when validation fails")
	}
}

func TestBridgeIsolationEnsure_Apply_UploadsSnippetAlways(t *testing.T) {
	client := &fakeBridgeClient{}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	op.hookscript = op.wantedHookscript() // already wired; upload should still happen

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.uploadSnippetCalls != 1 {
		t.Fatalf("expected UploadSnippet to be called once, got %d", client.uploadSnippetCalls)
	}
	if client.lastSnippetStorage != "local" {
		t.Errorf("storage = %q, want local", client.lastSnippetStorage)
	}
	if client.lastSnippetFilename != "pveforge-bridge-isolate-vm100-net0.sh" {
		t.Errorf("filename = %q", client.lastSnippetFilename)
	}
	if !strings.Contains(client.lastSnippetContent, "post-start") {
		t.Errorf("expected the script to reference the post-start phase, got:\n%s", client.lastSnippetContent)
	}
	if !strings.Contains(client.lastSnippetContent, "tap100i0") {
		t.Errorf("expected the script to reference tap100i0, got:\n%s", client.lastSnippetContent)
	}
	if !strings.HasSuffix(strings.TrimRight(client.lastSnippetContent, "\n"), "exit 0") {
		t.Errorf("expected the script to unconditionally exit 0, got:\n%s", client.lastSnippetContent)
	}
	// Hookscript already correct: no CAS write should have happened.
	if client.setFieldCASCalls != 0 {
		t.Errorf("expected no hookscript write when already correct, got %d calls", client.setFieldCASCalls)
	}
}

func TestBridgeIsolationEnsure_Apply_SetsHookscriptWhenMissing(t *testing.T) {
	client := &fakeBridgeClient{}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	op.hookscript = ""
	op.digest = "d1"

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCASCalls != 1 {
		t.Fatalf("expected exactly 1 CAS write, got %d", client.setFieldCASCalls)
	}
	if client.lastCASField != "hookscript" {
		t.Errorf("field = %q, want hookscript", client.lastCASField)
	}
	if client.lastCASValue != op.wantedHookscript() {
		t.Errorf("value = %q, want %q", client.lastCASValue, op.wantedHookscript())
	}
	if client.lastCASDigest != "d1" {
		t.Errorf("digest = %q, want d1", client.lastCASDigest)
	}
	if client.setIsolatedCalls != nil {
		t.Error("expected no live-apply calls: op.running was never set (defaults to false)")
	}
}

func TestBridgeIsolationEnsure_Apply_WrapsDigestConflictAsErrConflict(t *testing.T) {
	client := &fakeBridgeClient{setFieldCASErrs: []error{errors.New("digest mismatch: config changed")}}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected ErrConflict, got: %v", err)
	}
}

// TestBridgeIsolationEnsure_Apply_RootOnlyHookscriptFallsBackToPlainSetter
// covers the unverified-live risk this Op's own doc comment flags:
// whether "hookscript" is REST-writable from a scoped token, or root-only
// like "args". If PVE rejects the CAS write as root-only, Apply must fall
// back to the plain (non-CAS) setter rather than failing outright.
func TestBridgeIsolationEnsure_Apply_RootOnlyHookscriptFallsBackToPlainSetter(t *testing.T) {
	client := &fakeBridgeClient{
		setFieldCASErrs: []error{errors.New(`set vm 100 field "hookscript": only root can set 'hookscript' config`)},
	}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 1 {
		t.Fatalf("expected the plain setter to be called as a fallback, got %d calls", client.setFieldCalls)
	}
	if client.lastFieldValue != op.wantedHookscript() {
		t.Errorf("fallback value = %q, want %q", client.lastFieldValue, op.wantedHookscript())
	}
}

func TestBridgeIsolationEnsure_Apply_RootOnlyFallbackAlsoFails(t *testing.T) {
	client := &fakeBridgeClient{
		setFieldCASErrs: []error{errors.New(`only root can set 'hookscript' config`)},
		setFieldErrs:    []error{errors.New("ssh unavailable")},
	}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when both the CAS write and its ssh fallback fail")
	}
	if !strings.Contains(err.Error(), "ssh unavailable") {
		t.Errorf("expected the fallback's own error to be surfaced, got: %v", err)
	}
}

func TestBridgeIsolationEnsure_Apply_PropagatesOtherHookscriptError(t *testing.T) {
	client := &fakeBridgeClient{setFieldCASErrs: []error{errors.New("permission denied")}}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrConflict) {
		t.Error("an unrelated failure must not be wrapped as ErrConflict")
	}
}

// TestBridgeIsolationEnsure_Apply_RunningVM_AppliesIsolationLive proves the
// second piece of state this Op reconciles: when Read last observed the VM
// running, Apply must immediately isolate every configured tap, not just
// wire the hookscript for next boot.
func TestBridgeIsolationEnsure_Apply_RunningVM_AppliesIsolationLive(t *testing.T) {
	client := &fakeBridgeClient{}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0, 1}, StorageID: "local"}
	op.running = true
	op.hookscript = op.wantedHookscript()

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setIsolatedCalls["tap100i0"] != 1 || client.setIsolatedCalls["tap100i1"] != 1 {
		t.Fatalf("expected both taps to be isolated live, got calls: %+v", client.setIsolatedCalls)
	}
	if !client.lastIsolatedRequests["tap100i0"] || !client.lastIsolatedRequests["tap100i1"] {
		t.Error("expected both taps to be set isolated=true")
	}
}

func TestBridgeIsolationEnsure_Apply_NotRunning_NeverTouchesLiveTaps(t *testing.T) {
	client := &fakeBridgeClient{}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	op.running = false
	op.hookscript = op.wantedHookscript()

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setIsolatedCalls != nil {
		t.Errorf("expected no live-apply calls while the vm is stopped, got: %+v", client.setIsolatedCalls)
	}
}

// TestBridgeIsolationEnsure_Apply_LiveApplyFailureIsHardError is the
// recorded-decision regression test: a failure applying isolation to a
// running VM's tap must be a real Apply error, never swallowed as
// best-effort (pveforge-bridge-isolation-via-hookscript, decision 2,
// 2026-09-14).
func TestBridgeIsolationEnsure_Apply_LiveApplyFailureIsHardError(t *testing.T) {
	client := &fakeBridgeClient{
		setIsolatedErrs: map[string]error{"tap100i0": errors.New("bridge: device busy")},
	}
	op := &BridgeIsolationEnsure{Client: client, VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	op.running = true
	op.hookscript = op.wantedHookscript()

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected the live-apply failure to surface as a real Apply error")
	}
	if !strings.Contains(err.Error(), "device busy") {
		t.Errorf("expected the underlying error to be surfaced, got: %v", err)
	}
}

// TestBridgeIsolationEnsure_ViaRun_EndToEnd_StoppedVM_NoOp exercises the
// full stack (internal/lock + the read-compare-mutate contract) against a
// VM that already has the right hookscript wired and is currently
// stopped — satisfied purely on the durable/hookscript dimension, with
// nothing live to check.
func TestBridgeIsolationEnsure_ViaRun_EndToEnd_StoppedVM_NoOp(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{vmWithHookscript(op.wantedHookscript(), "d1", "stopped")},
	}
	op.Client = client
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: hookscript already wired and nothing live to check while stopped")
	}
	if client.uploadSnippetCalls != 0 || client.setFieldCASCalls != 0 {
		t.Error("Apply must not run on a no-op")
	}
}

// TestBridgeIsolationEnsure_ViaRun_EndToEnd_RunningVM_AppliesBoth proves
// the full stack drives BOTH pieces of state to convergence for a running
// VM starting from scratch: hookscript unset AND tap not yet isolated.
func TestBridgeIsolationEnsure_ViaRun_EndToEnd_RunningVM_AppliesBoth(t *testing.T) {
	op := &BridgeIsolationEnsure{VMID: 100, NetIndices: []int{0}, StorageID: "local"}
	client := &fakeBridgeClient{
		getVMResults: []*proxmox.VirtualMachine{
			vmWithHookscript("", "d1", "running"),                    // first Read: nothing wired yet
			vmWithHookscript(op.wantedHookscript(), "d2", "running"), // final re-read for Result.After
		},
		tapStates: map[string]sshexec.TapLinkState{
			"tap100i0": {Exists: true, Isolated: false},
		},
	}
	op.Client = client
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if client.uploadSnippetCalls != 1 {
		t.Errorf("expected the snippet to be uploaded once, got %d", client.uploadSnippetCalls)
	}
	if client.setFieldCASCalls != 1 {
		t.Errorf("expected the hookscript to be wired once, got %d", client.setFieldCASCalls)
	}
	if client.setIsolatedCalls["tap100i0"] != 1 {
		t.Errorf("expected the live tap to be isolated once, got: %+v", client.setIsolatedCalls)
	}
}
