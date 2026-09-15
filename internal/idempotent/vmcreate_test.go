package idempotent

import (
	"context"
	"errors"
	"net/url"
	"testing"

	proxmox "github.com/luthermonson/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// fakeVMCreateClient is a scriptable VMCreateClient, local to this test
// file — VMCreate's Client interface is narrower than the shared
// fakeClient in fake_test.go (CreateVM/WaitForTask instead of
// SetVMConfigFieldCAS/SetVMConfigField/RawRequest), so it gets its own
// small fake rather than widening fakeClient for a shape only this Op
// uses, matching this package's existing "one fake per interface shape"
// discipline (fakeClient itself is already shared across VMTagEnsure and
// VMFieldsEnsure only because they happen to need the same interface).
type fakeVMCreateClient struct {
	node string

	getVMResult *proxmox.VirtualMachine
	getVMErr    error
	getVMCalls  int

	createVMUPID  string
	createVMErr   error
	createVMCalls int
	lastVMID      int
	lastParams    url.Values

	waitForTaskErr   error
	waitForTaskCalls int
	lastWaitNode     string
	lastWaitUPID     string
}

func (f *fakeVMCreateClient) Node() string { return f.node }

func (f *fakeVMCreateClient) GetVM(_ context.Context, _ string, _ int) (*proxmox.VirtualMachine, error) {
	f.getVMCalls++
	if f.getVMErr != nil {
		return nil, f.getVMErr
	}
	return f.getVMResult, nil
}

func (f *fakeVMCreateClient) CreateVM(_ context.Context, vmid int, params url.Values) (string, error) {
	f.createVMCalls++
	f.lastVMID = vmid
	f.lastParams = params
	if f.createVMErr != nil {
		return "", f.createVMErr
	}
	return f.createVMUPID, nil
}

func (f *fakeVMCreateClient) WaitForTask(_ context.Context, node, upid string) error {
	f.waitForTaskCalls++
	f.lastWaitNode = node
	f.lastWaitUPID = upid
	return f.waitForTaskErr
}

// TestVMCreate_Validate_RejectsOrphanIPConfig covers Validate() called
// directly/standalone, mirroring TestVMFieldsEnsure_Validate's pattern of
// testing Validate in isolation: an ipconfigN key with no matching netN
// key must be rejected, since it would silently leave that interface
// without networking rather than erroring on PVE's own side.
func TestVMCreate_Validate_RejectsOrphanIPConfig(t *testing.T) {
	op := &VMCreate{
		VMID: 100,
		Params: url.Values{
			"ipconfig0": {"ip=10.0.0.5/24,gw=10.0.0.1"},
		},
	}
	err := op.Validate()
	if err == nil {
		t.Fatal("expected an error for ipconfig0 with no matching net0")
	}
}

func TestVMCreate_Validate_AcceptsMatchedNetAndIPConfig(t *testing.T) {
	op := &VMCreate{
		VMID: 100,
		Params: url.Values{
			"net0":      {"virtio,bridge=vmbr0"},
			"ipconfig0": {"ip=10.0.0.5/24,gw=10.0.0.1"},
			"net1":      {"virtio,bridge=vmbr1"},
		},
	}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestVMCreate_Validate_NoNetOrIPConfigIsFine covers the common case of a
// create with no networking parameters at all — nothing to validate,
// never an error.
func TestVMCreate_Validate_NoNetOrIPConfigIsFine(t *testing.T) {
	op := &VMCreate{VMID: 100, Params: url.Values{"cores": {"2"}, "memory": {"2048"}}}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestVMCreate_Validate_MismatchedIndexIsRejected covers a net/ipconfig
// pair whose numeric suffixes don't line up (net0 present, but only
// ipconfig1 given) — still an orphan ipconfig from PVE's perspective.
func TestVMCreate_Validate_MismatchedIndexIsRejected(t *testing.T) {
	op := &VMCreate{
		VMID: 100,
		Params: url.Values{
			"net0":      {"virtio,bridge=vmbr0"},
			"ipconfig1": {"ip=10.0.0.5/24,gw=10.0.0.1"},
		},
	}
	if err := op.Validate(); err == nil {
		t.Fatal("expected an error: ipconfig1 has no matching net1")
	}
}

// TestVMCreate_Read_FreshVMID covers a vmid nothing answers to yet: the
// fake GetVM returns an error, Read must treat that as "doesn't exist"
// (empty string, no error).
func TestVMCreate_Read_FreshVMID(t *testing.T) {
	client := &fakeVMCreateClient{node: "qa-pve-01", getVMErr: errors.New("no such vm")}
	op := &VMCreate{Client: client, VMID: 100}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current != "" {
		t.Errorf("current = %q, want empty for a fresh vmid", current)
	}
	if op.Satisfied(current) {
		t.Error("expected Satisfied(current) to be false for a fresh vmid")
	}
}

// TestVMCreate_Read_ExistingVMID covers a vmid that already answers to a
// VM: the fake GetVM succeeds, Read must return a non-empty comparable
// string, and Satisfied must report true.
func TestVMCreate_Read_ExistingVMID(t *testing.T) {
	vm := &proxmox.VirtualMachine{VirtualMachineConfig: &proxmox.VirtualMachineConfig{Tags: "prod"}}
	client := &fakeVMCreateClient{node: "qa-pve-01", getVMResult: vm}
	op := &VMCreate{Client: client, VMID: 100}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current == "" {
		t.Fatal("expected a non-empty current state for an existing vmid")
	}
	if !op.Satisfied(current) {
		t.Error("expected Satisfied(current) to be true for an existing vmid")
	}
}

// TestVMCreate_ViaRun_FreshVMID_AppliesCreate proves a fresh vmid drives a
// full Run-style Read -> Satisfied(false) -> Apply cycle: Apply must
// actually be called (CreateVM + WaitForTask both invoked).
func TestVMCreate_ViaRun_FreshVMID_AppliesCreate(t *testing.T) {
	client := &fakeVMCreateClient{
		node:         "qa-pve-01",
		getVMErr:     errors.New("no such vm"),
		createVMUPID: "UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:",
	}
	op := &VMCreate{Client: client, VMID: 100, Params: url.Values{"cores": {"2"}}}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true for a fresh vmid")
	}
	if client.createVMCalls != 1 {
		t.Errorf("expected 1 CreateVM call, got %d", client.createVMCalls)
	}
	if client.waitForTaskCalls != 1 {
		t.Errorf("expected 1 WaitForTask call, got %d", client.waitForTaskCalls)
	}
	if client.lastWaitUPID != "UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:" {
		t.Errorf("WaitForTask called with upid %q, want the UPID CreateVM returned", client.lastWaitUPID)
	}
	if client.lastWaitNode != "qa-pve-01" {
		t.Errorf("WaitForTask called with node %q, want qa-pve-01", client.lastWaitNode)
	}
}

// TestVMCreate_ViaRun_ExistingVMID_SkipsApply is the regression guard for
// a real review finding: a caller that calls op.Validate() explicitly
// ahead of the Read/Satisfied cycle (mirroring cmd/pveforge/vm.go's
// existing pattern for VMFieldsEnsure — explicit Validate before
// idempotent.Run, because Run skips Apply — and therefore Apply's own
// internal Validate call — entirely once already-satisfied) still gets
// validation enforcement even on this already-satisfied path.
func TestVMCreate_ViaRun_ExistingVMID_SkipsApply(t *testing.T) {
	vm := &proxmox.VirtualMachine{VirtualMachineConfig: &proxmox.VirtualMachineConfig{Tags: "prod"}}
	client := &fakeVMCreateClient{node: "qa-pve-01", getVMResult: vm}
	op := &VMCreate{
		Client: client,
		VMID:   100,
		Params: url.Values{"ipconfig0": {"ip=10.0.0.5/24"}}, // orphan ipconfig0: invalid
	}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	// Mirrors cmd/pveforge/vm.go's newVMSetCmd: explicit Validate call
	// ahead of Run, because Apply's own internal Validate never runs on
	// an already-satisfied cycle.
	if err := op.Validate(); err == nil {
		t.Fatal("expected explicit Validate() to catch the orphan ipconfig0, even though the vmid already exists")
	}

	// Confirm Run itself would have skipped Apply for this already-
	// satisfied vmid, silently bypassing Apply's own internal Validate
	// call — proving the explicit call above is load-bearing, not
	// redundant.
	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: the vmid already exists")
	}
	if client.createVMCalls != 0 {
		t.Error("CreateVM must not be called when the vmid already exists")
	}
}

// TestVMCreate_Apply_ValidatesBeforeTouchingClient mirrors
// TestVMTagEnsure_Apply_RejectsInvalidTagBeforeTouchingClient's pattern:
// prove Apply calls Validate before doing anything else — an invalid
// Params must never reach CreateVM at all.
func TestVMCreate_Apply_ValidatesBeforeTouchingClient(t *testing.T) {
	client := &fakeVMCreateClient{node: "qa-pve-01"}
	op := &VMCreate{
		Client: client,
		VMID:   100,
		Params: url.Values{"ipconfig0": {"ip=10.0.0.5/24"}}, // orphan ipconfig0
	}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error for an invalid Params")
	}
	if client.createVMCalls != 0 {
		t.Error("CreateVM must not be called when validation fails")
	}
	if client.waitForTaskCalls != 0 {
		t.Error("WaitForTask must not be called when validation fails")
	}
}

// TestVMCreate_Apply_WaitsForTheReturnedUPID proves Apply calls
// WaitForTask with the exact UPID CreateVM returned.
func TestVMCreate_Apply_WaitsForTheReturnedUPID(t *testing.T) {
	client := &fakeVMCreateClient{
		node:         "qa-pve-01",
		createVMUPID: "UPID:qa-pve-01:9:9:9:qmcreate:100:root@pam:",
	}
	op := &VMCreate{Client: client, VMID: 100, Params: url.Values{"cores": {"2"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.lastWaitUPID != "UPID:qa-pve-01:9:9:9:qmcreate:100:root@pam:" {
		t.Errorf("WaitForTask upid = %q, want the UPID CreateVM returned", client.lastWaitUPID)
	}
	if client.lastVMID != 100 {
		t.Errorf("CreateVM called with vmid=%d, want 100", client.lastVMID)
	}
}

// TestVMCreate_Apply_PropagatesCreateVMError proves a CreateVM failure
// (e.g. PVE rejecting a vmid collision with its own verbatim error text)
// is propagated as Apply's own error, and WaitForTask is never called.
func TestVMCreate_Apply_PropagatesCreateVMError(t *testing.T) {
	client := &fakeVMCreateClient{node: "qa-pve-01", createVMErr: errors.New("VM 100 already exists")}
	op := &VMCreate{Client: client, VMID: 100, Params: url.Values{"cores": {"2"}}}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when CreateVM fails")
	}
	if client.waitForTaskCalls != 0 {
		t.Error("WaitForTask must not be called when CreateVM fails")
	}
}

// TestVMCreate_Apply_PropagatesWaitForTaskError proves a WaitForTask
// failure propagates as the Op's own error, even though CreateVM itself
// succeeded.
func TestVMCreate_Apply_PropagatesWaitForTaskError(t *testing.T) {
	client := &fakeVMCreateClient{
		node:           "qa-pve-01",
		createVMUPID:   "UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:",
		waitForTaskErr: errors.New("task failed: unable to allocate storage"),
	}
	op := &VMCreate{Client: client, VMID: 100, Params: url.Values{"cores": {"2"}}}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when WaitForTask fails")
	}
	if client.createVMCalls != 1 {
		t.Errorf("expected CreateVM to still be called exactly once, got %d", client.createVMCalls)
	}
}
