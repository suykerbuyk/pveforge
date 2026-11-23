package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// The network and storage Ops state their pre-write refusals through
// idempotent.Preflighter (or, for a Read-time refusal, dispatch.Refuse on the
// Read's ctx): those are exit 4 while the run's gate is closed. Everything
// after the first write (the stage, the POST) is a plain error. These tests
// run the Ops through Run with a gate and assert, per boundary, the marker, the
// gate state and that nothing was sent; the post-write twin of each asserts
// the same Op's later refusal is NOT the marker and the gate is open.

func gated(t *testing.T) (context.Context, func() bool) {
	t.Helper()
	ctx, _ := dispatch.With(context.Background())
	return ctx, func() bool { return dispatch.Opened(ctx) }
}

func netKey() lock.ObjectKey { return NetworkLockKey("t", "pve1") }

// ---- NetworkFieldsEnsure ----------------------------------------------------

func fieldsOp(c *fakeNetworkFieldsClient) *NetworkFieldsEnsure {
	return &NetworkFieldsEnsure{Client: c, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
}

func fieldsRead(c *fakeNetworkFieldsClient) {
	c.getResponses["vmbr5"] = []getResponse{{fields: map[string]json.RawMessage{"type": rawField("bridge"), "mtu": rawField("1500")}}}
}

func TestPreflight_NetworkFields_UnknownType_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := newFakeNetworkFieldsClient("pve1")
	fieldsRead(c)
	c.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr0", nil)}}} // target not listed
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), fieldsOp(c), false)
	if err == nil || !dispatch.IsRefused(err) || !strings.Contains(err.Error(), "refusing to stage") {
		t.Fatalf("Run = %v, want a refused-before-write error", err)
	}
	if opened() || c.lastStageParams != nil || c.commitCalls != 0 {
		t.Errorf("gate=%v staged=%v commits=%d, want nothing sent and a closed gate", opened(), c.lastStageParams, c.commitCalls)
	}
}

func TestPreflight_NetworkFields_InterfaceMissing_ReadRefusal(t *testing.T) {
	c := newFakeNetworkFieldsClient("pve1")
	c.getResponses["vmbr5"] = []getResponse{{missing: true}}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), fieldsOp(c), false)
	if err == nil || !dispatch.IsRefused(err) || opened() {
		t.Fatalf("Run = %v (gate %v), want a refused-before-write error", err, opened())
	}
	// The same Read AFTER a write (the gate open) is a plain error.
	ctx2, _ := dispatch.With(context.Background())
	dispatch.Open(ctx2)
	if _, err := fieldsOp(c).Read(ctx2); err == nil || dispatch.IsRefused(err) {
		t.Fatalf("Read with an open gate = %v, want a plain (not refused) error", err)
	}
}

// Twin: the stage is sent, then the guard refuses: not the marker, gate open.
func TestPreflight_NetworkFields_GuardAfterStage_IsNotRefused(t *testing.T) {
	c := newFakeNetworkFieldsClient("pve1")
	fieldsRead(c)
	c.listResponses = []listResponse{
		{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", map[string]json.RawMessage{"type": rawField("bridge")}), ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")})}},
		{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", map[string]json.RawMessage{"type": rawField("bridge")}), ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth9")})}},
	}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), fieldsOp(c), false)
	if err == nil || dispatch.IsRefused(err) {
		t.Fatalf("Run = %v, want a plain error after the stage", err)
	}
	if !opened() || c.lastStageParams == nil || c.revertCalls != 1 {
		t.Errorf("gate=%v staged=%v reverts=%d, want an open gate, a stage and its revert", opened(), c.lastStageParams, c.revertCalls)
	}
}

// A failed READ in Preflight is not a refusal: Apply reports it (exit 1), and
// the interface list is read ONCE (Preflight's read is Apply's step 1).
func TestPreflight_NetworkFields_ReadFailureIsNotARefusal_AndReadsOnce(t *testing.T) {
	c := newFakeNetworkFieldsClient("pve1")
	fieldsRead(c)
	c.listResponses = []listResponse{{err: errors.New("boom: list failed")}}
	ctx, _ := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), fieldsOp(c), false)
	if err == nil || dispatch.IsRefused(err) || !strings.Contains(err.Error(), "boom: list failed") {
		t.Fatalf("Run = %v, want the read error, not refused", err)
	}
	if c.listCalls != 1 {
		t.Errorf("list calls = %d, want 1: Preflight's read must be Apply's step 1, not a second read", c.listCalls)
	}
}

// ---- NetworkBridgeEnsure ----------------------------------------------------

func bridgeClient() *fakeNetworkBridgeClient {
	c := newFakeNetworkBridgeClient("pve1")
	c.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	c.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	return c
}

func TestPreflight_NetworkBridge_ExistingOtherType_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := bridgeClient()
	c.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"type": rawField("OVSBridge")}}}
	op := NewNetworkBridgeCreate(c, "pve1", "vmbr99", "vmbr0", map[string]string{"mtu": "9000"})
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), op, false)
	if err == nil || !dispatch.IsRefused(err) || !strings.Contains(err.Error(), "nothing staged") {
		t.Fatalf("Run = %v, want a refused-before-write error", err)
	}
	if opened() || c.lastStageParams != nil || c.commitCalls != 0 {
		t.Errorf("gate=%v staged=%v commits=%d, want nothing sent", opened(), c.lastStageParams, c.commitCalls)
	}
}

func TestPreflight_NetworkBridge_MissingManagementBridge_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := newFakeNetworkBridgeClient("pve1")
	c.getResponses["vmbr0"] = []getResponse{{missing: true}}
	c.getResponses["vmbr99"] = []getResponse{{missing: true}}
	op := NewNetworkBridgeCreate(c, "pve1", "vmbr99", "vmbr0", nil)
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), op, false)
	if err == nil || !dispatch.IsRefused(err) || opened() {
		t.Fatalf("Run = %v (gate %v), want a refused-before-write error", err, opened())
	}
}

func TestPreflight_NetworkBridge_InvalidOp_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := newFakeNetworkBridgeClient("pve1")
	op := NewNetworkBridgeCreate(c, "pve1", "vmbr99", "", nil) // no management bridge
	// Run reads first, so give it an absent target; Preflight then refuses on Validate.
	c.getResponses["vmbr99"] = []getResponse{{missing: true}}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), op, false)
	if err == nil || !dispatch.IsRefused(err) || opened() {
		t.Fatalf("Run = %v (gate %v), want a refused-before-write error", err, opened())
	}
}

// A failed READ of the management bridge is not a refusal: Preflight keeps it
// for Apply (exit 1, gate open), and the bridge is read once.
func TestPreflight_NetworkBridge_ReadFailureIsNotARefusal(t *testing.T) {
	c := newFakeNetworkBridgeClient("pve1")
	c.getResponses["vmbr0"] = []getResponse{{err: errors.New("boom: mgmt read failed")}}
	c.getResponses["vmbr99"] = []getResponse{{missing: true}}
	op := NewNetworkBridgeCreate(c, "pve1", "vmbr99", "vmbr0", nil)
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), op, false)
	if err == nil || dispatch.IsRefused(err) || !strings.Contains(err.Error(), "boom: mgmt read failed") {
		t.Fatalf("Run = %v, want the read error, not refused", err)
	}
	if !opened() || c.getCalls["vmbr0"] != 1 {
		t.Errorf("gate=%v management-bridge reads=%d, want an open gate and exactly 1 read", opened(), c.getCalls["vmbr0"])
	}
}

// Twin: the create is staged, then the guard self-check refuses (the
// interface is already active before the commit): not the marker, gate open.
func TestPreflight_NetworkBridge_GuardAfterStage_IsNotRefused(t *testing.T) {
	c := bridgeClient()
	c.getResponses["vmbr99"] = []getResponse{{missing: true}, {missing: true}, {fields: map[string]json.RawMessage{"type": rawField("bridge"), "active": rawField("1")}}}
	c.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}
	op := NewNetworkBridgeCreate(c, "pve1", "vmbr99", "vmbr0", nil)
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), netKey(), op, false)
	if err == nil || dispatch.IsRefused(err) || !strings.Contains(err.Error(), "guard self-check failed") {
		t.Fatalf("Run = %v, want the guard's plain error", err)
	}
	if !opened() || c.lastStageParams == nil || c.revertCalls != 1 {
		t.Errorf("gate=%v staged=%v reverts=%d, want an open gate, a stage and its revert", opened(), c.lastStageParams, c.revertCalls)
	}
}

// ---- Storage ----------------------------------------------------------------

func TestPreflight_StorageCreate_Differing_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := &fakeStorageCreateClient{node: "qa-pve-07", getConfigResult: rawCfg("storage", "s", "type", "dir", "content", "images")}
	op := &StorageCreate{Client: c, Name: "s", Params: zfspoolParams()}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "s"}, op, false)
	var differs *StorageDiffersError
	if err == nil || !dispatch.IsRefused(err) || !errors.As(err, &differs) {
		t.Fatalf("Run = %v, want a refused *StorageDiffersError", err)
	}
	if opened() || c.createCalls != 0 {
		t.Errorf("gate=%v creates=%d, want nothing sent", opened(), c.createCalls)
	}
}

func TestPreflight_StorageCreate_PostFails_IsNotRefused(t *testing.T) {
	c := &fakeStorageCreateClient{node: "qa-pve-07", getConfigErr: storageNotFoundErr(), createErr: errors.New("pve rejected")}
	op := &StorageCreate{Client: c, Name: "s", Params: zfspoolParams()}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "s"}, op, false)
	if err == nil || dispatch.IsRefused(err) || !opened() || c.createCalls != 1 {
		t.Fatalf("Run = %v, gate %v, creates %d: want a plain error after the POST", err, opened(), c.createCalls)
	}
}

func TestStorageContent_MissingStorage_ReadRefusal_ButNotAfterAWrite(t *testing.T) {
	c := &fakeStorageContentClient{node: "qa-pve-07", getErr: storageNotFoundErr()}
	op := &StorageContentEnsure{Client: c, Storage: "s", ContentType: "iso"}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "s"}, op, false)
	if err == nil || !dispatch.IsRefused(err) || opened() || c.updateCalls != 0 {
		t.Fatalf("Run = %v (gate %v): want a refused-before-write error", err, opened())
	}
	ctx2, _ := dispatch.With(context.Background())
	dispatch.Open(ctx2)
	if _, err := op.Read(ctx2); err == nil || dispatch.IsRefused(err) {
		t.Fatalf("Read with an open gate = %v, want a plain error", err)
	}
}

func TestFreeOrphans_SelectorGuard_IsRefusedBeforeAnyWrite(t *testing.T) {
	c := &fakeStorageClient{node: "qa-pve-01"}
	op := &VolumeFreeOrphans{Client: c, Scanner: c, Storage: "local-lvm", VMID: 690} // neither selector set
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "local-lvm"}, op, false)
	if err == nil || !dispatch.IsRefused(err) || !errors.Is(err, pve.ErrUnverifiableRead) || opened() {
		t.Fatalf("Run = %v (gate %v), want a refused ErrUnverifiableRead", err, opened())
	}
	// Shared storage with a node-scoped selector.
	c2 := &fakeStorageClient{node: "qa-pve-01", storageShared: 1}
	op2 := &VolumeFreeOrphans{Client: c2, Scanner: c2, Storage: "local-lvm", VMID: 690, CompleteVMIDs: []int{}}
	ctx2, opened2 := gated(t)
	_, err = Run(ctx2, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "local-lvm"}, op2, false)
	if err == nil || !dispatch.IsRefused(err) || opened2() {
		t.Fatalf("shared + node-scoped: Run = %v (gate %v), want a refusal", err, opened2())
	}
}

// Twin: a DELETE is sent (the gate opens before Apply) and the free then fails:
// not the marker.
func TestFreeOrphans_DeleteFails_IsNotRefused(t *testing.T) {
	orphan := &proxmox.StorageContent{Volid: "local-lvm:vm-690-disk-0", VMID: 690}
	c := &fakeStorageClient{node: "qa-pve-01", scannerOrphans: []*proxmox.StorageContent{orphan}}
	op := &VolumeFreeOrphans{Client: c, Scanner: c, Storage: "local-lvm", VMID: 690, CompleteVMIDs: []int{}}
	ctx, opened := gated(t)
	_, err := Run(ctx, testRosterPath(t), lock.ObjectKey{TargetID: "t", Kind: "storage", ID: "local-lvm"}, op, false)
	if err == nil || dispatch.IsRefused(err) || !opened() {
		t.Fatalf("Run = %v (gate %v), want a plain error after the DELETE was attempted", err, opened())
	}
}
