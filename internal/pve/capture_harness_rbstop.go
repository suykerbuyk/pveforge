//go:build harness

// U-RBSTOP rollback run-state proof (pveforge-snapshot-rollback-lifecycle §6).
// Authored-but-not-run leg: compiled only under `-tags harness`, driven by the
// Chair against a live nested `pvh` guest, NOT by `make check`. It settles the
// ONE physical fact the fakes cannot — what run-state PVE's rollback (with the
// `start` parameter omitted, as Rollback sends it) actually leaves the guest in
// — which the CLI's run-state-aware witness decider keys on:
//
//   - running leg      (vmstate=1 snapshot of a RUNNING guest): expect the guest
//     up afterward and the witness to PASS.
//   - stopped leg      (vmstate=0 snapshot of an ALREADY-STOPPED guest): expect
//     the guest stopped afterward; no witness.
//   - finalizing leg   (vmstate=0 snapshot of a RUNNING guest): OBSERVE the
//     guest's actual run-state afterward. This DECIDES the
//     `|| guestRunningBeforeRollback` term in
//     cmd/pveforge/vmsnapshot.go's targetSnapshotWitnessPlan:
//     running-after ⇒ the conservative decider is correct;
//     stopped-after ⇒ drop the `|| wasRunning` term.
//
// The caller owns the disposable guest (create/start/stop and final destroy),
// as RunVmstateCapture does; this instrument creates the snapshot it tests,
// rolls back through the production Rollback primitive, reads run-state through
// GetVM, witnesses through RollbackWitness, and best-effort deletes the snapshot
// it made. Stay on the disposable nested tier (690–699).
package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// RollbackRunStateCapture records the observed run-state across a rollback.
type RollbackRunStateCapture struct {
	Node          string
	VMID          int
	Snap          string
	WantVmstate   bool // the vmstate the snapshot was created with
	GotVmstate    bool // what the snapshot list reported (verifies the setup)
	RunningBefore bool // GetVM status == "running" before the rollback
	RunningAfter  bool // GetVM status == "running" after the rollback
	WitnessTried  bool
	WitnessProven bool
	WitnessErr    string
	SnapDeleteErr string // best-effort cleanup note, non-fatal
}

// CaptureRollbackRunState snapshots vmid with the requested vmstate, rolls back
// to it via the production Rollback, and records the guest's run-state before
// and after plus a witness attempt when the guest is running afterward. It
// returns an error (fail-closed) on any read/snapshot/rollback failure; the
// witness outcome and run-state are DATA on the returned capture, not errors —
// the driver's gate interprets them per leg.
func (c *Client) CaptureRollbackRunState(ctx context.Context, node string, vmid int, snap string, wantVmstate bool, witnessCmd []string, wantMarker string, timeout time.Duration) (*RollbackRunStateCapture, error) {
	if node == "" || vmid < 1 || snap == "" {
		return nil, fmt.Errorf("rbstop proof: node, a positive vmid and a snap name are required")
	}
	out := &RollbackRunStateCapture{Node: node, VMID: vmid, Snap: snap, WantVmstate: wantVmstate}

	before, err := c.GetVM(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("rbstop proof: read run-state before: %w", err)
	}
	out.RunningBefore = before.Status == "running"

	// Create the snapshot with the chosen vmstate. CreateSnapshot always sends
	// vmstate=1, so a vmstate=0 snapshot must be POSTed raw.
	params := url.Values{"snapname": {snap}}
	if wantVmstate {
		params.Set("vmstate", "1")
	} else {
		params.Set("vmstate", "0")
	}
	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", url.PathEscape(node), vmid), params)
	if err != nil {
		return nil, fmt.Errorf("rbstop proof: create snapshot %q (vmstate=%v): %w", snap, wantVmstate, err)
	}
	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return nil, fmt.Errorf("rbstop proof: create snapshot %q: %w", snap, err)
	}
	if err := c.WaitForTask(ctx, node, upid); err != nil {
		return nil, fmt.Errorf("rbstop proof: create snapshot %q: %w", snap, err)
	}
	// Verify the setup: the created snapshot's vmstate flag is what we asked for.
	snaps, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("rbstop proof: verify snapshot %q: %w", snap, err)
	}
	for _, s := range realSnapshots(snaps) {
		if s.Name == snap {
			out.GotVmstate = s.Vmstate != 0
		}
	}
	if out.GotVmstate != wantVmstate {
		return nil, fmt.Errorf("rbstop proof: snapshot %q vmstate=%v, wanted %v (setup did not take)", snap, out.GotVmstate, wantVmstate)
	}

	// The primitive under test, exactly as the CLI calls it (no `start`).
	if err := c.Rollback(ctx, node, vmid, snap); err != nil {
		return nil, fmt.Errorf("rbstop proof: rollback to %q: %w", snap, err)
	}

	after, err := c.GetVM(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("rbstop proof: read run-state after: %w", err)
	}
	out.RunningAfter = after.Status == "running"

	// Witness only when the guest is actually running afterward — the physical
	// question the running/finalizing legs answer.
	if out.RunningAfter {
		out.WitnessTried = true
		if _, werr := c.RollbackWitness(ctx, node, vmid, witnessCmd, wantMarker, timeout); werr != nil {
			out.WitnessErr = werr.Error()
		} else {
			out.WitnessProven = true
		}
	}

	// Best-effort cleanup of the snapshot this proof created (non-fatal).
	if _, derr := c.CascadeDeleteSnapshots(ctx, node, vmid, []string{snap}); derr != nil {
		out.SnapDeleteErr = derr.Error()
	}
	return out, nil
}
