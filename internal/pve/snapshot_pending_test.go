package pve

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// pveforge-snapshot-pending-name-unguarded: "pending" is PVE's other
// reserved snapshot name (see pendingReservedName and its caveat).

// CreateSnapshot refuses "pending" in any case and padded, with
// *ErrReservedSnapshotName and no request at all, and the refusal says why
// in "pending"'s own terms — not "current"'s pseudo-entry explanation,
// which would be false for it.
func TestCreateSnapshot_PendingIsReservedInAnyCase(t *testing.T) {
	for _, name := range []string{"pending", "PENDING", "Pending", " pending\t"} {
		t.Run(name, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)
			err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, name, "")
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("CreateSnapshot(%q) err = %v, want *ErrReservedSnapshotName", name, err)
			}
			if reserved.Name != name || reserved.VMID != 100 {
				t.Errorf("refusal = %+v, want Name %q (as given) and VMID 100", reserved, name)
			}
			if got := atomic.LoadInt32(&f.listCalls) + atomic.LoadInt32(&f.createCalls); got != 0 {
				t.Errorf("%d endpoint(s) reached for %q, want 0", got, name)
			}
			msg := err.Error()
			if !strings.Contains(msg, "pending changes") || strings.Contains(msg, "pseudo-entry") {
				t.Errorf("message = %q: want pending's own reason, not current's", msg)
			}
		})
	}
	// And "current" keeps its own message.
	_, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)
	if err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "current", ""); err == nil || !strings.Contains(err.Error(), "pseudo-entry") {
		t.Errorf("CreateSnapshot(current) = %v, want current's pseudo-entry message", err)
	}
}

// "pending" stays out of the destructive-path guard: PVE never lists a
// snapshot by that name, so NewerSnapshots, Rollback and
// CascadeDeleteSnapshots treat it as an ordinary name — not found after one
// verifiable list read, never refused as reserved, and nothing destructive
// sent.
func TestPendingIsNotReservedOnTheDestructivePaths(t *testing.T) {
	ctx := context.Background()
	var reserved *ErrReservedSnapshotName
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	if _, err := c.NewerSnapshots(ctx, "qa-pve-01", rbVMID, "pending"); err == nil || errors.As(err, &reserved) {
		t.Errorf("NewerSnapshots(pending) = %v, want not-found, not reserved", err)
	}
	if err := c.Rollback(ctx, "qa-pve-01", rbVMID, "pending"); err == nil || errors.As(err, &reserved) {
		t.Errorf("Rollback(pending) = %v, want not-found, not reserved", err)
	}
	if _, err := c.CascadeDeleteSnapshots(ctx, "qa-pve-01", rbVMID, []string{"pending"}); errors.As(err, &reserved) {
		t.Errorf("CascadeDeleteSnapshots(pending) = %v, want it not refused as reserved", err)
	}
	if atomic.LoadInt32(&f.listCalls) == 0 {
		t.Error("no list read: the destructive paths refused pending locally")
	}
	if n := atomic.LoadInt32(&f.rollbackCalls) + atomic.LoadInt32(&f.deleteCalls); n != 0 {
		t.Errorf("%d destructive request(s) for a name that is not on the VM", n)
	}
}
