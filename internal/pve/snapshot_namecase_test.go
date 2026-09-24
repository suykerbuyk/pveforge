package pve

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
)

// pveforge-snapshot-reserved-name-case: the destructive paths refuse only
// the "current" pseudo-entry itself, so a real snapshot named "Current" —
// legal in PVE by a reading of its source (see isPseudoEntryName) — is
// reachable: it can be deleted, rolled back to and asked about.

// chainAlphaCurrent is alpha, then a REAL snapshot named "Current", beside
// PVE's own "current" pseudo-entry.
const chainAlphaCurrent = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"alpha","snaptime":1700000000,"vmstate":1,"parent":"current"},
	{"name":"Current","snaptime":1700003600,"vmstate":1,"parent":"alpha"}
]}`

// chainAlphaCurrentBravo adds bravo, newer than "Current".
const chainAlphaCurrentBravo = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"alpha","snaptime":1700000000,"vmstate":1,"parent":"current"},
	{"name":"Current","snaptime":1700003600,"vmstate":1,"parent":"alpha"},
	{"name":"bravo","snaptime":1700007200,"vmstate":1,"parent":"Current"}
]}`

// S1: the dead end is gone. A rollback to alpha is refused because the real
// "Current" is newer; passing that refusal's CascadeOrder() to
// CascadeDeleteSnapshots deletes exactly "Current"; the rollback to alpha
// then goes through.
func TestSnapshotNameCase_S1_ACurrentSnapshotCanBeClearedForARollback(t *testing.T) {
	// List reads in order: Rollback's newest-check; the cascade's pre-state
	// and post-verify; the second Rollback's newest-check.
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainAlphaCurrent, chainAlphaCurrent, chainA, chainA)
	ctx := context.Background()

	err := c.Rollback(ctx, "qa-pve-01", rbVMID, "alpha")
	var notNewest *ErrNotNewestSnapshot
	if !errors.As(err, &notNewest) || !slices.Equal(notNewest.Newer, []string{"Current"}) {
		t.Fatalf("Rollback(alpha) = %v, want ErrNotNewestSnapshot{Newer: [Current]}", err)
	}

	deleted, err := c.CascadeDeleteSnapshots(ctx, "qa-pve-01", rbVMID, notNewest.CascadeOrder())
	if err != nil {
		t.Fatalf("CascadeDeleteSnapshots(%q): %v — a real \"Current\" must be deletable", notNewest.CascadeOrder(), err)
	}
	if !slices.Equal(deleted, []string{"Current"}) {
		t.Errorf("deleted = %q, want [Current]", deleted)
	}
	if _, _, seq := f.recorded(); !slices.Equal(seq, []string{"Current"}) {
		t.Errorf("DELETEs sent for %q, want exactly [Current]", seq)
	}

	if err := c.Rollback(ctx, "qa-pve-01", rbVMID, "alpha"); err != nil {
		t.Fatalf("Rollback(alpha) after the cascade: %v", err)
	}
	if paths, _, _ := f.recorded(); len(paths) != 1 || paths[0] != "/nodes/qa-pve-01/qemu/4242/snapshot/alpha/rollback" {
		t.Errorf("rollback POSTs = %q, want exactly one, to alpha", paths)
	}
}

// S2: "Current" is a real target: NewerSnapshots answers what is newer than
// it, and a rollback to it (nothing newer) is sent to its own path.
func TestSnapshotNameCase_S2_ACurrentSnapshotIsAValidTarget(t *testing.T) {
	_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainAlphaCurrentBravo)
	newer, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "Current")
	if err != nil {
		t.Fatalf("NewerSnapshots(Current): %v", err)
	}
	if len(newer) != 1 || newer[0].Name != "bravo" {
		t.Errorf("newer than Current = %v, want [bravo]", newer)
	}

	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainAlphaCurrent)
	if err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "Current"); err != nil {
		t.Fatalf("Rollback(Current): %v", err)
	}
	if paths, _, _ := f.recorded(); len(paths) != 1 || paths[0] != "/nodes/qa-pve-01/qemu/4242/snapshot/Current/rollback" {
		t.Errorf("rollback POSTs = %q, want exactly one, to Current", paths)
	}
}

// S3 is the narrowed pinned set: TestRollback_ReservedNameNeverTouchesAnyEndpoint,
// TestNewerSnapshots_RequiresNodeAndTarget's reserved row,
// TestCascadeDeleteSnapshots_ReservedNameNeverTouchesAnyEndpoint and
// TestReservedNameRefusal_CarriesVMIDAndName still refuse "current" and its
// padded forms with zero requests. S4 is CreateSnapshot's pinned
// case-insensitive set, unchanged: TestCreateSnapshot_ReservedNameIsCaseInsensitive
// and TestCreateSnapshot_ReservedNameIgnoresSurroundingWhitespace.

// S5: a case variant of "current" that is NOT a snapshot on the VM is
// neither refused as reserved nor acted on: the destructive paths find
// nothing by that name after one verifiable list read, and send nothing
// destructive.
func TestSnapshotNameCase_S5_AnAbsentCaseVariantIsNotFoundNotReserved(t *testing.T) {
	ctx := context.Background()
	var reserved *ErrReservedSnapshotName

	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	if _, err := c.NewerSnapshots(ctx, "qa-pve-01", rbVMID, "CURRENT"); err == nil || errors.As(err, &reserved) {
		t.Errorf("NewerSnapshots(CURRENT) = %v, want not-found, not reserved", err)
	}
	if err := c.Rollback(ctx, "qa-pve-01", rbVMID, "CURRENT"); err == nil || errors.As(err, &reserved) {
		t.Errorf("Rollback(CURRENT) = %v, want not-found, not reserved", err)
	}
	deleted, err := c.CascadeDeleteSnapshots(ctx, "qa-pve-01", rbVMID, []string{"CURRENT"})
	if errors.As(err, &reserved) || len(deleted) != 0 {
		t.Errorf("CascadeDeleteSnapshots(CURRENT) = %q, %v; want nothing deleted, not reserved", deleted, err)
	}
	if n := atomic.LoadInt32(&f.rollbackCalls) + atomic.LoadInt32(&f.deleteCalls); n != 0 {
		t.Errorf("%d destructive request(s) sent for an absent name", n)
	}
	if atomic.LoadInt32(&f.listCalls) == 0 {
		t.Error("no list read: the absence was not checked against PVE")
	}
}
