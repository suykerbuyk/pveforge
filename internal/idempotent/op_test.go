package idempotent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// fakeOp is a scriptable Op, used to test Run's own orchestration logic
// in isolation from any PVE specifics (VMTagEnsure's own tests cover the
// concrete proof case).
type fakeOp struct {
	readResults []string // indexed by call number; a call past the end repeats the last entry
	readErrs    []error
	readCalls   int

	satisfiedFunc func(current string) bool

	applyErrs  []error // indexed by call number; a call past the end succeeds
	applyCalls int

	// applyBlock, if set, is read from before Apply returns — used to
	// prove Run holds its lock across a slow Apply.
	applyBlock <-chan struct{}
}

func (o *fakeOp) Read(_ context.Context) (string, error) {
	idx := o.readCalls
	o.readCalls++
	if idx < len(o.readErrs) && o.readErrs[idx] != nil {
		return "", o.readErrs[idx]
	}
	if len(o.readResults) == 0 {
		return "", nil
	}
	if idx >= len(o.readResults) {
		idx = len(o.readResults) - 1
	}
	return o.readResults[idx], nil
}

func (o *fakeOp) Satisfied(current string) bool {
	if o.satisfiedFunc != nil {
		return o.satisfiedFunc(current)
	}
	return false
}

func (o *fakeOp) Apply(_ context.Context) error {
	if o.applyBlock != nil {
		<-o.applyBlock
	}
	idx := o.applyCalls
	o.applyCalls++
	if idx < len(o.applyErrs) {
		return o.applyErrs[idx]
	}
	return nil
}

func testKey() lock.ObjectKey {
	return lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
}

func TestRun_NoOpWhenSatisfied(t *testing.T) {
	op := &fakeOp{readResults: []string{"a;b"}, satisfiedFunc: func(string) bool { return true }}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected Changed=false for a satisfied op")
	}
	if op.applyCalls != 0 {
		t.Error("Apply must not run when Satisfied is true and force is false")
	}
	if res.Before != "a;b" || res.After != "a;b" {
		t.Errorf("Before/After = %q/%q, want a;b/a;b", res.Before, res.After)
	}
}

func TestRun_AppliesWhenNotSatisfied(t *testing.T) {
	op := &fakeOp{
		readResults:   []string{"a", "a;b"}, // before, after
		satisfiedFunc: func(s string) bool { return s == "a;b" },
	}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if op.applyCalls != 1 {
		t.Errorf("expected exactly one Apply call, got %d", op.applyCalls)
	}
	if res.Before != "a" || res.After != "a;b" {
		t.Errorf("Before/After = %q/%q, want a/a;b", res.Before, res.After)
	}
}

func TestRun_ForceBypassesNoOp(t *testing.T) {
	op := &fakeOp{readResults: []string{"a;b"}, satisfiedFunc: func(string) bool { return true }}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, true)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true when force bypasses an already-satisfied check")
	}
	if op.applyCalls != 1 {
		t.Errorf("expected Apply to run once under force, got %d calls", op.applyCalls)
	}
}

func TestRun_ReadFailurePropagates(t *testing.T) {
	op := &fakeOp{readErrs: []error{errors.New("network down")}}

	_, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err == nil {
		t.Fatal("expected an error when Read fails")
	}
	if op.applyCalls != 0 {
		t.Error("Apply must not run when Read failed")
	}
}

func TestRun_ApplyFailurePropagates(t *testing.T) {
	op := &fakeOp{
		readResults:   []string{"a"},
		satisfiedFunc: func(string) bool { return false },
		applyErrs:     []error{errors.New("write rejected")},
	}

	_, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err == nil {
		t.Fatal("expected an error when Apply fails")
	}
	if op.readCalls != 1 {
		t.Errorf("a non-conflict Apply failure must not trigger a retry (extra Read), got %d Read calls", op.readCalls)
	}
}

func TestRun_RetriesOnConflictThenSucceeds(t *testing.T) {
	op := &fakeOp{
		readResults:   []string{"a", "a", "a;b"}, // attempt1 read, attempt2 read, final re-read for After
		satisfiedFunc: func(s string) bool { return s == "a;b" },
		applyErrs:     []error{fmt.Errorf("wrap: %w", ErrConflict), nil},
	}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true after a successful retry")
	}
	if op.applyCalls != 2 {
		t.Errorf("expected exactly 2 Apply calls (1 conflict + 1 success), got %d", op.applyCalls)
	}
	if op.readCalls != 3 {
		t.Errorf("expected 3 Read calls (2 attempts + 1 final re-read), got %d", op.readCalls)
	}
}

// TestRun_ConflictRetryReDiscoversSatisfied proves Run's retry re-runs the
// WHOLE cycle (Read + Satisfied), not just Apply: if a conflicting
// concurrent writer turns out to have already made the exact change this
// Op wanted, the retry's own Satisfied check must catch that and no-op
// rather than blindly re-Applying.
func TestRun_ConflictRetryReDiscoversSatisfied(t *testing.T) {
	op := &fakeOp{
		readResults:   []string{"a", "a;b"}, // attempt1: not yet satisfied; attempt2 (retry): now satisfied
		satisfiedFunc: func(s string) bool { return s == "a;b" },
		applyErrs:     []error{fmt.Errorf("wrap: %w", ErrConflict)},
	}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected Changed=false: the retry's own Read discovered the desired state already applied")
	}
	if op.applyCalls != 1 {
		t.Errorf("expected exactly 1 Apply call (the one that conflicted) — no second Apply once retry finds it already satisfied, got %d", op.applyCalls)
	}
}

func TestRun_GivesUpAfterMaxConflictRetries(t *testing.T) {
	conflictErr := fmt.Errorf("wrap: %w", ErrConflict)
	op := &fakeOp{
		readResults:   []string{"a"},
		satisfiedFunc: func(string) bool { return false },
		applyErrs:     []error{conflictErr, conflictErr, conflictErr, conflictErr, conflictErr},
	}

	_, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected the final error to still wrap ErrConflict, got: %v", err)
	}
	if op.applyCalls != maxConflictRetries {
		t.Errorf("expected exactly maxConflictRetries (%d) Apply calls, got %d", maxConflictRetries, op.applyCalls)
	}
}

// TestRun_HoldsLockAcrossTheWholeCycle proves Run genuinely serializes via
// internal/lock, not just calls it: a slow Run (Apply blocked) must
// prevent a second Run for the SAME key from making any progress until
// the first completes.
func TestRun_HoldsLockAcrossTheWholeCycle(t *testing.T) {
	roster := testRosterPath(t)
	key := testKey()

	releaseFirst := make(chan struct{})
	firstOp := &fakeOp{
		readResults:   []string{"a"},
		satisfiedFunc: func(string) bool { return false },
		applyBlock:    releaseFirst,
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), roster, key, firstOp, false)
		firstDone <- err
	}()

	// Give the first Run time to acquire the lock and block inside Apply.
	time.Sleep(50 * time.Millisecond)

	secondOp := &fakeOp{readResults: []string{"a"}, satisfiedFunc: func(string) bool { return true }}
	secondDone := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), roster, key, secondOp, false)
		secondDone <- err
	}()

	select {
	case <-secondDone:
		t.Fatal("second Run completed before the first released the lock")
	case <-time.After(100 * time.Millisecond):
		// expected: second Run is still blocked
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Run: %v", err)
	}
}
