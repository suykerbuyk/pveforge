package idempotent

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	if res.AfterErr != nil {
		t.Errorf("AfterErr = %v, want nil: a no-op never re-reads", res.AfterErr)
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
	if res.AfterErr != nil {
		t.Errorf("AfterErr = %v, want nil: the final re-read succeeded", res.AfterErr)
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
	if res.After != "a;b" || res.AfterErr != nil {
		t.Errorf("After/AfterErr = %q/%v, want a;b/nil: the retry's final re-read succeeded", res.After, res.AfterErr)
	}
}

// TestRun_ReReadFailureSetsAfterErr: when Apply succeeds but the final
// re-read fails, Run still succeeds (the mutation happened) but must not
// pass Before off as re-observed state — AfterErr carries the read's own
// cause, reachable with errors.Is, and After keeps Before's value.
func TestRun_ReReadFailureSetsAfterErr(t *testing.T) {
	cause := errors.New("re-read: connection reset")
	op := &fakeOp{
		readResults:   []string{"a"},
		readErrs:      []error{nil, cause}, // attempt read ok, final re-read fails
		satisfiedFunc: func(string) bool { return false },
	}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v (a failed re-read must not fail an applied mutation)", err)
	}
	if !res.Changed || op.applyCalls != 1 || op.readCalls != 2 {
		t.Fatalf("Changed=%v applyCalls=%d readCalls=%d, want true/1/2", res.Changed, op.applyCalls, op.readCalls)
	}
	if !errors.Is(res.AfterErr, cause) {
		t.Fatalf("AfterErr = %v, want it to wrap the re-read's cause", res.AfterErr)
	}
	if !strings.Contains(res.AfterErr.Error(), testKey().String()) {
		t.Errorf("AfterErr = %q, want it to name the object key %s", res.AfterErr, testKey())
	}
	if res.Before != "a" || res.After != "a" {
		t.Errorf("Before/After = %q/%q, want a/a (After falls back to Before)", res.Before, res.After)
	}
}

// TestRun_ReReadFailureAfterConflictRetry: the AfterErr assignment
// survives a conflict retry and describes the LATEST cycle — After is
// attempt 2's Before, not attempt 1's.
func TestRun_ReReadFailureAfterConflictRetry(t *testing.T) {
	cause := errors.New("re-read: connection reset")
	op := &fakeOp{
		readResults:   []string{"a", "a2"}, // attempt1 read, attempt2 read; call 3 errors
		readErrs:      []error{nil, nil, cause},
		satisfiedFunc: func(string) bool { return false },
		applyErrs:     []error{fmt.Errorf("wrap: %w", ErrConflict), nil},
	}

	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed || op.applyCalls != 2 || op.readCalls != 3 {
		t.Fatalf("Changed=%v applyCalls=%d readCalls=%d, want true/2/3", res.Changed, op.applyCalls, op.readCalls)
	}
	if !errors.Is(res.AfterErr, cause) {
		t.Fatalf("AfterErr = %v, want it to wrap the final re-read's cause", res.AfterErr)
	}
	if res.Before != "a2" || res.After != "a2" {
		t.Errorf("Before/After = %q/%q, want a2/a2 (attempt 2's own Before)", res.Before, res.After)
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

// holdCheckOp is an Op whose Apply outlasts the lock-wait bound and records
// whether the ctx Read and Apply ran under carried a deadline or ended.
type holdCheckOp struct {
	hold          time.Duration
	sawDeadline   bool
	ctxErrAtApply error
}

func (o *holdCheckOp) Read(ctx context.Context) (string, error) {
	if _, ok := ctx.Deadline(); ok {
		o.sawDeadline = true
	}
	return "a", nil
}

func (o *holdCheckOp) Satisfied(string) bool { return false }

func (o *holdCheckOp) Apply(ctx context.Context) error {
	if _, ok := ctx.Deadline(); ok {
		o.sawDeadline = true
	}
	time.Sleep(o.hold)
	o.ctxErrAtApply = ctx.Err()
	return nil
}

// TestRun_WaitBoundDoesNotReachHold: lock.WithWait bounds acquiring the lock
// only. A cycle that holds the lock far longer than the bound must run to
// completion under a ctx with no deadline.
func TestRun_WaitBoundDoesNotReachHold(t *testing.T) {
	op := &holdCheckOp{hold: 200 * time.Millisecond}
	ctx := lock.WithWait(context.Background(), 50*time.Millisecond)

	res, err := Run(ctx, testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected the Apply to have run")
	}
	if op.sawDeadline {
		t.Error("Read or Apply ran under a deadline: the lock-wait bound leaked into the hold")
	}
	if op.ctxErrAtApply != nil {
		t.Errorf("the ctx ended during a hold longer than the lock-wait bound: %v", op.ctxErrAtApply)
	}
}
