package idempotent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// postApplyOp is a fakeOp that is also a PostApplier. It counts its
// PostApply calls, records how many Reads had happened by then (so a test
// can see it ran after the final re-read), and runs check, if set, inside
// PostApply.
type postApplyOp struct {
	fakeOp
	postErr         error
	postCalls       int
	readsAtPost     int
	checkInsidePost func(ctx context.Context)
}

func (o *postApplyOp) PostApply(ctx context.Context) error {
	o.postCalls++
	o.readsAtPost = o.readCalls
	if o.checkInsidePost != nil {
		o.checkInsidePost(ctx)
	}
	return o.postErr
}

var _ PostApplier = (*postApplyOp)(nil)

// TestRun_PostApply_CalledOnceOnlyAfterASuccessfulApply (T1): PostApply runs
// exactly once, after the final re-read, when Apply succeeded — including
// after a conflict retry that then succeeded — and never on a no-op or after
// a failed Apply.
func TestRun_PostApply_CalledOnceOnlyAfterASuccessfulApply(t *testing.T) {
	for name, tc := range map[string]struct {
		op        *postApplyOp
		wantCalls int
		wantErr   bool
	}{
		"applied": {op: &postApplyOp{fakeOp: fakeOp{readResults: []string{"a", "b"}}}, wantCalls: 1},
		"no-op": {op: &postApplyOp{fakeOp: fakeOp{readResults: []string{"a"},
			satisfiedFunc: func(string) bool { return true }}}, wantCalls: 0},
		"apply failed": {op: &postApplyOp{fakeOp: fakeOp{readResults: []string{"a"},
			applyErrs: []error{errors.New("boom")}}}, wantCalls: 0, wantErr: true},
		"conflict then success": {op: &postApplyOp{fakeOp: fakeOp{readResults: []string{"a", "a2", "b"},
			applyErrs: []error{fmt.Errorf("wrap: %w", ErrConflict), nil}}}, wantCalls: 1},
		"conflict every time": {op: &postApplyOp{fakeOp: fakeOp{readResults: []string{"a"},
			applyErrs: []error{ErrConflict, ErrConflict, ErrConflict, ErrConflict}}}, wantCalls: 0, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Run(context.Background(), testRosterPath(t), testKey(), tc.op, false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Run err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.op.postCalls != tc.wantCalls {
				t.Errorf("PostApply called %d times, want %d", tc.op.postCalls, tc.wantCalls)
			}
			if tc.wantCalls == 1 && tc.op.readsAtPost != tc.op.readCalls {
				t.Errorf("PostApply ran after %d of %d reads, want after the final re-read", tc.op.readsAtPost, tc.op.readCalls)
			}
		})
	}
}

// TestRun_PostApply_RunsUnderTheLock (T2): PostApply runs while Run still
// holds the object's lock, so no other pveforge mutation of the object can
// land between Apply and the check.
func TestRun_PostApply_RunsUnderTheLock(t *testing.T) {
	roster := testRosterPath(t)
	var lockErr error
	op := &postApplyOp{
		fakeOp: fakeOp{readResults: []string{"a", "b"}},
		checkInsidePost: func(context.Context) {
			unlock, err := lock.Mutation(lock.WithWait(context.Background(), 20*time.Millisecond), roster, testKey())
			if err == nil {
				_ = unlock()
			}
			lockErr = err
		},
	}
	if _, err := Run(context.Background(), roster, testKey(), op, false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if op.postCalls != 1 {
		t.Fatalf("PostApply called %d times, want 1", op.postCalls)
	}
	if !errors.Is(lockErr, lock.ErrLockWaitTimeout) {
		t.Errorf("taking the object's lock inside PostApply gave %v, want ErrLockWaitTimeout: Run must still hold it", lockErr)
	}
}

// TestRun_PostApply_ErrorIsAdvisory (T3): a failed PostApply is reported in
// Result.PostApplyErr, wrapping its cause, and fails nothing: Run returns
// nil, Changed is true, and After is the re-read state.
func TestRun_PostApply_ErrorIsAdvisory(t *testing.T) {
	cause := errors.New("pending read: connection reset")
	op := &postApplyOp{fakeOp: fakeOp{readResults: []string{"a", "b"}}, postErr: cause}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil {
		t.Fatalf("Run = %v: a failed post-apply check must not fail an applied mutation", err)
	}
	if !res.Changed || res.Before != "a" || res.After != "b" || res.AfterErr != nil {
		t.Errorf("Result = %+v, want Changed with Before a, After b, no AfterErr", res)
	}
	if !errors.Is(res.PostApplyErr, cause) {
		t.Fatalf("PostApplyErr = %v, want it to wrap the check's cause", res.PostApplyErr)
	}
	if want := "idempotent: " + testKey().String() + ": post-apply check: " + cause.Error(); res.PostApplyErr.Error() != want {
		t.Errorf("PostApplyErr = %q, want %q", res.PostApplyErr, want)
	}
}

// TestRun_PostApply_AbsentOrCleanLeavesResultAsBefore (T4): an Op that is
// not a PostApplier gets exactly today's Result, and a PostApplier whose
// check passes adds nothing to it.
func TestRun_PostApply_AbsentOrCleanLeavesResultAsBefore(t *testing.T) {
	want := Result{Changed: true, Before: "a", After: "b"}

	plain := &fakeOp{readResults: []string{"a", "b"}}
	if _, ok := Op(plain).(PostApplier); ok {
		t.Fatal("fakeOp must not be a PostApplier for this test to mean anything")
	}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), plain, false)
	if err != nil || res != want {
		t.Errorf("non-PostApplier: Result = %+v, %v; want %+v, nil", res, err, want)
	}

	clean := &postApplyOp{fakeOp: fakeOp{readResults: []string{"a", "b"}}}
	res, err = Run(context.Background(), testRosterPath(t), testKey(), clean, false)
	if err != nil || res != want || clean.postCalls != 1 {
		t.Errorf("passing PostApplier: Result = %+v, %v, %d calls; want %+v, nil, 1 call", res, err, clean.postCalls, want)
	}
}
