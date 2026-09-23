package lock

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testSignal is a cancel cause that identifies a signal, the one shape
// ErrLockWaitInterrupted is reported for.
type testSignal struct{ sig os.Signal }

func (s testSignal) Error() string     { return "SIGINT" }
func (s testSignal) Signal() os.Signal { return s.sig }

// TestLockWait_InterruptClassification (B2): only a context cancelled with
// a signal cause is ErrLockWaitInterrupted; every other end of the caller's
// context keeps unit A's text exactly, and the bound running out is
// ErrLockWaitTimeout only.
func TestLockWait_InterruptClassification(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	cancelled := func(cause error) context.Context {
		ctx, cancel := context.WithCancelCause(context.Background())
		time.AfterFunc(30*time.Millisecond, func() { cancel(cause) })
		return ctx
	}

	t.Run("signal cause", func(t *testing.T) {
		cause := testSignal{syscall.SIGINT}
		_, err := Mutation(cancelled(cause), roster, key)
		if !errors.Is(err, ErrLockWaitInterrupted) || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
			t.Fatalf("want ErrLockWaitInterrupted wrapping context.Canceled and the cause, got: %v", err)
		}
		if errors.Is(err, ErrLockWaitTimeout) {
			t.Errorf("an interrupt is not a lock-wait timeout: %v", err)
		}
		want := "lock qa-pve-01/vm/100: interrupted while waiting for the lock (SIGINT); the operation did not start under it: context canceled"
		if err.Error() != want {
			t.Errorf("text = %q, want %q", err.Error(), want)
		}
	})

	// Unit A's contract, byte for byte: the context's own error.
	for name, tc := range map[string]struct {
		ctx  func() context.Context
		want string
	}{
		"plain cancel":     {func() context.Context { return cancelled(nil) }, "lock qa-pve-01/vm/100: acquire resource: context canceled"},
		"non-signal cause": {func() context.Context { return cancelled(errors.New("shutting down")) }, "lock qa-pve-01/vm/100: acquire resource: context canceled"},
		"caller deadline": {func() context.Context {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			t.Cleanup(cancel)
			return ctx
		}, "lock qa-pve-01/vm/100: acquire resource: context deadline exceeded"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Mutation(tc.ctx(), roster, key)
			if errors.Is(err, ErrLockWaitInterrupted) || errors.Is(err, ErrLockWaitTimeout) {
				t.Errorf("only a signal cause is an interrupt, and this is no timeout: %v", err)
			}
			if err == nil || err.Error() != tc.want {
				t.Errorf("text = %v, want exactly %q", err, tc.want)
			}
		})
	}

	t.Run("bound", func(t *testing.T) {
		_, err := Mutation(backstop(t, 30*time.Millisecond), roster, key)
		if !errors.Is(err, ErrLockWaitTimeout) || errors.Is(err, ErrLockWaitInterrupted) {
			t.Errorf("want ErrLockWaitTimeout only, got: %v", err)
		}
		if strings.Contains(err.Error(), "interrupted") {
			t.Errorf("a timeout must not read as an interrupt: %v", err)
		}
	})
}
