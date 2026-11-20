package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// The literals below are deliberately NOT the package constants: a test that
// compared runRoot's status to exitOutcomeUnknown would pass with the two
// constants swapped (the README test, which holds only the SET of numbers,
// passes too). 3 and 4 are the public contract, so they are written here.

// interruptNote is what runRoot appends for a signal that interrupted a
// command that may have changed something.
const interruptNote = "any change the command had already sent may or may not have been applied"

// X1, X2, X3, X7: through runRoot, each kind of error exits its own status,
// and the plain-error row sits in the same table so "3 and 4 are emitted" and
// "nothing else is" are one observation.
func TestExitStatus_X1X2X3X7_EachErrorKindExitsItsOwnStatus(t *testing.T) {
	cause := errors.New("the cause")
	failed := &pve.TaskFailedError{UPID: "UPID:n:1:2:3:t:i:u:", ExitStatus: "ERROR: x"}
	for _, c := range []struct {
		name string
		err  error
		want int
	}{
		{"plain error", cause, 1},
		{"task failed", failed, 1},
		{"outcome unknown", newOutcomeUnknownError(cause), 3},
		{"refused", newRefusedError(cause), 4},
		{"unknown wrapping a failed task is still unknown", newOutcomeUnknownError(failed), 3},
		{"refused wrapping a plain error", newRefusedError(fmt.Errorf("gate: %w", cause)), 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runRootFailing(t, c.err, nil)
			if code != c.want {
				t.Errorf("exit %d, want %d (stderr %q)", code, c.want, stderr)
			}
			if got := decodeErrText(t, oneLine(t, stderr)); got != c.err.Error() {
				t.Errorf("stderr text %q, want the error's own text %q", got, c.err.Error())
			}
		})
	}
	// A usage error never reaches a command: still 1.
	if code, _, _ := runRootArgs("no-such-subcommand"); code != 1 {
		t.Errorf("usage error exit %d, want 1", code)
	}
}

// X4: classification survives wrapping above the typed error, by %w and by
// errors.Join; wrapping by %v (which drops the chain) is NOT classified, so
// the fixture below cannot be what makes a row pass.
func TestExitStatus_X4_WrappingAboveTheTypedError(t *testing.T) {
	cause := errors.New("c")
	for _, c := range []struct {
		name string
		err  error
		want int
	}{
		{"unknown %w", fmt.Errorf("outer: %w", newOutcomeUnknownError(cause)), 3},
		{"unknown %w twice", fmt.Errorf("a: %w", fmt.Errorf("b: %w", newOutcomeUnknownError(cause))), 3},
		{"unknown joined", errors.Join(errors.New("other"), newOutcomeUnknownError(cause)), 3},
		{"refused %w", fmt.Errorf("outer: %w", newRefusedError(cause)), 4},
		{"refused joined", errors.Join(errors.New("other"), newRefusedError(cause)), 4},
		{"control: unknown flattened with %v", fmt.Errorf("outer: %v", newOutcomeUnknownError(cause)), 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code, stderr := runRootFailing(t, c.err, nil); code != c.want {
				t.Errorf("exit %d, want %d (stderr %q)", code, c.want, stderr)
			}
		})
	}
}

// X5: a signal beats 3 and 4's neighbour: an UNKNOWN error under a root whose
// context was cancelled with an interruptError cause exits 130/143 and keeps
// runRoot's note. The cause's type is what the interrupt block reads, so the
// fixture cancels with exactly that type; a plain context.Canceled would let 3
// win for the wrong reason (control row).
func TestExitStatus_X5_ASignalBeatsOutcomeUnknown(t *testing.T) {
	for _, c := range []struct {
		sig  syscall.Signal
		name string
		want int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runRootFailing(t, newOutcomeUnknownError(errors.New("wait ended")), func(cancel context.CancelCauseFunc) {
				cancel(interruptError{sig: c.sig})
			})
			if code != c.want {
				t.Fatalf("exit %d, want %d (stderr %q)", code, c.want, stderr)
			}
			got := decodeErrText(t, oneLine(t, stderr))
			if want := "interrupted (" + c.name + "): wait ended; " + interruptNote; got != want {
				t.Errorf("stderr %q, want %q", got, want)
			}
		})
	}
	code, _ := runRootFailing(t, newOutcomeUnknownError(errors.New("wait ended")), func(cancel context.CancelCauseFunc) {
		cancel(errors.New("a cancel that is not a signal"))
	})
	if code != 3 {
		t.Errorf("control: a non-signal cancel exit %d, want 3", code)
	}
}

// X6 (Chair ruling D2): a signal also beats REFUSED for the status, but the
// note that a change may have been applied is not printed: a refusal
// dispatched nothing.
func TestExitStatus_X6_ASignalBeatsRefusedWithoutTheFalseNote(t *testing.T) {
	for _, c := range []struct {
		sig  syscall.Signal
		name string
		want int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		t.Run(c.name, func(t *testing.T) {
			code, stderr := runRootFailing(t, newRefusedError(errors.New("a destroy is in flight")), func(cancel context.CancelCauseFunc) {
				cancel(interruptError{sig: c.sig})
			})
			if code != c.want {
				t.Fatalf("exit %d, want %d (stderr %q)", code, c.want, stderr)
			}
			got := decodeErrText(t, oneLine(t, stderr))
			if strings.Contains(got, "may or may not have been applied") {
				t.Errorf("a refusal dispatched nothing, but stderr says a change may have been applied: %q", got)
			}
			if got != "a destroy is in flight" {
				t.Errorf("stderr %q, want the refusal's own text", got)
			}
		})
	}
}

// F1: the constructors are the only construction path. Their output is
// classified; a POINTER to the wrapper is a different type to errors.As and
// exits 1. That is pinned on purpose, so a caller (U6) who writes
// &outcomeUnknownError{...} gets a red test instead of a silent exit 1.
func TestExitStatus_F1_OnlyTheValueFormClassifies(t *testing.T) {
	cause := errors.New("c")
	if code, _ := runRootFailing(t, newOutcomeUnknownError(cause), nil); code != 3 {
		t.Errorf("newOutcomeUnknownError: exit %d, want 3", code)
	}
	if code, _ := runRootFailing(t, newRefusedError(cause), nil); code != 4 {
		t.Errorf("newRefusedError: exit %d, want 4", code)
	}
	if code, _ := runRootFailing(t, &outcomeUnknownError{error: cause}, nil); code != 1 {
		t.Errorf("a pointer to outcomeUnknownError: exit %d, want 1 (only the constructor's value form classifies)", code)
	}
	if code, _ := runRootFailing(t, &refusedError{error: cause}, nil); code != 1 {
		t.Errorf("a pointer to refusedError: exit %d, want 1 (only the constructor's value form classifies)", code)
	}
}

// X8 + F2: the wrappers are transparent. The cause is longer than
// maxErrTextBytes, multi-line and multi-byte UTF-8, so the bound, the cut on a
// rune boundary and the quoting all act on it. The wrapper's text is the
// cause's byte for byte, and what runRoot prints for the wrapper is
// byte-identical to what it prints for the raw cause; the chain still reaches
// the cause.
func TestExitStatus_X8F2_TheWrappersAreTransparent(t *testing.T) {
	raw := errors.New(strings.Repeat("ünï\ncode ✓ ", maxErrTextBytes/4) + "tail")
	if len(raw.Error()) <= maxErrTextBytes || !utf8.ValidString(raw.Error()) || !strings.Contains(raw.Error(), "\n") {
		t.Fatalf("fixture is not long, multi-line UTF-8 text: %d bytes", len(raw.Error()))
	}
	_, rawStderr := runRootFailing(t, raw, nil)
	for _, c := range []struct {
		name string
		err  error
		want int
	}{{"unknown", newOutcomeUnknownError(raw), 3}, {"refused", newRefusedError(raw), 4}} {
		t.Run(c.name, func(t *testing.T) {
			if c.err.Error() != raw.Error() {
				t.Errorf("Error() differs from the cause's text")
			}
			if !errors.Is(c.err, raw) {
				t.Errorf("errors.Is does not reach the cause")
			}
			code, stderr := runRootFailing(t, c.err, nil)
			if code != c.want {
				t.Errorf("exit %d, want %d", code, c.want)
			}
			if stderr != rawStderr {
				t.Errorf("stderr differs from the raw cause's: %d bytes vs %d", len(stderr), len(rawStderr))
			}
		})
	}
	// The transparency the api wrapper relies on: pve's own classifiers still
	// see through it.
	wrapped := newOutcomeUnknownError(fmt.Errorf("wait: %w", context.DeadlineExceeded))
	if !errors.Is(wrapped, context.DeadlineExceeded) {
		t.Errorf("errors.Is(context.DeadlineExceeded) lost through the wrapper")
	}
}

// Both constructors refuse a nil cause, loudly and at the constructor.
func TestExitStatus_ConstructorsPanicOnNil(t *testing.T) {
	for _, c := range []struct {
		name string
		f    func(error) error
		want string
	}{
		{"unknown", newOutcomeUnknownError, "newOutcomeUnknownError: nil error"},
		{"refused", newRefusedError, "newRefusedError: nil error"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if got := fmt.Sprint(recover()); got != c.want {
					t.Errorf("panic %q, want %q", got, c.want)
				}
			}()
			c.f(nil)
			t.Errorf("no panic for a nil cause")
		})
	}
}

// Outcome-unknown wins whenever an outcomeUnknownError is anywhere in the
// chain: 3 whichever nesting or joining order, and under a signal 130/143 WITH
// the note (an unobserved dispatch is in the chain, so a change may have been
// applied). Control row: refused alone under the same signal has no note.
func TestExitStatus_Precedence_UnknownWinsOverRefused(t *testing.T) {
	cause := errors.New("c")
	chains := []struct {
		name string
		err  error
	}{
		{"unknown(refused)", newOutcomeUnknownError(newRefusedError(cause))},
		{"refused(unknown)", newRefusedError(newOutcomeUnknownError(cause))},
		{"join unknown,refused", errors.Join(newOutcomeUnknownError(cause), newRefusedError(cause))},
		{"join refused,unknown", errors.Join(newRefusedError(cause), newOutcomeUnknownError(cause))},
		{"refused wrapping a join holding unknown", newRefusedError(errors.Join(errors.New("x"), newOutcomeUnknownError(cause)))},
	}
	for _, c := range chains {
		t.Run(c.name, func(t *testing.T) {
			if code, stderr := runRootFailing(t, c.err, nil); code != 3 {
				t.Errorf("exit %d, want 3 (stderr %q)", code, stderr)
			}
			for _, sig := range []struct {
				s    syscall.Signal
				want int
			}{{syscall.SIGINT, 130}, {syscall.SIGTERM, 143}} {
				code, stderr := runRootFailing(t, c.err, func(cancel context.CancelCauseFunc) { cancel(interruptError{sig: sig.s}) })
				if code != sig.want {
					t.Errorf("%v: exit %d, want %d", sig.s, code, sig.want)
				}
				if !strings.Contains(decodeErrText(t, oneLine(t, stderr)), interruptNote) {
					t.Errorf("%v: the may-have-been-applied note is missing: %q", sig.s, stderr)
				}
			}
		})
	}
	_, stderr := runRootFailing(t, newRefusedError(cause), func(cancel context.CancelCauseFunc) { cancel(interruptError{sig: syscall.SIGINT}) })
	if strings.Contains(stderr, "may or may not") {
		t.Errorf("control: a refusal alone printed the note: %q", stderr)
	}
}
