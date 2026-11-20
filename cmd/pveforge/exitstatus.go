package main

// The exit statuses a command can choose, beyond 0 (success) and 1 (every
// other failure). runRoot is where an error becomes a status, and an error
// returned from a command's RunE is 1 by the time it gets there unless it is
// one of the types below, so these two statuses are only reachable by
// returning one. They sit next to signal.go's interruptError because they
// are the same mechanism: a type runRoot recognises, mapped to a constant.
//
// The status must be a CONSTANT expression inside runRoot, never a value read
// from the error: TestREADME_ExitStatusesMatchTheCode type-checks runRoot,
// collects every integer constant assigned to its code, and holds that set to
// the README's Exit status table, and it refuses a status it cannot resolve to
// a constant. That is why there are two types and not one carrying a number.
const (
	// exitOutcomeUnknown: this invocation dispatched a change to PVE and did
	// not observe how it ended (a task wait that timed out, was cut short by a
	// poll failure, or could not be started). The change may have been
	// applied, may still be running, or may have failed. Not success, not
	// failure: look it up, or re-run where re-running resolves it.
	exitOutcomeUnknown = 3
	// exitRefused: this invocation dispatched NOTHING. Nothing was changed;
	// wait and re-run.
	exitRefused = 4
)

// outcomeUnknownError marks an error whose change was dispatched and whose
// outcome was not observed; runRoot exits exitOutcomeUnknown for it. It is
// transparent: its text is its cause's, and Unwrap reaches the cause, so
// stderr, boundErrText's input and every errors.Is/As on the cause
// (pve.IsTaskOutcomeUnknown, context.DeadlineExceeded, ...) are exactly what
// they were without it.
type outcomeUnknownError struct{ error }

func (e outcomeUnknownError) Unwrap() error { return e.error }

// refusedError marks an error for which nothing was dispatched; runRoot exits
// exitRefused for it. Transparent in the same way as outcomeUnknownError.
//
// Both embed the error rather than defining Error(): the text is promoted, and
// no `.Error()` call is written, which TestBoundErrText_B8_EveryPrintedErrorTextIsBounded
// forbids outside boundErrText(x.Error()) (a wrapper that printed its cause
// itself would be a way round the bound).
type refusedError struct{ error }

func (e refusedError) Unwrap() error { return e.error }

// newOutcomeUnknownError and newRefusedError are the ONLY way to build the
// two types. They return the VALUE wrapper, which is the form runRoot's
// errors.As matches: a pointer to either type is a different type to
// errors.As and would exit 1, silently (TestExitStatus_F1_OnlyTheValueFormClassifies
// pins that, so a caller is held to these constructors). err must not be nil.
//
// Both PANIC on a nil err: a typed error with no cause has no text and would
// nil-dereference inside runRoot, and a nil that was meant as "no error" must
// never become a failing status by accident; it is a programming error.
//
// PRECEDENCE, for a caller that can have both (U6): outcome-unknown wins.
// Whenever an outcomeUnknownError is anywhere in the chain (wrapped, joined,
// either nesting order) runRoot exits 3 and, under a signal, still prints the
// "may or may not have been applied" note: a refusal must never claim that
// nothing was dispatched when an unobserved dispatch is also in the chain.
func newOutcomeUnknownError(err error) error {
	if err == nil {
		panic("newOutcomeUnknownError: nil error")
	}
	return outcomeUnknownError{error: err}
}

func newRefusedError(err error) error {
	if err == nil {
		panic("newRefusedError: nil error")
	}
	return refusedError{error: err}
}
