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

// verbExit is one mutating verb's row of the exit-status registry (contract
// plan §3.5, E2): which of the reserved statuses 3 and 4 it can return, and
// where. The registry is HAND-WRITTEN and checked against the real command tree
// (TestExitRegistry_IsTotalOverTheMutatingTree): a mutating command without a
// row, or a row for a command that does not exist, fails. Nothing here
// classifies an error; classification is by the run's write gate
// (internal/dispatch), never by an error's name.
//
//   - Exits is the subset of {3, 4} the verb can return. 4 only ever means
//     "refused before anything was changed on a PVE host or in the roster
//     file" (the gate was still closed); 3 only ever means "a change was
//     dispatched and its outcome was not observed" (a task wait that started
//     and did not observe, or a root-SSH write that was sent and timed out).
//   - Gate is where the verb's first write happens (the point from which a
//     refusal is exit 1, never 4).
//   - Refusals are the boundaries before the gate that exit 4; Waits the sites
//     that exit 3.
//   - State is a NAMED contract state (unobserved_dispatch, child_status);
//     Residual a documented exit-1 case that is not proof of no change.
type verbExit struct {
	Exits     []int
	Gate      string
	Refusals  []string
	Waits     []string
	State     string
	Residual  string
	WriteKind string // rest, ssh, roster, task, exec: the funnels the verb reaches
}

// Named contract states.
const (
	stateUnobservedDispatch = "unobserved_dispatch"
	stateChildStatus        = "child_status"
)

// verbExits is keyed by the command path without the root ("vm create").
var verbExits = map[string]verbExit{
	"api post":   apiExit,
	"api put":    apiExit,
	"api delete": apiExit,

	"vm destroy":             {Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the first stop or destroy POST", Refusals: []string{"visibility probe and in-flight determination", "--yes not given"}, Waits: []string{"the destroy task wait", "the stop task wait"}},
	"vm create":              {Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the create POST (after Preflight)", Refusals: []string{"exists with a different config", "vmid taken", "missing storage"}, Waits: []string{"the create/clone task wait", "the --unique-tag wait"}},
	"vm set":                 {Exits: []int{4}, WriteKind: "rest|ssh", Gate: "the config PUT (or the root qm set)", Refusals: []string{"Validate refusals (a field both set and deleted, a duplicate delete) and a lock-wait timeout, before the write"}, Residual: "allow-list and digest refusals raised inside the write are exit 1 (the gate is already open there); a lost PUT response is exit 1: not proof that nothing changed"},
	"vm snapshot create":     snapshotExit,
	"vm snapshot delete":     snapshotExit,
	"vm snapshot rollback":   snapshotExit,
	"network bridge create":  networkExit,
	"network bridge destroy": networkExit,
	"network set":            networkExit,

	"storage create":      {Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the create POST", Refusals: []string{"a differing definition", "shared-storage and quorum refusals"}, Waits: []string{"the create task wait"}},
	"storage set-content": {Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the PUT", Refusals: []string{"refusals before the PUT"}, Waits: []string{"the update task wait"}},
	"storage alloc":       {Exits: []int{4}, WriteKind: "rest", Gate: "the allocate POST", Refusals: []string{"shape, size and differing-volume refusals before the POST"}, Residual: "synchronous: a lost response is exit 1, not proof that nothing changed"},
	"storage free-orphans": {Exits: []int{3, 4}, WriteKind: "rest+task+ssh", Gate: "the first DELETE", Refusals: []string{"non-quorate and shared-storage refusals"},
		Waits: []string{"the DELETE task wait"}},

	"acl enable-vm-destroy": {Exits: []int{3, 4}, WriteKind: "ssh", Gate: "the first pveum write", Refusals: []string{"the dry-pass refusals", "declined or no terminal", "role conflict, not a VM-admin token, would not converge, plan changed"}, Waits: []string{"a root-SSH write that timed out"}},
	"acl grant":             {Exits: []int{3, 4}, WriteKind: "ssh", Gate: "the first pveum write", Refusals: []string{"self grant", "escalating role without the flag", "bad grant"}, Waits: []string{"a root-SSH write that timed out"}},
	"user ensure":           {Exits: []int{3, 4}, WriteKind: "ssh", Gate: "the first pveum write", Refusals: []string{"refusals before the write"}, Waits: []string{"a root-SSH write that timed out"}},
	"group ensure":          {Exits: []int{3, 4}, WriteKind: "ssh", Gate: "the first pveum write", Refusals: []string{"refusals before the write"}, Waits: []string{"a root-SSH write that timed out"}},

	"bootstrap": {Exits: []int{3, 4}, WriteKind: "ssh+rest+roster", Gate: "the earliest of the key install, a roster write, or a token command",
		Refusals: []string{"option and --grant validation", "host-key checks before a password is sent", "refusals raised while the gate is still closed"},
		Waits:    []string{"an unobserved revoke, mint or key install (a root-SSH write sent and timed out)"}},

	"roster init":         {Exits: []int{4}, WriteKind: "roster", Gate: "the roster file write", Refusals: []string{"the file exists without --force"}},
	"roster rekey":        {Exits: []int{4}, WriteKind: "roster", Gate: "the roster rewrite", Refusals: []string{"passphrase mismatch and validation before the write"}},
	"roster import-token": {Exits: []int{4}, WriteKind: "roster", Gate: "the first roster write", Refusals: []string{"validation and an unpinned target before the first roster write"}},
	"roster pin-tls":      {Exits: []int{4}, WriteKind: "roster", Gate: "the TLS pin write", Refusals: []string{"validation before the pin write"}},

	"exec": {Exits: []int{4}, WriteKind: "exec", Gate: "none: nothing is written before the handover", Refusals: []string{"refusals before the handover"}, State: stateChildStatus,
		Residual: "after the handover the exit status is the child's own: 3 and 4 from the child are not pveforge's"},

	"harness build":                harnessExit,
	"harness probe":                harnessExit,
	"harness golden":               harnessExit,
	"harness reset":                harnessExit,
	"harness vm destroy":           harnessExit,
	"harness vm shutdown":          harnessExit,
	"harness vm stop":              harnessExit,
	"harness vm snapshot create":   harnessExit,
	"harness vm snapshot delete":   harnessExit,
	"harness vm snapshot rollback": harnessExit,
}

var (
	apiExit = verbExit{Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the non-GET request", State: stateUnobservedDispatch,
		Refusals: []string{"the /access write refusal", "an unmatched path without --unsafe-no-lock"},
		Waits:    []string{"a task wait after a returned UPID"},
		Residual: "a response with no UPID is an ordinary success (exit 0); an undecodable body and a lost response are exit 1, not proof that nothing changed; --no-wait with a UPID exits 0 (unobserved_dispatch)"}
	snapshotExit = verbExit{Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the snapshot POST or DELETE",
		Refusals: []string{"an existing or reserved snapshot name", "the in-flight guard"}, Waits: []string{"the snapshot task wait"}}
	networkExit = verbExit{Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the STAGE request, not the commit",
		Refusals: []string{"before the stage only: type mismatch, validation, a missing management bridge"}, Waits: []string{"the apply or commit task wait"},
		Residual: "everything after the stage is exit 1; a lost stage response is exit 1, not proof that nothing changed"}
	harnessExit = verbExit{Exits: []int{3, 4}, WriteKind: "rest+task", Gate: "the first create, shutdown, snapshot or POST request",
		Refusals: []string{"preflight and Guard refusals before the first request"}, Waits: []string{"a task wait after the first request"}}
)
