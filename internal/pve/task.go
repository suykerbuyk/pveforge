package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// TaskWaitCeiling is the longest WaitForTask will ever wait for a task to
// leave the "running" state: defaultTaskWaitTimeout's production value, and
// the ceiling a caller-supplied shorter bound (cmd/pveforge's
// `api --wait-timeout`) is checked against. A const, so it is one source
// for both and adds no seam of its own.
const TaskWaitCeiling = 10 * time.Minute

// defaultTaskPollInterval is how often WaitForTask polls a running task's
// status. A var, not a const, purely so tests can point it at a few
// milliseconds instead of waiting out a real second per poll tick —
// production code never changes it. The only writer is setTaskTimings,
// below.
var defaultTaskPollInterval = time.Second

// defaultTaskWaitTimeout bounds how long WaitForTask will keep polling a
// task that never leaves the "running" state before giving up with
// proxmox.ErrTimeout. A var for the same test-override reason as
// defaultTaskPollInterval above; its production value is TaskWaitCeiling.
var defaultTaskWaitTimeout = TaskWaitCeiling

// SetTaskTimingsForTests overrides WaitForTask's poll interval and wait
// timeout process-wide, restoring the previous values via the returned
// func (call it, typically via t.Cleanup, once the test is done). It exists
// so a test in ANOTHER package — cmd/pveforge's `api` tests are the reason
// it was added — can drive a task that stays "running" for several polls
// without waiting out a real second per poll, and so a fake that never
// flips to "stopped" ends in a bounded failure rather than the 10-minute
// TaskWaitCeiling.
//
// It PANICS unless called from a binary built by `go test`, so the seam is
// inert in a shipped pveforge no matter who calls it. That is the
// sshexec.SetDialGuardForTests / roster.SetScryptWorkFactorForTests shape,
// deliberately, rather than the older ungated SetSSHPortForIntegrationTests:
// internal/pve/testdata/weakprobe is a non-test `package main` that calls
// this, and TestTaskTimingsSeam_WeakProbeIsRejectedOutsideATestBinary runs
// it with `go run` and requires it to die. That probe is also the ONLY
// observer of the argument this wrapper passes below — an in-process test
// can call setTaskTimings with false, but cannot see a wrapper that passes
// true.
//
// Production code must never call this. That is not left to convention:
// TestTaskTimingsSeam_NoProductionReferences forbids this name,
// setTaskTimings and both timing vars in every non-test file in the module
// except this one. Like every AST-based guard in this repo, it does not see
// a //go:linkname onto the vars themselves
// (pveforge-golinkname-defeats-source-guards).
//
// Not safe for two test packages to use concurrently: it mutates
// process-wide state with no locking, matching the seams named above. Each
// package's tests run in their own process, so the hazard is only ever
// intra-package, and the module's no-parallel pin
// (internal/sourceguard/noparallel_guard_test.go) holds that no package using
// it calls t.Parallel. A test that leaves a
// WaitForTask goroutine running must join it BEFORE restore runs, or the
// race detector reports the restore's write against the poll loop's read.
func SetTaskTimingsForTests(interval, timeout time.Duration) (restore func()) {
	return setTaskTimings(interval, timeout, testing.Testing())
}

// setTaskTimings holds the whole decision, with the "am I in a test binary"
// answer PASSED IN rather than read, for the same reason
// roster.setScryptWorkFactor does: the refusal branch is then reachable from
// an ordinary in-process test, so the suite's own coverage profile covers it.
func setTaskTimings(interval, timeout time.Duration, inTestBinary bool) (restore func()) {
	if !inTestBinary {
		panic("pve: SetTaskTimingsForTests called outside a test binary")
	}
	// A non-positive interval makes the poll loop spin; a non-positive
	// timeout, or one shorter than a single interval, makes every wait end
	// before it could observe a second poll. None is a timing any test wants.
	if interval <= 0 || timeout <= 0 || timeout < interval {
		panic(fmt.Sprintf("pve: SetTaskTimingsForTests: invalid timings interval=%s timeout=%s", interval, timeout))
	}
	origInterval, origTimeout := defaultTaskPollInterval, defaultTaskWaitTimeout
	defaultTaskPollInterval, defaultTaskWaitTimeout = interval, timeout
	return func() {
		defaultTaskPollInterval, defaultTaskWaitTimeout = origInterval, origTimeout
	}
}

// TaskFailedError reports that a PVE task ran to completion and PVE
// reported it unsuccessful: status "stopped" with an ExitStatus that
// taskExitSucceeded does not accept. It is the ONLY WaitForTask error that describes an observed
// outcome. Every other WaitForTask error means the outcome was never
// observed at all; see IsTaskOutcomeUnknown. Whether a TaskFailedError is
// safe to retry is still the caller's call, but it is the only class where
// that question can be asked from what WaitForTask knows.
type TaskFailedError struct {
	UPID       string
	ExitStatus string
}

func (e *TaskFailedError) Error() string {
	return fmt.Sprintf("task %s failed: %s", e.UPID, e.ExitStatus)
}

// taskExitOK is the exit status of a task that completed cleanly.
const taskExitOK = "OK"

// taskExitWarnings matches the exit status of a task that completed but
// logged warnings.
var taskExitWarnings = regexp.MustCompile(`^WARNINGS: \d+$`)

// taskExitSucceeded reports whether a stopped task's exit status is a
// success, by Proxmox's own rule (PVE::UPID::status_is_error in
// pve-common): "OK", or exactly "WARNINGS: <n>" for a task that completed
// but logged warnings — PVE's worker exits 0 for both. Anything else is the
// task's error message. It is the one place pveforge judges an exit status.
//
// Derived from pve-common's source; not yet verified against a live host
// (see pveforge-nested-pve-test-harness's live-check list).
func taskExitSucceeded(exitStatus string) bool {
	return exitStatus == taskExitOK || taskExitWarnings.MatchString(exitStatus)
}

// TaskWarningsFunc is told about each task WaitForTask saw succeed with
// warnings: its node, UPID and exit status ("WARNINGS: <n>").
type TaskWarningsFunc func(node, upid, exitStatus string)

type taskWarningsKey struct{}

// WithTaskWarnings returns ctx carrying f, which WaitForTask calls for every
// task under ctx that succeeds with warnings. cmd/pveforge installs one for
// every command, so such a success always reaches the operator.
func WithTaskWarnings(ctx context.Context, f TaskWarningsFunc) context.Context {
	return context.WithValue(ctx, taskWarningsKey{}, f)
}

func reportTaskWarnings(ctx context.Context, node, upid, exitStatus string) {
	if f, ok := ctx.Value(taskWarningsKey{}).(TaskWarningsFunc); ok && f != nil {
		f(node, upid, exitStatus)
	}
}

// taskOutcomeUnknownError marks every WaitForTask error that is not a
// TaskFailedError: the task was dispatched, but its outcome was never
// observed. It wraps its cause, so errors.Is/As still reach the
// *proxmox.StatusError, proxmox.ErrTimeout, context error or
// ErrUnverifiableRead underneath. IsTaskOutcomeUnknown matches it.
type taskOutcomeUnknownError struct {
	cause error
}

func (e *taskOutcomeUnknownError) Error() string { return e.cause.Error() }
func (e *taskOutcomeUnknownError) Unwrap() error { return e.cause }

// maxConsecutiveTransientPolls is how many task-status polls in a row may
// fail transiently before WaitForTask gives up on them. A successful poll
// resets the count.
const maxConsecutiveTransientPolls = 3

// WaitForTask polls a PVE task to completion and reports whether it
// succeeded. node is the PVE node the task is running on (a UPID embeds
// its own node, but callers already know which node they dispatched the
// mutation to, and RoutedClient's own pass-through keeps node as an
// explicit parameter to match GetVM and the other typed getters, rather
// than relying solely on what's embedded in upid).
//
// Every non-nil error is exactly one of two classes:
//
//   - *TaskFailedError: PVE reported the task stopped with an exit status
//     that is not a success (taskExitSucceeded). The task ran; this is its
//     outcome.
//   - IsTaskOutcomeUnknown: everything else. The task was dispatched but
//     its outcome was never observed: the deadline passed, ctx was
//     canceled, a status poll failed, a poll's payload was outside PVE's
//     contract, or the UPID/node pre-check below refused before polling
//     (WaitForTask is only ever called after a mutation was dispatched, so
//     even then a task exists that nothing observed). A caller must not
//     blindly retry a non-idempotent operation on one of these.
//
// The poll loop is pveforge's own rather than go-proxmox's Task.Wait,
// because go-proxmox (still at v0.8.2-pveforge.2) reports every non-2xx status poll
// as a *proxmox.StatusError, which Task.Wait returns at once: a single
// pveproxy hiccup mid-task would end the wait. Each poll decodes into a
// FRESH Task, polls start immediately (no sleep before the first), and
// between polls the loop sleeps defaultTaskPollInterval in a select that
// also watches ctx and the defaultTaskWaitTimeout deadline. The deadline
// is armed once for the whole wait; retries never extend it. A poll is:
//
//   - running: keep polling, and reset the transient count;
//   - stopped with exit status "OK": success;
//   - stopped with "WARNINGS: <n>": success, reported to ctx's
//     TaskWarningsFunc (WithTaskWarnings) so it is never silent;
//   - stopped with any other non-empty exit status: *TaskFailedError;
//   - TRANSIENT, keep polling: a transport error (*url.Error), a
//     *proxmox.StatusError 502/503/504/595-599, or a payload with no
//     status at all (ErrUnverifiableRead). The 4th consecutive transient
//     poll ends the wait, reporting the last one's cause;
//   - anything else ends the wait at once: any other status (400, a 404 for
//     an unknown UPID, 500, ...), proxmox.ErrNotAuthorized, a decode error,
//     a status other than "running"/"stopped", "stopped" without an exit
//     status, or a canceled ctx (checked before a failed poll is
//     classified, so a cancel is never retried as a transient failure).
//
// upid's shape is validated BEFORE it is ever handed to proxmox.NewTask or
// used in any network call: a UPID outside PVE's grammar is not one PVE
// issued, so it is refused as an unverifiable read rather than polled
// (validateUPIDShape). Through v0.8.2-pveforge.1 this also stood between a
// 7-field UPID and a panic in go-proxmox's NewTask, whose guard was
// `len(sp) < 7` before it indexed sp[7]. v0.8.2-pveforge.2 fixed that
// (`len(sp) < 8`; TestForkNewTask_ShortUPIDDoesNotPanic pins it), and the
// check stays for the grammar. Both proxmox.Task.Ping and this loop call
// NewTask again on every poll, so the check is made once, up front, here.
//
// A related, still-unfixed-upstream risk in the same area: proxmox.Task's
// UnmarshalJSON copies every field present in a status response onto the
// Task via reflection, including UPID and Node — a response body that
// omits those two fields silently zeroes them on the Task, and a REUSED
// Task would then poll /nodes//tasks//status (or nil-panic inside Ping,
// since NewTask("", ...) returns nil). The fresh Task per poll above
// neutralises that for WaitForTask: a clobbered Task is discarded after
// the one poll that decoded into it. Other go-proxmox users of a reused
// Task are still exposed. The loop deliberately never validates the UPID
// or node a poll echoes back; test fixtures rely on that.
func (c *Client) WaitForTask(ctx context.Context, node, upid string) error {
	prefix := "wait for task"
	if upid != "" {
		prefix += " " + upid
	}
	outcomeUnknown := func(cause error) error {
		return fmt.Errorf("%s: %w", prefix, &taskOutcomeUnknownError{cause: cause})
	}
	// The UPID's own shape is checked before the node, so a caller with no
	// independent node (cmd/pveforge's `api` verbs on a node-less path pass
	// UPIDNode's "" for a malformed UPID) still gets the shape error, with
	// the same outcome-unknown classification as every other caller.
	if upid == "" {
		return outcomeUnknown(errors.New("upid is required"))
	}
	if err := validateUPIDShape(upid); err != nil {
		return outcomeUnknown(err)
	}
	if node == "" {
		return outcomeUnknown(errors.New("node is required"))
	}

	parsed := proxmox.NewTask(proxmox.UPID(upid), c.pc)
	if parsed == nil {
		// proxmox.NewTask only returns nil for an empty UPID today, which
		// the check above already excludes — this stays as a defensive
		// backstop against that behavior ever changing upstream, not dead
		// code: this same library boundary already proved unreliable once
		// (the sp[7] off-by-one, fixed only at v0.8.2-pveforge.2).
		return outcomeUnknown(errors.New("empty upid"))
	}
	if parsed.Node != node {
		return outcomeUnknown(fmt.Errorf("upid %q is for node %q, not %q", upid, parsed.Node, node))
	}

	deadline := time.NewTimer(defaultTaskWaitTimeout)
	defer deadline.Stop()

	transient := 0
	for {
		task := proxmox.NewTask(proxmox.UPID(upid), c.pc)
		cause := pollTask(ctx, task)
		switch {
		case cause == nil && task.Status == proxmox.TaskRunning:
			transient = 0
		case cause == nil && task.Status == "stopped":
			if taskExitSucceeded(task.ExitStatus) {
				if task.ExitStatus != taskExitOK {
					reportTaskWarnings(ctx, node, upid, task.ExitStatus)
				}
				return nil
			}
			if task.ExitStatus == "" {
				return outcomeUnknown(fmt.Errorf("task status poll reported stopped with no exit status: %w", ErrUnverifiableRead))
			}
			return &TaskFailedError{UPID: upid, ExitStatus: task.ExitStatus}
		case cause == nil:
			return outcomeUnknown(fmt.Errorf("task status poll reported unknown status %q: %w", task.Status, ErrUnverifiableRead))
		case ctx.Err() != nil:
			// The poll failed because ctx was canceled: never a transient
			// failure to retry.
			return outcomeUnknown(cause)
		case isTransientPollError(cause):
			transient++
			if transient > maxConsecutiveTransientPolls {
				return outcomeUnknown(cause)
			}
		default:
			return outcomeUnknown(cause)
		}

		select {
		case <-ctx.Done():
			return outcomeUnknown(ctx.Err())
		case <-deadline.C:
			return outcomeUnknown(proxmox.ErrTimeout)
		case <-time.After(defaultTaskPollInterval):
		}
	}
}

// validateUPIDShape is the ONE statement of what a UPID must look like
// before anything parses it. WaitForTask and UPIDNode both call it and
// neither carries any shape logic of its own, so the two cannot drift.
//
// The rule is PVE's own UPID grammar, from PVE::UPID::decode in
// pve-common (src/PVE/UPID.pm), which writes them as
// "UPID:%s:%08X:%08X:%08X:%s:%s:%s:" and parses them with:
//
//		^UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:$
//
//	  - node: [a-zA-Z0-9], optionally [a-zA-Z0-9-]* then [a-zA-Z0-9];
//	  - pid and starttime: exactly 8 hex digits; pstart: 8 or 9;
//	  - type and user: one or more, and id: zero or more, of any character
//	    but ':', '/' and whitespace.
//
// Perl's \s there covers Unicode whitespace (U+2028, U+0085, ...); Go's
// regexp \s does not, so whitespace is refused here rune by rune
// (unicode.IsSpace), and so is a control character, which no PVE writer
// puts in a UPID. Anything else is refused as an unverifiable read before
// any poll: a UPID outside this grammar is not one PVE issued, and it
// would otherwise reach proxmox.NewTask, a poll URL, and the stderr lines
// that print it.
//
// Derived from pve-common's source; not yet verified against a live host
// (see pveforge-nested-pve-test-harness's live-check list).
func validateUPIDShape(upid string) error {
	m := upidGrammar.FindStringSubmatch(upid)
	if m == nil {
		return fmt.Errorf("malformed upid %q: not PVE's UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>: form: %w", upid, ErrUnverifiableRead)
	}
	for i, field := range []string{"type", "id", "user"} {
		if strings.ContainsFunc(m[i+1], func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("malformed upid %q: its %s field holds whitespace or a control character: %w", upid, field, ErrUnverifiableRead)
		}
	}
	return nil
}

// upidGrammar is PVE::UPID::decode's pattern, less its \s, which
// validateUPIDShape applies rune by rune. Its groups are type, id and user.
var upidGrammar = regexp.MustCompile(`^UPID:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8,9}:[0-9A-Fa-f]{8}:([^:/]+):([^:/]*):([^:/]+):$`)

// UPIDNode returns the node a UPID names (its second field), after
// validating its shape with validateUPIDShape. It never calls
// proxmox.NewTask, which parses no node from a UPID of fewer than 8 fields
// (and panicked on a 7-field one before v0.8.2-pveforge.2).
//
// A caller that already knows which node it dispatched to must pass THAT
// node to WaitForTask, not this one: a node taken from the UPID itself makes
// WaitForTask's own node check tautological. This is for the case where no
// independent node exists — cmd/pveforge's `api` verbs on a path with no
// /nodes/{node} segment.
func UPIDNode(upid string) (string, error) {
	if err := validateUPIDShape(upid); err != nil {
		return "", err
	}
	return strings.SplitN(upid, ":", 3)[1], nil
}

// errNoTaskStatus is pollTask's cause for a poll that answered without any
// status: a {"data":null} payload, which leaves a fresh Task's Status "".
var errNoTaskStatus = fmt.Errorf("task status poll returned no status: %w", ErrUnverifiableRead)

// pollTask issues one status poll into task and returns nil only when the
// poll produced a status.
func pollTask(ctx context.Context, task *proxmox.Task) error {
	if err := task.Ping(ctx); err != nil {
		return err
	}
	if task.Status == "" {
		return errNoTaskStatus
	}
	return nil
}

// isTransientPollError reports whether a failed status poll is worth
// polling again: a transport error, a gateway or pveproxy status
// (502/503/504, 595-599), or a poll that returned no status.
func isTransientPollError(err error) bool {
	if errors.Is(err, errNoTaskStatus) {
		return true
	}
	var se *proxmox.StatusError
	if errors.As(err, &se) {
		switch code := se.StatusCode; {
		case code == 502, code == 503, code == 504:
			return true
		case code >= 595 && code <= 599:
			return true
		}
		return false
	}
	var ue *url.Error
	return errors.As(err, &ue)
}

// IsTaskTimeoutError reports whether err is (or wraps) the timeout
// WaitForTask returns when a task never leaves the "running" state within
// defaultTaskWaitTimeout — proxmox.ErrTimeout, propagated unchanged
// through WaitForTask's own %w wrap. Exposed as a project-level predicate,
// mirroring IsDigestConflictError's precedent (vmconfig.go) of giving
// callers pveforge's own API to check against rather than expecting them
// to import go-proxmox's sentinel directly.
//
// A timeout is one case of IsTaskOutcomeUnknown: the task's actual outcome
// is unknown, so a caller whose WaitForTask call is guarding a
// destructive, non-retryable operation (VMDestroy's hard destroy step is
// the motivating case — see its own doc comment) must not blindly retry
// it. It is NOT the only such case, and a caller deciding whether a retry
// is safe should ask IsTaskOutcomeUnknown instead: every WaitForTask error
// that is not a *TaskFailedError is outcome-unknown, and a
// TaskFailedError is the only class that describes what the task did.
func IsTaskTimeoutError(err error) bool {
	return proxmox.IsTimeout(err)
}

// IsTaskOutcomeUnknown reports whether err is a WaitForTask error for a
// task whose outcome was never observed: the deadline passed, ctx was
// canceled, a status poll failed (or failed transiently too many times in
// a row), a poll's payload was outside PVE's contract, or WaitForTask's
// own UPID/node pre-check refused. The task may still be running, may have
// succeeded, or may have failed, so a caller must not blindly retry a
// non-idempotent operation on the strength of it.
//
// Every non-nil WaitForTask error is either this or a *TaskFailedError,
// never both. It matches only errors WaitForTask itself produced: a bare
// proxmox.ErrTimeout from anywhere else is not one.
func IsTaskOutcomeUnknown(err error) bool {
	var unknown *taskOutcomeUnknownError
	return errors.As(err, &unknown)
}
