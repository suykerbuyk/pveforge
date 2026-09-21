package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

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
// intra-package, and TestNoParallelTests in this package and in
// cmd/pveforge pins that neither uses t.Parallel. A test that leaves a
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
// reported it unsuccessful: status "stopped" with an ExitStatus other than
// "OK". It is the ONLY WaitForTask error that describes an observed
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
//   - *TaskFailedError: PVE reported the task stopped with a non-OK exit
//     status. The task ran; this is its outcome.
//   - IsTaskOutcomeUnknown: everything else. The task was dispatched but
//     its outcome was never observed: the deadline passed, ctx was
//     canceled, a status poll failed, a poll's payload was outside PVE's
//     contract, or the UPID/node pre-check below refused before polling
//     (WaitForTask is only ever called after a mutation was dispatched, so
//     even then a task exists that nothing observed). A caller must not
//     blindly retry a non-idempotent operation on one of these.
//
// The poll loop is pveforge's own rather than go-proxmox's Task.Wait,
// because go-proxmox v0.8.2-pveforge.1 reports every non-2xx status poll
// as a *proxmox.StatusError, which Task.Wait returns at once: a single
// pveproxy hiccup mid-task would end the wait. Each poll decodes into a
// FRESH Task, polls start immediately (no sleep before the first), and
// between polls the loop sleeps defaultTaskPollInterval in a select that
// also watches ctx and the defaultTaskWaitTimeout deadline. The deadline
// is armed once for the whole wait; retries never extend it. A poll is:
//
//   - running: keep polling, and reset the transient count;
//   - stopped with exit status "OK": success;
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
// used in any network call. This matters because of a confirmed bug in
// go-proxmox's NewTask, present since upstream v0.8.1 and STILL present at
// the pinned v0.8.2-pveforge.1 (tasks.go:27-34): its own guard is
// `len(sp) < 7`, but it then indexes sp[7] — a UPID that splits into
// exactly 7 colon-separated fields
// passes that guard and then panics with an out-of-range index inside
// NewTask itself. A genuine PVE UPID always has 9 fields (8 colons), so
// this can't fire from real PVE output, but pveforge has no panic recovery
// anywhere, so a malformed UPID reaching that code must never be allowed
// to get there at all — and since both proxmox.Task.Ping and this loop
// call NewTask again on every single poll, the check has to happen once,
// up front, here, rather than relying on anything downstream.
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
		// (the sp[7] off-by-one this function's pre-check guards against).
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
			if task.ExitStatus == "OK" {
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
// The rules: the "UPID:" prefix PVE always writes; at least 8
// colon-separated fields (a real UPID has 9), which is what keeps a
// 7-field string away from proxmox.NewTask's sp[7] panic described on
// WaitForTask; and a non-empty node field, since an empty node can never
// match the node a caller waits on and would otherwise reach NewTask as a
// task with no node at all.
func validateUPIDShape(upid string) error {
	if !strings.HasPrefix(upid, "UPID:") {
		return fmt.Errorf("malformed upid %q: missing UPID: prefix", upid)
	}
	if strings.Count(upid, ":") < 7 {
		return fmt.Errorf("malformed upid %q: expected at least 8 colon-separated fields", upid)
	}
	if strings.SplitN(upid, ":", 3)[1] == "" {
		return fmt.Errorf("malformed upid %q: empty node field", upid)
	}
	return nil
}

// UPIDNode returns the node a UPID names (its second field), after
// validating its shape with validateUPIDShape. It never calls
// proxmox.NewTask, which panics on a 7-field UPID at the pinned fork.
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
