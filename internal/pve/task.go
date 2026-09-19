package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// defaultTaskPollInterval is how often WaitForTask polls a running task's
// status. A var, not a const, purely so this package's own tests can point
// it at a few milliseconds instead of waiting out a real second per poll
// tick — production code never changes it. Mirrors the same pattern
// routed.go already uses for sshPort.
var defaultTaskPollInterval = time.Second

// defaultTaskWaitTimeout bounds how long WaitForTask will keep polling a
// task that never leaves the "running" state before giving up with
// proxmox.ErrTimeout. A var for the same test-override reason as
// defaultTaskPollInterval above.
var defaultTaskWaitTimeout = 10 * time.Minute

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
	if node == "" {
		return outcomeUnknown(errors.New("node is required"))
	}
	if upid == "" {
		return outcomeUnknown(errors.New("upid is required"))
	}
	if strings.Count(upid, ":") < 7 {
		return outcomeUnknown(fmt.Errorf("malformed upid %q: expected at least 8 colon-separated fields", upid))
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
