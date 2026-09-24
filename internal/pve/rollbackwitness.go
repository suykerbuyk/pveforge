package pve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// witnessWaitGrace is how far past the witness deadline the exec wait's
// context may run. WaitForAgentExec has its own timer at the deadline, and
// its AgentExecTimeoutError says the most (polls, last poll error); a
// context ending at the same instant would race it and cut the last poll
// short. The grace lets that timer fire first while still bounding a poll
// that hangs.
const witnessWaitGrace = 250 * time.Millisecond

// ErrRollbackNotWitnessed is what every RollbackWitnessError matches: the
// guest was not shown to be running the rolled-back state. It is NOT a
// verdict that the rollback failed — only that it was not proven — and a
// caller's context ending is never reported this way (see RollbackWitness).
var ErrRollbackNotWitnessed = errors.New("rollback not witnessed")

// WitnessReason says why a rollback was not witnessed. The four are
// deliberately distinct: each implies a different next step.
type WitnessReason string

const (
	// WitnessNeverResponded: no command could be run in the guest before
	// the deadline — every dispatch was refused by PVE with a 5xx (the
	// agent not up yet, typically right after a rollback that reboots the
	// guest), a dispatch or poll was still in flight when the deadline came,
	// or a dispatched command's exit was never observed.
	WitnessNeverResponded WitnessReason = "the guest agent never responded"
	// WitnessCommandFailed: the command ran and did not succeed — a
	// non-zero exit, a signal, or an exit with no exit code (Succeeded).
	WitnessCommandFailed WitnessReason = "the witness command ran and did not succeed"
	// WitnessMarkerMissing: the command succeeded, but its output does not
	// carry the expected marker (for the default command, the fresh nonce:
	// the answer is not from this command).
	WitnessMarkerMissing WitnessReason = "the witness command's output lacks the expected marker"
	// WitnessOutputTruncated: the command succeeded, the marker is not in
	// the output PVE returned, and PVE says that output was truncated — so
	// the marker may be in the part that was cut. Never reported as
	// WitnessMarkerMissing.
	WitnessOutputTruncated WitnessReason = "the witness command's output was truncated before the marker could be checked"
)

// RollbackWitnessError reports a rollback that was not witnessed, and why.
//
// Its text never carries the guest command's output (OutData, ErrData):
// that is arbitrary, multi-line, guest-controlled text. RollbackWitness
// returns the *AgentExecStatus alongside this error instead, so a caller
// that wants to show the output shows a bounded, quoted excerpt of its own.
// Last is the last dispatch refusal or the exec wait's error. That is PVE's
// answer or pveforge's own text — but PVE's answer can quote what the guest
// agent said, so Last is not guaranteed free of guest-agent text; it is
// bounded and quoted where printed (runRoot's boundErrText).
type RollbackWitnessError struct {
	VMID       int
	Reason     WitnessReason
	Dispatches int
	// ExitCode, ExitCodeSet and Signal are set for WitnessCommandFailed.
	ExitCode    int
	ExitCodeSet bool
	Signal      *int
	Last        error
}

func (e *RollbackWitnessError) Error() string {
	msg := fmt.Sprintf("rollback witness on vm %d: %s: %s", e.VMID, ErrRollbackNotWitnessed.Error(), e.Reason)
	switch {
	case e.Reason == WitnessCommandFailed && e.Signal != nil:
		msg += fmt.Sprintf(" (killed by signal %d)", *e.Signal)
	case e.Reason == WitnessCommandFailed && !e.ExitCodeSet:
		msg += " (it exited with no exit code)"
	case e.Reason == WitnessCommandFailed:
		msg += fmt.Sprintf(" (exit code %d)", e.ExitCode)
	}
	if e.Reason == WitnessNeverResponded {
		msg += fmt.Sprintf(" after %d dispatch attempt(s)", e.Dispatches)
	}
	if e.Last != nil {
		msg += ": " + e.Last.Error()
	}
	return msg
}

// Unwrap exposes ErrRollbackNotWitnessed and, when there was one, Last.
func (e *RollbackWitnessError) Unwrap() []error {
	if e.Last != nil {
		return []error{ErrRollbackNotWitnessed, e.Last}
	}
	return []error{ErrRollbackNotWitnessed}
}

// IsRollbackNotWitnessed reports whether err is a RollbackWitnessError.
// False for a caller's context ending, which is not a witness outcome.
func IsRollbackNotWitnessed(err error) bool {
	return errors.Is(err, ErrRollbackNotWitnessed)
}

// RollbackWitness proves a rolled-back guest is running by executing
// command in it through the QEMU guest agent and checking the result,
// under ONE deadline, timeout (defaultAgentExecTimeout when non-positive),
// shared by every step. Never trust a rollback's own exit code, or a config
// field, as proof: a rollback that did not restore the guest's disk can
// leave a field like description unchanged (pveforge-vm-rollback-witness).
//
// Every request it makes runs under a context bounded by that deadline —
// exactly for a dispatch, and by witnessWaitGrace more for a status poll —
// so no single call that hangs can outlive it by the HTTP client's own 30s
// timeout.
//
//  1. Dispatch (AgentExec). Right after a rollback the agent is often not
//     up yet, and PVE refuses the dispatch at once with a 5xx. A 5xx that
//     is PVE's typed answer (HTTPStatus) is retried, every
//     defaultAgentExecPollInterval (never sleeping past the deadline), until
//     the deadline. A typed 4xx (400, 401, 403, …) is returned at once, as
//     it is: retrying cannot fix a bad request or a refused credential, and
//     it is not "never responded". A TRANSPORT error is never retried
//     either, and is returned as it is. IsAgentUnavailableError is
//     deliberately not the test: it matches a reason phrase HTTP/2 erases.
//  2. Wait (WaitForAgentExec) with whatever remains of the deadline.
//  3. Judge: Succeeded() — never ExitCode alone, which reads a signal-killed
//     command (no exit code sent, zero value) as a clean exit — then, when
//     wantOutput is non-empty, the marker, as a substring of OutData.
//
// THE COMMAND MUST BE SAFE TO RUN TWICE. A retried 5xx does not prove the
// earlier attempt never ran: a 596 from pveproxy (another node timing out)
// or a QMP guest-exec timeout can arrive after the guest agent started the
// command. The default (DefaultRollbackWitnessCommand, an echo of a nonce)
// is; a caller-supplied witness command must be too.
//
// Returns the status on success, and on WitnessCommandFailed,
// WitnessMarkerMissing and WitnessOutputTruncated (the command ran; its
// status is data). A caller's context ending is returned as the context's
// own error (errors.Is(err, context.Canceled), the cause on the context) —
// checked FIRST at every step, so it is never reported as a
// RollbackWitnessError, even when it lands just as the deadline does, and
// never as whatever the attempt in flight happened to return — so a signal
// is reported as an interruption, not as a rollback not proven.
//
// The error's text never carries the guest command's output. It can carry
// guest-agent text, though: a dispatch refusal or a poll error (Last, and
// AgentExecTimeoutError's LastErr) is PVE's answer, which may quote what the
// agent said. It is bounded and quoted where printed (runRoot).
//
// Takes no lock. Its caller (pveforge-vm-snapshot-cli) must hold the VM's
// lock across the rollback AND this witness, so no other pveforge mutation
// can land between them and be witnessed instead.
func (c *Client) RollbackWitness(ctx context.Context, node string, vmid int, command []string, wantOutput string, timeout time.Duration) (*AgentExecStatus, error) {
	if timeout <= 0 {
		timeout = defaultAgentExecTimeout
	}
	deadline := time.Now().Add(timeout)
	// Every request runs under dctx; the caller's ctx is checked first
	// wherever an outcome is decided, so the caller's stop and this
	// witness's own deadline are never confused.
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stopped := func() error {
		if ctx.Err() != nil {
			return fmt.Errorf("rollback witness on vm %d: %w", vmid, ctx.Err())
		}
		return nil
	}
	neverResponded := func(dispatches int, last error) error {
		return &RollbackWitnessError{VMID: vmid, Reason: WitnessNeverResponded, Dispatches: dispatches, Last: last}
	}

	var pid, dispatches int
	var lastRefusal error // PVE's last typed refusal: more telling than a cut-off attempt
	for {
		p, err := c.AgentExec(dctx, node, vmid, command, "")
		dispatches++
		if err == nil {
			pid = p
			break
		}
		if stop := stopped(); stop != nil {
			// Whatever this attempt's own error says — a refusal that
			// arrived as the caller stopped, or a transport error carrying
			// the context's cause — the outcome is the caller's stop.
			return nil, stop
		}
		if dctx.Err() != nil {
			// The deadline ended this attempt mid-request.
			if lastRefusal != nil {
				err = lastRefusal
			}
			return nil, neverResponded(dispatches, err)
		}
		code, answered := HTTPStatus(err)
		if !answered || code < 500 {
			return nil, err
		}
		lastRefusal = err
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, neverResponded(dispatches, err)
		}
		wait := time.NewTimer(min(defaultAgentExecPollInterval, remaining))
		select {
		case <-ctx.Done():
			wait.Stop()
			return nil, stopped()
		case <-wait.C:
		}
	}

	wctx, wcancel := context.WithDeadline(ctx, deadline.Add(witnessWaitGrace))
	defer wcancel()
	status, err := c.WaitForAgentExec(wctx, node, vmid, pid, 0, time.Until(deadline))
	if err != nil {
		// The caller's stop first: WaitForAgentExec's final select picks
		// at random when its ctx and its deadline are both ready.
		if stop := stopped(); stop != nil {
			return nil, stop
		}
		if IsAgentExecTimeoutError(err) || wctx.Err() != nil {
			return nil, neverResponded(dispatches, err)
		}
		return nil, err
	}
	if !status.Succeeded() {
		return status, &RollbackWitnessError{VMID: vmid, Reason: WitnessCommandFailed, Dispatches: dispatches,
			ExitCode: status.ExitCode, ExitCodeSet: status.ExitCodeSet, Signal: status.Signal}
	}
	if wantOutput != "" && !strings.Contains(status.OutData, wantOutput) {
		reason := WitnessMarkerMissing
		if bool(status.OutTruncated) {
			reason = WitnessOutputTruncated
		}
		return status, &RollbackWitnessError{VMID: vmid, Reason: reason, Dispatches: dispatches}
	}
	return status, nil
}

// DefaultRollbackWitnessCommand is the witness for a caller with nothing
// guest-specific to check: /bin/echo of a fresh nonce, with the same nonce
// as the marker. The nonce, not a fixed string, is the point: a rollback
// that restores RAM restores the guest agent's own exec state with it, so
// a status read could return a pre-snapshot command's output — only an
// answer carrying a nonce made now proves a command ran now. It comes from
// crypto/rand, so two witnesses — in one process, on a coarse clock —
// cannot share one.
//
// /bin/echo assumes a POSIX guest. A Windows guest needs a caller-supplied
// command and marker, which RollbackWitness takes directly.
func DefaultRollbackWitnessCommand() (command []string, wantOutput string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("rollback witness: make a nonce: %w", err)
	}
	nonce := "pveforge-witness-" + hex.EncodeToString(b)
	return []string{"/bin/echo", nonce}, nonce, nil
}
