package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// VMDestroyClient is the subset of *pve.RoutedClient a VM-destroy Op needs:
// the typed GetVM getter (the status gate, Apply step 1), the raw REST
// passthrough (VMDestroy uses this for its existence check — see
// fetchVMConfig's own doc comment on why it reads the raw config there,
// while the status gate uses the typed GetVM), Node, the stop/destroy calls
// themselves, WaitForTask, and the post-destroy tag recheck.
// *pve.RoutedClient satisfies this interface structurally (see compat_test.go).
type VMDestroyClient interface {
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// GetVM fetches vmid's current status (and config) on node. VMDestroy
	// uses the typed .Status field as its fail-closed stop gate (Apply step
	// 1); since P1 a Status=="" (or null-config) payload comes back as
	// ErrUnverifiableRead.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// RawRequest issues a raw PVE REST call — see pve.RoutedClient.RawRequest's
	// own doc comment. VMDestroy uses this for its existence check
	// (fetchVMConfig); the status gate uses the typed GetVM getter.
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	// StopVM issues a hard stop for vmid. VMDestroy.Apply calls it only when
	// the status gate reads a state that is not positively "stopped", and
	// RETURNS on its error (never swallowing it) — see VMDestroy.Apply.
	StopVM(ctx context.Context, vmid int) (string, error)
	// DestroyVM issues the hard destroy for vmid.
	DestroyVM(ctx context.Context, vmid int, purge bool) (string, error)
	// WaitForTask polls a PVE task (by UPID) to completion.
	WaitForTask(ctx context.Context, node, upid string) error
	// TagStillClaimed reports whether any VM other than excludeVMID still
	// carries tag.
	TagStillClaimed(ctx context.Context, tag string, excludeVMID int) (bool, error)
}

// VMDestroy is idempotent-mutation-engine's Op for `vm destroy`
// (pveforge-vm-lifecycle-ops item 2c): read VMID's run status as a
// fail-closed gate, stop it unless it is already positively-parsed
// "stopped" (returning on any stop or stop-task failure, never swallowing
// it), destroy it (hard-fail) only once the stop is confirmed, reverify
// against this client's own node that it's actually gone, and optionally
// recheck a tag it was resolved by for other VMs still claiming it. An
// unverifiable status read (empty, null-config, or transport-failed)
// aborts before any mutation — "already stopped" is tolerated by the gate,
// not by swallowing errors, so teardown still never deadlocks on a stop
// that does not matter.
//
// KNOWN HAZARD, not resolved by this Op: WaitForTask's own timeout
// (10 minutes — internal/pve/task.go's defaultTaskWaitTimeout) can expire
// while PVE's destroy task is still genuinely running server-side.
// idempotent.Run releases its mutation lock the instant Apply returns,
// including on this timeout, and that lock only ever serialized
// pveforge's own callers against each other — it says nothing about the
// PVE-side task's own lifetime. A caller that blindly retries `vm destroy`
// after a timeout can therefore fire a SECOND DestroyVM while the first is
// still in flight. Whether PVE itself rejects a concurrent second destroy
// against an already-locked vmid is NOT confirmed against a live host or
// PVE's own documentation as of this writing — an explicit unverified
// assumption, tracked in the vault task (pveforge-vm-destroy) this Op was
// implemented from. The same holds for every destroy-step WaitForTask
// failure other than a pve.TaskFailedError: a status poll that kept
// failing leaves the destroy's outcome just as unknown as a timeout does.
// Callers should use pve.IsTaskOutcomeUnknown (true for the timeout too)
// to recognize these on the destroy step's WaitForTask call and avoid
// blindly retrying, rather than treating them like any other Apply error.
// The gated stop step is now the same class of non-retryable failure: Apply
// RETURNS (wrapped with %w, so pve.IsTaskOutcomeUnknown still matches) on a
// stop-task WaitForTask failure and never issues the destroy, so a caller
// must not blindly retry an outcome-unknown stop either.
//
// Not a PostApplier: Apply already verifies its own effect (step 3: the VM
// is confirmed gone) before it returns.
type VMDestroy struct {
	Client VMDestroyClient
	VMID   int
	// Tag, if non-empty, is the tag this VM was resolved by — triggers the
	// post-destroy stale-cache-tolerant recheck (Apply's step 4).
	Tag string

	// TagStillClaimedWarning is set by Apply if the post-destroy tag
	// recheck (step 4) found another VM still carrying Tag. Informational
	// only — never a hard Apply error, since the destroy itself already
	// succeeded by the time this runs.
	TagStillClaimedWarning bool
	// TagRecheckErr is set by Apply if the post-destroy tag recheck (step
	// 4) itself failed to run — distinct from TagStillClaimedWarning,
	// which means the recheck ran successfully and found nothing. A
	// non-nil TagRecheckErr means the recheck's own outcome is UNKNOWN,
	// never "confirmed no stale claim" — the exact absence-of-signal-
	// read-as-clean-result conflation this Op's Read/reverify fixes were
	// built to eliminate elsewhere. Never propagated as a hard Apply
	// error: the destroy itself already succeeded by the time this runs.
	TagRecheckErr error
}

// isMissingVMError reports whether err looks like PVE's own "no such VM"
// response for vmid specifically — anchored on the vmid-specific config
// path fragment PVE's real message names
// ("qemu-server/<vmid>.conf ... does not exist"), NOT a bare substring
// match on "does not exist" alone. A bare match would also classify PVE's
// unrelated "user '<name>@pve' does not exist" auth-failure text as "VM
// gone," silently no-op'ing a real destroy the same way an earlier,
// rejected draft of this Op's Read did via GetVM's own opaque errors.
// Requiring BOTH the vmid-specific path fragment AND the "does not exist"
// phrase also guards the other direction: an unrelated error that merely
// happens to name this vmid's config path (e.g. a permissions error) isn't
// misclassified as "gone" either.
//
// The match itself is pve.NotFound's Fragment rule, on PVE's typed answer
// only: the phrase is what PVE is EXPECTED to say for a missing VM config,
// from source review and PVE's documented config-file-backed VM model, NOT
// confirmed against a live host (see pve.NotFound's own caveat on where
// PVE puts the message).
func isMissingVMError(err error, vmid int) bool {
	return pve.NotFound(err, pve.Subject{Fragment: fmt.Sprintf("qemu-server/%d.conf", vmid)})
}

// fetchVMConfig issues GET /nodes/{node}/qemu/{vmid}/config via RawRequest,
// whose *pve.StatusError keeps PVE's status line and body, which
// isMissingVMError reads. (Through v0.8.2-pveforge.0, upstream's behaviour,
// go-proxmox discarded the body on HTTP 500/501, the status PVE uses for
// "no such VM"; since .1 the fork keeps it in its *proxmox.StatusError,
// which pve.NotFound also reads, so
// VMCreate.ReRead can classify GetVM's errors the same way. This Op reads
// the raw config because Read returns its fields as the pre-destroy
// snapshot, not to route around that.)
//
// A RawRequest error matching isMissingVMError is treated as "doesn't
// exist" (exists == false, err == nil); every other error propagates as a
// real error. Mirrors NetworkBridgeEnsure.fetchInterface's identical
// three-outcome shape (networkbridge.go).
func (op *VMDestroy) fetchVMConfig(ctx context.Context) (map[string]json.RawMessage, bool, error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(op.Client.Node()), op.VMID)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		if isMissingVMError(err, op.VMID) {
			return nil, false, nil
		}
		return nil, false, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, fmt.Errorf("parse: %w", err)
	}
	return fields, true, nil
}

// Read reports whether VMID currently exists, via fetchVMConfig. An
// unclassified fetchVMConfig error MUST propagate rather than being folded
// into "doesn't exist" the way VMCreate.Read treats any GetVM failure —
// DESTROY's polarity is the opposite of CREATE's: an inconclusive Read
// reading as "already gone" here would make Satisfied true and skip Apply
// entirely (idempotent.Run's own no-op path, op.go), silently no-op'ing a
// real destroy and reporting false success.
//
// A successful fetchVMConfig marshals the raw config fields PVE returned
// as the comparable "current state" string — this doubles as the
// pre-destroy config snapshot the epic wanted preserved, surfaced for free
// via idempotent.Run's own Result.Before (which stores Read's return),
// with no extra plumbing.
func (op *VMDestroy) Read(ctx context.Context) (string, error) {
	fields, exists, err := op.fetchVMConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("vm destroy: vm %d: read: %w", op.VMID, err)
	}
	if !exists {
		return "", nil
	}

	b, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("vm destroy: vm %d: read: encode: %w", op.VMID, err)
	}
	return string(b), nil
}

// Satisfied reports whether current is empty — i.e. whether Read found
// nothing answering to VMID. Destroying an already-gone VMID is
// idempotent-satisfied: there is nothing left to destroy.
func (op *VMDestroy) Satisfied(current string) bool {
	return current == ""
}

// Apply runs the destroy sequence: (1) read the run status as a fail-closed
// gate, (2) stop unless already "stopped" (returning on any stop failure),
// (3) hard destroy, (4) node-local reverify, (5) stale-cache-tolerant tag
// recheck. See this type's own doc comment for why the stop is now gated and
// fail-closed, and for the destroy-step WaitForTask-timeout hazard it does
// not resolve.
func (op *VMDestroy) Apply(ctx context.Context) error {
	// Step 1: status gate. Read node-local run state before any mutation.
	// GetVM does a status GET and a config GET; since P1 an empty status, a
	// config-read failure, or a transport failure all return an error, which
	// ABORTS here (0 stop, 0 destroy). An unverifiable read is never treated
	// as "stopped".
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		return fmt.Errorf("vm destroy: vm %d: status gate: %w", op.VMID, err)
	}
	// Local refusal mirroring VMShutdown.Read (vmshutdown.go:125-134): GetVM's
	// own contract never returns (nil, nil) or an empty status, but this
	// interface can, and an unverifiable read must never fall through as "not
	// stopped" and trigger a stop+destroy. Fail closed with ErrUnverifiableRead.
	if vm == nil || vm.Status == "" {
		return fmt.Errorf("vm destroy: vm %d: status gate: %w", op.VMID, pve.ErrUnverifiableRead)
	}

	// Step 2: stop, gated and fail-closed. Skip the stop ONLY on a
	// positively-parsed "stopped" (a hibernated VM also reports "stopped" and
	// is correctly skipped). Every other state — including a paused VM, which
	// PVE reports as Status "running" — sends the hard stop and RETURNS on any
	// stop or stop-task failure (including an outcome-unknown one; %w keeps
	// pve.IsTaskOutcomeUnknown true for the caller), so the destroy below is
	// reached only once the stop is confirmed.
	if vm.Status != proxmox.StatusVirtualMachineStopped {
		upid, err := op.Client.StopVM(ctx, op.VMID)
		if err != nil {
			return fmt.Errorf("vm destroy: vm %d: stop: %w", op.VMID, err)
		}
		if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
			return fmt.Errorf("vm destroy: vm %d: stop: wait for task: %w", op.VMID, err)
		}
	}

	// Step 3: destroy, hard-fail.
	upid, err := op.Client.DestroyVM(ctx, op.VMID, true)
	if err != nil {
		return fmt.Errorf("vm destroy: vm %d: %w", op.VMID, err)
	}
	if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		return fmt.Errorf("vm destroy: vm %d: %w", op.VMID, err)
	}

	// Step 4: node-local reverify. A nil error (VM still answers) is the
	// failure here, not a non-nil one: WaitForTask succeeding above only
	// proves the DELETE task's own exit status was OK, not that this
	// node's own live state actually reflects the VM's removal. An
	// unclassified fetchVMConfig error is likewise a hard failure — it can
	// never be read as "proven removed."
	_, exists, err := op.fetchVMConfig(ctx)
	if err != nil {
		return fmt.Errorf("vm destroy: vm %d: reverify: could not confirm vm is gone: %w", op.VMID, err)
	}
	if exists {
		return fmt.Errorf("vm destroy: vm %d: destroy reported success but vm still exists", op.VMID)
	}

	// Step 5: stale-cache-tolerant tag recheck — informational only, never
	// fails Apply (the destroy itself already succeeded by this point).
	// A TagStillClaimed error is recorded on TagRecheckErr, distinct from
	// TagStillClaimedWarning, so a caller can tell "recheck ran, found
	// nothing" apart from "recheck didn't run at all" instead of both
	// silently reading as the same clean result.
	if op.Tag != "" {
		claimed, err := op.Client.TagStillClaimed(ctx, op.Tag, op.VMID)
		if err != nil {
			op.TagRecheckErr = fmt.Errorf("vm destroy: vm %d: tag recheck: %w", op.VMID, err)
		} else if claimed {
			op.TagStillClaimedWarning = true
		}
	}

	return nil
}
