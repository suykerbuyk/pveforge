package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// VMDestroyClient is the subset of *pve.RoutedClient a VM-destroy Op needs:
// the raw REST passthrough (VMDestroy uses this for its existence check —
// see fetchVMConfig's own doc comment on why the typed GetVM getter can't
// be used for that), Node, the stop/destroy calls themselves, WaitForTask,
// and the post-destroy tag recheck. *pve.RoutedClient satisfies this
// interface structurally (see compat_test.go).
type VMDestroyClient interface {
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// RawRequest issues a raw PVE REST call — see pve.RoutedClient.RawRequest's
	// own doc comment. VMDestroy uses this exclusively for its existence
	// check (fetchVMConfig), never the typed GetVM getter.
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	// StopVM issues a best-effort stop for vmid.
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
// (pveforge-vm-lifecycle-ops item 2c): stop VMID (best-effort), destroy it
// (hard-fail), reverify against this client's own node that it's actually
// gone, and optionally recheck a tag it was resolved by for other VMs
// still claiming it.
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
//
// Not a PostApplier: Apply already verifies its own effect (step 3: the VM
// is confirmed gone) before it returns.
type VMDestroy struct {
	Client VMDestroyClient
	VMID   int
	// Tag, if non-empty, is the tag this VM was resolved by — triggers the
	// post-destroy stale-cache-tolerant recheck (Apply's step 4).
	Tag string

	// StopWarning is set by Apply if the best-effort stop (step 1) failed.
	// Never propagated as a hard error — see this type's own doc comment.
	StopWarning error
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

// vmConfigMissingSubstring, combined with a vmid-specific path fragment in
// isMissingVMError, is the text this project EXPECTS PVE's real "no such
// VM" response to contain — asserted from source review and PVE's
// documented config-file-backed VM model, NOT independently confirmed
// against a live host in this implementation session (same
// empirical-verification gap this project already tracks for
// pve.IsDigestConflictError's own substring and
// isMissingNetworkInterfaceError's — see resume.md's Open Threads).
const vmConfigMissingSubstring = "does not exist"

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
func isMissingVMError(err error, vmid int) bool {
	if err == nil {
		return false
	}
	needle := fmt.Sprintf("qemu-server/%d.conf", vmid)
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, needle) && strings.Contains(msg, vmConfigMissingSubstring)
}

// fetchVMConfig issues GET /nodes/{node}/qemu/{vmid}/config via RawRequest
// — never the typed GetVM getter, because go-proxmox's own transport
// (which GetVM goes through) discards the response body entirely on HTTP
// 500/501, the exact status PVE uses for "no such VM," so no classifier
// could ever be built on top of it. RawRequest preserves the body
// unconditionally, which is what makes isMissingVMError possible at all.
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

// Apply runs the four-step destroy sequence: (1) best-effort stop,
// (2) hard destroy, (3) node-local reverify, (4) stale-cache-tolerant tag
// recheck. See this type's own doc comment for the stop/destroy asymmetry
// and the WaitForTask-timeout hazard neither step guards against.
func (op *VMDestroy) Apply(ctx context.Context) error {
	// Step 1: stop, best-effort. Any failure here is recorded on
	// StopWarning and never blocks the hard destroy below.
	if upid, err := op.Client.StopVM(ctx, op.VMID); err != nil {
		op.StopWarning = fmt.Errorf("vm destroy: vm %d: stop: %w", op.VMID, err)
	} else if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		op.StopWarning = fmt.Errorf("vm destroy: vm %d: stop: wait for task: %w", op.VMID, err)
	}

	// Step 2: destroy, hard-fail.
	upid, err := op.Client.DestroyVM(ctx, op.VMID, true)
	if err != nil {
		return fmt.Errorf("vm destroy: vm %d: %w", op.VMID, err)
	}
	if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		return fmt.Errorf("vm destroy: vm %d: %w", op.VMID, err)
	}

	// Step 3: node-local reverify. A nil error (VM still answers) is the
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

	// Step 4: stale-cache-tolerant tag recheck — informational only, never
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
