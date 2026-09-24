package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// VMFieldsEnsure is a PostApplier: after a batch that changed something, it
// asks PVE which of those changes are only pending.
var _ PostApplier = (*VMFieldsEnsure)(nil)

// PostApply reads GET /nodes/{node}/qemu/{vmid}/pending once, after Run's
// final attempt and still under the VM's lock, and records in Pending and
// PendingDeletes which of this Run's writes (Applied) and removals (Deleted)
// PVE holds as pending: persisted in the config — so Read already sees them
// — but not yet adopted by the running guest, which takes them at its next
// cold boot. Run reports its error as Result.PostApplyErr, which never fails
// the Run: the change was made either way.
//
// Keys are matched by presence, never by value: PVE canonicalises written
// values (net0 gains a MAC), and a pending value is no exception.
//
// NOT verified against a live host, owed to the nested harness
// (pveforge-nested-pve-test-harness): the exact /pending shape on PVE 9.2.x
// — an array of {key, value?, pending?, delete?}, "pending" present only
// for a change not yet applied, "delete" 1 or 2 for a pending removal; that
// a stopped VM reports nothing pending (a write applies at once); that a
// hot-pluggable change on a running VM is not left pending; that a
// root-only write over SSH (qm set) is pending the same way; and that the
// read needs only VM.Audit.
//
// The same read also answers for the keys this command asked for that the
// Run did not change because they already read as set (or, for a delete, as
// absent) — a Read without current=1 sees a pending value as applied — and
// records in AlreadyPending and AlreadyPendingDeletes which of those PVE
// still holds pending: the mixed batch, where one key changes and another
// is skipped. No extra request: when nothing changed there is no /pending
// read here at all (PostNoop is the no-op path's check), and the skipped
// keys never trigger the cloud-init read.
func (op *VMFieldsEnsure) PostApply(ctx context.Context) error {
	op.resetFindings()
	if !op.Wrote() {
		return nil
	}
	pending, deleting, err := op.readChanges(ctx, "pending", "read pending changes")
	if err != nil {
		return err
	}
	op.Pending, op.PendingDeletes = pick(op.Applied, pending), pick(op.Deleted, deleting)
	op.AlreadyPending = pick(without(op.requestedFields(), op.Applied), pending)
	op.AlreadyPendingDeletes = pick(without(op.Deletes, op.Deleted), deleting)
	op.CloudInitStale, op.CloudInitStaleDeletes, err = op.checkCloudInit(ctx, op.Applied, op.Deleted, op.Pending, op.PendingDeletes)
	return err
}

var _ NoopChecker = (*VMFieldsEnsure)(nil)

// PostNoop is the no-op path's check (NoopChecker): every requested value
// already read as set and every requested delete as absent, but a Read
// without current=1 sees a value PVE holds pending as already applied — so
// re-running a change that is still only pending would otherwise report
// nothing. It reads /pending once and records in AlreadyPending and
// AlreadyPendingDeletes which of this command's requested keys PVE still
// holds pending; then, only for requested cloud-init keys not already
// found pending, reads /cloudinit once and records in AlreadyCloudInitStale
// and AlreadyCloudInitStaleDeletes which are not yet on the drive. Only
// keys this command asked for are reported, in the order it asked. Its
// error, through the same strict decoding as PostApply's, is
// Result.PostApplyErr with Changed false: advisory.
//
// NOT verified against a live host, owed to pveforge-nested-pve-test-
// harness: the /pending answer for a key re-requested while it is still
// pending (see PostApply for the rest of /pending's shape).
//
// A no-op Run can still have written: an attempt that wrote some keys and
// then hit a digest conflict is superseded, and the retry can find the rest
// already as requested (an outside writer set them). Then Wrote is true,
// and PostNoop is PostApply — this Run's own writes are reported as P1's
// pending changes, and only the requested keys it never touched as
// already set — never "already set" for a key this Run wrote.
func (op *VMFieldsEnsure) PostNoop(ctx context.Context) error {
	if op.Wrote() {
		return op.PostApply(ctx)
	}
	op.resetFindings()
	fields := op.requestedFields()
	if len(fields) == 0 && len(op.Deletes) == 0 {
		return nil
	}
	pending, deleting, err := op.readChanges(ctx, "pending", "read pending changes")
	if err != nil {
		return err
	}
	op.AlreadyPending, op.AlreadyPendingDeletes = pick(fields, pending), pick(op.Deletes, deleting)
	op.AlreadyCloudInitStale, op.AlreadyCloudInitStaleDeletes, err = op.checkCloudInit(ctx, fields, op.Deletes, op.AlreadyPending, op.AlreadyPendingDeletes)
	return err
}

// Wrote reports whether this Run wrote or deleted anything, on any attempt:
// Applied and Deleted accumulate across a conflict retry, so this holds even
// when the Run ended on the no-op path (Result.Changed false) after an
// earlier attempt's writes. It is the fact a caller words its report by.
func (op *VMFieldsEnsure) Wrote() bool {
	return len(op.Applied) > 0 || len(op.Deleted) > 0
}

// resetFindings clears what an earlier PostApply or PostNoop found.
func (op *VMFieldsEnsure) resetFindings() {
	op.Pending, op.PendingDeletes = nil, nil
	op.CloudInitStale, op.CloudInitStaleDeletes = nil, nil
	op.AlreadyPending, op.AlreadyPendingDeletes = nil, nil
	op.AlreadyCloudInitStale, op.AlreadyCloudInitStaleDeletes = nil, nil
}

// requestedFields is the field names of Pairs, in order.
func (op *VMFieldsEnsure) requestedFields() []string {
	fields := make([]string, 0, len(op.Pairs))
	for _, p := range op.Pairs {
		fields = append(fields, p.Field)
	}
	return fields
}

// readChanges reads GET /nodes/{node}/qemu/{vmid}/<list> once and decodes
// it strictly (decodeChanges); what names the read in its error.
func (op *VMFieldsEnsure) readChanges(ctx context.Context, list, what string) (pending, deleting map[string]bool, err error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/%s", url.PathEscape(op.Client.Node()), op.VMID, list)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vm fields ensure: vm %d: %s: %w", op.VMID, what, err)
	}
	pending, deleting, err = decodeChanges(raw, list)
	if err != nil {
		return nil, nil, fmt.Errorf("vm fields ensure: vm %d: %s: %w", op.VMID, what, err)
	}
	return pending, deleting, nil
}

// pick is the keys of list in set, in list's order; nil when none are.
func pick(list []string, set map[string]bool) []string {
	var out []string
	for _, k := range list {
		if set[k] {
			out = append(out, k)
		}
	}
	return out
}

// without is list less every key in drop, in list's order.
func without(list, drop []string) []string {
	var out []string
	for _, k := range list {
		if !slices.Contains(drop, k) {
			out = append(out, k)
		}
	}
	return out
}

// decodeChanges strictly decodes a PVE list of {key, value?, pending?,
// delete?} entries — /pending, and /cloudinit — into the keys with a
// pending value and the keys with a pending removal; list names it in
// errors. Anything a healthy PVE does not produce — not an array, null, an
// entry that is not an object or has no string key, a "delete" that is not
// 0, 1 or 2 — is pve.ErrUnverifiableRead: never read as "nothing is
// pending".
func decodeChanges(raw json.RawMessage, list string) (pending, deleting map[string]bool, err error) {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, nil, fmt.Errorf("%w: the %s list is not a JSON array", pve.ErrUnverifiableRead, list)
	}
	pending, deleting = map[string]bool{}, map[string]bool{}
	for i, e := range entries {
		if e == nil {
			return nil, nil, fmt.Errorf("%w: %s entry %d is not an object", pve.ErrUnverifiableRead, list, i)
		}
		var key string
		if err := json.Unmarshal(e["key"], &key); err != nil || key == "" {
			return nil, nil, fmt.Errorf("%w: %s entry %d has no key", pve.ErrUnverifiableRead, list, i)
		}
		if d, ok := e["delete"]; ok {
			var n int
			if err := json.Unmarshal(d, &n); err != nil || n < 0 || n > 2 {
				return nil, nil, fmt.Errorf("%w: %s entry %d has a delete flag that is not 0, 1 or 2", pve.ErrUnverifiableRead, list, i)
			}
			if n > 0 {
				deleting[key] = true
				continue
			}
		}
		if _, ok := e["pending"]; ok {
			pending[key] = true
		}
	}
	return pending, deleting, nil
}
