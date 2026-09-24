package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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
func (op *VMFieldsEnsure) PostApply(ctx context.Context) error {
	op.Pending, op.PendingDeletes = nil, nil
	op.CloudInitStale, op.CloudInitStaleDeletes = nil, nil
	if len(op.Applied) == 0 && len(op.Deleted) == 0 {
		return nil
	}
	path := fmt.Sprintf("/nodes/%s/qemu/%d/pending", url.PathEscape(op.Client.Node()), op.VMID)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("vm fields ensure: vm %d: read pending changes: %w", op.VMID, err)
	}
	pending, deleting, err := decodePending(raw)
	if err != nil {
		return fmt.Errorf("vm fields ensure: vm %d: read pending changes: %w", op.VMID, err)
	}
	var keys, deletes []string
	for _, f := range op.Applied {
		if pending[f] {
			keys = append(keys, f)
		}
	}
	for _, f := range op.Deleted {
		if deleting[f] {
			deletes = append(deletes, f)
		}
	}
	op.Pending, op.PendingDeletes = keys, deletes
	return op.checkCloudInit(ctx)
}

// decodePending strictly decodes a /pending answer into the keys with a
// pending value and the keys with a pending removal. Anything a healthy PVE
// does not produce — not an array, null, an entry that is not an object or
// has no string key, a "delete" that is not 0, 1 or 2 — is
// pve.ErrUnverifiableRead: never read as "nothing is pending".
func decodePending(raw json.RawMessage) (pending, deleting map[string]bool, err error) {
	return decodeChanges(raw, "pending")
}

// decodeChanges is decodePending for any PVE list of the same
// {key, value?, pending?, delete?} shape; list names it in errors.
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
