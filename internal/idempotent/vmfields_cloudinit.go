package idempotent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// cloudInitKeys are the VM config keys PVE renders into the VM's cloud-init
// drive, besides ipconfigN and netN (isCloudInitKey) — qemu-server's
// cloudinit_pending_properties, from a reading of its source (UNVERIFIED
// live, like the rest of this file). A change to one is saved in the config
// at once, or for netN may be held pending (then /pending reports it), but
// the guest sees it only once the drive is regenerated (at the VM's next
// start) and cloud-init runs again inside it. name is the guest's hostname
// on the drive.
var cloudInitKeys = map[string]bool{
	"ciuser": true, "cipassword": true, "citype": true, "ciupgrade": true,
	"cicustom": true, "sshkeys": true, "nameserver": true, "searchdomain": true,
	"name": true,
}

// cloudInitIndexed are the key prefixes that take a decimal index and are
// rendered into the drive: ipconfigN (the guest's addresses) and netN (its
// NIC's MAC, in the drive's network config).
var cloudInitIndexed = []string{"ipconfig", "net"}

// isCloudInitKey reports whether a config key is rendered into the
// cloud-init drive: one of cloudInitKeys, or ipconfigN or netN for a
// decimal N.
func isCloudInitKey(key string) bool {
	if cloudInitKeys[key] {
		return true
	}
	for _, p := range cloudInitIndexed {
		if n, ok := strings.CutPrefix(key, p); ok && n != "" && strings.Trim(n, "0123456789") == "" {
			return true
		}
	}
	return false
}

// CloudInitCheckError is PostApply's error when /pending was read and only
// the cloud-init check after it failed, so a caller can say which question
// went unanswered: whether a change is pending was answered; whether it has
// reached the cloud-init drive was not. It unwraps to the cause.
type CloudInitCheckError struct{ Err error }

func (e *CloudInitCheckError) Error() string { return e.Err.Error() }
func (e *CloudInitCheckError) Unwrap() error { return e.Err }

// checkCloudInit is PostApply's second read, pveforge-post-apply-verification-
// and-pending's P2′: only when this Run wrote or deleted a cloud-init key
// that /pending did not already report, it reads GET
// /nodes/{node}/qemu/{vmid}/cloudinit once and records in CloudInitStale and
// CloudInitStaleDeletes which of those keys PVE has not yet written to the
// drive. Its error, like /pending's, is Result.PostApplyErr: advisory.
//
// NOT verified against a live host, owed to the nested harness
// (pveforge-nested-pve-test-harness): that PVE 9.2.x answers /cloudinit
// (PVE 7.2+) with the same array of {key, value?, pending?, delete?} as
// /pending — "value" what the current drive holds, "pending" a configured
// value not yet on it, "delete" 1 for a key removed from the config but
// still on it; that ci changes are never also held in /pending (if they
// are, this read adds nothing, and the double-report rule keeps the output
// right); the exact key set PVE renders; and that the read needs only
// VM.Audit. The decode is strict for the same reason as /pending's: an
// answer of any other shape is pve.ErrUnverifiableRead, never "nothing to
// report".
func (op *VMFieldsEnsure) checkCloudInit(ctx context.Context) error {
	var writes, deletes []string
	for _, f := range op.Applied {
		if isCloudInitKey(f) && !slices.Contains(op.Pending, f) {
			writes = append(writes, f)
		}
	}
	for _, f := range op.Deleted {
		if isCloudInitKey(f) && !slices.Contains(op.PendingDeletes, f) {
			deletes = append(deletes, f)
		}
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	path := fmt.Sprintf("/nodes/%s/qemu/%d/cloudinit", url.PathEscape(op.Client.Node()), op.VMID)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return &CloudInitCheckError{fmt.Errorf("vm fields ensure: vm %d: read the cloud-init drive's state: %w", op.VMID, err)}
	}
	stale, staleDel, err := decodeChanges(raw, "cloud-init")
	if err != nil {
		return &CloudInitCheckError{fmt.Errorf("vm fields ensure: vm %d: read the cloud-init drive's state: %w", op.VMID, err)}
	}
	var keys, dels []string
	for _, f := range writes {
		if stale[f] {
			keys = append(keys, f)
		}
	}
	for _, f := range deletes {
		if staleDel[f] {
			dels = append(dels, f)
		}
	}
	op.CloudInitStale, op.CloudInitStaleDeletes = keys, dels
	return nil
}
