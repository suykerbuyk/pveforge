package outer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// U-PROBE storage-capability layer (FINDING A): the static-status checks
// (inline at probe.sh:127-140) and the empirical storage accounting
// (harness_storage_baseline lib.sh:695, harness_storage_used :718,
// harness_storage_leftover :734). Net-new — U-CORE scoped storage out. All
// decoding is RAW JSON (not pve.GetStorage/proxmox.Storage, which rejects a
// boolean enabled/active and truncates a fractional used): a storage's own
// JSON is read on its own terms, every state decision on a typed field.

// storageIDRE matches a PVE storage id (harness_require_storage, lib.sh:226).
var storageIDRE = regexp.MustCompile(`^[a-z][a-z0-9._-]*[a-z0-9]$`)

// StorageSlack is HARNESS_USED_SLACK (lib.sh:675): how far above its baseline
// a storage's `used` may sit and not count as a leftover — the empty ZFS
// dataset's own metadata. 1 MiB.
const StorageSlack int64 = 1 << 20

// gib is one GiB in bytes, PVE's and the probe's unit for free space.
const gib int64 = 1 << 30

// StorageStatus is a storage's /status, decoded only as far as the probe's
// checks need. Enabled/Active came from a number (1) or a bool (true).
type StorageStatus struct {
	Type    string
	Enabled bool
	Active  bool
	Content string
	Avail   int64
	Used    int64
	HasUsed bool
}

// RequireStorage validates the storage id (harness_require_storage,
// lib.sh:226): there is no default; it must look like a PVE storage id.
func RequireStorage(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("the outer storage is required (--storage or HARNESS_STORAGE); there is no default")
	}
	if !storageIDRE.MatchString(s) {
		return "", fmt.Errorf("%q is not a PVE storage id", s)
	}
	return s, nil
}

// boolish reports a JSON token that is 1/0 or true/false as a bool. ok=false
// for anything else, so a missing or oddly-typed flag never reads as enabled.
func boolish(raw json.RawMessage) (val, ok bool) {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	return false, false
}

// intJSON reports a JSON token that is a non-negative INTEGER number as an
// int64. A fraction (PVE occasionally reports a fractional `used`) is NOT an
// integer: ok=false, so the caller treats it as an unexpected shape rather
// than truncating it (which proxmox.Storage does).
func intJSON(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64() // Int64 fails on a fractional literal like "1.5"
	if err != nil || i < 0 {
		return 0, false
	}
	return i, true
}

// ParseStorageStatus decodes a /status answer as raw JSON (UseNumber), with
// the shape probe.sh:127 asserts: an object with a string type, a numeric
// avail and a string content. enabled/active are read as boolish; used, when
// present, must be a non-negative integer. A bad shape is an error (the
// caller fails, it never refuses a storage for a shape it could not read).
func ParseStorageStatus(raw json.RawMessage) (StorageStatus, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return StorageStatus{}, fmt.Errorf("the status answer has an unexpected shape: %w", err)
	}
	var st StorageStatus
	if err := json.Unmarshal(m["type"], &st.Type); err != nil || st.Type == "" {
		return StorageStatus{}, fmt.Errorf("the status answer has an unexpected shape: no string type")
	}
	if err := json.Unmarshal(m["content"], &st.Content); err != nil {
		return StorageStatus{}, fmt.Errorf("the status answer has an unexpected shape: no string content")
	}
	avail, ok := intJSON(m["avail"])
	if !ok {
		return StorageStatus{}, fmt.Errorf("the status answer has an unexpected shape: avail is not an integer number")
	}
	st.Avail = avail
	st.Enabled, _ = boolish(m["enabled"])
	st.Active, _ = boolish(m["active"])
	if u, ok := intJSON(m["used"]); ok {
		st.Used, st.HasUsed = u, true
	}
	return st, nil
}

// Unsuitable returns a non-empty reason when the storage cannot hold the
// harness (probe.sh:129-140): not enabled, not active, content lacks the
// "images" ELEMENT (an element compare, so "imagesx" does NOT qualify), a
// type other than zfspool (lvmthin and every other type refused by name), or
// below minFreeGiB. "" means it passes the static checks.
func (s StorageStatus) Unsuitable(minFreeGiB int) string {
	if !s.Enabled {
		return "it is not enabled"
	}
	if !s.Active {
		return "it is not active"
	}
	if !contentHasImages(s.Content) {
		return "its content does not include images"
	}
	switch s.Type {
	case "zfspool":
	case "lvmthin":
		return "type lvmthin is not supported: the harness is proven on zfspool only (lvmthin support is a follow-up task)"
	default:
		return fmt.Sprintf("type %s cannot hold the harness: it needs zfspool (snapshots of raw disks)", s.Type)
	}
	if s.Avail < int64(minFreeGiB)*gib {
		return fmt.Sprintf("%d GiB free, below HARNESS_PROBE_MIN_FREE_GIB=%d", s.Avail/gib, minFreeGiB)
	}
	return ""
}

// contentHasImages splits content on commas and compares the element (never a
// substring), so "images,rootdir" qualifies and "imagesx" does not.
func contentHasImages(content string) bool {
	for _, c := range strings.Split(content, ",") {
		if c == "images" {
			return true
		}
	}
	return false
}

// BaselineUsed returns a storage's `used` now as the baseline the empirical
// run compares against, refusing when it is above the empty-dataset slack
// (harness_storage_baseline, lib.sh:695): the storage must be EMPTY, at most
// StorageSlack. A higher figure is an orphan the pool token cannot list, or
// an earlier run's ZFS free still in progress — a baseline that absorbed it
// would hide a leftover.
func BaselineUsed(st StorageStatus, storage string) (int64, error) {
	if !st.HasUsed {
		return 0, fmt.Errorf("storage %s's status has no usable 'used'", storage)
	}
	if st.Used > StorageSlack {
		return 0, fmt.Errorf("storage %s is not empty: its used is %d bytes, above the empty dataset's 1 MiB", storage, st.Used)
	}
	return st.Used, nil
}

// StorageReader is the read subset the storage layer needs — the same
// RawRequest-only Reader the guard/gone-proof use. *pve.RoutedClient
// satisfies it.
type StorageReader = Reader

// StatusPath / ContentPath build the storage endpoints.
func StatusPath(node, storage string) string {
	return fmt.Sprintf("/nodes/%s/storage/%s/status", node, storage)
}

func ContentPath(node, storage string) string {
	return fmt.Sprintf("/nodes/%s/storage/%s/content", node, storage)
}

// ReadStorageStatus reads and parses /status.
func ReadStorageStatus(ctx context.Context, r Reader, node, storage string) (StorageStatus, json.RawMessage, error) {
	raw, err := r.RawRequest(ctx, http.MethodGet, StatusPath(node, storage), nil)
	if err != nil {
		return StorageStatus{}, nil, fmt.Errorf("storage %s's status could not be read: %w", storage, err)
	}
	st, err := ParseStorageStatus(raw)
	if err != nil {
		return StorageStatus{}, raw, fmt.Errorf("storage %s: %w", storage, err)
	}
	return st, raw, nil
}

// StorageLeftover is a DETECTOR (harness_storage_leftover, lib.sh:726-737): it
// waits up to bound for `used` to be back within StorageSlack of baseline with
// no volume of any vmid listed (ZFS frees asynchronously). It returns (true,
// reason) only when it DETECTS a leftover — a volume still listed, or `used`
// still above baseline when the wait ends. A status it cannot read detects
// NOTHING (returns false, ""), never a failure (PollIsBounded). bound=0 means
// one read, no wait. The bound/poll are PER CALL (B2): the probe passes 180s,
// the build 600s (three large zvols) or 0 when a VM is not yet proven gone.
func StorageLeftover(ctx context.Context, r Reader, node, storage string, baseline int64, vmids []int, bound, poll time.Duration) (bool, string) {
	deadline := time.Now().Add(bound)
	for {
		used, usedOK := readUsed(ctx, r, node, storage)
		listed := listedVMIDs(ctx, r, node, storage, vmids)
		if usedOK && used <= baseline+StorageSlack && len(listed) == 0 {
			return false, "" // back to baseline, nothing listed: not a leftover
		}
		if bound == 0 || !time.Now().Before(deadline) {
			// Wait is over, however it ends.
			if len(listed) > 0 {
				return true, fmt.Sprintf("storage %s still lists volumes of VM(s) %v", storage, listed)
			}
			if usedOK {
				return true, fmt.Sprintf("storage %s's used is %d, not back within 1 MiB of its baseline %d", storage, used, baseline)
			}
			return false, "" // status unreadable at the end: nothing detected, nothing proven
		}
		select {
		case <-ctx.Done():
			return false, ""
		case <-time.After(poll):
		}
	}
}

func readUsed(ctx context.Context, r Reader, node, storage string) (int64, bool) {
	raw, err := r.RawRequest(ctx, http.MethodGet, StatusPath(node, storage), nil)
	if err != nil {
		return 0, false
	}
	st, err := ParseStorageStatus(raw)
	if err != nil || !st.HasUsed {
		return 0, false
	}
	return st.Used, true
}

func listedVMIDs(ctx context.Context, r Reader, node, storage string, vmids []int) []int {
	var listed []int
	for _, v := range vmids {
		raw, err := r.RawRequest(ctx, http.MethodGet, ContentPath(node, storage), url.Values{"vmid": {fmt.Sprint(v)}})
		if err != nil {
			continue
		}
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			listed = append(listed, v)
		}
	}
	return listed
}
