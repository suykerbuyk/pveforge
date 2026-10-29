package pve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
)

// ParseNodeVMIDs decodes the JSON of `pvesh get /nodes/{node}/qemu
// --output-format json` strictly and returns that node's QEMU VMIDs, sorted
// ascending with no duplicates. It fails closed, as ErrUnverifiableRead, on
// anything a healthy PVE does not print: a reply that is not a bare JSON
// array (null, or a {"data":[...]} transport envelope — pvesh prints the
// array itself, not PVE's REST envelope), trailing data after the array, a
// null entry, a missing / null / empty / non-numeric / non-positive /
// range-overflowing vmid, or a vmid listed twice. An empty array [] is a
// node with no QEMU guests: a valid empty set, not a refusal (the same []
// vs null distinction GetVMs draws, vms.go).
//
// vmid is accepted as a JSON number OR a numeric string. go-proxmox decodes
// this exact endpoint's vmid as StringOrUint64 (types.go), whose
// UnmarshalJSON strips quotes before parsing and so accepts both 690 and
// "690"; a parser that refused the string form could reject a reply PVE's
// own client treats as valid (and the obvious mis-fix — skipping an
// unparseable entry — reintroduces the silent short-list this exists to
// prevent). The <1 / missing refusals are deliberately STRICTER than
// StringOrUint64, which decodes null/empty to 0: a VMID-0 is never a real
// guest and must never enter a destructive consumer's set.
//
// This is a new parser, not ParseClusterGuests reused: the /nodes/{node}/qemu
// index rows carry no "type" field (the endpoint is already qemu-only), so
// ParseClusterGuests' type-gate would refuse every real row. The strict,
// fail-closed decode skeleton is the same.
func ParseNodeVMIDs(b []byte) ([]int, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw []map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("node qemu list: %w: %v", ErrUnverifiableRead, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("node qemu list: %w: the list is null", ErrUnverifiableRead)
	}
	// Nothing may follow the array. dec.More reports false for a stray ']'
	// or '}', so the next token must be the end of input itself — the same
	// trailing-data guard ParseClusterGuests uses (guests.go).
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("node qemu list: %w: trailing data after the list", ErrUnverifiableRead)
	}
	seen := make(map[int]bool, len(raw))
	vmids := make([]int, 0, len(raw))
	for i, e := range raw {
		if e == nil {
			return nil, fmt.Errorf("node qemu list: %w: entry %d is null", ErrUnverifiableRead, i)
		}
		vmid, err := nodeEntryVMID(e["vmid"])
		if err != nil {
			return nil, fmt.Errorf("node qemu list: %w: entry %d has vmid %v: %s", ErrUnverifiableRead, i, e["vmid"], err)
		}
		if seen[vmid] {
			return nil, fmt.Errorf("node qemu list: %w: vmid %d is listed twice", ErrUnverifiableRead, vmid)
		}
		seen[vmid] = true
		vmids = append(vmids, vmid)
	}
	sort.Ints(vmids)
	return vmids, nil
}

// nodeEntryVMID reads one entry's vmid, accepting a json.Number or a numeric
// string (StringOrUint64's tolerance) and refusing everything a healthy PVE
// never emits for this field: a missing or null value (nil), a non-numeric
// value, a fractional or exponent form, a value below 1, or one outside the
// platform int range.
func nodeEntryVMID(v any) (int, error) {
	var s string
	switch t := v.(type) {
	case json.Number:
		s = t.String()
	case string:
		s = t
	case nil:
		return 0, fmt.Errorf("missing or null")
	default:
		return 0, fmt.Errorf("not a number or numeric string")
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	// Base-10 integer only: rejects "100.5", "1e2", and non-numeric text.
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a base-10 integer")
	}
	if n < 1 {
		return 0, fmt.Errorf("not a positive integer")
	}
	if n > int64(math.MaxInt) {
		return 0, fmt.Errorf("exceeds the platform int range")
	}
	return int(n), nil
}
