package pve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Guest is one entry of PVE's cluster resource list of type vm: a QEMU VM
// or an LXC container, with the node it lives on and its tags as PVE stores
// them.
//
// Node is REQUIRED (U-CWCV C-1/R5): the cluster-wide claimed-set union reads
// each guest's /nodes/{node}/qemu/{vmid}/config, so a guest with no node is
// useless and a lenient "missing node = empty" would silently claim nothing
// for that VM (a freed live disk). ParseClusterGuests refuses a row with no
// non-empty string node — unlike Tags, whose absence is a legitimate empty.
type Guest struct {
	Type string // "qemu" or "lxc"
	VMID int
	Node string // the node the guest lives on; required
	Tags string
}

// Kind is how a refusal names the guest: "vm" for QEMU, "ct" for LXC, as
// PVE's own tools do.
func (g Guest) Kind() string {
	if g.Type == "lxc" {
		return "ct"
	}
	return "vm"
}

// ParseClusterGuests decodes the JSON of `pvesh get /cluster/resources
// --type vm --output-format json` (the REST list's schema) strictly. It
// fails closed, as ErrUnverifiableRead, on anything a healthy PVE does not
// produce: a reply that is not a JSON array (null included), an entry with
// no type or no positive integer vmid, a guest type other than qemu or lxc,
// or tags that are not a string. A missing tags field is a guest with no
// tags.
func ParseClusterGuests(b []byte) ([]Guest, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw []map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("cluster guest list: %w: %v", ErrUnverifiableRead, err)
	}
	if raw == nil {
		return nil, fmt.Errorf("cluster guest list: %w: the list is null", ErrUnverifiableRead)
	}
	// Nothing may follow the list. dec.More reports false for a stray ']'
	// or '}', so the next token must be the end of input itself.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("cluster guest list: %w: trailing data after the list", ErrUnverifiableRead)
	}
	guests := make([]Guest, 0, len(raw))
	for i, e := range raw {
		if e == nil {
			return nil, fmt.Errorf("cluster guest list: %w: entry %d is null", ErrUnverifiableRead, i)
		}
		typ, _ := e["type"].(string)
		if typ != "qemu" && typ != "lxc" {
			return nil, fmt.Errorf("cluster guest list: %w: entry %d has type %v, not qemu or lxc", ErrUnverifiableRead, i, e["type"])
		}
		n, ok := e["vmid"].(json.Number)
		vmid, err := n.Int64()
		if !ok || err != nil || vmid < 1 {
			return nil, fmt.Errorf("cluster guest list: %w: entry %d has vmid %v, not a positive integer", ErrUnverifiableRead, i, e["vmid"])
		}
		// node is REQUIRED and must be a non-empty string — a missing or empty
		// node is an unverifiable row, NOT an empty-defaulted field like tags
		// below (C-1/R5): the destructive union reads /nodes/{node}/qemu/… and a
		// blank node would silently claim nothing for this VM.
		node, ok := e["node"].(string)
		if !ok || node == "" {
			return nil, fmt.Errorf("cluster guest list: %w: %s %d has node %v, not a non-empty string", ErrUnverifiableRead, typ, vmid, e["node"])
		}
		var tags string
		if v, present := e["tags"]; present {
			if tags, ok = v.(string); !ok {
				return nil, fmt.Errorf("cluster guest list: %w: %s %d has tags %v, not a string", ErrUnverifiableRead, typ, vmid, v)
			}
		}
		guests = append(guests, Guest{Type: typ, VMID: int(vmid), Node: node, Tags: tags})
	}
	return guests, nil
}

// ClusterQemuPairs converts a cluster guest enumeration into the node-carrying
// (node, vmid) pairs the cluster-wide claimed-set union consumes
// (ClusterClaimedVolumes), QEMU-ONLY, cross-checking each guest's node against
// the positive online-node set (U-CWCV §4.3, the sound-but-weaker membership
// check).
//
//   - LXC guests are EXCLUDED: ClaimedVolumes reads a /nodes/{node}/qemu/…
//     path, so an LXC VMID there would 500 or address a same-numbered QEMU VM.
//   - A QEMU guest naming a node NOT reported online by /cluster/status is a
//     CORRUPTED/garbage enumeration and is REFUSED (ErrUnverifiableRead) BEFORE
//     any claim read — never silently dropped.
//   - An online node with ZERO guests does NOT false-refuse: nothing references
//     it, so there is nothing to validate.
//
// It returns a non-nil (possibly empty) slice, so ClusterClaimedVolumes does
// not mistake a genuinely zero-QEMU cluster for a dropped-enumeration nil.
//
// This does NOT close whole-node-omission (a node dropped from the enumeration
// entirely) nor the quorate-but-stale short list: both are indistinguishable
// from an empty node here, are deferred to
// pveforge-cluster-free-stale-shortlist-completeness, and are gated by the
// free's quorum check + warning. This check catches only an enumeration that
// names a node the cluster does not report online.
func ClusterQemuPairs(guests []Guest, onlineNodes map[string]bool) ([]NodeVMID, error) {
	pairs := make([]NodeVMID, 0, len(guests))
	for _, g := range guests {
		if g.Type != "qemu" {
			continue
		}
		if !onlineNodes[g.Node] {
			return nil, fmt.Errorf("cluster claimed set: %w: guest vmid %d names node %q, which /cluster/status does not report online", ErrUnverifiableRead, g.VMID, g.Node)
		}
		pairs = append(pairs, NodeVMID{Node: g.Node, VMID: g.VMID})
	}
	return pairs, nil
}

// guestTagSplit separates a guest's stored tags. PVE stores them
// ';'-joined; ',' and whitespace are what its tag-list format also accepts
// on input, so splitting on all of them can only find more matches, never
// fewer.
var guestTagSplit = regexp.MustCompile(`[;,\s]+`)

// FindGuestByTagFold returns the one guest, QEMU VM or LXC container,
// carrying tag, matched case-insensitively (strings.EqualFold) as PVE
// matches tags by default, and as a whole element, never a substring. No
// guest wraps ErrNotFound; more than one wraps ErrAmbiguousTag.
func FindGuestByTagFold(guests []Guest, tag string) (*Guest, error) {
	if tag == "" {
		return nil, fmt.Errorf("find guest by tag: tag is required")
	}
	var matches []Guest
	for _, g := range guests {
		for _, t := range guestTagSplit.Split(g.Tags, -1) {
			if t != "" && strings.EqualFold(t, tag) {
				matches = append(matches, g)
				break
			}
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("find guest by tag %q: %w", tag, ErrNotFound)
	case 1:
		return &matches[0], nil
	default:
		return nil, fmt.Errorf("find guest by tag %q: %d guests: %w", tag, len(matches), ErrAmbiguousTag)
	}
}
