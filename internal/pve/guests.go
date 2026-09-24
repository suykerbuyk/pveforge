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
// or an LXC container, with its tags as PVE stores them.
type Guest struct {
	Type string // "qemu" or "lxc"
	VMID int
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
		var tags string
		if v, present := e["tags"]; present {
			if tags, ok = v.(string); !ok {
				return nil, fmt.Errorf("cluster guest list: %w: %s %d has tags %v, not a string", ErrUnverifiableRead, typ, vmid, v)
			}
		}
		guests = append(guests, Guest{Type: typ, VMID: int(vmid), Tags: tags})
	}
	return guests, nil
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
