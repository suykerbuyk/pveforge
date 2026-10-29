package pve

import (
	"errors"
	"slices"
	"testing"
)

// ParseNodeVMIDs decodes root's `pvesh get /nodes/{node}/qemu` strictly: a
// healthy reply is a bare JSON array of objects carrying a positive-integer
// vmid (as a number OR a numeric string), and anything else is an
// unverifiable read, never a short or empty list.
func TestParseNodeVMIDs_Good(t *testing.T) {
	// Mixed vmid forms (number and string), out of order, with extra fields
	// the parser ignores (status/name/maxmem).
	good := `[{"vmid":300,"status":"running","name":"c"},` +
		`{"vmid":"100","status":"stopped","name":"a"},` +
		`{"vmid":690,"status":"running","name":"b","maxmem":1073741824}]`
	got, err := ParseNodeVMIDs([]byte(good))
	if err != nil {
		t.Fatalf("ParseNodeVMIDs(good) error: %v", err)
	}
	if want := []int{100, 300, 690}; !slices.Equal(got, want) {
		t.Fatalf("ParseNodeVMIDs(good) = %v, want %v (sorted, both vmid forms accepted)", got, want)
	}

	// An empty node is a valid empty set, not a refusal.
	if got, err := ParseNodeVMIDs([]byte(`[]`)); err != nil || len(got) != 0 {
		t.Errorf("ParseNodeVMIDs([]) = %v, %v; want empty, nil", got, err)
	}
}

// Completeness: the root list must include a VMID a token would omit (the
// measured ACL/NoAccess omission, Batch C item 76), AND a malformed entry
// beside valid ones must REFUSE the whole read, never silently drop it — the
// property that keeps a skip-bad-entry mutant from producing a short list a
// destructive free would trust.
func TestParseNodeVMIDs_Completeness(t *testing.T) {
	// root's ACL-unfiltered list carries 690 (which the token's GetVMs omits).
	root := `[{"vmid":100},{"vmid":690},{"vmid":300}]`
	got, err := ParseNodeVMIDs([]byte(root))
	if err != nil {
		t.Fatalf("ParseNodeVMIDs(root) error: %v", err)
	}
	if !slices.Contains(got, 690) {
		t.Fatalf("ParseNodeVMIDs(root) = %v, want it to CONTAIN 690 (root leaves out nothing)", got)
	}

	// A bad entry among valid ones refuses the whole read — it is NOT skipped
	// to yield [100, 690]. A skip-bad-entry mutant returns [100,690], nil and
	// fails this assertion (RED).
	mixed := `[{"vmid":100},{"vmid":"bad"},{"vmid":690}]`
	if got, err := ParseNodeVMIDs([]byte(mixed)); err == nil || !errors.Is(err, ErrUnverifiableRead) || got != nil {
		t.Fatalf("ParseNodeVMIDs(bad-entry-among-valid) = %v, %v; want nil + ErrUnverifiableRead (refuse, never silently drop)", got, err)
	}
}

func TestParseNodeVMIDs_FailsClosed(t *testing.T) {
	for name, bad := range map[string]string{
		"null":             `null`,
		"empty input":      ``,
		"not json":         `pvesh: 591 no such resource`,
		"data envelope":    `{"data":[{"vmid":100}]}`,
		"an object":        `{"vmid":100}`,
		"trailing array":   `[] []`,
		"a stray ]":        `[]]`,
		"a stray }":        `[{"vmid":100}]}`,
		"trailing text":    `[{"vmid":100}] x`,
		"a null entry":     `[null]`,
		"vmid missing":     `[{"status":"running"}]`,
		"vmid null":        `[{"vmid":null}]`,
		"vmid empty str":   `[{"vmid":""}]`,
		"vmid non-numeric": `[{"vmid":"abc"}]`,
		"vmid fractional":  `[{"vmid":100.5}]`,
		"vmid exponent":    `[{"vmid":1e2}]`,
		"vmid zero":        `[{"vmid":0}]`,
		"vmid negative":    `[{"vmid":-5}]`,
		"vmid overflow":    `[{"vmid":99999999999999999999}]`,
		"vmid an array":    `[{"vmid":[100]}]`,
		"duplicate vmid":   `[{"vmid":100},{"vmid":"100"}]`,
	} {
		got, err := ParseNodeVMIDs([]byte(bad))
		if err == nil || !errors.Is(err, ErrUnverifiableRead) || got != nil {
			t.Errorf("%s: ParseNodeVMIDs(%q) = %v, %v; want nil + ErrUnverifiableRead", name, bad, got, err)
		}
	}
}
