package idempotent

import (
	"sort"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// BuildFieldsEnsure translates an UNORDERED desired field/value map — the
// natural shape for a declarative spec, unlike `vm set`'s ordered CLI args
// — into a *VMFieldsEnsure ready for idempotent.Run. VMFieldsEnsure is
// already the full read-diff-write convergence engine (pveforge-vm-set-
// unlocked); this function's only job is the map-to-ordered-Pairs
// translation above it.
//
// desired's keys are sorted lexicographically before building Pairs.
// VMFieldsEnsure.Apply iterates Pairs in caller order and stops at the
// first non-conflict failure (its own documented "stop at first failure"
// contract) — but a Go map has no iteration order, so without an imposed
// order the SAME desired map could produce a DIFFERENT partial-failure
// point on every run, a correctness-adjacent nondeterminism bug that would
// never surface until a real Apply-time failure partway through a
// multi-field batch.
//
// The constructed Op's own Validate() is called before returning — it
// already rejects an empty desired (via len(Pairs)==0) and a non-positive
// vmid, so this function fails fast at construction without duplicating
// either check.
func BuildFieldsEnsure(client Client, vmid int, desired map[string]string) (*VMFieldsEnsure, error) {
	keys := make([]string, 0, len(desired))
	for k := range desired {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]kvjson.Pair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, kvjson.Pair{Field: k, Value: desired[k]})
	}

	op := &VMFieldsEnsure{Client: client, VMID: vmid, Pairs: pairs}
	if err := op.Validate(); err != nil {
		return nil, err
	}
	return op, nil
}
