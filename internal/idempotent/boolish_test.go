package idempotent

import "testing"

// TestFieldsEqual is migrated unmodified from networkfields_test.go
// (pveforge-vm-converge-fields, 2026-09-16 boolish extraction) for its
// first 12 cases — same table, same case names, same assertions. The
// three empty-string-exclusion cases ("empty vs false", "empty vs 0",
// "false vs empty") are the ones that must still fail if parseBoolish's
// empty-string exclusion is ever removed; this migration is not proven
// behavior-preserving until they still pass, unmodified, from this new
// location.
//
// The trailing "not boolish" cases (added 2026-09-16, code review) prove
// the OTHER edge of the same boundary: parseBoolish's four-token domain
// (true/false/1/0) is deliberately narrow, and that narrowness is
// load-bearing. A field whose legitimate value happens to be the literal
// string "yes" (or "on") must never be silently compared as a boolean —
// if it were, it could read as already-satisfied against a caller's "1"
// when it never actually was, silently dropping a requested change. The
// cross-comparison cases (current "yes"/"on"/"no"/"off" vs. a numeric
// token) prove the fifth/sixth token is NOT recognized as boolish at all;
// the self-comparison cases ("yes" vs "yes") prove the rejection falls
// through to a genuine exact-string comparison rather than a hardcoded
// "always false for anything unrecognized" shortcut that would happen to
// produce the same answer for the wrong reason.
func TestFieldsEqual(t *testing.T) {
	cases := []struct {
		name            string
		current, wanted string
		want            bool
	}{
		{"exact string match", "9000", "9000", true},
		{"exact string mismatch", "9000", "1500", false},
		{"true vs 1", "true", "1", true},
		{"false vs 0", "false", "0", true},
		{"TRUE vs 1 (case-insensitive)", "TRUE", "1", true},
		{" true  vs 1 (trimmed)", " true ", "1", true},
		{"true vs 0", "true", "0", false},
		{"1 vs 0", "1", "0", false},
		{"empty vs false", "", "false", false},
		{"empty vs 0", "", "0", false},
		{"false vs empty", "false", "", false},
		{"non-boolish exact match", "eth0", "eth0", true},
		{"yes is not boolish (vs 1)", "yes", "1", false},
		{"no is not boolish (vs 0)", "no", "0", false},
		{"on is not boolish (vs 1)", "on", "1", false},
		{"off is not boolish (vs 0)", "off", "0", false},
		{"yes vs yes (not boolish, falls through to exact match)", "yes", "yes", true},
		{"on vs on (not boolish, falls through to exact match)", "on", "on", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fieldsEqual(tc.current, tc.wanted); got != tc.want {
				t.Fatalf("fieldsEqual(%q, %q) = %v, want %v", tc.current, tc.wanted, got, tc.want)
			}
		})
	}
}
