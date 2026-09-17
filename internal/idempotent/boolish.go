package idempotent

import "strings"

// fieldsEqual reports whether current and wanted represent the same field
// value, treating four specific boolean-shaped tokens — "true", "false",
// "1", "0" (case-insensitive, whitespace-trimmed) — as equivalent to their
// counterpart regardless of which side wrote which form: PVE can report a
// boolean-shaped field (e.g. NetworkFieldsEnsure's vlan_filtering,
// VMFieldsEnsure's protection/onboot/template/tablet/kvm/acpi/numa/
// autostart/ciupgrade — go-proxmox's own IntOrBool type exists precisely
// because these arrive as either form) as a JSON bool (kvjson.Scalar
// renders that as literal "true"/"false"), while the PVE-CLI convention a
// caller is likely to type is "1"/"0" — kvjson.Scalar itself has no
// normalization for this (see internal/kvjson/kvjson.go's Scalar), and
// this package is deliberately the only place that gets one, scoped to
// these Ops' own comparisons rather than touching the shared kvjson
// package every other field/render path also depends on.
//
// The empty string "" is deliberately EXCLUDED from the four-token set: in
// both NetworkFieldsEnsure and VMFieldsEnsure, a field absent from current
// state is represented by the key being absent entirely from that Op's own
// current-state map (never by an empty-string value), so "" reaching this
// function at all already means a field is genuinely, deliberately set to
// empty text — that must never be treated as boolean-false-shaped, or it
// would silently match a caller's wanted "false"/"0" for a field that was
// never actually false.
func fieldsEqual(current, wanted string) bool {
	cb, cok := parseBoolish(current)
	wb, wok := parseBoolish(wanted)
	if cok && wok {
		return cb == wb
	}
	return current == wanted
}

// parseBoolish reports s's boolean value and whether s is one of the four
// recognized boolean-shaped tokens at all — see fieldsEqual's own doc
// comment for exactly which four and why the empty string isn't one of
// them.
func parseBoolish(s string) (value bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	default:
		return false, false
	}
}
