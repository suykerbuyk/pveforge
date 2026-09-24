// Package evasion is DirectiveEvasions' positive control: each evasion the
// scanner must report, and decoys it must not. It is never built.
package evasion

import _ "unsafe"

// The pull form: a local name bound to another package's symbol.
//
//go:linkname knob github.com/suykerbuyk/pveforge/internal/roster.scryptWorkFactorOverride
var knob int

func init() { knob = 10 }
