package evasion

// Prose that mentions the directive is not the directive:
//
//	//go:linkname knob github.com/suykerbuyk/pveforge/internal/roster.scryptWorkFactorOverride
//
// and neither is a comment with a space after the slashes:
// go:linkname knob x
const decoy = "a string"
