package sourceguard

import (
	"strings"
	"testing"
)

// directiveAllow is the exact-path allow-list per kind. All empty: at the
// time this guard was written the module had no linkname directive, no
// non-test unsafe import, no non-Go source and no cgo import. A new entry is a reviewed
// exception, like TestSeam_NoProductionReferences' own — never a way to
// quiet this test.
var directiveAllow = map[EvasionKind]map[string]bool{
	EvasionLinkname: {},
	EvasionUnsafe:   {},
	EvasionNonGo:    {},
	EvasionCgo:      {},
}

// TestModule_NoDirectiveEvasions (D1) is the text-level layer under every
// AST-based guard in this repo (the roster KDF seam, the transport boundary,
// netguard's seams): no non-test file in the module carries a
// //go:linkname, imports "unsafe" or "C", or is a non-Go source — the ingredients
// of binding a production name to a symbol those guards forbid, which no
// identifier walk can see (pveforge-golinkname-defeats-source-guards).
//
// Anti-vacuity: the walk covers the module (a floor on files walked, and
// cmd/pveforge/main.go reached) and not this package's own evasion fixture,
// which DirectiveEvasions_D2 proves the scanner catches.
func TestModule_NoDirectiveEvasions(t *testing.T) {
	ev, err := DirectiveEvasions("../..")
	if err != nil {
		t.Fatalf("DirectiveEvasions: %v", err)
	}
	var bad []string
	for _, h := range ev.Hits {
		if !directiveAllow[h.Kind][h.File] {
			bad = append(bad, "  "+h.String())
		}
	}
	if len(bad) > 0 {
		t.Errorf("a directive-shaped evasion of the source guards is in production source:\n%s\n"+
			"A //go:linkname, an unsafe import or a non-Go file can reach any symbol the AST guards forbid, invisibly to them. "+
			"A real need is a reviewed entry in directiveAllow, not a way around this test.",
			strings.Join(bad, "\n"))
	}
	if len(ev.Walked) < 70 {
		t.Errorf("walked only %d files from the module root; the module has well over 70 — wrong root?", len(ev.Walked))
	}
	if !ev.Reached("cmd/pveforge/main.go") || !ev.Reached("internal/roster/secrets.go") {
		t.Error("the walk did not cover the module")
	}
	if ev.Reached("internal/sourceguard/testdata/evasion/pull.go") {
		t.Error("the walk reached the evasion fixture, which must be skipped as testdata")
	}
}
