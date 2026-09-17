package sourceguard

import (
	"sort"
	"strings"
	"testing"
)

// The fixture package under testdata/ plants one distinctive token in each
// position that matters. testdata/ is invisible to the go tool's own build,
// so these files are only ever read as parser input.
const fixtureDir = "testdata/fixture"

// TestReachableTokens_IsNotVacuous is the calibration this package needs
// most: every guard built on it is an assertion that a scan found NOTHING,
// and a scanner that silently returned nothing would make all of them pass
// vacuously while proving exactly zero. Each subtest below plants a token
// and demands the scan actually finds it.
func TestReachableTokens_IsNotVacuous(t *testing.T) {
	tokens, err := ReachableTokens(fixtureDir, []string{"Root"})
	if err != nil {
		t.Fatalf("ReachableTokens: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("scan returned nothing at all — every guard built on this would pass vacuously")
	}

	all := flatten(tokens)
	mustFind := []struct{ token, why string }{
		{"plantedAfterSlashes", "a token on the same line AFTER a string literal containing // — the truncation bug that made the old hand-rolled comment stripper weaker, not stricter, than its comment claimed"},
		{"planted/in/a/sibling/file", "a token in a SIBLING FILE reached only by following a call — the one-file blind spot this package exists to close"},
		{"second-root-token", "a token behind a second call from the root"},
	}
	for _, c := range mustFind {
		if !contains(all, c.token) {
			t.Errorf("scan did not find %q: %s", c.token, c.why)
		}
	}
}

// TestReachableTokens_IgnoresCommentsAndUnreachableCode pins the other
// direction. A scan that swept the whole package text would fire on the
// fixture's comments and on Unreachable(), making the guard unusable in a
// package that legitimately contains a hard stop somewhere else — which
// internal/pve does (vmdestroy.go's StopVM).
func TestReachableTokens_IgnoresCommentsAndUnreachableCode(t *testing.T) {
	all := flatten(mustScan(t, []string{"Root"}))

	for _, c := range []struct{ token, why string }{
		{"status/stop", "it appears only in a doc comment and in the unreachable function"},
		{"forceStop", "it appears only in a doc comment"},
		{"StopVM", "it appears only in an inline comment"},
		{"skiplock", "it appears only in an inline comment"},
		{"plantedInATestFile", "it lives in a _test.go file, which the parser filter must skip"},
	} {
		if contains(all, c.token) {
			t.Errorf("scan picked up %q, but %s", c.token, c.why)
		}
	}
}

// TestFindForbidden_MatchesAndReportsWhere proves the reporting half works:
// a planted token must be reported, attributed to the function it was found
// in, and matched case-insensitively.
func TestFindForbidden_MatchesAndReportsWhere(t *testing.T) {
	tokens := mustScan(t, []string{"Root"})

	hits := FindForbidden(tokens, []string{"PLANTED/IN/A/SIBLING/FILE"})
	if len(hits) != 1 {
		t.Fatalf("FindForbidden = %v, want exactly 1 hit (case-insensitively)", hits)
	}
	if !strings.Contains(hits[0], "helperInSiblingFile") {
		t.Errorf("hit %q does not name the function the token was found in", hits[0])
	}

	if hits := FindForbidden(tokens, []string{"a-token-nobody-planted"}); len(hits) != 0 {
		t.Errorf("FindForbidden invented %v for a token that is not there", hits)
	}
}

// TestReachableTokens_UnknownRootIsAnError is the guard against the failure
// mode that would be silent otherwise: if a guarded entry point is renamed,
// scanning nothing must be a loud error, not a clean pass.
func TestReachableTokens_UnknownRootIsAnError(t *testing.T) {
	if _, err := ReachableTokens(fixtureDir, []string{"NoSuchFunction"}); err == nil {
		t.Fatal("a root that does not exist must be an error, never an empty (passing) scan")
	}
	if _, err := ReachableTokens(fixtureDir, []string{"Root", "AlsoMissing"}); err == nil {
		t.Fatal("one missing root among several must still be an error")
	}
}

// TestReachableTokens_QualifiedRootResolvesTheRightMethod exercises the
// "Receiver.Method" form, which is the ONLY form the two real consumers use
// ("Client.ShutdownVM", "RoutedClient.ShutdownVM", "VMShutdown.Apply") and
// which an earlier version of this test did not reach at all: both its roots
// were bare and the fixture contained no methods, so byQualified was
// populated and never consulted. Review confirmed by mutation that deleting
// the byQualified population left this package's tests green.
//
// Two receivers share the method name Handle specifically so the qualified
// form is falsifiable: it must reach Server.Handle and NOT Worker.Handle,
// which a lookup that quietly fell back to bare-name matching would fail.
func TestReachableTokens_QualifiedRootResolvesTheRightMethod(t *testing.T) {
	all := flatten(mustScan(t, []string{"Server.Handle"}))

	for _, want := range []string{"planted-in-Server-Handle", "planted-in-Server-helperMethod"} {
		if !contains(all, want) {
			t.Errorf("qualified root Server.Handle did not reach %q", want)
		}
	}
	if contains(all, "planted-in-Worker-Handle") {
		t.Error("qualified root Server.Handle reached Worker.Handle — it resolved by bare name, not by receiver")
	}
}

// TestReachableTokens_BareRootReachesEveryReceiver is the counterpart: the
// bare form is deliberately over-approximate (see ReachableTokens' own doc
// comment), so "Handle" must reach BOTH receivers. Without this, a
// byQualified-only implementation would pass the test above.
func TestReachableTokens_BareRootReachesEveryReceiver(t *testing.T) {
	all := flatten(mustScan(t, []string{"Handle"}))
	for _, want := range []string{"planted-in-Server-Handle", "planted-in-Worker-Handle"} {
		if !contains(all, want) {
			t.Errorf("bare root Handle did not reach %q — bare matching must follow every receiver", want)
		}
	}
}

// TestReachableTokens_PackageLevelValuesAreWalked covers the hole review
// executed a hard-stop escalation through: a package-level var bound to a
// function value. The GenDecl was never indexed and the call site's only
// token was the var's name, which resolves to no FuncDecl — invisible in
// both directions at once.
func TestReachableTokens_PackageLevelValuesAreWalked(t *testing.T) {
	all := flatten(mustScan(t, []string{"Root"}))

	for _, c := range []struct{ token, why string }{
		{"planted-in-a-package-level-var", "the initialiser of a package-level var mentioned in a reachable body"},
		{"planted-in-IndirectlyReached", "a function reached ONLY as a value bound to a package-level var, never called by name"},
	} {
		if !contains(all, c.token) {
			t.Errorf("scan did not find %q: %s", c.token, c.why)
		}
	}
}

func mustScan(t *testing.T, roots []string) map[string][]string {
	t.Helper()
	tokens, err := ReachableTokens(fixtureDir, roots)
	if err != nil {
		t.Fatalf("ReachableTokens: %v", err)
	}
	return tokens
}

func flatten(tokens map[string][]string) []string {
	var all []string
	for _, toks := range tokens {
		all = append(all, toks...)
	}
	sort.Strings(all)
	return all
}

func contains(all []string, want string) bool {
	for _, tok := range all {
		if strings.Contains(tok, want) {
			return true
		}
	}
	return false
}
