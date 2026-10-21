package sourceguard

import "testing"

// Additive never-destroy SOURCE guard for internal/harness/build (U-BUILD plan
// V#10 / brief 8). Unlike the golden/reset driver, build DOES destroy — but only
// its own cleanup leaf, after the ledger gate and the gone-proof. So this guard
// does NOT forbid every net/http.MethodDelete (that would be wrong); it requires
// EXACTLY ONE MethodDelete reference in the build package — the cleanup destroy
// leaf — and fails if a second appears (a VM-destroy planted on any other path).
// The runtime t.Cleanup write-log (harness_build_test.go) catches the
// string-literal "DELETE" form the AST walk cannot see; this guard is additive.
func TestHarnessBuild_DestroysOnlyFromTheCleanupLeaf(t *testing.T) {
	const root = "../../internal/harness/build"
	res, err := NonTestReferences(Scope{Root: root}, []Target{
		{ImportPath: "net/http", Name: "MethodDelete"},
		{ImportPath: "net/http", Name: "MethodPost"},
	})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if !res.Reached("build.go") {
		t.Fatalf("the walk did not parse build.go (parsed %v)", res.Parsed)
	}
	var dels, posts int
	var delSites []string
	for _, refs := range res.Refs {
		for _, r := range refs {
			switch r.Target.Name {
			case "MethodDelete":
				dels++
				delSites = append(delSites, r.String())
			case "MethodPost":
				posts++
			}
		}
	}
	if dels != 1 {
		t.Errorf("internal/harness/build references net/http.MethodDelete %d times, want exactly 1 (the cleanup destroy leaf): %v", dels, delSites)
	}
	if posts == 0 {
		t.Fatalf("no net/http.MethodPost ref in the build package: the walker is not seeing the driver's writes, so the MethodDelete count would be vacuous")
	}
}
