package sourceguard

import "testing"

// Additive never-destroy SOURCE guard for internal/harness/reset (U-GOLDEN/RESET
// plan V#10). The golden/reset driver must reference no VM-destroy endpoint.
// Every HTTP write it issues goes through outer.RawUPID with http.MethodGet or
// http.MethodPost, or through the pve snapshot cascade (snapshot-scoped); a raw
// VM destroy is a DELETE request, i.e. a net/http.MethodDelete reference in the
// package's own non-test source. There is none, and this pins it: a planted
// bare `DELETE /nodes/<node>/qemu/<vmid>` adds a MethodDelete ref and fails
// here on every build, independent of any test's execution path. This is NOT
// the shell-only TestGoldenReset_NeverDestroy (harness_reset_test.go), which
// greps golden.sh/reset.sh/golden-reset.sh; this guards the Go driver.
func TestHarnessReset_ReferencesNoVMDestroyEndpoint(t *testing.T) {
	const root = "../../internal/harness/reset"
	res, err := NonTestReferences(Scope{Root: root}, []Target{
		{ImportPath: "net/http", Name: "MethodDelete"},
		{ImportPath: "net/http", Name: "MethodPost"},
	})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	// Anti-vacuity: the walk must have parsed the driver and must still see its
	// HTTP writes (MethodPost), or a zero-MethodDelete result means nothing.
	if !res.Reached("reset.go") {
		t.Fatalf("the walk did not parse reset.go (parsed %v): it is not looking at the driver", res.Parsed)
	}
	var posts, dels int
	for _, refs := range res.Refs {
		for _, r := range refs {
			switch r.Target.Name {
			case "MethodPost":
				posts++
			case "MethodDelete":
				dels++
				t.Errorf("internal/harness/reset references net/http.MethodDelete at %s:%d — a raw VM-destroy endpoint is forbidden (snapshot deletes go through the pve cascade)", r.File, r.Line)
			}
		}
	}
	if posts == 0 {
		t.Fatalf("no net/http.MethodPost ref found in the reset package: the walker is not seeing the driver's writes, so a zero-MethodDelete result would be vacuous")
	}
}
