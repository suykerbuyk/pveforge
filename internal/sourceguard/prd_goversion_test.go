package sourceguard

import (
	"os"
	"regexp"
	"testing"
)

// TestPRD_GoVersionMatchesGoMod holds every "Go 1.x.y" the PRD states to
// go.mod's `go` directive. The PRD said 1.27.1 for weeks while the floor moved
// to 1.27.4; a statement nothing compares is a statement that rots. It goes red
// if either side drifts, and when the PRD names no version at all (the check
// would otherwise be vacuous).
func TestPRD_GoVersionMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)\s*$`).FindStringSubmatch(string(mod))
	if m == nil {
		t.Fatal("go.mod has no `go X.Y.Z` directive with a patch version")
	}
	want := m[1]
	prd, err := os.ReadFile("../../docs/prd.md")
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`\bGo (\d+\.\d+\.\d+)\b`).FindAllStringSubmatch(string(prd), -1)
	if len(found) < 2 {
		t.Fatalf("docs/prd.md states a Go version %d time(s), want at least 2 (the §5 toolchain line and the module overview): the guard would be vacuous", len(found))
	}
	for _, f := range found {
		if f[1] != want {
			t.Errorf("docs/prd.md says Go %s but go.mod's go directive is %s", f[1], want)
		}
	}
}
