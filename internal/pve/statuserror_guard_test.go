package pve

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// A *StatusError is what NotFound trusts as PVE's own answer. NewStatusError
// builds one from arbitrary text, for fakes; a production call anywhere but
// the one HTTP path that builds it from a real response would let pveforge's
// own text pass for PVE's, which is exactly the misreading typed errors
// exist to end. So production may reach the constructors only here:
//
//   - NewStatusError: its declaration (notfound.go) and newStatusError's
//     body (rawrequest.go) — nowhere else, bare or as pve.NewStatusError;
//   - newStatusError, which takes the real *http.Response: its declaration
//     and RawRequest's non-2xx return (rawrequest.go), and the config PUT
//     behind SetVMConfigFieldCAS and DeleteVMConfigFieldCAS (vmconfig.go).
//     The config PUT builds through newStatusError, never NewStatusError.
var (
	tgtNewStatusErrorBare = sourceguard.Target{Name: "NewStatusError"}
	tgtNewStatusErrorPkg  = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/pve", Name: "NewStatusError"}
	tgtNewStatusErrorHTTP = sourceguard.Target{Name: "newStatusError"}
)

var statusErrorSites = []struct {
	file  string
	tgt   sourceguard.Target
	count int
}{
	{"internal/pve/notfound.go", tgtNewStatusErrorBare, 1},   // the declaration
	{"internal/pve/rawrequest.go", tgtNewStatusErrorBare, 1}, // newStatusError's body
	{"internal/pve/rawrequest.go", tgtNewStatusErrorHTTP, 2}, // its declaration, and RawRequest's non-2xx return
	{"internal/pve/vmconfig.go", tgtNewStatusErrorHTTP, 1},   // the config PUT's non-2xx return
}

// TestStatusErrorConstructors_OnlyOnTheHTTPPath: no non-test file in the
// module references NewStatusError or newStatusError outside the sites
// above, each exactly as often as listed. Anti-vacuity: the exact counts
// prove the walk still sees the allowed references, so a clean result is
// not the walk seeing nothing.
func TestStatusErrorConstructors_OnlyOnTheHTTPPath(t *testing.T) {
	scope := sourceguard.Scope{Root: "../.."}
	seen := map[string]bool{}
	for _, s := range statusErrorSites {
		if !seen[s.file] {
			scope.AllowFiles = append(scope.AllowFiles, s.file)
			seen[s.file] = true
		}
	}
	res, err := sourceguard.NonTestReferences(scope, []sourceguard.Target{tgtNewStatusErrorBare, tgtNewStatusErrorPkg, tgtNewStatusErrorHTTP})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("a StatusError constructor is referenced off the HTTP path:\n%s\n"+
			"A *StatusError is trusted as PVE's own answer (NotFound); only a real response may build one in production.",
			strings.Join(lines, "\n"))
	}
	for _, s := range statusErrorSites {
		if got := len(res.Allowed(s.file, s.tgt)); got != s.count {
			t.Errorf("%s: %d reference(s) to %s, want %d — the walk no longer sees the allowed sites, or one was added", s.file, got, s.tgt, s.count)
		}
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Error("the walk did not cover the module")
	}
}
