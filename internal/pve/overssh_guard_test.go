package pve

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// The two SSH-only fallbacks bypass the API token's ACL by design: they run
// `qm set` as root. They exist for exactly one situation — PVE refused a CAS
// change as root-only — so production may call them only at the three
// fallback sites that handle that refusal.
var (
	tgtOverSSHSet    = sourceguard.Target{AnyQualifier: true, Name: "SetVMConfigFieldOverSSH"}
	tgtOverSSHDelete = sourceguard.Target{AnyQualifier: true, Name: "DeleteVMConfigFieldOverSSH"}
)

// overSSHSites are the only production calls allowed, per file and target,
// with their exact count: a fourth call fails whether it is in a new file or
// an allowed one.
var overSSHSites = []struct {
	file  string
	tgt   sourceguard.Target
	count int
}{
	{"internal/idempotent/vmfields.go", tgtOverSSHSet, 1},        // vm set: a write refused as root-only
	{"internal/idempotent/vmfields.go", tgtOverSSHDelete, 1},     // vm set: a delete refused as root-only
	{"internal/idempotent/bridgeisolation.go", tgtOverSSHSet, 1}, // the hookscript write refused as root-only
}

// TestOverSSHFallbacks_OnlyAtTheRootOnlyRefusalSites: no non-test file in
// the module calls SetVMConfigFieldOverSSH or DeleteVMConfigFieldOverSSH
// except the three root-only fallbacks, each exactly once. Anti-vacuity: the
// exact per-site counts prove the walk still sees the allowed calls, so a
// "no violations" result is not the walk seeing nothing.
func TestOverSSHFallbacks_OnlyAtTheRootOnlyRefusalSites(t *testing.T) {
	scope := sourceguard.Scope{Root: "../.."}
	seen := map[string]bool{}
	for _, s := range overSSHSites {
		if !seen[s.file] {
			scope.AllowFiles = append(scope.AllowFiles, s.file)
			seen[s.file] = true
		}
	}
	res, err := sourceguard.NonTestReferences(scope, []sourceguard.Target{tgtOverSSHSet, tgtOverSSHDelete})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("an SSH-only fallback (root, bypassing the token's ACL) is called outside the root-only refusal sites:\n%s\n"+
			"Only a caller handling PVE's root-only refusal of a CAS change may use one; a new site needs its own review.",
			strings.Join(lines, "\n"))
	}
	// Every fallback, in every allowed file, has exactly its listed count (0
	// when unlisted): AllowFiles admits a file for both targets, so checking
	// only the listed pairs would let a DeleteVMConfigFieldOverSSH call into
	// bridgeisolation.go, which is allowed only the Set.
	for file := range seen {
		for _, tgt := range []sourceguard.Target{tgtOverSSHSet, tgtOverSSHDelete} {
			want := 0
			for _, s := range overSSHSites {
				if s.file == file && s.tgt == tgt {
					want = s.count
				}
			}
			if got := len(res.Allowed(file, tgt)); got != want {
				t.Errorf("%s: %d call(s) of %s, want exactly %d", file, got, tgt, want)
			}
		}
	}
}
