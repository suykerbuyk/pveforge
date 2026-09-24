package bootstrap

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// RootAccess's writers run pveum as root: they create and change principals
// and grant ACLs outside the roster token's reach, by design. Production may
// call them only where 6a's reviewed guards stand in front of them: the user
// and group writes only from their idempotent Ops, and the grant only from
// `acl grant`, which is the command whose refusals (self, escalating role,
// bootstrap's grant rules) GrantACL itself enforces.
//
// Below them, the unexported helpers that actually run pveum as root
// (pveum, aclModify) are used only inside access.go; and the Ops themselves
// are built only by the two commands, which wire the self and escalation
// checks into them (UserEnsure.BeforeJoin, via CheckGroupJoin).
var (
	tgtAddUser     = sourceguard.Target{AnyQualifier: true, Name: "AddUser"}
	tgtModifyUser  = sourceguard.Target{AnyQualifier: true, Name: "ModifyUser"}
	tgtAddGroup    = sourceguard.Target{AnyQualifier: true, Name: "AddGroup"}
	tgtModifyGroup = sourceguard.Target{AnyQualifier: true, Name: "ModifyGroup"}
	tgtGrantACL    = sourceguard.Target{AnyQualifier: true, Name: "GrantACL"}
	tgtPveum       = sourceguard.Target{AnyQualifier: true, Name: "pveum"}
	tgtACLModify   = sourceguard.Target{AnyQualifier: true, Name: "aclModify"}
	tgtCheckJoin   = sourceguard.Target{AnyQualifier: true, Name: "CheckGroupJoin"}
	tgtUserEnsure  = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/idempotent", Name: "UserEnsure"}
	tgtGroupEnsure = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/idempotent", Name: "GroupEnsure"}

	rootWriterTargets = []sourceguard.Target{tgtAddUser, tgtModifyUser, tgtAddGroup, tgtModifyGroup, tgtGrantACL,
		tgtPveum, tgtACLModify, tgtCheckJoin, tgtUserEnsure, tgtGroupEnsure}
)

var rootWriterSites = []struct {
	file  string
	tgt   sourceguard.Target
	count int
}{
	{"internal/idempotent/pveumaccess.go", tgtAddUser, 1},
	{"internal/idempotent/pveumaccess.go", tgtModifyUser, 1},
	{"internal/idempotent/pveumaccess.go", tgtAddGroup, 1},
	{"internal/idempotent/pveumaccess.go", tgtModifyGroup, 1},
	{"cmd/pveforge/access.go", tgtGrantACL, 1},
	{"cmd/pveforge/access.go", tgtCheckJoin, 1},
	{"cmd/pveforge/access.go", tgtUserEnsure, 1},
	{"cmd/pveforge/access.go", tgtGroupEnsure, 1},
	{"internal/bootstrap/access.go", tgtPveum, 9},
	{"internal/bootstrap/access.go", tgtACLModify, 1},
}

// TestRootAccessWriters_OnlyAtTheirSites: no non-test file calls a root
// pveum writer except at its one reviewed site. The exact per-site counts
// are the anti-vacuity: a walk that saw nothing would fail them.
func TestRootAccessWriters_OnlyAtTheirSites(t *testing.T) {
	scope := sourceguard.Scope{Root: "../.."}
	seen := map[string]bool{}
	for _, s := range rootWriterSites {
		if !seen[s.file] {
			scope.AllowFiles = append(scope.AllowFiles, s.file)
			seen[s.file] = true
		}
	}
	res, err := sourceguard.NonTestReferences(scope, rootWriterTargets)
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("a root pveum writer is called outside its reviewed site:\n%s", strings.Join(lines, "\n"))
	}
	// Every writer, in every allowed file, has exactly its listed count
	// (0 when unlisted): AllowFiles admits a file for all targets, so
	// checking only the listed pairs would let AddGroup into the file
	// allowed only for GrantACL.
	for file := range seen {
		for _, tgt := range rootWriterTargets {
			want := 0
			for _, s := range rootWriterSites {
				if s.file == file && s.tgt == tgt {
					want = s.count
				}
			}
			if got := len(res.Allowed(file, tgt)); got != want {
				t.Errorf("%s: %d reference(s) to %s, want exactly %d", file, got, tgt, want)
			}
		}
	}
}
