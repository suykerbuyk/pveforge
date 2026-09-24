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
//
// ClusterGuests, `vm create --unique-tag`'s root read, is held to its
// reviewed sites too. It runs one read-only command
// (TestRootAccess_ClusterGuests_RunsOnlyTheRead), and vm.go, its only
// caller, holds none of the writers above: vm.go is not an allowed file,
// so a writer reference there fails this test.
var (
	tgtAddUser     = sourceguard.Target{AnyQualifier: true, Name: "AddUser"}
	tgtModifyUser  = sourceguard.Target{AnyQualifier: true, Name: "ModifyUser"}
	tgtAddGroup    = sourceguard.Target{AnyQualifier: true, Name: "AddGroup"}
	tgtModifyGroup = sourceguard.Target{AnyQualifier: true, Name: "ModifyGroup"}
	tgtGrantACL    = sourceguard.Target{AnyQualifier: true, Name: "GrantACL"}
	tgtPveum       = sourceguard.Target{AnyQualifier: true, Name: "pveum"}
	tgtPveumWrite  = sourceguard.Target{AnyQualifier: true, Name: "pveumWrite"}
	tgtRootRun     = sourceguard.Target{AnyQualifier: true, Name: "rootRun"}
	tgtACLModify   = sourceguard.Target{AnyQualifier: true, Name: "aclModify"}
	tgtCheckJoin   = sourceguard.Target{AnyQualifier: true, Name: "CheckGroupJoin"}
	tgtUserEnsure  = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/idempotent", Name: "UserEnsure"}
	tgtGroupEnsure = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/idempotent", Name: "GroupEnsure"}
	tgtClusterGst  = sourceguard.Target{AnyQualifier: true, Name: "ClusterGuests"}

	rootWriterTargets = []sourceguard.Target{tgtAddUser, tgtModifyUser, tgtAddGroup, tgtModifyGroup, tgtGrantACL,
		tgtPveum, tgtPveumWrite, tgtRootRun, tgtACLModify, tgtCheckJoin, tgtUserEnsure, tgtGroupEnsure, tgtClusterGst}
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
	{"internal/bootstrap/access.go", tgtPveum, 6},      // five reads (guests, users, groups, ACLs, roles) and pveumWrite
	{"internal/bootstrap/access.go", tgtRootRun, 1},    // pveum's own call
	{"internal/bootstrap/inventory.go", tgtRootRun, 1}, // getent, which reads its own exit 2
	{"internal/bootstrap/access.go", tgtPveumWrite, 5}, // the five writers
	{"cmd/pveforge/vm.go", tgtClusterGst, 2},           // the check and the visibility wait
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

// TestRootSession_OnlyAtItsSites (S1): a command reaches root only through
// RootAccess.root, and that is taken at exactly its reviewed sites: in
// access.go, Connect (which dials and runs nothing), pveum and the role
// list; in inventory.go, getent. A new raw root command anywhere else, or
// another one in either file, fails here.
func TestRootSession_OnlyAtItsSites(t *testing.T) {
	tgt := sourceguard.Target{AnyQualifier: true, Name: "root"}
	// access.go: Connect, and rootRun, the one command runner (B5), which
	// the role list and the inventory's getent now go through too.
	sites := map[string]int{"internal/bootstrap/access.go": 2}
	scope := sourceguard.Scope{Root: "../.."}
	for f := range sites {
		scope.AllowFiles = append(scope.AllowFiles, f)
	}
	res, err := sourceguard.NonTestReferences(scope, []sourceguard.Target{tgt})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("RootAccess.root is taken outside its reviewed sites:\n%s", strings.Join(lines, "\n"))
	}
	for f, want := range sites {
		if got := len(res.Allowed(f, tgt)); got != want {
			t.Errorf("%s: %d reference(s) to %s, want exactly %d", f, got, tgt, want)
		}
	}
}
