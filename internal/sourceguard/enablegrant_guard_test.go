package sourceguard

import (
	"slices"
	"testing"
)

// INV-1.4 of `acl enable-vm-destroy` (task pveforge-bootstrap-ensure-roles-
// and-grants): the verb can never revoke or re-mint a token, so the code that
// does — bootstrap's token phase and the roster's token writers — must not be
// reachable from the verb's files. This is a call-SITE guard (a reference to
// the symbol anywhere in those files is red), the module's idiom for "this
// file must not mention that".
//
// WHY IT CANNOT PASS BY MATCHING NOTHING (this package's standing failure
// mode): the walk skips testdata, and Result.Allowed is an allow-list mark,
// not evidence that a call was seen. So non-vacuity is asserted three ways —
// the walk parsed a real floor of files and Reached the guarded files; every
// forbidden identifier target DOES match real code elsewhere (rotation.go),
// so a target that silently matches nothing is caught; and one deliberate
// allowed literal (the verb's own write command) is seen inside the one file
// that owns it. The forbidden literals are never allowed: no AllowFiles entry
// names a file that holds a forbidden target.

const (
	enableVerbFile = "internal/bootstrap/vmdestroygrant.go"
	enableCmdFile  = "cmd/pveforge/acl_enable.go"
	rotationFile   = "internal/bootstrap/rotation.go"
	rosterPkg      = "github.com/suykerbuyk/pveforge/internal/roster"
)

// forbiddenIdents are the token phase's remove/mint machinery, spelled as it
// is reached: bare (a function) or as a method selector.
func forbiddenIdents() []Target {
	return []Target{
		{Name: "grantAll"},
		{AnyQualifier: true, Name: "removeHeld"},
		{AnyQualifier: true, Name: "mintAndPersist"},
		{AnyQualifier: true, Name: "tokenPhase"},
		{AnyQualifier: true, Name: "removeCmd"},
		{AnyQualifier: true, Name: "removeFresh"},
		{ImportPath: rosterPkg, Name: "ClearTokenAuth"},
		{ImportPath: rosterPkg, Name: "WriteTokenAuth"},
	}
}

// forbiddenLiterals are commands the verb must never spell: anything that
// removes or adds a token, deletes an ACL, or edits or deletes a role.
func forbiddenLiterals() []Target {
	var out []Target
	for _, s := range []string{
		"pveum user token remove", "pveum user token add", "pveum acl delete",
		"pveum role modify", "pveum role delete", "pveum user delete",
	} {
		out = append(out, Target{Literal: true, Name: s})
	}
	return out
}

func refsIn(res Result, file string, targets []Target) []Ref {
	var out []Ref
	for _, t := range targets {
		for _, r := range res.Refs[file] {
			if r.Target == t {
				out = append(out, r)
			}
		}
	}
	return out
}

func TestEnableVMDestroy_INV1_RemoveAndMintAreUnreachable(t *testing.T) {
	idents, lits := forbiddenIdents(), forbiddenLiterals()
	// No AllowFiles at all: every forbidden reference anywhere is a violation,
	// and Allowed is false by construction.
	res, err := NonTestReferences(Scope{Root: "../.."}, slices.Concat(idents, lits))
	if err != nil {
		t.Fatal(err)
	}

	// Non-vacuity 1: a real floor of files parsed, the guarded files and a far
	// one reached.
	if len(res.Parsed) < 100 {
		t.Fatalf("the walk parsed only %d files: it is not walking the module", len(res.Parsed))
	}
	for _, f := range []string{enableVerbFile, enableCmdFile, rotationFile} {
		if !res.Reached(f) {
			t.Fatalf("the walk never parsed %s", f)
		}
	}

	// Non-vacuity 2: every forbidden IDENTIFIER target matches real code
	// outside the guarded files, so none of them is a target that matches
	// nothing.
	for _, tg := range idents {
		found := false
		for file, refs := range res.Refs {
			if file == enableVerbFile || file == enableCmdFile {
				continue
			}
			for _, r := range refs {
				if r.Target == tg {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("target %s matches nothing outside the guarded files: the guard would pass on a typo", tg)
		}
	}

	// The invariant: no forbidden reference in either guarded file, and none of
	// them Allowed (nothing is allowed here).
	for _, f := range []string{enableVerbFile, enableCmdFile} {
		for _, r := range refsIn(res, f, slices.Concat(idents, lits)) {
			t.Errorf("INV-1: %s", r)
		}
		for _, r := range res.Refs[f] {
			if r.Allowed {
				t.Errorf("%s: a reference is Allowed in a guarded file: %s", f, r)
			}
		}
	}
}

// The verb reaches pveumWrite from exactly one function, enableWrite, which
// screens its argv first; and never reaches the existing aclModify, whose
// string has no screen.
func TestEnableVMDestroy_OnlyEnableWriteWrites(t *testing.T) {
	write := Target{AnyQualifier: true, Name: "pveumWrite"}
	acl := Target{AnyQualifier: true, Name: "aclModify"}
	res, err := NonTestReferences(Scope{Root: "../.."}, []Target{write, acl})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reached(enableVerbFile) {
		t.Fatal("the walk never parsed the verb file")
	}
	writes := refsIn(res, enableVerbFile, []Target{write})
	if len(writes) != 1 || writes[0].Func != "RootAccess.enableWrite" {
		t.Fatalf("pveumWrite is reached from %v; want exactly one site, in RootAccess.enableWrite", writes)
	}
	if r := refsIn(res, enableVerbFile, []Target{acl}); len(r) != 0 {
		t.Fatalf("the verb reaches aclModify: %v", r)
	}
	// Control: aclModify is a real reference elsewhere (access.go), so the
	// target is not one that matches nothing.
	if len(refsIn(res, "internal/bootstrap/access.go", []Target{acl})) == 0 {
		t.Fatal("aclModify matches nothing in access.go: the target is vacuous")
	}
}

// The deliberate allowed literal: the verb's own write command, seen inside
// the one file that owns it, allowed by (file) because that file holds no
// forbidden target (the test above proves it). A walk that matched nothing
// would leave Allowed empty here.
func TestEnableVMDestroy_AllowedLiteralIsSeen(t *testing.T) {
	role := Target{Literal: true, Name: "pveum role add"}
	acl := Target{Literal: true, Name: "pveum acl modify"}
	res, err := NonTestReferences(Scope{Root: "../..", AllowFiles: []string{enableVerbFile}}, []Target{role, acl})
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range []Target{role, acl} {
		if len(res.Allowed(enableVerbFile, tg)) == 0 {
			t.Errorf("the allowed literal %s is not seen in %s", tg, enableVerbFile)
		}
	}
	// And the same literals are violations anywhere else in the verb's own
	// command file: the cmd layer never builds a pveum command.
	for _, r := range refsIn(res, enableCmdFile, []Target{role, acl}) {
		t.Errorf("the cmd file spells a pveum write: %s", r)
	}
}
