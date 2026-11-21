package sourceguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nestedTree builds, in a temp dir (git refuses to track a path component
// named .git, so this cannot be a committed fixture), a module whose layout
// exercises every skip walkNonTest makes and every one it must NOT make.
func nestedTree(t *testing.T, withInTreeModule bool) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":           "module example.com/m\n",
		"a.go":             "package m\n",
		".wt/u/go.mod":     "module example.com/m\n", // a worktree: a separate module
		".wt/u/x.go":       "package m\n",            // must NOT be parsed
		".hid/h.go":        "package hid\n",          // dot-named package: importable, MUST be parsed
		"sm/.git":          "gitdir: ../.git/modules/sm\n",
		"sm/s.go":          "package sm\n", // a submodule-shaped dir: still this module, MUST be parsed
		"p/build/b.go":     "package build\n",
		"p/.build/c.go":    "package build\n",   // .build at depth: MUST be parsed
		"p/.wt/d.go":       "package wt\n",      // .wt at depth with no go.mod: MUST be parsed
		".build/e.go":      "package scratch\n", // top-level .build: importable, MUST be parsed
		".wt/nomod/y.go":   "package y\n",       // under .wt but no go.mod of its own: MUST be parsed
		"internal/ok/n.go": "package ok\n",
	}
	if withInTreeModule {
		files["internal/nm/go.mod"] = "module example.com/nm\n"
		files["internal/nm/n.go"] = "package nm\n"
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestWalk_SkipsOnlyANestedModuleUnderATopLevelDotDir is the D6 rule. Each
// assertion names the wrong rule it kills: a skip of the top-level .build, a
// name skip of .wt or .build at depth, a skip of every dot-dir, a skip keyed
// on a .git file, a skip of "build", and a lost root exemption.
func TestWalk_SkipsOnlyANestedModuleUnderATopLevelDotDir(t *testing.T) {
	root := nestedTree(t, false)
	res, err := NonTestReferences(Scope{Root: root}, []Target{{Name: "x"}})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if res.Reached(".wt/u/x.go") {
		t.Errorf("walked .wt/u/x.go: a nested module under a top-level dot-dir is not this module's source; Parsed = %v", res.Parsed)
	}
	for _, kept := range []string{
		"a.go",
		".build/e.go",    // killed by "skip the top-level .build" (B-1)
		".hid/h.go",      // killed by "skip every dot-dir"
		"sm/s.go",        // killed by "skip a dir holding a .git file"
		"p/build/b.go",   // killed by "skip build"
		"p/.build/c.go",  // killed by "skip .build by name"
		"p/.wt/d.go",     // killed by "skip .wt by name"
		".wt/nomod/y.go", // killed by "skip .wt by name" at the top level
		"internal/ok/n.go",
	} {
		if !res.Reached(kept) {
			t.Errorf("did not walk %s, which go build would compile into the module; Parsed = %v", kept, res.Parsed)
		}
	}

	// The root exemption: walking the worktree AS Root still parses it.
	sub, err := NonTestReferences(Scope{Root: filepath.Join(root, ".wt", "u")}, []Target{{Name: "x"}})
	if err != nil {
		t.Fatalf("NonTestReferences on the nested module as Root: %v", err)
	}
	if !sub.Reached("x.go") {
		t.Errorf("the nested module was skipped even as the walk Root; Parsed = %v", sub.Parsed)
	}

	// DirectiveEvasions shares the walk and therefore the rule.
	ev, err := DirectiveEvasions(root)
	if err != nil {
		t.Fatalf("DirectiveEvasions: %v", err)
	}
	if ev.Reached(".wt/u/x.go") || !ev.Reached(".hid/h.go") {
		t.Errorf("DirectiveEvasions does not walk what NonTestReferences walks: %v", ev.Walked)
	}
}

// TestWalk_AnInTreeNestedModuleIsAnError: a nested go.mod anywhere but under
// a top-level dot-dir is not silently skipped — it is a place source could
// hide from every guard.
func TestWalk_AnInTreeNestedModuleIsAnError(t *testing.T) {
	root := nestedTree(t, true)
	_, err := NonTestReferences(Scope{Root: root}, []Target{{Name: "x"}})
	if err == nil {
		t.Fatal("an in-tree nested module (internal/nm/go.mod) was walked past without an error")
	}
	if !strings.Contains(err.Error(), "internal/nm") || !strings.Contains(err.Error(), "go.mod") {
		t.Fatalf("error %q does not name the nested module", err)
	}
	if _, err := DirectiveEvasions(root); err == nil {
		t.Fatal("DirectiveEvasions walked past an in-tree nested module without an error")
	}
}
