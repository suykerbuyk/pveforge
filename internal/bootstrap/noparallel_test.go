package bootstrap

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoParallelTests pins the assumption that makes roster's process-wide
// scrypt work-factor override safe: nothing in this package runs in parallel,
// so a test encrypting at a lowered factor can never overlap one asserting
// production's 18.
//
// Each package gets its own test process, so cross-package parallelism in
// `go test ./...` is not a hazard — only t.Parallel inside THIS package is.
// internal/roster and internal/bootstrap therefore each carry a copy of this;
// a Go test helper cannot cross a package boundary, and widening
// sourceguard's contract (which two units now depend on) to serve a
// single-directory, test-file-only case would be the worse trade.
//
// Mutant M7a adds a t.Parallel call to this package and must turn this red.
func TestNoParallelTests(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Parallel" {
				return true
			}
			t.Errorf("%s:%d: t.Parallel is not allowed in this package: "+
				"roster's scrypt work-factor override is a process-global, and a "+
				"parallel test encrypting at a lowered factor would race one "+
				"asserting production's 18 (see roster.SetScryptWorkFactorForTests)",
				e.Name(), fset.Position(sel.Pos()).Line)
			return true
		})
	}
	// Without this the check passes trivially if the glob ever stops
	// matching — the failure mode this whole package keeps rediscovering.
	if scanned == 0 {
		t.Fatal("no _test.go files were scanned, so this guard proved nothing")
	}
}
