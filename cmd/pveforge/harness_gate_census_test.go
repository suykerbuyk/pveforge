package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The harness family's write-gate sites, pinned from the AST (never a grep, a
// comment or a string): the EXACT set of dispatch.Refuse call expressions per
// non-test file under internal/harness and cmd/pveforge/harness*.go, zero
// dispatch.Open calls (the gate is opened only by the funnels: the REST round
// tripper and idempotent.Run; evidence files, the ledger, the lock files and
// the probe's harness-state/ file are bookkeeping, D17/D18, and never open
// it), and zero hand-built dispatch markers (Refuse is the only constructor of
// a refusal; Unobserved is built only by the funnels).

func harnessGateFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.Walk("../../internal/harness", func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := filepath.Glob("harness*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range m {
		if !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
	}
	sort.Strings(files)
	return files
}

type gateSites struct{ refuse, open, marker int }

func scanGateSites(t *testing.T, path string) gateSites {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var g gateSites
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "dispatch" {
					switch sel.Sel.Name {
					case "Refuse":
						g.refuse++
					case "Open":
						g.open++
					}
				}
			}
		case *ast.CompositeLit:
			if sel, ok := x.Type.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "dispatch" && (sel.Sel.Name == "RefusedBeforeWrite" || sel.Sel.Name == "Unobserved") {
					g.marker++
				}
			}
		}
		return true
	})
	return g
}

func TestHarnessGateSites_ExactAndNeverOpened(t *testing.T) {
	want := map[string]int{
		"../../internal/harness/build/build.go": 2, // LoadSite refusal; d.refuse (preflight)
		"../../internal/harness/outer/guard.go": 6, // bound, membership, node, ledger-missing, not-created, tag
		"../../internal/harness/probe/probe.go": 1, // d.refuse (static layer + preCreate)
		"../../internal/harness/reset/reset.go": 4, // snapshot-state refusals (2), first acceptance, d.refuse
		"harness_build.go":                      1, // lock wait
		"harness_probe.go":                      1, // lock wait
		"harness_reset.go":                      2, // lock wait (golden, reset)
		"harness_vm.go":                         8, // VMID band, destroy --yes, six lock waits
	}
	got := map[string]int{}
	files := harnessGateFiles(t)
	if len(files) < 15 {
		t.Fatalf("vacuous: the scan found %d files", len(files))
	}
	for _, p := range files {
		g := scanGateSites(t, p)
		if g.open != 0 {
			t.Errorf("%s calls dispatch.Open %d time(s): bookkeeping and verbs never open the gate", p, g.open)
		}
		if g.marker != 0 {
			t.Errorf("%s builds a dispatch marker by hand (%d): only Refuse and the funnels may", p, g.marker)
		}
		if g.refuse > 0 {
			got[p] = g.refuse
		}
	}
	for p, n := range want {
		if got[p] != n {
			t.Errorf("%s: %d dispatch.Refuse call(s), want exactly %d", p, got[p], n)
		}
	}
	for p, n := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("%s: %d unlisted dispatch.Refuse call(s): classify it in this table with its boundary", p, n)
		}
	}
}
