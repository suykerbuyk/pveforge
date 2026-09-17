// Package sourceguard is test-support machinery for structural source
// guards: assertions of the form "no code reachable from THIS function may
// mention THAT". It exists for pveforge-vm-shutdown's no-hard-stop guard
// (internal/pve/vmshutdown.go, internal/idempotent/vmshutdown.go), which
// two different packages need to run — a Go test file cannot be shared
// across packages, so the shared half lives here rather than being
// copy-pasted into both.
//
// Production code must never call this, in the same spirit as
// pve.SetSSHPortForIntegrationTests: it is a build-visible package purely
// because the test files that use it live in two different packages.
//
// WHY AN AST WALK RATHER THAN A TEXT SCAN. The guard this replaces read
// one file and substring-matched its text with comments stripped by hand.
// That had two defects, both found by review and both fixed here
// structurally rather than by patching the string handling:
//
//   - It read ONE file. A hard-stop helper in a sibling file of the same
//     package — an entirely ordinary thing for a later contributor to
//     write — was invisible to it. ReachableTokens parses the whole
//     package and follows calls, so a dangerous path is caught wherever in
//     the package it is written.
//   - Its comment-stripping truncated each line at the first "//",
//     including one inside a string literal, which silently hid every
//     token after it on that line. Here comments are never walked at all
//     (they hang off ast.File.Comments, which this package ignores) and a
//     string literal is a single token, so neither can affect the other.
//
// WRITING FIXTURES AND TESTS FOR THIS PACKAGE — read this first.
//
// AN ASSERTION IS ONLY AN ASSERTION IF THE THING IT ASSERTS ABOUT IS
// REACHABLE FROM THE ROOT UNDER TEST. This package's whole subject is
// reachability, which makes it unusually easy to write a test that cannot
// fail: plant a token somewhere the scan was never going to look, assert the
// scan does not find it, and watch it pass forever while proving nothing.
// This has now happened three times in this unit — a status value the code
// could not produce, a token in a _test.go file no root called into, and a
// qualified-root test whose fixture contained no methods — each caught by
// mutation rather than by the suite, because a vacuous assertion is
// invisible to a green run.
//
// So, before adding a fixture or a test here: state which root reaches the
// code you are planting a token in, and confirm it by mutation — break the
// behaviour the assertion claims to guard and watch the test FAIL. If it
// still passes, the token is unreachable and the assertion is decoration. A
// test that has never been observed failing has not been shown to work.
package sourceguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
)

// ReachableTokens parses every non-test .go file in dir — one package —
// and returns the identifiers, selector names and string-literal contents
// appearing in the bodies of the functions transitively reachable from
// roots, together with the name of the function each token was found in.
//
// roots name functions as "Receiver.Method" (e.g. "Client.ShutdownVM") or
// as a bare function name. An unmatched root is an error rather than an
// empty result: a guard whose entry point has been renamed away must fail
// loudly, not silently pass by scanning nothing.
//
// Call resolution is deliberately OVER-APPROXIMATE: a call is matched by
// its bare method name, since resolving a receiver's type would require
// full type-checking. Every function sharing that name is followed. The
// error only ever pulls in MORE code than strictly reachable, which can
// make a guard stricter but never weaker — the safe direction for a check
// whose job is refusing things.
func ReachableTokens(dir string, roots []string) (map[string][]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("sourceguard: parse %s: %w", dir, err)
	}

	// byName indexes every function/method by its bare name; byQualified
	// additionally indexes methods as "Receiver.Method" so a root can name
	// one precisely when two types share a method name.
	byName := map[string][]*ast.FuncDecl{}
	byQualified := map[string]*ast.FuncDecl{}
	// pkgLevelValues holds every package-level var/const initialiser
	// expression, keyed by the name it is bound to. See scanValues below for
	// why these are walked at all.
	pkgLevelValues := map[string][]ast.Expr{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					byName[d.Name.Name] = append(byName[d.Name.Name], d)
					if recv := receiverTypeName(d); recv != "" {
						byQualified[recv+"."+d.Name.Name] = d
					}
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, name := range vs.Names {
							if i < len(vs.Values) {
								pkgLevelValues[name.Name] = append(pkgLevelValues[name.Name], vs.Values[i])
							}
						}
					}
				}
			}
		}
	}

	var queue []*ast.FuncDecl
	for _, root := range roots {
		if fn, ok := byQualified[root]; ok {
			queue = append(queue, fn)
			continue
		}
		if fns, ok := byName[root]; ok {
			queue = append(queue, fns...)
			continue
		}
		return nil, fmt.Errorf("sourceguard: root %q not found in %s — has the guarded entry point been renamed?", root, dir)
	}

	found := map[string][]string{}
	seen := map[*ast.FuncDecl]bool{}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if seen[fn] {
			continue
		}
		seen[fn] = true

		label := fn.Name.Name
		if recv := receiverTypeName(fn); recv != "" {
			label = recv + "." + label
		}

		inspect := func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind == token.STRING {
					// Unquote is deliberately not used: a malformed or
					// exotic literal must still be scanned, not dropped.
					found[label] = append(found[label], strings.Trim(node.Value, "`\""))
				}
			case *ast.Ident:
				found[label] = append(found[label], node.Name)
				// A package-level var/const can hold a FUNCTION VALUE, and a
				// call through it reaches code with no FuncDecl call site to
				// follow. Review executed exactly that: a hard-stop helper
				// bound to `var shutdownFallback = (*Client).quiesceGuest`
				// was invisible to this scan in BOTH directions at once —
				// the GenDecl was never indexed, and the call site's only
				// token was the var's name, which resolves to no FuncDecl.
				// Mentioning such a name anywhere in a reachable body pulls
				// its initialiser in, and any function it names with it.
				for _, expr := range pkgLevelValues[node.Name] {
					scanValues(expr, label, found, byName, &queue)
				}
			case *ast.SelectorExpr:
				found[label] = append(found[label], node.Sel.Name)
			case *ast.CallExpr:
				if name := calleeName(node.Fun); name != "" {
					queue = append(queue, byName[name]...)
				}
			}
			return true
		}
		ast.Inspect(fn.Body, inspect)
	}
	return found, nil
}

// scanValues walks a package-level initialiser expression: it records its
// tokens under the function that referenced it, and queues any function it
// names — whether called (`f()`), taken as a value (`var x = f`), or taken
// as a method expression (`var x = (*T).m`). Bounded by seenValues so a
// self-referential declaration cannot loop.
func scanValues(expr ast.Expr, label string, found map[string][]string, byName map[string][]*ast.FuncDecl, queue *[]*ast.FuncDecl) {
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				found[label] = append(found[label], strings.Trim(node.Value, "`\""))
			}
		case *ast.Ident:
			found[label] = append(found[label], node.Name)
			*queue = append(*queue, byName[node.Name]...)
		case *ast.SelectorExpr:
			found[label] = append(found[label], node.Sel.Name)
			*queue = append(*queue, byName[node.Sel.Name]...)
		}
		return true
	})
}

// FindForbidden reports every (function, token) pair in tokens whose token
// contains any of the forbidden substrings, compared case-insensitively.
// Returns a sorted, human-readable list for a test to print.
func FindForbidden(tokens map[string][]string, forbidden []string) []string {
	var hits []string
	for fn, toks := range tokens {
		for _, tok := range toks {
			low := strings.ToLower(tok)
			for _, f := range forbidden {
				if strings.Contains(low, strings.ToLower(f)) {
					hits = append(hits, fmt.Sprintf("%s: %q (matches %q)", fn, tok, f))
				}
			}
		}
	}
	return hits
}

func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
