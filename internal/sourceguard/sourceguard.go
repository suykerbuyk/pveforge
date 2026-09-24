// Package sourceguard is test-support machinery for structural source
// guards: assertions of the form "no code reachable from THIS function may
// mention THAT". It exists for pveforge-vm-shutdown's no-hard-stop guard
// (internal/pve/vmshutdown.go, internal/idempotent/vmshutdown.go), which
// two different packages need to run — a Go test file cannot be shared
// across packages, so the shared half lives here rather than being
// copy-pasted into both.
//
// It also backs internal/pve's RoutedClient completeness gate, through
// ExportedMethods and TestCallees below: a test that every exported method of
// a type is accounted for in a table, and that each test the table names
// really calls the method it is credited with.
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
	"path/filepath"
	"sort"
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

// ExportedMethods parses every non-test .go file in dir — one package — and
// returns the sorted names of the exported methods declared on receiver,
// whether on a pointer or a value receiver.
//
// It scans the whole package, not one file, for the same reason
// ReachableTokens does: a method declared in a sibling file is still a
// method of the type, and a gate that read one file would miss it.
//
// A receiver with no exported methods is an error rather than an empty
// result, matching ReachableTokens' rule for an unmatched root: a gate whose
// type has been renamed away must fail loudly, not pass by enumerating
// nothing.
func ExportedMethods(dir, receiver string) ([]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("sourceguard: parse %s: %w", dir, err)
	}

	var names []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				if receiverTypeName(fd) == receiver && fd.Name.IsExported() {
					names = append(names, fd.Name.Name)
				}
			}
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("sourceguard: no exported methods on %q in %s — has the type been renamed?", receiver, dir)
	}
	sort.Strings(names)
	return names, nil
}

// TestCallees parses the _test.go files in dir once and, for each top-level
// function named in fns, returns the sorted, de-duplicated names of everything
// it calls. That covers its own body, including closures and composite
// literals, and, transitively, any function it calls that is itself defined in
// a test file. Names are bare, as calleeName gives them, so a call is matched
// by name and not by receiver type.
//
// It deliberately does NOT follow calls into non-test files. A test that
// calls rc.GetVM would otherwise reach RoutedClient.GetVM and Client.GetVM,
// and pick up every name those bodies mention, so the answer would stop
// meaning "what this test calls".
//
// It takes several names so that a gate checking many tests parses the
// package's test files once rather than once per test; under the race
// detector that difference is seconds. Any name not found among the test
// files is an error, for the same reason an unmatched root is in
// ReachableTokens.
func TestCallees(dir string, fns ...string) (map[string][]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("sourceguard: parse tests in %s: %w", dir, err)
	}

	byName := map[string][]*ast.FuncDecl{}
	topLevel := map[string][]*ast.FuncDecl{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				byName[fd.Name.Name] = append(byName[fd.Name.Name], fd)
				if fd.Recv == nil {
					topLevel[fd.Name.Name] = append(topLevel[fd.Name.Name], fd)
				}
			}
		}
	}

	result := make(map[string][]string, len(fns))
	for _, fn := range fns {
		roots := topLevel[fn]
		if len(roots) == 0 {
			return nil, fmt.Errorf("sourceguard: test function %q not found in %s", fn, dir)
		}

		found := map[string]bool{}
		seen := map[*ast.FuncDecl]bool{}
		queue := append([]*ast.FuncDecl(nil), roots...)
		for len(queue) > 0 {
			fd := queue[0]
			queue = queue[1:]
			if seen[fd] {
				continue
			}
			seen[fd] = true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if name := calleeName(call.Fun); name != "" {
						found[name] = true
						queue = append(queue, byName[name]...)
					}
				}
				return true
			})
		}

		names := make([]string, 0, len(found))
		for name := range found {
			names = append(names, name)
		}
		sort.Strings(names)
		result[fn] = names
	}
	return result, nil
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

// TestFileFacts is what TestFacts found in one package's test files.
type TestFileFacts struct {
	// Files is how many _test.go files were parsed; zero means the walk
	// proved nothing.
	Files int
	// Parallel is "file:line" of every selection of a method named
	// Parallel or RunParallel: a t.Parallel() or b.RunParallel(...) call,
	// or a method value taken from one.
	Parallel []string
	// Globals is "file:line: what" of every place a test touches
	// process-global state:
	//   - an assignment, or ++/--, whose target's root — through fields,
	//     indexes, derefs and parentheses — is a package-level var of this
	//     package (declared in a non-test OR a test file) or a name from an
	//     imported package: seam = f, counter++, registry["k"] = 1,
	//     cfg.N = 1, os.Stdin = r, http.DefaultClient.Timeout = d;
	//   - a call of a process-mutating function, matched through the file's
	//     imports (processMutators): os.Setenv, os.Chdir, log.SetOutput …;
	//   - a call of a function named *ForTests or *ForIntegrationTests;
	//   - any use of package netguard, whose recorder is process-wide.
	Globals []string
}

// processMutators are functions that change state every test in the
// process shares, keyed by import path. A name ending in "*" matches every
// function with that prefix. t.Setenv and t.Chdir are deliberately absent:
// the testing package itself refuses them in a parallel test.
var processMutators = map[string][]string{
	"os":            {"Setenv", "Unsetenv", "Clearenv", "Chdir"},
	"syscall":       {"Setenv", "Unsetenv", "Clearenv", "Chdir"},
	"log":           {"Set*"},
	"log/slog":      {"SetDefault", "SetLogLoggerLevel"},
	"os/signal":     {"Notify", "Ignore", "Reset", "Stop"},
	"runtime":       {"GOMAXPROCS"},
	"runtime/debug": {"Set*"},
	"net/http":      {"Handle", "HandleFunc"},
	"flag":          {"Set"},
}

func mutates(path, name string) bool {
	for _, m := range processMutators[path] {
		if m == name || (strings.HasSuffix(m, "*") && strings.HasPrefix(name, strings.TrimSuffix(m, "*"))) {
			return true
		}
	}
	return false
}

// rootIdent strips fields, indexes, derefs and parentheses off an
// assignment target down to the identifier it starts from.
func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			return x
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// TestFacts walks the _test.go files of dir — one package, in-package and
// external tests alike, build tags ignored — for the two facts the
// module's no-parallel pin needs: where a test runs in parallel, and where
// a test mutates state every test in the process shares. Like TestCallees
// it reads test files only; unlike it, it follows nothing, since both facts
// are about what a test file itself says.
//
// Matching is by name, deliberately over-approximate in the same safe
// direction as ReachableTokens: any method named Parallel counts, and an
// assignment counts as global whenever its target's root names a
// package-level var, even if a local of that name shadows it. Either error
// can only make a package look MORE in need of the pin, never less.
func TestFacts(dir string) (TestFileFacts, error) {
	var facts TestFileFacts
	fset := token.NewFileSet()
	pkgVars := map[string]bool{}
	collectVars := func(file *ast.File) {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					if name.Name != "_" {
						pkgVars[name.Name] = true
					}
				}
			}
		}
	}
	nonTest, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return facts, fmt.Errorf("sourceguard: parse %s: %w", dir, err)
	}
	for _, pkg := range nonTest {
		for _, file := range pkg.Files {
			collectVars(file)
		}
	}

	tests, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return facts, fmt.Errorf("sourceguard: parse tests in %s: %w", dir, err)
	}
	var files []*ast.File
	for _, pkg := range tests {
		for _, file := range pkg.Files {
			files = append(files, file)
			collectVars(file) // a package-level var a test file declares is just as shared
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return fset.Position(files[i].Pos()).Filename < fset.Position(files[j].Pos()).Filename
	})
	at := func(n ast.Node) string {
		p := fset.Position(n.Pos())
		return fmt.Sprintf("%s:%d", filepath.Base(p.Filename), p.Line)
	}
	for _, file := range files {
		facts.Files++
		// imported: the name each import is used by in this file -> its path.
		imported := map[string]string{}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			name := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imported[name] = path
		}
		target := func(lhs ast.Expr, op string) {
			root := rootIdent(lhs)
			if root == nil {
				return
			}
			if _, isPkg := imported[root.Name]; isPkg || pkgVars[root.Name] {
				facts.Globals = append(facts.Globals, at(lhs)+": "+targetText(lhs)+op)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "Parallel" || x.Sel.Name == "RunParallel" {
					facts.Parallel = append(facts.Parallel, at(x))
				}
				if id, ok := x.X.(*ast.Ident); ok && imported[id.Name] != "" && strings.HasSuffix(imported[id.Name], "/netguard") {
					facts.Globals = append(facts.Globals, at(x)+": netguard."+x.Sel.Name)
				}
			case *ast.CallExpr:
				name := calleeName(x.Fun)
				if strings.HasSuffix(name, "ForTests") || strings.HasSuffix(name, "ForIntegrationTests") {
					facts.Globals = append(facts.Globals, at(x)+": "+name)
				}
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && mutates(imported[id.Name], sel.Sel.Name) {
						facts.Globals = append(facts.Globals, at(x)+": "+id.Name+"."+sel.Sel.Name)
					}
				}
			case *ast.AssignStmt:
				if x.Tok == token.DEFINE {
					return true // := declares locals
				}
				for _, lhs := range x.Lhs {
					target(lhs, " "+x.Tok.String())
				}
			case *ast.IncDecStmt:
				target(x.X, x.Tok.String())
			}
			return true
		})
	}
	return facts, nil
}

// targetText renders an assignment target for a TestFileFacts entry.
func targetText(e ast.Expr) string {
	var b strings.Builder
	var walk func(ast.Expr)
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case *ast.Ident:
			b.WriteString(x.Name)
		case *ast.SelectorExpr:
			walk(x.X)
			b.WriteString("." + x.Sel.Name)
		case *ast.IndexExpr:
			walk(x.X)
			b.WriteString("[…]")
		case *ast.StarExpr:
			b.WriteString("*")
			walk(x.X)
		case *ast.ParenExpr:
			b.WriteString("(")
			walk(x.X)
			b.WriteString(")")
		default:
			b.WriteString("…")
		}
	}
	walk(e)
	return b.String()
}
