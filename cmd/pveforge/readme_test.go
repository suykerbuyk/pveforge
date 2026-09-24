package main

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The README states two facts an operator looks for and must be able to
// trust: the environment variables pveforge reads, and its exit statuses.
// These tests derive both from the code and require the README's tables to
// say exactly that, so neither can silently rot.

// readmeTable returns the first backticked cell of every row of the table
// under the README heading "## <section>".
func readmeTable(t *testing.T, section string) []string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(b), "\n## "+section+"\n")
	if !ok {
		t.Fatalf("README has no %q section", section)
	}
	if i := strings.Index(body, "\n## "); i >= 0 {
		body = body[:i]
	}
	var cells []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([^`]+)` \\|").FindAllStringSubmatch(body, -1) {
		cells = append(cells, m[1])
	}
	if len(cells) == 0 {
		t.Fatalf("README's %q section has no table rows", section)
	}
	slices.Sort(cells)
	return cells
}

// TestREADME_EnvironmentVariablesMatchTheCode: the README's Environment
// table names exactly the PVEFORGE_* variables the module's non-test source
// mentions.
func TestREADME_EnvironmentVariablesMatchTheCode(t *testing.T) {
	re := regexp.MustCompile(`PVEFORGE_[A-Z0-9_]+`)
	seen := map[string]bool{}
	files := 0
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && path != "../.." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				for _, v := range re.FindAllString(lit.Value, -1) {
					seen[v] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A name built from constants ("PVEFORGE_" + "X", or a const of one)
	// is no literal of its own: resolve every environment call's name.
	for v := range envCallNames(t) {
		seen[v] = true
	}
	var code []string
	for v := range seen {
		code = append(code, v)
	}
	slices.Sort(code)
	if files < 50 || len(code) == 0 {
		t.Fatalf("walked %d files and found %q: the sweep is not seeing the module", files, code)
	}
	if doc := readmeTable(t, "Environment"); !slices.Equal(doc, code) {
		t.Errorf("README Environment table = %q, but the code reads %q", doc, code)
	}
}

// envCallNames type-checks every module package whose non-test source calls
// os or syscall Getenv, LookupEnv, Setenv or Unsetenv, and returns the
// PVEFORGE_* names those calls use, folded to their constant values. A
// name that is not a constant fails the test: it could be any variable.
func envCallNames(t *testing.T) map[string]bool {
	t.Helper()
	envFuncs := map[string]bool{"Getenv": true, "LookupEnv": true, "Setenv": true, "Unsetenv": true}
	byDir := map[string][]string{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "../.." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	calls := 0
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)
	for dir, paths := range byDir {
		var files []*ast.File
		mentions := false
		for _, p := range paths {
			src, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if regexp.MustCompile(`\b(Getenv|LookupEnv|Setenv|Unsetenv)\(`).Match(src) {
				mentions = true
			}
			f, err := parser.ParseFile(fset, p, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		if !mentions {
			continue
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
		if _, err := (&types.Config{Importer: imp}).Check(dir, fset, files, info); err != nil {
			t.Fatalf("type-check %s: %v", dir, err)
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				fn, ok := info.Uses[sel.Sel].(*types.Func)
				if !ok || fn.Pkg() == nil || (fn.Pkg().Path() != "os" && fn.Pkg().Path() != "syscall") || !envFuncs[fn.Name()] {
					return true
				}
				calls++
				tv := info.Types[call.Args[0]]
				if tv.Value == nil || tv.Value.Kind() != constant.String {
					t.Errorf("%s: %s.%s's variable name is not a constant, so the README's Environment table cannot be checked against it", fset.Position(call.Pos()), fn.Pkg().Name(), fn.Name())
					return true
				}
				if v := constant.StringVal(tv.Value); strings.HasPrefix(v, "PVEFORGE_") {
					names[v] = true
				}
				return true
			})
		}
	}
	if calls < 3 {
		t.Fatalf("found %d environment calls: the type-checked walk is not seeing them", calls)
	}
	return names
}

// TestREADME_ExitStatusesMatchTheCode: the README's Exit status table lists
// exactly the statuses pveforge can exit with: the integer literals runRoot
// returns or assigns to its code, and 128+signum for each signal
// notifyInterrupt catches. main's os.Exit(realMain()) must be the only exit.
func TestREADME_ExitStatusesMatchTheCode(t *testing.T) {
	fset, files, info := checkedPackage(t)
	signums := map[string]syscall.Signal{
		"SIGHUP": syscall.SIGHUP, "SIGINT": syscall.SIGINT, "SIGQUIT": syscall.SIGQUIT,
		"SIGTERM": syscall.SIGTERM, "SIGUSR1": syscall.SIGUSR1, "SIGUSR2": syscall.SIGUSR2,
	}
	codes := map[int]bool{}
	var sawRunRoot, sawExitCode, sawNotify bool
	exits := 0
	// status resolves one exit-status expression: a constant of any
	// spelling (a literal, a named const, a folded expression) is recorded;
	// the signal path (ie.exitCode()) and the variable code itself are
	// accounted for elsewhere; anything else cannot be checked, and fails.
	status := func(e ast.Expr, where string) {
		if tv := info.Types[e]; tv.Value != nil {
			n, ok := constant.Int64Val(tv.Value)
			if !ok {
				t.Errorf("%s: exit status %s is not an integer constant", fset.Position(e.Pos()), types.ExprString(e))
			}
			codes[int(n)] = true
			return
		}
		if id, ok := e.(*ast.Ident); ok && id.Name == "code" && where == "runRoot" {
			return
		}
		if call, ok := e.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "exitCode" {
				return
			}
		}
		if where == "exitCode" {
			return // 128+signum: accounted for from notifyInterrupt's signals
		}
		t.Errorf("%s: exit status %s in %s cannot be resolved to a constant", fset.Position(e.Pos()), types.ExprString(e), where)
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" {
						exits++
						if inner, ok := call.Args[0].(*ast.CallExpr); !ok || calleeIdent(inner) != "realMain" {
							t.Errorf("%s: an os.Exit other than main's os.Exit(realMain()): its status is not in the README's contract", fset.Position(call.Pos()))
						}
					}
				}
			}
			return true
		})
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			switch name := fd.Name.Name; name {
			case "runRoot", "exitCode":
				if name == "runRoot" {
					sawRunRoot = true
				} else {
					sawExitCode = true
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncLit:
						return false // a closure's returns are not the function's
					case *ast.ReturnStmt:
						for _, r := range x.Results {
							status(r, name)
						}
					case *ast.AssignStmt:
						for i, l := range x.Lhs {
							if id, ok := l.(*ast.Ident); ok && id.Name == "code" && i < len(x.Rhs) {
								status(x.Rhs[i], name)
							}
						}
					}
					return true
				})
			case "notifyInterrupt":
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || calleeIdent(call) != "notifySignals" {
						return true
					}
					sawNotify = true
					for _, a := range call.Args[1:] {
						name := exprName(a)
						s, known := signums[strings.TrimPrefix(name, "syscall.")]
						if !known {
							t.Fatalf("notifyInterrupt catches %s, which this test does not know: add it here and to the README", name)
						}
						codes[128+int(s)] = true
					}
					return true
				})
			}
		}
	}
	if !sawRunRoot || !sawExitCode || !sawNotify || exits != 1 {
		t.Fatalf("runRoot seen %v, exitCode seen %v, notifySignals seen %v, os.Exit calls %d: the walk is not seeing the exit paths", sawRunRoot, sawExitCode, sawNotify, exits)
	}
	var code []string
	for c := range codes {
		code = append(code, strconv.Itoa(c))
	}
	doc := readmeTable(t, "Exit status")
	slices.SortFunc(code, func(a, b string) int { x, _ := strconv.Atoi(a); y, _ := strconv.Atoi(b); return x - y })
	slices.SortFunc(doc, func(a, b string) int { x, _ := strconv.Atoi(a); y, _ := strconv.Atoi(b); return x - y })
	if !slices.Equal(doc, code) {
		t.Errorf("README Exit status table = %q, but the code can exit with %q", doc, code)
	}
}

func calleeIdent(call *ast.CallExpr) string {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// exprName is "pkg.Name" for a qualified identifier, else a placeholder.
func exprName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
	}
	return "an expression"
}
