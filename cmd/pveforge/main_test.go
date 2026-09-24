package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewRootCmd_RegistersSubcommands(t *testing.T) {
	root := newRootCmd()
	names := map[string]bool{}
	for _, c := range root.Commands() {
		names[c.Name()] = true
	}
	for _, want := range []string{"roster", "bootstrap", "vm", "node", "storage", "network"} {
		if !names[want] {
			t.Errorf("expected root command to register a %q subcommand, got: %v", want, names)
		}
	}
}

// C8: a non-bootstrap command's error carrying server text (an api 500
// body with a line break) reaches stderr through runRoot as ONE line.
func TestRunRoot_C8_ServerTextInAnErrorIsOneLine(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("x\nwarning: forged"))
	}))
	t.Cleanup(srv.Close)
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	root := newRootCmd()
	root.SetArgs([]string{"api", "get", "/x", "qa-pve-01", "--roster", rosterPath})
	root.SetOut(io.Discard)
	var stderr bytes.Buffer
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(stderr.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stderr has %d lines: %q", len(lines), stderr.String())
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "warning:") {
			t.Fatalf("a forged warning line: %q", stderr.String())
		}
	}
	var decoded string
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil || !strings.Contains(decoded, "pve returned 500") {
		t.Fatalf("decoded %q, %v", decoded, err)
	}
}

// C9: an error text that needs no quoting prints exactly as before.
func TestRunRoot_C9_PlainErrorUnchanged(t *testing.T) {
	root := &cobra.Command{Use: "x", SilenceUsage: true, SilenceErrors: true, RunE: func(*cobra.Command, []string) error {
		return errors.New("bootstrap qa: preflight: the requested node is not a member of the PVE cluster")
	}}
	root.SetArgs(nil)
	var stderr bytes.Buffer
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if got, want := stderr.String(), "bootstrap qa: preflight: the requested node is not a member of the PVE cluster\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

// checkedPackage parses and type-checks this package's non-test files once,
// for the source guards (the source importer is slow).
func checkedPackage(t *testing.T) (*token.FileSet, []*ast.File, *types.Info) {
	t.Helper()
	checked.once.Do(func() {
		checked.fset = token.NewFileSet()
		entries, err := os.ReadDir(".")
		if err != nil {
			checked.err = err
			return
		}
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
				f, err := parser.ParseFile(checked.fset, n, nil, 0)
				if err != nil {
					checked.err = err
					return
				}
				checked.files = append(checked.files, f)
			}
		}
		checked.info = &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Uses:       map[*ast.Ident]types.Object{},
			Defs:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		conf := types.Config{Importer: importer.ForCompiler(checked.fset, "source", nil)}
		if _, err := conf.Check("main", checked.fset, checked.files, checked.info); err != nil {
			checked.err = fmt.Errorf("type-check: %w", err)
		}
	})
	if checked.err != nil {
		t.Fatal(checked.err)
	}
	return checked.fset, checked.files, checked.info
}

var checked struct {
	once  sync.Once
	fset  *token.FileSet
	files []*ast.File
	info  *types.Info
	err   error
}

// MS1: a source guard over this package's non-test files, type-checked.
// (a) Only main.go (runRoot) may print an error-typed value to stderr:
// fmt.Fprint* to os.Stderr or to any X.ErrOrStderr(), or cmd.PrintErr*. A
// second raw print site would bypass runRoot's one-line quoting.
// (b) Every fmt.Fprint* to ErrOrStderr() in api.go that formats the
// server's UPID passes it through kvjson.QuoteValue.
func TestStderrErrorPrintsOnlyThroughRunRoot_MS1(t *testing.T) {
	fset, files, info := checkedPackage(t)
	errorIface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	isStderr := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr: // os.Stderr
			id, ok := x.X.(*ast.Ident)
			return ok && id.Name == "os" && x.Sel.Name == "Stderr"
		case *ast.CallExpr: // X.ErrOrStderr()
			sel, ok := x.Fun.(*ast.SelectorExpr)
			return ok && sel.Sel.Name == "ErrOrStderr"
		}
		return false
	}
	stderrSites, upidSites := 0, 0
	for _, f := range files {
		file := filepath.Base(fset.Position(f.Pos()).Filename)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			var args []ast.Expr
			switch {
			case strings.HasPrefix(sel.Sel.Name, "Fprint") && len(call.Args) > 0 && isStderr(call.Args[0]):
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
					return true
				}
				args = call.Args[1:]
			case strings.HasPrefix(sel.Sel.Name, "PrintErr"):
				args = call.Args
			default:
				return true
			}
			stderrSites++
			for _, a := range args {
				tv, ok := info.Types[a]
				if ok && tv.Type != nil && types.Implements(tv.Type, errorIface) && file != "main.go" {
					t.Errorf("%s: an error-typed value printed to stderr outside runRoot", fset.Position(a.Pos()))
				}
				if file == "api.go" {
					if id, ok := a.(*ast.Ident); ok && id.Name == "upid" {
						t.Errorf("%s: the server's UPID printed to stderr without kvjson.QuoteValue", fset.Position(a.Pos()))
					}
					if c, ok := a.(*ast.CallExpr); ok {
						if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "QuoteValue" && len(c.Args) == 1 {
							if id, ok := c.Args[0].(*ast.Ident); ok && id.Name == "upid" {
								upidSites++
							}
						}
					}
				}
			}
			return true
		})
	}
	// Anti-vacuity: the walk must have seen the known sites.
	if stderrSites < 6 || upidSites != 3 {
		t.Fatalf("stderr sites seen = %d, quoted UPID sites = %d (want >= 6 and exactly 3): the guard is not seeing the code", stderrSites, upidSites)
	}
}

// stderrSites is the complete allow-list of the places this package's
// non-test files reach stderr, as "file: function: source" with a count
// ("(package)" for a top-level declaration). A place reaches stderr when it
// names os.Stderr or X.ErrOrStderr/X.OutOrStderr (called or not), calls
// SetErr/SetOutput or cobra's Print*/PrintErr*, uses the log package or the
// print builtins, or uses a variable that may hold a stderr writer. Such
// variables are found by what is ASSIGNED to them, never by their name: a
// local or package-level var whose declaration or any assignment carries a
// stderr reference, and a parameter of this package's functions that any
// call passes one to, to a fixed point. The site is the call that place is
// an argument of, else its own statement or var spec, else its top-level
// declaration. A new stderr write, however it is spelled (err.Error() in a
// string, a writer held in a local or package-level variable of any name),
// is not on this list and fails MS1c: add it here only after checking that
// it cannot print server text or an error outside runRoot's one-line
// quoting.
//
// Known, deliberate limits: a writer made from the raw descriptor
// (os.NewFile(2, ...), or a syscall on fd 2) is not recognised; neither is a
// writer read back from a struct field, map or func value (storing one there
// is itself a site, so the binding is caught, not every later use).
var stderrSites = map[string]int{
	"api.go: newAPIVerbCmd: fmt.Fprintf(cmd.ErrOrStderr(), \"dispatched PVE task %s\\n\", kvjson.QuoteValue(upid))":                                                                                                                                                                                1,
	"api.go: newAPIVerbCmd: fmt.Fprintf(cmd.ErrOrStderr(), \"notice: --no-wait: not waiting for task %s; its outcome is not checked\\n\", kvjson.QuoteValue(upid))":                                                                                                                                1,
	"api.go: newAPIVerbCmd: fmt.Fprintf(cmd.ErrOrStderr(), \"notice: --no-wait: not waiting for task %s; the lock on %s is released now, before the task finishes, so a concurrent pveforge mutation of the same object is no longer serialized against it\\n\", kvjson.QuoteValue(upid), key)":    1,
	"api.go: newAPIVerbCmd: fmt.Fprintf(cmd.ErrOrStderr(), \"warning: path %q does not match a known pveforge-managed object type \u2014 proceeding WITHOUT internal/lock protection (--unsafe-no-lock); concurrent pveforge mutations against this target/path are not serialized\\n\", rawPath)": 1,
	"bootstrap.go: finishBootstrap: renderBootstrapResult(out, errOut, f, target, res)":                                                                                                                                                                                                            1,
	"bootstrap.go: newBootstrapCmd: finishBootstrap(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, args[0], res, err)":                                                                                                                                                                              1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: API token %s may have been revoked and was NOT replaced: the remove's outcome could not be established; check it with pveum user token list\\n\", id)":                                                                    1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: existing API token %s was revoked and NOT replaced; every copy of its secret, including this roster's, is dead\\n\", id)":                                                                                                 1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: replaced API token %s (%s): it no longer existed on PVE; nothing was revoked by this run\\n\", id, q(res.ReplacedReason))":                                                                                                1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: replaced API token %s (%s); its old secret is now revoked for every holder\\n\", id, q(res.ReplacedReason))":                                                                                                              1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: this roster still holds token %s, which is dead on PVE; remove the target's [targets.token] block by hand\\n\", id)":                                                                                                      1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: token %s created by this run is still live on PVE and its secret was lost; remove it by hand with pveum user token remove\\n\", q(res.LeftoverToken))":                                                                    1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: token %s created by this run may still be live on PVE and its secret was lost; check with pveum user token list and remove it by hand with pveum user token remove\\n\", q(res.LeftoverToken))":                           1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: token %s is still live on PVE with its grants but is no longer held by this roster\\n\", q(res.OrphanedToken))":                                                                                                           1,
	"bootstrap.go: renderBootstrapResult: fmt.Fprintf(errOut, \"warning: token %s was persisted but its grants could not be verified\\n\", id)":                                                                                                                                                    1,
	"bootstrap.go: resolvePVEPassword: fmt.Fprint(os.Stderr, \"PVE password: \")":                                                                                                                                                                                                                  1,
	"bootstrap.go: resolvePVEPassword: fmt.Fprintln(os.Stderr)":                                                                   1,
	"main.go: realMain: runRoot(root, os.Stderr)":                                                                                 1,
	"main.go: runRoot: fmt.Fprintln(stderr, kvjson.QuoteValue(msg))":                                                              1,
	"main.go: runRoot: root.SetErr(stderr)":                                                                                       1,
	"roster_import.go: newRosterImportTokenCmd: finishBootstrap(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, args[0], res, err)": 1,
	"vm.go: newVMSetCmd: fmt.Fprintf(cmd.ErrOrStderr(), \"warning: %s: vm %d: the write was applied but its result could not be re-read: %s\\n\", args[0], vmid, kvjson.QuoteValue(boundErrText(res.AfterErr.Error())))":                         1,
	"vm.go: newVMSetCmd: reportPending(cmd.ErrOrStderr(), args[0], vmid, op, res.PostApplyErr)":                                                                                                                                                  1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"warning: %s: vm %d: the change was applied but whether it is pending could not be checked: %s\\n\", targetID, vmid, kvjson.QuoteValue(boundErrText(postErr.Error())))":                          1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"warning: %s: vm %d: the change was applied but whether it has reached the cloud-init drive could not be checked: %s\\n\", targetID, vmid, kvjson.QuoteValue(boundErrText(postErr.Error())))":    1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"notice: %s: vm %d: %s is pending: it takes effect at the VM's next cold boot\\n\", targetID, vmid, kvjson.QuoteKey(f))":                                                                         1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"notice: %s: vm %d: delete=%s is pending: it takes effect at the VM's next cold boot\\n\", targetID, vmid, kvjson.QuoteValue(f))":                                                                1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"notice: %s: vm %d: %s is saved but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\\n\", targetID, vmid, kvjson.QuoteKey(f))":          1,
	"vm.go: reportPending: fmt.Fprintf(errOut, \"notice: %s: vm %d: delete=%s is saved but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\\n\", targetID, vmid, kvjson.QuoteValue(f))": 1,
}

// MS1c: every stderr site in this package is on stderrSites, exactly.
func TestStderrSitesAreAllowListed_MS1c(t *testing.T) {
	fset, files, info := checkedPackage(t)
	isPkg := func(e ast.Expr, path string) bool {
		id, ok := e.(*ast.Ident)
		if !ok {
			return false
		}
		pn, ok := info.Uses[id].(*types.PkgName)
		return ok && pn.Imported().Path() == path
	}
	isCobraCmd := func(sel *ast.SelectorExpr) bool {
		s, ok := info.Selections[sel]
		return ok && strings.Contains(s.Recv().String(), "github.com/spf13/cobra.Command")
	}
	// funcDecls maps this package's functions and methods to their
	// declarations, for tainting parameters.
	funcDecls := map[types.Object]*ast.FuncDecl{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				funcDecls[info.Defs[fd.Name]] = fd
			}
		}
	}
	// tainted: the variables that may hold a stderr writer, by assignment.
	tainted := map[types.Object]bool{}
	// isRef: the node itself names a stderr writer.
	isRef := func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			return (isPkg(x.X, "os") && x.Sel.Name == "Stderr") || x.Sel.Name == "ErrOrStderr" || x.Sel.Name == "OutOrStderr"
		case *ast.Ident:
			return tainted[info.Uses[x]]
		}
		return false
	}
	// carries: e evaluates to a stderr writer itself (a ref, a call of
	// X.ErrOrStderr, or a conversion or assertion of one). Any other
	// expression that merely contains a ref (a closure, a composite, a call
	// result) is not followed: it is a site of its own, so the binding is
	// already on the list.
	var carries func(e ast.Expr) bool
	carries = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.ParenExpr:
			return carries(x.X)
		case *ast.TypeAssertExpr:
			return carries(x.X)
		case *ast.CallExpr:
			if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
				return carries(x.Args[0]) // a conversion, io.Writer(os.Stderr)
			}
			sel, ok := x.Fun.(*ast.SelectorExpr)
			return ok && (sel.Sel.Name == "ErrOrStderr" || sel.Sel.Name == "OutOrStderr")
		case *ast.SelectorExpr, *ast.Ident:
			return isRef(x)
		}
		return false
	}
	taint := func(id *ast.Ident) bool {
		obj := info.Defs[id]
		if obj == nil {
			obj = info.Uses[id]
		}
		v, ok := obj.(*types.Var)
		if !ok || v.IsField() || tainted[v] {
			return false
		}
		tainted[v] = true
		return true
	}
	paired := func(lhs []*ast.Ident, rhs []ast.Expr) bool {
		changed := false
		for i, id := range lhs {
			switch {
			case len(rhs) == len(lhs):
				if carries(rhs[i]) {
					changed = taint(id) || changed
				}
			case len(rhs) == 1:
				if carries(rhs[0]) {
					changed = taint(id) || changed
				}
			}
		}
		return changed
	}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					changed = paired(x.Names, x.Values) || changed
				case *ast.AssignStmt:
					var lhs []*ast.Ident
					for _, l := range x.Lhs {
						id, _ := l.(*ast.Ident)
						if id == nil {
							id = ast.NewIdent("_") // a field or index: the statement is a site
						}
						lhs = append(lhs, id)
					}
					changed = paired(lhs, x.Rhs) || changed
				case *ast.CallExpr:
					var fnObj types.Object
					switch fun := x.Fun.(type) {
					case *ast.Ident:
						fnObj = info.Uses[fun]
					case *ast.SelectorExpr:
						fnObj = info.Uses[fun.Sel]
					}
					fd := funcDecls[fnObj]
					if fd == nil {
						return true
					}
					var params []*ast.Ident
					for _, fld := range fd.Type.Params.List {
						params = append(params, fld.Names...)
					}
					for i, arg := range x.Args {
						p := i
						if p >= len(params) {
							p = len(params) - 1 // variadic
						}
						if p >= 0 && carries(arg) {
							changed = taint(params[p]) || changed
						}
					}
				}
				return true
			})
		}
	}
	// selfSite: the node is itself the stderr write (the call is the site).
	// writerRef: the node names a stderr writer; the site is where it goes.
	classify := func(n ast.Node) (selfSite, writerRef bool) {
		if isRef(n) {
			return false, true
		}
		x, ok := n.(*ast.CallExpr)
		if !ok {
			return false, false
		}
		switch f := x.Fun.(type) {
		case *ast.Ident:
			_, builtin := info.Uses[f].(*types.Builtin)
			return builtin && (f.Name == "print" || f.Name == "println"), false
		case *ast.SelectorExpr:
			switch {
			case isPkg(f.X, "log"):
				return true, false
			case f.Sel.Name == "SetErr" || f.Sel.Name == "SetOutput" || strings.HasPrefix(f.Sel.Name, "PrintErr"):
				return true, false
			case strings.HasPrefix(f.Sel.Name, "Print") && isCobraCmd(f):
				return true, false
			}
		}
		return false, false
	}
	render := func(n ast.Node) string {
		var b bytes.Buffer
		if err := printer.Fprint(&b, fset, n); err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(b.String()), " ")
	}
	got := map[string]int{}
	for _, f := range files {
		file := filepath.Base(fset.Position(f.Pos()).Filename)
		var stack []ast.Node
		seen := map[ast.Node]bool{} // a site is counted once, however many refs it holds
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			fn := "(package)"
			if len(stack) > 1 {
				if d, ok := stack[1].(*ast.FuncDecl); ok {
					fn = d.Name.Name
				}
			}
			self, ref := classify(n)
			var site ast.Node
			switch {
			case self:
				site = n
			case ref:
				for i := len(stack) - 2; i >= 0 && site == nil; i-- {
					switch a := stack[i].(type) {
					case *ast.CallExpr:
						if a.Fun != stack[i+1] { // not the ref's own call, X.ErrOrStderr()
							site = a
						}
					case ast.Stmt, *ast.ValueSpec:
						site = a
					}
				}
				if site == nil && len(stack) > 1 {
					site = stack[1] // the top-level declaration
				}
			}
			if site != nil && !seen[site] {
				seen[site] = true
				got[file+": "+fn+": "+render(site)]++
			}
			return true
		})
	}
	for k, n := range got {
		if stderrSites[k] != n {
			t.Errorf("a stderr site not on the allow-list (seen %d, allowed %d):\n\t%s", n, stderrSites[k], k)
		}
	}
	for k, n := range stderrSites {
		if got[k] != n {
			t.Errorf("an allow-listed stderr site was not seen (seen %d, allowed %d): the list is stale or the guard is blind:\n\t%s", got[k], n, k)
		}
	}
}
