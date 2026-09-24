// Package lockguard is the one source scan behind the tests that hold
// internal/lock's callers to account. It is imported only by tests: by
// internal/lock's, which checks that every lock-taking call is given its
// caller's own context, and by cmd/pveforge's, which checks that every
// command reaching a lock carries --lock-wait. Both need the same list of
// lock-taking functions, so it is derived here once rather than walked
// twice.
//
// The same scan also holds every PVE task wait to account (Scan.TaskWaits):
// each call of a WaitForTask method must be given its caller's own context,
// by the same rule as a lock call outside the command package, because the
// context carries what the wait reports to (pve.WithTaskWarnings). A wait
// on context.Background() would succeed with its warnings unreported.
//
// It imports no pveforge package (sourceguard imports none either), so
// internal/lock's own tests can use it without an import cycle.
//
// The context check is syntax only, and deliberately conservative: a call's
// context must be the parameter itself — cmd.Context() on the command's
// *cobra.Command parameter, or the function's own context.Context parameter
// — and that parameter's name must not be re-bound ANYWHERE in the function
// that declares it (assigned, redeclared with :=, declared with var, or
// bound as a range variable or an inner closure's parameter), in any order.
// So `cmd = cmd.Root()` or `ctx = context.Background()` before the call is
// refused, and so, as the price of not analysing order or flow, is the
// correct `ctx := cmd.Context(); lock.Read(ctx, ...)`: pass cmd.Context()
// (or the ctx parameter) to the call directly. Outside the command package a
// closure must take its own ctx parameter: one that uses its enclosing
// function's ctx is refused as well. testdata/tree holds one fixture per
// accepted and refused shape (lockguard_test.go).
package lockguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// LockPkg is internal/lock's import path.
const LockPkg = "github.com/suykerbuyk/pveforge/internal/lock"

// CommandDir is the command package, where every lock-taking call must be
// given its command's own context: <*cobra.Command>.Context().
const CommandDir = "cmd/pveforge"

// TakerFiles are the only non-test files outside CommandDir allowed to take
// an internal/lock lock, with their package paths. Every exported top-level
// function in them that does is a sink; a lock taken anywhere else in the
// module is a Violation until it has been reviewed and listed here.
var TakerFiles = map[string]string{
	"internal/idempotent/op.go":       "github.com/suykerbuyk/pveforge/internal/idempotent",
	"internal/bootstrap/bootstrap.go": "github.com/suykerbuyk/pveforge/internal/bootstrap",
}

// taskWaitTarget is every call of a method named WaitForTask: the pve
// clients' and the idempotent package's interfaces over them.
var taskWaitTarget = sourceguard.Target{AnyQualifier: true, Name: "WaitForTask"}

// lockTargets are internal/lock's two lock-taking functions.
var lockTargets = []sourceguard.Target{{ImportPath: LockPkg, Name: "Mutation"}, {ImportPath: LockPkg, Name: "Read"}}

// Call is one checked call of a sink.
type Call struct {
	Ref sourceguard.Ref
	// Problem is why the call's context argument is not its caller's own
	// context, or "" when it is.
	Problem string
}

// Scan is the result of one walk of the module.
type Scan struct {
	// Sinks are the lock-taking functions, as "<import path>.<name>":
	// lock.Mutation, lock.Read and the ones derived from TakerFiles.
	Sinks map[string]bool
	// Violations are lock.Mutation/lock.Read references outside CommandDir
	// and TakerFiles.
	Violations []sourceguard.Ref
	// TakerProblems are locks taken in a TakerFiles file somewhere no
	// caller can be checked against (a method, an unexported function), or
	// a TakerFiles file that no longer takes a lock at all.
	TakerProblems []string
	// Calls are every call of a sink in CommandDir and TakerFiles, each
	// with its context-argument verdict.
	Calls []Call
	// TaskWaits are every call of a WaitForTask method anywhere in the
	// module's non-test source, each with its context-argument verdict: the
	// enclosing function's own context.Context parameter, never re-bound,
	// in the command package too.
	TaskWaits []Call
	// Parsed is the first walk's file list, for a caller's coverage floor.
	Parsed []string
	// Result is the first walk's own result, for a caller's anti-vacuity
	// assertions (Allowed).
	Result sourceguard.Result
}

// Targets are the lock.Mutation and lock.Read targets.
func Targets() []sourceguard.Target { return append([]sourceguard.Target(nil), lockTargets...) }

// ScanModule walks the module at root (a relative path such as "../..") and
// returns what it found. An error means the walk itself failed.
func ScanModule(root string) (Scan, error) {
	var sc Scan
	scope := sourceguard.Scope{Root: root, AllowDirs: []string{CommandDir}}
	for f := range TakerFiles {
		scope.AllowFiles = append(scope.AllowFiles, f)
	}
	sort.Strings(scope.AllowFiles)
	res, err := sourceguard.NonTestReferences(scope, lockTargets)
	if err != nil {
		return sc, err
	}
	sc.Result, sc.Parsed, sc.Violations = res, res.Parsed, res.Violations()

	sc.Sinks = map[string]bool{LockPkg + ".Mutation": true, LockPkg + ".Read": true}
	var derived []sourceguard.Target
	files := sortedKeys(TakerFiles)
	for _, file := range files {
		var refs []sourceguard.Ref
		for _, tgt := range lockTargets {
			refs = append(refs, res.Allowed(file, tgt)...)
		}
		if len(refs) == 0 {
			sc.TakerProblems = append(sc.TakerProblems, fmt.Sprintf("%s no longer takes a lock: drop it from lockguard.TakerFiles", file))
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, 0)
		if err != nil {
			return sc, err
		}
		for _, ref := range refs {
			fd := enclosingDecl(fset, f, ref.Line)
			if fd == nil || fd.Recv != nil || !fd.Name.IsExported() {
				sc.TakerProblems = append(sc.TakerProblems, fmt.Sprintf("%s: the lock is taken outside an exported top-level function, so no caller can be checked against it", ref))
				continue
			}
			name := TakerFiles[file] + "." + fd.Name.Name
			if !sc.Sinks[name] {
				sc.Sinks[name] = true
				derived = append(derived, sourceguard.Target{ImportPath: TakerFiles[file], Name: fd.Name.Name})
			}
		}
	}

	// Every call of a sink, in CommandDir and TakerFiles: the lock calls
	// from the first walk, the derived sinks' calls from a second.
	calls := res
	var derivedRes sourceguard.Result
	if len(derived) > 0 {
		if derivedRes, err = sourceguard.NonTestReferences(scope, derived); err != nil {
			return sc, err
		}
	}
	byFile := map[string][]sourceguard.Ref{}
	for _, r := range []sourceguard.Result{calls, derivedRes} {
		for file, refs := range r.Refs {
			for _, ref := range refs {
				if ref.Allowed {
					byFile[file] = append(byFile[file], ref)
				}
			}
		}
	}
	for _, file := range sortedKeys(byFile) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, 0)
		if err != nil {
			return sc, err
		}
		inCommands := strings.HasPrefix(file, CommandDir+"/")
		for _, ref := range byFile[file] {
			sc.Calls = append(sc.Calls, Call{Ref: ref, Problem: checkContextArg(fset, f, ref, inCommands)})
		}
	}

	// Every task wait, module-wide: no allow-list, so every ref is one to check.
	waits, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: root}, []sourceguard.Target{taskWaitTarget})
	if err != nil {
		return sc, err
	}
	for _, file := range sortedKeys(waits.Refs) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, file), nil, 0)
		if err != nil {
			return sc, err
		}
		for _, ref := range waits.Refs[file] {
			sc.TaskWaits = append(sc.TaskWaits, Call{Ref: ref, Problem: checkContextArg(fset, f, ref, false)})
		}
	}
	return sc, nil
}

// checkContextArg finds ref's call and reports why its first argument is
// not the caller's own context, or "" when it is. In the command package
// that is <p>.Context() for a *cobra.Command parameter p of an enclosing
// function; elsewhere it is a context.Context parameter of the enclosing
// function, passed as is. Either way the parameter's name must not be
// re-bound anywhere in the function declaring it (rebound).
func checkContextArg(fset *token.FileSet, f *ast.File, ref sourceguard.Ref, inCommands bool) string {
	call, stack := findCall(fset, f, ref)
	if call == nil {
		return "the call could not be located in the source"
	}
	if len(call.Args) == 0 {
		return "the call has no context argument"
	}
	if inCommands {
		cobraName := importName(f, "github.com/spf13/cobra")
		c, ok := call.Args[0].(*ast.CallExpr)
		if !ok || len(c.Args) != 0 {
			return "its context is not <cmd>.Context() of the command's *cobra.Command: pass cmd.Context() directly"
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Context" {
			return "its context is not <cmd>.Context() of the command's *cobra.Command: pass cmd.Context() directly"
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || cobraName == "" {
			return "its context is not <cmd>.Context() of the command's *cobra.Command: pass cmd.Context() directly"
		}
		decl, scope := paramDecl(stack, id.Name, func(t ast.Expr) bool {
			st, ok := t.(*ast.StarExpr)
			return ok && isQualified(st.X, cobraName, "Command")
		})
		if decl == nil {
			return "its context is not <cmd>.Context() of the command's *cobra.Command: pass cmd.Context() directly"
		}
		if rebound(scope, id.Name) {
			return fmt.Sprintf("its context is %s.Context(), but %s is re-bound in the function that declares it, so it may no longer be the command: pass cmd.Context() directly, on a %s that is never re-bound", id.Name, id.Name, id.Name)
		}
		return ""
	}
	contextName := importName(f, "context")
	id, ok := call.Args[0].(*ast.Ident)
	if !ok || contextName == "" {
		return "its context is not the enclosing function's own context.Context parameter: pass that parameter directly"
	}
	decl, scope := paramDecl(stack, id.Name, func(t ast.Expr) bool {
		return isQualified(t, contextName, "Context")
	})
	// The parameter must be the innermost function's own: a closure using
	// an outer function's ctx is refused too (conservative, like FP1).
	if decl == nil || decl != stack[len(stack)-1] {
		return "its context is not the enclosing function's own context.Context parameter: pass that parameter directly"
	}
	if rebound(scope, id.Name) {
		return fmt.Sprintf("its context is %s, but %s is re-bound in the function that declares it, so it may no longer be the caller's context: pass the parameter directly, never re-bound", id.Name, id.Name)
	}
	return ""
}

// rebound reports whether name is bound again anywhere in fn's body: the
// target of an assignment (=, :=, op=) or of a var declaration, a range key
// or value, or a parameter or result of a closure inside fn. Order is not
// considered: a re-binding after the call counts too (see the package doc).
func rebound(fn ast.Node, name string) bool {
	body := funcBody(fn)
	if body == nil {
		return false
	}
	is := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if is(l) {
					found = true
				}
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				if id.Name == name {
					found = true
				}
			}
		case *ast.RangeStmt:
			if (x.Key != nil && is(x.Key)) || (x.Value != nil && is(x.Value)) {
				found = true
			}
		case *ast.FuncLit:
			for _, fl := range []*ast.FieldList{x.Type.Params, x.Type.Results} {
				if fl == nil {
					continue
				}
				for _, field := range fl.List {
					for _, id := range field.Names {
						if id.Name == name {
							found = true
						}
					}
				}
			}
		}
		return !found
	})
	return found
}

// findCall returns ref's call and the functions (FuncDecl or FuncLit)
// enclosing it, outermost first.
func findCall(fset *token.FileSet, f *ast.File, ref sourceguard.Ref) (*ast.CallExpr, []ast.Node) {
	var found *ast.CallExpr
	var foundStack []ast.Node
	var stack []ast.Node
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		if n == nil || found != nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			stack = append(stack, x)
			ast.Inspect(funcBody(x), visit)
			stack = stack[:len(stack)-1]
			return false
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == ref.Target.Name && fset.Position(sel.Sel.Pos()).Line == ref.Line {
				// A method target's receiver can be any expression
				// (op.Client.WaitForTask): its name and line locate it.
				if id, ok := sel.X.(*ast.Ident); (ok && id.Name == ref.Qualifier) || ref.Target.AnyQualifier {
					found, foundStack = x, append([]ast.Node(nil), stack...)
					return false
				}
			}
		}
		return true
	}
	for _, d := range f.Decls {
		ast.Inspect(d, visit)
	}
	return found, foundStack
}

func funcBody(n ast.Node) ast.Node {
	switch x := n.(type) {
	case *ast.FuncDecl:
		if x.Body == nil {
			return nil
		}
		return x.Body
	case *ast.FuncLit:
		return x.Body
	}
	return nil
}

func funcParams(n ast.Node) *ast.FieldList {
	switch x := n.(type) {
	case *ast.FuncDecl:
		return x.Type.Params
	case *ast.FuncLit:
		return x.Type.Params
	}
	return nil
}

// paramDecl finds the functions in stack (outermost first) that declare a
// parameter named name. inner is the innermost of them, returned only when
// its parameter's type satisfies want (else both are nil); outer is the
// outermost, the scope rebound must search: a closure parameter of the
// same name inside it is a re-binding that shadows it.
func paramDecl(stack []ast.Node, name string, want func(ast.Expr) bool) (inner, outer ast.Node) {
	declares := func(fn ast.Node) (ast.Expr, bool) {
		params := funcParams(fn)
		if params == nil {
			return nil, false
		}
		for _, field := range params.List {
			for _, n := range field.Names {
				if n.Name == name {
					return field.Type, true
				}
			}
		}
		return nil, false
	}
	for i := len(stack) - 1; i >= 0; i-- {
		if t, ok := declares(stack[i]); ok {
			if !want(t) {
				return nil, nil
			}
			inner = stack[i]
			break
		}
	}
	if inner == nil {
		return nil, nil
	}
	for _, fn := range stack {
		if _, ok := declares(fn); ok {
			return inner, fn
		}
	}
	return inner, inner
}

func isQualified(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// importName is f's local name for path ("" if f does not import it). An
// unaliased import is named by the path's last segment, which holds for the
// two paths this package asks about (cobra and context).
func importName(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return path[strings.LastIndex(path, "/")+1:]
	}
	return ""
}

func enclosingDecl(fset *token.FileSet, f *ast.File, line int) *ast.FuncDecl {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fset.Position(fd.Pos()).Line <= line && line <= fset.Position(fd.End()).Line {
			return fd
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
