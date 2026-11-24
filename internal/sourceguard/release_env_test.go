package sourceguard

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The ENVIRONMENT contract (contract plan §3.3 6b, rulings CX2 and the U-B brief):
// the set of environment variables the module reads, sets or strips is held to a
// golden (testdata/env_names.golden) EXACTLY, from a type-checked scan of every
// production file in the default and the harness configurations. Nothing here is
// matched by name: a call is recognised by the *types.Func it resolves to. A
// function VALUE (`lookup := os.LookupEnv`, a method value) resolves to a variable and
// would be skipped, so any reference to an env function that is not the callee of a
// call is itself a failure (TestRelease_EnvFunctionValuesAreRejected).
//
// Three kinds of access are census'd:
//
//  1. the os / syscall environment functions (Getenv, LookupEnv, Setenv,
//     Unsetenv, Environ, ExpandEnv, Expand);
//  2. WRAPPERS: an in-module function whose parameters are an environment slice
//     and a name (internal/harness's lookupEnv reads an injected environ slice),
//     recognised by signature ([]string, string) and by reaching an env type, and
//     every in-module function that takes a name and reads os.Getenv;
//  3. string constants and literals that look like one of this program's
//     variables (^(PVEFORGE|HARNESS)_[A-Z0-9_]+$), so a variable that is only
//     ever handed to a child process or an allow-list is still counted.
//
// A read whose name is not a constant (a dynamic read) must be one of the
// allowed Environ sites below, whose only use is to filter or hand over a whole
// environment.

var envFuncs = map[string]bool{
	"os.Getenv": true, "os.LookupEnv": true, "os.Setenv": true, "os.Unsetenv": true,
	"os.Environ": true, "os.ExpandEnv": true, "os.Expand": true,
	"syscall.Getenv": true, "syscall.Setenv": true, "syscall.Unsetenv": true, "syscall.Environ": true,
}

// environSites are the files that hand a whole environment over or filter one
// (no variable name is read there): `exec` strips two variables and adds one for
// its child; the harness guard injects the process environment into its checks;
// the harness secrets tool passes it to its helper.
var environSites = map[string]string{
	"cmd/pveforge/exec.go":                 "execEnv: the child's environment, minus the roster passphrase and PVE password, plus the authorization variable",
	"internal/harness/guard.go":            "Open injects the process environment into the guard (read through lookupEnv)",
	"cmd/pveforge-harness-secrets/main.go": "the secrets tool hands the process environment to harnesssecrets.Main",
}

var envNameRE = regexp.MustCompile(`^(PVEFORGE|HARNESS)_[A-Z0-9_]+$`)

// envNamesFromGolden reads the golden.
func envGolden(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/env_names.golden")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

type envScan struct {
	names    map[string][]string // name -> sites
	environ  map[string]bool     // files calling os.Environ
	dynamic  []string            // reads whose name is not a constant
	wrappers map[string]bool     // wrapper functions found
	calls    int
}

func isEnvWrapper(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || fn.Pkg() == nil || !strings.HasPrefix(fn.Pkg().Path(), modPath) {
		return false
	}
	p := sig.Params()
	if p.Len() != 2 || sig.Results().Len() != 2 {
		return false
	}
	return p.At(0).Type().String() == "[]string" && p.At(1).Type().String() == "string" && strings.Contains(strings.ToLower(fn.Name()), "env")
}

// stringListVars maps every package-level `var X = []string{...}` of constants
// (by its *types.Var) to its values, so a read inside `for _, v := range X` is
// resolved to the names in X instead of being a dynamic read.
func stringListVars(files []typedFile) map[types.Object][]string {
	out := map[types.Object][]string{}
	for _, tf := range files {
		for _, d := range tf.file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				cl, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				var vals []string
				allConst := true
				for _, e := range cl.Elts {
					tv, ok := tf.info.Types[e]
					if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
						allConst = false
						break
					}
					vals = append(vals, constant.StringVal(tv.Value))
				}
				if allConst && len(vals) > 0 {
					if obj := tf.info.Defs[vs.Names[0]]; obj != nil {
						out[obj] = vals
					}
				}
			}
		}
	}
	return out
}

func scanEnv(t *testing.T) envScan {
	t.Helper()
	files, _ := typedModule(t)
	lists := stringListVars(files)
	res := envScan{names: map[string][]string{}, environ: map[string]bool{}, wrappers: map[string]bool{}}
	note := func(name, site string) { res.names[name] = append(res.names[name], site) }
	for _, tf := range files {
		var ranges []*ast.RangeStmt
		var stack []ast.Node
		ast.Inspect(tf.file, func(n ast.Node) bool {
			if n == nil {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if rs, ok := top.(*ast.RangeStmt); ok && len(ranges) > 0 && ranges[len(ranges)-1] == rs {
					ranges = ranges[:len(ranges)-1]
				}
				return true
			}
			stack = append(stack, n)
			if rs, ok := n.(*ast.RangeStmt); ok {
				ranges = append(ranges, rs)
			}
			switch x := n.(type) {
			case *ast.CallExpr:
				var obj types.Object
				switch f := x.Fun.(type) {
				case *ast.SelectorExpr:
					obj = tf.info.Uses[f.Sel]
				case *ast.Ident:
					obj = tf.info.Uses[f]
				}
				fn, _ := obj.(*types.Func)
				if fn == nil {
					return true
				}
				full := fn.FullName()
				wrapper := isEnvWrapper(fn)
				if !envFuncs[full] && !wrapper {
					return true
				}
				res.calls++
				if wrapper {
					res.wrappers[full] = true
				}
				if full == "os.Environ" || full == "syscall.Environ" {
					res.environ[tf.rel] = true
					return true
				}
				// the name is the last argument (Getenv/LookupEnv/Setenv/Unsetenv:
				// first; the wrapper: second): find the first string argument
				var arg ast.Expr
				for _, a := range x.Args {
					if tv, ok := tf.info.Types[a]; ok && tv.Type != nil && tv.Type.String() != "[]string" {
						arg = a
						break
					}
				}
				if arg == nil {
					return true
				}
				tv := tf.info.Types[arg]
				if tv.Value != nil && tv.Value.Kind() == constant.String {
					note(constant.StringVal(tv.Value), tf.rel)
				} else if names := rangedNames(tf, ranges, arg, lists); len(names) > 0 {
					for _, nm := range names {
						note(nm, tf.rel)
					}
				} else {
					res.dynamic = append(res.dynamic, tf.rel+": "+nodeText(tf.fset, x))
				}
			case *ast.BasicLit:
				if tv, ok := tf.info.Types[x]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
					if v := constant.StringVal(tv.Value); envNameRE.MatchString(v) {
						note(v, tf.rel)
					}
				}
			}
			return true
		})
		// named string constants (const X = "PVEFORGE_…") are literals too, counted
		// by the BasicLit case above at their declaration
	}
	return res
}

// rangedNames resolves a read of a range variable over a package-level list of
// constants (guard.go's proxyVars) to the list's values.
func rangedNames(tf typedFile, ranges []*ast.RangeStmt, arg ast.Expr, lists map[types.Object][]string) []string {
	id, ok := arg.(*ast.Ident)
	if !ok {
		return nil
	}
	use := tf.info.Uses[id]
	for i := len(ranges) - 1; i >= 0; i-- {
		rs := ranges[i]
		val, ok := rs.Value.(*ast.Ident)
		if !ok || tf.info.Defs[val] != use {
			continue
		}
		if x, ok := rs.X.(*ast.Ident); ok {
			return lists[tf.info.Uses[x]]
		}
	}
	return nil
}

func (r envScan) set() []string {
	var out []string
	for n := range r.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// AC-S1: the code's environment set equals the schema golden, EXACTLY.
func TestRelease_EnvSetIsExact(t *testing.T) {
	r := scanEnv(t)
	got, want := r.set(), envGolden(t)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the environment variables the code reads, sets or strips differ from testdata/env_names.golden (and the schema's env table):\n code: %v\n golden: %v\n a new variable needs a row in cmd/pveforge/contract.go envTable and a line in the golden; a removed one is a breaking change", got, want)
	}
	// non-vacuity: the known reads are found through all three routes
	for _, must := range []string{"PVEFORGE_ROSTER", "PVEFORGE_ROSTER_PASSPHRASE", "HARNESS_STORAGE", "HARNESS_CREATED_FILE", "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"} {
		if len(r.names[must]) == 0 {
			t.Errorf("the scan did not find %s", must)
		}
	}
	if r.calls < 12 {
		t.Errorf("the scan saw only %d environment calls: it is not seeing the module", r.calls)
	}
	if !r.wrappers["github.com/suykerbuyk/pveforge/internal/harness.lookupEnv"] {
		t.Errorf("the lookupEnv wrapper of internal/harness (guard.go:143) was not recognised; wrappers: %v", r.wrappers)
	}
	// the wrapper route must have found a name the direct route cannot see
	foundViaWrapper := false
	for _, s := range r.names["PVEFORGE_HARNESS_OUTER_ROSTERS"] {
		if strings.HasPrefix(s, "internal/harness/") {
			foundViaWrapper = true
		}
	}
	if !foundViaWrapper {
		t.Errorf("PVEFORGE_HARNESS_OUTER_ROSTERS was not seen in internal/harness: the wrapper route is not working")
	}
}

// A read whose name is not a constant, and every whole-environment hand-over, is
// on an explicit list with a reason: a new one fails until a reviewer adds it.
func TestRelease_EnvDynamicAccessIsListed(t *testing.T) {
	r := scanEnv(t)
	for _, d := range r.dynamic {
		t.Errorf("an environment read whose name is not a constant: %s", d)
	}
	var got []string
	for f := range r.environ {
		got = append(got, f)
	}
	sort.Strings(got)
	var want []string
	for f := range environSites {
		want = append(want, f)
	}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("os.Environ is used in %v, the reviewed sites are %v", got, want)
	}
}

// FUNCTION VALUES (code review C1/G1). The scan above recognises a call whose callee
// resolves to an env function. `lookup := os.LookupEnv; lookup(name)` and a method
// value resolve to a variable, so the call would be skipped and the name never
// counted. Following assignments through every variable is open-ended, so the rule is
// the closed one: ANY reference to an env function (or the lookupEnv wrapper) that is
// not the callee of a call expression is a FAILURE, unless it is on this allow-list
// (empty: nothing in the module needs one).
var envFuncValueAllowed = map[string]string{}

// envFuncValueRefs returns every reference to an env function or env wrapper in the
// files that is not the callee of a call.
func envFuncValueRefs(files []typedFile) []string {
	var out []string
	for _, tf := range files {
		callee := map[*ast.Ident]bool{}
		ast.Inspect(tf.file, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			f := c.Fun
			for {
				p, ok := f.(*ast.ParenExpr)
				if !ok {
					break
				}
				f = p.X
			}
			switch x := f.(type) {
			case *ast.SelectorExpr:
				callee[x.Sel] = true
			case *ast.Ident:
				callee[x] = true
			}
			return true
		})
		ast.Inspect(tf.file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			fn, _ := tf.info.Uses[id].(*types.Func)
			if fn == nil || !(envFuncs[fn.FullName()] || isEnvWrapper(fn)) || callee[id] {
				return true
			}
			site := tf.rel + ":" + strconv.Itoa(tf.fset.Position(id.Pos()).Line) + ": " + fn.FullName()
			if _, ok := envFuncValueAllowed[tf.rel+": "+fn.FullName()]; !ok {
				out = append(out, site)
			}
			return true
		})
	}
	return out
}

func TestRelease_EnvFunctionValuesAreRejected(t *testing.T) {
	files, _ := typedModule(t)
	for _, s := range envFuncValueRefs(files) {
		t.Errorf("an environment function used as a value, which the census cannot follow: %s", s)
	}
}

// checkSource type-checks one source file as a package of the module (so the
// lookupEnv wrapper rule applies to it) and returns it as a typedFile.
func checkSource(t *testing.T, src string) typedFile {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{},
		Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check(modPath+"/internal/fixture", fset, []*ast.File{f}, info); err != nil {
		t.Fatalf("fixture does not type-check: %v", err)
	}
	return typedFile{rel: "internal/fixture/fixture.go", fset: fset, file: f, info: info}
}

// The plants of the two reviewers, and the controls that must NOT trip it.
func TestRelease_EnvFunctionValuePlantsAreCaught(t *testing.T) {
	const wrapper = "func lookupEnv(environ []string, name string) (string, bool) { return \"\", false }\n"
	plants := map[string]string{
		"codex: a variable holding os.LookupEnv": "package fixture\nimport (\"os\"; \"strings\")\nfunc F() { lookup := os.LookupEnv; name := strings.Join([]string{\"PVEFORGE\", \"INJECTED\"}, \"_\"); _, _ = lookup(name) }\n",
		"grok: a method value of os.Getenv":      "package fixture\nimport \"os\"\nfunc F() string { fn := os.Getenv; return fn(\"HOME\") }\n",
		"a package-level var of os.Setenv":       "package fixture\nimport \"os\"\nvar set = os.Setenv\nfunc F() { _ = set(\"A\", \"b\") }\n",
		"os.Environ passed as a value":           "package fixture\nimport \"os\"\nfunc g(f func() []string) []string { return f() }\nfunc F() []string { return g(os.Environ) }\n",
		"the lookupEnv wrapper as a value":       "package fixture\n" + wrapper + "func F() { lk := lookupEnv; _, _ = lk(nil, \"X\") }\n",
		"os.Unsetenv in a struct field":          "package fixture\nimport \"os\"\ntype T struct{ f func(string) error }\nfunc F() T { return T{f: os.Unsetenv} }\n",
	}
	for name, src := range plants {
		if got := envFuncValueRefs([]typedFile{checkSource(t, src)}); len(got) == 0 {
			t.Errorf("%s: the census did not flag the function value", name)
		}
	}
	controls := map[string]string{
		"a direct call":        "package fixture\nimport \"os\"\nfunc F() string { return os.Getenv(\"HOME\") }\n",
		"a parenthesised call": "package fixture\nimport \"os\"\nfunc F() string { return (os.Getenv)(\"HOME\") }\n",
		"the wrapper, called":  "package fixture\n" + wrapper + "func F() { _, _ = lookupEnv(nil, \"X\") }\n",
	}
	for name, src := range controls {
		if got := envFuncValueRefs([]typedFile{checkSource(t, src)}); len(got) != 0 {
			t.Errorf("%s: flagged a plain call: %v", name, got)
		}
	}
}
