package sourceguard

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// A TYPE-AWARE view of the module's production code, for the U-A censuses.
//
// The first version matched calls by NAME, so every selector called `Run` was
// exempted, a method value (`f := c.Run`) or a method expression
// (`(*sshexec.Client).Run`) was invisible, a package-level initializer was
// never walked, and a type alias hid the refusal marker. Here every package of
// the module is type-checked with go/types (the standard library's source
// importer, as cmd/pveforge's own guards do; no module is added), and a
// reference is resolved to its *types.Func by object, whatever it is spelled.
//
// Objects of IMPORTED packages come from the importer's own type-check, not from
// this one, so functions are identified by FullName() ("(*pkg/path.T).M"), which
// is stable across the two.

type typedFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
	info *types.Info
}

type typedResult struct {
	files []typedFile
	// pkgs maps import path to the checked package, for scope questions.
	pkgs map[string]*types.Package
}

const modPath = "github.com/suykerbuyk/pveforge"

// typedModuleOnce builds the type-checked module once per process. It is a
// sync.OnceValues (no package variable is assigned from a test), so the
// package's t.Parallel tests share it safely.
var typedModuleOnce = sync.OnceValues(func() (*typedResult, error) { return buildTypedModule(nil) })

// typedHarnessOnce is the same module type-checked with the `harness` build tag:
// the harness-tagged production files (internal/pve/capture_harness_*.go,
// cmd/pveforge-harness-capture) hold task waits and could hold SSH calls.
var typedHarnessOnce = sync.OnceValues(func() (*typedResult, error) { return buildTypedModule([]string{"harness"}) })

// coveredBuildTags are the custom build tags the census covers, each as its own
// configuration beside the default one. TestUA_EveryBuildTagInUseIsCovered fails
// when a production file uses a tag that is not here (and not a platform tag),
// so the census cannot silently narrow to the default configuration again.
var coveredBuildTags = []string{"harness"}

func buildTypedModule(tags []string) (*typedResult, error) {
	res := &typedResult{pkgs: map[string]*types.Package{}}
	root, _ := filepath.Abs("../..")
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)
	var dirs []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		switch d.Name() {
		case "testdata", ".git", "vendor", ".wt", ".build":
			return filepath.SkipDir
		}
		dirs = append(dirs, p)
		return nil
	})
	sort.Strings(dirs)
	for _, dir := range dirs {
		ctx := build.Default
		ctx.BuildTags = tags
		bp, err := ctx.ImportDir(dir, 0)
		if err != nil || len(bp.GoFiles) == 0 {
			continue
		}
		rel, _ := filepath.Rel(root, dir)
		path := modPath
		if rel != "." {
			path += "/" + filepath.ToSlash(rel)
		}
		var files []*ast.File
		var names []string
		for _, n := range bp.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			files = append(files, f)
			names = append(names, filepath.ToSlash(filepath.Join(rel, n)))
		}
		info := &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Uses:       map[*ast.Ident]types.Object{},
			Defs:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		conf := types.Config{Importer: imp, Error: func(error) {}}
		pkg, _ := conf.Check(path, fset, files, info)
		if pkg == nil {
			return nil, fmt.Errorf("type-check %s failed", path)
		}
		res.pkgs[path] = pkg
		for i, f := range files {
			res.files = append(res.files, typedFile{rel: names[i], fset: fset, file: f, info: info})
		}
	}
	return res, nil
}

// typedModule returns the census universe: every production file of the default
// configuration, plus every file that only the harness configuration compiles
// (a file is never counted twice), and the default configuration's packages.
func typedModule(t *testing.T) ([]typedFile, map[string]*types.Package) {
	t.Helper()
	def, err := typedModuleOnce()
	if err != nil {
		t.Fatal(err)
	}
	if len(def.files) < 100 || len(def.pkgs) < 20 {
		t.Fatalf("the typed census saw %d files in %d packages: it is not seeing the module", len(def.files), len(def.pkgs))
	}
	har, err := typedHarnessOnce()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	files := append([]typedFile(nil), def.files...)
	for _, f := range def.files {
		seen[f.rel] = true
	}
	extra := 0
	for _, f := range har.files {
		if !seen[f.rel] {
			files = append(files, f)
			extra++
		}
	}
	// non-vacuity: the harness configuration really adds files (the capture
	// instruments), so a build that stopped honouring the tag fails here.
	if extra < 5 {
		t.Fatalf("the harness configuration added only %d files: the tagged files are not being census'd", extra)
	}
	return files, def.pkgs
}

// isSSHEntry reports whether fn is one of the SSH dispatch entry points: a
// METHOD named Run, rootRun, pveum or pveumWrite whose parameters are
// (context.Context, string). That is the shape of sshexec.Client.Run, of
// bootstrap.SSHSession.Run and of every adapter, and of RootAccess's helpers;
// it is NOT idempotent.Run or bootstrap.Run (functions) or a cobra Run.
func isSSHEntry(fn *types.Func) bool {
	if fn == nil || !sshEntryNames[fn.Name()] {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil || sig.Params().Len() != 2 {
		return false
	}
	return sig.Params().At(0).Type().String() == "context.Context" && sig.Params().At(1).Type().String() == "string"
}

type typedRef struct {
	site   censusSite
	isCall bool
	text   string // the selector as written
	fd     *ast.FuncDecl
	fset   *token.FileSet
}

// sshReferences returns every reference to an SSH entry point in non-test code:
// calls, and every other use (method values, method expressions, package-level
// initializers included).
func sshReferences(t *testing.T) []typedRef {
	files, _ := typedModule(t)
	var out []typedRef
	for _, tf := range files {
		callFuns := map[ast.Node]bool{}
		ast.Inspect(tf.file, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				f := c.Fun
				for {
					p, ok := f.(*ast.ParenExpr)
					if !ok {
						break
					}
					f = p.X
				}
				callFuns[f] = true
			}
			return true
		})
		var walk func(fn string, fd *ast.FuncDecl, n ast.Node)
		walk = func(fn string, fd *ast.FuncDecl, n ast.Node) {
			ast.Inspect(n, func(x ast.Node) bool {
				sel, ok := x.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				f, _ := tf.info.Uses[sel.Sel].(*types.Func)
				if !isSSHEntry(f) {
					return true
				}
				call := callFuns[sel]
				arg := ""
				if c := callOf(tf.file, sel); c != nil && len(c.Args) > 0 {
					arg = nodeText(tf.fset, c.Args[0])
				}
				text := nodeText(tf.fset, sel.X) + "." + sel.Sel.Name
				out = append(out, typedRef{
					site:   censusSite{file: tf.rel, fn: fn, callee: text, arg: arg, line: tf.fset.Position(sel.Pos()).Line},
					isCall: call, text: nodeText(tf.fset, sel), fd: fd, fset: tf.fset,
				})
				return true
			})
		}
		for _, d := range tf.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if fd.Body != nil {
					walk(funcName(tf.fset, fd), fd, fd.Body)
				}
				continue
			}
			walk("<package>", nil, d) // a package-level initializer
		}
	}
	return out
}

// callOf finds the CallExpr whose Fun is sel (unwrapping parentheses), or nil.
func callOf(f *ast.File, sel *ast.SelectorExpr) *ast.CallExpr {
	var found *ast.CallExpr
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return true
		}
		fn := c.Fun
		for {
			p, ok := fn.(*ast.ParenExpr)
			if !ok {
				break
			}
			fn = p.X
		}
		if fn == ast.Expr(sel) {
			found = c
		}
		return true
	})
	return found
}

// funcsIn returns the FuncDecl bodies by "file | func", for the funnel pins.
func typedBodies(t *testing.T) (map[string]*ast.FuncDecl, map[string]*token.FileSet) {
	files, _ := typedModule(t)
	bodies, fsets := map[string]*ast.FuncDecl{}, map[string]*token.FileSet{}
	for _, tf := range files {
		for _, d := range tf.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				k := tf.rel + " | " + funcName(tf.fset, fd)
				bodies[k], fsets[k] = fd, tf.fset
			}
		}
	}
	return bodies, fsets
}

// ---- the dispatch package's surface, and its constructors' callers ----

var dispatchPath = modPath + "/internal/dispatch"

// The exported surface of internal/dispatch is exactly this. The two marker
// TYPES are unexported with unexported fields (refusedBeforeWrite, unobserved),
// so only Refuse and Unobserve can build them, from anywhere, aliases included.
var dispatchSurface = []string{"Gate", "Has", "IsRefused", "IsUnobserved", "Open", "Opened", "Refuse", "Unobserve", "With"}

func TestUA_Dispatch_SurfaceIsClosed(t *testing.T) {
	_, pkgs := typedModule(t)
	p := pkgs[dispatchPath]
	if p == nil {
		t.Fatal("internal/dispatch was not type-checked")
	}
	var got []string
	for _, n := range p.Scope().Names() {
		if ast.IsExported(n) {
			got = append(got, n)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(dispatchSurface, ",") {
		t.Errorf("internal/dispatch exports %v, want exactly %v: an exported marker type would let any package build a refusal or an unobserved dispatch", got, dispatchSurface)
	}
	// no exported struct type with an exported field (a marker one could fill in)
	for _, n := range p.Scope().Names() {
		tn, ok := p.Scope().Lookup(n).(*types.TypeName)
		if !ok || !ast.IsExported(n) {
			continue
		}
		if st, ok := tn.Type().Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Exported() {
					t.Errorf("dispatch.%s has the exported field %s", n, st.Field(i).Name())
				}
			}
		}
	}
}

// Unobserve is called from exactly the two sites that KNOW a change was
// dispatched: the task wait and the root-SSH funnel. And NO type in the module
// declares a method DispatchUnobserved (the old open interface): a foreign type
// cannot make an error exit 3.
func TestUA_Dispatch_UnobserveCallersAreThePlansTwo_AndNoOpenInterface(t *testing.T) {
	files, _ := typedModule(t)
	callers := map[string]bool{}
	var open []string
	for _, tf := range files {
		ast.Inspect(tf.file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if f, ok := tf.info.Defs[id].(*types.Func); ok && f.Name() == "DispatchUnobserved" {
					open = append(open, tf.rel+": "+id.Name)
				}
			}
			return true
		})
		for _, d := range tf.file.Decls {
			// EVERY declaration is walked, a package-level initializer included:
			// `var x = dispatch.Unobserve(...)` is a caller too.
			encl := "<package>"
			if fd, ok := d.(*ast.FuncDecl); ok {
				encl = funcName(tf.fset, fd)
			}
			ast.Inspect(d, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if f, ok := tf.info.Uses[id].(*types.Func); ok && f.FullName() == dispatchPath+".Unobserve" && !strings.HasPrefix(tf.rel, "internal/dispatch/") {
					callers[tf.rel+" | "+encl] = true
				}
				return true
			})
		}
	}
	var got []string
	for k := range callers {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"internal/pve/task.go | Client.WaitForTask", "internal/sshexec/client.go | Client.Run"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("dispatch.Unobserve is called from %v, want exactly %v", got, want)
	}
	if len(open) != 0 {
		t.Errorf("a type declares DispatchUnobserved (the open marker interface is gone; nothing may implement it): %v", open)
	}
	// non-vacuity: the Uses walk finds callers at all
	if len(got) == 0 {
		t.Error("vacuous: no caller of dispatch.Unobserve was found")
	}
}

// newRefusedError is referenced, by OBJECT, only from the plan's files.
func TestUA_RefusedErrorIsReferencedOnlyWhereThePlanSays(t *testing.T) {
	files, _ := typedModule(t)
	allowed := map[string]bool{
		"cmd/pveforge/exitstatus.go": true, "cmd/pveforge/vm_destroy.go": true, "cmd/pveforge/doctor.go": true, "cmd/pveforge/acl_enable.go": true,
	}
	seen := false
	for _, tf := range files {
		ast.Inspect(tf.file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if f, ok := tf.info.Uses[id].(*types.Func); ok && f.Name() == "newRefusedError" {
					seen = true
					if !allowed[tf.rel] {
						t.Errorf("newRefusedError is referenced from %s (%s): a verb states a refusal with dispatch.Refuse", tf.rel, tf.fset.Position(id.Pos()))
					}
				}
			}
			return true
		})
	}
	if !seen {
		t.Error("vacuous: no reference to newRefusedError found")
	}
}

func TestUA_SSHEntryReferences_AreCalls_OnlyAndAllClassified(t *testing.T) {
	refs := sshReferences(t)
	golden := readGolden(t, "ssh_census.golden")
	seen := map[string]bool{}
	var problems []string
	calls := 0
	for _, r := range refs {
		if !r.isCall {
			problems = append(problems, fmt.Sprintf("a METHOD VALUE or METHOD EXPRESSION of an SSH dispatch entry point (it would send a command without a census row): %s | %s | %s (line %d)", r.site.file, r.site.fn, r.text, r.site.line))
			continue
		}
		calls++
		k := r.site.key()
		cls, ok := golden[k]
		if !ok {
			problems = append(problems, "UNCLASSIFIED SSH dispatch call (add it to testdata/ssh_census.golden as READ, WRITE, PASS or FUNNEL): "+k+" ctx="+r.site.arg)
			continue
		}
		seen[k] = true
		switch cls {
		case "WRITE":
			if !strings.HasSuffix(r.site.callee, ".pveumWrite") && (r.fd == nil || !marked(r.fset, r.fd, r.site.arg)) {
				problems = append(problems, "WRITE site whose ctx is not rooted in WithWrite/configWrite: "+k+" ctx="+r.site.arg)
			}
		case "READ":
			if r.fd != nil && marked(r.fset, r.fd, r.site.arg) {
				problems = append(problems, "READ site that carries the write mark: "+k+" ctx="+r.site.arg)
			}
		case "PASS", "FUNNEL":
		default:
			problems = append(problems, "unknown class "+cls+" for "+k)
		}
	}
	for k := range golden {
		if !seen[k] {
			problems = append(problems, "the golden names a site the typed scan no longer finds: "+k)
		}
	}
	if calls != sshCensusCount || len(golden) != sshCensusCount {
		problems = append(problems, fmt.Sprintf("census count: typed scan %d, golden %d, declared %d", calls, len(golden), sshCensusCount))
	}
	for _, p := range problems {
		t.Error(p)
	}
	for _, k := range []string{
		"internal/bootstrap/bootstrap.go | grantACL | session.Run",
		"internal/bootstrap/rotation.go | runner.removeHeld | r.session.Run",
		"internal/sshexec/install.go | InstallPubkeyViaPassword | client.Run",
	} {
		if golden[k] == "" {
			t.Errorf("non-vacuity: %s is not classified", k)
		}
	}
}

// G4: the harness teardown contexts are derived from WithoutCancel(the command's
// ctx), not from context.Background(), so the write gate stays visible to them.
func TestUA_HarnessCleanupContextsKeepTheGate(t *testing.T) {
	bodies, fsets := typedBodies(t)
	for _, k := range []string{"internal/harness/build/build.go | Driver.cleanup", "internal/harness/probe/probe.go | Driver.cleanup"} {
		fd := bodies[k]
		if fd == nil {
			t.Fatalf("%s not found", k)
		}
		body := nodeText(fsets[k], fd.Body)
		if !strings.Contains(body, "context.WithoutCancel(cmdCtx)") {
			t.Errorf("%s does not derive its teardown ctx from context.WithoutCancel(cmdCtx)", k)
		}
		if strings.Contains(body, "context.Background()") {
			t.Errorf("%s builds a context from context.Background(): the write gate would be invisible to the teardown", k)
		}
	}
}

// ---- the build configurations the census covers ----

// platformTags are build constraints the toolchain itself defines (GOOS, GOARCH,
// cgo, the compiler). They select files by platform, not by repo configuration:
// the census runs on the repo's one platform (linux) and the harness tag.
var platformTags = map[string]bool{
	"linux": true, "darwin": true, "windows": true, "freebsd": true, "netbsd": true, "openbsd": true, "solaris": true,
	"plan9": true, "js": true, "wasip1": true, "android": true, "ios": true, "aix": true, "dragonfly": true, "illumos": true,
	"unix": true, "amd64": true, "arm64": true, "arm": true, "386": true, "riscv64": true, "ppc64": true, "ppc64le": true,
	"s390x": true, "mips": true, "mipsle": true, "mips64": true, "mips64le": true, "loong64": true, "wasm": true,
	"cgo": true, "gc": true, "gccgo": true,
}

// buildTagsInUse returns every build tag named by a //go:build (or legacy
// // +build) line in a non-test, non-testdata production file, whether or not
// the default build would compile that file (the raw lines are read, so a file
// the default configuration skips is still seen).
func buildTagsInUse(t *testing.T) map[string][]string {
	t.Helper()
	used := map[string][]string{}
	walkModuleSources(t, func(rel string, fset *token.FileSet, f *ast.File, src []byte) {
		for _, line := range strings.Split(string(src), "\n") {
			line = strings.TrimSpace(line)
			var expr string
			switch {
			case strings.HasPrefix(line, "//go:build "):
				expr = strings.TrimPrefix(line, "//go:build ")
			case strings.HasPrefix(line, "// +build "):
				expr = strings.TrimPrefix(line, "// +build ")
			default:
				continue
			}
			for _, tok := range strings.FieldsFunc(expr, func(r rune) bool {
				return !(r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
			}) {
				used[tok] = append(used[tok], rel)
			}
		}
	})
	return used
}

// TestUA_EveryBuildTagInUseIsCovered: a production file under a custom build tag
// the census does not cover would be invisible to it (that is how the census
// first narrowed to the default build). A NEW tag fails here until it is added
// to coveredBuildTags (which adds a configuration to the typed census) on purpose.
func TestUA_EveryBuildTagInUseIsCovered(t *testing.T) {
	used := buildTagsInUse(t)
	covered := map[string]bool{}
	for _, c := range coveredBuildTags {
		covered[c] = true
	}
	if len(used["harness"]) < 5 {
		t.Fatalf("vacuous: the scan found only %d harness-tagged files", len(used["harness"]))
	}
	var tags []string
	for tag := range used {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		if platformTags[tag] || covered[tag] || strings.HasPrefix(tag, "go1.") {
			continue
		}
		t.Errorf("build tag %q (in %v) is not covered by the typed census: add it to coveredBuildTags and give it a configuration, or the files it selects are invisible to the SSH, roster and Unobserve censuses", tag, used[tag])
	}
	for _, c := range coveredBuildTags {
		if len(used[c]) == 0 {
			t.Errorf("coveredBuildTags names %q, which no production file uses any more", c)
		}
	}
}
