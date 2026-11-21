package sourceguard

// U7, the destroy boundary guard (spec Q4). The ONE production path that
// sends PVE `DELETE /nodes/<n>/qemu/<vmid>` is `pveforge vm destroy`:
// cmd/pveforge/vm_destroy.go runVMDestroy, which determines an in-flight
// destroy first (U4) and proves the VM gone after (U5). Every other way the
// module's non-test source can reach a VM destroy is enumerated in
// destroySites below, keyed (file, enclosing function, target) with an EXACT
// count and a reason; anything else is RED.
//
// What counts as "a way to destroy" (destroyTargets):
//
//	T1 *.DestroyVM              any selector: call, method value, method
//	                            expression, interface call, promotion
//	T2 DestroyVM                a declaration or interface method spec: a
//	                            new wrapper or interface to hide behind
//	T3 idempotent.VMDestroy     constructing the Op is the only way to its
//	                            Apply (destroy, no determination, nil wait
//	                            taken as success) — alias-proof
//	T4 VMDestroy                the same inside package idempotent
//	T5 net/http.MethodDelete    the raw-DELETE idiom (rawUPID, RawUPID,
//	                            RawRequest) — alias-proof
//	T6 "DELETE"                 the same spelled as a literal
//	T7 "DestroyVM"              reflect MethodByName
//	T8 *.Delete, *.DeleteWithParams
//	                            go-proxmox's own deletes, which carry no
//	                            DELETE token at the call site (a stdlib
//	                            slices.Delete, resolved through the file's
//	                            imports, is dropped: destroyRefs)
//	P  runVMDestroy, newVMDestroyCmd, newAPICmd, newHarnessVMDestroyCmd
//	                            the funnels: a second caller of the verb's
//	                            body (which never takes the object lock), or
//	                            a re-registration of a destroying command
//
// And one rule no count can express (B1 of the plan review): each ALLOWED
// idempotent.VMDestroy construction must have the shape
// `<ident> := &idempotent.VMDestroy{...}` and its value may only be used as
// `<ident>.Read(...)` or `<ident>.StatusGatedStop(...)` inside its own
// function. A *VMDestroy is an idempotent.Op; passed, returned, stored or
// assigned to an interface it can reach Apply — `idempotent.Run(…, op, …)`
// or a one-line `func applyOp(ctx, o idempotent.Op) error` — with no new T-ref
// and every count unchanged.
//
// And its twin on the RECEIVER side (FO-1 of the code review): inside
// internal/idempotent/vmdestroy.go, every VMDestroy method other than Apply —
// Read and StatusGatedStop are exactly what the verb and the harness call —
// may use its receiver only as `<recv>.<member>` with member != Apply, and
// may not call Run at all. Otherwise an edit inside Read could reach Apply
// with no new T-ref.
//
// WHAT THIS GUARD CANNOT SEE (accepted residuals; a call-SITE guard, not a
// call graph):
//
//   - runtime data: `pveforge api delete /nodes/<n>/qemu/<vmid>` (api.go's
//     row is the source site only), the shell harness (lib.sh
//     harness_vm_destroy → `pveforge api delete`), and a Go self-exec such
//     as exec.Command(os.Args[0], "api", "delete", …);
//   - a computed method string: "DEL"+"ETE", strings.ToUpper("delete"), a
//     lowercase "delete" handed to http.NewRequestWithContext inside
//     internal/pve (whether PVE accepts a lowercase method is unverified),
//     bytes. RawRequest itself refuses anything but the exact "DELETE".
//     Inside an ALLOWED destroying function this is narrowed, not closed:
//     there every net/http.MethodDelete must be the method argument of its
//     request call (destroyTokenShapes), every DestroyVM a call, and the
//     number of request-shaped calls is pinned (destroyFuncRequests), so a
//     discarded `_ = http.MethodDelete` beside a byte-built method (G28), or
//     a second byte-built request beside the real one (G22, G12), is RED. A
//     byte-built or concatenated method that REPLACES the method argument of
//     an EXISTING request call in an allowed function — count and token
//     shape unchanged, e.g. one of NetworkBridgeEnsure.stage's three
//     requests turned from GET into DELETE — is still invisible, as is a
//     request built through a call this guard does not name (requestCalls);
//   - a value already holding "DELETE" carried across a function boundary
//     into an ALLOWED funnel (api.go's `method` closure, outer.RawUPID,
//     rawUPID, RawRequest) — a NEW caller still needs a T5/T6 at its site;
//   - transitive callers of allowed functions beyond the pinned funnels:
//     probe.(*Driver).Run, the build driver, the cobra parent trees
//     (newHarnessVMCmd, newVMCmd, newRootCmd) re-registered whole;
//   - reflection by index (reflect.Value.Method(i)), reflection on a name
//     computed at run time, and reflection by a literal name other than
//     "DestroyVM" — notably reflect.ValueOf(vm).MethodByName("Delete") on a
//     go-proxmox *VirtualMachine (T8 sees vm.Delete as a selector, not as a
//     string);
//   - SSH command strings (`qm destroy`, `pvesh delete`): matching is
//     exact-literal, not substring;
//   - //go:linkname, assembly, cgo, unsafe: DirectiveEvasions owns them;
//   - the slices drop (destroyRefs) is scope-checked only syntactically: a
//     `slices` declared ANYWHERE in the enclosing function (a define, an
//     assign target, a param, a range variable — any bare identifier
//     `slices` that is not a selector's left side) keeps the ref (G20b,
//     `slices := vm; slices.Delete(ctx, …)`, is RED). A package-level
//     `slices` cannot coexist with the import in the same file (the
//     compiler refuses it);
//   - B1's check is syntactic per FuncDecl with no object resolution:
//     shadowing the construction's identifier errs toward RED, never green;
//   - a nested module re-admitted by a loosened replace/go.work policy
//     (walkNonTest skips one only under a top-level dot-dir, and an in-tree
//     one is a walker error).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const idempotentPath = "github.com/suykerbuyk/pveforge/internal/idempotent"

var (
	dtAnyDestroyVM     = Target{AnyQualifier: true, Name: "DestroyVM"}
	dtBareDestroyVM    = Target{Name: "DestroyVM"}
	dtIdemVMDestroy    = Target{ImportPath: idempotentPath, Name: "VMDestroy"}
	dtBareVMDestroy    = Target{Name: "VMDestroy"}
	dtMethodDelete     = Target{ImportPath: "net/http", Name: "MethodDelete"}
	dtLitDELETE        = Target{Literal: true, Name: "DELETE"}
	dtLitDestroyVM     = Target{Literal: true, Name: "DestroyVM"}
	dtAnyDelete        = Target{AnyQualifier: true, Name: "Delete"}
	dtAnyDeleteParams  = Target{AnyQualifier: true, Name: "DeleteWithParams"}
	dtRunVMDestroy     = Target{Name: "runVMDestroy"}
	dtNewVMDestroyCmd  = Target{Name: "newVMDestroyCmd"}
	dtNewAPICmd        = Target{Name: "newAPICmd"}
	dtNewHarnessDelCmd = Target{Name: "newHarnessVMDestroyCmd"}
)

func destroyTargets() []Target {
	return []Target{
		dtAnyDestroyVM, dtBareDestroyVM, dtIdemVMDestroy, dtBareVMDestroy,
		dtMethodDelete, dtLitDELETE, dtLitDestroyVM, dtAnyDelete, dtAnyDeleteParams,
		dtRunVMDestroy, dtNewVMDestroyCmd, dtNewAPICmd, dtNewHarnessDelCmd,
	}
}

// destroyFixtureOnly are the targets with NO site in the real tree today;
// their anti-vacuity source is the probe fixture alone. Every other target
// must have at least one row in destroySites.
var destroyFixtureOnly = map[Target]bool{
	dtLitDELETE: true, dtLitDestroyVM: true, dtAnyDelete: true, dtAnyDeleteParams: true,
}

// destroySite is one reviewed (file, func, target) key with its exact count.
type destroySite struct {
	file, fn string
	target   Target
	count    int
	class    string
	why      string
}

// The classes a row may carry.
var destroyClasses = map[string]bool{
	"verb": true, "definition": true, "forwarder": true, "dead-op": true,
	"harness-unclassified": true, "harness-capture": true,
	"non-vm-delete": true, "fake-server": true, "funnel": true,
}

const (
	whyHarness = "harness, unclassified, accepted: ledger-gated (outer.Guard ModeDestroy) → StatusGatedStop → raw DELETE with purge+destroy-unreferenced-disks (which DestroyVM cannot express) → outer.VMGone; not the verb's determination or gone-proof"
	whyStopOp  = "the VMDestroy is used ONLY for .Read/.StatusGatedStop (the B1 escape check pins that), never Applied"
)

// destroySites is the whole allow-list. A new site is a reviewed row with a
// reason — never an AllowDir, never a floor count.
var destroySites = []destroySite{
	// The verb.
	{"cmd/pveforge/vm_destroy.go", "runVMDestroy", dtAnyDestroyVM, 1, "verb",
		"THE one production destroy: after DetermineDestroyInFlight, --yes, its own config read and StatusGatedStop; followed by DestroyEnd + JudgeGone"},
	{"cmd/pveforge/vm_destroy.go", "runVMDestroy", dtIdemVMDestroy, 1, "verb", "the verb's own config read and gated stop; " + whyStopOp},
	{"cmd/pveforge/vm_destroy.go", "runVMDestroy", dtRunVMDestroy, 1, "funnel", "the declaration of the verb's body"},
	{"cmd/pveforge/vm_destroy.go", "newVMDestroyCmd", dtRunVMDestroy, 1, "funnel",
		"the ONE caller of runVMDestroy, which holds the object lock runVMDestroy never takes"},
	{"cmd/pveforge/vm_destroy.go", "newVMDestroyCmd", dtNewVMDestroyCmd, 1, "funnel", "the declaration of the verb's command"},
	{"cmd/pveforge/vm.go", "newVMCmd", dtNewVMDestroyCmd, 1, "funnel", "the verb's one registration, under `pveforge vm`"},

	// Definitions and forwarders.
	{"internal/pve/vmdestroy.go", "Client.DestroyVM", dtBareDestroyVM, 1, "definition", "the typed destroy's declaration"},
	{"internal/pve/vmdestroy.go", "Client.DestroyVM", dtMethodDelete, 1, "definition", "the one typed DELETE /nodes/<n>/qemu/<vmid>"},
	{"internal/pve/routed.go", "RoutedClient.DestroyVM", dtBareDestroyVM, 1, "forwarder", "the routed client's declaration"},
	{"internal/pve/routed.go", "RoutedClient.DestroyVM", dtAnyDestroyVM, 1, "forwarder", "a thin pass-through; its callers are themselves rows"},
	{"internal/idempotent/vmdestroy.go", "", dtBareDestroyVM, 1, "definition", "VMDestroyClient's method set (compat_test.go pins RoutedClient satisfies it)"},
	{"internal/idempotent/vmdestroy.go", "", dtBareVMDestroy, 1, "definition", "the VMDestroy type declaration"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.fetchVMConfig", dtBareVMDestroy, 1, "definition", "a receiver"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.Read", dtBareVMDestroy, 1, "definition", "a receiver"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.Satisfied", dtBareVMDestroy, 1, "definition", "a receiver"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.StatusGatedStop", dtBareVMDestroy, 1, "definition", "a receiver"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.Apply", dtBareVMDestroy, 1, "dead-op", "a receiver"},
	{"internal/idempotent/vmdestroy.go", "VMDestroy.Apply", dtAnyDestroyVM, 1, "dead-op",
		"no production caller: reachable only through a VMDestroy that escapes as an idempotent.Op (the construction rows and the B1 escape check forbid it) or through another VMDestroy method calling Apply or Run on its receiver (the receiver check forbids it)"},

	// The harness residuals (the spec's four, plus the capture instrument).
	{"cmd/pveforge/harness_vm.go", "newHarnessVMDestroyCmd", dtIdemVMDestroy, 1, "harness-unclassified", whyStopOp},
	{"cmd/pveforge/harness_vm.go", "newHarnessVMDestroyCmd", dtMethodDelete, 1, "harness-unclassified",
		whyHarness + "; ships in the production binary (no build tag) as `pveforge harness vm destroy`"},
	{"cmd/pveforge/harness_vm.go", "newHarnessVMDestroyCmd", dtNewHarnessDelCmd, 1, "funnel", "the declaration of the harness destroy command"},
	{"cmd/pveforge/harness_vm.go", "newHarnessVMCmd", dtNewHarnessDelCmd, 1, "funnel", "its one registration, under `pveforge harness vm`"},
	{"internal/harness/build/build.go", "Driver.cleanup", dtIdemVMDestroy, 1, "harness-unclassified", whyStopOp},
	{"internal/harness/build/build.go", "Driver.cleanup", dtMethodDelete, 1, "harness-unclassified", whyHarness},
	{"internal/harness/probe/probe.go", "Driver.destroyLeaf", dtIdemVMDestroy, 1, "harness-unclassified", whyStopOp},
	{"internal/harness/probe/probe.go", "Driver.destroyLeaf", dtMethodDelete, 1, "harness-unclassified", whyHarness},
	{"internal/harness/probe/probe.go", "Driver.cleanupTeardown", dtIdemVMDestroy, 1, "harness-unclassified", whyStopOp},
	{"internal/harness/probe/probe.go", "Driver.cleanupTeardown", dtMethodDelete, 1, "harness-unclassified", whyHarness},
	{"internal/pve/capture_harness_batchc.go", "Client.destroyAndConfirmGone", dtAnyDestroyVM, 1, "harness-capture",
		"//go:build harness capture instrument (not in the shipped binary) with its own gone oracle; a fifth harness site the spec's four do not count (D1)"},

	// DELETEs that are not a VM destroy.
	{"cmd/pveforge/api.go", "newAPICmd", dtMethodDelete, 1, "non-vm-delete",
		"registers `pveforge api delete`; its path is operator data at run time, which no source guard can see (D3)"},
	{"cmd/pveforge/api.go", "newAPICmd", dtNewAPICmd, 1, "funnel", "the declaration of the raw API command"},
	{"cmd/pveforge/main.go", "newRootCmd", dtNewAPICmd, 1, "funnel", "its one registration, under the root"},
	{"internal/pve/rawrequest.go", "Client.RawRequest", dtMethodDelete, 1, "non-vm-delete", "the method switch itself (query-string encoding)"},
	{"internal/pve/snapshot.go", "Client.CascadeDeleteSnapshots", dtMethodDelete, 1, "non-vm-delete", "DELETE …/qemu/<vmid>/snapshot/<name>"},
	{"internal/idempotent/networkbridge.go", "NetworkBridgeEnsure.stage", dtMethodDelete, 1, "non-vm-delete", "DELETE /nodes/<n>/network/<iface>"},
	{"internal/idempotent/networkbridge.go", "revertStagedAfter", dtMethodDelete, 1, "non-vm-delete", "DELETE /nodes/<n>/network (revert staged changes)"},
	{"internal/idempotent/storagevolume.go", "VolumeFreeOrphans.freeOne", dtMethodDelete, 1, "non-vm-delete", "DELETE of one storage volume"},
	{"internal/pvefake/rest.go", "BridgeREST.Server", dtMethodDelete, 2, "fake-server", "the fake server MATCHING a request method, not sending one"},
	{"internal/pvefake/rest.go", "FieldsREST.Server", dtMethodDelete, 1, "fake-server", "the fake server MATCHING a request method, not sending one"},
	{"internal/pvefake/vmrest.go", "VMREST.handler", dtMethodDelete, 1, "fake-server", "the fake server MATCHING a request method, not sending one"},
}

type destroyKey struct {
	file, fn string
	target   Target
}

func (k destroyKey) String() string {
	fn := k.fn
	if fn == "" {
		fn = "<package level>"
	}
	return fmt.Sprintf("(%s, %s, %s)", k.file, fn, k.target)
}

// destroyScope is the Scope the guard walks: the module root, the table's
// files path-exact, and never a directory.
func destroyScope() Scope {
	seen := map[string]bool{}
	var files []string
	for _, s := range destroySites {
		if !seen[s.file] {
			seen[s.file] = true
			files = append(files, s.file)
		}
	}
	sort.Strings(files)
	return Scope{Root: "../..", AllowFiles: files}
}

// destroyRefs returns every ref except a *.Delete whose qualifier this file
// imports as the standard library's "slices" (N1: slices.Delete is not a
// go-proxmox delete). dropped is returned so the probe can prove the filter
// is not vacuous.
func destroyRefs(t *testing.T, root string, res Result) (kept, dropped []Ref) {
	t.Helper()
	imports := map[string]map[string]string{}
	for file, refs := range res.Refs {
		for _, r := range refs {
			if r.Target == dtAnyDelete && r.Qualifier != "" {
				if imports[file] == nil {
					imports[file] = fileImportNames(t, filepath.Join(root, filepath.FromSlash(file)))
				}
				if imports[file][r.Qualifier] == "slices" && !funcShadows(t, filepath.Join(root, filepath.FromSlash(file)), r.Func, r.Qualifier) {
					dropped = append(dropped, r)
					continue
				}
			}
			kept = append(kept, r)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].String() < kept[j].String() })
	return kept, dropped
}

// funcShadows reports whether the FuncDecl(s) named fn (Ref.Func form) in
// path use name as a bare identifier anywhere other than as a selector's
// left side — a local, param, range variable or assignment that would shadow
// the import of that name (G20b). Syntactic and conservative: any such use,
// before or after the call, means the ref is NOT dropped, which errs toward
// RED. At package level (fn == "") a shadow cannot coexist with the import.
func funcShadows(t *testing.T, path, fn, name string) bool {
	t.Helper()
	if fn == "" {
		return false
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	shadow := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || funcDeclName(fd) != fn {
			continue
		}
		selX := map[*ast.Ident]bool{}
		ast.Inspect(fd, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := se.X.(*ast.Ident); ok {
					selX[id] = true
				}
				selX[se.Sel] = true
			}
			return true
		})
		ast.Inspect(fd, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name && !selX[id] {
				shadow = true
			}
			return true
		})
	}
	return shadow
}

func funcDeclName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		return recvTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// fileImportNames maps each import's local name to its path. An unaliased
// path's name is its last segment, which is exact for the one path the
// callers ask about ("slices", idempotent).
func fileImportNames(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse imports of %s: %v", path, err)
	}
	out := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		out[name] = p
	}
	return out
}

const destroyAdvice = "The ONE production destroy is cmd/pveforge/vm_destroy.go runVMDestroy (`pveforge vm destroy`: in-flight determination before, gone-proof after). " +
	"Do not add a second way to send DELETE /nodes/<n>/qemu/<vmid>: call the verb. A genuinely new DELETE site (a pool, a user, a stdlib sync.Map.Delete) " +
	"needs its own review and an exact (file, func, target, count) row in destroySites with a reason — never an AllowDir, never a floor count."

// TestVMDestroyCallSites_OnlyTheVerbAndTheListedResiduals is U7.
func TestVMDestroyCallSites_OnlyTheVerbAndTheListedResiduals(t *testing.T) {
	scope := destroyScope()
	res, err := NonTestReferences(scope, destroyTargets())
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	refs, _ := destroyRefs(t, scope.Root, res)

	// (i) a ref in a file no row names.
	got := map[destroyKey][]Ref{}
	for _, r := range refs {
		if !r.Allowed {
			t.Errorf("a new destroy-shaped reference, in a file no row allows: %s in %s", r, funcLabel(r.Func))
			continue
		}
		k := destroyKey{r.File, r.Func, r.Target}
		got[k] = append(got[k], r)
	}

	// (ii) exact (file, func, target) counts: an extra key is a new function
	// in an allowed file (a wrapper), a different count a second call.
	want := map[destroyKey]destroySite{}
	for _, s := range destroySites {
		want[destroyKey{s.file, s.fn, s.target}] = s
	}
	var keys []destroyKey
	for k := range got {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	for _, k := range keys {
		s, ok := want[k]
		switch {
		case !ok:
			t.Errorf("a new destroy-shaped reference %s in an allowed file, but no row for that function: %v", k, got[k])
		case len(got[k]) != s.count:
			t.Errorf("%s: %d references, the reviewed row says exactly %d (%s): %v", k, len(got[k]), s.count, s.class, got[k])
		}
	}
	for _, s := range destroySites {
		k := destroyKey{s.file, s.fn, s.target}
		if len(got[k]) == 0 {
			t.Errorf("stale row: the guard no longer sees %s (%s: %s) — the site moved, was renamed or was removed; if the verb's own call is gone, `pveforge vm destroy` no longer destroys", k, s.class, s.why)
		}
	}

	// (iii) B1: each allowed construction stays inside its function, used
	// only for Read and StatusGatedStop.
	for _, s := range destroySites {
		if s.target != dtIdemVMDestroy {
			continue
		}
		n, problems := vmDestroyEscapesIn(t, filepath.Join(scope.Root, filepath.FromSlash(s.file)), s.fn)
		for _, p := range problems {
			t.Errorf("%s %s: %s", s.file, s.fn, p)
		}
		if n != s.count {
			t.Errorf("%s %s: the escape check saw %d VMDestroy constructions, the row says %d — the check is not looking at the site the row allows", s.file, s.fn, n, s.count)
		}
	}

	// (iii-a) Grok FO-1: in each allowed destroying function, every DELETE
	// token is the method argument of its request call, every DestroyVM is a
	// call, and the request-shaped calls are exactly as many as pinned.
	for _, p := range destroyShapeProblems(t, scope.Root) {
		t.Error(p)
	}

	// (iii-b) FO-1: VMDestroy's own methods never reach Apply.
	recvChecked, recvProblems := vmDestroyReceiverEscapesIn(t, filepath.Join(scope.Root, "internal", "idempotent", "vmdestroy.go"))
	for _, p := range recvProblems {
		t.Errorf("internal/idempotent/vmdestroy.go: %s", p)
	}
	if recvChecked != 4 {
		t.Errorf("the receiver check saw %d non-Apply VMDestroy methods, want 4 (fetchVMConfig, Read, Satisfied, StatusGatedStop) — a new method needs a row and a look", recvChecked)
	}

	// (iv) coverage: the walk is the module, from its root, tags and all,
	// and not this package's own probe.
	if len(res.Parsed) < 150 {
		t.Errorf("parsed only %d non-test files from the module root; the module has 167 — wrong Root?", len(res.Parsed))
	}
	for _, far := range []string{
		"cmd/pveforge/vm_destroy.go",
		"internal/pve/vmdestroy.go",
		"internal/pve/capture_harness_batchc.go", // a //go:build harness file
		"internal/harness/probe/probe.go",
		"internal/harness/build/build.go",
	} {
		if !res.Reached(far) {
			t.Errorf("the walk did not parse %s", far)
		}
	}
	if res.Reached("internal/sourceguard/testdata/destroyprobe/second_caller.go") {
		t.Error("the walk parsed the probe fixture, which is testdata and must be skipped")
	}

	if t.Failed() {
		t.Log(destroyAdvice)
	}
}

func funcLabel(fn string) string {
	if fn == "" {
		return "<package level>"
	}
	return fn
}

// TestVMDestroyCallSites_TableIsPathExactAndFuncExact keeps the table from
// being widened into something that passes by matching everything.
func TestVMDestroyCallSites_TableIsPathExactAndFuncExact(t *testing.T) {
	if s := destroyScope(); len(s.AllowDirs) != 0 || s.Root != "../.." {
		t.Fatalf("the guard's Scope must be the module root with no AllowDirs, got %+v", s)
	}
	seen := map[destroyKey]bool{}
	for _, s := range destroySites {
		k := destroyKey{s.file, s.fn, s.target}
		if s.file == "" || strings.HasSuffix(s.file, "/") || !strings.HasSuffix(s.file, ".go") {
			t.Errorf("row %s: the file must be one exact .go path", k)
		}
		if s.count < 1 {
			t.Errorf("row %s: count %d; a row is an exact count ≥ 1, never 'any'", k, s.count)
		}
		if !destroyClasses[s.class] || s.why == "" {
			t.Errorf("row %s: class %q / why %q — a row needs a known class and a reason", k, s.class, s.why)
		}
		if seen[k] {
			t.Errorf("row %s appears twice", k)
		}
		seen[k] = true
	}
	verb := destroyKey{"cmd/pveforge/vm_destroy.go", "runVMDestroy", dtAnyDestroyVM}
	var found bool
	for _, s := range destroySites {
		if (destroyKey{s.file, s.fn, s.target}) == verb {
			found = s.count == 1 && s.class == "verb"
		}
	}
	if !found {
		t.Errorf("the verb's row %s ×1 class verb is missing or changed; deleting it is not a way to make this guard pass", verb)
	}
	var verbs int
	for _, s := range destroySites {
		if s.target == dtAnyDestroyVM && s.class == "verb" {
			verbs++
		}
	}
	if verbs != 1 {
		t.Errorf("%d DestroyVM rows are class verb; there is exactly one production destroy", verbs)
	}
}

const destroyProbeRoot = "testdata/destroyprobe"

// TestVMDestroyCallSites_EveryTargetMatchesTheProbe is the positive control:
// every target, and every idiom file, yields a violation when walked with no
// allow-list, so a target or an idiom that matches nothing cannot hide behind
// a green real-tree run.
func TestVMDestroyCallSites_EveryTargetMatchesTheProbe(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: destroyProbeRoot}, destroyTargets())
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	refs, dropped := destroyRefs(t, destroyProbeRoot, res)
	byTarget := map[Target]int{}
	byFile := map[string]int{}
	for _, r := range refs {
		if r.Allowed {
			t.Errorf("probe ref marked Allowed with no allow-list: %s", r)
		}
		byTarget[r.Target]++
		byFile[r.File]++
	}
	for _, tg := range destroyTargets() {
		if byTarget[tg] == 0 {
			t.Errorf("target %s matched nothing in the probe: it would match nothing in a real paste either", tg)
		}
	}
	for _, f := range res.Parsed {
		if f == "stdlib_delete.go" {
			continue
		}
		if byFile[f] == 0 {
			t.Errorf("probe idiom %s yields no violation", f)
		}
	}
	for _, f := range []string{"second_caller.go", "method_value.go", "iface.go", "apply_op.go", "raw_literal.go",
		"harness_paste.go", "goproxmox.go", "reflect.go", "wrapper.go", "funnels.go", "op_escape.go", "in_package.go", "receiver_escape.go", "shape_escape.go", "slices_shadow.go", "stdlib_delete.go"} {
		if !res.Reached(f) {
			t.Errorf("probe file %s was not parsed", f)
		}
	}
	// N1's control: the stdlib slices.Delete (aliased or not) is dropped,
	// and the drop is not vacuous.
	if byFile["stdlib_delete.go"] != 0 {
		t.Errorf("a stdlib slices.Delete is reported as a destroy: %d refs in stdlib_delete.go", byFile["stdlib_delete.go"])
	}
	if len(dropped) != 2 {
		t.Errorf("want the 2 slices.Delete refs in stdlib_delete.go dropped, dropped %v", dropped)
	}
}

// TestVMDestroyCallSites_EveryTargetHasAnAntiVacuitySource: each target is
// witnessed by a row in the real tree, or declared fixture-only — exactly one.
func TestVMDestroyCallSites_EveryTargetHasAnAntiVacuitySource(t *testing.T) {
	rows := map[Target]int{}
	for _, s := range destroySites {
		rows[s.target]++
	}
	for _, tg := range destroyTargets() {
		switch {
		case rows[tg] > 0 && destroyFixtureOnly[tg]:
			t.Errorf("target %s has a table row AND is declared fixture-only; drop it from destroyFixtureOnly", tg)
		case rows[tg] == 0 && !destroyFixtureOnly[tg]:
			t.Errorf("target %s has no table row and is not declared fixture-only", tg)
		}
	}
	isTarget := map[Target]bool{}
	for _, tg := range destroyTargets() {
		isTarget[tg] = true
	}
	for tg := range destroyFixtureOnly {
		if !isTarget[tg] {
			t.Errorf("fixture-only %s is not a target", tg)
		}
	}
}

// TestVMDestroyCallSites_DotImportIsRefused: a dot-import strips the
// qualifier off both alias-proof targets, so the walker must refuse it.
func TestVMDestroyCallSites_DotImportIsRefused(t *testing.T) {
	for path, src := range map[string]string{
		idempotentPath: "package main\n\nimport . \"" + idempotentPath + "\"\n\nvar _ = &VMDestroy{}\n",
		"net/http":     "package main\n\nimport . \"net/http\"\n\nvar _ = MethodDelete\n",
	} {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "main.go"), src, 0o600)
		_, err := NonTestReferences(Scope{Root: dir}, destroyTargets())
		if err == nil || !strings.Contains(err.Error(), "dot-imports") || !strings.Contains(err.Error(), path) {
			t.Errorf("a dot-import of %s: want the walker's dot-imports refusal naming it, got %v", path, err)
		}
	}
}

// TestVMDestroyCallSites_EscapeCheckSeesEveryEscape is B1's positive control:
// op_escape.go's okUse is clean, and every other function there is an escape
// that must be caught.
func TestVMDestroyCallSites_EscapeCheckSeesEveryEscape(t *testing.T) {
	path := filepath.Join(destroyProbeRoot, "op_escape.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var fns int
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name == "applyOp" {
			continue
		}
		fns++
		_, problems := vmDestroyEscapesIn(t, path, fd.Name.Name)
		if fd.Name.Name == "okUse" {
			if len(problems) != 0 {
				t.Errorf("okUse (Read + StatusGatedStop only) was flagged: %v", problems)
			}
			continue
		}
		if len(problems) == 0 {
			t.Errorf("%s lets a VMDestroy escape and was not flagged", fd.Name.Name)
		}
	}
	if fns != 10 {
		t.Fatalf("checked %d probe functions; the fixture has 10", fns)
	}
}

// vmDestroyEscapesIn parses path and runs vmDestroyEscapes on the FuncDecl
// whose Ref.Func-form name is fn. It fails the test if fn is not there.
func vmDestroyEscapesIn(t *testing.T, path, fn string) (int, []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	quals := map[string]bool{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if p != idempotentPath {
			continue
		}
		name := "idempotent"
		if im.Name != nil {
			name = im.Name.Name
		}
		quals[name] = true
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = recvTypeName(fd.Recv.List[0].Type) + "." + name
		}
		if name == fn {
			return vmDestroyEscapes(fset, fd, quals)
		}
	}
	t.Fatalf("%s has no function %s", path, fn)
	return 0, nil
}

// vmDestroyAllowedUses are the only methods an allowed VMDestroy may be
// called with. Apply, Satisfied and the value itself are not among them.
var vmDestroyAllowedUses = map[string]bool{"Read": true, "StatusGatedStop": true}

// vmDestroyEscapes is B1's check, syntactic and per FuncDecl: every
// idempotent.VMDestroy (qualifier in quals) in fd must be the type of a
// composite literal in `<ident> := &idempotent.VMDestroy{...}`, and every
// other appearance of <ident> in fd must be `<ident>.Read(...)` or
// `<ident>.StatusGatedStop(...)`. It returns the number of constructions
// found and one problem per violation. No object resolution: an identifier
// that merely shares the name is treated as the construction, so shadowing
// errs toward RED.
func vmDestroyEscapes(fset *token.FileSet, fd *ast.FuncDecl, quals map[string]bool) (int, []string) {
	parent := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(fd, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parent[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	at := func(n ast.Node) string { return fset.Position(n.Pos()).String() }

	var problems []string
	defs := map[*ast.Ident]bool{}
	names := map[string]bool{}
	constructions := 0
	ast.Inspect(fd, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "VMDestroy" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || !quals[x.Name] {
			return true
		}
		constructions++
		cl, ok := parent[sel].(*ast.CompositeLit)
		if !ok || cl.Type != sel {
			problems = append(problems, at(sel)+": idempotent.VMDestroy outside `<ident> := &idempotent.VMDestroy{...}` (a new(), a var or field or param type, a value)")
			return true
		}
		ue, ok := parent[cl].(*ast.UnaryExpr)
		if !ok || ue.Op != token.AND {
			problems = append(problems, at(sel)+": an idempotent.VMDestroy composite literal not taken as &idempotent.VMDestroy{...}")
			return true
		}
		as, ok := parent[ue].(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 || as.Rhs[0] != ue {
			problems = append(problems, at(sel)+": &idempotent.VMDestroy{...} not bound by `<ident> := ...` (passed, returned, stored, or a multi-assign)")
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name == "_" {
			problems = append(problems, at(sel)+": &idempotent.VMDestroy{...} not bound to a named local")
			return true
		}
		defs[id] = true
		names[id.Name] = true
		return true
	})

	ast.Inspect(fd, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || !names[id.Name] || defs[id] {
			return true
		}
		if se, ok := parent[id].(*ast.SelectorExpr); ok && se.Sel == id {
			return true // a field or method named like the local, x.op: not a use of it
		}
		se, ok := parent[id].(*ast.SelectorExpr)
		if ok && se.X == id && vmDestroyAllowedUses[se.Sel.Name] {
			if call, ok := parent[se].(*ast.CallExpr); ok && call.Fun == se {
				return true
			}
		}
		what := "used other than as ." + "Read(...)/.StatusGatedStop(...)"
		if ok && se.X == id {
			what = "." + se.Sel.Name + " — only Read and StatusGatedStop may be called on it"
		}
		problems = append(problems, fmt.Sprintf("%s: the VMDestroy %q escapes: %s; a *VMDestroy is an idempotent.Op, and anything that takes one can Apply it (destroy with no determination and no gone-proof)", at(id), id.Name, what))
		return true
	})
	return constructions, problems
}

// TestVMDestroyCallSites_ATopLevelBuildPackageIsWalked is B-1 of the code
// review: a package under the top-level .build is importable (cmd/pveforge
// can import ".../.build/evil"), so the walk must see a destroy planted
// there. Mutant: put the old `rel == ".build"` skip back, and this fails.
func TestVMDestroyCallSites_ATopLevelBuildPackageIsWalked(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/m\n", 0o600)
	writeFile(t, filepath.Join(root, "a.go"), "package m\n", 0o600)
	if err := os.MkdirAll(filepath.Join(root, ".build", "evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".build", "evil", "e.go"),
		"package evil\n\nfunc Nuke(ctx context.Context, c *pve.RoutedClient) { _, _ = c.DestroyVM(ctx, 1, true) }\n", 0o600)
	res, err := NonTestReferences(Scope{Root: root}, destroyTargets())
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	var hit bool
	for _, v := range res.Violations() {
		if v.File == ".build/evil/e.go" && v.Target == dtAnyDestroyVM {
			hit = true
		}
	}
	if !hit {
		t.Errorf("a DestroyVM caller under the top-level .build was not reported; Parsed = %v", res.Parsed)
	}
}

// TestVMDestroyCallSites_ReceiverCheckSeesEveryEscape is FO-1's positive
// control: receiver_escape.go's Read is clean, and every other non-Apply
// method there reaches Apply (or Run) through its receiver.
func TestVMDestroyCallSites_ReceiverCheckSeesEveryEscape(t *testing.T) {
	path := filepath.Join(destroyProbeRoot, "receiver_escape.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !isVMDestroyMethod(fd) || fd.Name.Name == "Apply" {
			continue
		}
		checked++
		problems := vmDestroyReceiverEscapes(fset, fd)
		if fd.Name.Name == "Read" {
			if len(problems) != 0 {
				t.Errorf("the clean Read was flagged: %v", problems)
			}
			continue
		}
		if len(problems) == 0 {
			t.Errorf("%s reaches Apply through its receiver and was not flagged", fd.Name.Name)
		}
	}
	if checked != 7 {
		t.Fatalf("checked %d probe methods; the fixture has 7", checked)
	}
}

func isVMDestroyMethod(fd *ast.FuncDecl) bool {
	return fd.Recv != nil && len(fd.Recv.List) == 1 && recvTypeName(fd.Recv.List[0].Type) == "VMDestroy"
}

// vmDestroyReceiverEscapesIn runs vmDestroyReceiverEscapes over every
// VMDestroy method in path except Apply, returning how many it checked.
func vmDestroyReceiverEscapesIn(t *testing.T, path string) (int, []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var n int
	var problems []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || !isVMDestroyMethod(fd) || fd.Name.Name == "Apply" {
			continue
		}
		n++
		for _, p := range vmDestroyReceiverEscapes(fset, fd) {
			problems = append(problems, "VMDestroy."+fd.Name.Name+": "+p)
		}
	}
	return n, problems
}

// vmDestroyReceiverEscapes is FO-1's check on one VMDestroy method (never
// Apply): the receiver may appear only as `<recv>.<member>` with member !=
// "Apply", and no call to Run, bare or qualified, may appear at all.
// Syntactic, no object resolution: a local shadowing the receiver's name errs
// toward RED.
func vmDestroyReceiverEscapes(fset *token.FileSet, fd *ast.FuncDecl) []string {
	at := func(n ast.Node) string { return fset.Position(n.Pos()).String() }
	var problems []string
	recv := ""
	var recvDecl *ast.Ident
	if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
		recv, recvDecl = names[0].Name, names[0]
	}
	parent := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(fd, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parent[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	ast.Inspect(fd, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			name := ""
			switch fn := x.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if name == "Run" {
				problems = append(problems, at(x)+": calls Run: a VMDestroy method must never run an Op (the only Op in reach is itself)")
			}
		case *ast.Ident:
			if recv == "" || x.Name != recv || x == recvDecl {
				return true
			}
			se, ok := parent[x].(*ast.SelectorExpr)
			if ok && se.Sel == x {
				return true // a member named like the receiver, y.op
			}
			switch {
			case ok && se.X == x && se.Sel.Name != "Apply":
				return true
			case ok && se.X == x:
				problems = append(problems, at(x)+": "+recv+".Apply: only Apply itself destroys; Read and StatusGatedStop are what the verb and the harness call")
			default:
				problems = append(problems, at(x)+": the receiver "+recv+" is used as a value (passed, returned, assigned): a *VMDestroy is an idempotent.Op and can be Applied")
			}
		}
		return true
	})
	return problems
}

// destroyTokenShapes is where each allowed net/http.MethodDelete must sit in
// its function (Grok FO-1): a token that is not the method argument of its
// request call — `_ = http.MethodDelete` kept beside a byte-built method
// (G28) — keeps the count at 1 while the request it was pinning is gone.
//
//	request-arg  the method argument of a requestCalls call
//	api-verb     newAPIVerbCmd's first (method) argument
//	case-clause  a value of a switch case (RawRequest's method switch)
//	compare      one side of `r.Method == http.MethodDelete` (a fake server)
var destroyTokenShapes = map[destroyKey]string{
	{"internal/pve/vmdestroy.go", "Client.DestroyVM", dtMethodDelete}:                     "request-arg",
	{"cmd/pveforge/harness_vm.go", "newHarnessVMDestroyCmd", dtMethodDelete}:              "request-arg",
	{"internal/harness/build/build.go", "Driver.cleanup", dtMethodDelete}:                 "request-arg",
	{"internal/harness/probe/probe.go", "Driver.destroyLeaf", dtMethodDelete}:             "request-arg",
	{"internal/harness/probe/probe.go", "Driver.cleanupTeardown", dtMethodDelete}:         "request-arg",
	{"internal/pve/snapshot.go", "Client.CascadeDeleteSnapshots", dtMethodDelete}:         "request-arg",
	{"internal/idempotent/networkbridge.go", "NetworkBridgeEnsure.stage", dtMethodDelete}: "request-arg",
	{"internal/idempotent/networkbridge.go", "revertStagedAfter", dtMethodDelete}:         "request-arg",
	{"internal/idempotent/storagevolume.go", "VolumeFreeOrphans.freeOne", dtMethodDelete}: "request-arg",
	{"cmd/pveforge/api.go", "newAPICmd", dtMethodDelete}:                                  "api-verb",
	{"internal/pve/rawrequest.go", "Client.RawRequest", dtMethodDelete}:                   "case-clause",
	{"internal/pvefake/rest.go", "BridgeREST.Server", dtMethodDelete}:                     "compare",
	{"internal/pvefake/rest.go", "FieldsREST.Server", dtMethodDelete}:                     "compare",
	{"internal/pvefake/vmrest.go", "VMREST.handler", dtMethodDelete}:                      "compare",
}

// requestCalls names the calls that send a request with a method argument,
// and where that argument sits. rawUPID is both cmd/pveforge's free function
// (client first, method third) and the probe driver's method (method second).
var requestCalls = map[string]struct{ asIdent, asSelector int }{
	"RawRequest":            {-1, 1},
	"rawUPID":               {2, 1},
	"RawUPID":               {-1, 2},
	"NewRequestWithContext": {-1, 1},
	"NewRequest":            {-1, 0},
	"Req":                   {-1, 1},
}

// destroyFuncRequests pins, for every function holding an allowed DestroyVM
// or MethodDelete row, the exact number of requestCalls calls in it. A second
// request with a byte-built method beside the real one (G22 in
// Client.DestroyVM, G12 in runVMDestroy) changes it.
var destroyFuncRequests = map[[2]string]int{
	{"cmd/pveforge/vm_destroy.go", "runVMDestroy"}:                             0,
	{"internal/pve/vmdestroy.go", "Client.DestroyVM"}:                          1,
	{"internal/pve/routed.go", "RoutedClient.DestroyVM"}:                       0,
	{"internal/idempotent/vmdestroy.go", "VMDestroy.Apply"}:                    0,
	{"cmd/pveforge/harness_vm.go", "newHarnessVMDestroyCmd"}:                   1,
	{"internal/harness/build/build.go", "Driver.cleanup"}:                      1,
	{"internal/harness/probe/probe.go", "Driver.destroyLeaf"}:                  1,
	{"internal/harness/probe/probe.go", "Driver.cleanupTeardown"}:              1,
	{"internal/pve/capture_harness_batchc.go", "Client.destroyAndConfirmGone"}: 0,
	{"cmd/pveforge/api.go", "newAPICmd"}:                                       0,
	{"internal/pve/rawrequest.go", "Client.RawRequest"}:                        1,
	{"internal/pve/snapshot.go", "Client.CascadeDeleteSnapshots"}:              1,
	{"internal/idempotent/networkbridge.go", "NetworkBridgeEnsure.stage"}:      3,
	{"internal/idempotent/networkbridge.go", "revertStagedAfter"}:              1,
	{"internal/idempotent/storagevolume.go", "VolumeFreeOrphans.freeOne"}:      1,
	{"internal/pvefake/rest.go", "BridgeREST.Server"}:                          0,
	{"internal/pvefake/rest.go", "FieldsREST.Server"}:                          0,
	{"internal/pvefake/vmrest.go", "VMREST.handler"}:                           0,
}

// destroyShapeProblems runs Grok FO-1's syntactic check over every allowed
// T1 and T5 row, and proves the two maps above cover exactly those rows.
func destroyShapeProblems(t *testing.T, root string) []string {
	t.Helper()
	var problems []string
	funcs := map[[2]string]bool{}
	for _, s := range destroySites {
		if s.target != dtMethodDelete && s.target != dtAnyDestroyVM {
			continue
		}
		funcs[[2]string{s.file, s.fn}] = true
		if s.target == dtMethodDelete {
			if _, ok := destroyTokenShapes[destroyKey{s.file, s.fn, s.target}]; !ok {
				problems = append(problems, fmt.Sprintf("row %s has no destroyTokenShapes entry", destroyKey{s.file, s.fn, s.target}))
			}
		}
	}
	for k := range destroyTokenShapes {
		if !funcs[[2]string{k.file, k.fn}] {
			problems = append(problems, fmt.Sprintf("destroyTokenShapes %s has no row", k))
		}
	}
	for k := range destroyFuncRequests {
		if !funcs[k] {
			problems = append(problems, fmt.Sprintf("destroyFuncRequests %v has no row", k))
		}
	}
	keys := make([][2]string, 0, len(funcs))
	for k := range funcs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		want, ok := destroyFuncRequests[k]
		if !ok {
			problems = append(problems, fmt.Sprintf("(%s, %s) holds a destroy row but has no destroyFuncRequests entry", k[0], k[1]))
			continue
		}
		shape := destroyTokenShapes[destroyKey{k[0], k[1], dtMethodDelete}]
		problems = append(problems, funcShapeProblems(t, filepath.Join(root, filepath.FromSlash(k[0])), k[0], k[1], shape, want)...)
	}
	return problems
}

// funcShapeProblems checks one function: its DELETE tokens sit in shape, its
// DestroyVM selectors are calls, and it holds exactly wantRequests
// requestCalls calls.
func funcShapeProblems(t *testing.T, path, file, fn, shape string, wantRequests int) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	httpName := map[string]bool{}
	for _, im := range f.Imports {
		if p, _ := strconv.Unquote(im.Path.Value); p == "net/http" {
			n := "http"
			if im.Name != nil {
				n = im.Name.Name
			}
			httpName[n] = true
		}
	}
	at := func(n ast.Node) string { return fmt.Sprintf("%s:%d (%s)", file, fset.Position(n.Pos()).Line, fn) }
	var problems []string
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || funcDeclName(fd) != fn {
			continue
		}
		found = true
		parent := map[ast.Node]ast.Node{}
		var stack []ast.Node
		ast.Inspect(fd, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				parent[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			return true
		})
		requests := 0
		ast.Inspect(fd, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if _, _, ok := requestCallIndex(x); ok {
					requests++
				}
			case *ast.SelectorExpr:
				switch x.Sel.Name {
				case "DestroyVM":
					if call, ok := parent[x].(*ast.CallExpr); !ok || call.Fun != x {
						problems = append(problems, at(x)+": DestroyVM is not called here (a method value, a discarded or unrelated reference): an allowed DestroyVM row must be a call")
					}
				case "MethodDelete":
					if id, ok := x.X.(*ast.Ident); ok && httpName[id.Name] {
						if p := deleteTokenProblem(parent, x, shape); p != "" {
							problems = append(problems, at(x)+": "+p)
						}
					}
				}
			}
			return true
		})
		if requests != wantRequests {
			problems = append(problems, fmt.Sprintf("%s:%s: %d request-shaped calls (%s), destroyFuncRequests pins %d — a request beside the pinned one, possibly with a byte-built method, in a function allowed to destroy", file, fn, requests, "RawRequest/rawUPID/RawUPID/NewRequest[WithContext]/Req", wantRequests))
		}
	}
	if !found {
		problems = append(problems, fmt.Sprintf("%s has no function %s", file, fn))
	}
	return problems
}

// requestCallIndex reports whether call is a requestCalls call and, if so,
// the index of its method argument.
func requestCallIndex(call *ast.CallExpr) (string, int, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if rc, ok := requestCalls[fn.Name]; ok && rc.asIdent >= 0 {
			return fn.Name, rc.asIdent, true
		}
	case *ast.SelectorExpr:
		if rc, ok := requestCalls[fn.Sel.Name]; ok && rc.asSelector >= 0 {
			return fn.Sel.Name, rc.asSelector, true
		}
	}
	return "", 0, false
}

// deleteTokenProblem says what is wrong with where tok sits, or "".
func deleteTokenProblem(parent map[ast.Node]ast.Node, tok *ast.SelectorExpr, shape string) string {
	switch shape {
	case "request-arg":
		call, ok := parent[tok].(*ast.CallExpr)
		if ok {
			if _, idx, isReq := requestCallIndex(call); isReq && idx < len(call.Args) && call.Args[idx] == tok {
				return ""
			}
		}
		return "http.MethodDelete is not the method argument of a request call (RawRequest/rawUPID/RawUPID/NewRequest[WithContext]/Req) — a discarded or unrelated token keeps the count while the real request may carry a byte-built method"
	case "api-verb":
		if call, ok := parent[tok].(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "newAPIVerbCmd" && len(call.Args) > 0 && call.Args[0] == tok {
				return ""
			}
		}
		return "http.MethodDelete is not newAPIVerbCmd's method argument"
	case "case-clause":
		if _, ok := parent[tok].(*ast.CaseClause); ok {
			return ""
		}
		return "http.MethodDelete is not a value of the method switch"
	case "compare":
		if be, ok := parent[tok].(*ast.BinaryExpr); ok && be.Op == token.EQL {
			other := be.X
			if other == tok {
				other = be.Y
			}
			if se, ok := other.(*ast.SelectorExpr); ok && se.Sel.Name == "Method" {
				return ""
			}
		}
		return "http.MethodDelete is not compared with a request's Method"
	}
	return "no shape is pinned for this DELETE token"
}

// TestVMDestroyCallSites_ShapeCheckSeesTheByteBuiltMethod is Grok FO-1's
// positive control over testdata/destroyprobe/shape_escape.go.
func TestVMDestroyCallSites_ShapeCheckSeesTheByteBuiltMethod(t *testing.T) {
	path := filepath.Join(destroyProbeRoot, "shape_escape.go")
	cases := []struct {
		fn       string
		shape    string
		requests int
		bad      bool
	}{
		{"okDestroy", "request-arg", 1, false},
		{"g28Discarded", "request-arg", 1, true},
		{"g22Second", "request-arg", 1, true},
		{"methodValue", "", 0, true},
		{"okVerb", "", 0, false},
		{"g12VerbRequest", "", 0, true},
	}
	for _, c := range cases {
		p := funcShapeProblems(t, path, "shape_escape.go", c.fn, c.shape, c.requests)
		if c.bad && len(p) == 0 {
			t.Errorf("%s: not flagged", c.fn)
		}
		if !c.bad && len(p) != 0 {
			t.Errorf("%s: clean shape flagged: %v", c.fn, p)
		}
	}
}

// TestVMDestroyCallSites_SlicesDropIsScopeChecked is Grok FO-2: a local
// named slices shadows the import, so its .Delete is NOT dropped.
func TestVMDestroyCallSites_SlicesDropIsScopeChecked(t *testing.T) {
	res, err := NonTestReferences(Scope{Root: destroyProbeRoot}, []Target{dtAnyDelete})
	if err != nil {
		t.Fatal(err)
	}
	kept, _ := destroyRefs(t, destroyProbeRoot, res)
	var shadowKept bool
	for _, r := range kept {
		if r.File == "stdlib_delete.go" {
			t.Errorf("a genuine slices.Delete was kept: %s", r)
		}
		if r.File == "slices_shadow.go" && r.Func == "shadowDelete" {
			shadowKept = true
		}
	}
	if !shadowKept {
		t.Error("slices := vm; slices.Delete(…) was dropped as a stdlib slices.Delete")
	}
}
