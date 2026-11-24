package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/types"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// The OUTPUT contract (contract plan §3.3 item 5, ruling C4/G7): what each verb
// renders is a GOLDEN table (outputs_table.go), never reflection at run time.
// This test derives the table from two independent sources and holds the golden
// to both:
//
//  1. SOURCE: every kvjson.Render call reachable from a command's constructor,
//     with the type-checked type of the rendered value (a map literal gives its
//     literal keys; a struct gives its json-tagged fields, omitempty = optional;
//     anything that is not this package's own type is PVE's object:
//     passthrough).
//  2. RENDERING: for every package-main struct a verb renders, the value is
//     built with EVERY field set (so omitempty keys appear), rendered through
//     the real kvjson.Render as JSON, and the key tree read back; the zero value
//     is rendered too, so a key is optional exactly when it vanishes.
//
// The two must agree for every named struct; the golden must equal the result.
// `make outputs` (-update-outputs) rewrites outputs_table.go.

var updateOutputs = flag.Bool("update-outputs", false, "regenerate cmd/pveforge/outputs_table.go from the command tree")

type renderSite struct {
	fn  string
	arg ast.Expr
}

// renderSitesByFunc maps each top-level function of the package to the
// kvjson.Render calls directly in its body.
func renderSitesByFunc(t *testing.T) (map[string][]renderSite, map[string][]string, *types.Info) {
	t.Helper()
	fset, files, info := checkedPackage(t)
	_ = fset
	sites := map[string][]renderSite{}
	calls := map[string][]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) > 0 {
				name = recvName(fd.Recv.List[0].Type) + "." + name
			}
			seen := map[string]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if fn, _ := calleeObj(info, x.Fun).(*types.Func); fn != nil {
						if fn.FullName() == "github.com/suykerbuyk/pveforge/internal/kvjson.Render" && len(x.Args) == 3 {
							sites[name] = append(sites[name], renderSite{fn: name, arg: x.Args[2]})
						}
					}
				case *ast.Ident:
					if fn, ok := info.Uses[x].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Name() == "main" {
						n := fn.Name()
						if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() != nil {
							n = recvTypeName(sig.Recv().Type()) + "." + n
						}
						if !seen[n] {
							seen[n] = true
							calls[name] = append(calls[name], n)
						}
					}
				}
				return true
			})
		}
	}
	return sites, calls, info
}

func recvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return "?"
}

func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return "?"
}

func calleeObj(info *types.Info, e ast.Expr) types.Object {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return info.Uses[x.Sel]
	case *ast.Ident:
		return info.Uses[x]
	}
	return nil
}

// constructorOf names the top-level function a command's RunE closure belongs to.
func constructorOf(cmd *cobra.Command) string {
	if cmd.RunE == nil {
		return ""
	}
	name := runtime.FuncForPC(reflect.ValueOf(cmd.RunE).Pointer()).Name()
	name = strings.TrimPrefix(strings.TrimPrefix(name, "github.com/suykerbuyk/pveforge/cmd/pveforge."), "main.")
	// closures are named <fn>.func1[.2...]; methods are (*T).M or T.M
	if i := strings.Index(name, ".func"); i >= 0 {
		name = name[:i]
	}
	name = strings.NewReplacer("(*", "", ")", "").Replace(name)
	return name
}

func reachableSites(start string, sites map[string][]renderSite, calls map[string][]string) []renderSite {
	seen := map[string]bool{start: true}
	queue := []string{start}
	var out []renderSite
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		out = append(out, sites[f]...)
		for _, c := range calls[f] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return out
}

// ---- type-derived keys ------------------------------------------------------

func jsonKindOf(t types.Type) string {
	for {
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
			continue
		}
		break
	}
	if n, ok := t.(*types.Named); ok {
		switch n.Obj().Pkg().Path() + "." + n.Obj().Name() {
		case "encoding/json.RawMessage":
			return "any"
		case "time.Time":
			return "string"
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch {
		case u.Info()&types.IsString != 0:
			return "string"
		case u.Info()&types.IsBoolean != 0:
			return "bool"
		case u.Info()&types.IsNumeric != 0:
			return "number"
		}
	case *types.Slice, *types.Array:
		return "array"
	case *types.Map, *types.Struct:
		return "object"
	case *types.Interface:
		return "any"
	}
	return "any"
}

func structKeysOf(st *types.Struct, depth int) []outputKey {
	var out []outputKey
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		tag := reflect.StructTag(st.Tag(i)).Get("json")
		if tag == "-" || (tag == "" && !f.Exported()) {
			continue
		}
		if f.Anonymous() && tag == "" {
			// an embedded struct is inlined by encoding/json
			if inner := nestedKeys(f.Type(), depth); len(inner) > 0 {
				out = append(out, inner...)
				continue
			}
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name()
		}
		k := outputKey{Name: name, Kind: jsonKindOf(f.Type()), Optional: strings.Contains(opts, "omitempty")}
		if depth < 4 {
			k.Keys = nestedKeys(f.Type(), depth+1)
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func nestedKeys(t types.Type, depth int) []outputKey {
	for {
		switch x := t.(type) {
		case *types.Pointer:
			t = x.Elem()
			continue
		case *types.Slice:
			t = x.Elem()
			continue
		}
		break
	}
	if n, ok := t.(*types.Named); ok {
		// nested structs may live in the module's own packages (a bootstrap
		// result embedded in a view); PVE's own objects (other modules) are
		// not described
		if p := n.Obj().Pkg(); p == nil || (p.Name() != "main" && !strings.HasPrefix(p.Path(), "github.com/suykerbuyk/pveforge")) {
			return nil
		}
	}
	if st, ok := t.Underlying().(*types.Struct); ok {
		return structKeysOf(st, depth)
	}
	return nil
}

// keysOfExpr classifies one render argument.
func keysOfExpr(info *types.Info, e ast.Expr) (keys []outputKey, passthrough bool, named string) {
	tv, ok := info.Types[e]
	if !ok {
		return nil, true, ""
	}
	t := tv.Type
	for {
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
			continue
		}
		break
	}
	if n, ok := t.(*types.Named); ok {
		if p := n.Obj().Pkg(); p == nil || p.Name() != "main" {
			return nil, true, ""
		}
		named = n.Obj().Name()
	}
	switch u := t.Underlying().(type) {
	case *types.Struct:
		return structKeysOf(u, 0), false, named
	case *types.Map:
		// a map literal: its constant string keys are what is rendered
		if cl, ok := e.(*ast.CompositeLit); ok {
			for _, el := range cl.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				ktv, ok := info.Types[kv.Key]
				if !ok || ktv.Value == nil {
					continue
				}
				name := strings.Trim(ktv.Value.ExactString(), `"`)
				vt := info.Types[kv.Value].Type
				k := outputKey{Name: name, Kind: jsonKindOf(vt)}
				if vt != nil {
					k.Keys = nestedKeys(vt, 1)
				}
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
			return keys, false, ""
		}
	}
	return nil, true, ""
}

// ---- rendering-derived keys -------------------------------------------------

// outputTypes are the package-main struct types a verb renders, for the
// every-field-set rendering.
var outputTypes = map[string]reflect.Type{
	"accessInventoryResult": reflect.TypeOf(accessInventoryResult{}),
	"accessKeysResult":      reflect.TypeOf(accessKeysResult{}),
	"bootstrapView":         reflect.TypeOf(bootstrapView{}),
	"destroyReport":         reflect.TypeOf(destroyReport{}),
	"doctorReport":          reflect.TypeOf(doctorReport{}),
	"enableReport":          reflect.TypeOf(enableReport{}),
	"harnessRollbackResult": reflect.TypeOf(harnessRollbackResult{}),
	"pinTLSView":            reflect.TypeOf(pinTLSView{}),
	"snapshotResult":        reflect.TypeOf(snapshotResult{}),
	"versionReport":         reflect.TypeOf(versionReport{}),
	"schemaDiffReport":      reflect.TypeOf(schemaDiffReport{}),
}

func fillAll(v reflect.Value, depth int) {
	if depth > 6 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillAll(v.Elem(), depth+1)
	case reflect.Slice:
		if v.Type() == reflect.TypeOf(json.RawMessage(nil)) {
			v.Set(reflect.ValueOf(json.RawMessage(`"x"`)))
			return
		}
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillAll(v.Index(0), depth+1)
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		k := reflect.New(v.Type().Key()).Elem()
		fillAll(k, depth+1)
		e := reflect.New(v.Type().Elem()).Elem()
		fillAll(e, depth+1)
		v.SetMapIndex(k, e)
	case reflect.Interface:
		v.Set(reflect.ValueOf("x"))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fillAll(v.Field(i), depth+1)
			}
		}
	}
}

func renderKeyTree(t *testing.T, v any) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := kvjson.Render(&b, kvjson.JSON, v); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("rendered value is not an object: %v\n%s", err, b.String())
	}
	return m
}

func treeKeys(full, zero map[string]any) []outputKey {
	var out []outputKey
	for name, fv := range full {
		k := outputKey{Name: name, Kind: kindOfJSON(fv)}
		_, inZero := zero[name]
		k.Optional = !inZero
		var fobj, zobj map[string]any
		switch x := fv.(type) {
		case map[string]any:
			fobj = x
		case []any:
			if len(x) > 0 {
				if m, ok := x[0].(map[string]any); ok {
					fobj = m
				}
			}
		}
		if z, ok := zero[name]; ok {
			switch x := z.(type) {
			case map[string]any:
				zobj = x
			case []any:
				if len(x) > 0 {
					zobj, _ = x[0].(map[string]any)
				}
			}
		}
		if fobj != nil {
			k.Keys = treeKeys(fobj, zobj)
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func kindOfJSON(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "any"
}

// renderedKeys renders the named struct filled and zero and reads the key tree.
func renderedKeys(t *testing.T, rt reflect.Type) []outputKey {
	t.Helper()
	filled := reflect.New(rt).Elem()
	fillAll(filled, 0)
	full := renderKeyTree(t, filled.Interface())
	zero := renderKeyTree(t, reflect.New(rt).Elem().Interface())
	return treeKeys(full, zero)
}

// shape compares the top-level key NAMES of the two derivations (optionality comes from rendering, which sees custom marshalers)
// stripKinds compares key NAMES and optionality (an `any` field's rendered kind
// is whatever the filler chose).
func shape(keys []outputKey) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k.Name)
		b.WriteString(";")
	}
	return b.String()
}

// withNestedFrom keeps the rendered key tree (the truth: it sees custom marshalers
// and omitted fields) and takes the OPTIONAL marks of nested keys from the
// type-derived tree where the same name exists there: a zero value renders no
// nested element at all, so nested optionality cannot be read from rendering.
// The top level keeps its rendered optionality.
func withNestedFrom(rendered, typed []outputKey) []outputKey {
	byName := map[string]outputKey{}
	for _, k := range typed {
		byName[k.Name] = k
	}
	out := make([]outputKey, len(rendered))
	for i, k := range rendered {
		if len(k.Keys) > 0 {
			var tkeys []outputKey
			if tk, ok := byName[k.Name]; ok {
				tkeys = tk.Keys
			}
			k.Keys = nestedOptional(k.Keys, tkeys)
		}
		out[i] = k
	}
	return out
}

func nestedOptional(rendered, typed []outputKey) []outputKey {
	byName := map[string]outputKey{}
	for _, k := range typed {
		byName[k.Name] = k
	}
	out := make([]outputKey, len(rendered))
	for i, k := range rendered {
		tk, ok := byName[k.Name]
		k.Optional = ok && tk.Optional
		if len(k.Keys) > 0 {
			k.Keys = nestedOptional(k.Keys, tk.Keys)
		}
		out[i] = k
	}
	return out
}

// derivedOutputs computes the table from source and rendering.
func derivedOutputs(t *testing.T) map[string]outputSchema {
	t.Helper()
	sites, calls, info := renderSitesByFunc(t)
	root := newRootCmd()
	out := map[string]outputSchema{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, ch := range c.Commands() {
			if ch.HasSubCommands() && ch.RunE != nil && constructorOf(ch) == "bareGroup" {
				walk(ch)
				continue
			}
			if ch.Runnable() && !ch.HasSubCommands() && ch.Annotations[mutationAnnotationKey] != "" {
				path := strings.TrimPrefix(ch.CommandPath(), root.Name()+" ")
				out[path] = outputFor(t, info, constructorOf(ch), sites, calls)
			}
			walk(ch)
		}
	}
	walk(root)
	return out
}

func outputFor(t *testing.T, info *types.Info, ctor string, sites map[string][]renderSite, calls map[string][]string) outputSchema {
	t.Helper()
	merged := map[string]outputKey{}
	var order []string
	any := false
	anyPass := false
	nsites := 0
	for _, s := range reachableSites(ctor, sites, calls) {
		keys, pass, named := keysOfExpr(info, s.arg)
		nsites++
		if pass {
			anyPass = true
			continue
		}
		if named != "" {
			rt, ok := outputTypes[named]
			if !ok {
				t.Errorf("%s renders the struct %s: add it to outputTypes so it is rendered with every field set", ctor, named)
				continue
			}
			rendered := renderedKeys(t, rt)
			if shape(rendered) != shape(keys) {
				t.Errorf("%s: %s rendered keys %q differ from the type-derived %q", ctor, named, shape(rendered), shape(keys))
			}
			keys = withNestedFrom(rendered, keys)
		}
		for _, k := range keys {
			if _, ok := merged[k.Name]; !ok {
				order = append(order, k.Name)
			}
			merged[k.Name] = k
		}
		any = true
	}
	switch {
	case nsites == 0:
		// no render site: the verb prints diagnostic text only
		return outputSchema{Kind: "none"}
	case anyPass || !any:
		// PVE's own object (or a payload that is PVE's): its shape is PVE's
		return outputSchema{Kind: "passthrough"}
	}
	sort.Strings(order)
	res := outputSchema{Kind: "object"}
	for _, n := range order {
		res.Keys = append(res.Keys, merged[n])
	}
	return res
}

func goLiteralOfKeys(keys []outputKey, indent string) string {
	if len(keys) == 0 {
		return "nil"
	}
	var b strings.Builder
	b.WriteString("[]outputKey{\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\t{Name: %q, Kind: %q", indent, k.Name, k.Kind)
		if k.Optional {
			b.WriteString(", Optional: true")
		}
		if len(k.Keys) > 0 {
			b.WriteString(", Keys: " + goLiteralOfKeys(k.Keys, indent+"\t"))
		}
		b.WriteString("},\n")
	}
	b.WriteString(indent + "}")
	return b.String()
}

func renderOutputsTable(m map[string]outputSchema) []byte {
	var b strings.Builder
	b.WriteString("// Code generated by `make outputs` (go test ./cmd/pveforge -run '^TestOutputs_GoldenMatchesSourceAndRendering$' -update-outputs); DO NOT EDIT.\n\n")
	b.WriteString("package main\n\n")
	b.WriteString("// outputTable is the GOLDEN list of what each verb renders (contract plan §3.3\n// item 5). It is published in `pveforge schema` as each command's `output`.\n// TestOutputs_GoldenMatchesSourceAndRendering derives it from the source and from\n// rendering every report with every field set, and fails when this table differs.\nvar outputTable = map[string]outputSchema{\n")
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		o := m[p]
		fmt.Fprintf(&b, "\t%q: {Kind: %q", p, o.Kind)
		if len(o.Keys) > 0 {
			b.WriteString(", Keys: " + goLiteralOfKeys(o.Keys, "\t"))
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n")
	src, err := format.Source([]byte(b.String()))
	if err != nil {
		panic(err)
	}
	return src
}

func TestOutputs_GoldenMatchesSourceAndRendering(t *testing.T) {
	derived := derivedOutputs(t)
	if len(derived) < 40 {
		t.Fatalf("the output scan saw only %d commands", len(derived))
	}
	// non-vacuity: the scan finds both kinds, and known reports
	var obj, pass int
	for _, o := range derived {
		if o.Kind == "object" {
			obj++
		} else {
			pass++
		}
	}
	if obj < 15 || pass < 5 {
		t.Fatalf("the output scan found %d object and %d passthrough commands: it is not seeing the renders", obj, pass)
	}
	for _, want := range []string{"doctor", "vm destroy", "acl enable-vm-destroy", "version", "schema diff", "harness vm stop"} {
		if derived[want].Kind != "object" {
			t.Errorf("%s is not an object output in the derived table (%v)", want, derived[want].Kind)
		}
	}
	want := renderOutputsTable(derived)
	if *updateOutputs {
		if err := os.WriteFile("outputs_table.go", want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote outputs_table.go (%d commands)", len(derived))
		return
	}
	got, err := os.ReadFile("outputs_table.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("outputs_table.go differs from what the verbs render; run `make outputs` and review the diff (a removed key is a breaking change)")
	}
}

// Every field of a rendered report is rendered by a filled value: the filler
// must reach optional keys, else an omitempty key's removal could not be seen.
func TestOutputs_OptionalKeysAreVisibleToTheFiller(t *testing.T) {
	keys := renderedKeys(t, reflect.TypeOf(destroyReport{}))
	var optional, required int
	for _, k := range keys {
		if k.Optional {
			optional++
		} else {
			required++
		}
	}
	if optional < 5 || required < 3 {
		t.Fatalf("destroyReport: %d optional and %d required keys: the every-field-set rendering is not working", optional, required)
	}
	for _, k := range keys {
		if k.Name == "error" && !k.Optional {
			t.Errorf("destroyReport.error is omitempty and must be optional")
		}
	}
}
