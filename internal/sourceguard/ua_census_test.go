package sourceguard

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// U-A (contract plan AC-W10): the write gate is opened by the FUNNELS, and the
// call sites that reach a funnel are CENSUSED, exactly, from the AST. A new
// SSH dispatch call or roster writer fails here until it is classified (or
// opened) on purpose. The counts below are authoritative; a grep count in the
// plan is not.
//
// WHY AST-ONLY AND NOT TYPED. There is no go/types here (the module guard
// forbids a new dependency for it), so a call is matched by its callee NAME
// and its position, and every match is CLASSIFIED in a checked-in golden
// (testdata/ssh_census.golden). A match that is not SSH at all (idempotent.Run,
// bootstrap.Run) is classified OTHER, so the golden is the whole truth.

type censusSite struct {
	file, fn, callee, arg string
	line                  int
}

func (s censusSite) key() string { return s.file + " | " + s.fn + " | " + s.callee }

func nodeText(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// walkModuleSources parses every non-test .go file of the module (testdata,
// vendor and nested worktrees excluded) and hands each FuncDecl's file info to
// fn.
func walkModuleSources(t *testing.T, fn func(rel string, fset *token.FileSet, f *ast.File, src []byte)) {
	t.Helper()
	root := "../.."
	n := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", ".git", "vendor", ".wt", ".build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, src, parser.ParseComments)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		n++
		fn(filepath.ToSlash(rel), fset, f, src)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("the census walked only %d files: it is not walking the module", n)
	}
}

func funcName(fset *token.FileSet, fd *ast.FuncDecl) string {
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		name = strings.TrimPrefix(nodeText(fset, fd.Recv.List[0].Type), "*") + "." + name
	}
	return name
}

var sshEntryNames = map[string]bool{"Run": true, "rootRun": true, "pveum": true, "pveumWrite": true}

func readGolden(t *testing.T, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, " | ")
		if len(parts) != 4 {
			t.Fatalf("bad golden line %q", line)
		}
		m[strings.Join(parts[:3], " | ")] = parts[3]
	}
	return m
}

// assignedFrom reports whether ident is assigned, in the function, from an
// expression whose text contains one of the needles.
func assignedFrom(fset *token.FileSet, fd *ast.FuncDecl, ident string, needles ...string) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, l := range as.Lhs {
			if id, ok := l.(*ast.Ident); ok && id.Name == ident && i < len(as.Rhs) {
				rhs := nodeText(fset, as.Rhs[i])
				for _, nd := range needles {
					if strings.Contains(rhs, nd) {
						found = true
					}
				}
			}
		}
		return true
	})
	return found
}

func marked(fset *token.FileSet, fd *ast.FuncDecl, arg string) bool {
	if strings.Contains(arg, "WithWrite(") || strings.Contains(arg, "configWrite(") {
		return true
	}
	if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`).MatchString(arg) {
		return assignedFrom(fset, fd, arg, "WithWrite(", "configWrite(")
	}
	return false
}

const sshCensusCount = 39 // every classified site in testdata/ssh_census.golden

func itoa(n int) string { return fmtInt(n) }

func fmtInt(n int) string { return strconv.Itoa(n) }

// The funnels themselves: pveumWrite marks its ctx (configWrite), and Run
// opens the gate when it is about to send a marked command.
func TestUA_Funnels_AreWhereThePlanSaysTheyAre(t *testing.T) {
	type want struct{ file, fn, needle string }
	wants := []want{
		{"internal/bootstrap/access.go", "RootAccess.pveumWrite", "configWrite(ctx)"},
		{"internal/bootstrap/bootstrap.go", "configWrite", "sshexec.WithWrite("},
		{"internal/sshexec/client.go", "Client.Run", "NoteWrite(parent)"},
		{"internal/sshexec/client.go", "NoteWrite", "dispatch.Open(ctx)"},
		{"internal/pve/client.go", "accessWriteGuard.RoundTrip", "dispatch.Open(req.Context())"},
		{"internal/idempotent/op.go", "Run", "dispatch.Open(ctx)"},
		{"internal/idempotent/op.go", "Run", "dispatch.Refuse(ctx"},
	}
	bodies, fsets := typedBodies(t)
	for _, w := range wants {
		fd := bodies[w.file+" | "+w.fn]
		if fd == nil {
			t.Errorf("%s %s not found", w.file, w.fn)
			continue
		}
		if !strings.Contains(nodeText(fsets[w.file+" | "+w.fn], fd.Body), w.needle) {
			t.Errorf("%s %s does not contain %q", w.file, w.fn, w.needle)
		}
	}
	// dropKeyOver applies the mark AFTER cleanupCtx (F-B): the assignment to
	// ctx from WithWrite must come after the cleanupCtx call.
	fd := bodies["internal/bootstrap/bootstrap.go | runner.dropKeyOver"]
	if fd == nil {
		t.Fatal("dropKeyOver not found")
	}
	body := nodeText(fsets["internal/bootstrap/bootstrap.go | runner.dropKeyOver"], fd.Body)
	i, j := strings.Index(body, "cleanupCtx()"), strings.Index(body, "ctx = sshexec.WithWrite(ctx)")
	if i < 0 || j < 0 || j < i {
		t.Errorf("dropKeyOver must apply sshexec.WithWrite to ctx AFTER cleanupCtx (cleanupCtx at %d, mark at %d)", i, j)
	}
}

// ---- roster census (AC-W10 d) ----

var rosterWriterRE = regexp.MustCompile(`^(Write[A-Za-z]*|Replace[A-Za-z]*|Clear[A-Za-z]*|Append[A-Za-z]*|Update[A-Za-z]*|Rekey)$`)

// rosterSeamVars are the function-valued roster writers (rotation.go): a call
// THROUGH one is a roster write, and the binding itself is allowed only here.
var rosterSeamVars = map[string]string{"writeTokenAuthFn": "WriteTokenAuth", "writeSSHAuthFn": "WriteSSHAuth"}

const rosterCensusCount = 14

func TestUA_RosterCensus_EveryWriterIsPrecededByOpen_Exactly(t *testing.T) {
	type site struct {
		file, fn, text string
		line           int
		prevLine       string
	}
	var sites []site
	var refs []string
	walkModuleSources(t, func(rel string, fset *token.FileSet, f *ast.File, src []byte) {
		if strings.HasPrefix(rel, "internal/roster/") {
			return
		}
		lines := strings.Split(string(src), "\n")
		prev := func(line int) string {
			for i := line - 2; i >= 0; i-- {
				l := strings.TrimSpace(lines[i])
				if l == "" || strings.HasPrefix(l, "//") {
					continue
				}
				return l
			}
			return ""
		}
		isRosterImport := map[string]bool{}
		for _, im := range f.Imports {
			if strings.Trim(im.Path.Value, `"`) == "github.com/suykerbuyk/pveforge/internal/roster" {
				name := "roster"
				if im.Name != nil {
					name = im.Name.Name
				}
				isRosterImport[name] = true
			}
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := funcName(fset, fd)
			callFuns := map[ast.Node]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					callFuns[c.Fun] = true
				}
				return true
			})
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					txt := ""
					switch f := x.Fun.(type) {
					case *ast.SelectorExpr:
						if id, ok := f.X.(*ast.Ident); ok && isRosterImport[id.Name] && rosterWriterRE.MatchString(f.Sel.Name) {
							txt = id.Name + "." + f.Sel.Name
						}
						if id, ok := f.X.(*ast.Ident); ok && id.Name == "os" && f.Sel.Name == "WriteFile" && rel == "cmd/pveforge/roster.go" {
							txt = "os.WriteFile"
						}
					case *ast.Ident:
						if _, ok := rosterSeamVars[f.Name]; ok {
							txt = f.Name
						}
					}
					if txt != "" {
						line := fset.Position(x.Pos()).Line
						sites = append(sites, site{rel, fn, txt, line, prev(line)})
					}
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && isRosterImport[id.Name] && rosterWriterRE.MatchString(x.Sel.Name) && !callFuns[x] {
						refs = append(refs, rel+" | "+fn+" | "+id.Name+"."+x.Sel.Name)
					}
				}
				return true
			})
		}
		// package-level bindings of a roster writer to a seam var
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, v := range vs.Values {
					if se, ok := v.(*ast.SelectorExpr); ok {
						if id, ok := se.X.(*ast.Ident); ok && isRosterImport[id.Name] && rosterWriterRE.MatchString(se.Sel.Name) {
							name := vs.Names[i].Name
							if rosterSeamVars[name] != se.Sel.Name {
								refs = append(refs, rel+" | package | "+name+" = "+id.Name+"."+se.Sel.Name)
							}
						}
					}
				}
			}
		}
	})
	if len(sites) != rosterCensusCount {
		var all []string
		for _, s := range sites {
			all = append(all, s.file+":"+s.fn+":"+s.text)
		}
		sort.Strings(all)
		t.Errorf("roster census: %d writer call expressions, want exactly %d:\n%s", len(sites), rosterCensusCount, strings.Join(all, "\n"))
	}
	for _, s := range sites {
		if !strings.HasPrefix(s.prevLine, "dispatch.Open(") {
			t.Errorf("%s %s: %s (line %d) is not immediately preceded by dispatch.Open (previous statement: %q)", s.file, s.fn, s.text, s.line, s.prevLine)
		}
	}
	for _, r := range refs {
		t.Errorf("a roster writer is referenced as a value outside the two seam bindings: %s", r)
	}
	// non-vacuity: the sites the plan names are all there, F-A included
	have := map[string]bool{}
	for _, s := range sites {
		have[s.file+" | "+s.fn+" | "+s.text] = true
	}
	for _, k := range []string{
		"cmd/pveforge/roster.go | newRosterInitCmd | os.WriteFile",
		"cmd/pveforge/roster_rekey.go | newRosterRekeyCmd | roster.Rekey",
		"internal/bootstrap/bootstrap.go | Import | writeTokenAuthFn",
		"internal/bootstrap/bootstrap.go | Run | writeSSHAuthFn",
		"internal/bootstrap/bootstrap.go | Run | roster.ReplaceSSHAuth",
		"internal/bootstrap/rotation.go | runner.mintAndPersist | roster.WriteTokenAuth",
	} {
		if !have[k] {
			t.Errorf("non-vacuity: %s is not in the census", k)
		}
	}
}
