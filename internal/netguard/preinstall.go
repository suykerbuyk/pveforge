package netguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dialerSeedCalls are CALLS that build something carrying a dialer.
//
// The list is deliberately short. It does not try to enumerate this module's
// constructors — NewClientForTarget, NewRoutedClient and friends are caught
// because the walk below follows calls transitively and they all bottom out
// in one of these. Enumerating wrappers is how such a list goes stale the
// first time someone adds one.
//
// pve.NewClient(InsecureTLS: true) is the one that matters most: it Clone()s
// http.DefaultTransport at CONSTRUCTION time (newHTTPClient in internal/pve/client.go, whose
// client go-proxmox shares), so a client built before
// Install carries the PRISTINE dialer and is invisible to Seam A forever
// after — no swap performed later can reach it.
var dialerSeedCalls = map[string]bool{
	// This module's real network entry points.
	"NewClient":        true, // internal/pve
	"Dial":             true, // internal/sshexec
	"DialWithPassword": true, // internal/sshexec
	// Standard-library helpers that use the global transport directly.
	"Get":      true,
	"Head":     true,
	"Post":     true,
	"PostForm": true,
}

// dialerSeedValues are package-level GLOBALS whose mere mention, in a
// position that runs before TestMain, captures the pristine transport.
//
// These live in their own map because of a defect worth recording rather
// than quietly fixing: they were originally listed alongside the calls, and
// that map is consulted only for a CallExpr's callee name. A bare
// `http.DefaultTransport` is a SelectorExpr and never a call, so those two
// entries were structurally incapable of matching anything — dead seeds in a
// guard that looked complete. Three distinct package-level forms survived
// because of it:
//
//	var x = http.DefaultTransport
//	var x = http.DefaultClient
//	var c = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
//
// The last is the pointed one: it is the exact idiom internal/pve/client.go
// uses, so it is the expression most likely to be copied into the position
// this guard exists to forbid. TestEverySeedCanActuallyFire now requires each
// seed in each map to be demonstrably matchable, so a dead seed fails the
// suite instead of quietly widening the hole.
var dialerSeedValues = map[string]bool{
	"DefaultTransport": true, // http.DefaultTransport
	"DefaultClient":    true, // http.DefaultClient
}

// dialerSeedTypes are composite-literal types with the same property.
// Separated because a bare name matches far too much as a call but is precise
// as a type.
//
// Only Transport is here, and the two omissions are deliberate:
//
//   - http.Client is NOT a seed BY TYPE. A client with a nil Transport
//     resolves http.DefaultTransport at REQUEST time, so one built at package
//     level still meets the swap Install performs later. A client whose
//     Transport IS set at construction is caught by the value and call seeds
//     above, which is where that case belongs.
//   - net.Dialer is NOT a seed. A bare dialer captures nothing and is inert
//     until something calls DialContext on it. Listing it produced exactly
//     one hit across all twelve packages, and that hit was this package's own
//     loopbackDialer — the trip-wire's dialer, used only AFTER the guard has
//     run. A seed whose only real-tree match is the guard itself is measuring
//     the wrong thing.
//
// An http.Transport literal genuinely is one: it is its own transport, never
// consults the global, and no swap can reach it.
var dialerSeedTypes = map[string]bool{
	"Transport": true, // http.Transport
}

// preInstallFinding is one package-level construction that runs too early.
type preInstallFinding struct {
	File  string
	Line  int
	Name  string
	Chain []string
}

func (f preInstallFinding) String() string {
	via := ""
	if len(f.Chain) > 0 {
		via = " (via " + strings.Join(f.Chain, " -> ") + ")"
	}
	return fmt.Sprintf("%s:%d: %s%s", f.File, f.Line, f.Name, via)
}

// AssertNoPreInstallDialer fails t if anything in the CALLING package's
// directory builds a client or transport at package-variable initialisation
// or in an init() function.
//
// THIS IS THE OTHER SIDE OF THE ORDERING CONSTRAINT. The package doc explains
// why Install must precede m.Run and calls it load-bearing. That pins one
// direction — a swap installed too LATE. This pins the other: a dialer built
// too EARLY. Go runs package-level var initialisers and init() before
// TestMain is entered at all, so a client constructed there never meets
// either seam.
//
// Measured, not reasoned about: six lines of package-level var in
// internal/pve dialed 203.0.113.1:9 for real, burned the full 30s client
// timeout awaiting headers, and netguard observed 0 -> 0 while the test
// PASSED and the package reported ok. Nothing else in this unit can see that
// — not the companions, which assert on dials they make themselves, and not
// the fail-closed probe, which reads a recorder nothing ever wrote to.
//
// It scans NON-TEST files too, not just _test.go: a package-level var in a
// production file of the same package initialises before TestMain exactly as
// a test one does. And it follows calls TRANSITIVELY within the package, so
// the idiomatic `var c = mustClient()` — with mustClient calling NewClient one
// level down — is caught, where a flat name match sees only `mustClient`,
// which is on no list and never will be.
//
// Call resolution is deliberately OVER-APPROXIMATE, the same trade
// sourceguard.ReachableTokens documents and for the same reason: a call is
// matched by its bare name, so every function sharing that name is followed.
// That can only pull in MORE code than is strictly reachable, which makes the
// guard stricter and never weaker — the safe direction for a check whose job
// is refusing things.
func AssertNoPreInstallDialer(t *testing.T) {
	t.Helper()
	AssertNoPreInstallDialerIn(t, ".")
}

// AssertNoPreInstallDialerIn is AssertNoPreInstallDialer against an explicit
// directory, so one package can sweep the whole module — see
// TestNoPreInstallDialerAnywhereInTheModule.
//
// A package-level dialer in ANY package linked into a test binary
// initialises before that binary's TestMain, not just one in the package
// under test. The per-package guard alone would therefore leave the six
// packages that wire no TestMain free to poison every other package's
// guarantee, silently.
func AssertNoPreInstallDialerIn(t *testing.T, dir string) {
	t.Helper()
	findings, scanned, err := scanPreInstallDialers(dir)
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	// Without this the check passes trivially if the glob ever stops
	// matching — the failure mode this repo keeps rediscovering.
	if scanned == 0 {
		t.Fatalf("no .go files were scanned in %s, so this guard proved nothing", dir)
	}
	for _, f := range findings {
		t.Errorf("%s/%s is reached from a package-level var or init().\n"+
			"Go runs those BEFORE TestMain, so it is built before "+
			"netguard.Install() swaps http.DefaultTransport — the dialer it "+
			"captures is invisible to both seams, and a dial it makes leaves "+
			"the machine unrecorded while the package still reports ok. "+
			"Construct it inside a test instead.", dir, f)
	}
}

// scanPreInstallDialers is the whole walk, returning findings rather than
// reporting them, so this package's own tests can assert on what it finds —
// including that every seed is capable of producing a finding at all.
func scanPreInstallDialers(dir string) ([]preInstallFinding, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	fset := token.NewFileSet()

	type namedFile struct {
		name string
		file *ast.File
	}
	var files []namedFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, 0, perr
		}
		files = append(files, namedFile{e.Name(), file})
	}
	if len(files) == 0 {
		return nil, 0, nil
	}

	// Index every function in the package by its bare name, so the walk can
	// step into a helper an initialiser calls.
	funcs := map[string][]*ast.FuncDecl{}
	for _, nf := range files {
		for _, d := range nf.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				funcs[fd.Name.Name] = append(funcs[fd.Name.Name], fd)
			}
		}
	}

	type hit struct {
		name  string
		pos   token.Pos
		chain []string
	}
	var reach func(n ast.Node, seen map[string]bool, chain []string) *hit
	reach = func(n ast.Node, seen map[string]bool, chain []string) *hit {
		var found *hit
		ast.Inspect(n, func(x ast.Node) bool {
			if found != nil {
				return false
			}
			switch e := x.(type) {
			case *ast.CompositeLit:
				if name, pos := typeName(e.Type); dialerSeedTypes[name] {
					found = &hit{name + "{}", pos, chain}
					return false
				}
			case *ast.SelectorExpr:
				// A bare mention of a captured global — http.DefaultTransport,
				// http.DefaultClient — in ANY position: a struct field value,
				// the receiver of a .Clone() chain, an assignment source.
				if dialerSeedValues[e.Sel.Name] {
					found = &hit{e.Sel.Name, e.Sel.Pos(), chain}
					return false
				}
			case *ast.Ident:
				if dialerSeedValues[e.Name] {
					found = &hit{e.Name, e.Pos(), chain}
					return false
				}
			case *ast.CallExpr:
				name, pos := calleeName(e.Fun)
				if name == "" {
					return true
				}
				if dialerSeedCalls[name] {
					found = &hit{name, pos, chain}
					return false
				}
				// Not a seed: step into it if this package declares it.
				if seen[name] || len(chain) > 12 {
					return true
				}
				seen[name] = true
				for _, fd := range funcs[name] {
					if fd.Body == nil {
						continue
					}
					if h := reach(fd.Body, seen, append(append([]string{}, chain...), name)); h != nil {
						found = &hit{h.name, pos, h.chain}
						return false
					}
				}
			}
			return true
		})
		return found
	}

	var findings []preInstallFinding
	for _, nf := range files {
		for _, d := range nf.file.Decls {
			var root ast.Node
			switch n := d.(type) {
			case *ast.GenDecl:
				if n.Tok != token.VAR {
					continue
				}
				root = n
			case *ast.FuncDecl:
				// init() has no receiver and takes no arguments; Go runs
				// every one of them before TestMain.
				if n.Recv != nil || n.Name.Name != "init" || n.Body == nil {
					continue
				}
				root = n.Body
			default:
				continue
			}
			if h := reach(root, map[string]bool{}, nil); h != nil {
				findings = append(findings, preInstallFinding{
					File: nf.name, Line: fset.Position(h.pos).Line, Name: h.name, Chain: h.chain,
				})
			}
		}
	}
	return findings, len(files), nil
}

func calleeName(fun ast.Expr) (string, token.Pos) {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name, f.Sel.Pos()
	case *ast.Ident:
		return f.Name, f.Pos()
	}
	return "", token.NoPos
}

func typeName(t ast.Expr) (string, token.Pos) {
	switch ty := t.(type) {
	case *ast.SelectorExpr:
		return ty.Sel.Name, ty.Sel.Pos()
	case *ast.Ident:
		return ty.Name, ty.Pos()
	case *ast.StarExpr:
		return typeName(ty.X)
	}
	return "", token.NoPos
}
