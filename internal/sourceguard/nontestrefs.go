package sourceguard

// NonTestReferences and its types are the module-wide half of this package:
// where ReachableTokens answers "what does THIS function reach, in ONE
// package", this answers "where in the whole module, outside test files, is
// THIS symbol mentioned at all".
//
// TWO UNITS CONSUME IT. pveforge-bootstrap-test-kdf-cost forbids the roster
// KDF work-factor seam anywhere but internal/roster/secrets.go;
// pveforge-transport-boundary-guard forbids building an HTTP or SSH transport
// anywhere but internal/pve and internal/sshexec. The shape below is the union
// of what those two need, settled before either was written, because a second
// near-identical walker beside this one is the design smell the second unit
// exists to avoid.
//
// WHY A WALK AND NOT ParseDir. parser.ParseDir reads ONE directory,
// non-recursively — it supplies the _test.go filter that ReachableTokens and
// ExportedMethods want, and nothing else. It is also deprecated as of Go 1.22.
// A module-wide guard needs filepath.WalkDir plus parser.ParseFile, which is
// what this is.
//
// WHY QUALIFIED MATCHING IS RESOLVED THROUGH THE FILE'S IMPORTS. Matching a
// selector by its bare Sel name cannot express "net/http.Client": reduced to
// "Client" it also matches pve.Client, proxmox.Client and sshexec.Client. In
// this module that is 2 intended hits against 86 total. Matching the
// qualifier's TEXT instead would be evaded by `import nethttp "net/http"`, so
// Target.ImportPath is resolved against each file's own import declarations.
//
// WHY AllowDirs AND AllowFiles MARK RATHER THAN DROP. This package's standing
// failure mode is a guard that passes by matching nothing (see the package doc
// above: three vacuous assertions in one unit, each caught by mutation rather
// than by the suite). If an allow-list dropped its hits, a caller would need a
// SECOND call to prove its predicate still matches the sites it permits, and
// that second call is the thing an implementor forgets. Marking means one call
// returns both the violations and the proof, so the anti-vacuity assertion is
// a property of the return value rather than of the implementor's memory.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// skippedDirNames are never descended into: generated or vendored trees, and
// testdata, which holds deliberately odd source that is not part of the
// module's build. A directory with one of these names is skipped UNLESS it is
// the walk root itself, so this package's own fixtures can live under testdata
// and still be walked directly by passing the fixture directory as Root.
var skippedDirNames = map[string]bool{"testdata": true, ".git": true, "vendor": true}

// Target names one symbol to look for. Exactly one of three forms, and the
// form is what stops a bare name colliding with a qualified one:
//
//	Target{Name: "x"}                               a bare identifier `x` that
//	                                                is NOT the Sel of a selector
//	Target{AnyQualifier: true, Name: "Do"}          any selector `<expr>.Do`
//	Target{ImportPath: "net/http", Name: "Client"}  a selector whose left side
//	                                                is THIS file's import name
//	                                                for net/http — alias-proof
type Target struct {
	// ImportPath, when set, matches a selector whose left-hand side is an
	// identifier this file imports that path as, whatever it is named
	// locally.
	ImportPath string
	// AnyQualifier matches a selector with any left-hand side, including a
	// receiver variable or a field. It is the only way to reach a method
	// call, whose receiver's type parsing alone cannot know.
	AnyQualifier bool
	// Name is the identifier, or the selector's Sel. Required.
	Name string
}

func (t Target) String() string {
	switch {
	case t.ImportPath != "":
		return t.ImportPath + "." + t.Name
	case t.AnyQualifier:
		return "*." + t.Name
	default:
		return t.Name
	}
}

func (t Target) validate() error {
	if t.Name == "" {
		return fmt.Errorf("sourceguard: target %#v has an empty Name", t)
	}
	if t.ImportPath != "" && t.AnyQualifier {
		return fmt.Errorf("sourceguard: target %q sets both ImportPath and AnyQualifier; use one form", t)
	}
	return nil
}

// Scope says what to walk and which hits are permitted.
//
// AllowDirs and AllowFiles do NOT drop a hit — they mark it Allowed. See the
// file comment for why. Paths are slash-separated and relative to Root.
type Scope struct {
	// Root is the directory to walk. Required.
	Root string
	// AllowDirs marks every ref in these directories, and below them,
	// Allowed. Use it for a whole in-boundary package.
	AllowDirs []string
	// AllowFiles marks every ref in these exact files Allowed. Path-exact
	// deliberately: a directory prefix here would re-open the whole package
	// to the thing being guarded against.
	AllowFiles []string
}

// Ref is one reference to one Target.
type Ref struct {
	Target Target
	// File is slash-separated and relative to Scope.Root.
	File string
	Line int
	// Qualifier is the selector's left-hand text as written, which for a
	// method call is the receiver expression and not a package. It is empty
	// for a bare identifier.
	Qualifier string
	// Allowed reports whether an AllowDir or AllowFile permitted this ref.
	Allowed bool
}

func (r Ref) String() string {
	q := r.Qualifier
	if q != "" {
		q += "."
	}
	return fmt.Sprintf("%s:%d: %s%s (matches %s)", r.File, r.Line, q, r.Target.Name, r.Target)
}

// Result holds every ref found, keyed by file path.
//
// Parsed lists every non-test .go file the walk actually parsed, sorted. It is
// deliberately the LIST and not just a count: a count proves the walk parsed N
// files, it does not prove it parsed the right tree. A caller pins a FLOOR on
// len(Parsed) — not an exact value, so an unrelated new file does not break
// every consumer at once — and asserts Reached on a file far from its own
// package.
type Result struct {
	Refs   map[string][]Ref
	Parsed []string
}

// Violations returns every ref that no AllowDir or AllowFile permitted,
// sorted by file then line.
func (r Result) Violations() []Ref {
	var out []Ref
	for _, refs := range r.Refs {
		for _, ref := range refs {
			if !ref.Allowed {
				out = append(out, ref)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Target.String() < out[j].Target.String()
	})
	return out
}

// Reached reports whether the walk parsed rel, which is slash-separated and
// relative to the Scope's Root.
func (r Result) Reached(rel string) bool {
	i := sort.SearchStrings(r.Parsed, rel)
	return i < len(r.Parsed) && r.Parsed[i] == rel
}

// Allowed returns the permitted refs for one target in one file, which is what
// an anti-vacuity assertion asks for: "the site I deliberately allow is still
// there, so this guard is not passing by matching nothing".
func (r Result) Allowed(file string, t Target) []Ref {
	var out []Ref
	for _, ref := range r.Refs[file] {
		if ref.Allowed && ref.Target == t {
			out = append(out, ref)
		}
	}
	return out
}

// NonTestReferences walks scope.Root, parses every non-test .go file that is
// not inside a skipped directory, and reports every reference to targets.
//
// EVERYTHING THAT COULD MAKE THIS PASS BY FINDING NOTHING IS AN ERROR rather
// than an empty result, matching ReachableTokens' rule that an unmatched root
// must fail loudly: an empty or non-directory Root, no targets, a malformed
// Target, a file in scope that will not parse (never skipped), an AllowDir or
// AllowFile naming a path that is not there, a walk that parses no files, and
// an unaliased import of a target's ImportPath whose last path segment is not
// a Go identifier — that last one because a package's name need not match its
// directory (github.com/suykerbuyk/go-proxmox is package proxmox), which
// parsing alone cannot know, and guessing would silently fail to match.
func NonTestReferences(scope Scope, targets []Target) (Result, error) {
	var zero Result
	if scope.Root == "" {
		return zero, fmt.Errorf("sourceguard: NonTestReferences: empty Root")
	}
	fi, err := os.Stat(scope.Root)
	if err != nil {
		return zero, fmt.Errorf("sourceguard: NonTestReferences: stat Root: %w", err)
	}
	if !fi.IsDir() {
		return zero, fmt.Errorf("sourceguard: NonTestReferences: Root %s is not a directory", scope.Root)
	}
	if len(targets) == 0 {
		return zero, fmt.Errorf("sourceguard: NonTestReferences: no targets — a guard that looks for nothing finds nothing")
	}
	for _, t := range targets {
		if err := t.validate(); err != nil {
			return zero, err
		}
	}
	for _, d := range scope.AllowDirs {
		p := filepath.Join(scope.Root, filepath.FromSlash(d))
		st, serr := os.Stat(p)
		if serr != nil || !st.IsDir() {
			return zero, fmt.Errorf("sourceguard: AllowDir %q is not a directory under %s — has it been renamed?", d, scope.Root)
		}
	}
	for _, f := range scope.AllowFiles {
		p := filepath.Join(scope.Root, filepath.FromSlash(f))
		st, serr := os.Stat(p)
		if serr != nil || st.IsDir() {
			return zero, fmt.Errorf("sourceguard: AllowFile %q is not a file under %s — has it been renamed?", f, scope.Root)
		}
	}

	byName := map[string][]Target{}
	wantPath := map[string]bool{}
	for _, t := range targets {
		byName[t.Name] = append(byName[t.Name], t)
		if t.ImportPath != "" {
			wantPath[t.ImportPath] = true
		}
	}

	res := Result{Refs: map[string][]Ref{}}
	fset := token.NewFileSet()
	walkErr := walkNonTest(scope.Root, func(path, rel string) error {
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("sourceguard: parse %s: %w", rel, perr)
		}
		res.Parsed = append(res.Parsed, rel)

		localName, lerr := importNames(file, rel, wantPath)
		if lerr != nil {
			return lerr
		}

		// A selector's Sel is itself an *ast.Ident and ast.Inspect visits
		// both, so a bare-name target would otherwise match the right-hand
		// side of every qualified reference — exactly the collision
		// Target's three forms exist to prevent. Collect the Sel idents
		// first and skip them in the bare pass.
		selSel := map[*ast.Ident]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if se, ok := n.(*ast.SelectorExpr); ok {
				selSel[se.Sel] = true
			}
			return true
		})

		allowed := scope.allows(rel)
		add := func(t Target, pos token.Pos, qual string) {
			res.Refs[rel] = append(res.Refs[rel], Ref{
				Target:    t,
				File:      rel,
				Line:      fset.Position(pos).Line,
				Qualifier: qual,
				Allowed:   allowed,
			})
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				cands := byName[node.Sel.Name]
				if len(cands) == 0 {
					return true
				}
				qual := ""
				if id, ok := node.X.(*ast.Ident); ok {
					qual = id.Name
				}
				for _, t := range cands {
					switch {
					case t.AnyQualifier:
						add(t, node.Sel.Pos(), qual)
					case t.ImportPath != "" && qual != "" && localName[qual] == t.ImportPath:
						add(t, node.Sel.Pos(), qual)
					}
				}
			case *ast.Ident:
				if selSel[node] {
					return true
				}
				for _, t := range byName[node.Name] {
					if t.ImportPath == "" && !t.AnyQualifier {
						add(t, node.Pos(), "")
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		return zero, walkErr
	}
	sort.Strings(res.Parsed)
	if len(res.Parsed) == 0 {
		return zero, fmt.Errorf("sourceguard: NonTestReferences parsed no non-test .go files under %s — wrong Root?", scope.Root)
	}
	return res, nil
}

// importNames maps file's qualifier identifiers to the import paths they
// stand for. An unaliased import is named by its package's own name, which is
// NOT always the last path segment and cannot be learned without reading that
// package; when such an import is one a target cares about, that is an error
// rather than a guess, because guessing wrong means the guard silently misses.
func importNames(file *ast.File, rel string, wantPath map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	for _, im := range file.Imports {
		p := strings.Trim(im.Path.Value, `"`)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		} else {
			name = p[strings.LastIndex(p, "/")+1:]
			if wantPath[p] && !isGoIdent(name) {
				return nil, fmt.Errorf("sourceguard: %s imports %q with no alias, and its last path segment %q is not an identifier, so the qualifier cannot be resolved — give the import an explicit alias", rel, p, name)
			}
		}
		if name == "." {
			// A dot-import gives its symbols NO qualifier: `import .
			// "net/http"` turns http.Client into a bare `Client`, which an
			// ImportPath target cannot see. That is the same one-line
			// evasion an alias would have been, so it is refused rather
			// than silently missed. Only for paths a target cares about —
			// an unrelated dot-import is nobody's business here.
			if wantPath[p] {
				return nil, fmt.Errorf("sourceguard: %s dot-imports %q, whose symbols then have no qualifier for a guard to match — import it under a name", rel, p)
			}
			continue
		}
		if name == "_" {
			// A blank import binds no identifier, so it can never be a
			// qualifier and never hides a reference.
			continue
		}
		out[name] = p
	}
	return out, nil
}

func (s Scope) allows(rel string) bool {
	for _, f := range s.AllowFiles {
		if rel == f {
			return true
		}
	}
	for _, d := range s.AllowDirs {
		d = strings.TrimSuffix(d, "/")
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

func isGoIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
