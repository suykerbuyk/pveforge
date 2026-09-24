package sourceguard

// DirectiveEvasions is the TEXT half of this package. Every other instrument
// here walks an AST of identifiers, and a //go:linkname is a comment: with
// `import _ "unsafe"`, which binds no identifier, a non-test file can bind a
// local name to any symbol in the module — an unexported package variable
// included — and assign it, with every AST guard green. Measured against the
// roster KDF override (pveforge-golinkname-defeats-source-guards): under a
// renamed alias, from a package outside internal/roster's own test binary,
// `go build`, `go vet` and `make lint` all pass and the binary writes scrypt
// logN 10. So this reads source as bytes, and refuses the evasion's
// ingredients themselves, whatever they target:
//
//   - linkname: a //go:linkname directive in a non-test .go file — any, not
//     only one naming a guarded symbol, because a renamed alias or a new
//     guarded symbol would outrun any list of names;
//   - unsafe: a non-test .go file importing "unsafe", which a pull-style
//     linkname cannot compile without, and which is a second route to memory
//     no identifier guard can follow;
//   - nongo: a non-Go source or object file (assembly, C and its relatives,
//     SWIG, .syso) — assembly writes another package's symbol with no
//     directive at all (MOVQ $10, …roster·scryptWorkFactorOverride(SB));
//   - cgo: a non-test .go file importing "C", whose preamble comment is C
//     source compiled into the same build — the nongo ingredient without a
//     non-Go file, and without an unsafe import. (Its by-name write into a
//     Go symbol was not made to link in review; it is refused as the same
//     ingredient, since C in the process reaches memory no identifier guard
//     follows.)
//
// It never evaluates build constraints, on purpose: a directive behind
// //go:build ignore, a custom tag or a GOOS is refused like any other, which
// no build-configuration-aware walk would see.
//
// Its limits, stated so nothing budgets past them: it covers this module's
// own tree only. A dependency in the module cache could //go:linkname into
// this module without importing it, and this scan cannot see it; the module
// guard pins which dependencies exist, and scanning the module cache is a
// separate decision. A vendor/ tree would put dependency code inside this
// tree where the walk deliberately does not look (walkNonTest skips it) and
// where `go build` compiles from — so the module guard refuses one outright
// (TestModule_NoVendorTree): pveforge does not vendor. And a directive
// inside a string literal that happens to start a line is reported too — a
// false refusal, which is the safe direction.

import (
	"bufio"
	"bytes"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// EvasionKind names what DirectiveEvasions found.
type EvasionKind string

const (
	EvasionLinkname EvasionKind = "linkname"
	EvasionUnsafe   EvasionKind = "unsafe"
	EvasionNonGo    EvasionKind = "nongo"
	EvasionCgo      EvasionKind = "cgo"
)

// Evasion is one finding: its kind, the file (slash-separated, relative to
// the walk root), and the line (0 for a whole-file finding such as nongo).
type Evasion struct {
	Kind EvasionKind
	File string
	Line int
	Text string
}

func (e Evasion) String() string {
	if e.Line == 0 {
		return fmt.Sprintf("%s: %s: %s", e.File, e.Kind, e.Text)
	}
	return fmt.Sprintf("%s:%d: %s: %s", e.File, e.Line, e.Kind, e.Text)
}

// Evasions is DirectiveEvasions' result: every finding, sorted by file and
// line, and every file the walk visited (Walked), so a caller can prove the
// walk covered the tree it meant to.
type Evasions struct {
	Hits   []Evasion
	Walked []string
}

// Reached reports whether rel was among the files walked.
func (e Evasions) Reached(rel string) bool {
	i := sort.SearchStrings(e.Walked, rel)
	return i < len(e.Walked) && e.Walked[i] == rel
}

// linknameDirective is where the gc toolchain honours the directive: a line
// comment that starts with exactly "//go:linkname", indentation allowed.
// Prose that merely mentions it ("//	//go:linkname …" in a doc comment) does
// not start that way and is not reported.
var linknameDirective = regexp.MustCompile(`^[ \t]*//go:linkname\b`)

// nonGoSources are the file extensions `go build` compiles or links besides
// Go: assembly, C, C++, Objective-C, Fortran, SWIG, and system objects.
var nonGoSources = map[string]bool{
	".s": true, ".S": true, ".sx": true,
	".c": true, ".h": true,
	".cc": true, ".cpp": true, ".cxx": true, ".hh": true, ".hpp": true, ".hxx": true,
	".m": true,
	".f": true, ".F": true, ".for": true, ".f90": true,
	".swig": true, ".swigcxx": true,
	".syso": true,
}

// DirectiveEvasions reads every non-test file under root (walkNonTest's
// definition) and reports each linkname directive, unsafe import and non-Go
// source file, and each cgo import. See the file comment for why each is
// refused.
func DirectiveEvasions(root string) (Evasions, error) {
	var out Evasions
	fset := token.NewFileSet()
	err := walkNonTest(root, func(path, rel string) error {
		out.Walked = append(out.Walked, rel)
		ext := filepath.Ext(path)
		if nonGoSources[ext] {
			out.Hits = append(out.Hits, Evasion{Kind: EvasionNonGo, File: rel, Text: "a " + ext + " file is compiled or linked into the module's build"})
			return nil
		}
		if ext != ".go" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(bytes.NewReader(src))
		sc.Buffer(make([]byte, 0, 64*1024), len(src)+1)
		for line := 1; sc.Scan(); line++ {
			if text := strings.TrimRight(sc.Text(), "\r"); linknameDirective.MatchString(text) {
				out.Hits = append(out.Hits, Evasion{Kind: EvasionLinkname, File: rel, Line: line, Text: strings.TrimSpace(text)})
			}
		}
		if err := sc.Err(); err != nil {
			return fmt.Errorf("sourceguard: scan %s: %w", rel, err)
		}
		f, err := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("sourceguard: parse the imports of %s: %w", rel, err)
		}
		for _, im := range f.Imports {
			switch p, _ := strconv.Unquote(im.Path.Value); p {
			case "unsafe":
				out.Hits = append(out.Hits, Evasion{Kind: EvasionUnsafe, File: rel, Line: fset.Position(im.Pos()).Line, Text: `imports "unsafe"`})
			case "C":
				out.Hits = append(out.Hits, Evasion{Kind: EvasionCgo, File: rel, Line: fset.Position(im.Pos()).Line, Text: `imports "C": its preamble is C compiled into the build`})
			}
		}
		return nil
	})
	if err != nil {
		return Evasions{}, err
	}
	sort.Strings(out.Walked)
	sort.SliceStable(out.Hits, func(i, j int) bool {
		if out.Hits[i].File != out.Hits[j].File {
			return out.Hits[i].File < out.Hits[j].File
		}
		return out.Hits[i].Line < out.Hits[j].Line
	})
	if len(out.Walked) == 0 {
		return Evasions{}, fmt.Errorf("sourceguard: DirectiveEvasions walked no files under %s — wrong root?", root)
	}
	return out, nil
}
