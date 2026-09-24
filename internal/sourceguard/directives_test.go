package sourceguard

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// hitKeys renders hits as "file:line:kind" (line 0 for a whole-file hit),
// the form the expectations below are written in.
func hitKeys(ev Evasions) []string {
	var out []string
	for _, h := range ev.Hits {
		out = append(out, filepathLineKind(h))
	}
	return out
}

func filepathLineKind(h Evasion) string {
	return fmt.Sprintf("%s:%d:%s", h.File, h.Line, h.Kind)
}

// D2: the fixture's evasions are reported exactly — a pull linkname and its
// unsafe import, a push linkname behind //go:build never and an aliased
// unsafe import, an assembly file, a cgo preamble — and none of its decoys: the directive
// quoted in a doc comment, "// go:linkname" with a space, a non-Go text
// file, a _test.go file, and a nested testdata directory.
func TestDirectiveEvasions_D2_Fixture(t *testing.T) {
	ev, err := DirectiveEvasions("testdata/evasion")
	if err != nil {
		t.Fatalf("DirectiveEvasions: %v", err)
	}
	want := []string{
		"asm.s:0:nongo",
		"cgo.go:5:cgo",
		"pull.go:5:unsafe",
		"pull.go:9:linkname",
		"push.go:5:unsafe",
		"push.go:9:linkname",
	}
	if got := hitKeys(ev); !slices.Equal(got, want) {
		t.Errorf("hits:\n got:  %q\n want: %q", got, want)
	}
	for _, f := range []string{"doc.go", "notes.txt", "pull.go", "push.go", "asm.s"} {
		if !ev.Reached(f) {
			t.Errorf("the walk did not reach %s", f)
		}
	}
	for _, f := range []string{"pull_test.go", "nested/testdata/deeper.go"} {
		if ev.Reached(f) {
			t.Errorf("the walk reached %s, which is not production source", f)
		}
	}
}

// writeTree writes files (relative path → content) under a fresh directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// D3: each kind on its own, in shapes the gofmt-clean fixture cannot hold.
func TestDirectiveEvasions_D3_EachKind(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"indented linkname": {
			map[string]string{"a.go": "package a\n\nfunc f() {\n\t//go:linkname x y.z\n}\n"},
			[]string{"a.go:4:linkname"},
		},
		"linkname with CRLF line endings": {
			map[string]string{"a.go": "package a\r\n\r\n//go:linkname x y.z\r\nvar x int\r\n"},
			[]string{"a.go:3:linkname"},
		},
		"linkname under a custom build tag": {
			map[string]string{"a.go": "//go:build pveforge_never\n\npackage a\n\n//go:linkname x y.z\nvar x int\n"},
			[]string{"a.go:5:linkname"},
		},
		"blank and aliased unsafe, grouped": {
			map[string]string{"a.go": "package a\n\nimport (\n\t\"fmt\"\n\t_ \"unsafe\"\n\tu \"unsafe\"\n)\n"},
			[]string{"a.go:5:unsafe", "a.go:6:unsafe"},
		},
		"cgo, grouped and aliased": {
			map[string]string{"a.go": "package a\n\n// int poke(void) { return 10; }\nimport \"C\"\n", "b.go": "package a\n\nimport (\n\t\"fmt\"\n\tc \"C\"\n)\n"},
			[]string{"a.go:4:cgo", "b.go:5:cgo"},
		},
		"non-Go sources": {
			map[string]string{"x.s": "", "y.c": "", "z.syso": "", "w.go": "package w\n"},
			[]string{"x.s:0:nongo", "y.c:0:nongo", "z.syso:0:nongo"},
		},
		"not production: test files and nested testdata": {
			map[string]string{
				"a_test.go":           "package a\n\nimport _ \"unsafe\"\n\n//go:linkname x y.z\nvar x int\n",
				"testdata/b.go":       "package b\n\nimport _ \"unsafe\"\n",
				"sub/testdata/c.s":    "",
				"vendor/v/v.go":       "package v\n\nimport _ \"unsafe\"\n",
				"clean.go":            "package a\n\n// //go:linkname only mentioned\n",
				"sub/fine.go":         "package sub\n",
				"sub/doc/indented.go": "package doc\n\n// Example:\n//\n//\t//go:linkname x y.z\n",
			},
			nil,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := DirectiveEvasions(writeTree(t, tc.files))
			if err != nil {
				t.Fatalf("DirectiveEvasions: %v", err)
			}
			if got := hitKeys(ev); !slices.Equal(got, tc.want) {
				t.Errorf("hits:\n got:  %q\n want: %q", got, tc.want)
			}
		})
	}
}

// D4: one definition of production source. On the module, NonTestReferences'
// Parsed set is exactly DirectiveEvasions' walked .go files.
func TestDirectiveEvasions_D4_SharesTheWalker(t *testing.T) {
	refs, err := NonTestReferences(Scope{Root: "../.."}, []Target{{Name: "NonTestReferences"}})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := DirectiveEvasions("../..")
	if err != nil {
		t.Fatal(err)
	}
	var goFiles []string
	for _, f := range ev.Walked {
		if strings.HasSuffix(f, ".go") {
			goFiles = append(goFiles, f)
		}
	}
	if !slices.Equal(goFiles, refs.Parsed) {
		t.Errorf("the two walks disagree on production .go files: %d vs %d", len(goFiles), len(refs.Parsed))
	}
}
