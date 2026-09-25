package harness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The harness suites run the guard in their TestMain and exit non-zero when
// it refuses: without a harness environment, `go test -tags harness` of the
// suites must FAIL with the guard's reason — never pass, never skip.
func TestSuites_FailClosedWithoutAHarness(t *testing.T) {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "PVEFORGE_") || name == "GOFLAGS" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOWORK=off")
	cmd := exec.Command("go", "test", "-tags", "harness", "-count=1", "./suites")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() == 0 {
		t.Fatalf("go test -tags harness ./suites: %v (want a failing exit)\n%s", err, out)
	}
	if !strings.Contains(string(out), "harness guard: "+RosterVar+" is not set") {
		t.Errorf("the suites did not fail on the guard's reason:\n%s", out)
	}
	for _, s := range []string{"--- PASS", "--- SKIP", "\nok "} {
		if strings.Contains(string(out), s) {
			t.Errorf("the suites reported %q without a harness:\n%s", s, out)
		}
	}
}

// The suites' imports are an ALLOW-list, so the rule fails closed: the
// standard library except the packages that reach the network, run a
// program or step outside the type system, plus internal/harness itself.
// Anything else — pve, roster, sshexec, go-proxmox, os/exec (a pveforge
// command), net/http — is refused, so a suite can only reach the nested
// cluster through harness.Open's vetted clients. No command helper exists
// until a suite needs one (then it is reviewed).
var (
	suiteAllowedModule = []string{"github.com/suykerbuyk/pveforge/internal/harness"}
	suiteDeniedStdlib  = []string{"os/exec", "net", "net/http", "syscall", "unsafe"}
)

// suiteImportAllowed reports whether a suite file may import path.
func suiteImportAllowed(path string) bool {
	if slices.Contains(suiteAllowedModule, path) {
		return true
	}
	first, _, _ := strings.Cut(path, "/")
	if strings.Contains(first, ".") {
		return false // not the standard library
	}
	for _, d := range suiteDeniedStdlib {
		if path == d || strings.HasPrefix(path, d+"/") {
			return false
		}
	}
	return true
}

// suiteViolations walks every Go file under dir, recursively (a suite in a
// subpackage is found too), tagged or not (the parser reads build-
// constrained files), and returns each import outside the allow-list, each
// dot-import, and each os.Setenv (the nested root password reaches a
// child's exec.Cmd.Env only, never the test process).
func suiteViolations(t *testing.T, dir string) (violations []string, files int) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return err
		}
		files++
		rel, _ := filepath.Rel(dir, p)
		osName := ""
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !suiteImportAllowed(path) {
				violations = append(violations, rel+": imports "+path)
			}
			if imp.Name != nil && imp.Name.Name == "." {
				violations = append(violations, rel+": dot-imports "+path)
			}
			if path == "os" {
				osName = "os"
				if imp.Name != nil {
					osName = imp.Name.Name
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && osName != "" && id.Name == osName && sel.Sel.Name == "Setenv" {
					violations = append(violations, rel+": os.Setenv")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return violations, files
}

func TestSuites_OnlyUseTheVettedClients(t *testing.T) {
	v, files := suiteViolations(t, "suites")
	if files < 2 {
		t.Fatalf("read %d suite files: the walk is not reading the suites", files)
	}
	if len(v) != 0 {
		t.Errorf("a suite reaches past harness.Open: %q", v)
	}
	// Anti-vacuity: the walker finds each refused import, a dot-import and
	// an aliased os.Setenv — in a SUBDIRECTORY too — and lets the allowed
	// ones through.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "vm"), 0o755); err != nil {
		t.Fatal(err)
	}
	bad := `//go:build harness

package vm

import (
	"context"
	"fmt"
	"os/exec"
	"net/http"
	"net/http/httptest"
	"net"
	"syscall"
	"unsafe"
	envos "os"
	. "strings"
	"github.com/suykerbuyk/pveforge/internal/harness"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	proxmox "github.com/suykerbuyk/go-proxmox"
)

var _ = envos.Setenv
`
	if err := os.WriteFile(filepath.Join(dir, "vm", "destroy_test.go"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := suiteViolations(t, dir)
	want := []string{
		"vm/destroy_test.go: imports os/exec", "vm/destroy_test.go: imports net/http", "vm/destroy_test.go: imports net/http/httptest",
		"vm/destroy_test.go: imports net", "vm/destroy_test.go: imports syscall", "vm/destroy_test.go: imports unsafe",
		"vm/destroy_test.go: dot-imports strings",
		"vm/destroy_test.go: imports github.com/suykerbuyk/pveforge/internal/pve", "vm/destroy_test.go: imports github.com/suykerbuyk/pveforge/internal/roster",
		"vm/destroy_test.go: imports github.com/suykerbuyk/pveforge/internal/sshexec", "vm/destroy_test.go: imports github.com/suykerbuyk/go-proxmox",
		"vm/destroy_test.go: os.Setenv",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the walker found\n%q\nwant\n%q", got, want)
	}
}

// make lint vets the harness-tagged code too (a type error there passes an
// untagged vet), and make harness runs the suites one package at a time
// with an absolute roster path.
func TestMakefile_VetsAndRunsTheHarness(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	mk := string(b)
	recipe := func(target string) string {
		_, rest, ok := strings.Cut(mk, "\n"+target+":")
		if !ok {
			t.Fatalf("the Makefile has no %s target", target)
		}
		var lines []string
		for _, l := range strings.Split(rest, "\n")[1:] {
			if !strings.HasPrefix(l, "\t") {
				break
			}
			lines = append(lines, l)
		}
		return strings.Join(lines, "\n")
	}
	if l := recipe("lint"); !strings.Contains(l, "$(OFFLINE) go vet -tags harness ./...") {
		t.Errorf("make lint does not vet the harness-tagged code:\n%s", l)
	}
	h := recipe("harness")
	for _, want := range []string{"go test -tags harness", "-count=1", "-p 1", "./internal/harness/suites/...", "$(abspath "} {
		if !strings.Contains(h, want) {
			t.Errorf("make harness lacks %q:\n%s", want, h)
		}
	}
}
