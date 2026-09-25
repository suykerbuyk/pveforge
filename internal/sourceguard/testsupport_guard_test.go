package sourceguard

import (
	"encoding/json"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// modulePath is this module's import-path prefix.
const modulePath = "github.com/suykerbuyk/pveforge/"

// testSupport are the build-visible packages that exist only for tests:
// shared test machinery that a Go test file cannot export across packages.
// None may ever be linked into pveforge. A new one belongs here — the
// completeness check below fails until it is added.
var testSupport = []string{
	"internal/harness",
	"internal/lock/lockguard",
	"internal/netguard",
	"internal/pvefake",
	"internal/sourceguard",
}

// harnessSuites are the nested-harness suite packages
// (pveforge-harness-guard): test files only, run with -tags harness against
// the nested cluster. Nothing may import them, so the test-support
// anti-vacuity rule ("another package's tests import it") cannot hold for
// them; they are held to their own rules instead (TestHarnessSuitesAreTestOnly).
var harnessSuites = []string{
	"internal/harness/suites",
}

// goPackage is the part of `go list -json` this guard reads.
type goPackage struct {
	ImportPath   string
	Name         string
	GoFiles      []string
	TestGoFiles  []string
	Imports      []string // non-test imports only
	TestImports  []string
	XTestImports []string
}

// goList runs `go list` from the module root with args and returns stdout.
func goList(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

// TestTestSupportPackagesNeverReachProduction holds, for each package in
// testSupport (one subtest each, so a failure names the package):
//
//   - no package outside testSupport imports it from a non-test file (one
//     test-support package may build on another: lockguard uses sourceguard);
//   - it is absent from `go list -deps` of every main package, which also
//     catches a blank or transitive import;
//   - anti-vacuity: some other package imports it from its tests, so these
//     checks are looking at a real importer.
//
// And for the table as a whole, completeness: the non-main packages that
// nothing outside testSupport imports from a non-test file are exactly
// testSupport.
//
// It asks the toolchain rather than walking source, because a blank import
// links a package without naming anything in it, which a selector walk
// (NonTestReferences) cannot see. testdata is excluded by the go tool's own
// pattern rule: `./...` never matches a directory named testdata, so
// internal/netguard/testdata/weakprobe — a main that imports netguard on
// purpose — is not in the set. That is asserted below, not assumed.
func TestTestSupportPackagesNeverReachProduction(t *testing.T) {
	var pkgs []goPackage
	dec := json.NewDecoder(strings.NewReader(goList(t, "-json", "./...")))
	for {
		var p goPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		if strings.Contains(p.ImportPath, "/testdata/") {
			t.Fatalf("go list ./... listed %s: testdata is supposed to be excluded by the go tool", p.ImportPath)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) < 12 {
		t.Fatalf("go list saw %d packages: the walk is not seeing the module", len(pkgs))
	}

	inTable := map[string]bool{}
	for _, rel := range testSupport {
		inTable[modulePath+rel] = true
	}
	var mains []string
	importedByProduction := map[string][]string{} // import path -> non-test importers outside the table
	for _, p := range pkgs {
		if p.Name == "main" {
			mains = append(mains, p.ImportPath)
		}
		if inTable[p.ImportPath] {
			continue
		}
		for _, imp := range p.Imports {
			importedByProduction[imp] = append(importedByProduction[imp], p.ImportPath)
		}
	}
	if !slices.Contains(mains, modulePath+"cmd/pveforge") {
		t.Fatalf("mains = %v: cmd/pveforge is not among them", mains)
	}
	deps := map[string][]string{}
	for _, m := range mains {
		deps[m] = strings.Fields(goList(t, "-deps", m))
		if !slices.Contains(deps[m], modulePath+"internal/lock") && m == modulePath+"cmd/pveforge" {
			t.Fatalf("go list -deps %s did not list internal/lock: the closure is not the binary's", m)
		}
	}

	for _, rel := range testSupport {
		path := modulePath + rel
		t.Run(rel, func(t *testing.T) {
			if by := importedByProduction[path]; len(by) > 0 {
				t.Errorf("%s is imported from non-test code by %v: test-support machinery must never reach production", rel, by)
			}
			for _, m := range mains {
				if slices.Contains(deps[m], path) {
					t.Errorf("%s is in the dependency closure of %s", rel, m)
				}
			}
			var testImporters []string
			for _, p := range pkgs {
				if p.ImportPath != path && (slices.Contains(p.TestImports, path) || slices.Contains(p.XTestImports, path)) {
					testImporters = append(testImporters, p.ImportPath)
				}
			}
			if len(testImporters) == 0 {
				t.Errorf("no other package's tests import %s: this guard is not looking at a real importer (or it is dead and should go)", rel)
			}
		})
	}

	// Completeness: every package nothing in production imports is either a
	// main or listed here.
	var orphans []string
	for _, p := range pkgs {
		if slices.Contains(harnessSuites, strings.TrimPrefix(p.ImportPath, modulePath)) {
			continue // held to TestHarnessSuitesAreTestOnly's rules
		}
		if p.Name != "main" && len(importedByProduction[p.ImportPath]) == 0 {
			orphans = append(orphans, strings.TrimPrefix(p.ImportPath, modulePath))
		}
	}
	slices.Sort(orphans)
	if !slices.Equal(orphans, testSupport) {
		t.Errorf("packages no production code imports = %v, want exactly testSupport %v: list a new test-support package, or delete dead code", orphans, testSupport)
	}

	// The testdata exclusion is doing real work: netguard's weakprobe is a
	// main that imports netguard, and only the testdata rule keeps it out.
	weak := goList(t, "-f", "{{join .Imports \" \"}}", "./internal/netguard/testdata/weakprobe")
	if !slices.Contains(strings.Fields(weak), modulePath+"internal/netguard") {
		t.Errorf("internal/netguard/testdata/weakprobe no longer imports netguard (%q): drop this anti-vacuity row", weak)
	}
}

// testOnlyDeps are packages, by import-path prefix, that the module may use
// from tests only: cobra/doc generates docs/man (cmd/pveforge/man_test.go),
// and go-md2man, blackfriday and go.yaml.in/yaml come in under it. None may
// be linked into a binary: pveforge ships no man-page generator.
var testOnlyDeps = []string{
	"github.com/spf13/cobra/doc",
	"github.com/cpuguy83/go-md2man/",
	"github.com/russross/blackfriday/",
	"go.yaml.in/yaml/",
}

// TestManPageGeneratorNeverReachesProduction: no main package's `go list
// -deps` holds a testOnlyDeps package — a blank or transitive import
// included, which a source walk would miss. Anti-vacuity: cmd/pveforge's
// test dependencies do hold each one, so the check is looking at a real
// importer rather than at packages nothing uses.
func TestManPageGeneratorNeverReachesProduction(t *testing.T) {
	mains := strings.Fields(goList(t, "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./..."))
	if !slices.Contains(mains, modulePath+"cmd/pveforge") {
		t.Fatalf("mains = %v: cmd/pveforge is not among them", mains)
	}
	matches := func(pkgs []string, prefix string) []string {
		var hit []string
		for _, p := range pkgs {
			if strings.HasPrefix(p, prefix) {
				hit = append(hit, p)
			}
		}
		return hit
	}
	for _, m := range mains {
		deps := strings.Fields(goList(t, "-deps", m))
		for _, d := range testOnlyDeps {
			if hit := matches(deps, d); len(hit) > 0 {
				t.Errorf("%s links %v: the man-page generator's dependencies must stay test-only", m, hit)
			}
		}
	}
	testDeps := strings.Fields(goList(t, "-deps", "-test", "./cmd/pveforge"))
	for _, d := range testOnlyDeps {
		if len(matches(testDeps, d)) == 0 {
			t.Errorf("no test of cmd/pveforge depends on %s: this guard is not looking at a real importer (or it is dead and should go)", d)
		}
	}
}

// TestHarnessSuitesAreTestOnly holds each harnessSuites package to: no
// subpackages, even with -tags harness (each would be a test binary whose
// suites run with no guard); no non-test Go files (nothing to link into
// anything); imported by no other
// package, from tests or not; and test files that exist only under
// -tags harness beyond the untagged anchor — anti-vacuity, so the rule is
// looking at the real suites.
func TestHarnessSuitesAreTestOnly(t *testing.T) {
	var pkgs []goPackage
	dec := json.NewDecoder(strings.NewReader(goList(t, "-json", "./...")))
	for {
		var p goPackage
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	for _, rel := range harnessSuites {
		path := modulePath + rel
		t.Run(rel, func(t *testing.T) {
			var found *goPackage
			for i := range pkgs {
				if pkgs[i].ImportPath == path {
					found = &pkgs[i]
				}
			}
			if found == nil {
				t.Fatalf("%s is not a package of this module", rel)
			}
			if len(found.GoFiles) != 0 {
				t.Errorf("%s has non-test Go files %q: a harness suite package holds tests only", rel, found.GoFiles)
			}
			for _, p := range pkgs {
				if p.ImportPath != path && (slices.Contains(p.Imports, path) || slices.Contains(p.TestImports, path) || slices.Contains(p.XTestImports, path)) {
					t.Errorf("%s is imported by %s: nothing may import a harness suite", rel, p.ImportPath)
				}
			}
			// Exactly one package, with the harness tag too: a suite in a
			// subpackage would be its own test binary, with no TestMain and
			// so no harness.Open guarding it.
			if under := strings.Fields(goList(t, "-tags", "harness", "./"+rel+"/...")); len(under) != 1 || under[0] != path {
				t.Errorf("go list -tags harness ./%s/... = %q: a harness suite package has no subpackages (each would run without the guard's TestMain)", rel, under)
			}
			tagged := strings.Fields(goList(t, "-tags", "harness", "-f", `{{join .TestGoFiles " "}}`, "./"+rel))
			if len(tagged) <= len(found.TestGoFiles) {
				t.Errorf("%s: -tags harness sees %q, untagged %q: no harness-tagged suite files, so this rule is not looking at the suites", rel, tagged, found.TestGoFiles)
			}
		})
	}
}
