package sourceguard

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The PRD's package map (docs/prd.md §7.3) names every package of the
// module and the plane it belongs to. It lives here, not with the PRD's
// other checks in cmd/pveforge/readme_test.go, because this package already
// asks the toolchain for the package set (goList) and already owns the
// classification the planes rest on: testSupport, harnessSuites and
// harnessToolMains above, held complete by
// TestTestSupportPackagesNeverReachProduction. Deriving the planes from
// those tables means a package that changes plane fails both guards, not
// just one.

// prdMapRowRE is one row of the package map: | `path` | plane | role |.
var prdMapRowRE = regexp.MustCompile("(?m)^\\| `([^`]+)` \\| ([a-z -]+) \\| .* \\|$")

// prdPackageMap returns the package map's rows, path to plane.
func prdPackageMap(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../../docs/prd.md")
	if err != nil {
		t.Fatal(err)
	}
	_, sec, ok := strings.Cut(string(b), "\n### 7.3 Package map\n")
	if !ok {
		t.Fatal(`docs/prd.md has no "### 7.3 Package map" heading`)
	}
	for _, end := range []string{"\n### ", "\n## "} {
		if i := strings.Index(sec, end); i >= 0 {
			sec = sec[:i]
		}
	}
	rows := map[string]string{}
	for _, m := range prdMapRowRE.FindAllStringSubmatch(sec, -1) {
		if _, dup := rows[m[1]]; dup {
			t.Errorf("§7.3 lists %s twice", m[1])
		}
		rows[m[1]] = m[2]
	}
	return rows
}

// modulePlanes classifies every package of the module (modulePackages: the
// default build and -tags harness):
//   - binary: cmd/pveforge, the product;
//   - harness tool: any other main (the harness helpers);
//   - production: linked into cmd/pveforge;
//   - test-support: in testSupport;
//   - harness suite: in harnessSuites;
//   - harness library: linked into a harness tool and into nothing above.
//
// A package that fits none of these fails the test: it needs a plane, here
// and in the PRD.
func modulePlanes(t *testing.T) map[string]string {
	t.Helper()
	pkgs := modulePackages(t)
	// The product is what ships: its default build, never a tagged one.
	product := strings.Fields(goList(t, "-deps", modulePath+"cmd/pveforge"))
	var toolDeps []string
	for _, p := range pkgs {
		if p.Name == "main" && p.ImportPath != modulePath+"cmd/pveforge" {
			toolDeps = append(toolDeps, moduleDeps(t, p.ImportPath)...)
		}
	}
	planes := map[string]string{}
	for _, p := range pkgs {
		rel := strings.TrimPrefix(p.ImportPath, modulePath)
		switch {
		case rel == "cmd/pveforge":
			planes[rel] = "binary"
		case p.Name == "main":
			planes[rel] = "harness tool"
		case slices.Contains(product, p.ImportPath):
			planes[rel] = "production"
		case slices.Contains(testSupport, rel):
			planes[rel] = "test-support"
		case slices.Contains(harnessSuites, rel):
			planes[rel] = "harness suite"
		case slices.Contains(toolDeps, p.ImportPath):
			planes[rel] = "harness library"
		default:
			t.Errorf("%s fits no plane: it is not linked into any binary, nor listed as test-support or a harness suite", rel)
		}
	}
	return planes
}

// TestPRD_PackageMapMatchesGoList: the PRD's package map lists exactly the
// packages `go list ./...` reports under the default build or -tags harness, each under the plane the toolchain and
// this package's own tables give it.
func TestPRD_PackageMapMatchesGoList(t *testing.T) {
	doc := prdPackageMap(t)
	code := modulePlanes(t)
	if len(code) < 20 || len(doc) < 20 {
		t.Fatalf("go list gave %d packages and the PRD's map %d rows: one side is not being seen", len(code), len(doc))
	}
	for pkg, plane := range code {
		switch {
		case doc[pkg] == "":
			t.Errorf("docs/prd.md §7.3 does not list %s (%s)", pkg, plane)
		case doc[pkg] != plane:
			t.Errorf("docs/prd.md §7.3 lists %s as %s, but it is %s", pkg, doc[pkg], plane)
		}
	}
	for pkg := range doc {
		if _, ok := code[pkg]; !ok {
			t.Errorf("docs/prd.md §7.3 lists %s, which go list ./... does not report", pkg)
		}
	}
}
