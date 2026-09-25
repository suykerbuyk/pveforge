package sourceguard

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The module-graph rules the go tool itself does not enforce. The rest of
// module hygiene — tidiness, go.sum against the module cache, an offline
// build — is `make modcheck`'s, since those are go commands already.
const (
	// forkModule is the go-proxmox fork pveforge builds against.
	forkModule = "github.com/suykerbuyk/go-proxmox"
	// upstreamModule is the module the fork replaced. A wrong-but-resolvable
	// import resolves against it silently, and a later `go mod tidy` writes
	// its require back — the failure the fork adoption measured. It must
	// never be in the module graph again.
	upstreamModule = "github.com/luthermonson/go-proxmox"
)

// forkTag is the only version shape the fork may be pinned to: a release
// tag of the fork, never a pseudo-version (an untagged commit, e.g.
// v0.8.2-0.20260901000000-abcdef123456) and never a plain upstream tag.
var forkTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-pveforge\.[0-9]+$`)

// noticesPlatforms are the GOOS/GOARCH pairs whose linked modules
// THIRD-PARTY-NOTICES.md must cover: the union, so the guard answers the
// same on any developer's machine, and a module linked on one platform only
// (cobra's mousetrap, on Windows) is never left unattributed.
var noticesPlatforms = []string{
	"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64",
	"windows/amd64", "windows/arm64", "freebsd/amd64", "freebsd/arm64",
}

// noticesRow is one row of THIRD-PARTY-NOTICES.md's module table:
// | `<module>` | <version> | <license> |
var noticesRow = regexp.MustCompile("^\\| `([^`]+)` \\| (v[^ |]+) \\| [^|]+\\|$")

// goModJSON is the part of `go mod edit -json` these rules read.
type goModJSON struct {
	Require []struct {
		Path     string
		Version  string
		Indirect bool
	}
	Replace []json.RawMessage
	Exclude []json.RawMessage
}

// offlineGo runs the go tool at the module root the way `make modcheck`
// does: read-only, with no module proxy and no go.work, so no rule here can
// fetch a module, edit go.mod/go.sum, or be redirected by a developer's
// workspace to an unpinned local tree. A cold module cache fails loudly.
func offlineGo(t *testing.T, args ...string) string {
	t.Helper()
	return offlineGoEnv(t, nil, args...)
}

// offlineGoEnv is offlineGo with env added (e.g. GOOS and GOARCH).
func offlineGoEnv(t *testing.T, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	cmd.Env = append(append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOWORK=off"), env...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return string(out)
}

// TestModuleGraph_ForkPinnedAndUpstreamAbsent holds four rules over the
// module definition and graph (one subtest each, so a failure names its
// rule):
//
//   - fork-pin: the fork is required at a vX.Y.Z-pveforge.N tag;
//   - no-replace-exclude: go.mod has no replace and no exclude directive
//     (a local-path replace would build against an unpinned tree);
//   - upstream-absent: the upstream module is in no require, no go.sum
//     line and nowhere in `go list -m all`;
//   - notices-versions: THIRD-PARTY-NOTICES.md lists exactly the modules
//     linked into the module's binaries — every non-standard-library module
//     of `go list -deps` over every main package (cmd/pveforge, and the
//     harness's cmd/pveforge-harness-secrets) on any of noticesPlatforms,
//     and nothing else — each at the version go.mod requires. A missing row
//     is a licence-attribution gap; a stale version misattributes whose
//     code pveforge ships.
//
// Anti-vacuity: the fork is found in the requires, in go.sum and in the
// module graph, so these rules are reading the real module. The graph is
// read offline, inside upstream-absent, so a rule that can be decided from
// go.mod and go.sum alone is never masked by a graph that cannot be read.
func TestModuleGraph_ForkPinnedAndUpstreamAbsent(t *testing.T) {
	var mod goModJSON
	if err := json.Unmarshal([]byte(offlineGo(t, "mod", "edit", "-json")), &mod); err != nil {
		t.Fatalf("parse go mod edit -json: %v", err)
	}
	gosum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatalf("read go.sum: %v", err)
	}

	t.Run("fork-pin", func(t *testing.T) {
		found := false
		for _, r := range mod.Require {
			if r.Path != forkModule {
				continue
			}
			found = true
			if !forkTag.MatchString(r.Version) {
				t.Errorf("%s is required at %q: it must be pinned to a release tag of the fork, vX.Y.Z-pveforge.N — never a pseudo-version (an untagged commit) or an upstream tag", forkModule, r.Version)
			}
			if r.Indirect {
				t.Errorf("%s is required // indirect: pveforge imports it directly", forkModule)
			}
		}
		if !found {
			t.Errorf("%s is not required at all: this guard is no longer looking at the fork", forkModule)
		}
	})

	t.Run("no-replace-exclude", func(t *testing.T) {
		if len(mod.Replace) > 0 {
			t.Errorf("go.mod has %d replace directive(s): pveforge builds only against pinned, published module versions", len(mod.Replace))
		}
		if len(mod.Exclude) > 0 {
			t.Errorf("go.mod has %d exclude directive(s)", len(mod.Exclude))
		}
	})

	t.Run("upstream-absent", func(t *testing.T) {
		for _, r := range mod.Require {
			if r.Path == upstreamModule {
				t.Errorf("go.mod requires %s %s: the fork replaced it; an import still naming it resolves silently against upstream", upstreamModule, r.Version)
			}
		}
		for i, line := range strings.Split(string(gosum), "\n") {
			if strings.HasPrefix(line, upstreamModule+" ") {
				t.Errorf("go.sum:%d names %s: %s", i+1, upstreamModule, line)
			}
		}
		// The graph last: an upstream require makes the offline graph read
		// itself fail (upstream is not in the cache), which fails this
		// subtest too — after the require and go.sum checks have named it.
		graph := strings.Fields(offlineGo(t, "list", "-m", "-f", "{{.Path}}", "all"))
		for _, p := range graph {
			if p == upstreamModule {
				t.Errorf("%s is in the module graph (go list -m all)", upstreamModule)
			}
		}
		// Anti-vacuity: the same three sources do see the fork.
		if !strings.Contains(string(gosum), forkModule+" ") {
			t.Errorf("go.sum has no %s line: the go.sum check is not reading the real file", forkModule)
		}
		inGraph := false
		for _, p := range graph {
			inGraph = inGraph || p == forkModule
		}
		if !inGraph || len(graph) < 10 {
			t.Errorf("go list -m all gave %d modules, fork present: %v — not the real module graph", len(graph), inGraph)
		}
	})

	t.Run("notices-versions", func(t *testing.T) {
		notices, err := os.ReadFile(filepath.Join("..", "..", "THIRD-PARTY-NOTICES.md"))
		if err != nil {
			t.Fatalf("read THIRD-PARTY-NOTICES.md: %v", err)
		}
		required := map[string]string{}
		for _, r := range mod.Require {
			required[r.Path] = r.Version
		}
		listed := map[string]bool{}
		for i, line := range strings.Split(string(notices), "\n") {
			if !strings.HasPrefix(line, "| `") {
				continue
			}
			m := noticesRow.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("THIRD-PARTY-NOTICES.md:%d: a module row this guard cannot read (want | `<module>` | <version> | <license> |): %s", i+1, line)
				continue
			}
			path, version := m[1], m[2]
			if listed[path] {
				t.Errorf("THIRD-PARTY-NOTICES.md:%d: %s is listed twice", i+1, path)
			}
			listed[path] = true
			want, ok := required[path]
			switch {
			case !ok:
				t.Errorf("THIRD-PARTY-NOTICES.md:%d: %s %s is not required by go.mod at all", i+1, path, version)
			case version != want:
				t.Errorf("THIRD-PARTY-NOTICES.md:%d: %s is listed at %s, but go.mod requires %s", i+1, path, version, want)
			}
		}
		// Anti-vacuity: the table was read, the fork's row with it.
		if !listed[forkModule] || len(listed) < 10 {
			t.Errorf("read %d module rows, fork's among them: %v: the guard is not reading the real table", len(listed), listed[forkModule])
		}

		// Completeness: the modules linked into the binaries — every main
		// package — on every platform, are exactly the listed ones.
		mains := strings.Fields(offlineGo(t, "list", "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`, "./..."))
		if !slices.Contains(mains, "github.com/suykerbuyk/pveforge/cmd/pveforge") || !slices.Contains(mains, "github.com/suykerbuyk/pveforge/cmd/pveforge-harness-secrets") {
			t.Fatalf("main packages = %v: cmd/pveforge and cmd/pveforge-harness-secrets must both be among them", mains)
		}
		linked := map[string][]string{} // module -> the platforms linking it
		for _, p := range noticesPlatforms {
			goos, goarch, _ := strings.Cut(p, "/")
			out := offlineGoEnv(t, []string{"GOOS=" + goos, "GOARCH=" + goarch},
				append([]string{"list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}"}, mains...)...)
			for _, m := range strings.Fields(out) {
				if !slices.Contains(linked[m], p) {
					linked[m] = append(linked[m], p)
				}
			}
		}
		for m, platforms := range linked {
			if !listed[m] {
				t.Errorf("%s is linked into a binary of this module (%s) but has no row in THIRD-PARTY-NOTICES.md: add it, with the licence from its own LICENSE file", m, strings.Join(platforms, ", "))
			}
		}
		for m := range listed {
			if _, ok := linked[m]; !ok {
				t.Errorf("THIRD-PARTY-NOTICES.md lists %s, which no platform links into any binary of this module any more: remove its row", m)
			}
		}
		// Anti-vacuity: the dependency walk saw the fork, on every platform.
		if len(linked[forkModule]) != len(noticesPlatforms) || len(linked) < 10 {
			t.Errorf("go list -deps saw %d modules, the fork on %d of %d platforms: not the real binary", len(linked), len(linked[forkModule]), len(noticesPlatforms))
		}
	})
}

// TestModule_NoVendorTree: the module holds no vendor/ directory, at any
// depth outside testdata. pveforge does not vendor, and one would be a
// blind spot by construction: every walk in this package skips vendor/
// (walkNonTest), while `go build` — what `make build` runs — compiles from a
// root vendor/ when it exists, and modcheck's -mod=readonly build and
// `go mod verify` never read it. Measured in review
// (pveforge-golinkname-defeats-source-guards, RGL2): a //go:linkname plus
// init planted in a vendored dependency made the built binary write scrypt
// logN 10 with the directive scan, the roster guards and make lint all
// green. A nested vendor/ is refused too: it is not compiled in module mode,
// but it is skipped by the same walks, so nothing could hide there either.
//
// Anti-vacuity: the walk covers the module (cmd/pveforge and
// internal/sourceguard reached).
func TestModule_NoVendorTree(t *testing.T) {
	root := filepath.Join("..", "..")
	reached := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		reached[rel] = true
		switch d.Name() {
		case ".git", "testdata":
			if path != root {
				return filepath.SkipDir
			}
		case "vendor":
			t.Errorf("%s: a vendor/ tree is in the module. pveforge does not vendor: go build would compile dependency code from it that no source guard walks — remove it", rel)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the module: %v", err)
	}
	if !reached["cmd/pveforge"] || !reached["internal/sourceguard"] {
		t.Error("the walk did not cover the module")
	}
}
