package sourceguard

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOWORK=off")
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

// TestModuleGraph_ForkPinnedAndUpstreamAbsent holds three rules over the
// module definition and graph (one subtest each, so a failure names its
// rule):
//
//   - fork-pin: the fork is required at a vX.Y.Z-pveforge.N tag;
//   - no-replace-exclude: go.mod has no replace and no exclude directive
//     (a local-path replace would build against an unpinned tree);
//   - upstream-absent: the upstream module is in no require, no go.sum
//     line and nowhere in `go list -m all`.
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
}
