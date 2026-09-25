package sourceguard

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The module's no-t.Parallel pin, in one place (pveforge-noparallel-assertion-duplication).
//
// It replaces three copies of one assertion: hand-copied noparallel_test.go
// files in internal/roster and internal/bootstrap, and netguard's
// AssertNoParallel, called from five packages. The copies' stated reason
// for existing per package — "a Go test helper cannot cross a package
// boundary" — does not hold for a source walk: this package already walks
// the whole module from here (NonTestReferences, the module and
// test-support guards), and so does this test.
//
// Why the pin exists at all: each package's tests run in one process, and
// the packages below swap process-global state from their tests — a seam
// variable, a *ForTests override, os.Stdin, netguard's recorder. A test
// that swaps one and a test that relies on the production value are only
// safe together if they never overlap, i.e. if nothing in that package
// calls t.Parallel. Separate packages are separate processes under
// `go test ./...`, so only parallelism WITHIN a package is the hazard.
//
// The pin is enforced only by a run that includes internal/sourceguard
// (make test and any ./... run do); `go test ./internal/roster` alone does
// not check roster's.

// noParallel lists the packages whose tests mutate process-global state,
// each with what makes parallelism unsafe there.
var noParallel = []struct{ pkg, why string }{
	{"cmd/pveforge", "netguard's recorder, installed by TestMain, scopes ExpectViolation by wall-clock nesting; roster's scrypt work-factor override; the command seams (newBootstrapTransport, newBootstrapValidator, importStdin, importStdinIsTerminal, notifySignals, stopSignals, execHarden, execDecrypt, execve); pve.SetSSHPortForIntegrationTests; os.Stdin"},
	{"internal/bootstrap", "roster's scrypt work-factor override (a test at a lowered factor must not overlap one asserting production's 18); postMintRetryDelay, cleanupTimeout and the writeTokenAuthFn / dryRunTokenWrite / persistTargetMetaFn seams; netguard"},
	{"internal/roster", "the scrypt work-factor override itself (SetScryptWorkFactorForTests); the terminal seams readPassword, getTermState and restoreTermFn; dryRunCompose"},
	{"internal/pve", "netguard's recorder; SetTaskTimingsForTests and the task and agent-exec poll defaults; SetSSHPortForIntegrationTests"},
	{"internal/idempotent", "netguard's recorder; pve.SetTaskTimingsForTests"},
	{"internal/sshexec", "netguard's recorder; SetDialGuardForTests; os.Stdin"},
	{"internal/lock", "pollInterval and defaultWait, which the lock-wait tests shorten"},
	{"internal/netguard", "its own recorder (installed, violations, expecting, observedDials), which its tests reset"},
	{"internal/pvefake", "DrainJoinTimeout, the RecordStdin mode's drain bound, which TestSSHServer_BoundedDrainRecordsTruncation lowers"},
	{"internal/harnesssecrets", "the execve, isTerminal and readSecret seams; t.Setenv"},
	{"cmd/pveforge-harness-secrets", "t.Setenv, and child processes whose HOME and TMPDIR each test points at its own directory"},
}

// parallelAllowed lists the packages whose tests touch no process-global
// state, so t.Parallel is harmless there. Each is checked: one whose tests
// start touching global state fails until it moves to noParallel.
var parallelAllowed = []struct{ pkg, why string }{
	{"internal/device", "pure functions over their inputs"},
	{"internal/discover", "pure functions over their inputs"},
	{"internal/kvjson", "pure rendering"},
	{"internal/lock/lockguard", "a static source guard"},
	{"internal/nodump", "its test calls Set in a child process, never in the test process"},
	{"internal/sourceguard", "static walks and read-only go commands"},
}

// TestTestFacts_Calibration: the walker finds what it must — a t.Parallel
// call, a method value of Parallel in an external test package, and each
// kind of global touch — and nothing in a comment, a string or a local.
func TestTestFacts_Calibration(t *testing.T) {
	facts, err := TestFacts("testdata/testfacts")
	if err != nil {
		t.Fatal(err)
	}
	if facts.Files != 3 {
		t.Errorf("Files = %d, want 3 (two in-package test files and an external one)", facts.Files)
	}
	if want := []string{"a_test.go:11", "b_test.go:6", "c_test.go:18"}; !slices.Equal(facts.Parallel, want) {
		t.Errorf("Parallel = %q, want %q (a call, a method value in the _test package, and b.RunParallel; never a comment or string)", facts.Parallel, want)
	}
	// c_test.go's forms (pveforge-noparallel review, RNP1) are each a way a
	// test mutates shared state that an assignment-to-a-bare-name rule
	// misses; t.Setenv and a local's field (also in c_test.go) must not count.
	want := []string{
		"a_test.go:12: seam =",
		"a_test.go:13: grouped +=",
		"a_test.go:14: os.Stdin =",
		"a_test.go:15: SetTaskTimingsForTests",
		"a_test.go:17: netguard.ExpectViolation",
		"c_test.go:22: os.Setenv",
		"c_test.go:23: os.Chdir",
		"c_test.go:24: logpkg.SetOutput",
		"c_test.go:25: counter++",
		"c_test.go:26: registry[…] =",
		"c_test.go:27: cfg.N.M =",
		"c_test.go:28: hook =",
		"c_test.go:29: (*cfg.N).M--",
	}
	if !slices.Equal(facts.Globals, want) {
		t.Errorf("Globals = %q\nwant      %q", facts.Globals, want)
	}

	clean, err := TestFacts("testdata/testfacts_clean")
	if err != nil {
		t.Fatal(err)
	}
	if clean.Files != 1 || len(clean.Parallel) != 0 || len(clean.Globals) != 0 {
		t.Errorf("clean fixture = %+v, want one file and nothing found (a := local shadowing a package var is not a global touch)", clean)
	}
}

// TestNoParallel_WhereTestsShareProcessGlobals: in every package on
// noParallel, no test calls t.Parallel (one subtest per package, so a
// failure names it). Anti-vacuity per package: its test files were read,
// and the walker still sees it touching global state — otherwise its reason
// has gone stale and it belongs on parallelAllowed. Every package on
// parallelAllowed is checked the other way. Completeness: the two tables
// together are exactly the module's directories that hold a _test.go file,
// build tags ignored.
func TestNoParallel_WhereTestsShareProcessGlobals(t *testing.T) {
	for _, p := range noParallel {
		t.Run(p.pkg, func(t *testing.T) {
			facts, err := TestFacts("../../" + p.pkg)
			if err != nil {
				t.Fatal(err)
			}
			if facts.Files == 0 {
				t.Fatalf("no _test.go files read in %s: this pin proved nothing", p.pkg)
			}
			for _, site := range facts.Parallel {
				t.Errorf("%s/%s: t.Parallel is not allowed in %s: its tests mutate process-global state — %s", p.pkg, site, p.pkg, p.why)
			}
			if len(facts.Globals) == 0 {
				t.Errorf("%s: its tests no longer touch any process-global state the walker sees; move it to parallelAllowed or fix the walker", p.pkg)
			}
		})
	}
	for _, p := range parallelAllowed {
		t.Run("allowed/"+p.pkg, func(t *testing.T) {
			facts, err := TestFacts("../../" + p.pkg)
			if err != nil {
				t.Fatal(err)
			}
			if facts.Files == 0 {
				t.Fatalf("no _test.go files read in %s: drop it from parallelAllowed", p.pkg)
			}
			if len(facts.Globals) > 0 {
				t.Errorf("%s now touches process-global state from its tests (%s): move it to noParallel with the reason", p.pkg, strings.Join(facts.Globals, "; "))
			}
		})
	}

	// Every directory holding a _test.go file, whatever its build tags: go
	// list's default build would hide a package whose tests are all behind
	// a tag (an integration suite), and those run in one process too.
	var withTests []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "../.." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), "_test.go") {
			rel, err := filepath.Rel("../..", filepath.Dir(path))
			if err != nil {
				return err
			}
			if rel = filepath.ToSlash(rel); !slices.Contains(withTests, rel) {
				withTests = append(withTests, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the module: %v", err)
	}
	var tabled []string
	for _, p := range noParallel {
		tabled = append(tabled, p.pkg)
	}
	for _, p := range parallelAllowed {
		tabled = append(tabled, p.pkg)
	}
	slices.Sort(withTests)
	slices.Sort(tabled)
	if len(withTests) < 12 {
		t.Fatalf("the walk saw %d directories with tests: it is not seeing the module", len(withTests))
	}
	if !slices.Equal(withTests, tabled) {
		t.Errorf("packages with tests = %q\ntabled                = %q\nevery package with tests must be on noParallel or parallelAllowed, with its reason", withTests, tabled)
	}
}
