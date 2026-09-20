package roster

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// moduleRoot is where the static guard below walks from. internal/roster is
// two levels down. TestSeam_NoProductionReferences asserts the walk reached
// cmd/pveforge/main.go, so if this file ever moves and "../.." starts
// pointing somewhere shallower, the guard fails loudly instead of quietly
// scanning a smaller tree and finding nothing.
const moduleRoot = "../.."

// ---------------------------------------------------------------------------
// Layer 1: the runtime gate.
// ---------------------------------------------------------------------------

// TestSeam_RefusesOutsideATestBinary drives the refusal branch directly, in
// process, by passing inTestBinary=false. That is the whole reason
// setScryptWorkFactor takes the flag rather than reading testing.Testing():
// the branch is covered by the suite's own coverage profile, which a
// subprocess could never contribute to.
//
// Mutants P1 (delete the gate) and P1b (the wrapper passes true
// unconditionally) both go red here and in the probe below.
func TestSeam_RefusesOutsideATestBinary(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("setScryptWorkFactor(10, false) returned instead of panicking; the gate is gone")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "outside a test binary") {
			t.Fatalf("panic %q does not say why it refused", r)
		}
	}()
	restore := setScryptWorkFactor(10, false)
	restore()
}

// TestSeam_RejectsWorkFactorsOutsideTheAcceptedRange keeps the seam from
// handing age a value age itself panics on, with a message naming neither
// this package nor the caller, and keeps 0 from silently meaning "no
// override". Mutant P2 removes the range check.
func TestSeam_RejectsWorkFactorsOutsideTheAcceptedRange(t *testing.T) {
	for _, logN := range []int{-1, 0, 21, 31} {
		t.Run(strconv.Itoa(logN), func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("setScryptWorkFactor(%d, true) was accepted; the range check is gone", logN)
				}
				if msg, _ := r.(string); !strings.Contains(msg, "out of range") {
					t.Fatalf("panic %q does not name the range", r)
				}
			}()
			restore := setScryptWorkFactor(logN, true)
			restore()
		})
	}
	// The accepted ends of the range must actually be accepted, or the
	// cases above would pass with a check that rejects everything.
	for _, logN := range []int{1, 10, 18, 20} {
		restore := setScryptWorkFactor(logN, true)
		if scryptWorkFactorOverride != logN {
			t.Errorf("setScryptWorkFactor(%d, true) left the override at %d", logN, scryptWorkFactorOverride)
		}
		restore()
	}
	if scryptWorkFactorOverride != 0 {
		t.Fatalf("override left at %d after restoring; later tests would encrypt weakly", scryptWorkFactorOverride)
	}
}

// TestSeam_WeakProbeIsRejectedOutsideATestBinary is the only check that
// proves testing.Testing() is genuinely false in a binary that is not a test
// binary — the thing the in-process test above cannot show, because inside
// `go test` it is always true.
//
// It shells out to the Go toolchain, which nothing else in this repo does.
// That is deliberate and its failure modes are all loud: no `go` on PATH, an
// unwritable GOCACHE or an unresolvable module graph each fail this test
// rather than skipping it. Warm cost is about 100ms.
func TestSeam_WeakProbeIsRejectedOutsideATestBinary(t *testing.T) {
	// Bounded on purpose. Without a deadline a wedged toolchain — a stuck
	// module fetch, a contended build cache — would hang this package until
	// the Makefile's 20m suite timeout, and a suite that hangs is worse
	// than one that fails. A cold build of the probe is a few seconds; this
	// is deliberately far above that, because a timeout here must mean
	// "something is wrong", not "the machine was busy".
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "go", "run", "./testdata/weakprobe").CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("`go run ./testdata/weakprobe` did not finish within the deadline; "+
			"this is a toolchain problem, not a gate failure:\n%s", out)
	}
	if err == nil {
		t.Fatalf("the weak probe SUCCEEDED from a non-test binary; the gate is gone:\n%s", out)
	}
	// `go run` exits 1 when the program it ran died, even though that
	// program's own exit status was 2. Assert non-zero and the message,
	// never a specific code.
	if !strings.Contains(string(out), "called outside a test binary") {
		t.Fatalf("probe failed, but not at the gate — check the toolchain rather than assuming a kill:\nerr=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "WEAKENED") {
		t.Fatalf("the probe produced weakened ciphertext before dying:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Layer 2: the module-wide static guard.
// ---------------------------------------------------------------------------

// seamAllowedFile is the ONE non-test file permitted to mention any of the
// names below. Path-exact on purpose: a directory prefix here would re-open
// the whole of internal/roster to the thing this guard exists to prevent,
// which is mutant S6.
const seamAllowedFile = "internal/roster/secrets.go"

var (
	// The setter's own declaration is a bare identifier in secrets.go; a
	// reference from any other package is a selector. Both forms are
	// forbidden, and only the first has a legitimate site.
	tgtSetterDecl = sourceguard.Target{Name: "SetScryptWorkFactorForTests"}
	tgtSetterCall = sourceguard.Target{
		ImportPath: "github.com/suykerbuyk/pveforge/internal/roster",
		Name:       "SetScryptWorkFactorForTests",
	}
	// The unexported form takes the gate's answer as an argument, so a
	// production caller inside package roster could pass true and bypass
	// the gate entirely. That is the hole the exported/unexported split
	// would otherwise open, and this closes it.
	tgtSetterInner = sourceguard.Target{Name: "setScryptWorkFactor"}
	// The var itself: forbidding only the setters would leave a production
	// file in package roster free to assign the override directly.
	tgtOverrideVar = sourceguard.Target{Name: "scryptWorkFactorOverride"}
	// AnyQualifier because the receiver is a local *age.ScryptRecipient,
	// whose type is not knowable from the AST.
	tgtSetWorkFactor = sourceguard.Target{AnyQualifier: true, Name: "SetWorkFactor"}
	// Building a recipient anywhere else would let that code set its own
	// work factor without ever naming SetWorkFactor in a guarded file.
	tgtNewRecipient = sourceguard.Target{ImportPath: "filippo.io/age", Name: "NewScryptRecipient"}
)

// TestSeam_NoProductionReferences is the static half of the safety argument:
// no non-test file in the module except secrets.go may mention the seam at
// all.
//
// Mutants S1, S2 and S3 plant each forbidden form in
// internal/bootstrap/bootstrap.go; S5 assigns the override from a second
// production file in package roster; S6 widens the allow-list to a directory.
func TestSeam_NoProductionReferences(t *testing.T) {
	targets := []sourceguard.Target{
		tgtSetterDecl, tgtSetterCall, tgtSetterInner,
		tgtOverrideVar, tgtSetWorkFactor, tgtNewRecipient,
	}
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       moduleRoot,
		AllowFiles: []string{seamAllowedFile},
	}, targets)
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("the roster KDF seam is referenced outside %s:\n%s\n"+
			"Only that one file may touch the work factor. If a new legitimate "+
			"site really exists, it needs its own review, not an entry here.",
			seamAllowedFile, strings.Join(lines, "\n"))
	}

	// ANTI-VACUITY. A guard that matches nothing passes forever. Each
	// target below has a real site in secrets.go, and if the walker stops
	// finding it the "no violations" assertion above has stopped meaning
	// anything. This is why the allow-list MARKS rather than drops: one
	// call answers both questions.
	//
	// tgtSetterCall is deliberately absent from this list. It is a
	// pre-emptive fence with no legitimate site anywhere in the module, so
	// it cannot be proven non-vacuous from the real tree; the ImportPath
	// form's mechanism is proven instead by sourceguard's own fixture, in
	// TestNonTestReferences_QualifiedMatchingIsAliasProof.
	for _, tgt := range []sourceguard.Target{
		tgtSetterDecl, tgtSetterInner, tgtOverrideVar, tgtSetWorkFactor, tgtNewRecipient,
	} {
		if got := res.Allowed(seamAllowedFile, tgt); len(got) == 0 {
			t.Errorf("target %s matched nothing in %s — the guard is no longer looking at the code it claims to guard",
				tgt, seamAllowedFile)
		}
	}

	// ...and the walk has to have covered the module, not some subtree.
	// A floor rather than an exact count, so an unrelated new file does not
	// break this and the transport guard at once.
	if len(res.Parsed) < 70 {
		t.Errorf("walked only %d non-test files from %s; the module has ~75 — wrong root?", len(res.Parsed), moduleRoot)
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Errorf("the walk never reached cmd/pveforge/main.go, so it did not cover the module; Parsed[0:3]=%v", firstN(res.Parsed, 3))
	}
	// The weakprobe is a non-test file that calls the forbidden setter. It
	// must be invisible to this walk, or the guard fails against its own
	// fixture. sourceguard's TestNonTestReferences_SkipsNestedTestdataAndTestFiles
	// is the unit-level companion; this is the real-tree one.
	if res.Reached("internal/roster/testdata/weakprobe/main.go") {
		t.Error("the walk descended into testdata and will now report the weak probe as a violation")
	}
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
