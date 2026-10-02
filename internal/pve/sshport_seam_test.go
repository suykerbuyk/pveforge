package pve

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// The layers holding SetSSHPortForIntegrationTests shut, in the shape
// tasktimings_seam_test.go and internal/roster/kdf_seam_test.go established:
// a runtime testing.Testing() gate (S1, and S5 through a real non-test
// binary), an argument check (S1b), a restore round trip (S2), the
// production port pinned at rest (S3), and a module-wide static guard (S4).

// TestSSHPortSeam_RefusesOutsideATestBinary (S1) drives the inner function
// with the gate's answer forced to false.
func TestSSHPortSeam_RefusesOutsideATestBinary(t *testing.T) {
	requireSSHPortPanic(t, "called outside a test binary", func() {
		setSSHPortForTests(2222, false)
	})
}

// TestSSHPortSeam_RejectsOutOfRangePorts (S1b): no port outside 1..65535
// can reach a fake server.
func TestSSHPortSeam_RejectsOutOfRangePorts(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		requireSSHPortPanic(t, "out of range", func() {
			restore := setSSHPortForTests(port, true)
			restore() // unreachable unless the check is gone; keep the var clean either way
		})
	}
}

// TestSSHPortSeam_RestoresPrevious (S2) is the round trip: redirect, observe
// RoutedSSHPort honouring it, restore, observe the value on entry again. A
// no-op restore would silently hand one test's fake port to every later
// test in the package.
func TestSSHPortSeam_RestoresPrevious(t *testing.T) {
	restoreSSHPortOnEntry(t)
	entry := routedSSHDialPort

	restore := SetSSHPortForIntegrationTests(2222)
	if got := RoutedSSHPort(); got != 2222 {
		t.Fatalf("RoutedSSHPort() = %d while redirected, want 2222 — the seam had no effect", got)
	}
	restore()

	if routedSSHDialPort != entry {
		t.Errorf("restore() left routedSSHDialPort = %d, want the value on entry, %d", routedSSHDialPort, entry)
	}
}

// TestSSHPortSeam_ProductionPortAtRest (S3) pins the production port against
// a literal. It is only a real check because no test in this package writes
// that literal back: every cleanup restores the value it found on entry.
func TestSSHPortSeam_ProductionPortAtRest(t *testing.T) {
	if routedSSHDialPort != 22 {
		t.Errorf("routedSSHDialPort = %d at rest, want 22", routedSSHDialPort)
	}
}

// TestSSHPortSeam_ProbeIsRejectedOutsideATestBinary (S5) runs
// testdata/sshportprobe, a non-test main that calls the exported setter,
// and requires it to die at the gate. It is the only test that can observe
// the argument the exported wrapper passes: S1 calls the inner function with
// a literal false and cannot see a wrapper that passes true.
func TestSSHPortSeam_ProbeIsRejectedOutsideATestBinary(t *testing.T) {
	// Bounded for the same reason as the other probes: a wedged toolchain
	// must fail this test, not hang the package until the suite timeout.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "go", "run", "./testdata/sshportprobe").CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("`go run ./testdata/sshportprobe` did not finish within the deadline; "+
			"this is a toolchain problem, not a gate failure:\n%s", out)
	}
	if err == nil {
		t.Fatalf("the probe SUCCEEDED from a non-test binary; the gate is gone:\n%s", out)
	}
	if !strings.Contains(string(out), "called outside a test binary") {
		t.Fatalf("probe failed, but not at the gate — check the toolchain rather than assuming a kill:\nerr=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "REDIRECTED") {
		t.Fatalf("the probe redirected the SSH port before dying:\n%s", out)
	}
}

// sshPortSeamFile is the ONE non-test file permitted to mention any of the
// names below. Path-exact on purpose, as in the other seam guards.
const sshPortSeamFile = "internal/pve/routed.go"

var (
	// The setter's own declaration is a bare identifier in routed.go; a
	// reference from any other package is a selector. Both are fenced.
	tgtSSHPortSetterDecl = sourceguard.Target{Name: "SetSSHPortForIntegrationTests"}
	tgtSSHPortSetterCall = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/pve", Name: "SetSSHPortForIntegrationTests"}
	// The inner half: forbidding only the wrapper would leave another file
	// in package pve free to pass true and bypass the gate.
	tgtSSHPortSetterInner = sourceguard.Target{Name: "setSSHPortForTests"}
	// The var itself: forbidding only the setters would leave another file
	// in package pve free to assign it directly.
	tgtSSHPortVar = sourceguard.Target{Name: "routedSSHDialPort"}
)

// TestSSHPortSeam_NoProductionReferences (S4) is the static half: no
// non-test file in the module except routed.go may mention the seam at all.
func TestSSHPortSeam_NoProductionReferences(t *testing.T) {
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       seamModuleRoot,
		AllowFiles: []string{sshPortSeamFile},
	}, []sourceguard.Target{
		tgtSSHPortSetterDecl, tgtSSHPortSetterCall, tgtSSHPortSetterInner, tgtSSHPortVar,
	})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("the RoutedClient SSH port seam is referenced outside %s:\n%s\n"+
			"Only that one file may touch the port RoutedClient dials. If a new "+
			"legitimate site really exists, it needs its own review, not an entry here.",
			sshPortSeamFile, strings.Join(lines, "\n"))
	}

	// ANTI-VACUITY. Each target below has a real site in routed.go; if the
	// walker stops finding one, "no violations" above has stopped meaning
	// anything. tgtSSHPortSetterCall is deliberately absent: it has no
	// legitimate non-test site anywhere, and the ImportPath form's mechanism
	// is proven by sourceguard's own alias fixture.
	for _, tgt := range []sourceguard.Target{tgtSSHPortSetterDecl, tgtSSHPortSetterInner, tgtSSHPortVar} {
		if got := res.Allowed(sshPortSeamFile, tgt); len(got) == 0 {
			t.Errorf("target %s matched nothing in %s — the guard is no longer looking at the code it claims to guard",
				tgt, sshPortSeamFile)
		}
	}

	// ...and the walk has to have covered the module, not some subtree.
	if len(res.Parsed) < 70 {
		t.Errorf("walked only %d non-test files from %s; the module has ~80 — wrong root?", len(res.Parsed), seamModuleRoot)
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Errorf("the walk never reached cmd/pveforge/main.go, so it did not cover the module")
	}
	// The probe is a non-test file that calls the forbidden setter. It must
	// be invisible to this walk, or the guard fails against its own fixture.
	if res.Reached("internal/pve/testdata/sshportprobe/main.go") {
		t.Error("the walk descended into testdata and will now report the probe as a violation")
	}
}

// restoreSSHPortOnEntry puts the port back to whatever it held when called —
// never to a literal, which would mask a changed production value from S3.
func restoreSSHPortOnEntry(t *testing.T) {
	t.Helper()
	port := routedSSHDialPort
	t.Cleanup(func() { routedSSHDialPort = port })
}

func requireSSHPortPanic(t *testing.T, want string, f func()) {
	t.Helper()
	restoreSSHPortOnEntry(t)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("expected a panic containing %q, got none", want)
		}
		if msg, _ := r.(string); !strings.Contains(msg, want) {
			t.Fatalf("panic %v does not contain %q", r, want)
		}
	}()
	f()
}
