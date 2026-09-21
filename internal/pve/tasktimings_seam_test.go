package pve

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// The four layers holding SetTaskTimingsForTests shut, in the shape
// internal/roster/kdf_seam_test.go and internal/netguard/seam_test.go
// established: a runtime testing.Testing() gate (S1, and S5 through a real
// non-test binary), argument checks (S1b), a restore round trip (S2), the
// production values pinned at rest (S3), and a module-wide static guard (S4).

// TestTaskTimingsSeam_RefusesOutsideATestBinary (S1) drives the inner
// function with the gate's answer forced to false.
func TestTaskTimingsSeam_RefusesOutsideATestBinary(t *testing.T) {
	requireTaskTimingsPanic(t, "called outside a test binary", func() {
		setTaskTimings(time.Millisecond, time.Second, false)
	})
}

// TestTaskTimingsSeam_RejectsInvalidTimings (S1b): a non-positive interval
// spins the poll loop, and a timeout that is non-positive or shorter than
// one interval ends every wait before a second poll.
func TestTaskTimingsSeam_RejectsInvalidTimings(t *testing.T) {
	for _, c := range []struct {
		name              string
		interval, timeout time.Duration
	}{
		{"zero interval", 0, time.Second},
		{"zero timeout", time.Millisecond, 0},
		{"negative interval", -time.Millisecond, time.Second},
		{"timeout shorter than interval", 2 * time.Second, time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			requireTaskTimingsPanic(t, "invalid timings", func() {
				restore := setTaskTimings(c.interval, c.timeout, true)
				restore() // unreachable unless the check is gone; keep the vars clean either way
			})
		})
	}
}

// TestTaskTimingsSeam_RestoresPrevious (S2) is the round trip: lower the
// timings, observe WaitForTask honouring them, restore, observe production's
// values again. A no-op restore would silently hand one test's 1ms interval
// to every later test in the package.
func TestTaskTimingsSeam_RestoresPrevious(t *testing.T) {
	restoreOnEntry(t)
	entryInterval, entryTimeout := defaultTaskPollInterval, defaultTaskWaitTimeout

	restore := SetTaskTimingsForTests(time.Millisecond, 2*time.Second)

	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.running(), s.running(), s.running(), s.stopped("OK"))
	start := time.Now()
	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask while lowered: %v", err)
	}
	// Three running polls at the production 1s interval take 3s; the
	// lowered interval must make it far quicker, or the seam is doing
	// nothing and the restore assertion below would be vacuous.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("four polls took %s while lowered to 1ms — the seam had no effect", elapsed)
	}
	requirePolls(t, s, 4)

	restore()

	if defaultTaskPollInterval != entryInterval || defaultTaskWaitTimeout != entryTimeout {
		t.Errorf("restore() left interval=%s timeout=%s, want the values on entry, %s and %s",
			defaultTaskPollInterval, defaultTaskWaitTimeout, entryInterval, entryTimeout)
	}
}

// TestTaskTimingsSeam_ProductionDefaultsAtRest (S3) pins the production
// configuration against literals, so neither a changed var nor a drifted
// TaskWaitCeiling passes. It is only a real check because no test in this
// package writes those literals back: every cleanup restores the values it
// found on entry (restoreOnEntry), never the production values themselves.
// A cleanup that did would make this test observe its own fixture.
func TestTaskTimingsSeam_ProductionDefaultsAtRest(t *testing.T) {
	if defaultTaskPollInterval != time.Second {
		t.Errorf("defaultTaskPollInterval = %s at rest, want 1s", defaultTaskPollInterval)
	}
	if TaskWaitCeiling != 10*time.Minute {
		t.Errorf("TaskWaitCeiling = %s, want 10m", TaskWaitCeiling)
	}
	if defaultTaskWaitTimeout != TaskWaitCeiling {
		t.Errorf("defaultTaskWaitTimeout = %s at rest, want TaskWaitCeiling (%s)", defaultTaskWaitTimeout, TaskWaitCeiling)
	}
}

// TestTaskTimingsSeam_WeakProbeIsRejectedOutsideATestBinary (S5) runs
// testdata/weakprobe, a non-test main that calls the exported setter, and
// requires it to die at the gate. It is the only test that can observe the
// argument the exported wrapper passes: S1 calls the inner function with a
// literal false and cannot see a wrapper that passes true.
func TestTaskTimingsSeam_WeakProbeIsRejectedOutsideATestBinary(t *testing.T) {
	// Bounded for the same reason as roster's probe: a wedged toolchain
	// must fail this test, not hang the package until the suite timeout.
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
	if !strings.Contains(string(out), "called outside a test binary") {
		t.Fatalf("probe failed, but not at the gate — check the toolchain rather than assuming a kill:\nerr=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "WEAKENED") {
		t.Fatalf("the probe lowered the timings before dying:\n%s", out)
	}
}

// seamModuleRoot is the module root, two levels up from internal/pve.
const seamModuleRoot = "../.."

// taskTimingsSeamFile is the ONE non-test file permitted to mention any of
// the names below. Path-exact on purpose, as in the roster and netguard
// seam guards.
const taskTimingsSeamFile = "internal/pve/task.go"

var (
	// The setter's own declaration is a bare identifier in task.go; a
	// reference from any other package is a selector. Both are fenced.
	tgtTimingsSetterDecl = sourceguard.Target{Name: "SetTaskTimingsForTests"}
	tgtTimingsSetterCall = sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/pve", Name: "SetTaskTimingsForTests"}
	// The inner half: forbidding only the wrapper would leave another
	// file in package pve free to pass true and bypass the gate.
	tgtTimingsSetterInner = sourceguard.Target{Name: "setTaskTimings"}
	// The vars themselves: forbidding only the setters would leave another
	// file in package pve free to assign them directly.
	tgtTimingsInterval = sourceguard.Target{Name: "defaultTaskPollInterval"}
	tgtTimingsTimeout  = sourceguard.Target{Name: "defaultTaskWaitTimeout"}
)

// TestTaskTimingsSeam_NoProductionReferences (S4) is the static half: no
// non-test file in the module except task.go may mention the seam at all.
func TestTaskTimingsSeam_NoProductionReferences(t *testing.T) {
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       seamModuleRoot,
		AllowFiles: []string{taskTimingsSeamFile},
	}, []sourceguard.Target{
		tgtTimingsSetterDecl, tgtTimingsSetterCall, tgtTimingsSetterInner,
		tgtTimingsInterval, tgtTimingsTimeout,
	})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}

	if v := res.Violations(); len(v) > 0 {
		var lines []string
		for _, ref := range v {
			lines = append(lines, "  "+ref.String())
		}
		t.Errorf("the WaitForTask timing seam is referenced outside %s:\n%s\n"+
			"Only that one file may touch the poll interval or wait timeout. If a "+
			"new legitimate site really exists, it needs its own review, not an entry here.",
			taskTimingsSeamFile, strings.Join(lines, "\n"))
	}

	// ANTI-VACUITY. Each target below has a real site in task.go; if the
	// walker stops finding one, "no violations" above has stopped meaning
	// anything. tgtTimingsSetterCall is deliberately absent: it has no
	// legitimate non-test site anywhere, and the ImportPath form's
	// mechanism is proven by sourceguard's own alias fixture.
	for _, tgt := range []sourceguard.Target{
		tgtTimingsSetterDecl, tgtTimingsSetterInner, tgtTimingsInterval, tgtTimingsTimeout,
	} {
		if got := res.Allowed(taskTimingsSeamFile, tgt); len(got) == 0 {
			t.Errorf("target %s matched nothing in %s — the guard is no longer looking at the code it claims to guard",
				tgt, taskTimingsSeamFile)
		}
	}

	// ...and the walk has to have covered the module, not some subtree.
	if len(res.Parsed) < 70 {
		t.Errorf("walked only %d non-test files from %s; the module has ~80 — wrong root?", len(res.Parsed), seamModuleRoot)
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Errorf("the walk never reached cmd/pveforge/main.go, so it did not cover the module")
	}
	// The weakprobe is a non-test file that calls the forbidden setter. It
	// must be invisible to this walk, or the guard fails against its own
	// fixture.
	if res.Reached("internal/pve/testdata/weakprobe/main.go") {
		t.Error("the walk descended into testdata and will now report the weakprobe as a violation")
	}
}

// restoreOnEntry puts both timing vars back to whatever they held when it
// was called — never to literals, which would mask a changed production
// value from S3.
func restoreOnEntry(t *testing.T) {
	t.Helper()
	interval, timeout := defaultTaskPollInterval, defaultTaskWaitTimeout
	t.Cleanup(func() { defaultTaskPollInterval, defaultTaskWaitTimeout = interval, timeout })
}

func requireTaskTimingsPanic(t *testing.T, want string, f func()) {
	t.Helper()
	restoreOnEntry(t)
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
