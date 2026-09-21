package netguard

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// probePkg is the badly behaved package under testdata/. It is named by an
// explicit path rather than matched by a pattern: `go test ./...` does not
// reach into testdata, which is exactly why it is safe to keep a
// deliberately-failing package there.
const probePkg = "./internal/netguard/testdata/probe/"

// moduleRoot is where the subprocess runs. internal/netguard is one level
// down from internal, two from the module root.
const moduleRoot = "../.."

// TestCheckFailsThePackageOnASwallowedViolation is the fail-closed proof, and
// the only test in this module that can make it.
//
// The property under test lives in TestMain — `if err := netguard.Check();
// err != nil && code == 0 { code = 1 }` — which runs once and owns the exit
// status, so no in-process assertion can observe it. Mutants that delete the
// Check call, or make Check always return nil, or make Guard record nothing,
// survive every other test in this package and are killed only here.
//
// The assertion is deliberately on a COMBINATION rather than on the exit
// status alone:
//
//   - the child must exit NON-ZERO, and
//   - its output must contain "PASS", proving the test itself passed and the
//     failure came from TestMain's Check rather than from the test, a compile
//     error, or a panic, and
//   - its output must name the offending address, proving it failed for the
//     right reason.
//
// An exit-status check on its own would be satisfied by a child that simply
// failed to build — the classic green-looking instrument measuring the wrong
// object.
func TestCheckFailsThePackageOnASwallowedViolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", probePkg)
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	got := string(out)

	if err == nil {
		t.Fatalf("the probe package PASSED. A test that swallowed a non-loopback "+
			"dial was allowed to leave the package green, so the trip-wire does "+
			"not fail closed.\n%s", got)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("could not run the probe (%v); this test proved nothing.\n%s", err, got)
	}

	if !strings.Contains(got, "PASS") {
		t.Errorf("the probe failed, but its own test did not PASS — so it failed to "+
			"build, panicked, or errored for some reason other than Check. This "+
			"test is measuring the wrong thing.\n%s", got)
	}
	if !strings.Contains(got, DeliberateNonLoopbackAddr) {
		t.Errorf("the probe failed without naming %s, so it did not fail because of "+
			"the trip-wire.\n%s", DeliberateNonLoopbackAddr, got)
	}
}

// TestProbeIsInvisibleToTheModuleBuild keeps the deliberately-failing package
// above from ever being picked up by `make test`. If testdata's exclusion
// stopped applying, the probe would fail the real suite, and the failure
// would look like a genuine trip-wire violation rather than a packaging
// mistake.
func TestProbeIsInvisibleToTheModuleBuild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "list", "./...")
	cmd.Dir = moduleRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list ./...: %v", err)
	}
	listed := string(out)
	if strings.Contains(listed, "testdata") {
		t.Errorf("a testdata package is in ./..., so `make test` will run the "+
			"deliberately-failing probe:\n%s", listed)
	}
	// Anti-vacuity: the grep above proves nothing if the listing is empty or
	// did not include this package.
	if !strings.Contains(listed, "internal/netguard") {
		t.Errorf("go list ./... did not report internal/netguard, so the check "+
			"above looked at the wrong tree:\n%s", listed)
	}
}

// TestSeam_WeakProbeIsRejectedOutsideATestBinary closes the gap that the
// flag-passed-in split opens.
//
// Both seams' inner functions take inTestBinary as a parameter so the refusal
// branch carries real coverage from an ordinary in-process test. The cost is
// that a mutant which changes only the exported wrapper — `return
// install(true)`, `return setDialGuard(guard, true)` — survives every
// in-process assertion, because those tests call the inner function directly
// and never observe what the wrapper passes.
//
// Only a binary that `go test` did not build can show that testing.Testing()
// is false there and that the wrappers actually consult it. Mutants R1b and
// B4b are killed here and nowhere else.
func TestSeam_WeakProbeIsRejectedOutsideATestBinary(t *testing.T) {
	for _, tc := range []struct {
		seam string
		want string
	}{
		{"netguard", "netguard: Install called outside a test binary"},
		{"sshexec", "sshexec: SetDialGuardForTests called outside a test binary"},
	} {
		t.Run(tc.seam, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, "go", "run", "./internal/netguard/testdata/weakprobe", tc.seam)
			cmd.Dir = moduleRoot
			out, err := cmd.CombinedOutput()
			got := string(out)

			if err == nil {
				t.Fatalf("the %s seam accepted a call from a NON-TEST binary; its runtime gate is gone.\n%s", tc.seam, got)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("could not run the weak probe (%v); this test proved nothing.\n%s", err, got)
			}
			// Asserting on the message, not just on a non-zero exit: a probe
			// that failed to compile also exits non-zero, and would make this
			// test pass while proving the opposite of what it claims.
			if !strings.Contains(got, tc.want) {
				t.Errorf("the probe died, but not on the %s gate — so it failed to build, or died for some other reason.\nwant substring: %s\ngot:\n%s", tc.seam, tc.want, got)
			}
		})
	}
}

// TestSeam_WeakProbeIsInvisibleToTheSourceGuard pins the other half of the
// weak probe's safety: it is a NON-TEST file that deliberately references the
// very names TestSeam_NoProductionReferences forbids. If the module walk ever
// descended into testdata, the guard would report this probe as a violation
// and the two tests would be permanently in conflict.
func TestSeam_WeakProbeIsInvisibleToTheSourceGuard(t *testing.T) {
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       moduleRoot,
		AllowFiles: []string{netguardFile, sshexecFile},
	}, []sourceguard.Target{tgtInstallBare, tgtDialGuardBare})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	if res.Reached("internal/netguard/testdata/weakprobe/main.go") {
		t.Error("the walk descended into testdata and will now report the weak probe as a violation")
	}
	// Anti-vacuity: Reached returning false proves nothing if the walk went
	// nowhere at all.
	if !res.Reached(netguardFile) {
		t.Errorf("the walk never reached %s, so the check above looked at the wrong tree", netguardFile)
	}
}
