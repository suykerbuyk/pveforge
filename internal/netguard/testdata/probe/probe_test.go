// Package probe is netguard's fail-closed probe, and it is a deliberately
// BADLY BEHAVED test package.
//
// It lives under testdata/ so the module build never sees it: `go list ./...`
// does not report it and `make test` does not run it. Its own parent,
// internal/netguard's TestCheckFailsThePackageOnASwallowedViolation, runs it
// as a subprocess and REQUIRES it to fail.
//
// It exists because the thing it proves cannot be proven from inside a normal
// test. The wiring that makes the trip-wire fail closed —
//
//	if err := netguard.Check(); err != nil && code == 0 { code = 1 }
//
// — lives in TestMain, which runs exactly once and owns the process's exit
// status. No in-process test can observe its own TestMain's effect on that
// status, so a mutant that deletes the Check call, or makes Check always
// return nil, survives every in-process assertion in this repo. Only a
// separate process can see it, which is what this package is for. It follows
// internal/roster/testdata/weakprobe's precedent.
//
// NOTE for anyone counting tests in this module: this file declares a Test
// the toolchain never builds as part of ./... — the hazard that a whole-tree
// `find -name '*_test.go'` walks into. Count with per-package
// single-directory globs.
package probe

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/netguard"
)

// TestMain is the wiring under test: the same shape every real package uses.
func TestMain(m *testing.M) {
	restoreDial := netguard.Install()

	code := m.Run()

	if err := netguard.Check(); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}

	restoreDial()

	os.Exit(code)
}

// TestSwallowsAViolationAndPasses is the badly behaved test: it makes a
// deliberate off-loopback dial, never registers it with
// netguard.ExpectViolation, ignores the error it gets back, and PASSES.
//
// That is precisely the laundering this unit exists to stop. Refusal alone
// would not catch it — the dial is refused, and this test simply does not
// care. Only the recording half, read by Check after m.Run, turns the
// PACKAGE red while the TEST stays green. The parent asserts on exactly that
// combination: child output containing "PASS" and a non-zero exit status.
func TestSwallowsAViolationAndPasses(t *testing.T) {
	c := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + netguard.DeliberateNonLoopbackAddr + "/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	_ = err // swallowed ON PURPOSE; this is the defect being modelled
}
