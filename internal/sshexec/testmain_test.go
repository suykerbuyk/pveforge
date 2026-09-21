package sshexec

import (
	"fmt"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
)

// TestMain is this package's SINGLE process-wide test setup hook.
//
// Go permits exactly one TestMain per test package. Anything else that needs
// process-wide setup MERGES INTO THIS FUNCTION rather than adding its own — a
// second one does not conflict at review time, it fails to compile.
//
// It arms internal/netguard's loopback trip-wire over both seams. This
// package's tests are in-package (package sshexec), so the SSH seam is wired
// through the unexported dialGuard's own setter without a qualifier — and it
// is the reason netguard must never import internal/sshexec: this file's
// import of netguard would then be a cycle.
//
// Install in order and tear down in reverse. The teardown is written out
// longhand rather than deferred ON PURPOSE: os.Exit does not run deferred
// functions, so a `defer restore()` here would silently never fire.
func TestMain(m *testing.M) {
	restoreDial := netguard.Install()
	restoreSSHGuard := SetDialGuardForTests(netguard.Guard)

	code := m.Run()

	// Check BEFORE the restores: it reads the recorder restoreDial tears
	// down. And it must never turn a red suite green, so it only ever raises
	// the code.
	if err := netguard.Check(); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}

	restoreSSHGuard()
	restoreDial()

	os.Exit(code)
}
