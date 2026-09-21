package pve

import (
	"fmt"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// TestMain is this package's SINGLE process-wide test setup hook.
//
// Go permits exactly one TestMain per test package. Anything else that needs
// process-wide setup MERGES INTO THIS FUNCTION rather than adding its own — a
// second one does not conflict at review time, it fails to compile.
//
// It arms internal/netguard's loopback trip-wire over BOTH seams: Install
// swaps http.DefaultTransport for a loopback-only clone, and
// sshexec.SetDialGuardForTests covers internal/sshexec's own net.Dialer,
// which the HTTP seam cannot see. Neither seam alone covers this package.
//
// Install MUST precede m.Run, and not merely by convention: a swap installed
// after a pve.NewClient(InsecureTLS: true) is completely invisible to it,
// because that client already took its own Clone() of the global at
// construction. Nothing may construct a client before this point.
//
// Install in order and tear down in reverse. The teardown is written out
// longhand rather than deferred ON PURPOSE: os.Exit does not run deferred
// functions, so a `defer restore()` here would silently never fire.
func TestMain(m *testing.M) {
	restoreDial := netguard.Install()
	restoreSSHGuard := sshexec.SetDialGuardForTests(netguard.Guard)

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
