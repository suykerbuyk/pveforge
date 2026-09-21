package bootstrap

import (
	"fmt"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// testWorkFactor is the scrypt work factor this package's tests encrypt at.
//
// Every one of these tests writes and reads ciphertext in its own t.TempDir(),
// and none of them asserts anything about the KDF's parameters — that is
// internal/roster/kdf_guard_test.go's job, and it still requires production's
// 18 exactly. At age's default this package performs 79 derivations and takes
// roughly 500s under -race; at 10 it takes about 3s, with an identical set of
// test results.
const testWorkFactor = 10

// TestMain is this package's SINGLE process-wide test setup hook.
//
// Go permits exactly one TestMain per test package. Anything else that needs
// process-wide setup MERGES INTO THIS FUNCTION rather than adding its own —
// a second one does not conflict at review time, it fails to compile. In
// particular pveforge-test-loopback-tripwire installs a dialer hook that
// fails this package if any dial leaves loopback; it goes at the marked point
// below.
//
// Install in order and tear down in reverse, at the marked points. The
// teardown is written out longhand rather than deferred ON PURPOSE: os.Exit
// does not run deferred functions, so a `defer restore()` here would silently
// never fire, and that is exactly how a later contributor merging a hook
// loses its teardown.
func TestMain(m *testing.M) {
	restoreWorkFactor := roster.SetScryptWorkFactorForTests(testWorkFactor)
	// --- additional process-wide setup installs here ---
	// internal/netguard's loopback trip-wire, over BOTH seams: Install swaps
	// http.DefaultTransport for a loopback-only clone, and the sshexec dial
	// guard covers internal/sshexec's own net.Dialer, which the HTTP seam
	// cannot see. Install MUST precede m.Run — a swap installed after a
	// pve.NewClient(InsecureTLS: true) is invisible to it, because that
	// client already took its own Clone() of the global at construction.
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

	// --- and tears down here, in reverse order of installation ---
	restoreSSHGuard()
	restoreDial()
	restoreWorkFactor()

	os.Exit(code)
}
