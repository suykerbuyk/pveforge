package idempotent

import (
	"context"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// This package's companion to internal/netguard's loopback trip-wire.
//
// A trip-wire never observed tripping has not been shown to work, and the
// suite going green proves only that nothing dialed out — which is equally
// what a trip-wire that was never armed reports. These two tests are the
// separate observer: each makes a DELIBERATE off-loopback dial, one down each
// seam, and requires it to be refused with netguard's own sentinel.
//
// They are per-package on purpose. The wiring lives in this package's
// TestMain, a Go construct with no cross-package reuse, so "did THIS package
// arm the wire" can only be answered inside it. Deleting either line from
// testmain_test.go turns exactly one of these red.

// TestNetguardTripwire_HTTPSeamRefusesNonLoopback covers the
// http.DefaultTransport seam (netguard.Install).
func TestNetguardTripwire_HTTPSeamRefusesNonLoopback(t *testing.T) {
	netguard.AssertHTTPSeamRefuses(t)
}

// TestNetguardTripwire_SSHSeamRefusesNonLoopback covers the second seam,
// internal/sshexec's own net.Dialer, which the HTTP swap cannot see. Without
// sshexec.SetDialGuardForTests in this package's TestMain, this dial would
// leave the machine.
func TestNetguardTripwire_SSHSeamRefusesNonLoopback(t *testing.T) {
	netguard.MustRefuse(t, "sshexec", func() error {
		var captured sshexec.CapturedHostKey
		_, err := sshexec.DialWithPassword(context.Background(),
			netguard.DeliberateNonLoopbackAddr, "root", "unused",
			sshexec.CaptureHostKeyCallback(&captured))
		return err
	})
}

// TestNoParallelTests pins what netguard's ExpectViolation depends on: it
// scopes a deliberate violation by wall-clock nesting rather than by
// goroutine, so a parallel test could have its real violation excused by an
// unrelated companion.
func TestNoParallelTests(t *testing.T) {
	netguard.AssertNoParallel(t)
}

// TestNoPreInstallDialer pins the other side of the ordering constraint the
// package doc calls load-bearing. Install must precede m.Run; this requires
// that nothing in this package builds a client before TestMain is entered at
// all. Go runs package-level var initialisers and init() first, and a client
// built there captures the PRISTINE http.DefaultTransport — invisible to both
// seams, dialing for real, with the package still reporting ok.
func TestNoPreInstallDialer(t *testing.T) {
	netguard.AssertNoPreInstallDialer(t)
}
