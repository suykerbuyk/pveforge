package sshexec

import (
	"context"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
)

// This package's companion to internal/netguard's loopback trip-wire.
//
// A trip-wire never observed tripping has not been shown to work, and the
// suite going green proves only that nothing dialed out — which is equally
// what a trip-wire that was never armed reports. These tests are the separate
// observer: each makes a DELIBERATE off-loopback dial and requires it to be
// refused with netguard's own sentinel.
//
// This package matters more than the other four, because the seam being
// exercised is THIS package's: dial's guard hook at client.go is the only
// thing standing between an sshexec caller and a real host, and no
// http.DefaultTransport swap can see it.

// TestNetguardTripwire_DialRefusesNonLoopback drives the guard through the
// unexported dial that both Dial and DialWithPassword funnel into. Mutants
// B1 (delete the guard block), B2 (call it and ignore the error) and B3
// (SetDialGuardForTests stores nil) all turn this red.
func TestNetguardTripwire_DialRefusesNonLoopback(t *testing.T) {
	netguard.MustRefuse(t, "sshexec.DialWithPassword", func() error {
		var captured CapturedHostKey
		_, err := DialWithPassword(context.Background(),
			netguard.DeliberateNonLoopbackAddr, "root", "unused",
			CaptureHostKeyCallback(&captured))
		return err
	})
}

// TestNetguardTripwire_KeyAuthDialIsGuardedToo proves the guard sits in the
// shared dial rather than on one entry point. Dial parses its key first, so
// this also confirms the refusal happens at the dial and not somewhere
// earlier that DialWithPassword happens to share.
func TestNetguardTripwire_KeyAuthDialIsGuardedToo(t *testing.T) {
	kp, err := GenerateEd25519Keypair("netguard-tripwire")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	netguard.MustRefuse(t, "sshexec.Dial", func() error {
		var captured CapturedHostKey
		_, dialErr := Dial(context.Background(),
			netguard.DeliberateNonLoopbackAddr, "root", kp.PrivateKeyPEM,
			CaptureHostKeyCallback(&captured))
		return dialErr
	})
}

// TestNetguardTripwire_HTTPSeamRefusesNonLoopback covers the other seam. This
// package makes no HTTP requests of its own (it imports net/http nowhere, in
// production or in tests), so this asserts only that its TestMain armed the
// HTTP seam as well — which matters because a future test here that reached
// for an httptest server would otherwise be unguarded.
func TestNetguardTripwire_HTTPSeamRefusesNonLoopback(t *testing.T) {
	netguard.AssertHTTPSeamRefuses(t)
}

// TestSeam_RefusesOutsideATestBinary drives the dial guard's refusal branch
// directly, in process, by passing inTestBinary=false. That is the whole
// reason setDialGuard takes the flag rather than reading testing.Testing():
// the branch is then covered by the suite's own coverage profile, which a
// subprocess could never contribute to.
//
// Mutant B4 removes the gate; B4b has the exported wrapper pass true
// unconditionally.
func TestSeam_RefusesOutsideATestBinary(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("setDialGuard(_, false) returned instead of panicking; the gate is gone")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "outside a test binary") {
			t.Fatalf("panic %q does not say why it refused", r)
		}
	}()
	restore := setDialGuard(nil, false)
	restore()
}

// TestSeam_RestoreputsThePreviousGuardBack keeps SetDialGuardForTests from
// leaking a hook past the scope that installed it — which, since this file's
// own TestMain installs one for the whole package, would otherwise be
// invisible.
func TestSeam_RestorePutsThePreviousGuardBack(t *testing.T) {
	sentinel := func(string) error { return nil }
	restore := setDialGuard(sentinel, true)
	if dialGuard == nil {
		t.Fatal("setDialGuard did not install the hook")
	}
	restore()
	if dialGuard == nil {
		t.Error("restore left the package with no guard at all; this package's TestMain had installed one")
	}
	// And the restored one must be the TestMain's, not the sentinel: a
	// non-loopback address has to be refused again. That probe goes through
	// the real recording guard, so it must be registered like any other
	// deliberate violation or it would fail this package at Check time.
	netguard.ExpectViolation(t)
	if err := dialGuard(netguard.DeliberateNonLoopbackAddr); err == nil {
		t.Error("after restore the sentinel was still installed, so the hook leaked past its scope")
	}
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
