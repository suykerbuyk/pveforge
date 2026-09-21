package netguard

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// DeliberateNonLoopbackAddr is the address every companion aims at.
//
// 203.0.113.0/24 is TEST-NET-3 (RFC 5737), reserved for documentation and
// guaranteed not to be a real host, and discard/9 is not a service anyone
// runs. That matters for the mutation runs specifically: a mutant that stops
// refusing makes this dial for real, and it must not be able to reach
// anything if it does. The mutation harness additionally runs inside a
// loopback-only network namespace, so a leaked dial is unroutable as well as
// unrouted — two independent containments, because the whole point of the
// mutant is that the first one is broken.
const DeliberateNonLoopbackAddr = "203.0.113.1:9"

// companionTimeout bounds a deliberate dial. The trip-wire refuses before any
// syscall, so a correctly wired seam returns instantly and never waits this
// out; the bound exists only so that a MUTANT which stops refusing fails fast
// instead of hanging the suite for 30s on an unroutable address.
const companionTimeout = 2 * time.Second

// AssertHTTPSeamRefuses drives a real HTTP request at a non-loopback address
// through http.DefaultTransport and requires the trip-wire to refuse it.
//
// It is exported, and shared by all five wired packages, for the reason the
// kdf unit gave for refactoring its own second path away: two copies of an
// assertion are how the copies drift, and a companion that drifted into
// asserting something weaker would be invisible — it would still pass.
//
// This is the test a forgotten netguard.Install() in a package's TestMain
// turns red, and it is also what proves the seam is armed EARLY enough: an
// InsecureTLS client built before Install would never consult the swapped
// global at all.
func AssertHTTPSeamRefuses(t *testing.T) {
	t.Helper()
	ExpectViolation(t)

	before, _, _ := Stats()

	c := &http.Client{Transport: http.DefaultTransport, Timeout: companionTimeout}
	resp, err := c.Get("http://" + DeliberateNonLoopbackAddr + "/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatalf("an HTTP request to %s succeeded; the loopback trip-wire is not armed on this package's http.DefaultTransport", DeliberateNonLoopbackAddr)
	}
	// Asserting on the SENTINEL, not merely on "an error happened": a dial to
	// an unroutable address fails on its own, so a bare error check would be
	// satisfied by the ordinary failure and would survive a mutant that
	// stopped refusing.
	if !errors.Is(err, ErrNonLoopbackDial) {
		t.Fatalf("HTTP request to %s failed, but NOT with netguard's refusal — the trip-wire did not fire and the dial went out for real.\ngot: %v", DeliberateNonLoopbackAddr, err)
	}

	assertRecorded(t, before)
}

// AssertSeamRefusedAndRecorded is the second half of a companion's job, for
// the SSH seam, whose dial cannot be driven from this package (netguard must
// never import internal/sshexec — sshexec's tests are in-package, so it would
// be an import cycle). Each package dials through sshexec itself and hands
// the resulting error here.
func AssertSeamRefusedAndRecorded(t *testing.T, seam string, before int, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: a dial to %s succeeded; the trip-wire is not armed on this seam", seam, DeliberateNonLoopbackAddr)
	}
	if !errors.Is(err, ErrNonLoopbackDial) {
		t.Fatalf("%s: the dial to %s failed, but NOT with netguard's refusal — the trip-wire did not fire and the dial went out for real.\ngot: %v", seam, DeliberateNonLoopbackAddr, err)
	}
	assertRecorded(t, before)
}

// assertRecorded is the anti-vacuity half. Refusing is not enough on its own:
// if Guard refused without RECORDING, Check would be blind to a violation
// that some other test swallowed, which is the exact hole this unit exists to
// close. So a companion proves both halves, and proves the wire was armed at
// all by requiring the observed count to have moved.
func assertRecorded(t *testing.T, before int) {
	t.Helper()
	observed, refused, expectedCount := Stats()
	if observed <= before {
		t.Errorf("the trip-wire vetted no dial (observed %d -> %d); it was never armed, and a zero refusal count from it would mean nothing", before, observed)
	}
	if refused == 0 {
		t.Error("the dial was refused but nothing was RECORDED; Check would be blind to a violation another test swallowed")
	}
	if expectedCount == 0 {
		t.Error("ExpectViolation registered nothing, so this companion's own deliberate violation would fail the package")
	}
}

// MustRefuse is a convenience for a companion that has already produced the
// error, when it wants the before-count taken for it.
func MustRefuse(t *testing.T, seam string, dial func() error) {
	t.Helper()
	ExpectViolation(t)
	before, _, _ := Stats()
	AssertSeamRefusedAndRecorded(t, seam, before, dial())
}
