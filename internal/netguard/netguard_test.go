package netguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// reset puts the package globals back to a known state and restores them
// afterwards, so each test below starts from a clean recorder without
// depending on which order the tests ran in.
func reset(t *testing.T) {
	t.Helper()
	mu.Lock()
	origV, origO, origE, origI := violations, observedDials, expecting, installed
	violations, observedDials, expecting = nil, 0, 0
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		violations, observedDials, expecting, installed = origV, origO, origE, origI
		mu.Unlock()
	})
}

// ---------------------------------------------------------------------------
// The predicate.
// ---------------------------------------------------------------------------

// TestCheckAddr_AllowsLoopback is the anti-vacuity floor for the predicate: a
// trip-wire that refused everything would pass every refusal test below and
// make the whole suite red, so the accept side has to be pinned too.
func TestCheckAddr_AllowsLoopback(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:0",
		"127.0.0.1:8006",
		"127.0.0.53:53",
		"[::1]:443",
		"localhost:22",
		"LOCALHOST:22", // RFC 6761 names are case-insensitive
	} {
		if err := CheckAddr(addr); err != nil {
			t.Errorf("CheckAddr(%q) refused a loopback destination: %v", addr, err)
		}
	}
}

// TestCheckAddr_RefusesNonLoopbackIP is mutant A4: dropping the IsLoopback
// check so any parseable IP passes.
func TestCheckAddr_RefusesNonLoopbackIP(t *testing.T) {
	for _, addr := range []string{
		"203.0.113.1:9",
		"10.0.0.10:8006",
		"192.168.1.1:22",
		"8.8.8.8:53",
		"0.0.0.0:80",
		"[2001:db8::1]:443",
	} {
		err := CheckAddr(addr)
		if err == nil {
			t.Errorf("CheckAddr(%q) allowed a non-loopback address", addr)
			continue
		}
		if !errors.Is(err, ErrNonLoopbackDial) {
			t.Errorf("CheckAddr(%q) refused, but not with the sentinel: %v", addr, err)
		}
	}
}

// TestCheckAddr_RefusesHostnamesBeforeResolution is mutant A5, the
// fail-closed one: treating an unparseable host as allowed. It is the mutant
// that matters most in this module, because "qa-pve-01.example.com" is a
// config-only host at twenty-odd sites and a deny-list would have missed it.
//
// The refusal must also happen WITHOUT resolving the name, which is why the
// predicate never calls net.Resolve*: a refused dial emits no DNS query.
func TestCheckAddr_RefusesHostnamesBeforeResolution(t *testing.T) {
	for _, addr := range []string{
		"qa-pve-01.example.com:8006",
		"pve.local:22",
		"example.com:443",
		"localhost.evil.example.com:80", // must not be fooled by a prefix
	} {
		err := CheckAddr(addr)
		if err == nil {
			t.Errorf("CheckAddr(%q) allowed a hostname; the predicate is no longer fail-closed", addr)
			continue
		}
		if !errors.Is(err, ErrNonLoopbackDial) {
			t.Errorf("CheckAddr(%q) refused, but not with the sentinel: %v", addr, err)
		}
		if !strings.Contains(err.Error(), "hostname") {
			t.Errorf("CheckAddr(%q) refused without saying it was a name: %v", addr, err)
		}
	}
}

// TestCheckAddr_RefusesWhatItCannotParse keeps a malformed address from
// falling through the SplitHostPort error into an allow.
func TestCheckAddr_RefusesWhatItCannotParse(t *testing.T) {
	for _, addr := range []string{"", "not-a-host-port", "127.0.0.1", "[::1]"} {
		if err := CheckAddr(addr); err == nil {
			t.Errorf("CheckAddr(%q) allowed an address it could not parse", addr)
		}
	}
}

// TestCheckNetwork_RefusesNonTCP pins the other fail-closed edge. Nothing in
// this module dials unix or udp today; if something starts, it gets reviewed
// rather than silently permitted.
func TestCheckNetwork_RefusesNonTCP(t *testing.T) {
	for _, n := range []string{"tcp", "tcp4", "tcp6"} {
		if err := checkNetwork(n); err != nil {
			t.Errorf("checkNetwork(%q) refused a tcp network: %v", n, err)
		}
	}
	for _, n := range []string{"unix", "unixgram", "udp", "udp4", "ip:icmp", ""} {
		if err := checkNetwork(n); err == nil {
			t.Errorf("checkNetwork(%q) allowed a non-tcp network", n)
		}
	}
}

// ---------------------------------------------------------------------------
// The recorder.
// ---------------------------------------------------------------------------

// TestGuard_RefusesAndRecords is mutants A3 (predicate always nil), A6
// (records but does not refuse) and A8 (refuses but records nothing) at once
// — the three are distinguished by which half of this test goes red.
func TestGuard_RefusesAndRecords(t *testing.T) {
	reset(t)

	err := Guard(DeliberateNonLoopbackAddr)
	if err == nil {
		t.Fatal("Guard allowed a non-loopback address")
	}
	if !errors.Is(err, ErrNonLoopbackDial) {
		t.Fatalf("Guard refused without the sentinel: %v", err)
	}

	observed, refused, expectedCount := Stats()
	if observed != 1 {
		t.Errorf("observed = %d, want 1: the vetting counter is what proves the wire was armed", observed)
	}
	if refused != 1 {
		t.Errorf("refused = %d, want 1: a refusal that is not recorded leaves Check blind", refused)
	}
	if expectedCount != 0 {
		t.Errorf("expected = %d, want 0: nothing registered this violation", expectedCount)
	}
}

// TestGuard_CountsAllowedDialsToo is what makes the observed count a real
// anti-vacuity instrument rather than a synonym for the refusal count. If
// only refusals were counted, "observed == 0" and "armed but clean" would be
// the same reading, which is the ambiguity the census had to resolve.
func TestGuard_CountsAllowedDialsToo(t *testing.T) {
	reset(t)

	if err := Guard("127.0.0.1:8006"); err != nil {
		t.Fatalf("Guard refused loopback: %v", err)
	}
	observed, refused, _ := Stats()
	if observed != 1 {
		t.Errorf("observed = %d, want 1: an ALLOWED dial must still be counted", observed)
	}
	if refused != 0 {
		t.Errorf("refused = %d, want 0", refused)
	}
}

// ---------------------------------------------------------------------------
// Check, and the expectation mechanism.
// ---------------------------------------------------------------------------

// TestCheck_ReportsUnexpectedViolations is mutant A7 (Check always nil) and
// A9 (Check treats everything as expected).
func TestCheck_ReportsUnexpectedViolations(t *testing.T) {
	reset(t)
	mu.Lock()
	installed = true
	mu.Unlock()

	_ = Guard(DeliberateNonLoopbackAddr)

	err := Check()
	if err == nil {
		t.Fatal("Check passed despite a recorded, unregistered violation")
	}
	if !strings.Contains(err.Error(), DeliberateNonLoopbackAddr) {
		t.Errorf("Check's report does not name the offending address: %v", err)
	}
}

// TestCheck_IgnoresRegisteredViolations is mutant A10: ExpectViolation as a
// no-op. Without it the companions' own deliberate dials would fail every
// package they run in.
func TestCheck_IgnoresRegisteredViolations(t *testing.T) {
	reset(t)
	mu.Lock()
	installed = true
	mu.Unlock()

	t.Run("registered", func(t *testing.T) {
		ExpectViolation(t)
		_ = Guard(DeliberateNonLoopbackAddr)
	})

	if err := Check(); err != nil {
		t.Fatalf("Check failed on a violation a companion had registered: %v", err)
	}
}

// TestExpectViolation_ScopeEndsWithTheSubtest is the one that keeps
// ExpectViolation from becoming a blanket amnesty: a registration made in one
// sub-test must not excuse a real violation made after it returns.
func TestExpectViolation_ScopeEndsWithTheSubtest(t *testing.T) {
	reset(t)
	mu.Lock()
	installed = true
	mu.Unlock()

	t.Run("registered", func(t *testing.T) {
		ExpectViolation(t)
		_ = Guard(DeliberateNonLoopbackAddr)
	})

	// ...and now, outside that sub-test's scope, an unregistered one.
	_ = Guard("10.0.0.10:8006")

	err := Check()
	if err == nil {
		t.Fatal("a registration leaked past its sub-test and excused a later real violation")
	}
	if !strings.Contains(err.Error(), "10.0.0.10:8006") {
		t.Errorf("Check reported something other than the leaked-past violation: %v", err)
	}
	if strings.Contains(err.Error(), DeliberateNonLoopbackAddr) {
		t.Errorf("Check reported the REGISTERED violation as well: %v", err)
	}
}

// TestCheck_FailsWhenInstallWasNeverCalled closes the vacuity that the census
// had to be instrumented to rule out by hand: an unarmed trip-wire returning
// nil is indistinguishable from an armed one that saw nothing.
func TestCheck_FailsWhenInstallWasNeverCalled(t *testing.T) {
	reset(t)
	mu.Lock()
	installed = false
	mu.Unlock()

	err := Check()
	if err == nil {
		t.Fatal("Check returned nil although Install was never called; its silence would mean nothing")
	}
	if !strings.Contains(err.Error(), "never armed") {
		t.Errorf("Check did not say WHY its answer is worthless: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Install: the R1 runtime gate, and the swap itself.
// ---------------------------------------------------------------------------

// TestInstall_RefusesOutsideATestBinary drives the refusal branch directly,
// in process, by passing inTestBinary=false. That is the whole reason install
// takes the flag rather than reading testing.Testing(): the branch is covered
// by the suite's own coverage profile, which a subprocess could never
// contribute to.
//
// Mutant R1a removes the gate; R1b has the exported wrapper pass true
// unconditionally.
func TestInstall_RefusesOutsideATestBinary(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("install(false) returned instead of panicking; the gate is gone")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "outside a test binary") {
			t.Fatalf("panic %q does not say why it refused", r)
		}
	}()
	restore := install(false)
	restore()
}

// TestInstall_ArmsAndRestoresDefaultTransport is mutants A1 (Install never
// assigns the global) and A2 (it assigns a Clone but never overrides
// DialContext — installed but inert).
//
// It asserts BEHAVIOURALLY, through a real request, rather than comparing
// function identities: what matters is that a dial through the global gets
// refused, not which func value is in the field.
func TestInstall_ArmsAndRestoresDefaultTransport(t *testing.T) {
	reset(t)
	before := http.DefaultTransport

	restore := Install()
	if http.DefaultTransport == before {
		t.Fatal("Install left http.DefaultTransport untouched")
	}

	c := &http.Client{Transport: http.DefaultTransport, Timeout: companionTimeout}
	resp, err := c.Get("http://" + DeliberateNonLoopbackAddr + "/")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !errors.Is(err, ErrNonLoopbackDial) {
		t.Fatalf("a request through the installed transport was not refused by the trip-wire: %v", err)
	}

	restore()
	if http.DefaultTransport != before {
		t.Fatal("restore did not put the original http.DefaultTransport back")
	}
}

// TestInstall_PreservesTheTransportFieldsPveDependsOn pins an interaction
// that is easy to break and whose breakage would surface a long way from
// here: internal/pve/client.go:103 Clone()s this global for its InsecureTLS
// path, and internal/pve/client_test.go's
// TestNewClient_InsecureTLS_PreservesProxyFromEnvironment requires the result
// to carry a non-nil Proxy.
//
// So the trip-wire must override DialContext and NOTHING else. Nulling Proxy
// here — tempting, since it would make the suite hermetic against
// HTTPS_PROXY — turns that test red two packages away.
func TestInstall_PreservesTheTransportFieldsPveDependsOn(t *testing.T) {
	reset(t)
	orig, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skipf("http.DefaultTransport is %T, not *http.Transport", http.DefaultTransport)
	}

	restore := Install()
	defer restore()

	armed, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatalf("Install left an %T in http.DefaultTransport; pve.NewClient(InsecureTLS) would panic on its type assertion", http.DefaultTransport)
	}
	if (armed.Proxy == nil) != (orig.Proxy == nil) {
		t.Error("Install changed Proxy; internal/pve's TestNewClient_InsecureTLS_PreservesProxyFromEnvironment asserts a clone of this global has a non-nil one")
	}
	if armed.ForceAttemptHTTP2 != orig.ForceAttemptHTTP2 {
		t.Error("Install changed ForceAttemptHTTP2, which internal/pve/vmguest.go's error-text reasoning depends on")
	}
	if armed.IdleConnTimeout != orig.IdleConnTimeout || armed.TLSHandshakeTimeout != orig.TLSHandshakeTimeout {
		t.Error("Install changed a timeout; an ALLOWED dial must behave exactly as it did before the swap")
	}
}

// TestNoParallelTests is this package's own use of the guard it exports.
func TestNoParallelTests(t *testing.T) {
	AssertNoParallel(t)
}

// TestNoPreInstallDialer is this package's own use of the guard it exports.
func TestNoPreInstallDialer(t *testing.T) {
	AssertNoPreInstallDialer(t)
}
