// Package netguard is pveforge's test-only loopback trip-wire: it proves that
// no test in this module ever dials a real host.
//
// TWO SEAMS, NOT ONE. pveforge reaches the network two ways, and one hook
// cannot see both:
//
//   - HTTP, via http.DefaultTransport. Both of internal/pve's stacks resolve
//     it: with InsecureTLS off, go-proxmox's own *http.Client carries a nil
//     Transport (it never sets one — the only three sites that would are
//     gated on WithProxy, WithRetry or WithHTTPClient, none of which
//     internal/pve/client.go passes), so http.Client.send resolves the global
//     at REQUEST time; with InsecureTLS on, both go-proxmox (via its
//     ensureTransport) and internal/pve/client.go:103 Clone() the global at
//     CONSTRUCTION time, and (*http.Transport).Clone copies DialContext, so
//     the hook rides along into both clones. Install covers this seam.
//
//   - SSH, via internal/sshexec's own net.Dialer at client.go:60. That dial
//     never touches http.DefaultTransport, so the HTTP seam is blind to it.
//     sshexec.SetDialGuardForTests(netguard.Guard) covers this seam, and each
//     package's TestMain wires it — netguard must not import internal/sshexec
//     (sshexec's own tests are in-package, so the import would be a cycle).
//
// ORDERING IS LOAD-BEARING, AND ASYMMETRICALLY SO. Install must run before
// any pve.NewClient in the test binary. Measured: a swap installed after
// construction is still seen by an InsecureTLS=false client (which resolves
// the global lazily) but is COMPLETELY INVISIBLE to an InsecureTLS=true one,
// which already took its clone. That is why Install belongs in TestMain and
// nowhere else.
//
// WHY AN *http.Transport CLONE AND NEVER A CUSTOM RoundTripper. Installing a
// bare http.RoundTripper as http.DefaultTransport panics
// pve.NewClient(ClientConfig{InsecureTLS: true}) on the unchecked type
// assertion at internal/pve/client.go:103 ("interface conversion:
// http.RoundTripper is ..., not *http.Transport"), and go-proxmox's
// ensureTransport carries the identical unguarded assertion. Cloning the real
// transport and overriding one field keeps every other field — Proxy in
// particular, which internal/pve/client_test.go's
// TestNewClient_InsecureTLS_PreservesProxyFromEnvironment asserts is non-nil
// on a clone of this global.
//
// WHAT THIS CANNOT SEE. Five bounds, stated rather than papered over. The
// unit's claim is "no test in this process dials a real host in-process over
// HTTP or SSH" — not the broader thing its name suggests.
//
//  1. WEBSOCKETS. go-proxmox's TermWebSocket and VNCWebSocket build a
//     gorilla/websocket.Dialer with a nil NetDial/NetDialContext, so they
//     consult neither http.DefaultTransport nor this package. Unreachable
//     from pveforge today — both return ErrAPITokenWebSocketUnsupported for
//     token auth, and pveforge is token-only — but they stop being
//     unreachable the moment anyone adds credential or session auth, and no
//     seam here would notice. A sweep of the whole linked dependency set
//     (`go list -deps -test ./...`) found no OTHER in-process dial path:
//     go-proxmox's only routes are the three DefaultTransport sites and
//     these two.
//
//  2. SUBPROCESSES. Both seams live in THIS process's memory. A child
//     process inherits neither, so anything this module shells out to dials
//     freely and is recorded nowhere. Measured: a child dialed 203.0.113.1:9
//     for real while netguard observed 0. This unit itself adds three such
//     invocations (subprocess_test.go's `go test`, `go run` and `go list`),
//     beside the pre-existing one in internal/roster/kdf_seam_test.go, and
//     against a cold module cache those reach GOPROXY. They are the toolchain
//     doing its job, not pveforge dialing a host, but the trip-wire makes no
//     claim about them either way.
//
//  3. A LAUNDERED WRAPPER. netguard.go is an AllowFile of
//     TestSeam_NoProductionReferences and Scope.allows is exact on the file,
//     so a NEW exported wrapper added to THIS file under a name the target
//     list does not carry — `func ArmForDiagnostics() (restore func()) {
//     return install(true) }` — is permitted by the guard, compiles, and can
//     be called from production. The runtime testing.Testing() gate does not
//     help: the wrapper passes true past it. No name-based guard can close
//     this, because the laundering name is chosen after the guard is written.
//     The sibling transport-boundary unit documents the same class.
//
//  4. PACKAGES WITH NO TestMain. Six of this module's twelve packages wire
//     neither seam, because none of them dials today. A dial made at RUN TIME
//     from one of those packages' own tests would be unguarded and silent.
//     Widening the seams to cover them is deliberately NOT this unit's scope;
//     it is recorded so the next person does not mistake twelve green
//     packages for twelve guarded ones.
//
//     What IS covered there, and was not in the first cut of this unit: a
//     package-level dialer in any of them. Go initialises every linked
//     package before the test binary's TestMain, so such a var would be
//     constructed before Install in EVERY package that links it — one
//     package's omission silently weakening another's guarantee.
//     TestNoPreInstallDialerAnywhereInTheModule sweeps all twelve for that,
//     not just the six that wire a seam.
//
//  5. //go:linkname. No AST walk sees it — the directive is a comment and
//     `import _ "unsafe"` binds no identifier — so neither this package's
//     static half nor AssertNoPreInstallDialer's in-package walk can. It is
//     closed at the text level instead, module-wide:
//     sourceguard.DirectiveEvasions (TestModule_NoDirectiveEvasions) refuses
//     any linkname directive, any unsafe import and any non-Go source in
//     non-test code. What stays open is a dependency linking into this
//     module, which only the module guard's pinned dependency set bounds
//     (pveforge-golinkname-defeats-source-guards).
//
// The ordering hole on the other side of TestMain — a client built at
// package-variable initialisation or in init(), before Install runs, which
// captures the pristine transport and is invisible to both seams — is NOT on
// this list, because AssertNoPreInstallDialer closes it. See preinstall.go.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ErrNonLoopbackDial is the sentinel every refusal wraps. Companion tests
// assert against this rather than against "an error occurred", because
// several legitimate tests in this module already expect a dial to fail: a
// bare "did it error" assertion would be satisfied by the ordinary failure
// too, and a mutant that stopped refusing would survive it.
var ErrNonLoopbackDial = errors.New("netguard: refused a dial to a non-loopback address")

// violation is one recorded off-loopback dial attempt.
type violation struct {
	network  string
	addr     string
	expected bool
}

var (
	// mu guards every package-global below. The recorder is mutex-guarded by
	// construction rather than by relying on this module's zero-t.Parallel
	// property: -race is then clean no matter who adds a parallel test later.
	// ExpectViolation's EXACTNESS does still assume no parallelism (it is
	// scoped by wall-clock nesting, not by goroutine), which the module's
	// no-parallel pin holds for every package using netguard
	// (internal/sourceguard/noparallel_guard_test.go).
	mu sync.Mutex

	installed     bool
	origTransport http.RoundTripper
	violations    []violation

	// observedDials counts every dial the trip-wire vetted, allowed ones
	// included. See Stats for why this is the number that proves the wire was
	// actually armed.
	observedDials int

	// expecting is the nesting depth of live ExpectViolation registrations.
	// A counter rather than a bool so two nested companions cannot have the
	// inner one's Cleanup cancel the outer one's registration.
	expecting int
)

// loopbackDialer mirrors http.DefaultTransport's own dialer
// (net/http/transport.go: Timeout 30s, KeepAlive 30s) so that an ALLOWED dial
// behaves exactly as it did before the swap. The trip-wire changes what is
// refused, never how a permitted connection is made.
var loopbackDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// CheckAddr is the predicate, and it is pure: it records nothing and refuses
// nothing on its own. It is exported so a companion test can assert the exact
// text the trip-wire produces without going through a dial.
//
// It is an ALLOW-LIST, and everything it cannot positively identify as
// loopback is refused — including every hostname, which is refused BEFORE
// resolution, so a non-loopback dial emits no DNS query and no SYN. That
// matters here specifically: "qa-pve-01.example.com" appears at twenty-odd
// sites in this module's tests as a config-only host, and a deny-list would
// have to enumerate them.
func CheckAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not a host:port — refusing what it cannot parse", ErrNonLoopbackDial, addr)
	}
	// RFC 6761 reserves localhost and requires it to resolve to loopback.
	// It is the one name on the allow-list.
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is a hostname, not a loopback IP literal (refused before resolution, so no DNS query left this process)", ErrNonLoopbackDial, addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %s", ErrNonLoopbackDial, addr)
	}
	return nil
}

// checkNetwork refuses anything that is not TCP. Nothing in this module dials
// unix or udp (all five listeners are net.Listen("tcp", "127.0.0.1:0")), so
// an unrecognised network is a surprise, and a surprise fails closed.
func checkNetwork(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	}
	return fmt.Errorf("%w: network %q is not tcp", ErrNonLoopbackDial, network)
}

// Guard vets one address and RECORDS every refusal, then refuses it. It is
// what both seams are wired to.
//
// The recording half is the whole reason Check exists as a second observer.
// Refusal alone is not enough: several tests in this module legitimately
// expect a dial to fail, and one of them swallowing the trip-wire's own error
// would launder a real violation into a green package. The record outlives
// m.Run, so Check fails the package whether or not anyone looked at the error.
func Guard(addr string) error {
	return guard("tcp", addr)
}

func guard(network, addr string) error {
	err := checkNetwork(network)
	if err == nil {
		err = CheckAddr(addr)
	}

	mu.Lock()
	observedDials++
	if err != nil {
		violations = append(violations, violation{network: network, addr: addr, expected: expecting > 0})
	}
	mu.Unlock()

	return err
}

func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := guard(network, addr); err != nil {
		return nil, err
	}
	return loopbackDialer.DialContext(ctx, network, addr)
}

// Install swaps http.DefaultTransport for a loopback-only clone of itself and
// resets the recorder. Call it BEFORE m.Run; the returned func restores the
// original transport and is called AFTER Check.
//
// It PANICS unless called from a binary built by `go test`, so the seam is
// inert in a shipped pveforge no matter who calls it. That gate is belt to
// TestSeam_NoProductionReferences' braces: this package is an ordinary
// importable non-test package, and nothing in the language stops production
// code importing it.
func Install() (restore func()) {
	return install(testing.Testing())
}

// install holds the whole decision with the "am I in a test binary" answer
// PASSED IN rather than read, for the same reason
// roster.setScryptWorkFactor does it (internal/roster/secrets.go:131): the
// refusal branch is then reachable from an ordinary in-process test, so it is
// covered by the suite's own profile rather than only by a subprocess whose
// coverage the profile never sees.
func install(inTestBinary bool) (restore func()) {
	if !inTestBinary {
		panic("netguard: Install called outside a test binary")
	}

	mu.Lock()
	defer mu.Unlock()

	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic(fmt.Sprintf("netguard: http.DefaultTransport is %T, not *http.Transport — "+
			"something already replaced it, and cloning it is what keeps "+
			"pve.NewClient(InsecureTLS) from panicking on its own type assertion",
			http.DefaultTransport))
	}

	origTransport = http.DefaultTransport
	clone := tr.Clone()
	clone.DialContext = dialContext
	http.DefaultTransport = clone

	installed = true
	violations = nil
	observedDials = 0
	expecting = 0

	return func() {
		mu.Lock()
		defer mu.Unlock()
		http.DefaultTransport = origTransport
		origTransport = nil
		installed = false
	}
}

// Check reports every recorded non-loopback dial that no companion registered
// with ExpectViolation. Call it AFTER m.Run and BEFORE restore — it reads
// state the restore tears down.
//
// A caller must only ever RAISE the exit code with this:
//
//	if err := netguard.Check(); err != nil && code == 0 { code = 1 }
//
// so that a trip-wire failure can never turn a red suite green.
func Check() error {
	mu.Lock()
	defer mu.Unlock()

	// An uninstalled trip-wire that returned nil would be indistinguishable
	// from an installed one that saw nothing — the exact vacuity this package
	// exists to prevent. A forgotten Install is loud.
	if !installed {
		return errors.New("netguard: Check called but Install was never called in this process; " +
			"the trip-wire was never armed, so its silence means nothing")
	}

	var unexpected []violation
	for _, v := range violations {
		if !v.expected {
			unexpected = append(unexpected, v)
		}
	}
	if len(unexpected) == 0 {
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "netguard: %d non-loopback dial(s) left this test binary:\n", len(unexpected))
	for _, v := range unexpected {
		fmt.Fprintf(&b, "  %s %s\n", v.network, v.addr)
	}
	b.WriteString("No test in this module may dial a real host. If one legitimately " +
		"must make a deliberate off-loopback dial, it registers it with " +
		"netguard.ExpectViolation(t) and asserts the refusal itself.")
	return errors.New(b.String())
}

// ExpectViolation registers the deliberate violation a companion sub-test is
// about to make, so Check does not fail the package on it. The registration
// is scoped by t.Cleanup, so it cannot leak past this sub-test and excuse a
// later real violation.
func ExpectViolation(t *testing.T) {
	t.Helper()
	mu.Lock()
	expecting++
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		expecting--
		mu.Unlock()
	})
}

// Stats reports how many dials this process's trip-wire has VETTED
// (observed), how many of those it refused, and how many of the refusals a
// companion had registered with ExpectViolation.
//
// observed is the anti-vacuity number, and it is the one that matters most: a
// trip-wire that was never armed, or that was armed after the clients were
// built, reports zero refusals — exactly what a correctly armed one reports
// on a clean suite. Only a non-zero observed count distinguishes "saw
// everything and refused nothing" from "saw nothing at all". Every companion
// asserts on it, and so does the census.
func Stats() (observed, refused, expectedCount int) {
	mu.Lock()
	defer mu.Unlock()
	for _, v := range violations {
		refused++
		if v.expected {
			expectedCount++
		}
	}
	return observedDials, refused, expectedCount
}
