package main

import (
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// ONE HTTP CLIENT CONSTRUCTOR. The roster's token never writes PVE's /access
// API (6a): internal/pve's accessWriteGuard refuses such a request at
// runtime, in the transport, however its path or call is spelled. What the
// runtime check cannot see is a request that never passes through it, so
// this guard holds the one thing left: every HTTP client or transport in
// production code is built by internal/pve/client.go's newHTTPClient, which
// always installs the guard, and go-proxmox is constructed only there,
// handed that client.
//
// The transport boundary guard (transportboundary_test.go) already keeps
// these symbols inside internal/pve, internal/sshexec and three reviewed
// files. This one is exact within them: each target's reference count in
// each file, 0 everywhere but the files below.
//
// Bounds. A client handed a different Transport after construction
// (c.httpClient.Transport = x) names no target here unless x is
// http.DefaultTransport or a *http.Transport; the runtime test
// TestNewClient_InstallsAccessWriteGuard pins what NewClient builds, and
// review holds the rest. internal/netguard's two sites are test support: its
// exemption holds only while no production file imports it, checked below.
var httpConstructorTargets = []sourceguard.Target{
	tgtHTTPClient, tgtHTTPTransport, tgtHTTPDefaultClient, tgtHTTPDefaultTransport,
	tgtHTTPGet, tgtHTTPPost, tgtHTTPHead, tgtHTTPPostForm,
	tgtProxmoxNewClient,
	tgtBaseTransport, tgtRoundTrip,
	tgtTLSDial, tgtTLSDialWithDialer, tgtTLSClient, tgtTLSDialer,
	tgtAnyTransportField,
	tgtInsecureSkipVerify, tgtInsecureSkipVerifyField,
}

// T3 (operator ruling 1, P3): chain verification is skipped in exactly two
// places, and only where a pin or a read-only probe stands in for it: the
// pinned transport in newHTTPClient, which always installs
// VerifyConnection and is built only with a pin, and servedPin's
// handshake, which carries no request. A composite-literal key names
// InsecureSkipVerify as a bare identifier; a field assignment
// (cfg.InsecureSkipVerify = true) as a selector, pinned to none.
var (
	tgtInsecureSkipVerify      = sourceguard.Target{Name: "InsecureSkipVerify"}
	tgtInsecureSkipVerifyField = sourceguard.Target{AnyQualifier: true, Name: "InsecureSkipVerify"}
)

// The type counts above cannot see a transport handed out by a helper: a
// call site of baseTransport() never names *http.Transport, so a new file
// doing `t := baseTransport(); t.TLSClientConfig = ...; return
// t.RoundTrip(req)` keeps every type count equal while making an unpinned
// round trip that also skips the accessWriteGuard (the Chair's T1a
// break-test). Two more targets close that:
//
//   - baseTransport, as a bare identifier: its every mention, a call, a
//     func value or an argument, is pinned to client.go's exact sites, so
//     a clone cannot leave newHTTPClient's and servedPin's hands.
//   - any selector .RoundTrip: the one round trip in production is the
//     accessWriteGuard's own hand-off to the transport behind it. A
//     RoundTrip called anywhere else, on a *http.Transport or through an
//     http.RoundTripper, is a request that skips the guard.
var (
	tgtBaseTransport = sourceguard.Target{Name: "baseTransport"}
	tgtRoundTrip     = sourceguard.Target{AnyQualifier: true, Name: "RoundTrip"}
)

// Two more ways to reach PVE past the pinned transport, each measured as a
// surviving bypass by the independent T1a review:
//
//   - crypto/tls directly: tls.Dial, DialWithDialer, Client and a Dialer
//     make a TLS connection no http.Client or transport ever sees, so a
//     new file could open one and write the token down it raw. Every such
//     reference is pinned: ServedPin's one tls.Client, which sends nothing.
//   - replacing a client's transport after construction,
//     `c.httpClient.Transport = accessWriteGuard{}`, drops the pin and
//     keeps the guard's type. Any selector .Transport is counted: that
//     covers the field assignment and, in the same count, the http.Transport
//     type name (so the two targets overlap on purpose; each file's exact
//     count holds both).
//
// Bounds. These are static: reflect (reflect.ValueOf(c).Elem().Field(i)
// .Set, or unsafe) can reach any field without naming it, and no source
// scan sees that; sourceguard.DirectiveEvasions refuses unsafe and
// linkname, and review holds reflect.
var (
	tgtTLSDial           = sourceguard.Target{ImportPath: "crypto/tls", Name: "Dial"}
	tgtTLSDialWithDialer = sourceguard.Target{ImportPath: "crypto/tls", Name: "DialWithDialer"}
	tgtTLSClient         = sourceguard.Target{ImportPath: "crypto/tls", Name: "Client"}
	tgtTLSDialer         = sourceguard.Target{ImportPath: "crypto/tls", Name: "Dialer"}
	tgtAnyTransportField = sourceguard.Target{AnyQualifier: true, Name: "Transport"}
)

// httpConstructorSites are the exact reference counts, per file and target.
var httpConstructorSites = map[string]map[string]int{
	"internal/pve/client.go": {
		tgtHTTPClient.String(): 3, // the Client field, newHTTPClient's result type and its one literal
		// net/http.Transport, three sites, each a type name and none a new
		// transport: (1) baseTransport's type assertion on DefaultTransport,
		// the ONE clone site; (2) baseTransport's result type; (3)
		// servedPin's parameter, so tests can hand the probe a clone whose
		// Proxy and DialContext they control (pveforge-rest-tls-certificate-
		// pinning, Plan r5 R1).
		tgtHTTPTransport.String(): 3,
		// net/http.DefaultTransport, two sites: cloned once, in
		// baseTransport (for InsecureTLS, a TLS pin, and ServedPin's dialer);
		// resolved per request by the accessWriteGuard when there is neither.
		tgtHTTPDefaultTransport.String(): 2,
		tgtProxmoxNewClient.String():     1, // handed newHTTPClient's client (WithHTTPClient)
		// baseTransport, three mentions: its declaration, newHTTPClient's
		// call and ServedPin's call (which hands it to servedPin).
		tgtBaseTransport.String(): 3,
		// .RoundTrip, one site: the accessWriteGuard handing the request,
		// once checked, to the transport behind it.
		tgtRoundTrip.String(): 1,
		// crypto/tls, one site: servedPin's tls.Client, a handshake that
		// sends no byte and returns only the peer's certificate.
		tgtTLSClient.String(): 1,
		// any .Transport selector, three: exactly the three http.Transport
		// type names above, so no client's transport is assigned anywhere.
		tgtAnyTransportField.String(): 3,
		// InsecureSkipVerify, two literal keys: newHTTPClient's pinned
		// transport and servedPin's probe; no field assignment anywhere.
		tgtInsecureSkipVerify.String(): 2,
	},
	"internal/netguard/netguard.go": {
		tgtHTTPTransport.String():        1,
		tgtAnyTransportField.String():    1, // the same http.Transport type assertion
		tgtHTTPDefaultTransport.String(): 5,
	},
	"internal/netguard/assert.go": {
		tgtHTTPClient.String():           1,
		tgtHTTPDefaultTransport.String(): 1,
	},
}

// TestHTTPClients_OnlyFromNewHTTPClient: every reference to an HTTP client or
// transport, a package-level round-trip helper, or go-proxmox's constructor
// in non-test code is one of httpConstructorSites, exactly. The exact
// counts are the anti-vacuity: a walk that saw nothing fails them.
func TestHTTPClients_OnlyFromNewHTTPClient(t *testing.T) {
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: transportModuleRoot}, httpConstructorTargets)
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	got := map[string]map[string]int{}
	for file, refs := range res.Refs {
		for _, ref := range refs {
			if got[file] == nil {
				got[file] = map[string]int{}
			}
			got[file][ref.Target.String()]++
		}
	}
	for file := range mergeKeys(got, httpConstructorSites) {
		if !maps.Equal(got[file], httpConstructorSites[file]) {
			t.Errorf("%s: HTTP client/transport references = %v, want exactly %v.\n"+
				"Every production HTTP client is built by internal/pve's newHTTPClient, whose transport refuses writes to /access; "+
				"use a pve.Client, or have a new site reviewed and listed.", file, got[file], httpConstructorSites[file])
		}
	}
	if len(res.Parsed) < transportParsedFloor {
		t.Errorf("walked only %d non-test files; wrong root?", len(res.Parsed))
	}
}

// TestHTTPClients_NetguardIsNotLinked: netguard's client and transport sites
// are exempt only as test support. No production file outside
// internal/netguard imports it.
func TestHTTPClients_NetguardIsNotLinked(t *testing.T) {
	const netguard = "github.com/suykerbuyk/pveforge/internal/netguard"
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: transportModuleRoot}, httpConstructorTargets)
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	fset := token.NewFileSet()
	sawSelf := false
	for _, rel := range res.Parsed {
		f, err := parser.ParseFile(fset, filepath.Join(transportModuleRoot, rel), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "net/http" && rel == "internal/netguard/assert.go" {
				sawSelf = true
			}
			if p == netguard && !strings.HasPrefix(rel, "internal/netguard/") {
				t.Errorf("%s imports internal/netguard: its HTTP client and transport sites would reach production", rel)
			}
		}
	}
	if !sawSelf {
		t.Error("never parsed internal/netguard/assert.go's imports: the walk is not seeing the code")
	}
}

func mergeKeys[V any](a, b map[string]V) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}
