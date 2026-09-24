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
}

// httpConstructorSites are the exact reference counts, per file and target.
var httpConstructorSites = map[string]map[string]int{
	"internal/pve/client.go": {
		tgtHTTPClient.String():           3, // the Client field, newHTTPClient's result type and its one literal
		tgtHTTPTransport.String():        1, // the InsecureTLS clone's type assertion
		tgtHTTPDefaultTransport.String(): 2, // cloned for InsecureTLS; resolved per request by the guard
		tgtProxmoxNewClient.String():     1, // handed newHTTPClient's client (WithHTTPClient)
	},
	"internal/netguard/netguard.go": {
		tgtHTTPTransport.String():        1,
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
