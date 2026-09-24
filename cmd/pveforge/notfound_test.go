package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// N8 (pveforge-unify-notfound-classifiers): `network bridge destroy` of an
// interface PVE says does not exist — a real HTTP 400 parameter-verification
// answer, so the typed answer pve.NotFound reads — is a no-op through the
// whole CLI: exit 0, the exact "already absent" line, nothing written.
func TestNetworkBridgeDestroy_AlreadyAbsent_ThroughRunRoot(t *testing.T) {
	var writes int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			atomic.AddInt32(&writes, 1)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":{"iface":"interface does not exist"},"data":null}`))
	}))
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootArgs("network", "bridge", "destroy", "--roster", rosterPath, "--management-bridge", "vmbr0", "qa-pve-01", "vmbr5")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "qa-pve-01: bridge vmbr5 already absent\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if n := atomic.LoadInt32(&writes); n != 0 {
		t.Errorf("%d write(s) for an absent bridge", n)
	}
}
