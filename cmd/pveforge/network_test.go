package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewNetworkGetCmd_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api2/json/nodes/qa-pve-01/network/vmbr0" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"cidr":"10.0.0.5/24","gateway":"10.0.0.1"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newNetworkGetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "vmbr0"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// proxmox.NodeNetwork.Node is `json:"-"` (excluded); Iface/CIDR carry
	// lowercase json tags.
	got := out.String()
	if !strings.Contains(got, "iface=vmbr0") {
		t.Errorf("expected iface=vmbr0 in output, got:\n%s", got)
	}
	if !strings.Contains(got, "cidr=10.0.0.5/24") {
		t.Errorf("expected cidr=10.0.0.5/24 in output, got:\n%s", got)
	}
}

func TestNewNetworkGetCmd_RequiresTwoArgs(t *testing.T) {
	cmd := newNetworkGetCmd()
	cmd.SetArgs([]string{"qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing iface argument")
	}
}
