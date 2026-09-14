package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewNodeGetCmd_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api2/json/nodes/qa-pve-01/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"uptime":12345,"pveversion":"pve-manager/9.2.11"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newNodeGetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Uptime=12345") {
		t.Errorf("expected Uptime=12345 in output, got:\n%s", got)
	}
	if !strings.Contains(got, "pve-manager/9.2.11") {
		t.Errorf("expected the pve version in output, got:\n%s", got)
	}
}

func TestNewNodeGetCmd_RequiresOneArg(t *testing.T) {
	cmd := newNodeGetCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing target-id argument")
	}
}

func TestNewNodeGetCmd_UnknownTarget(t *testing.T) {
	rosterPath := newTestRosterEmpty(t)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newNodeGetCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--roster", rosterPath, "does-not-exist"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a target not in the roster")
	}
}
