package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewStorageGetCmd_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api2/json/nodes/qa-pve-01/storage/local-lvm/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"type":"lvmthin","total":1000000,"used":250000}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageGetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "local-lvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// proxmox.Storage.Name carries `json:"storage"` — the JSON/KV key is
	// "storage", not "Name".
	got := out.String()
	if !strings.Contains(got, "Type=lvmthin") {
		t.Errorf("expected Type=lvmthin in output, got:\n%s", got)
	}
	if !strings.Contains(got, "storage=local-lvm") {
		t.Errorf("expected storage=local-lvm in output, got:\n%s", got)
	}
}

func TestNewStorageGetCmd_RequiresTwoArgs(t *testing.T) {
	cmd := newStorageGetCmd()
	cmd.SetArgs([]string{"qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing storage-name argument")
	}
}
