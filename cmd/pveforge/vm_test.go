package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewVMGetCmd_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// pve.NewClient (built from Host/APIPort, the roster-driven path
		// every command here goes through) always prefixes "/api2/json" —
		// unlike internal/pve's own tests, which use BaseURLOverride to
		// bypass it entirely.
		switch r.URL.Path {
		case "/api2/json/nodes/qa-pve-01/qemu/100/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
		case "/api2/json/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"name":"web-01","cores":2}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMGetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// proxmox.VirtualMachine's fields mostly have no json tag override, so
	// KV rendering uses the Go field name verbatim (Status, not status);
	// VirtualMachineConfig is a named (not embedded) field, so it renders
	// as its own nested compact-JSON blob rather than flattening its own
	// fields up a level — both exactly as kvjson.Render is designed to
	// behave (see its own doc comment).
	got := out.String()
	if !strings.Contains(got, "Status=running") {
		t.Errorf("expected Status=running in output, got:\n%s", got)
	}
	if !strings.Contains(got, `"name":"web-01"`) {
		t.Errorf("expected the nested config's name field in output, got:\n%s", got)
	}
}

func TestNewVMGetCmd_JSONOutput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMGetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "-o", "json", "qa-pve-01", "100"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "{\n") {
		t.Errorf("expected indented JSON output, got:\n%s", got)
	}
}

// TestNewVMGetCmd_BlocksOnPendingMutation proves `vm get` actually
// participates in the locking protocol (pveforge-wire-existing-reads-to-lock-read):
// while a lock.Mutation is held for the same object, the get command's
// lock.Read call must block rather than reach the PVE API, and once the
// mutation releases, the read proceeds normally.
func TestNewVMGetCmd_BlocksOnPendingMutation(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newVMGetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("expected the read to be blocked by the pending mutation and time out")
	} else if !strings.Contains(err.Error(), "acquire read lock") {
		t.Errorf("expected a read-lock-acquisition error, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected the read to never reach the PVE API while the mutation held the lock, got %d hits", got)
	}

	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	cmd2 := newVMGetCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	// GetVM fetches status and config in two separate requests (see
	// TestNewVMGetCmd_Success), so one successful read means two hits.
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected exactly one successful read (2 hits: status+config) after the mutation released, got %d hits", got)
	}
}

func TestNewVMGetCmd_InvalidVMID(t *testing.T) {
	cmd := newVMGetCmd()
	cmd.SetArgs([]string{"qa-pve-01", "not-a-number"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a non-numeric vmid")
	}
}

func TestNewVMGetCmd_RequiresTwoArgs(t *testing.T) {
	cmd := newVMGetCmd()
	cmd.SetArgs([]string{"qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for missing vmid argument")
	}
}

func TestNewVMSetCmd_RequiresExactlyOneMode(t *testing.T) {
	cases := [][]string{
		{"qa-pve-01", "100"}, // zero modes
		{"qa-pve-01", "100", "cores=4", "--json", `{"name":"x"}`},       // two modes
		{"qa-pve-01", "100", "cores=4", "--json-file", "/tmp/x.json"},   // two modes
		{"qa-pve-01", "100", "--json", `{"a":"1"}`, "--json-file", "x"}, // two modes
	}
	for _, args := range cases {
		cmd := newVMSetCmd()
		cmd.SetArgs(args)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err == nil {
			t.Errorf("args %v: expected exactly-one-mode error", args)
		}
	}
}

func TestNewVMSetCmd_PositionalPairs_Success(t *testing.T) {
	var receivedFields []string
	var receivedValues []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			receivedFields = append(receivedFields, k)
			receivedValues = append(receivedValues, v[0])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4", "name=web-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(receivedFields) != 2 {
		t.Fatalf("expected 2 fields set on the server, got %v", receivedFields)
	}
	got := out.String()
	if !strings.Contains(got, "qa-pve-01: cores=4\n") {
		t.Errorf("expected a confirmation line for cores, got:\n%s", got)
	}
	if !strings.Contains(got, "qa-pve-01: name=web-01\n") {
		t.Errorf("expected a confirmation line for name, got:\n%s", got)
	}
}

func TestNewVMSetCmd_JSONBody_Success(t *testing.T) {
	var receivedField, receivedValue string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			receivedField = k
			receivedValue = v[0]
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "--json", `{"memory":"8192"}`})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if receivedField != "memory" || receivedValue != "8192" {
		t.Errorf("field/value = %q/%q, want memory/8192", receivedField, receivedValue)
	}
}

func TestNewVMSetCmd_JSONFile_Success(t *testing.T) {
	var receivedField, receivedValue string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			receivedField = k
			receivedValue = v[0]
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	jsonFile := filepath.Join(t.TempDir(), "fields.json")
	if err := os.WriteFile(jsonFile, []byte(`{"description":"hello"}`), 0o600); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	cmd := newVMSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "--json-file", jsonFile})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if receivedField != "description" || receivedValue != "hello" {
		t.Errorf("field/value = %q/%q, want description/hello", receivedField, receivedValue)
	}
}

func TestNewVMSetCmd_JSONFile_MissingFile(t *testing.T) {
	cmd := newVMSetCmd()
	cmd.SetArgs([]string{"qa-pve-01", "100", "--json-file", "/no/such/file.json"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing json file")
	}
}

func TestNewVMSetCmd_InvalidKVPair(t *testing.T) {
	cmd := newVMSetCmd()
	cmd.SetArgs([]string{"qa-pve-01", "100", "novalue"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an invalid field=value pair")
	}
}

func TestNewVMSetCmd_InvalidJSONBody(t *testing.T) {
	cmd := newVMSetCmd()
	cmd.SetArgs([]string{"qa-pve-01", "100", "--json", `{"cores":4}`})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a non-string JSON value")
	}
}

// TestNewVMSetCmd_StopsAtFirstFailure exercises the multi-field
// stop-at-first-failure semantics: the second field (alphabetically
// first-applied, since JSON pairs are sorted by key) fails, and the third
// must never be attempted.
func TestNewVMSetCmd_StopsAtFirstFailure(t *testing.T) {
	var appliedFields []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k := range r.PostForm {
			appliedFields = append(appliedFields, k)
			if k == "b_field" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("simulated failure"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	// Sorted key order: a_field, b_field, c_field — b_field fails, so
	// c_field must never be attempted.
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "--json", `{"a_field":"1","b_field":"2","c_field":"3"}`})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error when a field fails")
	}
	if !strings.Contains(err.Error(), "b_field") {
		t.Errorf("expected the error to name the failing field, got: %v", err)
	}

	if len(appliedFields) != 2 || appliedFields[0] != "a_field" || appliedFields[1] != "b_field" {
		t.Fatalf("expected exactly a_field then b_field to be attempted, got: %v", appliedFields)
	}
	got := out.String()
	if !strings.Contains(got, "a_field=1") {
		t.Errorf("expected a confirmation line for the field that succeeded before the failure, got:\n%s", got)
	}
	if strings.Contains(got, "c_field") {
		t.Errorf("c_field must never have been attempted, got:\n%s", got)
	}
}
