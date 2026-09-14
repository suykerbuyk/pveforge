package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// newVMConfigServer serves a stateful, minimal simulation of PVE's VM
// config GET/PUT cycle — realistic enough for vm set's Read-then-write
// flow (idempotent.VMFieldsEnsure) to observe its own writes on the
// final best-effort re-read idempotent.Run does after a successful
// Apply: GET returns the current field map (always including a
// "digest"), PUT merges the posted form's non-"digest" fields into it.
// Does NOT model PVE's real digest-rotation semantics or validate the
// posted digest at all — vm set's own tests exercise that at the
// internal/idempotent level (vmfields_test.go); this fake only needs to
// be consistent enough for vm.go's CLI wiring to observe correct
// before/after state.
//
// onWrite, if non-nil, is called for every field PVE-write attempt
// (field, value) — including one this fake will then reject via
// failField — so a test can track write ORDER without depending on
// config's own (mutex-guarded, unordered-iteration) map.
func newVMConfigServer(t *testing.T, failField string, failStatus int, failBody string, onWrite func(field, value string)) *httptest.Server {
	t.Helper()
	config := map[string]string{"digest": "d1"}
	var mu sync.Mutex
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.Method == http.MethodGet {
			body, err := json.Marshal(config)
			if err != nil {
				t.Fatalf("marshal fake config: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			if k == "digest" {
				continue
			}
			if onWrite != nil {
				onWrite(k, v[0])
			}
			if failField != "" && k == failField {
				w.WriteHeader(failStatus)
				_, _ = w.Write([]byte(failBody))
				return
			}
			config[k] = v[0]
		}
		w.WriteHeader(http.StatusOK)
	}))
}

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
	var mu sync.Mutex
	var receivedFields []string
	var receivedValues []string
	srv := newVMConfigServer(t, "", 0, "", func(field, value string) {
		mu.Lock()
		defer mu.Unlock()
		receivedFields = append(receivedFields, field)
		receivedValues = append(receivedValues, value)
	})
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
	var mu sync.Mutex
	var receivedField, receivedValue string
	srv := newVMConfigServer(t, "", 0, "", func(field, value string) {
		mu.Lock()
		defer mu.Unlock()
		receivedField = field
		receivedValue = value
	})
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
	var mu sync.Mutex
	var receivedField, receivedValue string
	srv := newVMConfigServer(t, "", 0, "", func(field, value string) {
		mu.Lock()
		defer mu.Unlock()
		receivedField = field
		receivedValue = value
	})
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
//
// Disclosed behavior change from the old direct-write loop (which printed
// a_field's confirmation line the instant it succeeded, before b_field's
// failure occurred): idempotent.Run reports the whole cycle as one
// success-or-failure — on ANY Apply failure it returns a zeroed Result
// alongside the error, so vm.go's RunE returns before printChangedFields
// ever runs. a_field's write still genuinely took effect server-side
// (correctness is unaffected — this is purely a lost intermediate
// progress line), but no confirmation output appears for it on a failed
// batch; only the error is shown.
func TestNewVMSetCmd_StopsAtFirstFailure(t *testing.T) {
	var mu sync.Mutex
	var appliedFields []string
	srv := newVMConfigServer(t, "b_field", http.StatusInternalServerError, "simulated failure", func(field, _ string) {
		mu.Lock()
		defer mu.Unlock()
		appliedFields = append(appliedFields, field)
	})
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
	// No output at all on a failed batch — see this test's own doc
	// comment on the disclosed behavior change from the old per-field
	// streamed confirmation lines.
	if got := out.String(); got != "" {
		t.Errorf("expected no stdout output when the batch fails, got:\n%s", got)
	}
}

// TestNewVMSetCmd_BlocksOnPendingMutation proves `vm set` now actually
// participates in the locking protocol at all (pveforge-vm-set-unlocked)
// — unlike the old direct-write implementation, which took no lock
// whatsoever: while another lock.Mutation is held for the same VM,
// idempotent.Run's own lock.Mutation acquisition inside vm set must block
// rather than let the write reach the PVE API, and once the held mutation
// releases, the write proceeds normally. Mirrors
// TestNewVMGetCmd_BlocksOnPendingMutation's own structure, adapted for a
// write.
func TestNewVMSetCmd_BlocksOnPendingMutation(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	config := map[string]string{"digest": "d1"}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			body, _ := json.Marshal(config)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			if k != "digest" {
				config[k] = v[0]
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newVMSetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("expected the write to be blocked by the already-held mutation and time out")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected the write to never reach the PVE API while another mutation held the lock, got %d hits", got)
	}

	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	cmd2 := newVMSetCmd()
	var out2 bytes.Buffer
	cmd2.SetOut(&out2)
	cmd2.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if !strings.Contains(out2.String(), "qa-pve-01: cores=4") {
		t.Errorf("expected a confirmation line for the successful write, got:\n%s", out2.String())
	}
}

// TestNewVMSetCmd_AlreadySatisfiedField_NoOp proves the disclosed,
// intentional behavior change from the old direct-write loop: a field
// already at its wanted value is left untouched (no write attempted at
// all) and prints no confirmation line — the entire point of routing vm
// set through idempotent.Run's check-then-act cycle.
func TestNewVMSetCmd_AlreadySatisfiedField_NoOp(t *testing.T) {
	var writeAttempted int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"digest":"d1","cores":"4"}}`))
			return
		}
		atomic.AddInt32(&writeAttempted, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMSetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if atomic.LoadInt32(&writeAttempted) != 0 {
		t.Error("expected no write to be attempted for an already-satisfied field")
	}
	if got := out.String(); got != "" {
		t.Errorf("expected no confirmation line for an already-satisfied field, got:\n%s", got)
	}
}

// TestNewVMSetCmd_ReportsAppliedFieldEvenWhenFinalReReadFails is the
// end-to-end regression test for a real, shipped bug: idempotent.Run's
// own documented fallback — Result.After equals Result.Before whenever
// the post-Apply best-effort re-read fails, even though Result.Changed
// stays true — used to make vm.go's old Before/After-diffing output
// logic print NOTHING for a real, successful write, indistinguishable
// from a no-op and with no error either. The fix (printAppliedFields)
// reports from VMFieldsEnsure.Applied — populated by Apply itself as it
// writes each field — never by diffing Before/After, so it's immune to
// this fallback entirely.
//
// The fake server here deliberately drops "digest" from its THIRD GET
// response only (Run's own post-Apply best-effort re-read; GET #1 is
// Run's initial Read, GET #2 is Apply's own pre-write digest re-fetch) —
// readConfig requires a digest and errors without one, reproducing the
// exact fallback idempotent.Run documents, through the real code path
// rather than a hand-built Result.
func TestNewVMSetCmd_ReportsAppliedFieldEvenWhenFinalReReadFails(t *testing.T) {
	var mu sync.Mutex
	config := map[string]string{"digest": "d1"}
	getCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if r.Method == http.MethodGet {
			getCalls++
			w.Header().Set("Content-Type", "application/json")
			if getCalls == 3 {
				// The post-Apply best-effort re-read: no digest at all,
				// so readConfig errors and Run's own fallback kicks in —
				// Result.After falls back to Result.Before even though
				// the write already genuinely succeeded.
				_, _ = w.Write([]byte(`{"data":{"cores":"4"}}`))
				return
			}
			body, err := json.Marshal(config)
			if err != nil {
				t.Fatalf("marshal fake config: %v", err)
			}
			_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		for k, v := range r.PostForm {
			if k != "digest" {
				config[k] = v[0]
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
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "qa-pve-01: cores=4") {
		t.Errorf("expected a confirmation line for the real, successful write even though the final re-read failed, got:\n%s", out.String())
	}
}

// TestNewVMSetCmd_DuplicateFieldRejectedEvenWhenAlreadySatisfied is the
// regression test for a third real, shipped bug: VMFieldsEnsure.Validate
// (which rejects a duplicate field name) was only ever called from
// inside Apply — but idempotent.Run calls Satisfied BEFORE Apply, and if
// the batch already matches current state (as it does here: cores=4
// given twice, and cores is already 4 on the fake server), Apply — and
// therefore Validate — never runs at all, silently bypassing the
// documented "no duplicate field name" contract. vm.go's RunE now calls
// op.Validate() itself, before calling idempotent.Run, so this is caught
// regardless of whether the batch would have been a no-op.
func TestNewVMSetCmd_DuplicateFieldRejectedEvenWhenAlreadySatisfied(t *testing.T) {
	var writeHit int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"digest":"d1","cores":"4"}}`))
			return
		}
		atomic.AddInt32(&writeHit, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newVMSetCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	// Duplicate field, already satisfied (cores is already 4 on the fake
	// server) — Satisfied would short-circuit before Apply/Validate ever
	// ran, if RunE didn't call Validate explicitly first.
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected an error for a duplicate field name, even though the batch is already satisfied")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("expected the duplicate-field error, got: %v", err)
	}
	if atomic.LoadInt32(&writeHit) != 0 {
		t.Error("expected no write to be attempted: Validate should reject the batch before any write")
	}
}
