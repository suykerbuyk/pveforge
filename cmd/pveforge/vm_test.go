package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// answerNothingPending answers vm set's post-apply reads — of
// /nodes/{node}/qemu/{vmid}/pending and, after a cloud-init key changed,
// /cloudinit — with an empty list: nothing pending, nothing stale on the
// drive, as for a stopped VM. So a fake written for the config endpoint
// neither counts those reads as config GETs nor turns them into a warning.
// It reports whether it answered.
func answerNothingPending(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !(strings.HasSuffix(r.URL.Path, "/pending") || strings.HasSuffix(r.URL.Path, "/cloudinit")) {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":[]}`))
	return true
}

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
		if answerNothingPending(w, r) {
			return
		}
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

	// Control: a mutation on a DIFFERENT vm must not block this read.
	control := newVMGetCmd()
	control.SetOut(&bytes.Buffer{})
	control.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "101"}, control)
	atomic.StoreInt32(&hits, 0)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newVMGetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})

	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
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
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4", "name=web-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// A clean run re-reads successfully, so no "could not be re-read"
	// warning may appear.
	if errOut.Len() != 0 {
		t.Errorf("expected no stderr output for a write whose re-read succeeded, got:\n%s", errOut.String())
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
		if answerNothingPending(w, r) {
			return
		}
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

	// Control: a mutation on a DIFFERENT vm must not block this write. It
	// writes cores=2, so the cores=4 write below is still a real change.
	control := newVMSetCmd()
	control.SetOut(&bytes.Buffer{})
	control.SilenceUsage = true
	control.SilenceErrors = true
	control.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=2"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "101"}, control)
	atomic.StoreInt32(&hits, 0)

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

	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
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
		if answerNothingPending(w, r) {
			return
		}
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
// this fallback entirely. (The failed re-read itself is now reported too,
// as Result.AfterErr's stderr warning — pinned through runRoot by
// TestVMSet_AfterErrWarning_ThroughRunRoot.)
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
		if answerNothingPending(w, r) {
			return
		}
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
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "qa-pve-01: cores=4") {
		t.Errorf("expected a confirmation line for the real, successful write even though the final re-read failed, got:\n%s", out.String())
	}
	// A 2xx re-read that fails validation (no digest) is a failed re-read
	// too, not only a 5xx: the warning must fire for it, once.
	got := errOut.String()
	if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "warning: ") || !strings.Contains(got, "response carries no digest") {
		t.Errorf("stderr = %q, want exactly one warning line carrying the re-read's cause (response carries no digest)", got)
	}
}

// TestVMSet_AfterErrWarning_ThroughRunRoot pins, at the CLI's own entry
// point, that a failed post-Apply re-read reaches the operator: Run's
// Result.AfterErr must be consumed by vm set (not discarded), printed on
// stderr as exactly one line with the cause quoted — the fake's 5xx body
// carries a newline and a forged "warning:" line, which must stay inside
// the quoted cause — while stdout still reports the applied field and
// the exit status stays 0, since the write itself succeeded.
func TestVMSet_AfterErrWarning_ThroughRunRoot(t *testing.T) {
	var mu sync.Mutex
	config := map[string]string{"digest": "d1"}
	getCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) {
			return
		}
		mu.Lock()
		defer mu.Unlock()

		if r.Method == http.MethodGet {
			getCalls++
			if getCalls == 3 {
				// Run's post-Apply re-read (GET #1 is Run's Read, GET #2
				// Apply's digest re-fetch).
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("boom\nwarning: forged"))
				return
			}
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
			if k != "digest" {
				config[k] = v[0]
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	root := newRootCmd()
	root.SetArgs([]string{"vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4"})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	if code := runRoot(root, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (the write succeeded); stderr:\n%s", code, stderr.String())
	}

	mu.Lock()
	gets := getCalls
	mu.Unlock()
	if gets != 3 {
		t.Fatalf("GET calls = %d, want 3: the failing re-read was never reached", gets)
	}
	if got := stdout.String(); got != "qa-pve-01: cores=4\n" {
		t.Errorf("stdout = %q, want exactly the applied line", got)
	}
	got := stderr.String()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("stderr must be exactly one line (a quoted cause cannot forge a second), got %q", got)
	}
	const prefix = "warning: qa-pve-01: vm 100: the write was applied but its result could not be re-read: \""
	if !strings.HasPrefix(got, prefix) {
		t.Errorf("stderr = %q, want prefix %q", got, prefix)
	}
	if !strings.Contains(got, `500`) || !strings.Contains(got, `boom\nwarning: forged`) {
		t.Errorf("stderr = %q, want the quoted cause carrying the 5xx status and body", got)
	}
}

// TestVMSet_LineUnsafeTargetID_RefusedThroughRunRoot: a roster whose
// target id carries a line break (a valid TOML escape, so it parses) is
// refused when vm set loads it — before any PVE request — so no output
// line can ever begin with a forged id: exit 1, nothing on stdout, and the
// error on one stderr line naming the id quoted. This is what makes the
// target id safe to print bare in vm set's stdout lines and its warning.
func TestVMSet_LineUnsafeTargetID_RefusedThroughRunRoot(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	const id = "qa\nwarning: forged"
	rosterPath := newTestRosterWithTLSTarget(t, srv, id, "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	root := newRootCmd()
	root.SetArgs([]string{"vm", "set", "--roster", rosterPath, id, "100", "cores=4"})
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	if code := runRoot(root, &stderr); code != 1 {
		t.Fatalf("exit code = %d, want 1; stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("PVE requests = %d, want 0: the id must be refused before any request", n)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	got := stderr.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, `target id "qa\nwarning: forged"`) {
		t.Errorf("stderr = %q, want one line naming the quoted id", got)
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
		if answerNothingPending(w, r) {
			return
		}
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

// vmCreateFake is a minimal stateful PVE stand-in for `vm create`'s three
// network touchpoints, each independently steerable so a test can put the
// cluster in states a single boolean can't express — in particular
// "vmid taken cluster-wide but NOT present on this node", which is what
// separates the NextVMID pre-check from the post-Run backstop.
type vmCreateFake struct {
	// nextIDTaken makes GET /cluster/nextid?vmid=N answer with PVE's own
	// "VM N already exists" rejection (the cluster-wide view NextVMID's
	// pin path consults).
	nextIDTaken bool
	// nextIDBroken makes that same check fail for a reason that is NOT
	// "taken" — a 500. vmidFree must propagate it rather than read it as
	// "free" and wave the create through.
	nextIDBroken bool
	// nextIDStatus, when non-zero, makes that same check answer this
	// status with a {"data":null} body: the shape pveproxy sends when it
	// cannot reach the node (595), which go-proxmox v0.8.2-pveforge.0
	// decoded as an empty success.
	nextIDStatus int

	// createRejects makes POST /nodes/{node}/qemu answer with PVE's own
	// "VM N already exists" rejection — the collision that happens at the
	// create call itself, past both the pre-check and Read.
	createRejects bool

	createCalls  int32
	nextIDChecks int32

	// mu guards the fields below: httptest serves each request on its own
	// goroutine, so the POST handler's write to vmPresent and the later
	// GET handler's read of it are cross-goroutine even though the client
	// issues them strictly in sequence. The lock tests additionally read
	// createdForm from the TEST goroutine while the command runs on
	// another, which makes the guard load-bearing rather than defensive.
	mu          sync.Mutex
	vmPresentMu bool
	createdForm url.Values
}

func (f *vmCreateFake) present() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.vmPresentMu
}

func (f *vmCreateFake) setPresent(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vmPresentMu = v
}

func (f *vmCreateFake) form() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createdForm
}

func (f *vmCreateFake) setForm(v url.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createdForm = v
}

// newPresentFake starts with the VM already visible on this node — the
// state where the NextVMID pre-check passes but VMCreate.Read finds
// something, i.e. the residual race the Changed==false backstop exists
// for.
func newPresentFake() *vmCreateFake {
	f := &vmCreateFake{}
	f.setPresent(true)
	return f
}

// waitForCount blocks until counter reaches want, or timeout elapses.
//
// These tests synchronize on an OBSERVABLE event (the pre-check's request
// landing at the fake server) rather than on a wall-clock guess at how
// long roster decryption, the TLS handshake and the first round-trip
// take. That guess is exactly what made an earlier version of the two
// lock tests below pass in isolation and then FAIL inside a loaded
// `make test` -race run, where a 5s context budget was consumed entirely
// by setup before the command ever reached the lock it was supposed to
// block on.
func waitForCount(counter *int32, want int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if atomic.LoadInt32(counter) >= want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// runVMCreateAsync starts `vm create <vmid>` on its own goroutine with a
// deadline-free context, so the ONLY thing that can release it is the
// lock it is waiting on. Returns a channel carrying its exit error.
func runVMCreateAsync(rosterPath, vmid string) <-chan error {
	done := make(chan error, 1)
	go func() {
		cmd := newVMCreateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", vmid, "cores=4"})
		done <- cmd.Execute()
	}()
	return done
}

// newVMCreateServer wires f up as a TLS httptest server speaking the
// /api2/json-prefixed paths the roster-driven client actually uses.
func newVMCreateServer(t *testing.T, node string, vmid int, f *vmCreateFake) *httptest.Server {
	t.Helper()
	upid := fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:qmcreate:%d:root@pam:", node, vmid)
	base := "/api2/json"

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == base+"/cluster/nextid":
			atomic.AddInt32(&f.nextIDChecks, 1)
			if got := r.URL.Query().Get("vmid"); got != fmt.Sprint(vmid) {
				t.Errorf("vm create must consult NextVMID's PIN path only (?vmid=%d), got query %q", vmid, r.URL.RawQuery)
			}
			if f.nextIDBroken {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if f.nextIDStatus != 0 {
				w.WriteHeader(f.nextIDStatus)
				_, _ = fmt.Fprint(w, `{"data":null}`)
				return
			}
			if f.nextIDTaken {
				// The exact body shape PVE returns for a taken vmid — see
				// internal/pve/nextvmid_test.go's own canned fixture.
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"errors":{"vmid":"VM %d already exists"},"data":null}`, vmid)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":%q}`, fmt.Sprint(vmid))

		case r.URL.Path == fmt.Sprintf("%s/nodes/%s/qemu/%d/status/current", base, node, vmid):
			if !f.present() {
				http.Error(w, "no such vm", http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"status":"running","vmid":%d}}`, vmid)

		case r.URL.Path == fmt.Sprintf("%s/nodes/%s/qemu/%d/config", base, node, vmid):
			_, _ = fmt.Fprint(w, `{"data":{"name":"already-here","cores":2}}`)

		case r.URL.Path == fmt.Sprintf("%s/nodes/%s/qemu", base, node) && r.Method == http.MethodPost:
			atomic.AddInt32(&f.createCalls, 1)
			if err := r.ParseForm(); err != nil {
				// t.Errorf, never t.Fatalf: this runs on httptest's own
				// per-request goroutine, and t.Fatalf calls runtime.Goexit
				// on its CALLING goroutine — which would abandon this
				// handler without ever writing a response, hang the client,
				// and surface as an unrelated 120s timeout somewhere else.
				t.Errorf("ParseForm: %v", err)
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			f.setForm(r.PostForm)
			if f.createRejects {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"errors":{"vmid":"VM %d already exists"},"data":null}`, vmid)
				return
			}
			// The create "succeeds": from here on the VM is present, so
			// idempotent.Run's own best-effort post-Apply re-read sees it.
			f.setPresent(true)
			_, _ = fmt.Fprintf(w, `{"data":%q}`, upid)

		case strings.HasPrefix(r.URL.Path, fmt.Sprintf("%s/nodes/%s/tasks/", base, node)):
			_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, upid, node)

		default:
			http.NotFound(w, r)
		}
	}))
}

// vmCreateRoster points a one-target roster at srv and arms the
// passphrase env var, the same two-line preamble every other command test
// in this package opens with.
func vmCreateRoster(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return rosterPath
}

// TestNewVMCreateCmd_Success is the baseline the collision tests are
// measured against: a free vmid creates, reports the id it used, and puts
// the caller's parameters (tags included, atomically, with no separate
// post-create tag write) on the create call itself.
func TestNewVMCreateCmd_Success(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4", "memory=2048", "tags=pveforge"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "vm 100 created") {
		t.Errorf("expected the created vmid to be reported, got: %q", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Fatalf("expected exactly 1 create call, got %d", got)
	}
	if got := atomic.LoadInt32(&f.nextIDChecks); got != 1 {
		t.Errorf("expected exactly 1 NextVMID pin check, got %d", got)
	}
	if got := f.form().Get("vmid"); got != "100" {
		t.Errorf("create form vmid = %q, want 100", got)
	}
	if got := f.form().Get("cores"); got != "4" {
		t.Errorf("create form cores = %q, want 4", got)
	}
	if got := f.form().Get("tags"); got != "pveforge" {
		t.Errorf("create form tags = %q, want pveforge — tags must ride the create call itself, never a separate post-create write", got)
	}
}

// TestNewVMCreateCmd_TakenVMID_ErrorsAndNamesIt is the unit's central
// guarantee AND the sensitivity test for the NextVMID pre-check.
//
// The fake deliberately reports the vmid taken CLUSTER-WIDE (via
// /cluster/nextid, which is what NextVMID's pin path consults) while the
// VM is NOT visible on this node (GetVM 404s) — a real, ordinary state:
// the VM lives on a different node of the same cluster. On that state the
// pre-check is the ONLY thing standing between the caller and a create,
// because VMCreate.Read would see nothing, Satisfied would be false, and
// the Op would happily Apply.
//
// So: delete the `client.NextVMID(...)` pre-check from newVMCreateCmd and
// this test fails — the command exits 0, createCalls becomes 1, and the
// shipped Satisfied semantics never get a chance to object. That is the
// mutation this test is here to catch.
func TestNewVMCreateCmd_TakenVMID_ErrorsAndNamesIt(t *testing.T) {
	f := &vmCreateFake{nextIDTaken: true}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected vm create against a taken vmid to ERROR, got success — a silent no-op is exactly what this command exists to prevent")
	}
	if !strings.Contains(err.Error(), "100") {
		t.Errorf("the error must NAME the taken vmid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "already taken") {
		t.Errorf("expected NextVMID's own verbatim pin-taken text, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("a refused vmid must never reach the create call, got %d create calls", got)
	}
}

// TestNewVMCreateCmd_PinCheck595_RefusesNamingTheStatus pins the pin
// pre-check's behaviour on a node pveproxy cannot reach: the create is
// refused before any POST, and the refusal names the status. On
// v0.8.2-pveforge.0 the 595 was swallowed and only P1's unverifiable-read
// guard stopped the create, with an error that said nothing about the
// status.
func TestNewVMCreateCmd_PinCheck595_RefusesNamingTheStatus(t *testing.T) {
	f := &vmCreateFake{nextIDStatus: 595}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected vm create to refuse when its pin check answers 595")
	}
	if !strings.Contains(err.Error(), "595") {
		t.Errorf("the refusal must name the status 595, got: %v", err)
	}
	if errors.Is(err, pve.ErrUnverifiableRead) {
		t.Errorf("the refusal is ErrUnverifiableRead: the status never reached the command, only its null payload did: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("a refused pin check must never reach the create call, got %d create calls", got)
	}
}

// TestNewVMCreateCmd_TakenVMID_NeverSubstitutesAnotherID guards the other
// half of the contract: the refusal must be terminal. A caller who asked
// for one VM must not discover it created one at an id it never saw, so
// nothing may retry the walk-forward search after a pin is refused.
func TestNewVMCreateCmd_TakenVMID_NeverSubstitutesAnotherID(t *testing.T) {
	f := &vmCreateFake{nextIDTaken: true}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error")
	}
	// Exactly one pin check and no bare /cluster/nextid call: the fake's
	// handler fails the test if it ever sees a request without ?vmid=100,
	// which is what an unpinned walk-forward search would issue.
	if got := atomic.LoadInt32(&f.nextIDChecks); got != 1 {
		t.Errorf("expected exactly 1 pin check and no walk-forward search, got %d nextid calls", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("expected no create at any vmid, got %d", got)
	}
}

// TestNewVMCreateCmd_ResidualRace_ChangedFalseBackstopFires is the
// sensitivity test for the post-Run backstop.
//
// It simulates exactly the window the backstop exists for: the pre-check
// PASSES (/cluster/nextid reports the vmid free), but by the time
// VMCreate.Read runs the VM is there. VMCreate.Satisfied returns true on
// a non-empty read (internal/idempotent/vmcreate.go:158-160), so
// idempotent.Run skips Apply and returns success with Changed == false —
// a silent no-op. Without the backstop the command exits 0 having created
// nothing.
//
// So: delete the `if !res.Changed` branch from newVMCreateCmd and this
// test fails with a nil error. Note the pre-check cannot save this case —
// it already passed — which is what makes the two guards genuinely
// independent rather than one guard tested twice.
func TestNewVMCreateCmd_ResidualRace_ChangedFalseBackstopFires(t *testing.T) {
	f := newPresentFake()
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the Changed==false backstop to turn the Op's idempotent-satisfied no-op into an error, got success")
	}
	if !strings.Contains(err.Error(), "100") {
		t.Errorf("the backstop error must NAME the vmid, got: %v", err)
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected the backstop to say the vm already exists, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.nextIDChecks); got != 1 {
		t.Errorf("the pre-check must still have run (and passed), got %d nextid calls", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("Run must have skipped Apply on the satisfied path, got %d create calls", got)
	}
}

// TestNewVMCreateCmd_SerializedUnderPerVMLockKey names, in executable
// assertions, WHICH lock key covers the create: {qa-pve-01, vm, 100} —
// the same per-VM key `vm get` and `vm set` already use. It takes a PAIR
// of tests to identify a key, because "it blocked" alone is also what a
// coarser target-wide lock would look like:
//
//   - here: holding {vm,100} blocks the create, and it never reaches the
//     create call, so the authoritative existence check idempotent.Run
//     performs under that key really is serialized against a concurrent
//     pveforge mutation on this VMID;
//   - next test: holding {vm,101} does NOT block it, so the key is
//     per-VMID rather than target- or node-wide.
//
// Deliberately asserts BEHAVIOR (blocked, then completes on release)
// rather than matching the lock key's text in a timeout error: the
// text-matching version depended on a context deadline firing in exactly
// the right phase, which is not a property that survives a loaded machine.
func TestNewVMCreateCmd_SerializedUnderPerVMLockKey(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlock, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	done := runVMCreateAsync(rosterPath, "100")

	// The pre-check runs BEFORE idempotent.Run takes the lock, so wait for
	// it to land: past this point the command is at the lock, and the
	// grace below measures the lock wait rather than setup.
	//
	// NOTE for anyone mutation-testing the pre-check: deleting the
	// client.NextVMID call makes this wait run its full 120s before failing,
	// so the suite LOOKS hung for two minutes. It is not hung — it is this
	// line correctly reporting that the pre-check never happened.
	if !waitForCount(&f.nextIDChecks, 1, 120*time.Second) {
		t.Fatal("the NextVMID pre-check never reached the fake server")
	}

	select {
	case err := <-done:
		t.Fatalf("vm create completed while %s was held by another mutation: %v", key, err)
	case <-time.After(time.Second):
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("the create must never run while another mutation holds %s, got %d create calls", key, got)
	}

	if err := unlock(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("vm create failed after the lock released: %v", err)
		}
	case <-time.After(120 * time.Second):
		t.Fatalf("vm create never completed after %s was released", key)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("expected exactly 1 create once the lock released, got %d", got)
	}
}

// TestNewVMCreateCmd_LockKeyIsPerVMIDNotTargetWide is the specificity half
// of the pair: a mutation held on a DIFFERENT vmid must not block this
// create at all.
func TestNewVMCreateCmd_LockKeyIsPerVMIDNotTargetWide(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	other := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "101"}
	unlock, err := lock.Mutation(context.Background(), rosterPath, other)
	if err != nil {
		t.Fatalf("acquire mutation on %s: %v", other, err)
	}
	defer func() { _ = unlock() }()

	select {
	case err := <-runVMCreateAsync(rosterPath, "100"):
		if err != nil {
			t.Fatalf("a mutation held on %s must not block a create of vm 100: %v", other, err)
		}
	case <-time.After(120 * time.Second):
		t.Fatalf("a mutation held on %s blocked a create of vm 100 — the create lock is not per-VMID", other)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("expected the create to proceed, got %d create calls", got)
	}
}

// TestNewVMCreateCmd_RejectsAutoAllocationSentinel covers the one piece of
// vmid validation this command does: 0 is NextVMID's "no pin,
// auto-allocate" sentinel, and auto-allocation is not this command's
// contract. This is sentinel hygiene, not band or range policy — nothing
// here knows about VMID ranges.
func TestNewVMCreateCmd_RejectsAutoAllocationSentinel(t *testing.T) {
	for _, arg := range []string{"0", "-1"} {
		cmd := newVMCreateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		// "--" so cobra reads a negative vmid as a positional argument
		// rather than as the shorthand flag "-1".
		cmd.SetArgs([]string{"--", "qa-pve-01", arg, "cores=4"})
		err := cmd.Execute()
		if err == nil {
			t.Fatalf("vmid %s: expected an error, got success", arg)
		}
		if !strings.Contains(err.Error(), "explicit positive vmid") {
			t.Errorf("vmid %s: expected the auto-allocation refusal, got: %v", arg, err)
		}
	}
}

func TestNewVMCreateCmd_InvalidVMID(t *testing.T) {
	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"qa-pve-01", "not-a-number", "cores=4"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid vmid") {
		t.Fatalf("expected an invalid-vmid error, got: %v", err)
	}
}

// TestNewVMCreateCmd_OrphanIPConfigRejected proves the explicit
// VMCreate.Validate() call ahead of idempotent.Run is load-bearing: an
// ipconfigN with no matching netN is refused before any network call.
func TestNewVMCreateCmd_OrphanIPConfigRejected(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "ipconfig0=ip=10.0.0.5/24"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no matching net0") {
		t.Fatalf("expected an orphan-ipconfig rejection, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("expected no create call, got %d", got)
	}
}

func TestVMCreateParams_ModeSelection(t *testing.T) {
	if _, err := vmCreateParams(nil, "", ""); err == nil {
		t.Error("expected an error when no input mode is given")
	}
	if _, err := vmCreateParams([]string{"cores=4"}, `{"memory":"2048"}`, ""); err == nil {
		t.Error("expected an error when two input modes are given")
	}
	got, err := vmCreateParams(nil, `{"memory":"2048"}`, "")
	if err != nil {
		t.Fatalf("vmCreateParams(--json): %v", err)
	}
	if got.Get("memory") != "2048" {
		t.Errorf("--json memory = %q, want 2048", got.Get("memory"))
	}
}

// TestNewVMCreateCmd_CreateTimeCollision_SurfacesPVEsOwnError covers the
// third and last collision path: the pre-check passes, VMCreate.Read sees
// nothing, and the id is taken only by the time CreateVM itself runs.
// There is nothing left to catch it client-side, so the requirement is
// that PVE's own verbatim rejection reaches the caller — never swallowed,
// and never retried into some other vmid the caller did not ask for.
func TestNewVMCreateCmd_CreateTimeCollision_SurfacesPVEsOwnError(t *testing.T) {
	f := &vmCreateFake{createRejects: true}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the create-time collision to fail the command")
	}
	if !strings.Contains(err.Error(), "VM 100 already exists") {
		t.Errorf("expected PVE's own verbatim rejection text to reach the caller, got: %v", err)
	}
	// Exactly one create attempt, at the vmid the caller named: a retry
	// that silently moved to another id is the failure this must not ship.
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("expected exactly 1 create attempt and no substitution, got %d", got)
	}
	if got := f.form().Get("vmid"); got != "100" {
		t.Errorf("the single create attempt must be at the requested vmid, got %q", got)
	}
}

// TestNewVMCreateCmd_RejectsVMIDAsCreateParameter covers the one place a
// user-typed value could vanish without a word. pve.CreateVM stamps
// form.Set("vmid", ...) from the Op's VMID, so a `vmid=999` among the
// create parameters is overwritten by the positional — the safe
// resolution, but a silent one. On the command whose entire contract is
// that the VMID is explicit, silently discarding an explicitly typed vmid
// is the wrong shape even when the outcome is right.
func TestNewVMCreateCmd_RejectsVMIDAsCreateParameter(t *testing.T) {
	f := &vmCreateFake{}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4", "vmid=999"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a vmid= create parameter to be REFUSED, not silently discarded")
	}
	if !strings.Contains(err.Error(), "vmid is the positional argument") {
		t.Errorf("expected the positional-argument explanation, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("expected no create call, got %d", got)
	}
	// Refused before any network call at all: parameter parsing happens
	// ahead of client resolution.
	if got := atomic.LoadInt32(&f.nextIDChecks); got != 0 {
		t.Errorf("expected the refusal before any PVE contact, got %d nextid calls", got)
	}
}

// TestNewVMCreateCmd_PreCheckFailsClosedOnNonTakenError guards the
// fail-closed direction of the pre-check, which nothing else in this suite
// covers.
//
// vmidFree only reads a rejection as "taken" when it matches PVE's own
// vmid-specific text (internal/pve.isVMIDTakenError); ANY other error —
// here a 500 — propagates. The failure this catches is a fail-OPEN
// regression: if that classification ever widened to treat an unknown
// error as "free", a PVE outage would stop being a refusal and start being
// a create against an id nobody verified.
func TestNewVMCreateCmd_PreCheckFailsClosedOnNonTakenError(t *testing.T) {
	f := &vmCreateFake{nextIDBroken: true}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	rosterPath := vmCreateRoster(t, srv)

	cmd := newVMCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100", "cores=4"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a failing vmid check to REFUSE the create, not fall through to it")
	}
	if !strings.Contains(err.Error(), "check pin 100") {
		t.Errorf("expected NextVMID's own check-pin wrapping, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("a create must never run when the vmid check itself failed, got %d create calls", got)
	}
}

// TestPrintAppliedFields_QuotesLikeKV pins that the "applied" confirmation
// lines follow the kv line contract: a value (or field) that could be
// misread is written as one JSON string, so a --json-file value holding a
// newline cannot forge a second applied line; plain values print as-is.
func TestPrintAppliedFields_QuotesLikeKV(t *testing.T) {
	pairs := []kvjson.Pair{
		{Field: "description", Value: "a\nqa: cores=99"},
		{Field: "cores", Value: "4"},
		{Field: "odd=key", Value: "null"},
	}
	var out bytes.Buffer
	if err := printAppliedFields(&out, "qa", []string{"description", "cores", "odd=key"}, pairs); err != nil {
		t.Fatalf("printAppliedFields: %v", err)
	}
	want := `qa: description="a\nqa: cores=99"` + "\n" +
		"qa: cores=4\n" +
		`qa: "odd=key"="null"` + "\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}
