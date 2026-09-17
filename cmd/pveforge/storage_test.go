package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
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

// TestNewStorageGetCmd_BlocksOnPendingMutation proves `storage get`
// participates in the locking protocol — see the matching vm get test for
// the full rationale.
func TestNewStorageGetCmd_BlocksOnPendingMutation(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"lvmthin"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "storage", ID: "local-lvm"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newStorageGetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "local-lvm"})

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

	cmd2 := newStorageGetCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "local-lvm"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
	}
}

func TestNewStorageGetCmd_RequiresTwoArgs(t *testing.T) {
	cmd := newStorageGetCmd()
	cmd.SetArgs([]string{"qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing storage-name argument")
	}
}

// --- storage orphans ----------------------------------------------------

func TestNewStorageOrphansCmd_SingleStorage_Success(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/api2/json/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-105-disk-0","vmid":105,"content":"images"}]}`))
		case "/api2/json/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageOrphansCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "local-lvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "local-lvm:vm-105-disk-0") {
		t.Errorf("expected the orphaned volid in output, got:\n%s", got)
	}
}

// TestNewStorageOrphansCmd_JSONOutput documents the --output json path
// (the default CLI-wiring test above only exercises the default kv
// format) — proves the {"orphans": [...]} wrapper round-trips correctly
// as valid, parseable JSON too.
func TestNewStorageOrphansCmd_JSONOutput(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/api2/json/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-105-disk-0","vmid":105,"content":"images"}]}`))
		case "/api2/json/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageOrphansCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "--output", "json", "qa-pve-01", "local-lvm"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var parsed struct {
		Orphans []struct {
			Volid string `json:"volid"`
		} `json:"orphans"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out.String())
	}
	if len(parsed.Orphans) != 1 || parsed.Orphans[0].Volid != "local-lvm:vm-105-disk-0" {
		t.Errorf("unexpected parsed orphans: %+v", parsed.Orphans)
	}
}

// TestNewStorageOrphansCmd_NodeWide_SkipsDisabledStorage proves the
// node-wide scan (no storage-name given) skips a disabled storage
// WITHOUT ever calling its content endpoint — asserted on call count,
// not just on the rendered output, per the Chair's requirement.
func TestNewStorageOrphansCmd_NodeWide_SkipsDisabledStorage(t *testing.T) {
	var disabledHits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "disabled-storage") {
			atomic.AddInt32(&disabledHits, 1)
			http.Error(w, "must never be called", http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/api2/json/nodes/qa-pve-01/storage":
			_, _ = w.Write([]byte(`{"data":[
				{"storage":"enabled-storage","enabled":1},
				{"storage":"disabled-storage","enabled":0}
			]}`))
		case "/api2/json/nodes/qa-pve-01/storage/enabled-storage/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"enabled-storage","type":"lvmthin","shared":0}}`))
		case "/api2/json/nodes/qa-pve-01/storage/enabled-storage/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"enabled-storage:vm-200-disk-0","vmid":200,"content":"images"}]}`))
		case "/api2/json/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageOrphansCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := atomic.LoadInt32(&disabledHits); got != 0 {
		t.Errorf("expected disabled-storage's content endpoint to never be called, got %d hits", got)
	}
	got := out.String()
	if !strings.Contains(got, "enabled-storage:vm-200-disk-0") {
		t.Errorf("expected the enabled storage's orphan in output, got:\n%s", got)
	}
}

// TestNewStorageOrphansCmd_GetStoragesFailure_Errors proves a failed
// node-wide storage listing aborts the command rather than silently
// reporting zero orphans scanned.
func TestNewStorageOrphansCmd_GetStoragesFailure_Errors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/nodes/qa-pve-01/storage" {
			http.Error(w, "storage list exploded", http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageOrphansCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected an error when GetStorages fails, got output:\n%s", out.String())
	}
}

func TestNewStorageOrphansCmd_RequiresAtLeastOneArg(t *testing.T) {
	cmd := newStorageOrphansCmd()
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing target-id argument")
	}
}
