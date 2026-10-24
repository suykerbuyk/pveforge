package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// newStorageCreateFakeServer returns a fake PVE answering the three calls
// `storage create` makes — GET /storage/{id} (read-back; 400 "No such storage."
// before the create, the config after), POST /storage (the create), and the GET
// re-read after — and a pointer to its POST count.
func newStorageCreateFakeServer(configJSON string) (*httptest.Server, *int32) {
	var posts int32
	var exists int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/storage/pveforge-harness":
			if atomic.LoadInt32(&exists) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"data":null,"errors":{"storage":"No such storage."}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":` + configJSON + `}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/storage":
			atomic.AddInt32(&posts, 1)
			atomic.StoreInt32(&exists, 1)
			_, _ = w.Write([]byte(`{"data":` + configJSON + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &posts
}

// TestNewStorageCreateCmd_Success drives the full command on an absent storage:
// it POSTs once and prints "created".
func TestNewStorageCreateCmd_Success(t *testing.T) {
	srv, posts := newStorageCreateFakeServer(`{"storage":"pveforge-harness","type":"zfspool","content":"images"}`)
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-07", "qa-pve-07")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageCreateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "pool=tank", "--data", "content=images"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out.String(), "storage pveforge-harness created") {
		t.Errorf("expected a created message, got: %q", out.String())
	}
	if atomic.LoadInt32(posts) != 1 {
		t.Errorf("expected exactly 1 POST /storage, got %d", atomic.LoadInt32(posts))
	}
}

// TestNewStorageCreateCmd_RequiredKeysGuardRefusesBeforeTheServer proves the
// client-side required-keys guard refuses --type zfspool with no pool BEFORE
// any request reaches PVE.
func TestNewStorageCreateCmd_RequiredKeysGuardRefusesBeforeTheServer(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-07", "qa-pve-07")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "content=images"}) // no pool
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --type zfspool with no pool to be refused")
	} else if !strings.Contains(err.Error(), "pool") {
		t.Errorf("expected the refusal to name the missing pool key, got: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("the required-keys guard must refuse before any request, got %d hits", atomic.LoadInt32(&hits))
	}
}

// TestNewStorageCreateCmd_DataTypeConflictRefused proves `--data type=` is
// refused in favor of `--type`, before any request (fold-in for surviving
// mutant C): dropping the guard would silently overwrite the --data value.
func TestNewStorageCreateCmd_DataTypeConflictRefused(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-07", "qa-pve-07")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "type=dir", "--data", "pool=tank"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --data type= to be refused in favor of --type")
	} else if !strings.Contains(err.Error(), "type") {
		t.Errorf("expected the refusal to name the type conflict, got: %v", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("the conflict must be refused before any request, got %d hits", atomic.LoadInt32(&hits))
	}
}

// TestNewStorageCreateCmd_DifferingRefusedNoPost proves a present+differing
// storage is refused by the command with no POST.
func TestNewStorageCreateCmd_DifferingRefusedNoPost(t *testing.T) {
	var posts int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			atomic.AddInt32(&posts, 1)
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		// Present, but type differs from the requested zfspool.
		_, _ = w.Write([]byte(`{"data":{"storage":"pveforge-harness","type":"dir","content":"images"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-07", "qa-pve-07")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newStorageCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "pool=tank", "--data", "content=images"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a refusal for a differing storage")
	} else if !strings.Contains(err.Error(), "differing") {
		t.Errorf("expected a differing-definition refusal, got: %v", err)
	}
	if atomic.LoadInt32(&posts) != 0 {
		t.Errorf("expected NO POST for a differing storage, got %d", atomic.LoadInt32(&posts))
	}
}

// TestNewStorageCreateCmd_LockKey is invariant 8: `storage create` takes the
// lock ObjectKey{Kind:"storage", ID:<name>} — proven both ways. Holding that
// exact key blocks the command (it never reaches PVE); a control holding an
// UNRELATED key does not block it.
func TestNewStorageCreateCmd_LockKey(t *testing.T) {
	srv, posts := newStorageCreateFakeServer(`{"storage":"pveforge-harness","type":"zfspool","content":"images"}`)
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-07", "qa-pve-07")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Control: an unrelated mutation (a DIFFERENT storage name) must NOT block
	// the create — proving the key is per-name, not per-kind.
	control := newStorageCreateCmd()
	control.SetOut(&bytes.Buffer{})
	control.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "pool=tank", "--data", "content=images"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "some-other-storage"}, control)

	// Now hold the storage's OWN key and prove the create blocks on it.
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}
	atomic.StoreInt32(posts, 0)

	cmd := newStorageCreateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-07", "pveforge-harness", "--type", "zfspool", "--data", "pool=tank", "--data", "content=images"})
	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("expected the create to be blocked by the pending mutation and time out")
	}
	if got := atomic.LoadInt32(posts); got != 0 {
		t.Errorf("expected the create to never reach PVE while the storage key was held, got %d POSTs", got)
	}
	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}
}
