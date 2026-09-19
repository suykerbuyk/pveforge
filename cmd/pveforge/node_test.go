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

// TestNewNodeGetCmd_BlocksOnPendingMutation proves `node get` participates
// in the locking protocol — see the matching vm get test for the full
// rationale.
func TestNewNodeGetCmd_BlocksOnPendingMutation(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"uptime":12345}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Control: a mutation on a DIFFERENT node must not block this read.
	control := newNodeGetCmd()
	control.SetOut(&bytes.Buffer{})
	control.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "node", ID: "qa-pve-02"}, control)
	atomic.StoreInt32(&hits, 0)

	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "node", ID: "qa-pve-01"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newNodeGetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})

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

	cmd2 := newNodeGetCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--roster", rosterPath, "qa-pve-01"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
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
