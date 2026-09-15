package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
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

// TestNewNetworkGetCmd_BlocksOnPendingMutation proves `network get`
// participates in the locking protocol — see the matching vm get test for
// the full rationale.
func TestNewNetworkGetCmd_BlocksOnPendingMutation(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"cidr":"10.0.0.5/24"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// The lock is keyed per-NODE ("qa-pve-01", this test's target's own
	// resolved node — see newTestRosterWithTLSTarget's target/node
	// arguments above), not per-iface: PVE's staged network config is
	// node-wide, matching NetworkBridgeEnsure's own NetworkLockKey (see
	// internal/idempotent/networkbridge.go).
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "network", ID: "qa-pve-01"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	cmd := newNetworkGetCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "vmbr0"})

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

	cmd2 := newNetworkGetCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "vmbr0"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
	}
}

func TestNewNetworkGetCmd_RequiresTwoArgs(t *testing.T) {
	cmd := newNetworkGetCmd()
	cmd.SetArgs([]string{"qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing iface argument")
	}
}

// --- network bridge create/destroy: CLI wiring and argument/flag
// validation. The full mutation round trip (real REST+SSH stage/guard/
// commit/verify sequence) is exercised end to end against a real
// *pve.RoutedClient by internal/idempotent's own
// TestNetworkBridgeEnsure_Apply_Create_FullStack/..._Destroy_FullStack —
// deliberately not duplicated here; these tests cover only what's unique
// to this layer: flag/arg wiring and the CLI-specific duplicate-field
// guard, none of which need a live roster or server.

func TestWantedFieldsFromKVArgs_DuplicateFieldRejected(t *testing.T) {
	_, err := wantedFieldsFromKVArgs([]string{"bridge_ports=eth0", "bridge_ports=eth1"})
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("expected a duplicate-field error, got %v", err)
	}
}

func TestWantedFieldsFromKVArgs_Success(t *testing.T) {
	wanted, err := wantedFieldsFromKVArgs([]string{"type=bridge", "bridge_ports=eth0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wanted["type"] != "bridge" || wanted["bridge_ports"] != "eth0" {
		t.Fatalf("unexpected wanted map: %+v", wanted)
	}
}

func TestNewNetworkBridgeCreateCmd_RequiresManagementBridgeFlag(t *testing.T) {
	cmd := newNetworkBridgeCreateCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"qa-pve-01", "vmbr1", "type=bridge"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "management-bridge") {
		t.Fatalf("expected an error naming the required --management-bridge flag, got %v", err)
	}
}

func TestNewNetworkBridgeCreateCmd_RequiresAtLeastTwoArgs(t *testing.T) {
	cmd := newNetworkBridgeCreateCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--management-bridge", "vmbr0", "qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing iface argument")
	}
}

// TestNewNetworkBridgeCreateCmd_DuplicateFieldRejectedBeforeResolvingClient
// proves the duplicate-field check runs before any roster/target
// resolution — no --roster flag is even given, so resolveRoutedClient
// would fail with a different error if the duplicate check didn't
// short-circuit first.
func TestNewNetworkBridgeCreateCmd_DuplicateFieldRejectedBeforeResolvingClient(t *testing.T) {
	cmd := newNetworkBridgeCreateCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--management-bridge", "vmbr0", "qa-pve-01", "vmbr1", "type=bridge", "type=other"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("expected a duplicate-field error, got %v", err)
	}
}

func TestNewNetworkBridgeDestroyCmd_RequiresManagementBridgeFlag(t *testing.T) {
	cmd := newNetworkBridgeDestroyCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"qa-pve-01", "vmbr1"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "management-bridge") {
		t.Fatalf("expected an error naming the required --management-bridge flag, got %v", err)
	}
}

func TestNewNetworkBridgeDestroyCmd_RequiresExactlyTwoArgs(t *testing.T) {
	cmd := newNetworkBridgeDestroyCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--management-bridge", "vmbr0", "qa-pve-01", "vmbr1", "extra-arg"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an unexpected extra positional argument (destroy takes no field=value args)")
	}
}

// TestNewNetworkBridgeCreateCmd_NoForceFlag and its destroy counterpart
// prove the deliberate design property that neither command wires a
// --force flag at all — see NetworkBridgeEnsure's own doc comment (step 5)
// on why no bypass is offered for the guard check.
func TestNewNetworkBridgeCreateCmd_NoForceFlag(t *testing.T) {
	cmd := newNetworkBridgeCreateCmd()
	if f := cmd.Flags().Lookup("force"); f != nil {
		t.Fatalf("expected no --force flag on network bridge create, found: %+v", f)
	}
}

func TestNewNetworkBridgeDestroyCmd_NoForceFlag(t *testing.T) {
	cmd := newNetworkBridgeDestroyCmd()
	if f := cmd.Flags().Lookup("force"); f != nil {
		t.Fatalf("expected no --force flag on network bridge destroy, found: %+v", f)
	}
}

func TestNewNetworkBridgeCreateCmd_MutationTierIsMutating(t *testing.T) {
	cmd := newNetworkBridgeCreateCmd()
	if got := cmd.Annotations[mutationAnnotationKey]; got != mutationMutating {
		t.Errorf("mutation tier = %q, want %q", got, mutationMutating)
	}
}

func TestNewNetworkBridgeDestroyCmd_MutationTierIsDestructive(t *testing.T) {
	cmd := newNetworkBridgeDestroyCmd()
	if got := cmd.Annotations[mutationAnnotationKey]; got != mutationDestructive {
		t.Errorf("mutation tier = %q, want %q", got, mutationDestructive)
	}
}
