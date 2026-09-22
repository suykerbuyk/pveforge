package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewAPIGetCmd_Success(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"uptime":12345}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodGet, "get")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "-o", "json", "--data", "type=qemu", "/nodes/qa-pve-01/status", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotPath != "/api2/json/nodes/qa-pve-01/status" {
		t.Errorf("path = %q", gotPath)
	}
	if gotQuery != "type=qemu" {
		t.Errorf("query = %q, want type=qemu", gotQuery)
	}
	if !strings.Contains(out.String(), `"uptime": 12345`) {
		t.Errorf("expected uptime in output, got:\n%s", out.String())
	}
}

func TestNewAPIPostCmd_MatchedPathLocksAutomaticallyNoFlagNeeded(t *testing.T) {
	var gotForm string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm.Get("snapname")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodPost, "post")
	var out bytes.Buffer
	cmd.SetOut(&out)
	// No --unsafe-no-lock: /nodes/{node}/qemu/{vmid}/snapshot matches the
	// vm pattern, so it must lock (and succeed) automatically.
	cmd.SetArgs([]string{"--roster", rosterPath, "--data", "snapname=before-upgrade", "/nodes/qa-pve-01/qemu/100/snapshot", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotForm != "before-upgrade" {
		t.Errorf("posted snapname = %q, want before-upgrade", gotForm)
	}
}

func TestNewAPIPutCmd_Success(t *testing.T) {
	var gotForm string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm.Get("cores")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodPut, "put")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--roster", rosterPath, "--data", "cores=4", "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotForm != "4" {
		t.Errorf("posted cores = %q, want 4", gotForm)
	}
	// An empty response body decodes as null, which kv renders as one
	// data=null line: the one rule for every non-object payload (see
	// renderAPIResult). It used to render as nothing, which a null could not
	// be told apart from an empty object by.
	if out.String() != "data=null\n" {
		t.Errorf("expected kv output %q for a null response, got:\n%s", "data=null\n", out.String())
	}
}

func TestNewAPIDeleteCmd_Success(t *testing.T) {
	var gotMethod, gotQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodDelete, "delete")
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--roster", rosterPath, "--data", "force=1", "/nodes/qa-pve-01/qemu/100/snapshot/before-upgrade", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotQuery != "force=1" {
		t.Errorf("query = %q, want force=1", gotQuery)
	}
}

// TestNewAPIGetCmd_UnmatchedPathProceedsUnconditionally is the fix this
// task's own review corrected: a GET on an unmatched path has no lock key
// anything else could ever be queuing a mutation against (PRD §3.4's
// "pending mutation takes priority over a pending read" has nothing to
// protect there), so it must proceed with no flag and no warning — unlike
// post/put/delete, which still refuse (see
// TestNewAPIMutatingCmd_RefusesUnmatchedPathWithoutUnsafeFlag below).
func TestNewAPIGetCmd_UnmatchedPathProceedsUnconditionally(t *testing.T) {
	var hit bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"version":"9.2.11"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodGet, "get")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	// Deliberately no --unsafe-no-lock: an unmatched-path GET must not
	// need it.
	cmd.SetArgs([]string{"--roster", rosterPath, "/version", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !hit {
		t.Fatal("expected the request to actually reach the fake PVE server")
	}
	if errOut.String() != "" {
		t.Errorf("expected no warning on stderr for an unmatched GET, got:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "9.2.11") {
		t.Errorf("expected the response rendered, got:\n%s", out.String())
	}
}

// TestNewAPIMutatingCmd_RefusesUnmatchedPathWithoutUnsafeFlag proves
// post/put/delete keep the original refuse-unless---unsafe-no-lock
// behavior unchanged: an unmatched path really can race against
// unknown/unmodeled state with nothing else guarding it, unlike a GET.
func TestNewAPIMutatingCmd_RefusesUnmatchedPathWithoutUnsafeFlag(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("must never reach the network when the lock gate refuses")
			}))
			defer srv.Close()

			rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
			t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

			cmd := newAPIVerbCmd(method, strings.ToLower(method))
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs([]string{"--roster", rosterPath, "/access/users", "qa-pve-01"})

			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected an error for an unmatched path without --unsafe-no-lock")
			}
			if !strings.Contains(err.Error(), "--unsafe-no-lock") {
				t.Errorf("expected the error to mention --unsafe-no-lock, got: %v", err)
			}
		})
	}
}

func TestNewAPIMutatingCmd_UnsafeNoLockProceedsAndWarns(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodPost, "post")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--roster", rosterPath, "--unsafe-no-lock", "/access/users", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(errOut.String(), "warning") || !strings.Contains(errOut.String(), "--unsafe-no-lock") {
		t.Errorf("expected a warning naming --unsafe-no-lock on stderr, got:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "/access/users") {
		t.Errorf("expected the warning to name the unmatched path, got:\n%s", errOut.String())
	}
}

// TestNewAPICmd_SharesLockKeyWithTypedCommand is the load-bearing interop
// test for this whole feature: a lock taken directly with the SAME
// lock.ObjectKey shape cmd/pveforge/vm.go's `get` uses must block BOTH a
// typed `vm get` AND a raw `api get` against the same VM — proving
// apiObjectKey's table actually reuses vm.go's own Kind/ID vocabulary
// rather than an independently-invented, non-interoperating one.
func TestNewAPICmd_SharesLockKeyWithTypedCommand(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Controls: a mutation on a DIFFERENT vm must block neither command.
	other := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "101"}
	vmControl := newVMGetCmd()
	vmControl.SetOut(&bytes.Buffer{})
	vmControl.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, vmControl)
	apiControl := newAPIVerbCmd(http.MethodGet, "get")
	apiControl.SetOut(&bytes.Buffer{})
	apiControl.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, apiControl)
	atomic.StoreInt32(&hits, 0)

	// Same key vm.go's own lock.Read call would use for vmid 100.
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	// Bounded: the api control above has just run, so a command that leaks
	// its lock past its own return makes this acquisition a named failure
	// here rather than a hang until the suite timeout.
	mctx, mcancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer mcancel()
	unlockMutation, err := lock.Mutation(mctx, rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v — a command run above still holds this object's lock after returning", err)
	}

	vmGet := newVMGetCmd()
	vmGet.SetOut(&bytes.Buffer{})
	vmGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	ctx1, cancel1 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel1()
	if err := vmGet.ExecuteContext(ctx1); err == nil {
		t.Fatal("expected the typed `vm get` to be blocked by the api-shaped mutation lock")
	} else if !strings.Contains(err.Error(), "acquire read lock") {
		t.Errorf("expected a read-lock-acquisition error from `vm get`, got: %v", err)
	}

	apiGet := newAPIVerbCmd(http.MethodGet, "get")
	apiGet.SetOut(&bytes.Buffer{})
	apiGet.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel2()
	if err := apiGet.ExecuteContext(ctx2); err == nil {
		t.Fatal("expected `api get` on the same vm path to be blocked by the same lock key")
	} else if !strings.Contains(err.Error(), "acquire lock for") {
		t.Errorf("expected a lock-acquisition error from `api get`, got: %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected neither read to reach the PVE API while the mutation held the lock, got %d hits", got)
	}

	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	apiGet2 := newAPIVerbCmd(http.MethodGet, "get")
	apiGet2.SetOut(&bytes.Buffer{})
	apiGet2.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"})
	ectx, ecancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer ecancel()
	if err := apiGet2.ExecuteContext(ectx); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
	}
}

// TestNewAPICmd_SharesLockKeyWithTypedCommand_LeadingZeroVMID is the
// regression test for the confirmed bug (adversarial review, 2026-09-14):
// the existing interop test above only ever used a well-formed vmid
// ("100"), which wouldn't have caught apiObjectKey capturing an
// unnormalized digit string. Here, `vm get` is invoked with the
// leading-zero CLI argument "0100" (which vm.go's own
// strconv.Atoi/Itoa round-trip normalizes to "100") while `api get`'s
// PATH names the leading-zero segment "/qemu/0100/..." (which
// apiObjectKey must ALSO normalize to "100") — both must still collide
// with a lock taken directly against ID "100", proving the two commands
// derive the identical key for the same real VM even when their inputs
// are spelled differently.
func TestNewAPICmd_SharesLockKeyWithTypedCommand_LeadingZeroVMID(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Controls: a mutation on a DIFFERENT vm must block neither command.
	other := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "101"}
	vmControl := newVMGetCmd()
	vmControl.SetOut(&bytes.Buffer{})
	vmControl.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "0100"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, vmControl)
	apiControl := newAPIVerbCmd(http.MethodGet, "get")
	apiControl.SetOut(&bytes.Buffer{})
	apiControl.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/0100/config", "qa-pve-01"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, apiControl)
	atomic.StoreInt32(&hits, 0)

	// The normalized key BOTH commands below must resolve to, despite
	// neither of their own inputs being spelled "100" verbatim.
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	// Bounded: the api control above has just run, so a command that leaks
	// its lock past its own return makes this acquisition a named failure
	// here rather than a hang until the suite timeout.
	mctx, mcancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer mcancel()
	unlockMutation, err := lock.Mutation(mctx, rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v — a command run above still holds this object's lock after returning", err)
	}

	vmGet := newVMGetCmd()
	vmGet.SetOut(&bytes.Buffer{})
	vmGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "0100"})
	ctx1, cancel1 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel1()
	if err := vmGet.ExecuteContext(ctx1); err == nil {
		t.Fatal("expected `vm get ... 0100` to be blocked by the ID:\"100\" mutation lock")
	} else if !strings.Contains(err.Error(), "acquire read lock") {
		t.Errorf("expected a read-lock-acquisition error from `vm get`, got: %v", err)
	}

	apiGet := newAPIVerbCmd(http.MethodGet, "get")
	apiGet.SetOut(&bytes.Buffer{})
	apiGet.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/0100/config", "qa-pve-01"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel2()
	if err := apiGet.ExecuteContext(ctx2); err == nil {
		t.Fatal("expected `api get .../qemu/0100/config` to be blocked by the ID:\"100\" mutation lock")
	} else if !strings.Contains(err.Error(), "acquire lock for") {
		t.Errorf("expected a lock-acquisition error from `api get`, got: %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected neither read to reach the PVE API while the mutation held the lock, got %d hits", got)
	}

	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	apiGet2 := newAPIVerbCmd(http.MethodGet, "get")
	apiGet2.SetOut(&bytes.Buffer{})
	apiGet2.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/0100/config", "qa-pve-01"})
	ectx, ecancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer ecancel()
	if err := apiGet2.ExecuteContext(ectx); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
	}
}

// TestNewAPICmd_SharesLockKeyWithTypedCommand_Network is the network
// analog of TestNewAPICmd_SharesLockKeyWithTypedCommand above: a lock
// taken directly with the node-keyed lock.ObjectKey{Kind: "network", ID:
// <node>} — the SAME key NetworkBridgeEnsure's own NetworkLockKey derives,
// and that `network bridge create|destroy` will use once wired into the
// CLI — must block BOTH a typed `network get` against some interface on
// that node AND a raw `api put` against the BARE network collection path
// (/nodes/{node}/network, with no trailing iface segment). The bare-path
// case is the one that mattered most here: before this fix, apiObjectKey's
// network pattern required a trailing "/{iface}" segment and so never
// matched the collection path at all, meaning a raw `pveforge api put
// /nodes/{node}/network` — the exact call NetworkBridgeEnsure's own commit
// step makes — took NO lock whatsoever.
func TestNewAPICmd_SharesLockKeyWithTypedCommand_Network(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"bridge","cidr":"10.0.0.5/24"}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Controls: a network mutation on a DIFFERENT node must block neither
	// command.
	other := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "network", ID: "qa-pve-02"}
	netControl := newNetworkGetCmd()
	netControl.SetOut(&bytes.Buffer{})
	netControl.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "vmbr0"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, netControl)
	apiControl := newAPIVerbCmd(http.MethodPut, "put")
	apiControl.SetOut(&bytes.Buffer{})
	apiControl.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/network", "qa-pve-01"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, other, apiControl)
	atomic.StoreInt32(&hits, 0)

	// The node-keyed lock `network bridge create|destroy` will use once
	// wired into the CLI, via NetworkBridgeEnsure's own NetworkLockKey.
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "network", ID: "qa-pve-01"}
	// Bounded: the api control above has just run, so a command that leaks
	// its lock past its own return makes this acquisition a named failure
	// here rather than a hang until the suite timeout.
	mctx, mcancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer mcancel()
	unlockMutation, err := lock.Mutation(mctx, rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v — a command run above still holds this object's lock after returning", err)
	}

	netGet := newNetworkGetCmd()
	netGet.SetOut(&bytes.Buffer{})
	netGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "vmbr0"})
	ctx1, cancel1 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel1()
	if err := netGet.ExecuteContext(ctx1); err == nil {
		t.Fatal("expected the typed `network get` to be blocked by the node-keyed mutation lock")
	} else if !strings.Contains(err.Error(), "acquire read lock") {
		t.Errorf("expected a read-lock-acquisition error from `network get`, got: %v", err)
	}

	apiPut := newAPIVerbCmd(http.MethodPut, "put")
	apiPut.SetOut(&bytes.Buffer{})
	// The bare collection path — no trailing iface segment — exactly what
	// NetworkBridgeEnsure's own commit/PUT and whole-node-revert/DELETE
	// calls use.
	apiPut.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/network", "qa-pve-01"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel2()
	if err := apiPut.ExecuteContext(ctx2); err == nil {
		t.Fatal("expected `api put` on the bare network collection path to be blocked by the same node-keyed lock")
	} else if !strings.Contains(err.Error(), "acquire lock for") {
		t.Errorf("expected a lock-acquisition error from `api put`, got: %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected neither call to reach the PVE API while the mutation held the lock, got %d hits", got)
	}

	if err := unlockMutation(); err != nil {
		t.Fatalf("release mutation: %v", err)
	}

	apiPut2 := newAPIVerbCmd(http.MethodPut, "put")
	apiPut2.SetOut(&bytes.Buffer{})
	apiPut2.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/network", "qa-pve-01"})
	ectx, ecancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer ecancel()
	if err := apiPut2.ExecuteContext(ectx); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful call after the mutation released, got %d hits", got)
	}
}

// TestNewAPICmd_APIMutationBlocksTypedRead proves the direction that
// actually matters most for the feature's safety claim: an `api post`
// mutation held via lock.Mutation must block the EXISTING typed `vm get`
// command, not just another `api` invocation.
func TestNewAPICmd_APIMutationBlocksTypedRead(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	// Control: the lock `api post` would take for a DIFFERENT vm must not
	// block this read.
	otherKey, ok := apiObjectKey("qa-pve-01", "/nodes/qa-pve-01/qemu/101/config")
	if !ok {
		t.Fatal("expected apiObjectKey to match the control path")
	}
	control := newVMGetCmd()
	control.SetOut(&bytes.Buffer{})
	control.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	requireRunsBesideUnrelatedMutation(t, rosterPath, otherKey, control)
	atomic.StoreInt32(&hits, 0)

	// Simulates the lock `api post /nodes/qa-pve-01/qemu/100/config` would
	// take, via the exact key apiObjectKey derives for that path.
	key, ok := apiObjectKey("qa-pve-01", "/nodes/qa-pve-01/qemu/100/config")
	if !ok {
		t.Fatal("expected apiObjectKey to match")
	}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}
	defer func() { _ = unlockMutation() }()

	vmGet := newVMGetCmd()
	vmGet.SetOut(&bytes.Buffer{})
	vmGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel()
	if err := vmGet.ExecuteContext(ctx); err == nil {
		t.Fatal("expected the typed `vm get` to be blocked by the api-derived mutation lock")
	} else if !strings.Contains(err.Error(), "acquire read lock") {
		t.Errorf("expected a read-lock-acquisition error, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected the read to never reach the PVE API while the mutation held the lock, got %d hits", got)
	}
}

func TestNewAPICmd_DataFlagRepeatable(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodGet, "get")
	cmd.SetOut(&bytes.Buffer{})
	// Unmatched path, no --unsafe-no-lock: a GET needs neither.
	cmd.SetArgs([]string{"--roster", rosterPath, "--data", "type=vm", "--data", "full=1", "/cluster/resources", "qa-pve-01"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotQuery.Get("type") != "vm" || gotQuery.Get("full") != "1" {
		t.Errorf("query = %v, want type=vm&full=1", gotQuery)
	}
}

func TestNewAPICmd_InvalidDataPair(t *testing.T) {
	cmd := newAPIVerbCmd(http.MethodGet, "get")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--data", "novalue", "/version", "qa-pve-01"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an invalid --data field=value pair")
	}
}

func TestNewAPICmd_RequiresTwoArgs(t *testing.T) {
	cmd := newAPIVerbCmd(http.MethodGet, "get")
	cmd.SetArgs([]string{"/version"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a missing target-id argument")
	}
}

func TestNewAPICmd_UnknownTarget(t *testing.T) {
	rosterPath := newTestRosterEmpty(t)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	cmd := newAPIVerbCmd(http.MethodGet, "get")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--roster", rosterPath, "--unsafe-no-lock", "/version", "does-not-exist"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a target not in the roster")
	}
}

func TestNewAPICmd_MutationTiers(t *testing.T) {
	cases := []struct {
		method string
		use    string
		want   string
	}{
		{http.MethodGet, "get", mutationSafe},
		{http.MethodPost, "post", mutationDestructive},
		{http.MethodPut, "put", mutationDestructive},
		{http.MethodDelete, "delete", mutationDestructive},
	}
	for _, c := range cases {
		cmd := newAPIVerbCmd(c.method, c.use)
		if got := cmd.Annotations[mutationAnnotationKey]; got != c.want {
			t.Errorf("%s: mutation tier = %q, want %q", c.use, got, c.want)
		}
	}
}

func TestParseDataParams(t *testing.T) {
	params, err := parseDataParams([]string{"a=1", "b=two"})
	if err != nil {
		t.Fatalf("parseDataParams: %v", err)
	}
	if params.Get("a") != "1" || params.Get("b") != "two" {
		t.Errorf("params = %v", params)
	}
}

func TestParseDataParams_Empty(t *testing.T) {
	params, err := parseDataParams(nil)
	if err != nil {
		t.Fatalf("parseDataParams: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("expected no params, got %v", params)
	}
}

func TestParseDataParams_Invalid(t *testing.T) {
	if _, err := parseDataParams([]string{"novalue"}); err == nil {
		t.Fatal("expected an error for a malformed pair")
	}
}

// ---------------------------------------------------------------------------
// Waiting on a returned task (pveforge-mutation-success-second-signal,
// Part 1). Every test that drives a task shortens WaitForTask's timings
// through pve.SetTaskTimingsForTests, so a fake that never flips to
// "stopped" ends in a bounded failure instead of the 10-minute ceiling.
// ---------------------------------------------------------------------------

// withFastTaskPolls points WaitForTask at a 5ms poll interval and a 2s
// ceiling for one test. A8 sets its own, longer ceiling; see that test.
func withFastTaskPolls(t *testing.T) {
	t.Helper()
	t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 2*time.Second))
}

// apiTestUPID is a well-formed UPID naming node, shaped like PVE's own.
func apiTestUPID(node string) string {
	return fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:qmstart:100:root@pam:", node)
}

// syncBuffer is a bytes.Buffer safe to write on one goroutine and read on
// another: a command writes stderr on its own goroutine while a fake's
// handler, on httptest's, snapshots it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// apiTaskFake is one PVE endpoint that answers an `api` verb with body, plus
// that task's status endpoint. Every other path answers as a running VM, so
// a typed `vm get` works against the same server. It counts each class of
// request separately.
type apiTaskFake struct {
	mutPath string // the raw path under test, without /api2/json
	body    string // JSON for the verb's "data" payload
	// status answers the n-th task-status poll (1-based) with an HTTP code
	// and a "data" payload. nil answers every poll stopped/OK. It must never
	// block: httptest's Close waits for in-flight handlers.
	status func(n int32) (int, string)
	// onFirstPoll, if set, runs inside the first poll's handler, before it
	// answers.
	onFirstPoll func()

	all, mutations, polls int32

	mu        sync.Mutex
	pollPaths []string
}

func (f *apiTaskFake) pollPathsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.pollPaths...)
}

// taskPayload is a task-status "data" payload echoing upid and its node, as
// real PVE does.
func taskPayload(upid, status, exitStatus string) string {
	node := strings.Split(upid, ":")[1]
	if exitStatus == "" {
		return fmt.Sprintf(`{"status":%q,"upid":%q,"node":%q}`, status, upid, node)
	}
	return fmt.Sprintf(`{"status":%q,"exitstatus":%q,"upid":%q,"node":%q}`, status, exitStatus, upid, node)
}

// newAPITaskServer serves f on a loopback TLS server and returns a roster
// whose one target, qa-pve-01, points at it. The server is closed by a
// t.Cleanup registered HERE, so it outlives every cleanup a test registers
// after this call — A8's goroutine join included.
func newAPITaskServer(t *testing.T, f *apiTaskFake) string {
	t.Helper()
	const base = "/api2/json"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.all, 1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status"):
			n := atomic.AddInt32(&f.polls, 1)
			f.mu.Lock()
			f.pollPaths = append(f.pollPaths, r.URL.Path)
			f.mu.Unlock()
			if n == 1 && f.onFirstPoll != nil {
				f.onFirstPoll()
			}
			code, data := http.StatusOK, ""
			if f.status != nil {
				code, data = f.status(n)
			} else {
				upid, _ := url.PathUnescape(strings.TrimSuffix(r.URL.Path[strings.Index(r.URL.Path, "/tasks/")+len("/tasks/"):], "/status"))
				data = taskPayload(upid, "stopped", "OK")
			}
			w.WriteHeader(code)
			_, _ = fmt.Fprintf(w, `{"data":%s}`, data)
		case r.URL.Path == base+f.mutPath:
			atomic.AddInt32(&f.mutations, 1)
			_, _ = fmt.Fprintf(w, `{"data":%s}`, f.body)
		default:
			_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100,"digest":"d"}}`))
		}
	}))
	t.Cleanup(srv.Close)

	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return rosterPath
}

// runAPICmd runs one `api` verb. Usage and error printing are silenced
// (the house pattern, as TestNewAPIMutatingCmd_RefusesUnmatchedPathWithoutUnsafeFlag
// does): cobra otherwise writes the usage text to the command's stdout on
// any RunE error, and "stdout is empty on failure" could never hold.
func runAPICmd(ctx context.Context, method string, errOut io.Writer, args ...string) (string, error) {
	cmd := newAPIVerbCmd(method, strings.ToLower(method))
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var out bytes.Buffer
	cmd.SetOut(&out)
	if errOut == nil {
		errOut = io.Discard
	}
	cmd.SetErr(errOut)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

// apiRenderedUPID is what a successful verb prints for a UPID payload.
func apiRenderedUPID(format, upid string) string {
	if format == "kv" {
		return "data=" + upid + "\n"
	}
	return fmt.Sprintf("%q\n", upid)
}

var apiFormats = []string{"kv", "json"}

// A1: a returned UPID is waited on, the command succeeds only once the task
// has, and stdout is exactly what the payload renders as. The UPID reaches
// stderr at DISPATCH — the snapshot is taken inside the first poll, before
// the wait can have finished.
func TestNewAPIPostCmd_WaitsOnReturnedTask(t *testing.T) {
	for _, format := range apiFormats {
		t.Run(format, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			errOut := &syncBuffer{}
			var snapMu sync.Mutex
			var stderrAtFirstPoll string
			f := &apiTaskFake{
				mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
				body:    fmt.Sprintf("%q", upid),
				status: func(n int32) (int, string) {
					if n == 1 {
						return http.StatusOK, taskPayload(upid, "running", "")
					}
					return http.StatusOK, taskPayload(upid, "stopped", "OK")
				},
				onFirstPoll: func() {
					snapMu.Lock()
					defer snapMu.Unlock()
					stderrAtFirstPoll = errOut.String()
				},
			}
			rosterPath := newAPITaskServer(t, f)

			out, err := runAPICmd(context.Background(), http.MethodPost, errOut,
				"--roster", rosterPath, "-o", format, f.mutPath, "qa-pve-01")
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if want := apiRenderedUPID(format, upid); out != want {
				t.Errorf("stdout = %q, want %q", out, want)
			}
			if got := atomic.LoadInt32(&f.polls); got != 2 {
				t.Errorf("task-status polls = %d, want 2 (running, then stopped)", got)
			}
			snapMu.Lock()
			defer snapMu.Unlock()
			if !strings.Contains(stderrAtFirstPoll, upid) {
				t.Errorf("stderr at the first poll = %q; the UPID must be printed at dispatch, before the wait", stderrAtFirstPoll)
			}
		})
	}
}

// A2: a task that ends with a non-OK exit status fails the command with the
// task's own error, and nothing reaches stdout.
func TestNewAPIPostCmd_FailedTaskFailsTheCommand(t *testing.T) {
	for _, format := range apiFormats {
		t.Run(format, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			f := &apiTaskFake{
				mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
				body:    fmt.Sprintf("%q", upid),
				status: func(int32) (int, string) {
					return http.StatusOK, taskPayload(upid, "stopped", "ERROR: x")
				},
			}
			rosterPath := newAPITaskServer(t, f)

			out, err := runAPICmd(context.Background(), http.MethodPost, nil,
				"--roster", rosterPath, "-o", format, f.mutPath, "qa-pve-01")
			var failed *pve.TaskFailedError
			if !errors.As(err, &failed) {
				t.Fatalf("expected a *pve.TaskFailedError, got: %v", err)
			}
			if failed.UPID != upid || failed.ExitStatus != "ERROR: x" {
				t.Errorf("TaskFailedError = %+v, want UPID %q and exit status %q", failed, upid, "ERROR: x")
			}
			if pve.IsTaskOutcomeUnknown(err) {
				t.Errorf("a task observed to fail is not outcome-unknown: %v", err)
			}
			if out != "" {
				t.Errorf("stdout must be empty when the task failed, got %q", out)
			}
		})
	}
}

// A3a: a status endpoint that keeps answering 503 is ridden out three times
// and given up on at the fourth — outcome unknown, never a task failure.
func TestNewAPIPostCmd_TransientPollFailuresEndOutcomeUnknown(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusServiceUnavailable, "null" },
	}
	rosterPath := newAPITaskServer(t, f)

	out, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01")
	if !pve.IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error, got: %v", err)
	}
	var failed *pve.TaskFailedError
	if errors.As(err, &failed) {
		t.Errorf("a poll failure must not be reported as a task failure: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 4 {
		t.Errorf("task-status polls = %d, want 4 (three transient, the fourth gives up)", got)
	}
	if out != "" {
		t.Errorf("stdout must be empty when the outcome is unknown, got %q", out)
	}
}

// A3b: a 404 from the status endpoint is not retried.
func TestNewAPIPostCmd_NotFoundPollEndsAtOnce(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusNotFound, "null" },
	}
	rosterPath := newAPITaskServer(t, f)

	_, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01")
	if !pve.IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 1 {
		t.Errorf("task-status polls = %d, want exactly 1", got)
	}
}

// A4: --no-wait on a locked path prints the UPID, never polls, and says the
// lock is released before the task finishes.
func TestNewAPIPostCmd_NoWaitOnLockedPath(t *testing.T) {
	for _, format := range apiFormats {
		t.Run(format, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			f := &apiTaskFake{mutPath: "/nodes/qa-pve-01/qemu/100/status/start", body: fmt.Sprintf("%q", upid)}
			rosterPath := newAPITaskServer(t, f)
			errOut := &syncBuffer{}

			out, err := runAPICmd(context.Background(), http.MethodPost, errOut,
				"--roster", rosterPath, "-o", format, "--no-wait", f.mutPath, "qa-pve-01")
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if want := apiRenderedUPID(format, upid); out != want {
				t.Errorf("stdout = %q, want %q", out, want)
			}
			if got := atomic.LoadInt32(&f.polls); got != 0 {
				t.Errorf("--no-wait must never poll, got %d polls", got)
			}
			if e := errOut.String(); !strings.Contains(e, "--no-wait") || !strings.Contains(e, "lock on") || !strings.Contains(e, "released now") {
				t.Errorf("expected a notice that the lock is released before the task finishes, got:\n%s", e)
			}
		})
	}
}

// A4b: on an unmatched path taken with --unsafe-no-lock there is no lock,
// so the --no-wait notice must not claim one was released.
func TestNewAPIPostCmd_NoWaitOnUnlockedPath(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{mutPath: "/cluster/backup", body: fmt.Sprintf("%q", upid)}
	rosterPath := newAPITaskServer(t, f)
	errOut := &syncBuffer{}

	if _, err := runAPICmd(context.Background(), http.MethodPost, errOut,
		"--roster", rosterPath, "--unsafe-no-lock", "--no-wait", f.mutPath, "qa-pve-01"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("--no-wait must never poll, got %d polls", got)
	}
	e := errOut.String()
	if strings.Contains(e, "released") || strings.Contains(e, "lock on") {
		t.Errorf("the notice claims a lock was released on a path that never had one:\n%s", e)
	}
	if !strings.Contains(e, "--no-wait") || !strings.Contains(e, "not checked") {
		t.Errorf("expected the no-lock --no-wait notice, got:\n%s", e)
	}
	if !strings.Contains(e, "WITHOUT internal/lock protection") {
		t.Errorf("expected the existing --unsafe-no-lock warning to still be printed, got:\n%s", e)
	}
}

// A5: the render table. One rule in kv — any top-level non-object renders
// as data=<value> — and JSON mode unchanged. Every row asserts a nil error
// and the exact bytes: a row that only counted polls would pass a mutant
// that sends "ok" to WaitForTask (refused before any poll).
func TestNewAPIPostCmd_RendersEveryPayloadShape(t *testing.T) {
	upid := apiTestUPID("qa-pve-01")
	rows := []struct {
		name, body, kv, json string
		polls                int32
	}{
		{"upid", fmt.Sprintf("%q", upid), "data=" + upid + "\n", fmt.Sprintf("%q\n", upid), 1},
		{"string", `"ok"`, "data=ok\n", "\"ok\"\n", 0},
		{"number", `42`, "data=42\n", "42\n", 0},
		{"null", `null`, "data=null\n", "null\n", 0},
		{"object", `{"a":1}`, "a=1\n", "{\n  \"a\": 1\n}\n", 0},
		{"array", `[1,2]`, "data=[1,2]\n", "[\n  1,\n  2\n]\n", 0},
		{"lowercase upid", `"upid:lower:x"`, "data=upid:lower:x\n", "\"upid:lower:x\"\n", 0},
		// kv line contract: a string that could forge a line, or read as
		// JSON null, is written as one JSON string (kvjson.QuoteValue).
		{"string with newline", `"a\nb=c"`, `data="a\nb=c"` + "\n", `"a\nb=c"` + "\n", 0},
		{"string null", `"null"`, `data="null"` + "\n", "\"null\"\n", 0},
	}
	for _, format := range apiFormats {
		for _, r := range rows {
			t.Run(format+"/"+r.name, func(t *testing.T) {
				withFastTaskPolls(t)
				f := &apiTaskFake{mutPath: "/nodes/qa-pve-01/qemu/100/config", body: r.body}
				rosterPath := newAPITaskServer(t, f)

				out, err := runAPICmd(context.Background(), http.MethodPost, nil,
					"--roster", rosterPath, "-o", format, f.mutPath, "qa-pve-01")
				if err != nil {
					t.Fatalf("Execute: %v", err)
				}
				want := r.kv
				if format == "json" {
					want = r.json
				}
				if out != want {
					t.Errorf("stdout = %q, want %q", out, want)
				}
				if got := atomic.LoadInt32(&f.polls); got != r.polls {
					t.Errorf("task-status polls = %d, want %d", got, r.polls)
				}
			})
		}
	}
}

// A6: a string claiming to be a UPID but one field short (6 colons) is an
// error, refused before any poll — never silently skipped, and never handed
// to proxmox.NewTask, which panics on exactly this shape.
func TestNewAPIPostCmd_MalformedUPIDIsRefused(t *testing.T) {
	withFastTaskPolls(t)
	f := &apiTaskFake{mutPath: "/nodes/qa-pve-01/qemu/100/status/start", body: `"UPID:n:1:2:3:4:5"`}
	rosterPath := newAPITaskServer(t, f)

	out, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01")
	if !pve.IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed upid") {
		t.Errorf("expected a malformed-upid error, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("a malformed UPID must be refused before polling, got %d polls", got)
	}
	if out != "" {
		t.Errorf("stdout must be empty, got %q", out)
	}
}

// A7: GET is never waited on, even when the payload is a UPID.
func TestNewAPIGetCmd_NeverWaits(t *testing.T) {
	for _, format := range apiFormats {
		t.Run(format, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			f := &apiTaskFake{mutPath: "/nodes/qa-pve-01/tasks", body: fmt.Sprintf("%q", upid)}
			rosterPath := newAPITaskServer(t, f)

			out, err := runAPICmd(context.Background(), http.MethodGet, nil,
				"--roster", rosterPath, "-o", format, f.mutPath, "qa-pve-01")
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if want := apiRenderedUPID(format, upid); out != want {
				t.Errorf("stdout = %q, want %q", out, want)
			}
			if got := atomic.LoadInt32(&f.polls); got != 0 {
				t.Errorf("GET must never poll a task, got %d polls", got)
			}
		})
	}
}

// A8: the object lock spans the task wait, and no longer.
//
// The task stays "running" until the test releases it — its duration is a
// channel, not a poll count or a clock. The windows are sized so that
// release is the ONLY bound that acts: phase 1 takes at most
// lockTestDeadline, phase 2 exactly lockTestDeadline (a blocked lock
// acquisition retries until its context expires), phase 3 at most 2s. So
// this test's own seam ceiling (30s) and the post's context (20s) are both
// far outside that ~6s window; with the package's usual 2s ceiling the wait
// times out mid-phase-2 and the post unlocks early.
//
// Every exit path — including a t.Fatal — releases the task and joins the
// goroutine BEFORE the seam's restore runs (cleanups are LIFO), so the
// restore never races the poll loop.
func TestNewAPIPostCmd_LockSpansTheTaskWait(t *testing.T) {
	t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 30*time.Second))

	upid := apiTestUPID("qa-pve-01")
	release := make(chan struct{})
	var releaseOnce sync.Once
	doRelease := func() { releaseOnce.Do(func() { close(release) }) }

	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status: func(int32) (int, string) {
			select {
			case <-release:
				return http.StatusOK, taskPayload(upid, "stopped", "OK")
			default:
				return http.StatusOK, taskPayload(upid, "running", "")
			}
		},
	}
	rosterPath := newAPITaskServer(t, f)

	vmGet := func() *cobra.Command {
		c := newVMGetCmd()
		c.SilenceUsage = true
		c.SilenceErrors = true
		c.SetOut(&bytes.Buffer{})
		c.SetErr(&bytes.Buffer{})
		c.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
		return c
	}

	// Phase 0, the control, BEFORE the post holds vm/100: `vm get 100`
	// reaches its own lock inside lockTestDeadline beside a mutation held on
	// a DIFFERENT vm.
	otherKey, ok := apiObjectKey("qa-pve-01", "/nodes/qa-pve-01/qemu/101/config")
	if !ok {
		t.Fatal("expected apiObjectKey to match the control path")
	}
	requireRunsBesideUnrelatedMutation(t, rosterPath, otherKey, vmGet())

	// Phase 1: the post dispatches and is waiting on the running task.
	exited := make(chan struct{})
	var postErr error
	go func() {
		defer close(exited)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, postErr = runAPICmd(ctx, http.MethodPost, nil, "--roster", rosterPath, f.mutPath, "qa-pve-01")
	}()
	t.Cleanup(func() {
		doRelease()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Errorf("the api post goroutine did not exit within 5s of its task being released")
		}
	})
	if !waitForCount(&f.polls, 1, lockTestDeadline) {
		t.Fatalf("the api post never polled its task within %s (mutations=%d)", lockTestDeadline, atomic.LoadInt32(&f.mutations))
	}

	// Phase 2: while the task runs, a typed read of the same VM is blocked
	// at its LOCK — not by some other failure.
	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
	err := vmGet().ExecuteContext(ctx)
	cancel()
	if err == nil {
		t.Fatal("vm get succeeded while the api post's task was still running — the lock did not span the wait")
	}
	if !strings.Contains(err.Error(), "acquire read lock") {
		t.Fatalf("vm get failed, but not at its lock: %v", err)
	}

	// Phase 3: the task ends, and the post returns success.
	doRelease()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("the api post did not return within 2s of its task stopping")
	}
	if postErr != nil {
		t.Fatalf("api post: %v (outcome-unknown=%v)", postErr, pve.IsTaskOutcomeUnknown(postErr))
	}

	// Phase 4: the lock was released with the task, so the same read now
	// succeeds.
	ctx, cancel = context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel()
	if err := vmGet().ExecuteContext(ctx); err != nil {
		t.Fatalf("vm get after the task ended: %v — the lock outlived the wait", err)
	}
}

// A10: on a path that names a node, that node is what the wait checks the
// UPID against, so a UPID for another node is refused before any poll.
func TestNewAPIPostCmd_UPIDForAnotherNodeThanThePathIsRefused(t *testing.T) {
	withFastTaskPolls(t)
	f := &apiTaskFake{mutPath: "/nodes/qa-pve-01/qemu/100/status/start", body: fmt.Sprintf("%q", apiTestUPID("pve9"))}
	rosterPath := newAPITaskServer(t, f)

	_, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01")
	if err == nil || !strings.Contains(err.Error(), `is for node "pve9", not "qa-pve-01"`) {
		t.Fatalf("expected the node-mismatch refusal, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("a node mismatch must be refused before polling, got %d polls", got)
	}
}

// A10b: a path addressing ANOTHER node than the roster target's own waits
// against the path's node. The nil error is the discriminator: taking the
// node from client.Node() (qa-pve-01) would trip the mismatch check.
func TestNewAPIPostCmd_CrossNodePathWaitsOnThePathsNode(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-02")
	f := &apiTaskFake{mutPath: "/nodes/qa-pve-02/qemu/100/status/start", body: fmt.Sprintf("%q", upid)}
	rosterPath := newAPITaskServer(t, f)

	if _, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	paths := f.pollPathsSnapshot()
	if len(paths) == 0 || !strings.Contains(paths[0], "/nodes/qa-pve-02/tasks/") {
		t.Errorf("expected the task to be polled on qa-pve-02, got %v", paths)
	}
}

// A11: --wait-timeout bounds the wait with a context deadline — an
// outcome-unknown error wrapping context.DeadlineExceeded, not the
// package's own ceiling timeout.
func TestNewAPIPostCmd_WaitTimeoutBoundsTheWait(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "running", "") },
	}
	rosterPath := newAPITaskServer(t, f)

	start := time.Now()
	_, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, "--wait-timeout", "50ms", f.mutPath, "qa-pve-01")
	elapsed := time.Since(start)
	if !pve.IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error, got: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected the --wait-timeout deadline in the chain, got: %v", err)
	}
	if pve.IsTaskTimeoutError(err) {
		t.Errorf("the wait ended at the package ceiling, not at --wait-timeout: %v", err)
	}
	if elapsed > time.Second {
		t.Errorf("the wait took %s; --wait-timeout 50ms was not applied", elapsed)
	}
}

// A12: bad wait flags are refused before the lock and before anything is
// sent, and the wait flags do not exist on `api get`. The last two rows are
// the positive controls on the same fixture: they prove "zero requests"
// above means refused, not a fixture that never routes anything.
func TestNewAPICmd_WaitFlagValidation(t *testing.T) {
	const path = "/nodes/qa-pve-01/qemu/100/status/start"
	rows := []struct {
		name         string
		method       string
		flags        []string
		holdLock     bool
		wantErr      string // "" means success
		wantRequests int32
	}{
		{"negative timeout", http.MethodPost, []string{"--wait-timeout", "-1s"}, false, "must not be negative", 0},
		{"above the ceiling", http.MethodPost, []string{"--wait-timeout", "11m"}, false, "exceeds the 10m0s ceiling", 0},
		{"no-wait with timeout", http.MethodPost, []string{"--no-wait", "--wait-timeout", "5s"}, false, "mutually exclusive", 0},
		{"no-wait with explicit zero timeout", http.MethodPost, []string{"--no-wait", "--wait-timeout", "0"}, false, "mutually exclusive", 0},
		{"get --no-wait", http.MethodGet, []string{"--no-wait"}, false, "unknown flag: --no-wait", 0},
		{"get --wait-timeout", http.MethodGet, []string{"--wait-timeout", "1s"}, false, "unknown flag: --wait-timeout", 0},
		{"refused before the lock", http.MethodPost, []string{"--wait-timeout", "-1s"}, true, "must not be negative", 0},
		{"control: --no-wait", http.MethodPost, []string{"--no-wait"}, false, "", 1},
		{"control: timeout at the ceiling", http.MethodPost, []string{"--wait-timeout", "10m"}, false, "", 2},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			withFastTaskPolls(t)
			f := &apiTaskFake{mutPath: path, body: fmt.Sprintf("%q", apiTestUPID("qa-pve-01"))}
			rosterPath := newAPITaskServer(t, f)

			if r.holdLock {
				key, ok := apiObjectKey("qa-pve-01", path)
				if !ok {
					t.Fatal("expected apiObjectKey to match")
				}
				unlock, err := lock.Mutation(context.Background(), rosterPath, key)
				if err != nil {
					t.Fatalf("acquire mutation: %v", err)
				}
				defer func() { _ = unlock() }()
			}

			ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
			defer cancel()
			args := append([]string{"--roster", rosterPath}, r.flags...)
			args = append(args, path, "qa-pve-01")
			start := time.Now()
			_, err := runAPICmd(ctx, r.method, nil, args...)
			elapsed := time.Since(start)

			if r.wantErr == "" {
				if err != nil {
					t.Fatalf("Execute: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), r.wantErr) {
				t.Fatalf("expected an error containing %q, got: %v", r.wantErr, err)
			}
			if got := atomic.LoadInt32(&f.all); got != r.wantRequests {
				t.Errorf("requests sent = %d, want %d", got, r.wantRequests)
			}
			if r.holdLock && elapsed >= lockTestDeadline/2 {
				t.Errorf("took %s: the flag was validated only after waiting on the lock", elapsed)
			}
		})
	}
}

// A13: a path with no /nodes/{node} segment — a matched storage path, or an
// unmatched one taken with --unsafe-no-lock — waits on the node the UPID
// itself names. The UPID's node differs from the roster target's, so
// falling back to client.Node() instead trips the mismatch check.
func TestNewAPIPostCmd_NodelessPathWaitsOnTheUPIDsNode(t *testing.T) {
	for _, r := range []struct {
		name, path, upid string
		flags            []string
	}{
		{"matched storage path", "/storage/local", apiTestUPID("qa-pve-02"), nil},
		// A real vzdump-of-everything task: its UPID's ID field is EMPTY,
		// which a "no :: anywhere" shortcut for the empty-node rule would
		// wrongly refuse after dispatch.
		{"unmatched path, empty id field", "/cluster/backup",
			"UPID:qa-pve-02:00001234:0000ABCD:5F000000:vzdump::root@pam:", []string{"--unsafe-no-lock"}},
	} {
		t.Run(r.name, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := r.upid
			f := &apiTaskFake{mutPath: r.path, body: fmt.Sprintf("%q", upid)}
			rosterPath := newAPITaskServer(t, f)

			args := append([]string{"--roster", rosterPath}, r.flags...)
			args = append(args, r.path, "qa-pve-01")
			out, err := runAPICmd(context.Background(), http.MethodPost, nil, args...)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if want := apiRenderedUPID("kv", upid); out != want {
				t.Errorf("stdout = %q, want %q", out, want)
			}
			if got := atomic.LoadInt32(&f.polls); got < 1 {
				t.Errorf("the task was never polled")
			}
		})
	}
}

// A13c: on a node-less path the node comes from the UPID, so a malformed
// UPID there is refused by the same shape rule, before any poll.
func TestNewAPIPostCmd_MalformedUPIDOnNodelessPathIsRefused(t *testing.T) {
	withFastTaskPolls(t)
	f := &apiTaskFake{mutPath: "/storage/local", body: `"UPID:n:1:2:3:4:5"`}
	rosterPath := newAPITaskServer(t, f)

	out, err := runAPICmd(context.Background(), http.MethodPost, nil,
		"--roster", rosterPath, f.mutPath, "qa-pve-01")
	if !pve.IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error, as on a path with a node (A6), got: %v", err)
	}
	if !strings.Contains(err.Error(), "malformed upid") {
		t.Errorf("expected a malformed-upid error, got: %v", err)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("a malformed UPID must be refused before polling, got %d polls", got)
	}
	if out != "" {
		t.Errorf("stdout must be empty, got %q", out)
	}
}

// B4: the wait honours the command's own context. Cancelling it mid-wait
// ends the wait as outcome-unknown with context.Canceled in the chain, and
// polling stops — the count is stable after a settle.
//
// Both branches of waitForAPITask's context handling are covered: without
// --wait-timeout the wait runs on the command's context directly, and with
// it the deadline must be derived FROM that context — a timeout built on
// context.Background() would drop the caller's cancel. 1s is far above the
// cancel point, so on that row only the command's own context can end the
// wait in time to report context.Canceled.
func TestNewAPIPostCmd_CancelledContextEndsTheWait(t *testing.T) {
	for _, r := range []struct {
		name  string
		flags []string
	}{
		{"no wait timeout", nil},
		{"with wait timeout", []string{"--wait-timeout", "1s"}},
	} {
		t.Run(r.name, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &apiTaskFake{
				mutPath:     "/nodes/qa-pve-01/qemu/100/status/start",
				body:        fmt.Sprintf("%q", upid),
				status:      func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "running", "") },
				onFirstPoll: cancel,
			}
			rosterPath := newAPITaskServer(t, f)

			args := append([]string{"--roster", rosterPath}, r.flags...)
			args = append(args, f.mutPath, "qa-pve-01")
			out, err := runAPICmd(ctx, http.MethodPost, nil, args...)
			if !pve.IsTaskOutcomeUnknown(err) {
				t.Fatalf("expected an outcome-unknown error, got: %v", err)
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("expected context.Canceled in the chain, got: %v", err)
			}
			if out != "" {
				t.Errorf("stdout must be empty, got %q", out)
			}
			settled := atomic.LoadInt32(&f.polls)
			if settled < 1 {
				t.Fatalf("the task was never polled, so the cancel never happened mid-wait")
			}
			time.Sleep(100 * time.Millisecond) // 20 poll intervals at the seam's 5ms
			if got := atomic.LoadInt32(&f.polls); got != settled {
				t.Errorf("polls went from %d to %d after the command returned — the wait did not stop", settled, got)
			}
		})
	}
}
