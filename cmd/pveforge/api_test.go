package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
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
	// Empty response body renders as null -> nothing under KV format.
	if out.String() != "" {
		t.Errorf("expected no KV output for a null response, got:\n%s", out.String())
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

	// Same key vm.go's own lock.Read call would use for vmid 100.
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	vmGet := newVMGetCmd()
	vmGet.SetOut(&bytes.Buffer{})
	vmGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "100"})
	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel1()
	if err := vmGet.ExecuteContext(ctx1); err == nil {
		t.Fatal("expected the typed `vm get` to be blocked by the api-shaped mutation lock")
	}

	apiGet := newAPIVerbCmd(http.MethodGet, "get")
	apiGet.SetOut(&bytes.Buffer{})
	apiGet.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if err := apiGet.ExecuteContext(ctx2); err == nil {
		t.Fatal("expected `api get` on the same vm path to be blocked by the same lock key")
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
	if err := apiGet2.Execute(); err != nil {
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

	// The normalized key BOTH commands below must resolve to, despite
	// neither of their own inputs being spelled "100" verbatim.
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockMutation, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("acquire mutation: %v", err)
	}

	vmGet := newVMGetCmd()
	vmGet.SetOut(&bytes.Buffer{})
	vmGet.SetArgs([]string{"--roster", rosterPath, "qa-pve-01", "0100"})
	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel1()
	if err := vmGet.ExecuteContext(ctx1); err == nil {
		t.Fatal("expected `vm get ... 0100` to be blocked by the ID:\"100\" mutation lock")
	}

	apiGet := newAPIVerbCmd(http.MethodGet, "get")
	apiGet.SetOut(&bytes.Buffer{})
	apiGet.SetArgs([]string{"--roster", rosterPath, "/nodes/qa-pve-01/qemu/0100/config", "qa-pve-01"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	if err := apiGet.ExecuteContext(ctx2); err == nil {
		t.Fatal("expected `api get .../qemu/0100/config` to be blocked by the ID:\"100\" mutation lock")
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
	if err := apiGet2.Execute(); err != nil {
		t.Fatalf("Execute after mutation released: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("expected exactly one successful read after the mutation released, got %d hits", got)
	}
}

// TestNewAPICmd_APIMutationBlocksTypedRead proves the direction that
// actually matters most for the feature's safety claim: an `api post`
// mutation held via lock.Mutation must block the EXISTING typed `vm get`
// command, not just another `api` invocation.
func TestNewAPICmd_APIMutationBlocksTypedRead(t *testing.T) {
	rosterPath := newTestRosterWithTLSTarget(t, httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100}}`))
	})), "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

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
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := vmGet.ExecuteContext(ctx); err == nil {
		t.Fatal("expected the typed `vm get` to be blocked by the api-derived mutation lock")
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
