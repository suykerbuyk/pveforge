package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// s5APIFake is a fake PVE with a REQUEST LOG of every non-GET request (the REST
// write log of the three-log contract), the task poll count, and the number of
// accepted connections (a transport-fault fixture asserts connections AND
// requests: instrument 7).
type s5APIFake struct {
	mu      sync.Mutex
	writes  []string // "METHOD path" of every non-GET request
	polls   int32
	body    string // the mutation's "data" payload
	rawBody string // if set, the whole response body (not JSON-wrapped)
	drop    bool   // read the request, then close the connection without answering
	status  func(n int32) (int, string)
}

func (f *s5APIFake) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func newS5APIServer(t *testing.T, f *s5APIFake) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status") {
			n := atomic.AddInt32(&f.polls, 1)
			code, data := http.StatusOK, ""
			if f.status != nil {
				code, data = f.status(n)
			}
			w.WriteHeader(code)
			_, _ = fmt.Fprintf(w, `{"data":%s}`, data)
			return
		}
		if r.Method != http.MethodGet {
			f.mu.Lock()
			f.writes = append(f.writes, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api2/json"))
			f.mu.Unlock()
		}
		if f.drop {
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			c, _, err := hj.Hijack()
			if err == nil {
				_ = c.Close()
			}
			return
		}
		if f.rawBody != "" {
			_, _ = w.Write([]byte(f.rawBody))
			return
		}
		_, _ = fmt.Fprintf(w, `{"data":%s}`, f.body)
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	t.Cleanup(srv.Close)
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return rp
}

func (f *s5APIFake) env(rp string) writeEnv {
	return writeEnv{roster: rp, restWrites: f.writeLog, sshWrites: noLog}
}

// The api verbs: every refusal boundary has the three logs and a post-write
// twin; every wait boundary asserts the dispatch (REST write) log AND the poll
// count.
func TestS5API_RefusalsAreFourOnlyBeforeTheRequest(t *testing.T) {
	withFastTaskPolls(t)
	t.Run("/access write refusal: 4, no request left the process", func(t *testing.T) {
		f := &s5APIFake{body: "null"}
		rp := newS5APIServer(t, f)
		o := f.env(rp).observe(t, "api", "post", "/access/users", "qa-pve-01", "--roster", rp, "--unsafe-no-lock", "--data", "userid=x@pve")
		o.wantRefusedBeforeAnyWrite(t)
		if !strings.Contains(o.stderr, "/access") {
			t.Fatalf("not the /access refusal: %q", o.stderr)
		}
	})
	t.Run("unmatched path without --unsafe-no-lock: 4", func(t *testing.T) {
		f := &s5APIFake{body: "null"}
		rp := newS5APIServer(t, f)
		o := f.env(rp).observe(t, "api", "post", "/version/x", "qa-pve-01", "--roster", rp)
		o.wantRefusedBeforeAnyWrite(t)
		if !strings.Contains(o.stderr, "--unsafe-no-lock") {
			t.Fatalf("not the unmatched-path refusal: %q", o.stderr)
		}
	})
	t.Run("lock-wait timeout on a matched path: 4 (the lock files are bookkeeping)", func(t *testing.T) {
		f := &s5APIFake{body: "null"}
		rp := newS5APIServer(t, f)
		holdLock(t, rp, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})
		o := f.env(rp).observe(t, "api", "put", "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01", "--roster", rp, "--lock-wait", "150ms")
		o.wantRefusedBeforeAnyWrite(t)
	})
	t.Run("twin: the same verb after the request left (response lost): 1, never 4", func(t *testing.T) {
		f := &s5APIFake{drop: true}
		rp := newS5APIServer(t, f)
		o := f.env(rp).observe(t, "api", "post", "/nodes/qa-pve-01/qemu/100/status/start", "qa-pve-01", "--roster", rp)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1 (a lost response is not proof that nothing changed, and not a refusal); stderr %q", o.code, o.stderr)
		}
		// instrument 7: the fault must really have arrived once, not been retried away
		if len(o.rest) != 1 {
			t.Fatalf("rest writes %q: the dropped request must be seen exactly once", o.rest)
		}
	})
}

func TestS5API_WaitBoundaries(t *testing.T) {
	withFastTaskPolls(t)
	const path = "/nodes/qa-pve-01/qemu/100/status/start"
	upid := apiTestUPID("qa-pve-01")
	for _, tc := range []struct {
		name      string
		f         *s5APIFake
		args      []string
		wantCode  int
		wantPolls int32
	}{
		{"UPID then 503 polls: 3", &s5APIFake{body: fmt.Sprintf("%q", upid), status: func(int32) (int, string) { return 503, "null" }}, nil, 3, 4},
		{"bad-shape UPID after a real dispatch: 3, no poll", &s5APIFake{body: `"UPID:n:1:2:3:4:5"`}, nil, 3, 0},
		{"UPID of another node: 3, no poll", &s5APIFake{body: fmt.Sprintf("%q", apiTestUPID("pve9"))}, nil, 3, 0},
		{"task seen to fail: 1", &s5APIFake{body: fmt.Sprintf("%q", upid), status: func(int32) (int, string) { return 200, taskPayload(upid, "stopped", "ERROR: x") }}, nil, 1, 1},
		{"task OK: 0", &s5APIFake{body: fmt.Sprintf("%q", upid), status: func(int32) (int, string) { return 200, taskPayload(upid, "stopped", "OK") }}, nil, 0, 1},
		{"task WARNINGS: 0", &s5APIFake{body: fmt.Sprintf("%q", upid), status: func(int32) (int, string) { return 200, taskPayload(upid, "stopped", "WARNINGS: 1") }}, nil, 0, 1},
		{"--no-wait with a UPID: 0 (named state unobserved_dispatch)", &s5APIFake{body: fmt.Sprintf("%q", upid)}, []string{"--no-wait"}, 0, 0},
		{"no-UPID body (null) is not a wait: 0 (a null PUT/DELETE answer is a normal success)", &s5APIFake{body: "null"}, nil, 0, 0},
		{"a response that does not decode: 1", &s5APIFake{rawBody: "not json"}, nil, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp := newS5APIServer(t, tc.f)
			o := tc.f.env(rp).observe(t, append([]string{"api", "post", path, "qa-pve-01", "--roster", rp}, tc.args...)...)
			o.wantNotRefusedAfterWrite(t)
			if o.code != tc.wantCode {
				t.Fatalf("exit %d, want %d; stderr %q", o.code, tc.wantCode, o.stderr)
			}
			if len(o.rest) != 1 || o.rest[0] != "POST "+path {
				t.Fatalf("rest writes %q, want exactly the one dispatch", o.rest)
			}
			if got := atomic.LoadInt32(&tc.f.polls); got != tc.wantPolls {
				t.Fatalf("polls = %d, want %d", got, tc.wantPolls)
			}
		})
	}
}
