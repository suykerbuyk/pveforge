package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// uaFront is the REST write logger and fault injector of the U-A (exit 3/4)
// fixtures of family S1 (vm). It is a TLS server the roster points at, in
// front of ANY existing fake (the vm create fake, the snapshot fake, the
// vm set config fake, pvefake), so those fakes need no change and every
// fixture reads the SAME independent log of what left the process:
//
//   - writes: every non-GET/HEAD request, "METHOD path", logged BEFORE the
//     fake (or an override) sees it. A request that is answered by an
//     override, or whose connection is dropped, is still a write that left
//     the process, which is exactly what exit 4 must never follow;
//   - polls: every GET of a task status, counted before it is answered;
//   - faults: connections it dropped on purpose (instrument #7: a fault test
//     asserts that the fault ARRIVED).
//
// override, when set, may answer or drop a request instead of the fake. It
// runs after the request is logged, never instead of logging.
type uaFront struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	writes []string
	// override answers (set) or drops a request; see uaReply.
	override func(r *http.Request) uaReply
	polls    atomic.Int32
	faults   atomic.Int32
}

// uaReply is an override's verdict on one request.
type uaReply struct {
	set  bool   // answer with code and body instead of the fake
	code int    // HTTP status
	body string // the whole response body (a JSON envelope for a 200)
	drop bool   // close the connection without any response
}

// uaAnswer answers with a 200 and data as the "data" payload.
func uaAnswer(data string) uaReply {
	return uaReply{set: true, code: 200, body: `{"data":` + data + `}`}
}

// uaStatus answers with an HTTP status and a null payload.
func uaStatus(code int) uaReply { return uaReply{set: true, code: code, body: `{"data":null}`} }

// uaDrop drops the connection.
func uaDrop() uaReply { return uaReply{drop: true} }

// newUAFront starts a TLS front for the fake at backendURL (an http or https
// URL). The caller registers the backend's own cleanup.
func newUAFront(t *testing.T, backendURL string) *uaFront {
	t.Helper()
	u, err := url.Parse(backendURL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true} //nolint:gosec // loopback test fake
	f := &uaFront{t: t}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			f.mu.Lock()
			f.writes = append(f.writes, r.Method+" "+r.URL.Path)
			f.mu.Unlock()
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status") {
			f.polls.Add(1)
		}
		if f.override != nil {
			if rep := f.override(r); rep.drop {
				f.faults.Add(1)
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
				return
			} else if rep.set {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(rep.code)
				_, _ = w.Write([]byte(rep.body))
				return
			}
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// writeLog is the REST write log, for writeEnv.restWrites.
func (f *uaFront) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

// isTaskPoll reports whether r is a task-status GET, and its UPID.
func isTaskPoll(r *http.Request) (upid string, ok bool) {
	if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/tasks/") || !strings.HasSuffix(r.URL.Path, "/status") {
		return "", false
	}
	p := r.URL.Path
	return strings.TrimSuffix(p[strings.Index(p, "/tasks/")+len("/tasks/"):], "/status"), true
}
