package main

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// Helpers of the network+storage exit 3/4 fixtures (contract plan §3.5,
// AC-W2/W3). They only ADD to writelogs_test.go: the three write logs and the
// gate-agreement assertion come from writeEnv.observe.

// s2Rest is a recording fake PVE for the storage verbs. Every request is
// logged ("METHOD path" plus the decoded form for a write); route decides the
// reply. Unlike routeFake it can answer a status code, so a task poll can
// fail (the fault the exit-3 fixtures inject) and an unexpected request is a
// recorded 404, never a silent success.
type s2Rest struct {
	mu    sync.Mutex
	all   []string
	polls atomic.Int32
	route func(method, path string, form url.Values) (code int, body string)
}

func newS2Rest(t *testing.T, route func(method, path string, form url.Values) (int, string)) (*httptest.Server, *s2Rest) {
	t.Helper()
	f := &s2Rest{route: route}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit := r.Method + " " + r.URL.Path
		var form url.Values
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if err := r.ParseForm(); err != nil {
				t.Errorf("s2Rest: %s: parse form: %v", hit, err)
			}
			form = r.PostForm
			hit += " " + form.Encode()
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status") {
			f.polls.Add(1)
		}
		f.mu.Lock()
		f.all = append(f.all, hit)
		f.mu.Unlock()
		code, body := route(r.Method, r.URL.Path, form)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

// writes is every non-GET request received (the REST write log).
func (f *s2Rest) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, h := range f.all {
		if !strings.HasPrefix(h, "GET ") {
			out = append(out, h)
		}
	}
	return out
}

// count is the number of logged requests starting with prefix.
func (f *s2Rest) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, h := range f.all {
		if strings.HasPrefix(h, prefix) {
			n++
		}
	}
	return n
}

// pollFailProxy fronts inner (a pvefake server) and answers every task STATUS
// poll itself with HTTP 500, counting them: the commit was dispatched (inner
// logged the PUT) and its outcome can never be observed. Everything else is
// forwarded untouched, so inner's own write log stays the REST write log.
func pollFailProxy(t *testing.T, inner *httptest.Server) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	target, err := url.Parse(inner.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = inner.Client().Transport
	var polls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status") {
			polls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &polls
}

// fastTaskTimings makes a failing wait end in milliseconds.
func fastTaskTimings(t *testing.T) {
	t.Helper()
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 500*time.Millisecond))
}

// sshWritesNotIn is a root-SSH write log: every command the fake received
// that isReadCmd does not recognise as a read. A fixture states its reads
// explicitly, so an unexpected command is counted as a write, never ignored.
func sshWritesNotIn(fs *pvefake.SSHServer, isReadCmd func(string) bool) func() []string {
	return func() []string {
		var out []string
		for _, c := range fs.Commands() {
			if !isReadCmd(c) {
				out = append(out, c)
			}
		}
		return out
	}
}

// s2NetSSHRead: the only root-SSH commands the network verbs send are the
// kernel link reads.
func s2NetSSHRead(c string) bool {
	return strings.HasPrefix(c, "ip -j link show") || strings.Contains(c, "link show")
}

// s2StorageSSHRead: the reads free-orphans makes as root.
func s2StorageSSHRead(c string) bool {
	return strings.HasPrefix(c, "readlink /etc/pve/local") ||
		strings.Contains(c, "/cluster/status") || strings.Contains(c, "/cluster/resources") || strings.Contains(c, "/qemu")
}

const s2UPIDStorage = "UPID:qa-pve-07:00001234:00ABCDEF:5F000000:imgdel:storage:root@pam:"
