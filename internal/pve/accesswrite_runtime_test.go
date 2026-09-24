package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// The runtime half of "the roster's token never writes /access" (6a, SR3):
// accessWriteGuard sits in the one http.Client every pve.Client request
// uses, so however a request's path or call is spelled, it is refused
// before it leaves the process. Each test drives a real Client against an
// httptest server that counts what reaches it.

// accessWriteServer counts every request that reaches it, and answers each
// with an empty success.
func accessWriteServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	})
	return srv, &hits
}

// requireAccessWriteRefused: err is the guard's typed refusal, naming
// method, and nothing reached the server.
func requireAccessWriteRefused(t *testing.T, err error, method string, hits *atomic.Int64) {
	t.Helper()
	if !errors.Is(err, ErrAccessWriteRefused) {
		t.Fatalf("err = %v, want ErrAccessWriteRefused", err)
	}
	var awe *AccessWriteError
	if !errors.As(err, &awe) || awe.Method != method {
		t.Fatalf("err = %v, want an *AccessWriteError for %s", err, method)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the server saw %d request(s); the refusal must happen before the request leaves the process", n)
	}
}

// TestAccessWriteGuard_StaticGuardBypasses: the five spellings that got
// past the static REST guard (SR3) are each refused at runtime, for every
// write method, with zero requests reaching the server.
func TestAccessWriteGuard_StaticGuardBypasses(t *testing.T) {
	ctx := context.Background()
	shapes := []struct {
		name string
		call func(c *Client, method string) error
	}{
		{"concatenation", func(c *Client, m string) error {
			_, err := c.RawRequest(ctx, m, "/"+"access/users", url.Values{"userid": {"x@pve"}})
			return err
		}},
		{"sprintf", func(c *Client, m string) error {
			_, err := c.RawRequest(ctx, m, fmt.Sprintf("/%s/users", "access"), url.Values{"userid": {"x@pve"}})
			return err
		}},
		{"dot-segment", func(c *Client, m string) error {
			_, err := c.RawRequest(ctx, m, "/nodes/../access/users", url.Values{"userid": {"x@pve"}})
			return err
		}},
		{"double-slash", func(c *Client, m string) error {
			_, err := c.RawRequest(ctx, m, "//access/users", url.Values{"userid": {"x@pve"}})
			return err
		}},
		{"method-value", func(c *Client, m string) error {
			rr := c.RawRequest
			_, err := rr(ctx, m, "/access/acl", url.Values{"path": {"/"}, "roles": {"Administrator"}})
			return err
		}},
	}
	for _, s := range shapes {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			t.Run(s.name+"/"+m, func(t *testing.T) {
				srv, hits := accessWriteServer(t)
				requireAccessWriteRefused(t, s.call(testClient(t, srv), m), m, hits)
			})
		}
	}
}

// TestAccessWriteGuard_EveryStack: the guard is in the transport that
// go-proxmox's own requests use (NewClient hands it our client) and that
// the direct NewRequest writers (vmconfig.go's shape) use, not only
// RawRequest's.
func TestAccessWriteGuard_EveryStack(t *testing.T) {
	ctx := context.Background()
	t.Run("go-proxmox Post", func(t *testing.T) {
		srv, hits := accessWriteServer(t)
		err := testClient(t, srv).pc.Post(ctx, "/access/users", map[string]string{"userid": "x@pve"}, nil)
		requireAccessWriteRefused(t, err, http.MethodPost, hits)
	})
	t.Run("go-proxmox Put", func(t *testing.T) {
		srv, hits := accessWriteServer(t)
		err := testClient(t, srv).pc.Put(ctx, "/access/acl", map[string]string{"path": "/"}, nil)
		requireAccessWriteRefused(t, err, http.MethodPut, hits)
	})
	t.Run("go-proxmox Delete", func(t *testing.T) {
		srv, hits := accessWriteServer(t)
		err := testClient(t, srv).pc.Delete(ctx, "/access/users/x@pve", nil)
		requireAccessWriteRefused(t, err, http.MethodDelete, hits)
	})
	t.Run("direct NewRequest", func(t *testing.T) {
		srv, hits := accessWriteServer(t)
		c := testClient(t, srv)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/access/acl", strings.NewReader("path=/"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.httpClient.Do(req)
		if res != nil {
			_ = res.Body.Close()
		}
		requireAccessWriteRefused(t, err, http.MethodPut, hits)
	})
	t.Run("InsecureTLS", func(t *testing.T) {
		var hits atomic.Int64
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte(`{"data":null}`))
		}))
		t.Cleanup(srv.Close)
		c, err := NewClient(ClientConfig{BaseURLOverride: srv.URL + "/api2/json", InsecureTLS: true, TokenID: "root@pam!pveforge", TokenSecret: "s"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.RawRequest(ctx, http.MethodPost, "/access/users", nil)
		requireAccessWriteRefused(t, err, http.MethodPost, &hits)
		// ...and the insecure transport is the one behind the guard: a
		// read reaches the self-signed server.
		if _, err := c.RawRequest(ctx, http.MethodGet, "/access/users", nil); err != nil || hits.Load() != 1 {
			t.Fatalf("GET over InsecureTLS: err = %v, hits = %d; want nil, 1", err, hits.Load())
		}
	})
}

// TestAccessWriteGuard_Paths: the decision on the path alone, as the
// transport sees it, under both base URLs pveforge uses (the real
// /api2/json one and a test server's bare root).
func TestAccessWriteGuard_Paths(t *testing.T) {
	refused := []string{
		"/access", "/access/", "/access/users", "/access/acl", "/access/users/x@pve/token/t",
		"/api2/json/access/acl", "/api2/extjs/access/users", "/base/api2/json/access/password",
		"/api2/json/nodes/../access/acl", "/api2/json//access/acl", "/api2/json/./access/acl",
		"/api2/json/access%2Facl", "/api2/json/%61ccess/acl", "/api2/json/nodes/..%2F..%2Fjson%2Faccess/acl",
		"/api2/json/nodes/%252e%252e/access/acl", "/API2/JSON/ACCESS/acl",
	}
	allowed := []string{
		"/", "/nodes/pve1/qemu/100/config", "/accessory", "/api2/json/accessory", "/api2/json/nodes/access",
		"/api2/json/pools/access/x", "/api2/json/cluster/acme/access",
	}
	check := func(p string) bool {
		req := httptest.NewRequest(http.MethodPost, "http://pve.invalid"+p, nil)
		return isAccessWrite(req)
	}
	for _, p := range refused {
		if !check(p) {
			t.Errorf("POST %s: not refused", p)
		}
	}
	for _, p := range allowed {
		if check(p) {
			t.Errorf("POST %s: refused, but it does not address /access", p)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if isAccessWrite(httptest.NewRequest(m, "http://pve.invalid/api2/json/access/users", nil)) {
			t.Errorf("%s /access/users refused; reads are the token's to make", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, "OPTIONS", "PROPFIND"} {
		if !isAccessWrite(httptest.NewRequest(m, "http://pve.invalid/api2/json/access/users", nil)) {
			t.Errorf("%s /access/users not refused; every method but GET and HEAD is", m)
		}
	}
}

// TestAccessWriteGuard_ReadsAndOtherWritesPass: the guard refuses nothing
// else. A GET of /access, and writes elsewhere, reach the server.
func TestAccessWriteGuard_ReadsAndOtherWritesPass(t *testing.T) {
	ctx := context.Background()
	srv, hits := accessWriteServer(t)
	c := testClient(t, srv)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/access/users"},
		{http.MethodPost, "/nodes/pve1/qemu/100/snapshot"},
		{http.MethodPut, "/nodes/pve1/network/vmbr1"},
		{http.MethodDelete, "/nodes/pve1/qemu/100/snapshot/s1"},
		{http.MethodPost, "/accessory"},
	} {
		if _, err := c.RawRequest(ctx, r.method, r.path, nil); err != nil {
			t.Errorf("%s %s: %v", r.method, r.path, err)
		}
	}
	if n := hits.Load(); n != 5 {
		t.Errorf("the server saw %d requests, want 5", n)
	}
}

// TestAccessWriteGuard_Redirect: a write elsewhere that the server
// redirects, method intact, to /access is refused at the hop: the
// redirected request passes through the same transport.
func TestAccessWriteGuard_Redirect(t *testing.T) {
	var hits, accessHits atomic.Int64
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasPrefix(r.URL.Path, "/access") {
			accessHits.Add(1)
		}
		http.Redirect(w, r, "/access/users", http.StatusTemporaryRedirect)
	})
	_, err := testClient(t, srv).RawRequest(context.Background(), http.MethodPost, "/nodes/pve1/qemu", url.Values{"a": {"b"}})
	if !errors.Is(err, ErrAccessWriteRefused) {
		t.Fatalf("err = %v, want ErrAccessWriteRefused", err)
	}
	if hits.Load() != 1 || accessHits.Load() != 0 {
		t.Fatalf("hits = %d, /access hits = %d; want 1, 0", hits.Load(), accessHits.Load())
	}
}

// TestNewClient_InstallsAccessWriteGuard: both transports NewClient can
// build are the guard, and go-proxmox's pc shares the very same client.
func TestNewClient_InstallsAccessWriteGuard(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		c, err := NewClient(ClientConfig{Host: "pve.invalid", InsecureTLS: insecure, TokenID: "root@pam!pveforge", TokenSecret: "s"})
		if err != nil {
			t.Fatal(err)
		}
		g, ok := c.httpClient.Transport.(accessWriteGuard)
		if !ok {
			t.Fatalf("InsecureTLS=%t: transport is %T, want accessWriteGuard", insecure, c.httpClient.Transport)
		}
		if insecure != (g.next != nil) {
			t.Errorf("InsecureTLS=%t: next = %T; want nil (DefaultTransport per request) exactly when not insecure", insecure, g.next)
		}
		if c.httpClient.Timeout != DefaultTimeout {
			t.Errorf("InsecureTLS=%t: timeout = %v, want %v", insecure, c.httpClient.Timeout, DefaultTimeout)
		}
	}
}
