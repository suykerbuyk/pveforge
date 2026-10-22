//go:build harness

package pve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// qemuHandler serves GET /nodes/<node>/qemu, choosing the data payload from the
// node name so one server covers every shape. It requires an Authorization
// header and answers 401 without one, so a test can prove the header is
// load-bearing.
func qemuHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		var body string
		switch {
		case strings.HasSuffix(r.URL.Path, "/nodes/nullnode/qemu"):
			body = `{"data":null}`
		case strings.HasSuffix(r.URL.Path, "/nodes/busy/qemu"):
			body = `{"data":[{"vmid":100,"name":"leftover","status":"running"}]}`
		default: // every "empty-*" node
			body = `{"data":[]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// newTestClient builds a Client the production way (NewClient) against an
// http/2 httptest TLS server on loopback, pinned to that server's own
// certificate — the real pinned-transport path, reachable because
// internal/netguard permits loopback. Constructed inside the test, after
// TestMain's netguard.Install, so the pinned transport clones the guarded
// DefaultTransport.
func newTestClient(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewUnstartedServer(qemuHandler(t))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)

	pin := tlspin.FromCertificate(ts.Certificate())
	c, err := NewClient(ClientConfig{
		BaseURLOverride: ts.URL,
		InsecureTLS:     true,
		TLSPin:          pin,
		TokenID:         "root@pam!batcha",
		TokenSecret:     "s3cr3t",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, ts
}

// (a)+(b): the null-vs-empty discriminator against the real decode path.
func TestCaptureVMListShape_NullVsEmpty(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	shape, n, err := c.CaptureVMListShape(ctx, "nullnode")
	if err != nil {
		t.Fatalf("nullnode: %v", err)
	}
	if shape != ShapeNull || n != 0 {
		t.Fatalf("nullnode: got (%q,%d), want (null,0)", shape, n)
	}

	shape, n, err = c.CaptureVMListShape(ctx, "empty-a")
	if err != nil {
		t.Fatalf("empty-a: %v", err)
	}
	if shape != ShapeEmpty || n != 0 {
		t.Fatalf("empty-a: got (%q,%d), want ([],0)", shape, n)
	}

	shape, n, err = c.CaptureVMListShape(ctx, "busy")
	if err != nil {
		t.Fatalf("busy: %v", err)
	}
	if shape != ShapeItems || n != 1 {
		t.Fatalf("busy: got (%q,%d), want (items,1)", shape, n)
	}
}

// (c): CaptureRawGET records the negotiated protocol and the raw body + sha256.
func TestCaptureRawGET_ProtoAndBytes(t *testing.T) {
	c, _ := newTestClient(t)
	rc, err := c.CaptureRawGET(context.Background(), "/nodes/empty-a/qemu")
	if err != nil {
		t.Fatalf("CaptureRawGET: %v", err)
	}
	if rc.Proto != "HTTP/2.0" {
		t.Fatalf("Proto = %q, want HTTP/2.0 (server has EnableHTTP2)", rc.Proto)
	}
	if string(rc.Body) != `{"data":[]}` {
		t.Fatalf("Body = %q, want the raw pre-unwrap envelope", rc.Body)
	}
	// The evidence hash is over exactly the raw body bytes, not a re-encoding.
	const wantSHA = "8fe32e407a1038ee38753b70e5374b3a46d6ae9d5f16cd5b73c53abaca8f5ed0"
	if rc.SHA256 != wantSHA {
		t.Fatalf("SHA256 = %q, want %q (sha256 of the raw body)", rc.SHA256, wantSHA)
	}
}

// (d): the Authorization header is load-bearing — CaptureRawGET (which sets it)
// gets 200; a control request through the same pinned client WITHOUT it gets 401.
func TestCaptureRawGET_AuthHeaderRequired(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	rc, err := c.CaptureRawGET(ctx, "/nodes/empty-a/qemu")
	if err != nil {
		t.Fatalf("CaptureRawGET: %v", err)
	}
	if rc.Status != "200 OK" {
		t.Fatalf("with auth: Status = %q, want 200 OK", rc.Status)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/nodes/empty-a/qemu", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.httpClient.Do(req) // deliberately no Authorization set
	if err != nil {
		t.Fatalf("control request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without auth: status = %d, want 401 (proves the header is what CaptureRawGET must set)", resp.StatusCode)
	}
}

// (e): the item-66 golden gate — both nodes empty passes; a non-empty node refuses.
func TestGoldenGateEmpty(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	shapes, err := c.GoldenGateEmpty(ctx, []string{"empty-a", "empty-b"})
	if err != nil {
		t.Fatalf("both empty: unexpected refusal: %v", err)
	}
	if shapes["empty-a"] != ShapeEmpty || shapes["empty-b"] != ShapeEmpty {
		t.Fatalf("both empty: shapes = %v, want both []", shapes)
	}

	_, err = c.GoldenGateEmpty(ctx, []string{"empty-a", "busy"})
	if !errors.Is(err, ErrNotAtGolden) {
		t.Fatalf("non-empty node: err = %v, want ErrNotAtGolden (NOT a vacuous pass)", err)
	}

	// An empty node set must REFUSE, not vacuously pass: checking no nodes is
	// not evidence the cluster is at golden.
	if _, err := c.GoldenGateEmpty(ctx, nil); !errors.Is(err, ErrNotAtGolden) {
		t.Fatalf("nil nodes: err = %v, want ErrNotAtGolden", err)
	}
	if _, err := c.GoldenGateEmpty(ctx, []string{}); !errors.Is(err, ErrNotAtGolden) {
		t.Fatalf("empty nodes: err = %v, want ErrNotAtGolden", err)
	}
}
