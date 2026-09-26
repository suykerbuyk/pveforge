package pve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// pinCert is a self-signed certificate on a FRESH key: every httptest
// server shares Go's one testcert key, so tests that tell peers apart by
// pin must not use it.
func pinCert(t *testing.T) (tls.Certificate, tlspin.Pin) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pve.example.test"},
		DNSNames:     []string{"pve.example.test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, tlspin.FromCertificate(cert)
}

// pinnedServer is a TLS server on its own key. It counts the connections
// it accepts and the requests that reach its handler, and records whether
// any request carried an Authorization header.
type pinnedServer struct {
	*httptest.Server
	pin          tlspin.Pin
	conns, hits  atomic.Int32
	sawAuthorize atomic.Bool
}

func newPinnedServer(t *testing.T, h http.HandlerFunc) *pinnedServer {
	t.Helper()
	kp, pin := pinCert(t)
	ps := &pinnedServer{pin: pin}
	ps.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			ps.sawAuthorize.Store(true)
		}
		h(w, r)
	}))
	ps.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			ps.conns.Add(1)
		}
	}
	ps.Config.ErrorLog = nil
	ps.TLS = &tls.Config{Certificates: []tls.Certificate{kp}}
	ps.StartTLS()
	t.Cleanup(ps.Close)
	return ps
}

func jsonOK(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func pinnedClient(t *testing.T, srv *pinnedServer, insecure bool, pin tlspin.Pin) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURLOverride: srv.URL + "/api2/json",
		InsecureTLS:     insecure,
		TLSPin:          pin,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func isPinMismatch(err error) bool {
	return err != nil && (errors.Is(err, tlspin.ErrPinMismatch) || strings.Contains(err.Error(), tlspin.ErrPinMismatch.Error()))
}

func TestPinnedClient_RightPinConnects(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{"data":[{"node":"n1","status":"online"}]}`))
	c := pinnedClient(t, srv, true, srv.pin)
	nodes, err := c.GetNodes(context.Background())
	if err != nil {
		t.Fatalf("GetNodes with the right pin: %v", err)
	}
	if len(nodes) != 1 || srv.hits.Load() != 1 || !srv.sawAuthorize.Load() {
		t.Fatalf("nodes %d, hits %d, token sent %v; want 1, 1, true", len(nodes), srv.hits.Load(), srv.sawAuthorize.Load())
	}
}

// Every REST path of the one shared client refuses a peer with another
// key, before any request (and so before the token) reaches it.
func TestPinnedClient_EveryPathRefusesAnotherKey(t *testing.T) {
	ctx := context.Background()
	paths := map[string]func(c *Client) error{
		"go-proxmox (GetNodes)": func(c *Client) error { _, err := c.GetNodes(ctx); return err },
		"RawRequest":            func(c *Client) error { _, err := c.RawRequest(ctx, http.MethodGet, "/version", nil); return err },
		"the form writer":       func(c *Client) error { return c.SetVMConfigField(ctx, "n1", 100, "name", "x") },
		"APIDocTree":            func(c *Client) error { _, err := c.APIDocTree(ctx); return err },
		"WaitForTask's poll": func(c *Client) error {
			wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return c.WaitForTask(wctx, "n1", "UPID:n1:00000001:00000001:00000001:qmstart:100:root@pam:")
		},
	}
	for name, call := range paths {
		for _, insecure := range []bool{true, false} {
			srv := newPinnedServer(t, jsonOK(`{"data":null}`))
			_, other := pinCert(t)
			err := call(pinnedClient(t, srv, insecure, other))
			if err == nil {
				t.Errorf("%s (insecure_tls %v): a peer with another key was accepted", name, insecure)
			}
			// With insecure_tls false the chain check refuses this self-signed
			// peer first; with it true the pin is the check. WaitForTask keeps
			// polling through transport errors until its deadline, so its own
			// error is the deadline: for it, the evidence is that handshakes
			// were attempted and no request arrived.
			if insecure && name != "WaitForTask's poll" && !isPinMismatch(err) {
				t.Errorf("%s: err = %v, want a TLS pin mismatch", name, err)
			}
			if srv.conns.Load() == 0 {
				t.Errorf("%s (insecure_tls %v): no connection was attempted, so nothing was tested", name, insecure)
			}
			if h := srv.hits.Load(); h != 0 || srv.sawAuthorize.Load() {
				t.Errorf("%s (insecure_tls %v): %d request(s) reached the server (token sent %v)", name, insecure, h, srv.sawAuthorize.Load())
			}
		}
	}
}

// With insecure_tls false, a pin does not replace chain verification: the
// right pin on a certificate no CA vouches for is still refused (D4a: the
// chain AND the pin).
func TestPinnedClient_CAModeStillVerifiesTheChain(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{"data":[]}`))
	_, err := pinnedClient(t, srv, false, srv.pin).GetNodes(context.Background())
	var ua x509.UnknownAuthorityError
	if err == nil || !(errors.As(err, &ua) || strings.Contains(err.Error(), "certificate signed by unknown authority")) {
		t.Fatalf("right pin, untrusted chain, insecure_tls false: err = %v, want the chain refused", err)
	}
	if srv.hits.Load() != 0 {
		t.Fatal("the request reached the server")
	}
}

// The pin is checked on every connection, not once: a server that
// changes its key between connections is refused on the second.
func TestPinnedClient_KeyChangeBetweenConnectionsRefused(t *testing.T) {
	kpA, pinA := pinCert(t)
	kpB, _ := pinCert(t)
	var handshakes atomic.Int32
	srv := httptest.NewUnstartedServer(jsonOK(`{"data":[]}`))
	// GetConfigForClient, not GetCertificate: StartTLS fills Certificates
	// with Go's shared testcert, and GetCertificate is not consulted for a
	// client that sends no SNI (an IP address), so it would silently serve
	// that shared key instead.
	srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if handshakes.Add(1) == 1 {
			return &tls.Config{Certificates: []tls.Certificate{kpA}}, nil
		}
		return &tls.Config{Certificates: []tls.Certificate{kpB}}, nil
	}}
	srv.Config.SetKeepAlivesEnabled(false) // every request is a new connection
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c, err := NewClient(ClientConfig{BaseURLOverride: srv.URL + "/api2/json", InsecureTLS: true, TLSPin: pinA, TokenID: "root@pam!pveforge", TokenSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetNodes(context.Background()); err != nil {
		t.Fatalf("the first connection, key A: %v", err)
	}
	if _, err := c.GetNodes(context.Background()); !isPinMismatch(err) {
		t.Fatalf("the second connection, key B: err = %v, want a TLS pin mismatch", err)
	}
	if handshakes.Load() < 2 {
		t.Fatalf("only %d handshake(s): the test did not reach a second connection", handshakes.Load())
	}
}

// R-a: an unpinned client is built exactly as before T1a.
func TestNewHTTPClient_UnpinnedUnchanged(t *testing.T) {
	c, err := newHTTPClient(time.Second, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if g := c.Transport.(accessWriteGuard); g.next != nil {
		t.Fatalf("insecure_tls false, no pin: next = %T, want nil (http.DefaultTransport at request time)", g.next)
	}
	// T3 (inverted from T1a's "unchanged"): insecure_tls with no pin is
	// refused, and no transport is built.
	c, err = newHTTPClient(time.Second, true, "")
	if !errors.Is(err, ErrTLSPinRequired) || c != nil {
		t.Fatalf("insecure_tls true, no pin: client %v, err %v; want nil, ErrTLSPinRequired", c != nil, err)
	}
}

// The pinned transport's shape: VerifyConnection (which runs on resumed
// sessions too), never VerifyPeerCertificate (which does not), no session
// cache, TLS 1.2 at least, the proxy honoured, the guard in front.
func TestNewHTTPClient_PinnedShape(t *testing.T) {
	_, pin := pinCert(t)
	for _, insecure := range []bool{true, false} {
		c, err := newHTTPClient(time.Second, insecure, pin)
		if err != nil {
			t.Fatal(err)
		}
		g, ok := c.Transport.(accessWriteGuard)
		if !ok {
			t.Fatalf("transport is %T, want the accessWriteGuard", c.Transport)
		}
		tr, ok := g.next.(*http.Transport)
		if !ok {
			t.Fatalf("insecure_tls %v with a pin: next = %T, want a transport built at construction", insecure, g.next)
		}
		cfg := tr.TLSClientConfig
		if cfg.InsecureSkipVerify != insecure || cfg.VerifyConnection == nil || cfg.VerifyPeerCertificate != nil ||
			cfg.ClientSessionCache != nil || cfg.MinVersion != tls.VersionTLS12 || tr.Proxy == nil {
			t.Fatalf("insecure_tls %v with a pin: skip %v, VerifyConnection %v, VerifyPeerCertificate %v, session cache %v, MinVersion %x, Proxy %v",
				insecure, cfg.InsecureSkipVerify, cfg.VerifyConnection != nil, cfg.VerifyPeerCertificate != nil, cfg.ClientSessionCache != nil, cfg.MinVersion, tr.Proxy != nil)
		}
	}
}

func TestNewClient_RefusesAMalformedPin(t *testing.T) {
	for _, bad := range []tlspin.Pin{"sha256//x", "SHA256:abc", " sha256//"} {
		_, err := NewClient(ClientConfig{Host: "h", TLSPin: bad, TokenID: "a@pam!b", TokenSecret: "s"})
		if !errors.Is(err, tlspin.ErrMalformedPin) {
			t.Errorf("TLSPin %q: err = %v, want ErrMalformedPin", bad, err)
		}
	}
}

// NewClientForTarget carries the roster's pin: a target pinned to another
// key is refused, and one pinned to the server's key connects.
func TestNewClientForTarget_CarriesTheRosterPin(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{"data":[]}`))
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	armored, err := fixtureEncrypt([]byte("test-secret"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, other := pinCert(t)
	for pin, wantOK := range map[tlspin.Pin]bool{srv.pin: true, other: false} {
		tg := &roster.Target{ID: "t", Host: u.Hostname(), Node: "n1", APIPort: port, InsecureTLS: true,
			Token: &roster.TokenAuth{ID: "root@pam!pveforge", SecretEnc: armored},
			TLS:   &roster.TLSPin{SPKISHA256: string(pin)}}
		c, err := NewClientForTarget(tg, "pw")
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.GetNodes(context.Background())
		if wantOK && err != nil {
			t.Errorf("pinned to the server's key: %v", err)
		}
		if !wantOK && !isPinMismatch(err) {
			t.Errorf("pinned to another key: err = %v, want a TLS pin mismatch", err)
		}
	}
}

// ---- ServedPin ----

func TestServedPin_ReadsTheKeyAndSendsNothing(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	pin, cert, err := ServedPin(context.Background(), u.Hostname(), port, false)
	if err != nil {
		t.Fatalf("ServedPin: %v", err)
	}
	if pin != srv.pin || tlspin.FromCertificate(cert) != srv.pin {
		t.Fatalf("pin %s, want %s", pin, srv.pin)
	}
	// Let the server's side of the closed connection settle.
	deadline := time.Now().Add(2 * time.Second)
	for srv.conns.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h, n := srv.hits.Load(), srv.conns.Load(); h != 0 || n != 1 {
		t.Fatalf("ServedPin made %d request(s) over %d connection(s); want 0 requests, 1 connection", h, n)
	}
}

// stubTransport is a clone whose dialer reaches srv whatever name is
// dialed (so a non-loopback name, which a proxy function would consider,
// still arrives), counting dials, with proxy as its Proxy.
func stubTransport(srv *pinnedServer, proxy func(*http.Request) (*url.URL, error), dials *atomic.Int32) *http.Transport {
	tr := baseTransport()
	tr.Proxy = proxy
	target := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	return tr
}

func TestServedPin_RefusesAProxiedAddressBeforeDialing(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	var dials atomic.Int32
	var asked string
	proxy := func(r *http.Request) (*url.URL, error) {
		asked = r.URL.String()
		return url.Parse("http://proxy.example.test:3128")
	}
	_, _, err := servedPin(context.Background(), stubTransport(srv, proxy, &dials), "pve.example.test", 8006, false)
	if !errors.Is(err, ErrProxiedProbe) {
		t.Fatalf("err = %v, want ErrProxiedProbe", err)
	}
	if dials.Load() != 0 {
		t.Fatalf("%d dial(s) before the refusal, want 0", dials.Load())
	}
	if asked != "https://pve.example.test:8006/" {
		t.Fatalf("the proxy was asked about %q, want https://pve.example.test:8006/", asked)
	}
}

func TestServedPin_NoProxyDialsOnce(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	var dials atomic.Int32
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	pin, _, err := servedPin(context.Background(), stubTransport(srv, noProxy, &dials), "pve.example.test", 8006, false)
	if err != nil || pin != srv.pin {
		t.Fatalf("pin %s, err %v; want %s", pin, err, srv.pin)
	}
	if dials.Load() != 1 || srv.hits.Load() != 0 {
		t.Fatalf("%d dial(s), %d request(s); want 1, 0", dials.Load(), srv.hits.Load())
	}
}

func TestServedPin_Refusals(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	var dials atomic.Int32
	tr := stubTransport(srv, func(*http.Request) (*url.URL, error) { return nil, errors.New("bad proxy config") }, &dials)
	if _, _, err := servedPin(context.Background(), tr, "pve.example.test", 8006, false); err == nil || !strings.Contains(err.Error(), "resolve the proxy") {
		t.Errorf("a proxy function that fails: err = %v", err)
	}
	tr = baseTransport()
	tr.Proxy = nil
	tr.DialContext = nil
	if _, _, err := servedPin(context.Background(), tr, "pve.example.test", 8006, false); err == nil || !strings.Contains(err.Error(), "no dialer") {
		t.Errorf("no dialer: err = %v", err)
	}
	if dials.Load() != 0 {
		t.Errorf("%d dial(s), want 0", dials.Load())
	}
}

// transportOf reaches into a client for its pinned transport (test-only).
func transportOf(t *testing.T, c *Client) *http.Transport {
	t.Helper()
	tr, ok := c.httpClient.Transport.(accessWriteGuard).next.(*http.Transport)
	if !ok {
		t.Fatal("the client has no transport of its own")
	}
	return tr
}

// connectProxy is a minimal http:// CONNECT proxy that counts tunnels.
func connectProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var tunnels atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		tunnels.Add(1)
		w.WriteHeader(http.StatusOK)
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			up.Close()
			return
		}
		go func() { _, _ = buf.WriteTo(up); _, _ = io.Copy(up, conn); up.Close() }()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}))
	t.Cleanup(srv.Close)
	return srv, &tunnels
}

// The documented proxy behaviour, both halves: through an http:// CONNECT
// proxy the pin is checked against the target end to end and the request
// succeeds; through an https:// proxy the pin is checked against the
// PROXY's certificate too, so it fails closed before any request reaches
// the target.
func TestPinnedClient_Proxies(t *testing.T) {
	target := newPinnedServer(t, jsonOK(`{"data":[]}`))

	proxy, tunnels := connectProxy(t)
	c := pinnedClient(t, target, true, target.pin)
	pu, _ := url.Parse(proxy.URL)
	transportOf(t, c).Proxy = http.ProxyURL(pu)
	if _, err := c.GetNodes(context.Background()); err != nil {
		t.Fatalf("through an http:// CONNECT proxy: %v", err)
	}
	if tunnels.Load() != 1 || target.hits.Load() != 1 {
		t.Fatalf("%d tunnel(s), %d request(s) at the target; want 1, 1", tunnels.Load(), target.hits.Load())
	}
	// The pin still binds through the tunnel: another pin is refused.
	_, other := pinCert(t)
	c = pinnedClient(t, target, true, other)
	transportOf(t, c).Proxy = http.ProxyURL(pu)
	if _, err := c.GetNodes(context.Background()); !isPinMismatch(err) {
		t.Fatalf("through the tunnel with another pin: err = %v, want a TLS pin mismatch", err)
	}

	tlsProxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the https:// proxy received a %s: the pin should have refused its handshake", r.Method)
	}))
	t.Cleanup(tlsProxy.Close)
	hitsBefore := target.hits.Load()
	c = pinnedClient(t, target, true, target.pin)
	tpu, _ := url.Parse(tlsProxy.URL)
	transportOf(t, c).Proxy = http.ProxyURL(tpu)
	if _, err := c.GetNodes(context.Background()); !isPinMismatch(err) {
		t.Fatalf("through an https:// proxy: err = %v, want a TLS pin mismatch (fail closed)", err)
	}
	if target.hits.Load() != hitsBefore {
		t.Fatal("a request reached the target through the https:// proxy")
	}
}

// TestPinnedClient_CAModeEnforcesThePin: with insecure_tls false, a chain
// the client TRUSTS and the WRONG pin is refused. The chain alone is not
// enough (D4a: the chain AND the pin). The client's roots are the system
// pool, which crypto/x509 reads from SSL_CERT_FILE on Linux, so the check
// runs in a child test process whose SSL_CERT_FILE names this test's own
// CA: no production hook is needed to make a chain trusted.
func TestPinnedClient_CAModeEnforcesThePin(t *testing.T) {
	if os.Getenv("PVEFORGE_TEST_CA_CHILD") == "1" {
		caModeChild(t)
		return
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pveforge test CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		jsonOK(`{"data":[]}`)(w, r)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	_, other := pinCert(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestPinnedClient_CAModeEnforcesThePin$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(),
		"PVEFORGE_TEST_CA_CHILD=1",
		"SSL_CERT_FILE="+caFile,
		"SSL_CERT_DIR="+t.TempDir(), // no other roots
		"PVEFORGE_TEST_CA_URL="+srv.URL,
		"PVEFORGE_TEST_CA_PIN="+string(tlspin.FromCertificate(leaf)),
		"PVEFORGE_TEST_CA_OTHER="+string(other),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	// Anti-vacuity: the child really ran all three cases.
	if !strings.Contains(string(out), "CA-MODE-CHILD: 3 cases checked") {
		t.Fatalf("the child did not run its checks:\n%s", out)
	}
	if h := hits.Load(); h != 2 {
		t.Fatalf("%d request(s) reached the server, want 2 (right pin, no pin; never the wrong pin)", h)
	}
}

func caModeChild(t *testing.T) {
	u := os.Getenv("PVEFORGE_TEST_CA_URL")
	client := func(pin tlspin.Pin) *Client {
		c, err := NewClient(ClientConfig{BaseURLOverride: u + "/api2/json", InsecureTLS: false, TLSPin: pin, TokenID: "root@pam!pveforge", TokenSecret: "s"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := context.Background()
	// The chain is trusted: with no pin it connects (CA mode unchanged).
	if _, err := client("").GetNodes(ctx); err != nil {
		t.Fatalf("trusted chain, no pin: %v (is SSL_CERT_FILE being read?)", err)
	}
	if _, err := client(tlspin.Pin(os.Getenv("PVEFORGE_TEST_CA_PIN"))).GetNodes(ctx); err != nil {
		t.Fatalf("trusted chain, right pin: %v", err)
	}
	if _, err := client(tlspin.Pin(os.Getenv("PVEFORGE_TEST_CA_OTHER"))).GetNodes(ctx); !isPinMismatch(err) {
		t.Fatalf("trusted chain, WRONG pin: err = %v, want a TLS pin mismatch", err)
	}
	fmt.Println("CA-MODE-CHILD: 3 cases checked")
}

// Port 0 is read as REST reads it: the probe dials host:8006, the address
// NewClient builds for the same target (EffectiveAPIPort, one rule).
func TestServedPin_PortZeroIsTheDefaultAPIPort(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	var dials atomic.Int32
	tr := stubTransport(srv, func(*http.Request) (*url.URL, error) { return nil, nil }, &dials)
	var dialed string
	inner := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = addr
		return inner(ctx, network, addr)
	}
	if _, _, err := servedPin(context.Background(), tr, "pve.example.test", 0, false); err != nil {
		t.Fatal(err)
	}
	if dialed != "pve.example.test:8006" {
		t.Fatalf("port 0 dialled %q, want pve.example.test:8006", dialed)
	}
	c, err := NewClient(ClientConfig{Host: "pve.example.test", TokenID: "a@pam!b", TokenSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://pve.example.test:8006/api2/json" {
		t.Fatalf("REST's base URL for the same target is %q", c.baseURL)
	}
	if EffectiveAPIPort(0) != DefaultAPIPort || EffectiveAPIPort(8443) != 8443 {
		t.Fatal("EffectiveAPIPort")
	}
}

// verifyChain: the probe also verifies the chain, and a certificate no
// system root vouches for is refused; without it the same server reads.
func TestServedPin_VerifyChain(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{}`))
	var dials atomic.Int32
	tr := stubTransport(srv, func(*http.Request) (*url.URL, error) { return nil, nil }, &dials)
	if _, _, err := servedPin(context.Background(), tr, "pve.example.test", 8006, true); err == nil || !strings.Contains(err.Error(), "TLS handshake") {
		t.Fatalf("verifyChain against a self-signed certificate: err = %v, want the handshake refused", err)
	}
	if pin, _, err := servedPin(context.Background(), tr, "pve.example.test", 8006, false); err != nil || pin != srv.pin {
		t.Fatalf("without verifyChain: %s, %v", pin, err)
	}
}

// T3: BaseURLOverride is a production field, so it is NOT an exemption: an
// unpinned insecure client is refused however its URL is given.
func TestNewClient_BaseURLOverrideIsNotExempt(t *testing.T) {
	srv := newPinnedServer(t, jsonOK(`{"data":[]}`))
	_, err := NewClient(ClientConfig{BaseURLOverride: srv.URL + "/api2/json", InsecureTLS: true, TokenID: "root@pam!pveforge", TokenSecret: "s"})
	if !errors.Is(err, ErrTLSPinRequired) || srv.hits.Load() != 0 {
		t.Fatalf("err = %v, hits %d; want ErrTLSPinRequired and no request", err, srv.hits.Load())
	}
}

// T3: NewClientForTarget names the target and the command that pins it.
func TestNewClientForTarget_UnpinnedInsecureIsRefused(t *testing.T) {
	armored, err := fixtureEncrypt([]byte("s"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	tg := &roster.Target{ID: "qa-x", Host: "h", Node: "n", InsecureTLS: true, Token: &roster.TokenAuth{ID: "a@pam!b", SecretEnc: armored}}
	_, err = NewClientForTarget(tg, "pw")
	if !errors.Is(err, ErrTLSPinRequired) || !strings.Contains(err.Error(), `target "qa-x"`) || !strings.Contains(err.Error(), "pveforge roster pin-tls qa-x") {
		t.Fatalf("err = %v", err)
	}
	tg.InsecureTLS = false // a CA-verified target needs no pin
	if _, err := NewClientForTarget(tg, "pw"); err != nil {
		t.Fatalf("a CA-verified target: %v", err)
	}
}
