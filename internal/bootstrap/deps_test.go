package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// depsFakeSSHServer is a minimal in-process SSH server, exercising the
// real deps.go adapters (realSSHTransport/realSSHSession) against actual
// sshexec/x-crypto-ssh network code — no live PVE host involved, per this
// package's test strategy.
//
// Configuration fields (password/allowedPub/handleExec) are guarded by mu
// and accessed only through the set*/get* methods below — never directly.
// Unlike internal/sshexec's and internal/pve's equivalent fixtures (which
// use a deferred Start() because each of their tests configures the
// server fully exactly once, before any use), several tests here
// reconfigure handleExec mid-test, AFTER the server has already handled
// one full connection (see TestRealSSHTransport_DialWithKey_RunAndClose
// and TestRealSSHTransport_ReconnectWithPinnedKey_RunAndClose): the
// client observing connection #1 complete does NOT create a
// race-detector-visible happens-before edge with the server-side
// goroutine that served it — Go's race detector has no model for
// ordering established via raw socket I/O, only via its own recognized
// primitives (channels, mutexes, atomics, goroutine creation). A
// one-time deferred Start() would still leave that second, mid-test
// write racing against the server goroutine from connection #1 as far as
// the detector is concerned, even though the real-world ordering happens
// to be safe. A mutex around every access closes that gap regardless of
// how many times a test reconfigures the server. See
// pveforge-fix-fake-ssh-server-test-races.
type depsFakeSSHServer struct {
	addr       string
	hostSigner ssh.Signer

	mu         sync.Mutex
	password   string
	allowedPub ssh.PublicKey
	handleExec func(cmd string) (string, string, int)
}

func newDepsFakeSSHServer(t *testing.T) *depsFakeSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	fs := &depsFakeSSHServer{
		addr:       ln.Addr().String(),
		hostSigner: signer,
		handleExec: func(cmd string) (string, string, int) { return "", "", 0 },
	}
	go fs.serve(ln)
	return fs
}

// setPassword, setAllowedPub, and setHandleExec are the only sanctioned
// way to configure a depsFakeSSHServer, at any point in a test's
// lifetime — including after the server has already handled earlier
// connections — since every access goes through fs.mu.
func (fs *depsFakeSSHServer) setPassword(password string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.password = password
}

func (fs *depsFakeSSHServer) setAllowedPub(pub ssh.PublicKey) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.allowedPub = pub
}

func (fs *depsFakeSSHServer) setHandleExec(fn func(cmd string) (string, string, int)) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.handleExec = fn
}

func (fs *depsFakeSSHServer) getPassword() string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.password
}

func (fs *depsFakeSSHServer) getAllowedPub() ssh.PublicKey {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.allowedPub
}

func (fs *depsFakeSSHServer) getHandleExec() func(cmd string) (string, string, int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.handleExec
}

func (fs *depsFakeSSHServer) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go fs.handleConn(conn)
	}
}

func (fs *depsFakeSSHServer) handleConn(conn net.Conn) {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if want := fs.getPassword(); want != "" && string(pass) == want {
				return nil, nil
			}
			return nil, errAuthRejected
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if allowed := fs.getAllowedPub(); allowed != nil && string(key.Marshal()) == string(allowed.Marshal()) {
				return nil, nil
			}
			return nil, errAuthRejected
		},
	}
	cfg.AddHostKey(fs.hostSigner)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go fs.handleSession(ch, chReqs)
	}
}

func (fs *depsFakeSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		cmd := string(req.Payload[4:])
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		stdout, stderr, code := fs.getHandleExec()(cmd)
		_, _ = ch.Write([]byte(stdout))
		_, _ = ch.Stderr().Write([]byte(stderr))
		status := make([]byte, 4)
		status[3] = byte(code)
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

type authRejectedError struct{}

func (*authRejectedError) Error() string { return "auth rejected" }

var errAuthRejected = &authRejectedError{}

func TestRealSSHTransport_InstallPubkeyViaPassword(t *testing.T) {
	fs := newDepsFakeSSHServer(t)
	fs.setPassword("hunter2")
	fs.setHandleExec(func(cmd string) (string, string, int) { return "added\n", "", 0 })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSSHTransport()
	fp, err := transport.InstallPubkeyViaPassword(ctx, fs.addr, "root", "hunter2", "ssh-ed25519 AAAAtest comment")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}
	if fp == "" {
		t.Fatal("expected a non-empty host key fingerprint")
	}
}

func TestRealSSHTransport_InstallPubkeyViaPassword_PropagatesError(t *testing.T) {
	fs := newDepsFakeSSHServer(t)
	fs.setPassword("hunter2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSSHTransport()
	_, err := transport.InstallPubkeyViaPassword(ctx, fs.addr, "root", "wrong-password", "ssh-ed25519 AAAAtest comment")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestRealSSHTransport_DialWithKey_EmptyFingerprintRejected(t *testing.T) {
	transport := NewSSHTransport()
	_, err := transport.DialWithKey(context.Background(), "127.0.0.1:1", "root", []byte("not-a-real-key"), "")
	if err == nil {
		t.Fatal("expected error for an empty host key fingerprint")
	}
	if !strings.Contains(err.Error(), "dial with pinned key") {
		t.Fatalf("expected the error to be wrapped with context, got: %v", err)
	}
}

func TestRealSSHTransport_DialWithKey_RunAndClose(t *testing.T) {
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	fs := newDepsFakeSSHServer(t)
	fs.setAllowedPub(signer.PublicKey())

	// Capture the real host key fingerprint the same way bootstrap's own
	// InstallPubkeyViaPassword step would, so DialWithKey's pinning check
	// has something real to compare against.
	fs.setPassword("hunter2")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fp, err := NewSSHTransport().InstallPubkeyViaPassword(ctx, fs.addr, "root", "hunter2", kp.AuthorizedKeyLine)
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}

	fs.setHandleExec(func(cmd string) (string, string, int) { return "ran: " + cmd, "", 0 })

	session, err := NewSSHTransport().DialWithKey(ctx, fs.addr, "root", kp.PrivateKeyPEM, fp)
	if err != nil {
		t.Fatalf("DialWithKey: %v", err)
	}
	res, err := session.Run(ctx, "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != "ran: echo hi" || res.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRealSSHTransport_ReconnectWithPinnedKey_EmptyFingerprintRejected(t *testing.T) {
	transport := NewSSHTransport()
	_, err := transport.ReconnectWithPinnedKey(context.Background(), "127.0.0.1:1", "root", []byte("not-a-real-key"), "")
	if err == nil {
		t.Fatal("expected error for an empty host key fingerprint")
	}
	if !strings.Contains(err.Error(), "dial with pinned key") {
		t.Fatalf("expected the error to be wrapped with context, got: %v", err)
	}
}

func TestRealSSHTransport_ReconnectWithPinnedKey_RunAndClose(t *testing.T) {
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	fs := newDepsFakeSSHServer(t)
	fs.setAllowedPub(signer.PublicKey())
	fs.setPassword("hunter2")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Establish the pinned fingerprint the same way a prior successful
	// bootstrap would have (via the password/TOFU path), then reconnect
	// using ONLY the reconnect path — no password auth involved.
	fp, err := NewSSHTransport().InstallPubkeyViaPassword(ctx, fs.addr, "root", "hunter2", kp.AuthorizedKeyLine)
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}

	fs.setHandleExec(func(cmd string) (string, string, int) { return "ran: " + cmd, "", 0 })

	session, err := NewSSHTransport().ReconnectWithPinnedKey(ctx, fs.addr, "root", kp.PrivateKeyPEM, fp)
	if err != nil {
		t.Fatalf("ReconnectWithPinnedKey: %v", err)
	}
	res, err := session.Run(ctx, "echo hi")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != "ran: echo hi" || res.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestRealSSHTransport_ReconnectWithPinnedKey_RejectsMismatchedHostKey(t *testing.T) {
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	fs := newDepsFakeSSHServer(t)
	fs.setAllowedPub(signer.PublicKey())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A fingerprint that does not match this server's actual host key —
	// simulating a target whose network address now answers with a
	// different host key than what was pinned on a prior bootstrap.
	_, err = NewSSHTransport().ReconnectWithPinnedKey(ctx, fs.addr, "root", kp.PrivateKeyPEM, "SHA256:not-the-real-host-key-at-all")
	if err == nil {
		t.Fatal("expected a host key mismatch error")
	}
}

// TestRealAPIValidator_ValidateTokenGrants_BuildClientError covers
// deps.go's own "build pve client" wrapping line. realAPIValidator always
// derives "https://<host>:<port>/api2/json" from APIConfig, so it can't be
// pointed at an httptest server the way internal/pve's own tests are
// (those use pve.ClientConfig.BaseURLOverride directly) — the actual
// request path is already covered there. Here we only exercise the
// error-translation path deps.go adds on top.
func TestRealAPIValidator_ValidateTokenGrants_BuildClientError(t *testing.T) {
	validator := NewAPIValidator()
	err := validator.ValidateTokenGrants(context.Background(), APIConfig{
		Host: "", // triggers pve.NewClient's "host is required" error
	}, []Grant{{Path: "/", Role: "PVEVMAdmin", Propagate: true}})
	if err == nil {
		t.Fatal("expected error when APIConfig is incomplete")
	}
	if !strings.Contains(err.Error(), "build pve client") {
		t.Fatalf("expected the error to be wrapped with context, got: %v", err)
	}
}

// d1Server is an httptest TLS PVE answering only the two endpoints the
// real validator reads: GET /access/permissions (tree, or ?path=) and GET
// /access/roles/<id>. Anything else is a test failure.
func d1Server(t *testing.T, status int, tree string, paths, roles map[string]string) APIConfig {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var body string
		var ok bool
		switch {
		case r.URL.Path == "/api2/json/access/permissions" && len(q) == 0:
			body, ok = tree, true
		case r.URL.Path == "/api2/json/access/permissions" && len(q) == 1:
			body, ok = paths[q.Get("path")]
		case strings.HasPrefix(r.URL.Path, "/api2/json/access/roles/"):
			body, ok = roles[strings.TrimPrefix(r.URL.Path, "/api2/json/access/roles/")]
		}
		if !ok {
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return APIConfig{Host: host, APIPort: port, InsecureTLS: true, TokenID: "root@pam!t", TokenSecret: "s"}
}

// D1-ext (S4g): the REAL validator, against an httptest TLS server, yields
// errors that match bootstrap's own sentinels, so isVerdict and
// postMintRetryable see them. A sentinel "aliased" by an errors.New copy
// instead of = pve.X would make every verdict look like a non-verdict; this
// turns that red.
func TestRealAPIValidator_D1_SentinelsAreTheAliases(t *testing.T) {
	want := []Grant{{Path: "/pool/p", Role: "R"}}
	roles := map[string]string{"R": `{"data":{"A":1}}`}
	for name, tc := range map[string]struct {
		status    int
		tree      string
		paths     map[string]string
		want      error
		retryable bool
	}{
		"403":           {http.StatusForbidden, `{"data":null}`, nil, ErrNotAuthorized, true},
		"empty tree":    {http.StatusOK, `{"data":{}}`, nil, ErrNoGrants, true},
		"missing grant": {http.StatusOK, `{"data":{"/storage/s":{"A":0}}}`, map[string]string{"/pool/p": `{"data":{"/pool/p":{}}}`}, ErrWrongScope, true},
		"too wide":      {http.StatusOK, `{"data":{"/":{"A":1}}}`, map[string]string{"/pool/p": `{"data":{"/pool/p":{"A":1}}}`}, ErrScopeTooWide, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := d1Server(t, tc.status, tc.tree, tc.paths, roles)
			err := NewAPIValidator().ValidateTokenGrants(context.Background(), cfg, want)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want errors.Is(%v)", err, tc.want)
			}
			for _, other := range []error{ErrNotAuthorized, ErrNoGrants, ErrWrongScope, ErrScopeTooWide} {
				if other != tc.want && errors.Is(err, other) {
					t.Fatalf("err = %v also matches %v", err, other)
				}
			}
			if !isVerdict(err) {
				t.Fatalf("isVerdict(%v) = false", err)
			}
			if postMintRetryable(err) != tc.retryable {
				t.Fatalf("postMintRetryable(%v) = %v, want %v", err, !tc.retryable, tc.retryable)
			}
		})
	}
}

// VR1: the default grant (PVEVMAdmin on /, propagating) against today's
// live root@pam!pveforge tree validates nil through the production wiring
// (translation, TLS client, RawRequest), so a default-flag reconnect keeps
// reusing today's token.
func TestRealAPIValidator_VR1_DefaultGrantAgainstLiveTree(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("../pve/testdata/permissions/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	tree := read("root-pam-pveforge.json")
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tree), &parsed); err != nil || len(parsed) != 8 {
		t.Fatalf("live tree fixture: %d paths, %v", len(parsed), err)
	}
	cfg := d1Server(t, http.StatusOK, `{"data":`+tree+`}`,
		map[string]string{"/": `{"data":{"/":` + string(parsed["/"]) + `}}`},
		map[string]string{"PVEVMAdmin": `{"data":` + read("role-pvevmadmin.json") + `}`})
	o := applied(Options{})
	want := requestedGrants(o)
	if err := NewAPIValidator().ValidateTokenGrants(context.Background(), cfg, want); err != nil {
		t.Fatalf("the default grant against the live tree: %v", err)
	}
}

// applied returns o with applyDefaults run.
func applied(o Options) Options {
	applyDefaults(&o)
	return o
}

// The translation keeps all four fields, and nil (unpinned) apart from
// empty and non-empty pinned Privs (M17, M19).
func TestToPVEGrants(t *testing.T) {
	in := []Grant{
		{Path: "/a", Role: "R", Propagate: true},
		{Path: "/b", Role: "S", Privs: []string{}},
		{Path: "/c", Role: "T", Propagate: true, Privs: []string{"A", "B"}},
	}
	out := toPVEGrants(in)
	if len(out) != 3 {
		t.Fatalf("out = %+v", out)
	}
	for i, g := range in {
		o := out[i]
		if o.Path != g.Path || o.Role != g.Role || o.Propagate != g.Propagate {
			t.Errorf("%d: %+v -> %+v", i, g, o)
		}
		if (o.Privs == nil) != (g.Privs == nil) || strings.Join(o.Privs, ",") != strings.Join(g.Privs, ",") {
			t.Errorf("%d: Privs %#v -> %#v", i, g.Privs, o.Privs)
		}
	}
	// A copy: the caller's slice is not shared.
	out[2].Privs[0] = "X"
	if in[2].Privs[0] != "A" {
		t.Error("the translation shares the Privs slice")
	}
	if toPVEGrants(nil) != nil {
		t.Error("nil want must stay nil")
	}
}

// bootstrap.Grant.Check delegates to pve's checks.
func TestGrantCheckDelegates(t *testing.T) {
	if err := (Grant{Path: "/pool/p", Role: "R"}).Check(); err != nil {
		t.Fatal(err)
	}
	for _, g := range []Grant{
		{Path: "/pool/p/", Role: "R"},
		{Path: "/pool/p", Privs: []string{"A"}},
		{Path: "/pool/p", Role: "R", Privs: []string{}},
	} {
		if err := g.Check(); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("%+v: want ErrInvalidGrant, got %v", g, err)
		}
	}
	if err := checkGrants([]Grant{{Path: "/a", Role: "R"}, {Path: "/a", Role: "S"}}); !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("two grants on one path: %v", err)
	}
}
