package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// installScriptPrefix is how sshexec's InstallPubkeyViaPassword script
// begins: a test server's one handler answers it apart from the commands
// that follow on the pinned session (pvefake is configured before Start).
const installScriptPrefix = "set -e\nmkdir -p ~/.ssh"

// ranOrInstalled answers the install script as the server's default does,
// and every other command with "ran: <cmd>".
func ranOrInstalled(cmd string) (string, string, int) {
	if strings.HasPrefix(cmd, installScriptPrefix) {
		return "", "", 0
	}
	return "ran: " + cmd, "", 0
}

func TestRealSSHTransport_InstallPubkeyViaPassword(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "hunter2")
	fs.HandleExec(func(cmd string) (string, string, int) { return "added\n", "", 0 })
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSSHTransport()
	fp, err := transport.InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "hunter2", "ssh-ed25519 AAAAtest comment", "")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}
	if fp == "" {
		t.Fatal("expected a non-empty host key fingerprint")
	}
}

func TestRealSSHTransport_InstallPubkeyViaPassword_PropagatesError(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "hunter2")
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport := NewSSHTransport()
	_, err := transport.InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "wrong-password", "ssh-ed25519 AAAAtest comment", "")
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

	fs := pvefake.NewSSHServer(t)
	fs.AllowKey(signer.PublicKey())
	// Capture the real host key fingerprint the same way bootstrap's own
	// InstallPubkeyViaPassword step would, so DialWithKey's pinning check
	// has something real to compare against. One handler answers both the
	// install and the pinned session's command.
	fs.AllowPassword("root", "hunter2")
	fs.HandleExec(ranOrInstalled)
	fs.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fp, err := NewSSHTransport().InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "hunter2", kp.AuthorizedKeyLine, "")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}

	session, err := NewSSHTransport().DialWithKey(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, fp)
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

	fs := pvefake.NewSSHServer(t)
	fs.AllowKey(signer.PublicKey())
	fs.AllowPassword("root", "hunter2")
	fs.HandleExec(ranOrInstalled)
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Establish the pinned fingerprint the same way a prior successful
	// bootstrap would have (via the password/TOFU path), then reconnect
	// using ONLY the reconnect path — no password auth involved.
	fp, err := NewSSHTransport().InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "hunter2", kp.AuthorizedKeyLine, "")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}

	session, err := NewSSHTransport().ReconnectWithPinnedKey(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, fp)
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

	fs := pvefake.NewSSHServer(t)
	fs.AllowKey(signer.PublicKey())
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A fingerprint that does not match this server's actual host key —
	// simulating a target whose network address now answers with a
	// different host key than what was pinned on a prior bootstrap.
	_, err = NewSSHTransport().ReconnectWithPinnedKey(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, "SHA256:not-the-real-host-key-at-all")
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

// VR1: today's effective grant (PVEVMAdmin on /, propagating), now stated
// explicitly as --grant /:PVEVMAdmin::1, against today's live
// root@pam!pveforge tree validates nil through the production wiring
// (translation, TLS client, RawRequest), so that re-run keeps reusing
// today's token. VR1b: the same grant without propagate (the --grant
// default) is ErrScopeTooWide, which on a re-run would revoke it.
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
	want, err := ParseGrants([]string{"/:PVEVMAdmin::1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewAPIValidator().ValidateTokenGrants(context.Background(), cfg, want); err != nil {
		t.Fatalf("/:PVEVMAdmin::1 against the live tree: %v", err)
	}
	t.Run("VR1b propagate 0 is too wide for the live token", func(t *testing.T) {
		want, err := ParseGrants([]string{"/:PVEVMAdmin"})
		if err != nil {
			t.Fatal(err)
		}
		if err := NewAPIValidator().ValidateTokenGrants(context.Background(), cfg, want); !errors.Is(err, ErrScopeTooWide) {
			t.Fatalf("/:PVEVMAdmin (propagate 0) against the live tree: want ErrScopeTooWide, got %v", err)
		}
	})
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

// C-T7 (U-C): the real keyless adapter against the same fake server.
// pin "" trusts on first use and returns the fingerprint
// InstallPubkeyViaPassword captures for the same host; that fingerprint,
// passed back as pin, is accepted; a different one is refused at the
// handshake (MK15, MK16). There is deliberately no pre-dial shape check,
// so no row for a malformed pin: "" MEANS trust-on-first-use here.
func TestRealSSHTransport_DialWithPassword(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "hunter2")
	fs.HandleExec(func(cmd string) (string, string, int) { return "ran: " + cmd, "", 0 })
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := NewSSHTransport()

	installFP, err := transport.InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "hunter2", "ssh-ed25519 AAAAtest comment", "")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}

	session, fp, err := transport.DialWithPassword(ctx, fs.Addr(), "root", "hunter2", "")
	if err != nil {
		t.Fatalf("DialWithPassword (tofu): %v", err)
	}
	if fp != installFP {
		t.Fatalf("the captured fingerprint %q differs from the install path's %q", fp, installFP)
	}
	res, err := session.Run(ctx, "echo hi")
	if err != nil || res.Stdout != "ran: echo hi" {
		t.Fatalf("Run: %+v, %v", res, err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pinned, fp2, err := transport.DialWithPassword(ctx, fs.Addr(), "root", "hunter2", fp)
	if err != nil {
		t.Fatalf("DialWithPassword (pinned to the captured key): %v", err)
	}
	if fp2 != fp {
		t.Fatalf("the pinned dial returned %q, want the pin %q", fp2, fp)
	}
	_ = pinned.Close()

	other := "SHA256:" + strings.Repeat("A", 43)
	if _, _, err := transport.DialWithPassword(ctx, fs.Addr(), "root", "hunter2", other); err == nil {
		t.Fatal("a dial pinned to a different host key was accepted")
	}
}
