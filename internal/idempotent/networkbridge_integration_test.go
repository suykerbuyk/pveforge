package idempotent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// This file is this task's full-stack integration test: NetworkBridgeEnsure
// (this package)'s Apply driven against a REAL *pve.RoutedClient — not the
// in-package fakeNetworkBridgeClient the rest of this file's suite uses —
// backed by a fake REST server AND a fake SSH server together.
//
// It deliberately lives HERE, in package idempotent, and not in
// internal/pve (as originally sketched for this task): this package's own
// production code already imports internal/pve (see vmtag.go, vmfields.go,
// bridgeisolation.go — for pve.IsDigestConflictError, pve.TaskFailedError,
// etc.), so a pve-package test file importing internal/idempotent back
// would be a genuine, tool-enforced import cycle (confirmed with `go vet`
// while writing this, not assumed) — "internal/idempotent's own non-test
// code never imports internal/pve" does not hold for this package as a
// whole, only for this one file. Placing the test here instead avoids the
// cycle entirely (this package already legitimately imports pve) while
// still exercising the real thing: a genuine *pve.RoutedClient, wired to a
// real REST server and a real (fake, in-process) SSH server, both reached
// through pve's OWN exported construction path (pve.NewRoutedClient),
// never a shortcut around it.
//
// Because this file lives outside package pve, it cannot reach pve's own
// private test harness (routed_test.go's bootstrappedTarget/
// newFakeSSHServer/testClient, all unexported) — it rebuilds the small
// pieces it needs from pve's and sshexec's EXPORTED surface only:
//   - the REST side is redirected via roster.Target's own ordinary
//     Host/APIPort/InsecureTLS fields pointed at a real httptest.NewTLSServer
//     (exactly cmd/pveforge's own newTestRosterWithTLSTarget pattern — no
//     pve-internal field poking at all).
//   - the SSH side needed a small, new, EXPORTED test seam added to
//     internal/pve for this: pve.SetSSHPortForIntegrationTests. RoutedClient
//     always dials the real port 22 otherwise, with no roster.Target field
//     or other exported way to redirect it — that seam is the minimal
//     addition that makes this genuine cross-package integration test
//     possible at all; production code never calls it.

// fakeIntegrationSSHServer is a minimal in-process SSH server, self-
// contained in this file: internal/pve's own equivalent
// (fakesshserver_test.go's fakeSSHServer) is unexported and can't be
// reused from this package, and no shared/exported test-SSH-server helper
// exists anywhere in this project (internal/bootstrap rolls its own
// private copy too) — this is the established convention, not a shortcut.
type fakeIntegrationSSHServer struct {
	hostSigner ssh.Signer
	allowedPub ssh.PublicKey
	listener   net.Listener
	addr       string

	mu   sync.Mutex
	cmds []string

	handleExec func(cmd string) (stdout, stderr string, exitCode int)
}

func newFakeIntegrationSSHServer(t *testing.T) *fakeIntegrationSSHServer {
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

	return &fakeIntegrationSSHServer{
		hostSigner: signer,
		listener:   ln,
		addr:       ln.Addr().String(),
		handleExec: func(string) (string, string, int) { return "", "", 0 },
	}
}

func (fs *fakeIntegrationSSHServer) port(t *testing.T) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(fs.addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return p
}

func (fs *fakeIntegrationSSHServer) start() {
	go func() {
		for {
			conn, err := fs.listener.Accept()
			if err != nil {
				return
			}
			go fs.handleConn(conn)
		}
	}()
}

func (fs *fakeIntegrationSSHServer) handleConn(conn net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if fs.allowedPub != nil && string(key.Marshal()) == string(fs.allowedPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("auth rejected")
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

func (fs *fakeIntegrationSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
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
		fs.mu.Lock()
		fs.cmds = append(fs.cmds, cmd)
		fs.mu.Unlock()

		stdout, stderr, code := fs.handleExec(cmd)
		_, _ = ch.Write([]byte(stdout))
		_, _ = ch.Stderr().Write([]byte(stderr))
		status := make([]byte, 4)
		status[3] = byte(code)
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

func (fs *fakeIntegrationSSHServer) cmdSequence() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	out := make([]string, len(fs.cmds))
	copy(out, fs.cmds)
	return out
}

// linkExistsJSON is the `ip -j link show` JSON body for an existing
// interface with the given up/down state.
func linkExistsJSON(iface string, up bool) string {
	state, flags := "DOWN", `["BROADCAST","MULTICAST"]`
	if up {
		state, flags = "UP", `["UP","BROADCAST","MULTICAST"]`
	}
	return fmt.Sprintf(`[{"ifname":%q,"operstate":%q,"flags":%s}]`, iface, state, flags)
}

const linkMissingStderrFmt = `Device "%s" does not exist.`

// bootstrappedIntegrationTarget builds a roster.Target with real,
// working token and SSH auth against restSrv/fs — mirroring
// internal/pve's own routed_test.go bootstrappedTarget, rebuilt here from
// exported roster/sshexec API only (see this file's own top-of-file doc
// comment on why it can't just call pve's private copy).
func bootstrappedIntegrationTarget(t *testing.T, restSrv *httptest.Server, fs *fakeIntegrationSSHServer, passphrase string) *roster.Target {
	t.Helper()

	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	fs.allowedPub = signer.PublicKey()
	fs.start()

	var captured sshexec.CapturedHostKey
	c, err := sshexec.Dial(context.Background(), fs.addr, "root", kp.PrivateKeyPEM, sshexec.CaptureHostKeyCallback(&captured))
	if err != nil {
		t.Fatalf("dial to capture host key: %v", err)
	}
	defer c.Close()

	tokenArmored, err := fixtureEncrypt([]byte("tok-secret-value"), passphrase)
	if err != nil {
		t.Fatalf("fixtureEncrypt token: %v", err)
	}
	sshArmored, err := fixtureEncrypt(kp.PrivateKeyPEM, passphrase)
	if err != nil {
		t.Fatalf("fixtureEncrypt ssh key: %v", err)
	}

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(restSrv.URL, "https://"))
	if err != nil {
		t.Fatalf("split rest server host/port: %v", err)
	}
	apiPort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse rest server port: %v", err)
	}

	return &roster.Target{
		ID:          "qa-pve-01",
		Host:        host,
		Node:        "qa-pve-01",
		APIPort:     apiPort,
		InsecureTLS: true,
		Token: &roster.TokenAuth{
			ID:        "root@pam!pveforge",
			SecretEnc: tokenArmored,
		},
		SSH: &roster.SSHAuth{
			User:               "root",
			PublicKey:          kp.AuthorizedKeyLine,
			HostKeyFingerprint: captured.Fingerprint(),
			PrivateKeyEnc:      sshArmored,
		},
	}
}

// networkBridgeRESTScript is a small, ordered fake REST server for exactly
// the PVE calls NetworkBridgeEnsure.Apply issues: pre/post-stage snapshots
// and the guard self-check GET against /nodes/{node}/network/{iface}, the
// stage POST/DELETE and commit PUT against /nodes/{node}/network, an
// optional revert DELETE against the same collection path, and the task
// status poll GET against /nodes/{node}/tasks/{upid}/status.
type networkBridgeRESTScript struct {
	t    *testing.T
	node string

	mgmtFields  string
	stageResp   string
	ifaceFields string
	commitUPID  string
	revertResp  string

	mu   sync.Mutex
	hits []string
}

func newNetworkBridgeRESTScript(t *testing.T, node string) *networkBridgeRESTScript {
	t.Helper()
	return &networkBridgeRESTScript{t: t, node: node, stageResp: `null`, revertResp: `null`}
}

func (s *networkBridgeRESTScript) server() *httptest.Server {
	mgmtPath := fmt.Sprintf("/api2/json/nodes/%s/network/vmbr0", s.node)
	collectionPath := fmt.Sprintf("/api2/json/nodes/%s/network", s.node)

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits = append(s.hits, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == mgmtPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.mgmtFields)

		case r.Method == http.MethodGet && r.URL.Path != mgmtPath && strings.HasPrefix(r.URL.Path, collectionPath+"/") && !strings.Contains(r.URL.Path, "/tasks/"):
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.ifaceFields)

		case r.Method == http.MethodPost && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.stageResp)

		case r.Method == http.MethodDelete && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.revertResp)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, collectionPath+"/"):
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.stageResp)

		case r.Method == http.MethodPut && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.commitUPID)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, fmt.Sprintf("/api2/json/nodes/%s/tasks/", s.node)) && strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, s.commitUPID, s.node)

		default:
			s.t.Fatalf("networkBridgeRESTScript: unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

func (s *networkBridgeRESTScript) hitSequence() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.hits))
	copy(out, s.hits)
	return out
}

func wellFormedNetworkUPID(node, iface string) string {
	return fmt.Sprintf("UPID:%s:00001234:00ABCDEF:5F000000:qmnetwork:%s:root@pam:", node, iface)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestNetworkBridgeEnsure_Apply_Create_FullStack drives NetworkBridgeEnsure
// .Apply against a REAL *pve.RoutedClient — reached only through pve's own
// exported pve.NewRoutedClient constructor, never a shortcut around it —
// backed by a fake REST server AND a fake SSH server together. Asserts, in
// order, the exact HTTP method+path sequence hit, the exact SSH command
// sequence run, and that Apply returns no error.
func TestNetworkBridgeEnsure_Apply_Create_FullStack(t *testing.T) {
	const node = "qa-pve-01"
	const mgmtIface = "vmbr0"
	const targetIface = "vmbr1"

	upid := wellFormedNetworkUPID(node, targetIface)
	restScript := newNetworkBridgeRESTScript(t, node)
	restScript.mgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	restScript.ifaceFields = `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}` // no "active": not yet committed
	restScript.commitUPID = upid
	restSrv := restScript.server()
	defer restSrv.Close()

	fs := newFakeIntegrationSSHServer(t)
	mgmtCmd := fmt.Sprintf("ip -j link show dev '%s'", mgmtIface)
	ifaceCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	var ifaceCalls int
	var mu sync.Mutex
	fs.handleExec = func(cmd string) (string, string, int) {
		switch cmd {
		case mgmtCmd:
			return linkExistsJSON(mgmtIface, true), "", 0
		case ifaceCmd:
			mu.Lock()
			idx := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if idx == 0 {
				// step 4 guard self-check: not yet live.
				return "", fmt.Sprintf(linkMissingStderrFmt, targetIface), 1
			}
			// step 8 post-apply check: now live.
			return linkExistsJSON(targetIface, true), "", 0
		default:
			t.Fatalf("unexpected ssh command: %q", cmd)
			return "", "", 1
		}
	}

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.port(t))
	t.Cleanup(restore)

	rc, err := pve.NewRoutedClient(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewRoutedClient: %v", err)
	}
	defer func() { _ = rc.Close() }()

	op := &NetworkBridgeEnsure{
		Client:           rc,
		Node:             rc.Node(),
		Iface:            targetIface,
		ManagementBridge: mgmtIface,
		Wanted:           map[string]string{"type": "bridge", "bridge_ports": "eth1"},
	}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"POST /api2/json/nodes/qa-pve-01/network",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
		// WaitForTask polls immediately and stops at the first poll that
		// reports the task stopped, so a task that is already stopped is
		// observed exactly once. (go-proxmox's Task.Wait, which it
		// replaced, pinged once up front and again in its loop: twice.)
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
	}
	if got := restScript.hitSequence(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}

	wantSSH := []string{mgmtCmd, ifaceCmd, mgmtCmd, ifaceCmd}
	if got := fs.cmdSequence(); !equalStringSlices(got, wantSSH) {
		t.Fatalf("SSH command sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}

// TestNetworkBridgeEnsure_Apply_Destroy_FullStack is the DESTROY-path
// mirror of the create test above: same real RoutedClient, same fake
// REST+SSH servers together, inverted exists/active expectations
// throughout (iface starts live, ends gone), and a DELETE against
// /nodes/{node}/network/{iface} in place of the create's POST.
func TestNetworkBridgeEnsure_Apply_Destroy_FullStack(t *testing.T) {
	const node = "qa-pve-01"
	const mgmtIface = "vmbr0"
	const targetIface = "vmbr1"

	upid := wellFormedNetworkUPID(node, targetIface)
	restScript := newNetworkBridgeRESTScript(t, node)
	restScript.mgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	restScript.ifaceFields = `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":"1"}` // still active pre-commit
	restScript.commitUPID = upid
	restSrv := restScript.server()
	defer restSrv.Close()

	fs := newFakeIntegrationSSHServer(t)
	mgmtCmd := fmt.Sprintf("ip -j link show dev '%s'", mgmtIface)
	ifaceCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	var ifaceCalls int
	var mu sync.Mutex
	fs.handleExec = func(cmd string) (string, string, int) {
		switch cmd {
		case mgmtCmd:
			return linkExistsJSON(mgmtIface, true), "", 0
		case ifaceCmd:
			mu.Lock()
			idx := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if idx == 0 {
				// step 4 guard self-check: still live pre-commit.
				return linkExistsJSON(targetIface, true), "", 0
			}
			// step 8 post-apply check: now gone.
			return "", fmt.Sprintf(linkMissingStderrFmt, targetIface), 1
		default:
			t.Fatalf("unexpected ssh command: %q", cmd)
			return "", "", 1
		}
	}

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.port(t))
	t.Cleanup(restore)

	rc, err := pve.NewRoutedClient(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewRoutedClient: %v", err)
	}
	defer func() { _ = rc.Close() }()

	op := &NetworkBridgeEnsure{
		Client:           rc,
		Node:             rc.Node(),
		Iface:            targetIface,
		ManagementBridge: mgmtIface,
		Wanted:           nil, // destroy
	}
	if err := op.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	wantREST := []string{
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"DELETE /api2/json/nodes/qa-pve-01/network/vmbr1",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr0",
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
		// WaitForTask polls immediately and stops at the first poll that
		// reports the task stopped, so a task that is already stopped is
		// observed exactly once. (go-proxmox's Task.Wait, which it
		// replaced, pinged once up front and again in its loop: twice.)
		"GET /api2/json/nodes/qa-pve-01/tasks/" + upid + "/status",
	}
	if got := restScript.hitSequence(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}

	wantSSH := []string{mgmtCmd, ifaceCmd, mgmtCmd, ifaceCmd}
	if got := fs.cmdSequence(); !equalStringSlices(got, wantSSH) {
		t.Fatalf("SSH command sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}
