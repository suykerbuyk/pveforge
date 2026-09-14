package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// sshTargetKeypair generates a real ed25519 keypair and returns both the
// sshexec.Keypair (for persisting into a fixture roster.Target) and the
// parsed ssh.PublicKey the fake SSH server needs to allow it.
func sshTargetKeypair(t *testing.T) (*sshexec.Keypair, ssh.PublicKey) {
	t.Helper()
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return kp, signer.PublicKey()
}

// bootstrappedTarget builds a roster.Target with both a working token and
// working, correctly-pinned SSH auth against fs, ready for a RoutedClient.
func bootstrappedTarget(t *testing.T, fs *fakeSSHServer, passphrase string) *roster.Target {
	t.Helper()
	kp, pub := sshTargetKeypair(t)
	fs.allowedPub = pub

	// Capture the fake server's real host key fingerprint the same way a
	// real bootstrap would, so PinnedHostKeyCallback has something
	// genuine to check against.
	var captured sshexec.CapturedHostKey
	c, err := sshexec.Dial(context.Background(), fs.addr, "root", kp.PrivateKeyPEM, sshexec.CaptureHostKeyCallback(&captured))
	if err != nil {
		t.Fatalf("dial to capture host key: %v", err)
	}
	defer c.Close()

	tokenArmored, err := roster.EncryptString([]byte("tok-secret-value"), passphrase)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	sshArmored, err := roster.EncryptString(kp.PrivateKeyPEM, passphrase)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	return &roster.Target{
		ID:   "qa-pve-01",
		Host: "127.0.0.1",
		Node: "qa-pve-01",
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

func withFakeSSHPort(t *testing.T, fs *fakeSSHServer) {
	t.Helper()
	orig := sshPort
	sshPort = fs.port(t)
	t.Cleanup(func() { sshPort = orig })
}

func TestRoutedClient_RootOnlyField_RoutesToSSH_NeverTouchesREST(t *testing.T) {
	fs := newFakeSSHServer(t)
	var receivedCmd string
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	}
	withFakeSSHPort(t, fs)

	restHit := false
	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		restHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer restSrv.Close()

	tg := bootstrappedTarget(t, fs, "roster-pass")
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}
	rest.baseURL = restSrv.URL // redirect REST calls to our fake server

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	if err := rc.SetVMConfigField(context.Background(), 100, "args", "-device foo"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if restHit {
		t.Fatal("a root-only field must never touch the REST endpoint")
	}
	if !strings.Contains(receivedCmd, "-device foo") {
		t.Fatalf("expected the ssh command to reference the value, got: %q", receivedCmd)
	}
	if rc.ssh == nil {
		t.Fatal("expected the ssh connection to have been established")
	}
}

func TestRoutedClient_NonRootOnlyField_UsesRESTOnly(t *testing.T) {
	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer restSrv.Close()

	armored, err := roster.EncryptString([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	tg := &roster.Target{
		ID:    "qa-pve-01",
		Host:  "qa-pve-01.example.com",
		Node:  "qa-pve-01",
		Token: &roster.TokenAuth{ID: "root@pam!pveforge", SecretEnc: armored},
	}
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}
	rest.baseURL = restSrv.URL

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	if err := rc.SetVMConfigField(context.Background(), 100, "description", "hello"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if rc.ssh != nil {
		t.Fatal("a non-root-only field that succeeds over REST must never dial SSH")
	}
}

func TestRoutedClient_UnregisteredRootOnlyField_FallsBackToSSH(t *testing.T) {
	fs := newFakeSSHServer(t)
	sshCalled := false
	fs.handleExec = func(cmd string) (string, string, int) {
		sshCalled = true
		return "", "", 0
	}
	withFakeSSHPort(t, fs)

	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`only root can set 'newfield' config`))
	}))
	defer restSrv.Close()

	tg := bootstrappedTarget(t, fs, "roster-pass")
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}
	rest.baseURL = restSrv.URL

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	if err := rc.SetVMConfigField(context.Background(), 100, "newfield", "v"); err != nil {
		t.Fatalf("expected the SSH fallback to succeed silently, got: %v", err)
	}
	if !sshCalled {
		t.Fatal("expected the SSH fallback to have been invoked")
	}
}

func TestRoutedClient_UnregisteredRootOnlyField_BothFail_ReturnsOriginalRESTError(t *testing.T) {
	const pveMessage = `only root can set 'newfield' config`
	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(pveMessage))
	}))
	defer restSrv.Close()

	armored, err := roster.EncryptString([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	// No SSH auth configured at all — the fallback must fail cleanly, and
	// the ORIGINAL REST error (carrying PVE's diagnostic text) must win.
	tg := &roster.Target{
		ID:    "qa-pve-01",
		Host:  "qa-pve-01.example.com",
		Node:  "qa-pve-01",
		Token: &roster.TokenAuth{ID: "root@pam!pveforge", SecretEnc: armored},
	}
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}
	rest.baseURL = restSrv.URL

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	err = rc.SetVMConfigField(context.Background(), 100, "newfield", "v")
	if err == nil {
		t.Fatal("expected an error when both REST and the SSH fallback fail")
	}
	if !strings.Contains(err.Error(), pveMessage) {
		t.Fatalf("expected the original REST error (with PVE's text) to be returned, got: %v", err)
	}
}

func TestRoutedClient_SetViaSSH_NoSSHAuthConfigured(t *testing.T) {
	armored, err := roster.EncryptString([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	tg := &roster.Target{
		ID:    "qa-pve-01",
		Host:  "qa-pve-01.example.com",
		Node:  "qa-pve-01",
		Token: &roster.TokenAuth{ID: "root@pam!pveforge", SecretEnc: armored},
	}
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	err = rc.SetVMConfigField(context.Background(), 100, "args", "v")
	if err == nil {
		t.Fatal("expected an error: args is root-only but the target has no ssh auth")
	}
	if !strings.Contains(err.Error(), "ssh auth") {
		t.Errorf("expected a clear error about missing ssh auth, got: %v", err)
	}
}

func TestRoutedClient_SetViaSSH_NoHostKeyFingerprint(t *testing.T) {
	armored, err := roster.EncryptString([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	sshArmored, err := roster.EncryptString([]byte("irrelevant"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	tg := &roster.Target{
		ID:    "qa-pve-01",
		Host:  "qa-pve-01.example.com",
		Node:  "qa-pve-01",
		Token: &roster.TokenAuth{ID: "root@pam!pveforge", SecretEnc: armored},
		SSH: &roster.SSHAuth{
			User:          "root",
			PublicKey:     "ssh-ed25519 AAAA...",
			PrivateKeyEnc: sshArmored,
			// HostKeyFingerprint deliberately blank.
		},
	}
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	err = rc.SetVMConfigField(context.Background(), 100, "args", "v")
	if err == nil {
		t.Fatal("expected an error: ssh auth present but no pinned fingerprint")
	}
	if !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("expected a clear error about the missing fingerprint, got: %v", err)
	}
}

func TestRoutedClient_Node(t *testing.T) {
	tg := &roster.Target{ID: "qa-pve-01", Host: "qa-pve-01.example.com", Node: "qa-pve-01"}
	rc := &RoutedClient{target: tg}
	if got := rc.Node(); got != "qa-pve-01" {
		t.Errorf("Node() = %q, want %q", got, "qa-pve-01")
	}
}

func TestRoutedClient_Close_NoopWhenSSHNeverDialed(t *testing.T) {
	rc := &RoutedClient{}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close should be a no-op when ssh was never dialed, got: %v", err)
	}
}

func TestRoutedClient_Close_ClosesSSHWhenDialed(t *testing.T) {
	fs := newFakeSSHServer(t)
	withFakeSSHPort(t, fs)

	tg := bootstrappedTarget(t, fs, "roster-pass")
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	if err := rc.SetVMConfigField(context.Background(), 100, "args", "v"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if rc.ssh == nil {
		t.Fatal("expected ssh to have been dialed")
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRoutedClient_RedialsAfterConnectionDrop guards against the defect
// where a cached c.ssh connection was reused unconditionally for the
// RoutedClient's whole lifetime, with no way to recover from a transient
// drop (network blip, NAT idle timeout, sshd ClientAliveInterval, a
// remote reboot): every later write would keep failing against the same
// known-dead connection forever. First call succeeds and caches a
// connection; the underlying connection is then closed out from under
// RoutedClient (simulating a drop); the next call must fail but discard
// the dead connection; the call after that must succeed by redialing.
func TestRoutedClient_RedialsAfterConnectionDrop(t *testing.T) {
	fs := newFakeSSHServer(t)
	withFakeSSHPort(t, fs)

	tg := bootstrappedTarget(t, fs, "roster-pass")
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	if err := rc.SetVMConfigField(context.Background(), 100, "args", "v1"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	cachedSSH := rc.ssh
	if cachedSSH == nil {
		t.Fatal("expected ssh to be cached after the first call")
	}

	// Simulate the connection going bad, as a network drop would.
	if err := cachedSSH.Close(); err != nil {
		t.Fatalf("Close (simulating a drop): %v", err)
	}

	// The call over the now-dead cached connection must fail...
	if err := rc.SetVMConfigField(context.Background(), 100, "args", "v2"); err == nil {
		t.Fatal("expected the call over a dead connection to fail")
	}
	// ...and the dead connection must be discarded, not kept around to
	// fail every future call the same way.
	if rc.ssh != nil {
		t.Fatal("expected the dead connection to be discarded after the failed call")
	}

	// The NEXT call must succeed by redialing — not repeat the same
	// stale-connection error forever.
	if err := rc.SetVMConfigField(context.Background(), 100, "args", "v3"); err != nil {
		t.Fatalf("call after redial should succeed, got: %v", err)
	}
	if rc.ssh == nil || rc.ssh == cachedSSH {
		t.Fatal("expected a fresh ssh connection after redial, not the stale one")
	}
}

// TestRoutedClient_RemoteCommandFailure_ReusesHealthyConnection is the
// other half of sshConnectionHealthy's contract, not covered by
// TestRoutedClient_RedialsAfterConnectionDrop: a normal, legitimate
// remote command failure (e.g. `qm set` exiting non-zero for a bad
// vmid/value) over a connection that is otherwise perfectly healthy must
// NOT cause the connection to be discarded and redialed. An
// implementation that discarded the connection on ANY error — defeating
// the whole point of the health-check distinction — would still pass
// every other test in this file; only this test catches that.
func TestRoutedClient_RemoteCommandFailure_ReusesHealthyConnection(t *testing.T) {
	fs := newFakeSSHServer(t)
	fs.handleExec = func(cmd string) (string, string, int) {
		if cmd == "true" {
			// sshConnectionHealthy's probe: the connection is fine.
			return "", "", 0
		}
		// The actual `qm set` command: fails on its own merits every
		// time, regardless of connection health.
		return "", "qm set: bad vmid", 1
	}
	withFakeSSHPort(t, fs)

	tg := bootstrappedTarget(t, fs, "roster-pass")
	rest, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	err = rc.SetVMConfigField(context.Background(), 100, "args", "v1")
	if err == nil {
		t.Fatal("expected the remote command failure to surface as an error")
	}
	if !strings.Contains(err.Error(), "bad vmid") {
		t.Fatalf("expected the remote stderr to be surfaced, got: %v", err)
	}
	cachedSSH := rc.ssh
	if cachedSSH == nil {
		t.Fatal("expected ssh to still be cached after a normal remote command failure")
	}

	// Second call: must reuse the SAME connection, not redial — the
	// connection itself is healthy, only the remote command failed.
	err = rc.SetVMConfigField(context.Background(), 100, "args", "v2")
	if err == nil {
		t.Fatal("expected the second call to fail the same way")
	}
	if rc.ssh != cachedSSH {
		t.Fatal("expected the healthy connection to be reused, not redialed, after a normal remote command failure")
	}
}

// TestRoutedClient_TypedReadForwarding exercises all 8 read-side
// pass-through methods, proving each one actually forwards to c.rest
// rather than being a dead/stubbed method — every one of them must reach
// the fake REST server and return the data it serves.
func TestRoutedClient_TypedReadForwarding(t *testing.T) {
	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/status":
			_, _ = w.Write([]byte(`{"data":{"uptime":100}}`))
		case "/nodes":
			_, _ = w.Write([]byte(`{"data":[{"node":"qa-pve-01"}]}`))
		case "/nodes/qa-pve-01/qemu/100/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"name":"web-01"}}`))
		case "/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[{"vmid":100}]}`))
		case "/nodes/qa-pve-01/storage/local/status":
			_, _ = w.Write([]byte(`{"data":{"type":"dir"}}`))
		case "/nodes/qa-pve-01/storage":
			_, _ = w.Write([]byte(`{"data":[{"storage":"local"}]}`))
		case "/nodes/qa-pve-01/storage/local/content":
			_, _ = w.Write([]byte(`{"data":[{"volid":"local:iso/x.iso"}]}`))
		case "/nodes/qa-pve-01/network/vmbr0":
			_, _ = w.Write([]byte(`{"data":{"cidr":"10.0.0.5/24"}}`))
		case "/nodes/qa-pve-01/network":
			_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer restSrv.Close()

	tg := &roster.Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
	}
	// Built directly via NewClient (BaseURLOverride), not
	// NewClientForTarget: the getters under test go through c.pc.Get,
	// which uses go-proxmox's own internal base URL set at construction
	// time — patching rest.baseURL after the fact (as other tests in this
	// file do, for the raw-HTTP write path only) would not reach it.
	rest := testClient(t, restSrv)

	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	ctx := context.Background()

	if node, err := rc.GetNode(ctx, "qa-pve-01"); err != nil || node.Uptime != 100 {
		t.Errorf("GetNode: node=%+v err=%v", node, err)
	}
	if nodes, err := rc.GetNodes(ctx); err != nil || len(nodes) != 1 {
		t.Errorf("GetNodes: nodes=%+v err=%v", nodes, err)
	}
	if vm, err := rc.GetVM(ctx, "qa-pve-01", 100); err != nil || vm.Status != "running" {
		t.Errorf("GetVM: vm=%+v err=%v", vm, err)
	}
	if vms, err := rc.GetVMs(ctx, "qa-pve-01"); err != nil || len(vms) != 1 {
		t.Errorf("GetVMs: vms=%+v err=%v", vms, err)
	}
	if storage, err := rc.GetStorage(ctx, "qa-pve-01", "local"); err != nil || storage.Type != "dir" {
		t.Errorf("GetStorage: storage=%+v err=%v", storage, err)
	}
	if storages, err := rc.GetStorages(ctx, "qa-pve-01"); err != nil || len(storages) != 1 {
		t.Errorf("GetStorages: storages=%+v err=%v", storages, err)
	}
	if vols, err := rc.GetStorageVolumes(ctx, "qa-pve-01", "local"); err != nil || len(vols) != 1 {
		t.Errorf("GetStorageVolumes: vols=%+v err=%v", vols, err)
	}
	if nw, err := rc.GetNetworkInterface(ctx, "qa-pve-01", "vmbr0"); err != nil || nw.CIDR != "10.0.0.5/24" {
		t.Errorf("GetNetworkInterface: nw=%+v err=%v", nw, err)
	}
	if networks, err := rc.GetNetworkInterfaces(ctx, "qa-pve-01"); err != nil || len(networks) != 1 {
		t.Errorf("GetNetworkInterfaces: networks=%+v err=%v", networks, err)
	}
}
