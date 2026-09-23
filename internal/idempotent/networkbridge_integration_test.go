package idempotent

import (
	"context"
	"fmt"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
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
// newFakeSSHServer/testClient, all unexported). The fake SSH server and the
// scripted REST server come from internal/pvefake, shared with
// cmd/pveforge's runRoot tests of the same commands; the rest is built from
// pve's and sshexec's EXPORTED surface only:
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

// bootstrappedIntegrationTarget builds a roster.Target with real,
// working token and SSH auth against restSrv/fs — mirroring
// internal/pve's own routed_test.go bootstrappedTarget, rebuilt here from
// exported roster/sshexec API only (see this file's own top-of-file doc
// comment on why it can't just call pve's private copy).
func bootstrappedIntegrationTarget(t *testing.T, restSrv *httptest.Server, fs *pvefake.SSHServer, passphrase string) *roster.Target {
	t.Helper()

	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	fs.AllowKey(signer.PublicKey())
	fs.Start()

	var captured sshexec.CapturedHostKey
	c, err := sshexec.Dial(context.Background(), fs.Addr(), "root", kp.PrivateKeyPEM, sshexec.CaptureHostKeyCallback(&captured))
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

	upid := pvefake.NetworkUPID(node, targetIface)
	restScript := pvefake.NewBridgeREST(t, node)
	restScript.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	restScript.IfaceResponses = []string{
		pvefake.IfaceAbsent, // pre-stage read: the bridge does not exist yet
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}`, // guard: staged, no "active": not yet committed
	}
	restScript.CommitUPID = upid
	restSrv := restScript.Server()
	defer restSrv.Close()

	fs := pvefake.NewSSHServer(t)
	mgmtCmd := fmt.Sprintf("ip -j link show dev '%s'", mgmtIface)
	ifaceCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	var ifaceCalls int
	var mu sync.Mutex
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case mgmtCmd:
			return pvefake.LinkJSON(mgmtIface, true), "", 0
		case ifaceCmd:
			mu.Lock()
			idx := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if idx == 0 {
				// step 4 guard self-check: not yet live.
				return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, targetIface), 1
			}
			// step 8 post-apply check: now live.
			return pvefake.LinkJSON(targetIface, true), "", 0
		default:
			t.Errorf("unexpected ssh command: %q", cmd) // not Fatalf: this runs on the fake server's goroutine
			return "", "unexpected ssh command", 127
		}
	})

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.Port(t))
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
		"GET /api2/json/nodes/qa-pve-01/network/vmbr1", // pre-stage read: absent
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
	wantWrites := []string{
		"POST /api2/json/nodes/qa-pve-01/network bridge_ports=eth1&iface=vmbr1&type=bridge",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := restScript.Hits(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	if got := restScript.Writes(); !equalStringSlices(got, wantWrites) {
		t.Fatalf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}

	wantSSH := []string{mgmtCmd, ifaceCmd, mgmtCmd, ifaceCmd}
	if got := fs.Commands(); !equalStringSlices(got, wantSSH) {
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

	upid := pvefake.NetworkUPID(node, targetIface)
	restScript := pvefake.NewBridgeREST(t, node)
	restScript.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	restScript.IfaceFields = `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":"1"}` // still active pre-commit
	restScript.CommitUPID = upid
	restSrv := restScript.Server()
	defer restSrv.Close()

	fs := pvefake.NewSSHServer(t)
	mgmtCmd := fmt.Sprintf("ip -j link show dev '%s'", mgmtIface)
	ifaceCmd := fmt.Sprintf("ip -j link show dev '%s'", targetIface)
	var ifaceCalls int
	var mu sync.Mutex
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case mgmtCmd:
			return pvefake.LinkJSON(mgmtIface, true), "", 0
		case ifaceCmd:
			mu.Lock()
			idx := ifaceCalls
			ifaceCalls++
			mu.Unlock()
			if idx == 0 {
				// step 4 guard self-check: still live pre-commit.
				return pvefake.LinkJSON(targetIface, true), "", 0
			}
			// step 8 post-apply check: now gone.
			return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, targetIface), 1
		default:
			t.Errorf("unexpected ssh command: %q", cmd) // not Fatalf: this runs on the fake server's goroutine
			return "", "unexpected ssh command", 127
		}
	})

	tg := bootstrappedIntegrationTarget(t, restSrv, fs, "roster-pass")
	restore := pve.SetSSHPortForIntegrationTests(fs.Port(t))
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
	wantWrites := []string{
		"DELETE /api2/json/nodes/qa-pve-01/network/vmbr1",
		"PUT /api2/json/nodes/qa-pve-01/network",
	}
	if got := restScript.Hits(); !equalStringSlices(got, wantREST) {
		t.Fatalf("REST hit sequence:\n got:  %v\n want: %v", got, wantREST)
	}
	if got := restScript.Writes(); !equalStringSlices(got, wantWrites) {
		t.Fatalf("REST writes:\n got:  %q\n want: %q", got, wantWrites)
	}

	wantSSH := []string{mgmtCmd, ifaceCmd, mgmtCmd, ifaceCmd}
	if got := fs.Commands(); !equalStringSlices(got, wantSSH) {
		t.Fatalf("SSH command sequence:\n got:  %v\n want: %v", got, wantSSH)
	}
}
