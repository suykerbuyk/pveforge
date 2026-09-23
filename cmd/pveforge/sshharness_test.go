package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// newTestRosterWithSSHTarget is newTestRosterWithTLSTarget for a command
// whose success path crosses SSH: the one target "qa-pve-01" reaches restSrv
// over REST and fs over SSH, with a working key and fs's host key pinned,
// and every RoutedClient in this process dials fs's port until t finishes.
//
// It starts fs, so configure fs (HandleExec) BEFORE calling it. The SSH
// fake is internal/pvefake's, shared with internal/idempotent's full-stack
// tests — never a copy.
func newTestRosterWithSSHTarget(t *testing.T, restSrv *httptest.Server, fs *pvefake.SSHServer) string {
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

	// Pin the host key the way bootstrap does: capture it on a first dial.
	var captured sshexec.CapturedHostKey
	c, err := sshexec.Dial(context.Background(), fs.Addr(), "root", kp.PrivateKeyPEM, sshexec.CaptureHostKeyCallback(&captured))
	if err != nil {
		t.Fatalf("dial to capture host key: %v", err)
	}
	_ = c.Close()

	sshArmored, err := fixtureEncrypt(kp.PrivateKeyPEM, rosterPassphrase)
	if err != nil {
		t.Fatalf("fixtureEncrypt ssh key: %v", err)
	}
	sshBlock := fmt.Sprintf(`
  [targets.ssh]
  user = "root"
  public_key = %q
  host_key_fingerprint = %q
  private_key_enc = '''
%s'''
`, strings.TrimSpace(kp.AuthorizedKeyLine), captured.Fingerprint(), sshArmored)

	path := writeTestRoster(t, restSrv, "qa-pve-01", "qa-pve-01", sshBlock)
	t.Cleanup(pve.SetSSHPortForIntegrationTests(fs.Port(t)))
	return path
}

// runRootArgs runs the whole CLI, root command and runRoot included, and
// returns the exit code, stdout and stderr.
func runRootArgs(args ...string) (code int, stdout, stderr string) {
	root := newRootCmd()
	root.SetArgs(args)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	code = runRoot(root, &errOut)
	return code, out.String(), errOut.String()
}
