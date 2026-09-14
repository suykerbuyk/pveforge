package sshexec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestInstallPubkeyViaPassword_AppendsAndCapturesHostKey(t *testing.T) {
	fs := newFakeServer(t)
	fs.allowPassword("correct-horse")

	var receivedCmd string
	authorizedKeys := "" // simulates the remote file's current contents
	fs.handleExec = func(cmd string) (string, string, int) {
		receivedCmd = cmd
		if strings.Contains(authorizedKeys, "ssh-ed25519") {
			return "present\n", "", 0
		}
		authorizedKeys += "ssh-ed25519 AAAAtest testkey\n"
		return "added\n", "", 0
	}
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := InstallPubkeyViaPassword(ctx, fs.addr, "root", "correct-horse", "ssh-ed25519 AAAAtest testkey")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword: %v", err)
	}
	if res.AlreadyPresent {
		t.Fatal("expected AlreadyPresent=false on first install")
	}
	if res.HostKeyFingerprint == "" {
		t.Fatal("expected a captured host key fingerprint")
	}
	if !strings.Contains(receivedCmd, "ssh-ed25519 AAAAtest testkey") {
		t.Fatalf("remote script did not reference the pubkey line: %s", receivedCmd)
	}

	// Second call: idempotent no-op.
	res2, err := InstallPubkeyViaPassword(ctx, fs.addr, "root", "correct-horse", "ssh-ed25519 AAAAtest testkey")
	if err != nil {
		t.Fatalf("InstallPubkeyViaPassword (second): %v", err)
	}
	if !res2.AlreadyPresent {
		t.Fatal("expected AlreadyPresent=true on second install")
	}
	if res2.HostKeyFingerprint != res.HostKeyFingerprint {
		t.Fatalf("host key fingerprint changed across calls to the same server: %q vs %q", res.HostKeyFingerprint, res2.HostKeyFingerprint)
	}
}

func TestInstallPubkeyViaPassword_WrongPasswordRejected(t *testing.T) {
	fs := newFakeServer(t)
	fs.allowPassword("correct-horse")
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := InstallPubkeyViaPassword(ctx, fs.addr, "root", "wrong-password", "ssh-ed25519 AAAAtest testkey")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestInstallPubkeyViaPassword_RemoteScriptFailure(t *testing.T) {
	fs := newFakeServer(t)
	fs.allowPassword("correct-horse")
	fs.handleExec = func(cmd string) (string, string, int) {
		return "", "permission denied\n", 1
	}
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := InstallPubkeyViaPassword(ctx, fs.addr, "root", "correct-horse", "ssh-ed25519 AAAAtest testkey")
	if err == nil {
		t.Fatal("expected error when the remote script exits non-zero")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error should surface remote stderr, got: %v", err)
	}
}
