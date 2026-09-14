package sshexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostKeyCaptureOnly returns a HostKeyCallback that accepts anything —
// used in tests exercising Dial/Run behavior where host-key pinning itself
// isn't under test (that's hostkey_test.go's job).
func acceptAnyHostKey() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey() //nolint:gosec // test-only, not reachable from production code paths
}

func TestDial_WithKey_RunCapturesStdoutStderrExit(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.handleExec = func(cmd string) (string, string, int) {
		if cmd == "fail-me" {
			return "partial-out", "boom\n", 3
		}
		return "hello stdout\n", "hello stderr\n", 0
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	res, err := client.Run(ctx, "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != "hello stdout\n" || res.Stderr != "hello stderr\n" || res.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}

	res2, err := client.Run(ctx, "fail-me")
	if err != nil {
		t.Fatalf("Run (fail-me): %v", err)
	}
	if res2.ExitCode != 3 || res2.Stderr != "boom\n" {
		t.Fatalf("unexpected non-zero-exit result: %+v", res2)
	}
}

func TestDial_WrongKeyRejected(t *testing.T) {
	fs := newFakeServer(t)
	_, allowedPub := clientKeypair(t)
	fs.allowPublicKey(allowedPub)

	otherKp, _ := clientKeypair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Dial(ctx, fs.addr, "root", otherKp.PrivateKeyPEM, acceptAnyHostKey())
	if err == nil {
		t.Fatal("expected error connecting with an unauthorized key")
	}
}

func TestClient_Run_ContextCancellation(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	fs.handleExec = func(cmd string) (string, string, int) {
		<-block
		return "", "", 0
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	client, err := Dial(dialCtx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	runCtx, runCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer runCancel()

	_, err = client.Run(runCtx, "sleep-forever")
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "context") {
		t.Fatalf("expected a context-cancellation error, got: %v", err)
	}
}
