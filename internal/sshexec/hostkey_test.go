package sshexec

import (
	"context"
	"testing"
	"time"
)

func TestPinnedHostKeyCallback_AcceptsMatchingKey(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First connect, capturing the host key trust-on-first-use.
	var captured CapturedHostKey
	c1, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, CaptureHostKeyCallback(&captured))
	if err != nil {
		t.Fatalf("first dial (capture): %v", err)
	}
	c1.Close()

	fp := captured.Fingerprint()
	if fp == "" {
		t.Fatal("expected a non-empty captured fingerprint")
	}

	// Second connect, pinned against the captured fingerprint: must succeed.
	cb, err := PinnedHostKeyCallback(fp)
	if err != nil {
		t.Fatalf("PinnedHostKeyCallback: %v", err)
	}
	c2, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, cb)
	if err != nil {
		t.Fatalf("second dial (pinned, matching): %v", err)
	}
	c2.Close()
}

func TestPinnedHostKeyCallback_RejectsMismatchedKey(t *testing.T) {
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.Start(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cb, err := PinnedHostKeyCallback("SHA256:not-the-real-fingerprint-at-all")
	if err != nil {
		t.Fatalf("PinnedHostKeyCallback: %v", err)
	}
	_, err = Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, cb)
	if err == nil {
		t.Fatal("expected a host key mismatch error")
	}
}

func TestPinnedHostKeyCallback_EmptyFingerprintRejected(t *testing.T) {
	if _, err := PinnedHostKeyCallback(""); err == nil {
		t.Fatal("expected error for empty fingerprint")
	}
}
