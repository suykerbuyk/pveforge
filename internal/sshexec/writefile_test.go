package sshexec

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

var base64ArgRe = regexp.MustCompile(`printf '%s' '([^']*)' \| base64 -d`)

func TestWriteFile_Success(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)

	var receivedCmd string
	fs.HandleExec(func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	})
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	content := []byte("#!/bin/sh\necho hello\n")
	if err := client.WriteFile(ctx, "/var/lib/vz/snippets/test.sh", content, "0755"); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := base64ArgRe.FindStringSubmatch(receivedCmd)
	if m == nil {
		t.Fatalf("expected a base64-encoded payload in the remote command, got: %s", receivedCmd)
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("decode captured base64 payload: %v", err)
	}
	if string(decoded) != string(content) {
		t.Errorf("decoded content = %q, want %q", decoded, content)
	}

	if !strings.Contains(receivedCmd, "mkdir -p '/var/lib/vz/snippets'") {
		t.Errorf("expected the parent directory to be created, got: %s", receivedCmd)
	}
	if !strings.Contains(receivedCmd, "chmod '0755'") {
		t.Errorf("expected the requested mode to be applied, got: %s", receivedCmd)
	}
	if !strings.Contains(receivedCmd, "mv '/var/lib/vz/snippets/test.sh.pveforge-tmp' '/var/lib/vz/snippets/test.sh'") {
		t.Errorf("expected an atomic rename into place, got: %s", receivedCmd)
	}
}

func TestWriteFile_ContentWithSingleQuotesAndBackslashes(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)

	var receivedCmd string
	fs.HandleExec(func(cmd string) (string, string, int) {
		receivedCmd = cmd
		return "", "", 0
	})
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Content deliberately full of shell/printf-hostile characters: single
	// quotes (would break naive ShellQuote-only embedding) and backslash
	// escape sequences (would be misinterpreted by some shells' echo
	// builtin, which is exactly why WriteFile uses printf instead).
	content := []byte(`it's a \n test \t with 'quotes' and \\ backslashes`)
	if err := client.WriteFile(ctx, "/tmp/x", content, "0644"); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := base64ArgRe.FindStringSubmatch(receivedCmd)
	if m == nil {
		t.Fatalf("expected a base64-encoded payload in the remote command, got: %s", receivedCmd)
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("decode captured base64 payload: %v", err)
	}
	if string(decoded) != string(content) {
		t.Errorf("decoded content = %q, want %q", decoded, content)
	}
}

func TestWriteFile_RemoteScriptFailure(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)
	fs.HandleExec(func(cmd string) (string, string, int) {
		return "", "permission denied\n", 1
	})
	fs.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	err = client.WriteFile(ctx, "/tmp/x", []byte("content"), "0644")
	if err == nil {
		t.Fatal("expected an error when the remote script exits non-zero")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected the error to surface remote stderr, got: %v", err)
	}
}

func TestWriteFile_RequiresRemotePath(t *testing.T) {
	c := &Client{}
	if err := c.WriteFile(context.Background(), "", []byte("x"), "0644"); err == nil {
		t.Fatal("expected an error for an empty remote path")
	}
}

func TestWriteFile_RequiresMode(t *testing.T) {
	c := &Client{}
	if err := c.WriteFile(context.Background(), "/tmp/x", []byte("x"), ""); err == nil {
		t.Fatal("expected an error for an empty mode")
	}
}
