package pvefake_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// pveforge-converge-ssh-test-fakes: the modes internal/sshexec's own fake
// used to carry, now pvefake's, each pinned here where it lives. The tests
// drive a raw x/crypto/ssh client, so pvefake's tests depend on no
// pveforge package either.

var stdinPayload = []byte("PVEFORGE-CALLER-STDIN-MUST-NOT-BE-SENT\n")

// dialRaw starts s (after allowing a fresh key) and returns an x/crypto/ssh
// client for it.
func dialRaw(t *testing.T, s *pvefake.SSHServer) *ssh.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s.AllowKey(signer.PublicKey())
	s.Start()
	c, err := ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // a loopback test fake
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSSHServer_RecordsStdinWhenSent (moved from internal/sshexec's
// TestFakeServer_RecordsStdinWhenSent) is the positive control for
// RecordStdin: a session that DOES send stdin is recorded byte for byte.
// Without it sshexec's TestRun_NeverForwardsCallerStdin would be vacuous:
// a server that never read stdin would also record nothing.
func TestSSHServer_RecordsStdinWhenSent(t *testing.T) {
	s := pvefake.NewSSHServer(t)
	s.RecordStdin()
	c := dialRaw(t, s)
	session, err := c.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	session.Stdin = bytes.NewReader(stdinPayload)
	if err := session.Run("true"); err != nil {
		t.Fatalf("session.Run: %v", err)
	}
	records := s.StdinRecords()
	if len(records) != 1 {
		t.Fatalf("server recorded %d sessions' stdin, want 1", len(records))
	}
	if records[0].Truncated {
		t.Fatalf("the drain hit DrainJoinTimeout (%s): this record is not evidence of anything", pvefake.DrainJoinTimeout)
	}
	if !bytes.Equal(records[0].Data, stdinPayload) {
		t.Fatalf("server recorded %d bytes (%q), want the %d bytes the session sent (%q)",
			len(records[0].Data), records[0].Data, len(stdinPayload), stdinPayload)
	}
}

// TestSSHServer_BoundedDrainRecordsTruncation (moved from internal/sshexec's
// TestFakeServer_BoundedDrainRecordsTruncation): a session whose stdin
// never reaches EOF makes the server come back after DrainJoinTimeout, not
// hang, and marks the record Truncated, never complete.
func TestSSHServer_BoundedDrainRecordsTruncation(t *testing.T) {
	orig := pvefake.DrainJoinTimeout
	pvefake.DrainJoinTimeout = 200 * time.Millisecond
	t.Cleanup(func() { pvefake.DrainJoinTimeout = orig })

	s := pvefake.NewSSHServer(t)
	s.RecordStdin()
	c := dialRaw(t, s)
	session, err := c.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	// StdinPipe, not session.Stdin: with an explicit pipe the client never
	// blocks on a copy of its own. The server is the only side under test.
	w, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := session.Start("true"); err != nil {
		t.Fatalf("session.Start: %v", err)
	}
	if _, err := w.Write([]byte("never-closed")); err != nil {
		t.Fatalf("write to stdin pipe: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the server never replied: the drain join is unbounded")
	}
	records := s.StdinRecords()
	if len(records) != 1 || !records[0].Truncated {
		t.Fatalf("records = %+v; want one, marked Truncated", records)
	}
}

// TestSSHServer_StallAnswersNoChannel: in Stall mode the handshake
// completes (the dial succeeds) but no session is ever opened.
func TestSSHServer_StallAnswersNoChannel(t *testing.T) {
	s := pvefake.NewSSHServer(t)
	s.Stall()
	c := dialRaw(t, s)
	opened := make(chan error, 1)
	go func() {
		_, err := c.NewSession()
		opened <- err
	}()
	select {
	case err := <-opened:
		t.Fatalf("NewSession returned (%v) on a stalled server", err)
	case <-time.After(300 * time.Millisecond):
	}
	if s.Connections() != 1 {
		t.Errorf("Connections = %d, want 1: the handshake must complete", s.Connections())
	}
}

// TestSSHServer_AsyncExecRecordsSignalThenClose: in AsyncExec mode a signal
// sent while the command runs is read and recorded, then the session's
// close, in that order.
func TestSSHServer_AsyncExecRecordsSignalThenClose(t *testing.T) {
	s := pvefake.NewSSHServer(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.HandleExec(func(string) (string, string, int) { <-release; return "", "", 0 })
	s.AsyncExec()
	c := dialRaw(t, s)
	session, err := c.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := session.Start("hang"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := session.Signal(ssh.SIGKILL); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	_ = session.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(s.Events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got, want := s.Events(), []string{"signal:KILL", "close"}; !slices.Equal(got, want) {
		t.Fatalf("Events = %q, want %q", got, want)
	}
	if got := s.Commands(); !slices.Equal(got, []string{"hang"}) {
		t.Errorf("Commands = %q, want the one command", got)
	}
}

// TestPVEFake_ImportsNoPveforgePackage (the Chair's ruling): pvefake's
// non-test files import only the standard library and x/crypto/ssh.
// internal/sshexec's and internal/pve's in-package tests import pvefake, so
// pvefake importing any pveforge package could close an import cycle.
func TestPVEFake_ImportsNoPveforgePackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range parsed.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if p == "golang.org/x/crypto/ssh" || !strings.Contains(first, ".") {
				continue
			}
			t.Errorf("%s imports %q: pvefake may import only the standard library and golang.org/x/crypto/ssh", f, p)
		}
	}
	if checked < 2 {
		t.Fatalf("checked %d non-test files; pvefake has at least ssh.go and rest.go", checked)
	}
}
