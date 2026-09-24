package sshexec

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// stdinPayload is the caller-stdin fixture both tests below use.
//
// Its exact CONTENT is asserted at both ends — the server must record none
// of it, and the caller's own stdin must still hold all of it — which is
// what makes "0 bytes forwarded" distinguishable from "nothing was ever
// there to forward". requirePayloadUsable pins the one property that
// reasoning depends on, rather than leaving it to a comment: a payload
// that had silently become empty would make every such assertion pass for
// nothing. No length literal appears in the string itself, so editing the
// payload cannot make a name or a comment wrong.
var stdinPayload = []byte("PVEFORGE-CALLER-STDIN-MUST-NOT-BE-SENT\n")

// requirePayloadUsable fails the calling test unless the fixture actually
// carries bytes to forward.
func requirePayloadUsable(t *testing.T) {
	t.Helper()
	if len(stdinPayload) == 0 {
		t.Fatal("stdinPayload is empty, so every assertion about forwarding it is vacuous")
	}
}

// requireComplete fails unless the drain reached EOF. A truncated record
// may be short, so asserting "0 bytes" on one would be asserting that the
// observer gave up — see pvefake.StdinRecord.Truncated.
func requireComplete(t *testing.T, label string, r pvefake.StdinRecord) {
	t.Helper()
	if r.Truncated {
		t.Fatalf("%s: the server's stdin drain hit pvefake.DrainJoinTimeout (%s) before EOF, "+
			"so this record is not evidence of anything; it holds %d byte(s) so far",
			label, pvefake.DrainJoinTimeout, len(r.Data))
	}
}

// replaceOSStdin points os.Stdin at a pipe holding payload and closes the
// write end, so a reader sees payload followed by EOF. It restores the
// real os.Stdin via t.Cleanup and returns the read end so a test can check
// what is LEFT on it afterwards.
//
// Safe despite mutating a process-global: this module contains no
// t.Parallel call in any package, so no two tests in this binary run
// concurrently.
func replaceOSStdin(t *testing.T, payload []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write payload to pipe: %v", err)
	}
	// Closing the write end matters for the MUTANT, not for correct code:
	// with session.Stdin = os.Stdin, x/crypto/ssh copies the reader to the
	// channel and only then CloseWrite()s, and Session.Wait blocks on that
	// copy. An unclosed pipe would make the mutant HANG to the package
	// timeout instead of failing; closed, it fails in milliseconds.
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
	return r
}

// dialFake dials fs as root over a freshly generated, server-allowed
// keypair. It is the same entry point production uses.
func dialFake(t *testing.T, fs *pvefake.SSHServer) *Client {
	t.Helper()
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)
	fs.RecordStdin()
	fs.Start()

	var captured CapturedHostKey
	c, err := Dial(context.Background(), fs.Addr(), "root", kp.PrivateKeyPEM, CaptureHostKeyCallback(&captured))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestRun_NeverForwardsCallerStdin pins the transport-stdin-isolation
// property: sshexec.Client.Run opens a session that sets Stdout and Stderr
// and never Stdin, so no byte of the CALLER's stdin is ever handed to a
// remote command.
//
// It drives THREE sequential Run calls, not one, deliberately. The bug
// class this guards against is "an iteration over N items performs 1 and
// reports success": a defect that drains the caller's stdin into the first
// command leaves calls 2..N looking correct, so a single-call test would
// see the isolated-looking tail and pass.
//
// The assertion has two halves, and each is a separate observer of the
// same property:
//
//  1. The SERVER's record — three sessions, each having received exactly 0
//     bytes on its stdin. The count is asserted as well as the contents,
//     which is what stops this test from passing vacuously: a fake server
//     that never read stdin at all would record 0 sessions, not 3, and
//     this test would fail. (Observed: it DID fail that way, by
//     construction, before fakeServer.handleSession learned to drain.)
//  2. The CALLER's stdin afterwards — still holding every byte. A defect
//     that forwarded stdin would necessarily have consumed it.
//
// The mutation this exists to kill is `session.Stdin = os.Stdin` in
// Client.Run.
func TestRun_NeverForwardsCallerStdin(t *testing.T) {
	const runs = 3

	requirePayloadUsable(t)
	stdin := replaceOSStdin(t, stdinPayload)

	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) { return "ok\n", "", 0 })
	c := dialFake(t, fs)

	for i := range runs {
		res, err := c.Run(context.Background(), "true")
		if err != nil {
			t.Fatalf("Run #%d: %v", i+1, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("Run #%d: exit code %d, want 0", i+1, res.ExitCode)
		}
	}

	records := fs.StdinRecords()
	if len(records) != runs {
		t.Fatalf("server recorded %d sessions' stdin, want %d — a server that never reads stdin "+
			"records nothing and would make this test vacuous", len(records), runs)
	}
	for i, got := range records {
		requireComplete(t, fmt.Sprintf("Run #%d", i+1), got)
		if len(got.Data) != 0 {
			t.Errorf("Run #%d forwarded %d bytes of the caller's stdin (%q), want 0 bytes",
				i+1, len(got.Data), got.Data)
		}
	}

	// Second observer: the caller's own stdin must be untouched. Read it
	// to EOF and require every byte back.
	left, err := io.ReadAll(stdin)
	if err != nil {
		t.Fatalf("read back caller stdin: %v", err)
	}
	if !bytes.Equal(left, stdinPayload) {
		t.Errorf("caller stdin after %d Run calls: got %d bytes (%q), want the original %d bytes (%q)",
			runs, len(left), left, len(stdinPayload), stdinPayload)
	}
}
