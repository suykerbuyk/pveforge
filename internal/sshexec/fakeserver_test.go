package sshexec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeServer is a minimal in-process SSH server for testing sshexec's
// client behavior without any real network/PVE-host access, per the
// project's test strategy for this package.
type fakeServer struct {
	addr     string
	hostKey  ssh.Signer
	password string          // "" disables password auth
	authKeys map[string]bool // marshaled-pubkey -> allowed, "" disables pubkey auth
	listener net.Listener

	// handleExec is invoked for every "exec" request accepted by the
	// server; it returns (stdout, stderr, exitStatus).
	handleExec func(cmd string) (string, string, int)

	// stdinSeen holds one entry per session this server has finished
	// handling, recording what that session received on its STDIN. It
	// exists so a test can assert what the client actually forwarded
	// rather than inferring it from the client's own source — see
	// stdinisolation_test.go.
	//
	// stdinMu guards it, and guards nothing else. Every other field on
	// fakeServer is written by the test goroutine before Start and never
	// again (see newFakeServer's doc comment for why that ordering is
	// load-bearing), whereas stdinSeen is written from each accepted
	// session's own goroutine while the test goroutine reads it.
	stdinMu   sync.Mutex
	stdinSeen []stdinRecord

	// stall, when set before Start, makes the server complete the
	// handshake and then answer no channel request until it is closed: a
	// peer that stopped responding after the connection was made.
	stall chan struct{}

	// asyncExec, when set before Start, runs handleExec beside the
	// session's request loop instead of inline, so requests the client
	// sends while a command runs (a "signal") are read, and recorded in
	// events with the session's close ("signal:KILL", then "close").
	asyncExec bool
	eventsMu  sync.Mutex
	events    []string
}

func (fs *fakeServer) event(e string) {
	fs.eventsMu.Lock()
	defer fs.eventsMu.Unlock()
	fs.events = append(fs.events, e)
}

func (fs *fakeServer) eventLog() []string {
	fs.eventsMu.Lock()
	defer fs.eventsMu.Unlock()
	return append([]string(nil), fs.events...)
}

// drainJoinTimeout bounds how long handleSession waits for a session's
// stdin to reach EOF before it gives up, records what arrived and replies
// anyway.
//
// It races an in-process EOF on a loopback SSH channel, which for every
// session this package opens arrives in microseconds — x/crypto/ssh
// CloseWrite()s as soon as the session's Stdin source is exhausted, and
// for a nil Stdin that is immediate. Five seconds is roughly six orders of
// magnitude of headroom, chosen so that expiring means "the client is not
// closing stdin", never "the machine was busy under -race".
//
// A var, not a const, only so TestFakeServer_BoundedDrainRecordsTruncation
// can lower it to prove the bound fires; it lives in a _test.go file, so
// there is no production surface to guard.
var drainJoinTimeout = 5 * time.Second

// stdinRecord is one session's stdin observation.
type stdinRecord struct {
	// data is every byte that arrived on the session's stdin.
	data []byte
	// truncated reports that the drain did NOT reach EOF within
	// drainJoinTimeout, so data may be short.
	//
	// This field is the whole reason the bound is safe to add. A bound
	// that silently recorded a partial read would convert a hang into a
	// quiet "0 bytes received", and the isolation assertion would then
	// pass for exactly the wrong reason — a check that reports success
	// because its observer gave up. Every assertion on a record must
	// therefore reject a truncated one.
	truncated bool
}

// recordStdin records one finished session's stdin observation.
func (fs *fakeServer) recordStdin(r stdinRecord) {
	fs.stdinMu.Lock()
	defer fs.stdinMu.Unlock()
	fs.stdinSeen = append(fs.stdinSeen, r)
}

// stdinRecords returns one entry per session the server has finished
// handling, in completion order. A session appears here only once its
// stdin has reached EOF or drainJoinTimeout has expired, so a caller that
// has observed Run return can read these without racing the drain — see
// handleSession.
func (fs *fakeServer) stdinRecords() []stdinRecord {
	fs.stdinMu.Lock()
	defer fs.stdinMu.Unlock()
	out := make([]stdinRecord, len(fs.stdinSeen))
	copy(out, fs.stdinSeen)
	return out
}

// newFakeServer constructs the fake server and binds its listening port,
// but does NOT start accepting connections yet — call Start() once the
// test has finished configuring it (allowPassword/allowPublicKey/
// handleExec). Starting the accept loop here, before the caller
// configures the struct, was a genuine data race: a connection accepted
// in that window could read fs.password/fs.authKeys concurrently with the
// test goroutine's write to them (caught by `go test -race`).
func newFakeServer(t *testing.T) *fakeServer {
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

	fs := &fakeServer{
		addr:     ln.Addr().String(),
		hostKey:  signer,
		authKeys: map[string]bool{},
		handleExec: func(cmd string) (string, string, int) {
			return "", "", 0
		},
		listener: ln,
	}
	return fs
}

// Start begins accepting connections. Call it only after the test has
// finished configuring the server (allowPassword/allowPublicKey/setting
// handleExec) — see newFakeServer's doc comment for why the ordering
// matters.
func (fs *fakeServer) Start(t *testing.T) {
	t.Helper()
	go fs.serve(t, fs.listener)
}

// allowPassword enables password auth accepting exactly this password.
func (fs *fakeServer) allowPassword(password string) { fs.password = password }

// allowPublicKey enables pubkey auth accepting exactly this key.
func (fs *fakeServer) allowPublicKey(pub ssh.PublicKey) {
	fs.authKeys[string(pub.Marshal())] = true
}

func (fs *fakeServer) serve(t *testing.T, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed, test is done
		}
		go fs.handleConn(t, conn)
	}
}

func (fs *fakeServer) handleConn(t *testing.T, conn net.Conn) {
	cfg := &ssh.ServerConfig{}
	if fs.password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == fs.password {
				return nil, nil
			}
			return nil, fmtErrAuth
		}
	}
	cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if fs.authKeys[string(key.Marshal())] {
			return nil, nil
		}
		return nil, fmtErrAuth
	}
	cfg.AddHostKey(fs.hostKey)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return // expected for auth-failure test cases
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)
	if fs.stall != nil {
		<-fs.stall
	}

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

func (fs *fakeServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()

	// Read this session's STDIN to EOF, in its own goroutine, so that what
	// the client forwarded is observed rather than assumed. Reading the
	// ssh.Channel itself is reading the session's stdin: the bytes the
	// CLIENT wrote into the channel.
	//
	// This must be a separate goroutine, not an inline read: the client
	// writes stdin concurrently with waiting for the command's output, and
	// x/crypto/ssh's Session.Start launches its stdin copy in a goroutine
	// of its own. It CloseWrite()s as soon as the source is exhausted, so
	// for a session whose Stdin was never set — which is every session
	// Client.Run opens — this returns immediately with zero bytes.
	//
	// The join below is BOUNDED by drainJoinTimeout. Unbounded, a session
	// whose stdin is never closed would deadlock this handler and hang the
	// whole package to the Makefile's 20m timeout instead of failing it —
	// and a suite that hangs is an instrument that lies, which is this
	// project's cardinal defect class. Bounding it turns that into a
	// recorded truncation the assertions reject by name.
	//
	// The read accumulates incrementally rather than using io.ReadAll,
	// because ReadAll yields nothing at all until EOF: on timeout it would
	// hand back an empty slice indistinguishable from "the client sent
	// nothing", which is precisely the confusion stdinRecord.truncated
	// exists to prevent.
	buf := &bytes.Buffer{}
	var bufMu sync.Mutex
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		chunk := make([]byte, 4096)
		for {
			n, err := ch.Read(chunk)
			if n > 0 {
				bufMu.Lock()
				buf.Write(chunk[:n])
				bufMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	if fs.asyncExec {
		for req := range reqs {
			switch req.Type {
			case "exec":
				cmd := string(req.Payload[4:])
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				go func() {
					stdout, stderr, code := fs.handleExec(cmd)
					_, _ = ch.Write([]byte(stdout))
					_, _ = ch.Stderr().Write([]byte(stderr))
					_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(code))
					_ = ch.Close()
				}()
			case "signal":
				fs.event("signal:" + string(req.Payload[4:]))
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		fs.event("close") // the client closed the channel: no more requests
		return
	}

	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := string(req.Payload[4:]) // uint32 length prefix + string
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			stdout, stderr, code := fs.handleExec(cmd)
			// Join the drain and record BEFORE the exit-status goes out.
			// Client.Run returns once it has the exit status, so joining
			// here is what lets a test read stdinRecords() straight after
			// Run without racing this goroutine. Recording asynchronously
			// instead would turn the isolation assertion into a race the
			// test usually wins — a check that passes without having
			// observed anything, which is the exact defect class this
			// test exists to rule out.
			timer := time.NewTimer(drainJoinTimeout)
			truncated := false
			select {
			case <-drained:
			case <-timer.C:
				truncated = true
			}
			timer.Stop()
			bufMu.Lock()
			got := append([]byte(nil), buf.Bytes()...)
			bufMu.Unlock()
			fs.recordStdin(stdinRecord{data: got, truncated: truncated})
			_, _ = ch.Write([]byte(stdout))
			_, _ = ch.Stderr().Write([]byte(stderr))
			_, _ = ch.SendRequest("exit-status", false, exitStatusPayload(code))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func exitStatusPayload(code int) []byte {
	b := make([]byte, 4)
	b[3] = byte(code)
	return b
}

var fmtErrAuth = &authError{}

type authError struct{}

func (*authError) Error() string { return "auth rejected" }

// clientKeypair is a small test helper: generates a keypair and returns
// both the sshexec.Keypair (PEM etc.) and the parsed ssh.PublicKey the fake
// server needs to allow it.
func clientKeypair(t *testing.T) (*Keypair, ssh.PublicKey) {
	t.Helper()
	kp, err := GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	return kp, signer.PublicKey()
}
