package pve

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeSSHServer is a minimal in-process SSH server for testing
// RoutedClient's SSH-routed path without any real network/PVE-host
// access — same pattern used by internal/sshexec's and
// internal/bootstrap's own tests.
type fakeSSHServer struct {
	addr       string
	hostSigner ssh.Signer
	allowedPub ssh.PublicKey
	handleExec func(cmd string) (stdout, stderr string, exitCode int)
	listener   net.Listener
}

// newFakeSSHServer constructs the fake server and binds its listening
// port, but does NOT start accepting connections yet — call Start() once
// the test has finished configuring it (setting allowedPub/handleExec).
// Starting the accept loop here, before the caller configures the struct,
// was a genuine data race: a connection accepted in that window could
// read fs.allowedPub concurrently with the test goroutine's write to it
// (caught by `go test -race`) — see pveforge-fix-fake-ssh-server-test-races.
func newFakeSSHServer(t *testing.T) *fakeSSHServer {
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

	fs := &fakeSSHServer{
		addr:       ln.Addr().String(),
		hostSigner: signer,
		handleExec: func(cmd string) (string, string, int) { return "", "", 0 },
		listener:   ln,
	}
	return fs
}

// Start begins accepting connections. Call it only after the test has
// finished configuring the server — see newFakeSSHServer's doc comment.
func (fs *fakeSSHServer) Start() {
	go fs.serve(fs.listener)
}

func (fs *fakeSSHServer) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go fs.handleConn(conn)
	}
}

func (fs *fakeSSHServer) handleConn(conn net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if fs.allowedPub != nil && string(key.Marshal()) == string(fs.allowedPub.Marshal()) {
				return nil, nil
			}
			return nil, errFakeAuthRejected
		},
	}
	cfg.AddHostKey(fs.hostSigner)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)

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

func (fs *fakeSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		cmd := string(req.Payload[4:])
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		stdout, stderr, code := fs.handleExec(cmd)
		_, _ = ch.Write([]byte(stdout))
		_, _ = ch.Stderr().Write([]byte(stderr))
		status := make([]byte, 4)
		status[3] = byte(code)
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

type fakeAuthRejectedError struct{}

func (*fakeAuthRejectedError) Error() string { return "auth rejected" }

var errFakeAuthRejected = &fakeAuthRejectedError{}

// port extracts the numeric port fakeSSHServer is listening on, for
// pointing RoutedClient's sshPort test seam at it.
func (fs *fakeSSHServer) port(t *testing.T) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(fs.addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return p
}
