package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

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

	// handleExec is invoked for every "exec" request accepted by the
	// server; it returns (stdout, stderr, exitStatus).
	handleExec func(cmd string) (string, string, int)
}

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
	}

	go fs.serve(t, ln)
	return fs
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
	for req := range reqs {
		switch req.Type {
		case "exec":
			cmd := string(req.Payload[4:]) // uint32 length prefix + string
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			stdout, stderr, code := fs.handleExec(cmd)
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
