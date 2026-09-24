// Package pvefake is test-support machinery: an in-process fake SSH server
// standing in for a PVE host's sshd, and scripted fake PVE REST servers for
// the network-bridge and network-fields flows. Together with
// pve.SetSSHPortForIntegrationTests they let a test drive a REAL
// *pve.RoutedClient — built through pve.NewRoutedClient, never a shortcut —
// over both of its transports at once.
//
// It exists because test files in two packages need it: internal/idempotent's
// full-stack Op tests and cmd/pveforge's runRoot tests of the commands whose
// success path crosses SSH (network bridge create/destroy, network set, vm
// set on a root-only field). A Go test file cannot be shared across
// packages, so the shared half lives here rather than being copied — the
// same reason internal/sourceguard and internal/netguard are build-visible.
//
// Production code must never import this package. That is not left to
// convention: TestPVEFake_NoProductionReferences forbids every reference to
// it from any non-test file in the module, and a package nothing non-test
// imports is never linked into the binary.
//
// It imports only the standard library and golang.org/x/crypto/ssh — never
// internal/pve or internal/sshexec — so any package's in-package tests,
// including those two, can import it without an import cycle.
package pvefake

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// SSHServer is a minimal in-process SSH server: public-key auth against one
// allowed key, and one "exec" request per session, answered by the
// configured handler. Every command it receives is recorded in order.
//
// Configure it (AllowKey, AllowPassword, HandleExec) BEFORE Start, and never after: the
// accept loop reads that configuration from other goroutines, so a write
// after Start is a data race (the one internal/pve's own fake once had —
// pveforge-fix-fake-ssh-server-test-races). Both setters panic once Start
// has run, so the mistake fails loudly rather than racing quietly.
type SSHServer struct {
	hostSigner ssh.Signer
	listener   net.Listener
	addr       string

	allowedPub ssh.PublicKey
	// allowedUser/allowedPassword, when set, also admit password auth.
	allowedUser, allowedPassword string
	handleExec                   func(cmd string) (stdout, stderr string, exitCode int)
	started                      bool

	mu   sync.Mutex
	cmds []string
}

// NewSSHServer generates a fresh host key and binds a loopback listener,
// closed when t finishes. It does not accept connections until Start. The
// default exec handler succeeds with no output.
func NewSSHServer(t testing.TB) *SSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("pvefake: generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("pvefake: host key signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pvefake: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	return &SSHServer{
		hostSigner: signer,
		listener:   ln,
		addr:       ln.Addr().String(),
		handleExec: func(string) (string, string, int) { return "", "", 0 },
	}
}

// AllowKey sets the one client public key the server accepts. Until it is
// called, every connection is refused. Panics after Start.
func (s *SSHServer) AllowKey(pub ssh.PublicKey) {
	s.mustNotBeStarted("AllowKey")
	s.allowedPub = pub
}

// AllowPassword also admits password auth as user with password, for a
// caller's keyless path. Panics after Start.
func (s *SSHServer) AllowPassword(user, password string) {
	s.mustNotBeStarted("AllowPassword")
	s.allowedUser, s.allowedPassword = user, password
}

// HandleExec sets the handler that answers every exec request with its
// stdout, stderr and exit status. Panics after Start.
func (s *SSHServer) HandleExec(fn func(cmd string) (stdout, stderr string, exitCode int)) {
	s.mustNotBeStarted("HandleExec")
	s.handleExec = fn
}

func (s *SSHServer) mustNotBeStarted(setter string) {
	if s.started {
		panic("pvefake: SSHServer." + setter + " called after Start: configure the server before starting it")
	}
}

// Start begins accepting connections.
func (s *SSHServer) Start() {
	s.started = true
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()
}

// Addr is the server's host:port.
func (s *SSHServer) Addr() string { return s.addr }

// Port is the server's port, for pve.SetSSHPortForIntegrationTests.
func (s *SSHServer) Port(t testing.TB) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatalf("pvefake: split host port: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("pvefake: parse port %q: %v", portStr, err)
	}
	return p
}

// Commands returns every exec command received so far, in arrival order.
func (s *SSHServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.cmds))
	copy(out, s.cmds)
	return out
}

func (s *SSHServer) handleConn(conn net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.allowedPub != nil && string(key.Marshal()) == string(s.allowedPub.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("auth rejected")
		},
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if s.allowedPassword != "" && m.User() == s.allowedUser && string(pw) == s.allowedPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("auth rejected")
		},
	}
	cfg.AddHostKey(s.hostSigner)

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
		go s.handleSession(ch, chReqs)
	}
}

func (s *SSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
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
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd)
		s.mu.Unlock()

		stdout, stderr, code := s.handleExec(cmd)
		_, _ = ch.Write([]byte(stdout))
		_, _ = ch.Stderr().Write([]byte(stderr))
		status := make([]byte, 4)
		status[3] = byte(code)
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

// LinkJSON is the `ip -j link show` JSON body for an existing interface
// with the given up/down state.
func LinkJSON(iface string, up bool) string {
	state, flags := "DOWN", `["BROADCAST","MULTICAST"]`
	if up {
		state, flags = "UP", `["UP","BROADCAST","MULTICAST"]`
	}
	return fmt.Sprintf(`[{"ifname":%q,"operstate":%q,"flags":%s}]`, iface, state, flags)
}

// LinkMissingStderrFmt is iproute2's stderr for a missing interface; format
// it with the interface name and pair it with exit status 1.
const LinkMissingStderrFmt = `Device "%s" does not exist.`

// LinkShowCmd is the exact command sshexec.LinkState runs for iface.
func LinkShowCmd(iface string) string {
	return fmt.Sprintf("ip -j link show dev '%s'", iface)
}
