package sshexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialTimeout bounds how long an SSH TCP-connect + handshake may take, so a
// network-partitioned or firewalled target fails fast rather than hanging
// the caller forever.
const DialTimeout = 15 * time.Second

// Client is a live SSH connection. Both the bootstrap flow's pveum
// invocations and the standing root-only-field workaround's qm set
// invocations run over this same type.
type Client struct {
	conn *ssh.Client
}

// Dial opens an SSH connection to addr (host:port) as user, authenticated
// by privateKeyPEM (OpenSSH PEM format, as produced by
// GenerateEd25519Keypair and round-tripped through the roster's encrypted
// storage), verified against hostKeyCallback — in practice always
// PinnedHostKeyCallback outside of the one-time bootstrap connection.
func Dial(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyCallback ssh.HostKeyCallback) (*Client, error) {
	signer, err := ssh.ParsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ssh private key: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         DialTimeout,
	}
	return dial(ctx, addr, cfg)
}

// DialWithPassword opens an SSH connection authenticated by password
// instead of a key. Used only for the one-time bootstrap pubkey-install
// step (InstallPubkeyViaPassword); every later connection uses Dial with
// the installed key.
func DialWithPassword(ctx context.Context, addr, user, password string, hostKeyCallback ssh.HostKeyCallback) (*Client, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         DialTimeout,
	}
	return dial(ctx, addr, cfg)
}

func dial(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return &Client{conn: ssh.NewClient(c, chans, reqs)}, nil
}

// Close closes the underlying SSH connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Result is the outcome of Run.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes cmd on the remote host and waits for completion or ctx
// cancellation, whichever comes first. A non-zero remote exit status is
// reported via Result.ExitCode with a nil error — Run's own error return is
// reserved for transport/session failures (can't open a session, the
// connection dropped, ctx was cancelled before the command finished).
// Callers that need "the command failed" to be a Go error should check
// ExitCode themselves.
//
// STDIN ISOLATION. The session below sets Stdout and Stderr and
// deliberately never sets Stdin. x/crypto/ssh substitutes an empty buffer
// for a nil Session.Stdin, so the remote command sees an immediate EOF and
// not one byte of THIS process's stdin ever reaches it. That matters
// because pveforge runs as an interactive CLI: os.Stdin here is the
// operator's terminal, holding a passphrase prompt's input among other
// things, and a remote `qm`/`pvesh` invocation has no business consuming
// it. The property is pinned by TestRun_NeverForwardsCallerStdin, which
// the mutation `session.Stdin = os.Stdin` turns red.
//
// A future feature that genuinely needs to STREAM data to the remote side
// — a large upload, say, too big for WriteFile's argv-embedded payload —
// must open its own explicit, separate channel for it rather than reusing
// this command session's stdin. Keeping the data plane out of the command
// plane is the point; sharing them is how a command ends up eating input
// that was never meant for it.
//
// NOT VERIFIABLE WITHOUT A LIVE PVE HOST: the test above proves pveforge
// SENDS no stdin. It cannot prove the remote never WANTED any, because it
// asserts against an in-process fake SSH server rather than a real
// pvesh/qm/pvesm/ifreload. If some remote command were to block waiting on
// stdin instead of tolerating EOF, the suite would stay green and the call
// would hang against a real host. Nothing observed so far suggests one
// does; it is recorded here because no test in this repo can settle it.
func (c *Client) Run(ctx context.Context, cmd string) (*Result, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return nil, ctx.Err()
	case runErr := <-done:
		res := &Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if runErr == nil {
			return res, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return nil, fmt.Errorf("run %q: %w", cmd, runErr)
	}
}
