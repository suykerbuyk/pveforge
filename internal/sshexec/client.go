package sshexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// DialTimeout bounds how long an SSH TCP-connect + handshake may take, so a
// network-partitioned or firewalled target fails fast rather than hanging
// the caller forever.
const DialTimeout = 15 * time.Second

// CommandTimeout bounds every command Run executes, unless the caller sets
// its own bound with WithCommandTimeout: 30s, the bound pve.DefaultTimeout
// puts on a REST call. It covers every read and two small writes that take
// no PVE lock: InstallPubkeyViaPassword's append to root's authorized_keys
// (on PVE a link into /etc/pve/priv) and SetBridgePortIsolated's
// `bridge link set`. A half-open connection, a hung pmxcfs or a stuck
// remote process must never hold the caller, or a pveforge lock the caller
// holds, without end. The table of every caller's expected duration, and
// the reason for each explicit bound, is in the task
// pveforge-root-channel-deadlines. A variable only so tests can lower it.
//
// There are no SSH keepalives, deliberately: with every command bounded,
// they would only notice a dead connection sooner between commands.
var CommandTimeout = 30 * time.Second

// ErrCommandTimedOut matches a *CommandTimeoutError.
var ErrCommandTimedOut = errors.New("ssh command timed out")

// CommandTimeoutError is Run's error when a command ran past its own
// deadline (CommandTimeout, or WithCommandTimeout's): not a cancellation of
// the caller's context, which Run returns unchanged. Run sent the remote
// process SIGKILL and closed the session, but the command's outcome is
// unknown: it may have taken effect, and, since sshd signals only the
// session's own process, a child of it may still be running on the host,
// past pveforge and past any pveforge lock.
type CommandTimeoutError struct {
	Cmd   string // the command's first words, never its arguments' payload
	After time.Duration
}

func (e *CommandTimeoutError) Error() string {
	return fmt.Sprintf("%s: %s after %s; whether it took effect is unknown, and it may still be running on the host", e.Cmd, ErrCommandTimedOut, e.After)
}

func (e *CommandTimeoutError) Is(target error) bool {
	return target == ErrCommandTimedOut || target == context.DeadlineExceeded
}

// ErrNoCommandSent matches every Run error that happened before the
// command was sent: the session could not be opened (in time, or at all),
// or the connection was already closed. Such a command certainly did not
// run, which is what lets a writer report it as a plain failure rather than
// an unknown outcome.
var ErrNoCommandSent = errors.New("no command was sent")

// ErrSessionOpenTimedOut matches a *SessionOpenTimeoutError.
var ErrSessionOpenTimedOut = errors.New("ssh session open timed out")

// SessionOpenTimeoutError is Run's error when the command's deadline passed
// while the session was still being opened: no command was sent.
type SessionOpenTimeoutError struct {
	Cmd   string
	After time.Duration
}

func (e *SessionOpenTimeoutError) Error() string {
	return fmt.Sprintf("%s: %s after %s; %s", e.Cmd, ErrSessionOpenTimedOut, e.After, ErrNoCommandSent)
}

func (e *SessionOpenTimeoutError) Is(target error) bool {
	return target == ErrSessionOpenTimedOut || target == ErrNoCommandSent || target == context.DeadlineExceeded
}

// ErrConnClosedAfterTimeout: this Client's connection was closed by Run
// itself after a timed-out command whose signal and session close could
// not complete (a write blocked on a dead connection). The Client is
// unusable; the caller reconnects. It matches ErrNoCommandSent.
var ErrConnClosedAfterTimeout = fmt.Errorf("ssh connection closed after a timed-out command; reconnect: %w", ErrNoCommandSent)

// TimeoutCloseGrace bounds how long Run waits, after a command's deadline,
// for the SIGKILL request and the session close to be sent. Both are
// writes on the connection, taken under the same locks as a write already
// in flight: when that write is stuck (a half-open connection with a full
// send buffer, a large exec request), they would wait forever. Past the
// grace Run closes the whole connection, which unblocks them, and the
// Client is dead from then on. A variable only so tests can lower it.
var TimeoutCloseGrace = 2 * time.Second

type commandTimeoutKey struct{}

// WithCommandTimeout returns ctx carrying d as the bound for the commands
// Run executes under it, in place of CommandTimeout: for a caller whose
// command can legitimately run longer (a PVE cluster-config write waits up
// to 10s for its lock and may then run 60s under it), or that wants a
// tighter one. It is a value, not ctx's own deadline, so an unrelated outer
// deadline never changes a command's bound; an earlier parent deadline
// still ends the command first, as that parent's error.
func WithCommandTimeout(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, commandTimeoutKey{}, d)
}

// CommandTimeoutFor is the bound Run applies to a command run under ctx:
// WithCommandTimeout's, else CommandTimeout.
func CommandTimeoutFor(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(commandTimeoutKey{}).(time.Duration); ok && d > 0 {
		return d
	}
	return CommandTimeout
}

// abandon ends a session whose command ran past its deadline: SIGKILL, then
// close (closing first would drop the channel the signal travels on). Both
// are writes that can be stuck behind a blocked one, so they run aside, for
// at most TimeoutCloseGrace; past it the whole connection is closed, which
// unblocks them, and the Client is marked dead.
func (c *Client) abandon(session *ssh.Session) {
	finished := make(chan struct{})
	go func() {
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		close(finished)
	}()
	timer := time.NewTimer(TimeoutCloseGrace)
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
		c.dead.Store(true)
		_ = c.conn.Close()
	}
}

// commandName is cmd's first two words, for an error: a command can carry
// a payload (WriteFile's content) that must never be echoed.
func commandName(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) > 2 {
		f = f[:2]
	}
	return strings.Join(f, " ")
}

// Client is a live SSH connection. Both the bootstrap flow's pveum
// invocations and the standing root-only-field workaround's qm set
// invocations run over this same type.
type Client struct {
	conn *ssh.Client
	// dead is set when Run had to close the connection itself, because a
	// timed-out command's signal and close were stuck behind a blocked
	// write. Every later Run fails at once (ErrConnClosedAfterTimeout).
	dead atomic.Bool
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

// dialGuard, when non-nil, vets every address this package is about to dial
// and may refuse it. Nil in production, and nothing but
// SetDialGuardForTests ever assigns it.
//
// This package's dial is the one network egress in pveforge that an
// http.DefaultTransport hook cannot see — it builds its own net.Dialer below
// — which is why internal/netguard needs a second seam here rather than one
// hook covering both. See that package's doc comment.
//
// NOT SAFE for two test packages to use concurrently: it mutates
// process-wide state with no locking, matching SetSSHPortForIntegrationTests
// (internal/pve/routed.go:29-49) and roster.SetScryptWorkFactorForTests,
// whose caveat and shape this deliberately copies. Each package's tests run
// in their own process, so the hazard is only ever intra-package.
var dialGuard func(addr string) error

// SetDialGuardForTests installs guard as the vetting hook every dial in this
// process passes through, restoring the previous hook via the returned func.
// internal/netguard.Guard is the only intended argument.
//
// It PANICS unless called from a binary built by `go test`, so the seam is
// inert in a shipped pveforge no matter who calls it.
//
// Production code must never call this. That is not left to convention:
// internal/netguard's TestSeam_NoProductionReferences forbids this name,
// setDialGuard and dialGuard in every non-test file in the module except this
// one.
func SetDialGuardForTests(guard func(addr string) error) (restore func()) {
	return setDialGuard(guard, testing.Testing())
}

// setDialGuard holds the whole decision with the "am I in a test binary"
// answer PASSED IN rather than read, for the same reason
// roster.setScryptWorkFactor does it (internal/roster/secrets.go:131): the
// refusal branch is then reachable from an ordinary in-process test, so the
// suite's own coverage profile covers it rather than only a subprocess whose
// coverage the profile never sees.
func setDialGuard(guard func(addr string) error, inTestBinary bool) (restore func()) {
	if !inTestBinary {
		panic("sshexec: SetDialGuardForTests called outside a test binary")
	}
	orig := dialGuard
	dialGuard = guard
	return func() { dialGuard = orig }
}

func dial(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*Client, error) {
	// Vet BEFORE dialing, so a refused address produces no DNS query and no
	// SYN — the refusal is the whole point, not a post-hoc report.
	if dialGuard != nil {
		if err := dialGuard(addr); err != nil {
			return nil, fmt.Errorf("dial %s: %w", addr, err)
		}
	}
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
//
// DEADLINE. Every command runs under its own bound (CommandTimeout, or the
// caller's WithCommandTimeout), from before the session is opened until
// it exits.
//   - Past it while the session is still opening, nothing was sent: a
//     *SessionOpenTimeoutError, matching ErrNoCommandSent.
//   - Past it once the command was sent, Run sends the remote process
//     SIGKILL (best effort: OpenSSH honours signal requests since 7.9), THEN
//     closes the session, and returns a *CommandTimeoutError: the outcome is
//     unknown, and the command may outlive pveforge and its lock. The signal
//     and the close are bounded by TimeoutCloseGrace; if a stuck write holds
//     them past it, Run closes the whole connection and the Client is dead
//     (every later Run: ErrConnClosedAfterTimeout).
//   - When the caller's own ctx ends first (a signal, or its own deadline),
//     Run returns that ctx's error, so an interruption is never reported as
//     a timeout, nor the reverse.
func (c *Client) Run(parent context.Context, cmd string) (*Result, error) {
	if c.dead.Load() {
		return nil, ErrConnClosedAfterTimeout
	}
	after := CommandTimeoutFor(parent)
	ctx, cancel := context.WithTimeout(parent, after)
	defer cancel()
	// ended is the error for ctx ending: the parent's own, or the timeout.
	ended := func() error {
		if err := parent.Err(); err != nil {
			return err
		}
		return &CommandTimeoutError{Cmd: commandName(cmd), After: after}
	}

	// Opening the session is a round trip too: on a half-open connection,
	// or a server that stopped answering, NewSession blocks with no
	// deadline of its own. So it runs beside ctx like the command does; a
	// session that arrives after ctx ended is closed unused.
	type opened struct {
		session *ssh.Session
		err     error
	}
	openc := make(chan opened, 1)
	go func() {
		s, err := c.conn.NewSession()
		openc <- opened{s, err}
	}()
	var session *ssh.Session
	select {
	case <-ctx.Done():
		go func() {
			if o := <-openc; o.session != nil {
				_ = o.session.Close()
			}
		}()
		// Nothing was sent: the session never opened.
		if err := parent.Err(); err != nil {
			return nil, fmt.Errorf("%w (%w)", err, ErrNoCommandSent)
		}
		return nil, &SessionOpenTimeoutError{Cmd: commandName(cmd), After: after}
	case o := <-openc:
		if o.err != nil {
			return nil, fmt.Errorf("open ssh session: %w (%w)", o.err, ErrNoCommandSent)
		}
		session = o.session
	}

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	select {
	case <-ctx.Done():
		c.abandon(session)
		return nil, ended()
	case runErr := <-done:
		_ = session.Close()
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
