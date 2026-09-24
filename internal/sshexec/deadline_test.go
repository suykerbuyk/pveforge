package sshexec

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pveforge-root-channel-deadlines: every command Run executes is bounded,
// by CommandTimeout or the caller's WithCommandTimeout, and a command's own
// timeout is told apart from the caller's cancellation.

// hangingServer returns a started fake server whose commands block until
// the test ends (or, with asyncExec, until then too), and a client for it.
func hangingServer(t *testing.T, async bool) (*fakeServer, *Client) {
	t.Helper()
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fs.handleExec = func(cmd string) (string, string, int) {
		// A qm set of the value 'slow', and any command over 32 KiB (a
		// WriteFile with a large payload), take 400ms.
		if strings.Contains(cmd, "'slow'") || len(cmd) > 32<<10 {
			cmd = "sleep 400ms"
		}
		if strings.HasPrefix(cmd, "sleep ") {
			d, _ := time.ParseDuration(strings.TrimPrefix(cmd, "sleep "))
			select {
			case <-time.After(d):
			case <-release:
			}
			return "slept", "", 0
		}
		<-release
		return "", "", 0
	}
	fs.asyncExec = async
	fs.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return fs, c
}

// setCommandTimeout lowers CommandTimeout for one test.
func setCommandTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := CommandTimeout
	t.Cleanup(func() { CommandTimeout = orig })
	CommandTimeout = d
}

// runWithin runs c.Run(ctx, cmd) and fails the test if it has not returned
// within d.
func runWithin(t *testing.T, d time.Duration, c *Client, ctx context.Context, cmd string) (*Result, error) {
	t.Helper()
	type out struct {
		res *Result
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := c.Run(ctx, cmd)
		done <- out{res, err}
	}()
	select {
	case o := <-done:
		return o.res, o.err
	case <-time.After(d):
		t.Fatalf("Run(%q) still running after %s: the command is not bounded", cmd, d)
		return nil, nil
	}
}

// R1: a command that never finishes ends at CommandTimeout, as a
// *CommandTimeoutError naming it, never echoing its arguments.
func TestRun_R1_AHungCommandTimesOut(t *testing.T) {
	setCommandTimeout(t, 200*time.Millisecond)
	_, c := hangingServer(t, false)
	_, err := runWithin(t, 5*time.Second, c, context.Background(), "pveum user add 'secret-arg' --enable 1")
	var te *CommandTimeoutError
	if !errors.As(err, &te) || !errors.Is(err, ErrCommandTimedOut) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v, want a *CommandTimeoutError", err)
	}
	if te.After != 200*time.Millisecond || te.Cmd != "pveum user" || strings.Contains(err.Error(), "secret-arg") {
		t.Errorf("timeout error = %+v (%q); want After 200ms, Cmd %q, no argument echoed", te, err, "pveum user")
	}
	if !strings.Contains(err.Error(), "whether it took effect is unknown") {
		t.Errorf("error %q does not say the outcome is unknown", err)
	}
}

// R2: the caller's cancellation mid-command is the caller's error, never a
// timeout: an interruption must stay an interruption.
func TestRun_R2_ParentCancellationIsNotATimeout(t *testing.T) {
	setCommandTimeout(t, 5*time.Second)
	_, c := hangingServer(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := runWithin(t, 3*time.Second, c, ctx, "pveum user add x")
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrCommandTimedOut) {
		t.Fatalf("Run = %v, want context.Canceled and not a command timeout", err)
	}
}

// R3: a caller's own deadline earlier than the command's wins, and is the
// caller's error, not the command's timeout.
func TestRun_R3_AnEarlierParentDeadlineWins(t *testing.T) {
	setCommandTimeout(t, 5*time.Second)
	_, c := hangingServer(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := runWithin(t, 3*time.Second, c, ctx, "pveum user list")
	var te *CommandTimeoutError
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &te) {
		t.Fatalf("Run = %v, want the caller's own deadline, not a *CommandTimeoutError", err)
	}
}

// R4 (S4): a session open that stalls is bounded by the same deadline, and
// reported as such: no command was sent, so its outcome is known.
func TestRun_R4_AStalledSessionOpenTimesOut(t *testing.T) {
	setCommandTimeout(t, 200*time.Millisecond)
	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	fs.stall = make(chan struct{})
	t.Cleanup(func() { close(fs.stall) })
	fs.Start(t)
	c, err := Dial(context.Background(), fs.addr, "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	_, err = runWithin(t, 5*time.Second, c, context.Background(), "true")
	if !errors.Is(err, ErrSessionOpenTimedOut) || !errors.Is(err, ErrNoCommandSent) || errors.Is(err, ErrCommandTimedOut) {
		t.Fatalf("Run = %v, want ErrSessionOpenTimedOut and ErrNoCommandSent, not ErrCommandTimedOut", err)
	}
	// The caller's own cancellation while opening is its own error, and
	// still known not to have sent anything.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	setCommandTimeout(t, 5*time.Second)
	_, err = runWithin(t, 3*time.Second, c, ctx, "true")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrNoCommandSent) || errors.Is(err, ErrSessionOpenTimedOut) {
		t.Fatalf("cancelled while opening: Run = %v, want context.Canceled and ErrNoCommandSent", err)
	}
}

// R5: WithCommandTimeout sets the bound in both directions.
func TestRun_R5_WithCommandTimeout(t *testing.T) {
	_, c := hangingServer(t, false)
	setCommandTimeout(t, 5*time.Second)
	_, err := runWithin(t, 3*time.Second, c, WithCommandTimeout(context.Background(), 150*time.Millisecond), "pveum user list")
	var te *CommandTimeoutError
	if !errors.As(err, &te) || te.After != 150*time.Millisecond {
		t.Fatalf("shorter: Run = %v, want a timeout after 150ms", err)
	}
	setCommandTimeout(t, 100*time.Millisecond)
	res, err := runWithin(t, 5*time.Second, c, WithCommandTimeout(context.Background(), 3*time.Second), "sleep 400ms")
	if err != nil || res.Stdout != "slept" {
		t.Fatalf("longer: Run = %+v, %v; want the 400ms command to finish under its 3s bound", res, err)
	}
	if got := CommandTimeoutFor(WithCommandTimeout(context.Background(), time.Minute)); got != time.Minute {
		t.Errorf("CommandTimeoutFor = %s, want 1m", got)
	}
	if got := CommandTimeoutFor(context.Background()); got != CommandTimeout {
		t.Errorf("CommandTimeoutFor(no value) = %s, want CommandTimeout", got)
	}
}

// R6: on a timeout the remote process is sent SIGKILL BEFORE the session
// is closed (closing first would drop the channel the signal travels on).
func TestRun_R6_SignalThenClose(t *testing.T) {
	setCommandTimeout(t, 150*time.Millisecond)
	fs, c := hangingServer(t, true)
	if _, err := runWithin(t, 5*time.Second, c, context.Background(), "pveum user add x"); !errors.Is(err, ErrCommandTimedOut) {
		t.Fatalf("Run = %v, want ErrCommandTimedOut", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(fs.eventLog()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got, want := fs.eventLog(), []string{"signal:KILL", "close"}; !slices.Equal(got, want) {
		t.Fatalf("the server saw %q, want %q", got, want)
	}
}

// The two callers whose commands can legitimately outlast CommandTimeout
// carry their own bound: `qm set` QMSetTimeout, WriteFile one scaled to
// its payload. With CommandTimeout at 100ms, each 400ms command finishes
// under its own bound, and qm set still ends at QMSetTimeout.
func TestRun_ExplicitBoundsForLongCommands(t *testing.T) {
	_, c := hangingServer(t, false)
	setCommandTimeout(t, 100*time.Millisecond)
	orig := QMSetTimeout
	t.Cleanup(func() { QMSetTimeout = orig })

	QMSetTimeout = 3 * time.Second
	within := func(name string, fn func() error) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatalf("%s still running after 5s", name)
			return nil
		}
	}
	if err := within("qm set", func() error { return c.SetVMConfigField(context.Background(), 100, "args", "slow") }); err != nil {
		t.Errorf("a 400ms qm set under QMSetTimeout 3s: %v", err)
	}
	if err := within("qm set --delete", func() error { return c.DeleteVMConfigField(context.Background(), 100, "slow") }); err != nil {
		t.Errorf("a 400ms qm set --delete under QMSetTimeout 3s: %v", err)
	}
	QMSetTimeout = 150 * time.Millisecond
	var te *CommandTimeoutError
	if err := within("qm set", func() error { return c.SetVMConfigField(context.Background(), 100, "args", "hang") }); !errors.As(err, &te) || te.After != 150*time.Millisecond {
		t.Errorf("qm set past QMSetTimeout = %v, want a timeout after 150ms", err)
	}

	big := make([]byte, 48<<10) // 64 KiB encoded: 2s past CommandTimeout
	if err := within("write file", func() error { return c.WriteFile(context.Background(), "/var/lib/vz/snippets/x", big, "0644") }); err != nil {
		t.Errorf("a 400ms write of 48 KiB under its size-scaled bound: %v", err)
	}
	if got := writeFileTimeout(0); got != CommandTimeout {
		t.Errorf("writeFileTimeout(0) = %s, want CommandTimeout", got)
	}
	if got := writeFileTimeout(128 << 10); got != CommandTimeout+4*time.Second {
		t.Errorf("writeFileTimeout(128KiB) = %s, want CommandTimeout+4s", got)
	}
}

// stuckConn models a half-open TCP connection whose send buffer has filled:
// once armed, the first write larger than 4 KiB blocks, and so does every
// write after it, until the connection is closed.
type stuckConn struct {
	net.Conn
	mu    sync.Mutex
	armed bool
	stuck bool
	gone  chan struct{}
}

func (c *stuckConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.armed && (c.stuck || len(p) > 4096) {
		c.stuck = true
		c.mu.Unlock()
		<-c.gone
		return 0, net.ErrClosed
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *stuckConn) Close() error {
	c.mu.Lock()
	select {
	case <-c.gone:
	default:
		close(c.gone)
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// D1: a command whose exec request is stuck in a write (a half-open
// connection, a full send buffer, a WriteFile-sized argv) still times out:
// the SIGKILL and the session close queue behind that write, so after
// TimeoutCloseGrace Run closes the connection itself. The Client is then
// dead, and a later Run fails at once, knowing nothing was sent.
// Adapted from the independent review's reproduction.
func TestRun_D1_AStuckWriteCannotHoldTheTimeout(t *testing.T) {
	setCommandTimeout(t, 200*time.Millisecond)
	orig := TimeoutCloseGrace
	t.Cleanup(func() { TimeoutCloseGrace = orig })
	TimeoutCloseGrace = 300 * time.Millisecond

	fs := newFakeServer(t)
	kp, pub := clientKeypair(t)
	fs.allowPublicKey(pub)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	fs.handleExec = func(string) (string, string, int) { <-release; return "", "", 0 }
	fs.Start(t)
	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Dial("tcp", fs.addr)
	if err != nil {
		t.Fatal(err)
	}
	sc := &stuckConn{Conn: raw, gone: make(chan struct{})}
	cc, chans, reqs, err := ssh.NewClientConn(sc, fs.addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: acceptAnyHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{conn: ssh.NewClient(cc, chans, reqs)}
	t.Cleanup(func() { _ = c.Close() })
	sc.mu.Lock()
	sc.armed = true
	sc.mu.Unlock()

	start := time.Now()
	_, err = runWithin(t, 3*time.Second, c, context.Background(), "echo "+strings.Repeat("A", 64<<10))
	if !errors.Is(err, ErrCommandTimedOut) {
		t.Fatalf("Run = %v, want ErrCommandTimedOut", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond+TimeoutCloseGrace+time.Second {
		t.Errorf("Run took %s, want about the deadline plus the grace", d)
	}
	if !c.dead.Load() {
		t.Error("the Client is not marked dead after its connection was closed")
	}
	select {
	case <-sc.gone: // closed: the stuck write, and the signal behind it, are released
	default:
		t.Error("the connection was not closed: the stuck write, and the SIGKILL queued behind it, are still blocked")
	}
	_, err = runWithin(t, time.Second, c, context.Background(), "true")
	if !errors.Is(err, ErrConnClosedAfterTimeout) || !errors.Is(err, ErrNoCommandSent) {
		t.Fatalf("a Run on the dead Client = %v, want ErrConnClosedAfterTimeout", err)
	}
}
