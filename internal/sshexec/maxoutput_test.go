package sshexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// sizedServer answers "out N" with N bytes on stdout and "err N" with N
// bytes on stderr, and returns a client for it.
func sizedServer(t *testing.T) *Client {
	t.Helper()
	fs := pvefake.NewSSHServer(t)
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)
	fs.HandleExec(func(cmd string) (string, string, int) {
		var n int
		switch {
		case strings.HasPrefix(cmd, "out "):
			_, _ = fmt.Sscan(cmd[4:], &n)
			return strings.Repeat("o", n), "", 0
		case strings.HasPrefix(cmd, "err "):
			_, _ = fmt.Sscan(cmd[4:], &n)
			return "", strings.Repeat("e", n), 0
		}
		return "", "", 127
	})
	fs.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestRun_MaxOutput_RefusesAnOversizedAnswer: past its limit, on stdout or
// on stderr, a command is stopped and Run returns OutputTooLargeError with
// no Result; an answer of exactly the limit is kept whole.
func TestRun_MaxOutput_RefusesAnOversizedAnswer(t *testing.T) {
	c := sizedServer(t)
	const limit = 64 << 10
	ctx := WithMaxOutput(context.Background(), limit)
	for _, cmd := range []string{"out 200000", "err 200000", "out 65537"} {
		res, err := runWithin(t, 5*time.Second, c, ctx, cmd)
		var tooLarge *OutputTooLargeError
		if !errors.Is(err, ErrOutputTooLarge) || !errors.As(err, &tooLarge) || tooLarge.Limit != limit || res != nil {
			t.Errorf("%s under a %d-byte limit: res %v, err %v; want OutputTooLargeError and no result", cmd, limit, res, err)
		}
	}
	res, err := runWithin(t, 5*time.Second, c, ctx, "out 65536")
	if err != nil || len(res.Stdout) != limit {
		t.Errorf("exactly the limit: %d bytes, %v; want all %d kept", len(res.Stdout), err, limit)
	}
}

// TestRun_OutputIsUnlimitedByDefault: every caller that does not set a
// limit (all but the TLS capture) gets the whole answer, however large, as
// before.
func TestRun_OutputIsUnlimitedByDefault(t *testing.T) {
	c := sizedServer(t)
	for _, ctx := range []context.Context{context.Background(), WithMaxOutput(context.Background(), 0)} {
		res, err := runWithin(t, 5*time.Second, c, ctx, "out 1048576")
		if err != nil || len(res.Stdout) != 1<<20 {
			t.Errorf("no limit: %d bytes, %v; want the whole 1 MiB", len(res.Stdout), err)
		}
		res, err = runWithin(t, 5*time.Second, c, ctx, "err 1048576")
		if err != nil || len(res.Stderr) != 1<<20 {
			t.Errorf("no limit: %d stderr bytes, %v; want the whole 1 MiB", len(res.Stderr), err)
		}
	}
}

func TestMaxOutputFor(t *testing.T) {
	if n := MaxOutputFor(context.Background()); n != 0 {
		t.Errorf("default %d, want 0 (unlimited)", n)
	}
	if n := MaxOutputFor(WithMaxOutput(context.Background(), 4096)); n != 4096 {
		t.Errorf("set %d, want 4096", n)
	}
	if n := MaxOutputFor(WithMaxOutput(context.Background(), -1)); n != 0 {
		t.Errorf("negative %d, want 0", n)
	}
}

// TestRun_MaxOutput_StopsACommandThatKeepsRunning: a command that overflows
// its limit and then keeps its session open (still streaming, or hung) is
// stopped at once, SIGKILL then close, and reported as too large, not
// waited on until its time bound. The control shows the fake really holds
// such a session open: with no limit, the same command runs to its bound.
func TestRun_MaxOutput_StopsACommandThatKeepsRunning(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	kp, pub := clientKeypair(t)
	fs.AllowKey(pub)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if cmd == "flood" {
			return strings.Repeat("o", 200000), "", 0
		}
		return "small", "", 0
	})
	fs.AsyncExec()
	fs.HangAfterOutput()
	fs.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, fs.Addr(), "root", kp.PrivateKeyPEM, acceptAnyHostKey())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	setCommandTimeout(t, 300*time.Millisecond)
	if _, err := runWithin(t, 5*time.Second, c, context.Background(), "small"); !errors.Is(err, ErrCommandTimedOut) {
		t.Fatalf("control: %v, want a timeout: the fake does not hold the session open", err)
	}

	setCommandTimeout(t, 30*time.Second)
	time.Sleep(100 * time.Millisecond) // let the control's own events land
	eventsBefore := len(fs.Events())
	start := time.Now()
	_, err = runWithin(t, 10*time.Second, c, WithMaxOutput(context.Background(), 64<<10), "flood")
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v, want ErrOutputTooLarge", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v: Run waited on the command instead of stopping it", d)
	}
	// Only the events after the control: its timeout sent a SIGKILL too.
	deadline := time.Now().Add(2 * time.Second)
	for !slicesContains(fs.Events()[eventsBefore:], "signal:KILL") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !slicesContains(fs.Events()[eventsBefore:], "signal:KILL") {
		t.Errorf("events after the control %q: the overflowing command was not sent SIGKILL", fs.Events()[eventsBefore:])
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestFinishRun_NeverReturnsOverflowedOutput: when a command overflowed and
// then ended before Run noticed, the result is still OutputTooLargeError,
// never the truncated output; within the limit, the result is as before.
func TestFinishRun_NeverReturnsOverflowedOutput(t *testing.T) {
	buffers := func() (*cappedBuffer, *cappedBuffer) {
		over, once := make(chan struct{}), &sync.Once{}
		return &cappedBuffer{limit: 4, over: over, once: once}, &cappedBuffer{limit: 4, over: over, once: once}
	}
	for _, overflow := range []string{"stdout", "stderr"} {
		out, errb := buffers()
		w := out
		if overflow == "stderr" {
			w = errb
		}
		_, _ = w.Write([]byte("12345"))
		res, err := finishRun("cmd x", nil, out, errb)
		if !errors.Is(err, ErrOutputTooLarge) || res != nil {
			t.Errorf("%s overflowed: res %+v, err %v; want OutputTooLargeError and no result", overflow, res, err)
		}
	}
	out, errb := buffers()
	_, _ = out.Write([]byte("1234"))
	_, _ = errb.Write([]byte("ab"))
	if res, err := finishRun("cmd x", nil, out, errb); err != nil || res.Stdout != "1234" || res.Stderr != "ab" {
		t.Errorf("within the limit: %+v, %v", res, err)
	}
}
