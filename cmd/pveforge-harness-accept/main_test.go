package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRun_AcceptedExitsZero(t *testing.T) {
	var errOut bytes.Buffer
	n := 0
	code := run(context.Background(), []string{"-deadline", "1s", "-every", "1ms"}, &errOut, func(context.Context) error {
		n++
		if n < 2 {
			return errors.New("pvh-n2: the QDevice is \"Disconnected\"")
		}
		return nil
	})
	if code != 0 || n != 2 {
		t.Fatalf("exit %d after %d attempts, want 0 after 2\n%s", code, n, errOut.String())
	}
	out := errOut.String()
	if !strings.Contains(out, "attempt 1: pvh-n2: the QDevice") || !strings.Contains(out, "the nested cluster is accepted") {
		t.Errorf("stderr does not report the failed attempt and the acceptance:\n%s", out)
	}
}

func TestRun_NotAcceptedByTheDeadlineExitsOne(t *testing.T) {
	var errOut bytes.Buffer
	code := run(context.Background(), []string{"-deadline", "30ms", "-every", "5ms"}, &errOut, func(context.Context) error {
		return errors.New("pvh-n1: /cluster/status: the cluster is not quorate")
	})
	if code != 1 || !strings.Contains(errOut.String(), "not accepted before the deadline") || !strings.Contains(errOut.String(), "not quorate") {
		t.Fatalf("exit %d, want 1 naming the deadline and the last failure\n%s", code, errOut.String())
	}
}

func TestRun_UsageErrorsExitTwo(t *testing.T) {
	for _, args := range [][]string{{"-deadline", "0"}, {"-deadline", "-1s"}, {"-every", "0"}, {"-every", "-1s"}, {"extra"}, {"-nope"}, {"-deadline", "soon"}} {
		var errOut bytes.Buffer
		called := false
		code := run(context.Background(), args, &errOut, func(context.Context) error { called = true; return nil })
		if code != 2 || called {
			t.Errorf("%q: exit %d (attempted %v), want 2 and no attempt", args, code, called)
		}
	}
}

// A signal ends the wait with 128+signum, never a pass.
func TestRun_ASignalEndsIt(t *testing.T) {
	var errOut bytes.Buffer
	code := run(context.Background(), []string{"-deadline", "10s", "-every", "10ms"}, &errOut, func(ctx context.Context) error {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("the signal never reached the attempt's context")
		}
		return ctx.Err()
	})
	if code != 143 || !strings.Contains(errOut.String(), "interrupted") {
		t.Fatalf("exit %d, want 143\n%s", code, errOut.String())
	}
}

// Unflagged, the whole wait is bounded at 15 minutes.
func TestRun_TheDefaultDeadlineIsFifteenMinutes(t *testing.T) {
	var errOut bytes.Buffer
	code := run(context.Background(), nil, &errOut, func(ctx context.Context) error {
		d, ok := ctx.Deadline()
		if left := time.Until(d); !ok || left > 15*time.Minute || left < 15*time.Minute-10*time.Second {
			t.Errorf("the attempt's deadline is %v away (set: %v), want 15 minutes", left, ok)
		}
		return nil
	})
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, errOut.String())
	}
}
