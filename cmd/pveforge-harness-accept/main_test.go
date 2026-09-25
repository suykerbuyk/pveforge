package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
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

// A signal ends the wait with 128+signum, never a pass and never "not
// accepted". The attempt signals the process and returns only once its
// context is cancelled: whatever the scheduling from there, the status must
// come from the signal (the 5 s bound only catches a signal that never
// arrives; it synchronises nothing).
func TestRun_ASignalEndsIt(t *testing.T) {
	for sig, want := range map[syscall.Signal]int{syscall.SIGTERM: 143, syscall.SIGINT: 130} {
		var errOut bytes.Buffer
		code := run(context.Background(), []string{"-deadline", "10s", "-every", "10ms"}, &errOut, func(ctx context.Context) error {
			if err := syscall.Kill(syscall.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Error("the signal never reached the attempt's context")
			}
			return ctx.Err()
		})
		if code != want || !strings.Contains(errOut.String(), "interrupted ("+sig.String()+")") {
			t.Fatalf("%v: exit %d, want %d\n%s", sig, code, want, errOut.String())
		}
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

// laggingSignals stands in for os/signal. os/signal hands a signal to each
// channel registered for it in turn, and a subscriber may act on it (cancel a
// context) before a later channel has it. This delivers to the FIRST channel
// registered at once, and to any later one only after run has returned: the
// latest os/signal may deliver it. A status decided from one subscriber's
// record is right under any delivery order; one that waits on a second
// subscriber it cannot be sure has been handed the signal is not.
type laggingSignals struct {
	mu    sync.Mutex
	chans []chan<- os.Signal
	late  []os.Signal
}

func (l *laggingSignals) notify(c chan<- os.Signal, _ ...os.Signal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.chans = append(l.chans, c)
}

func (l *laggingSignals) stop(chan<- os.Signal) {}

func (l *laggingSignals) send(s os.Signal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.chans) == 0 {
		panic("a signal before any subscriber")
	}
	l.chans[0] <- s
	l.late = append(l.late, s)
}

// flush hands the held signals to the later channels, after run returned.
func (l *laggingSignals) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.chans[1:] {
		for _, s := range l.late {
			select {
			case c <- s:
			default:
			}
		}
	}
}

// The status of a signalled wait is decided by the signal, whatever order
// the signal reaches the subscribers in: deterministic, no timing involved.
func TestRun_ASignalDecidesTheStatusUnderAnyDeliveryOrder(t *testing.T) {
	for sig, want := range map[syscall.Signal]int{syscall.SIGTERM: 143, syscall.SIGINT: 130} {
		l := &laggingSignals{}
		origN, origS := notifySignals, stopSignals
		notifySignals, stopSignals = l.notify, l.stop
		var errOut bytes.Buffer
		code := run(context.Background(), []string{"-deadline", "10s", "-every", "10ms"}, &errOut, func(ctx context.Context) error {
			l.send(sig)
			<-ctx.Done()
			return ctx.Err()
		})
		l.flush()
		notifySignals, stopSignals = origN, origS
		if code != want || !strings.Contains(errOut.String(), "interrupted ("+sig.String()+")") {
			t.Fatalf("%v: exit %d, want %d\n%s", sig, code, want, errOut.String())
		}
	}
}
