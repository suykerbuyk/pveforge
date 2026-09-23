package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// interruptError is the cancel cause of the command context when SIGINT or
// SIGTERM arrives. Its Signal method is what internal/lock recognises
// (lock.ErrLockWaitInterrupted is reported only for a cause that has one),
// and what runRoot turns into the exit status 128+signum.
type interruptError struct{ sig os.Signal }

// Error names the signal as a shell does: SIGINT, SIGTERM.
func (e interruptError) Error() string {
	switch e.sig {
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	}
	return e.sig.String()
}

// Signal is the signal that interrupted the command.
func (e interruptError) Signal() os.Signal { return e.sig }

// exitCode is the conventional status of a process ended by the signal:
// 128+signum, so 130 for SIGINT and 143 for SIGTERM.
func (e interruptError) exitCode() int {
	if s, ok := e.sig.(syscall.Signal); ok {
		return 128 + int(s)
	}
	return 1
}

// Seams over os/signal, so a test can deliver a signal on the channel and
// observe the Stop without signalling its own process.
var (
	notifySignals = signal.Notify
	stopSignals   = signal.Stop
)

// notifyInterrupt returns a context cancelled, with an interruptError cause,
// by the first SIGINT or SIGTERM. At that first signal it stops catching
// them, which restores their default disposition: a SECOND signal kills the
// process outright — the way out when the command is slow to stop: a
// cleanup that runs on its own detached context keeps going after the
// first signal. Both such cleanups are proven end to end through the CLI:
// bootstrap's removal of a fresh token
// (TestInterrupt_BootstrapCleanupRunsAfterTheFirstSignal) and the network
// stage revert (TestInterrupt_NetworkRevertRunsAfterTheFirstSignal). The
// kernel releases any lock the killed process held.
//
// It prints nothing: runRoot remains the one place a command's end is
// reported.
func notifyInterrupt(parent context.Context) context.Context {
	ctx, cancel := context.WithCancelCause(parent)
	ch := make(chan os.Signal, 1)
	notifySignals(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		stopSignals(ch)
		cancel(interruptError{sig: sig})
	}()
	return ctx
}
