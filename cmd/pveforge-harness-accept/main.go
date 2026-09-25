// Command pveforge-harness-accept waits for the nested harness cluster to be
// whole (pveforge-harness-golden-reset, P1): through the nested-harness guard
// (internal/harness Open: the nested roster only, the cluster's and every
// node's identity, a pinned SSH dial), then quorum, a connected QDevice, the
// shared storage active and each node's own status. Every attempt is whole,
// Open included, and attempts repeat until one passes or the deadline.
//
// Usage: pveforge-harness-accept [-deadline 15m] [-every 30s]
//
// It is built and run by hack/harness/golden.sh and reset.sh, with the
// environment Open requires (PVEFORGE_HARNESS_ROSTER,
// PVEFORGE_HARNESS_OUTER_ROSTERS, the roster passphrase; PVEFORGE_ROSTER,
// PVEFORGE_PVE_PASSWORD and every proxy variable unset). Exit status: 0
// accepted, 1 not accepted by the deadline, 2 a usage error, 130 or 143 on
// a signal.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/suykerbuyk/pveforge/internal/harness"
)

// notifySignals and stopSignals are signal.Notify and signal.Stop; a test
// replaces them to deliver a signal in the order os/signal may, not the one
// the scheduler happens to pick.
var (
	notifySignals = signal.Notify
	stopSignals   = signal.Stop
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr, harness.AcceptOnce))
}

// run is main without the process: attempt is one whole acceptance attempt.
func run(ctx context.Context, args []string, stderr io.Writer, attempt func(context.Context) error) int {
	fs := flag.NewFlagSet("pveforge-harness-accept", flag.ContinueOnError)
	fs.SetOutput(stderr)
	deadline := fs.Duration("deadline", 15*time.Minute, "give up after this long")
	every := fs.Duration("every", 30*time.Second, "wait this long between attempts")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *deadline <= 0 || *every <= 0 {
		fmt.Fprintln(stderr, "usage: pveforge-harness-accept [-deadline 15m] [-every 30s] (both positive)")
		return 2
	}
	// One subscriber, and the signal it receives is the cancellation's cause:
	// context.Cause is set before the context reports Done, so once the wait
	// has ended on a cancelled context, which signal ended it is already
	// known. (Two subscribers, a signal.NotifyContext and a separate channel
	// read without waiting, raced: under load the context could be cancelled
	// and the wait end before the signal reached the channel, and a Ctrl-C
	// or TERM was reported as "not accepted", 1.)
	sigc := make(chan os.Signal, 1)
	notifySignals(sigc, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals(sigc)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		select {
		case s := <-sigc:
			cancel(signalCause{s})
		case <-ctx.Done():
		}
	}()

	err := harness.Await(ctx, *deadline, *every, attempt, func(n int, err error) {
		fmt.Fprintf(stderr, "pveforge-harness-accept: attempt %d: %v\n", n, err)
	})
	if err == nil {
		fmt.Fprintln(stderr, "pveforge-harness-accept: the nested cluster is accepted")
		return 0
	}
	// A signal decides the status whenever it cancelled the wait, even one
	// that raced the deadline.
	var sc signalCause
	if errors.As(context.Cause(ctx), &sc) {
		fmt.Fprintf(stderr, "pveforge-harness-accept: interrupted (%v)\n", sc.sig)
		if sc.sig == syscall.SIGTERM {
			return 143
		}
		return 130
	}
	fmt.Fprintf(stderr, "pveforge-harness-accept: %v\n", err)
	return 1
}

// signalCause is the cancellation cause a signal gives the wait's context.
type signalCause struct{ sig os.Signal }

func (c signalCause) Error() string { return "interrupted by " + c.sig.String() }
