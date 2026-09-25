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
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	err := harness.Await(ctx, *deadline, *every, attempt, func(n int, err error) {
		fmt.Fprintf(stderr, "pveforge-harness-accept: attempt %d: %v\n", n, err)
	})
	switch {
	case err == nil:
		fmt.Fprintln(stderr, "pveforge-harness-accept: the nested cluster is accepted")
		return 0
	case errors.Is(err, harness.ErrNotAccepted):
		fmt.Fprintf(stderr, "pveforge-harness-accept: %v\n", err)
		return 1
	default:
		select {
		case s := <-sig:
			fmt.Fprintf(stderr, "pveforge-harness-accept: interrupted (%v)\n", s)
			if s == syscall.SIGTERM {
				return 143
			}
			return 130
		default:
		}
		fmt.Fprintf(stderr, "pveforge-harness-accept: %v\n", err)
		return 1
	}
}
