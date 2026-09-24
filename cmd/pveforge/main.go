// Command pveforge is a standalone Go CLI for Proxmox VE cluster lifecycle
// management. See docs/prd.md for the design.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

func main() {
	os.Exit(realMain())
}

// realMain is main without the exit, so a test can re-execute the test
// binary as pveforge itself. The root carries a context that the first
// SIGINT/SIGTERM cancels (notifyInterrupt); cobra hands it to every
// command as cmd.Context().
func realMain() int {
	root := newRootCmd()
	root.SetContext(notifyInterrupt(context.Background()))
	return runRoot(root, os.Stderr)
}

// runRoot executes root and returns the process exit code. It is the ONE
// place any command's final error is printed, and it prints it as a single
// line: kvjson.QuoteValue writes the text as a JSON string when it could be
// misread (a line break or other control character, edge whitespace, a
// leading quote), so server text embedded in an error (a pveum stderr, a
// 5xx body) can never forge a second line such as "warning: ...". An error
// text that needs no quoting prints exactly as before. Before it is quoted,
// the text is bounded (boundErrText), so a server body cannot make that one
// line arbitrarily long either. Commands' own stderr lines
// (cmd.ErrOrStderr()) go to the same writer.
//
// When a signal interrupted the command (root's context was cancelled by
// notifyInterrupt), it reports only what was observed:
//
//   - the command completed anyway: its outcome was observed, so exit 0;
//   - it was waiting for an object lock (lock.ErrLockWaitInterrupted): that
//     error already says so, and that the operation did not start under the
//     lock — it is printed as it is;
//   - it was at a secret prompt (roster.ErrPromptInterrupted): that error
//     names the prompt, and is printed as it is;
//   - anything else: the error, never replaced — an outcome-unknown or UPID
//     text keeps at least its head (boundErrText) — between "interrupted (SIGINT): " and a note that a
//     change already sent may or may not have been applied.
//
// An interrupted run exits 128+signum: 130 for SIGINT, 143 for SIGTERM.
func runRoot(root *cobra.Command, stderr io.Writer) int {
	root.SetErr(stderr)
	err := root.Execute()
	if err == nil {
		return 0
	}
	// Bounded first, so the interrupt wrapping below is never what is cut.
	msg, code := boundErrText(err.Error()), 1
	var ie interruptError
	if ctx := root.Context(); ctx != nil && errors.As(context.Cause(ctx), &ie) {
		code = ie.exitCode()
		if !errors.Is(err, lock.ErrLockWaitInterrupted) && !errors.Is(err, roster.ErrPromptInterrupted) {
			msg = fmt.Sprintf("interrupted (%s): %s; any change the command had already sent may or may not have been applied", ie, msg)
		}
	}
	fmt.Fprintln(stderr, kvjson.QuoteValue(msg))
	return code
}

// maxErrTextBytes bounds the error text boundErrText lets through: far
// above any PVE diagnostic (a parameter-error map, a message), far below a
// proxy's HTML error page or a body echoed back whole.
const maxErrTextBytes = 4096

// boundErrText returns s unchanged when it is at most maxErrTextBytes
// long; otherwise its head, cut on a UTF-8 boundary, followed by
// " … [N bytes elided]". Every site that prints an error's text calls it on
// that text before quoting it (kvjson.QuoteValue), so the quoting sees
// exactly what is printed and stays one valid line.
//
// It bounds only what is printed. The error keeps its whole text, and
// every in-process reader of it — the not-found and digest classifiers, and
// bootstrap.Import's secret redaction, which must see an echoed secret
// whole to remove it — runs on that full text, before this cut.
func boundErrText(s string) string {
	if len(s) <= maxErrTextBytes {
		return s
	}
	cut := maxErrTextBytes
	// Back off to the start of the rune the bound falls in: at most
	// utf8.UTFMax-1 continuation bytes, so invalid input cannot walk far.
	for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(s[cut]); i++ {
		cut--
	}
	return fmt.Sprintf("%s … [%d bytes elided]", s[:cut], len(s)-cut)
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pveforge",
		Short:         "Proxmox VE cluster lifecycle management",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRosterCmd())
	root.AddCommand(newBootstrapCmd())
	root.AddCommand(newVMCmd())
	root.AddCommand(newNodeCmd())
	root.AddCommand(newStorageCmd())
	root.AddCommand(newNetworkCmd())
	root.AddCommand(newDiscoverCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newExecCmd())
	root.AddCommand(newSchemaCmd())
	return root
}
