// Command pveforge is a standalone Go CLI for Proxmox VE cluster lifecycle
// management. See docs/prd.md for the design.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
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
//   - vm snapshot rollback's rollback completed and its witness was then
//     interrupted (errRollbackCompletedWitnessInterrupted): that error says
//     so, and is printed as it is — the generic note below would contradict
//     "completed";
//   - vm create --unique-tag's VM was created and its wait to be listed was
//     then interrupted (errVMCreatedTagWaitInterrupted): that error says
//     so, and is printed as it is, for the same reason;
//   - anything else: the error, never replaced — an outcome-unknown or UPID
//     text keeps at least its head (boundErrText) — between "interrupted (SIGINT): " and a note that a
//     change already sent may or may not have been applied.
//
// An interrupted run exits 128+signum: 130 for SIGINT, 143 for SIGTERM.
//
// It also gives every command a context that reports a PVE task which
// succeeded with warnings (pve.WithTaskWarnings): pveforge counts such a
// task as a success, as PVE does, and says so on stderr, one quoted line
// per task, so the warnings are never silent. The exit status is unchanged.
// The notice's values come from PVE (the UPID from a mutation's answer), so
// each is bounded (boundErrText) and quoted like error text.
func runRoot(root *cobra.Command, stderr io.Writer) int {
	root.SetErr(stderr)
	ctx := root.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	root.SetContext(pve.WithTaskWarnings(ctx, taskWarningsNotice(stderr)))
	err := root.Execute()
	if err == nil {
		return 0
	}
	// Bounded first, so the interrupt wrapping below is never what is cut.
	msg, code := boundErrText(err.Error()), 1
	var ie interruptError
	if ctx := root.Context(); ctx != nil && errors.As(context.Cause(ctx), &ie) {
		code = ie.exitCode()
		if !errors.Is(err, lock.ErrLockWaitInterrupted) && !errors.Is(err, roster.ErrPromptInterrupted) && !errors.Is(err, errRollbackCompletedWitnessInterrupted) && !errors.Is(err, errVMCreatedTagWaitInterrupted) {
			msg = fmt.Sprintf("interrupted (%s): %s; any change the command had already sent may or may not have been applied", ie, msg)
		}
	}
	fmt.Fprintln(stderr, kvjson.QuoteValue(msg))
	return code
}

// taskWarningsNotice is the reporter runRoot installs: one line on stderr
// per PVE task that succeeded with warnings. Each value is bounded and
// quoted like error text. WaitForTask already refuses a UPID outside PVE's
// grammar, so none can hold a line break; the quoting stays regardless.
func taskWarningsNotice(stderr io.Writer) pve.TaskWarningsFunc {
	return func(node, upid, exitStatus string) {
		fmt.Fprintf(stderr, "notice: PVE task %s on node %s succeeded with warnings (%s): its task log has them\n",
			kvjson.QuoteValue(boundErrText(upid)), kvjson.QuoteValue(boundErrText(node)), kvjson.QuoteValue(boundErrText(exitStatus)))
	}
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
	root.AddCommand(newUserCmd())
	root.AddCommand(newGroupCmd())
	root.AddCommand(newACLCmd())
	root.AddCommand(newAccessCmd())
	root.AddCommand(newSchemaCmd())
	// cobra adds these two only inside Execute; add them now so the walk
	// below covers completion's group as well.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	refuseUnknownSubcommands(root)
	return root
}

// refuseUnknownSubcommands makes every command group in c's tree (a command
// with subcommands and no Run of its own) fail when it is run as anything
// but a request for its help. cobra runs a group by printing its help and
// succeeding, before it looks at the group's arguments, so without this
// `pveforge vm destroy` (there is no such verb) and `pveforge vm $VERB`
// with an empty $VERB both exit 0 having done nothing. A script driving
// destructive operations must see both fail.
//
// A group given an argument refuses it as an unknown command. A bare group
// prints its help to stderr and fails as a usage error. Explicit help
// (--help, -h, `pveforge help vm`) is unchanged: exit 0, help on stdout.
func refuseUnknownSubcommands(c *cobra.Command) {
	if c.HasSubCommands() && !c.Runnable() {
		c.Args = unknownSubcommand
		c.RunE = bareGroup
	}
	for _, s := range c.Commands() {
		refuseUnknownSubcommands(s)
	}
}

// unknownSubcommand is a group's Args: any argument is a subcommand that
// does not exist, since a known one would have been run instead.
func unknownSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	msg := fmt.Sprintf("unknown command %q for %q", args[0], cmd.CommandPath())
	// SuggestionsFor reads the command's own distance, which cobra defaults
	// to 2 only on its own unknown-command path (findSuggestions): left at
	// 0, only an exact name or a prefix would ever be suggested, never a
	// typo. Set it the way cobra does, only when unset — idempotent, and
	// the field is read by nothing else.
	if cmd.SuggestionsMinimumDistance <= 0 {
		cmd.SuggestionsMinimumDistance = 2
	}
	// No suggestion for an empty argument (anything is "near" it), nor one
	// that is the argument itself (`pveforge -- vm`: vm is a real command,
	// taken here as an argument after "--").
	if s := cmd.SuggestionsFor(args[0]); args[0] != "" && len(s) > 0 && s[0] != args[0] {
		msg += fmt.Sprintf("; did you mean %q?", s[0])
	}
	return errors.New(msg)
}

// bareGroup is a group's RunE, reached only with no arguments. It writes the
// group's help to stderr as cobra's default help func renders it (Long, else
// Short, right-trimmed, then UsageString; pveforge sets no help func or
// template of its own), without cmd.SetOut, which would persist on the
// command: a tree run again, as in a test, would then print an explicit
// `--help` to stderr too.
func bareGroup(cmd *cobra.Command, _ []string) error {
	w := cmd.ErrOrStderr()
	if usage := strings.TrimRightFunc(cmp.Or(cmd.Long, cmd.Short), unicode.IsSpace); usage != "" {
		fmt.Fprintf(w, "%s\n\n", usage)
	}
	fmt.Fprint(w, cmd.UsageString())
	return fmt.Errorf("%s: a subcommand is required", cmd.CommandPath())
}
