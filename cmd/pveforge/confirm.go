package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The y/N confirmation `acl enable-vm-destroy` asks before it writes. There is
// no visible-line prompt elsewhere (the roster and PVE password prompts read
// secrets with echo off), so this is the one, in the style of the others:
// package-level seams a test replaces, the terminal test made on the real file
// descriptors, and a read a signal can end.
var (
	// confirmTerminal reports whether a person can be asked: stdin AND stderr
	// (where the question is written) must both be terminals. A question
	// nobody can see is a hang, so anything less is "no terminal".
	confirmTerminal = func() bool {
		return terminalAvailable(term.IsTerminal(int(os.Stdin.Fd())), term.IsTerminal(int(os.Stderr.Fd())))
	}
	// confirmInput is where the answer is read from.
	confirmInput = func() io.Reader { return os.Stdin }
	// confirmAsk asks the question and returns the answer.
	confirmAsk = askYesNo
)

// terminalAvailable is the whole decision, as a pure function of the two
// descriptors: both must be terminals. stdin alone would prompt into a
// redirected stderr nobody sees (a hang); stderr alone could not be answered.
func terminalAvailable(stdinTTY, stderrTTY bool) bool { return stdinTTY && stderrTTY }

const confirmPrompt = "Proceed? [y/N] "

// isAffirmative is the one place an answer is judged: "y" or "yes" in any
// case, around any whitespace, and nothing else. An empty line, a NUL, "yes
// please" and every other text are "no".
func isAffirmative(answer string) bool {
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true
	}
	return false
}

// askYesNo writes the fixed prompt to w and reads one line from in. The read
// runs in a goroutine so a signal (ctx done) ends the wait with
// roster.ErrPromptInterrupted, the same error the secret prompts return, which
// runRoot reports as 130/143. EOF with no text is "no"; any other read error
// is returned and the caller treats it as "no" too.
func askYesNo(ctx context.Context, in io.Reader, w io.Writer) (bool, error) {
	fmt.Fprint(w, confirmPrompt)
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(in).ReadString('\n')
		done <- result{line, err}
	}()
	select {
	case r := <-done:
		fmt.Fprintln(w)
		// select picks at random when both are ready: a line that arrived with
		// a signal is not an answer.
		if ctx.Err() != nil {
			return false, fmt.Errorf("%w (%v) at the confirmation prompt", roster.ErrPromptInterrupted, context.Cause(ctx))
		}
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return false, fmt.Errorf("read the answer: %w", r.err)
		}
		return isAffirmative(r.line), nil
	case <-ctx.Done():
		fmt.Fprintln(w)
		return false, fmt.Errorf("%w (%v) at the confirmation prompt", roster.ErrPromptInterrupted, context.Cause(ctx))
	}
}
