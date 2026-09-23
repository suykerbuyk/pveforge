package roster

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

// withTermSeams points ReadSecret's terminal seams at read, recording
// restores, for the rest of the test.
func withTermSeams(t *testing.T, read func(int) ([]byte, error)) (state *term.State, restored *[]*term.State) {
	t.Helper()
	state = &term.State{}
	restored = &[]*term.State{}
	origRead, origGet, origRestore := readPassword, getTermState, restoreTermFn
	readPassword = read
	getTermState = func(int) (*term.State, error) { return state, nil }
	restoreTermFn = func(_ int, s *term.State) error {
		*restored = append(*restored, s)
		return nil
	}
	t.Cleanup(func() { readPassword, getTermState, restoreTermFn = origRead, origGet, origRestore })
	return state, restored
}

// TestReadSecret_ReturnsTheSecret: an ordinary read returns what was typed,
// and does not touch the terminal state itself (term.ReadPassword restores
// its own).
func TestReadSecret_ReturnsTheSecret(t *testing.T) {
	_, restored := withTermSeams(t, func(int) ([]byte, error) { return []byte("s3cret"), nil })
	b, err := ReadSecret(context.Background(), 0, "roster passphrase")
	if err != nil || string(b) != "s3cret" {
		t.Fatalf("ReadSecret = %q, %v; want s3cret", b, err)
	}
	if len(*restored) != 0 {
		t.Errorf("an ordinary read restored the terminal itself %d times", len(*restored))
	}
}

// TestReadSecret_InterruptedRestoresTheTerminal (B8): when the context ends
// during the read, ReadSecret returns at once — the read is still blocked —
// with ErrPromptInterrupted naming the prompt and the cause, and puts the
// terminal back as it was before the prompt.
func TestReadSecret_InterruptedRestoresTheTerminal(t *testing.T) {
	// The fake read ends by itself after 2s, so a ReadSecret that ignored
	// the context fails here by name rather than hanging the package.
	release := make(chan struct{})
	time.AfterFunc(2*time.Second, func() { close(release) })
	state, restored := withTermSeams(t, func(int) ([]byte, error) {
		<-release
		return nil, errors.New("released")
	})

	ctx, cancel := context.WithCancelCause(context.Background())
	time.AfterFunc(20*time.Millisecond, func() { cancel(errors.New("SIGINT")) })
	start := time.Now()
	_, err := ReadSecret(ctx, 0, "roster passphrase")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("ReadSecret took %v to return after the context ended", elapsed)
	}
	if !errors.Is(err, ErrPromptInterrupted) {
		t.Fatalf("want ErrPromptInterrupted, got: %v", err)
	}
	if want := "interrupted (SIGINT) at the roster passphrase prompt"; err.Error() != want {
		t.Errorf("text = %q, want %q (the location only)", err.Error(), want)
	}
	if len(*restored) != 1 || (*restored)[0] != state {
		t.Errorf("restored %v, want exactly the state saved before the prompt", *restored)
	}
}

// TestReadSecret_TerminalStateUnavailable_FailsClosed: when the terminal's
// state cannot be saved, ReadSecret refuses before reading anything — it
// could not restore echo afterwards — and restores nothing.
func TestReadSecret_TerminalStateUnavailable_FailsClosed(t *testing.T) {
	reads := 0
	_, restored := withTermSeams(t, func(int) ([]byte, error) {
		reads++
		return []byte("s3cret"), nil
	})
	getTermState = func(int) (*term.State, error) { return nil, errors.New("not a terminal") }

	b, err := ReadSecret(context.Background(), 0, "roster passphrase")
	if err == nil || b != nil {
		t.Fatalf("ReadSecret = %q, %v; want an error and no secret", b, err)
	}
	if !strings.Contains(err.Error(), "save terminal state") || errors.Is(err, ErrPromptInterrupted) {
		t.Errorf("err = %v, want the save-state failure, not an interrupt", err)
	}
	if reads != 0 || len(*restored) != 0 {
		t.Errorf("reads=%d restores=%d, want neither: nothing may be read without a state to restore", reads, len(*restored))
	}
}
