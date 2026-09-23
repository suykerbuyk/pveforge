package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// runRootInterruptible runs args through runRoot under a root context the
// test cancels with an interruptError, as notifyInterrupt's goroutine does
// on a real signal. It returns the exit code, stdout and stderr.
func runRootInterruptible(ctx context.Context, args ...string) (int, string, string) {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	code := runRoot(root, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestNotifyInterrupt_FirstSignalCancelsAndStopsCatching (B3): the context
// is cancelled by the first SIGINT with an interruptError cause, and
// catching is stopped first — so a second signal meets the default
// disposition and kills. Signals are delivered on the channel through the
// seams, never to this process.
func TestNotifyInterrupt_FirstSignalCancelsAndStopsCatching(t *testing.T) {
	var mu sync.Mutex
	var ch chan<- os.Signal
	var caught []os.Signal
	stopped := make(chan chan<- os.Signal, 1)
	origNotify, origStop := notifySignals, stopSignals
	notifySignals = func(c chan<- os.Signal, sigs ...os.Signal) {
		mu.Lock()
		ch, caught = c, sigs
		mu.Unlock()
	}
	stopSignals = func(c chan<- os.Signal) { stopped <- c }
	t.Cleanup(func() { notifySignals, stopSignals = origNotify, origStop })

	ctx := notifyInterrupt(context.Background())
	mu.Lock()
	gotCh, gotSigs := ch, caught
	mu.Unlock()
	if !slices.Equal(gotSigs, []os.Signal{syscall.SIGINT, syscall.SIGTERM}) {
		t.Fatalf("catching %v, want SIGINT and SIGTERM", gotSigs)
	}
	select {
	case <-ctx.Done():
		t.Fatal("the context ended before any signal")
	default:
	}

	gotCh <- syscall.SIGINT
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("the context did not end after SIGINT")
	}
	select {
	case c := <-stopped:
		if c != gotCh {
			t.Error("Stop was called on another channel than the one registered")
		}
	default:
		t.Error("catching was not stopped before the context was cancelled: a second signal would not kill")
	}
	var ie interruptError
	if !errors.As(context.Cause(ctx), &ie) || ie.Signal() != syscall.SIGINT || ie.Error() != "SIGINT" || ie.exitCode() != 130 {
		t.Errorf("cause = %v, want interruptError SIGINT with exit code 130", context.Cause(ctx))
	}
	if term := (interruptError{sig: syscall.SIGTERM}); term.Error() != "SIGTERM" || term.exitCode() != 143 {
		t.Errorf("SIGTERM reads as %q, exit %d; want SIGTERM, 143", term.Error(), term.exitCode())
	}
}

// interruptAfter returns a context an interruptError(sig) cancels after d.
func interruptAfter(t *testing.T, sig syscall.Signal, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	timer := time.AfterFunc(d, func() { cancel(interruptError{sig: sig}) })
	t.Cleanup(func() { timer.Stop(); cancel(nil) })
	return ctx
}

// TestInterrupt_WhileWaitingForTheLock (B4): a signal while vm set waits for
// a held lock exits 128+signum with the lock's own line: interrupted while
// waiting, so the operation did not start under the lock.
func TestInterrupt_WhileWaitingForTheLock(t *testing.T) {
	srv := newVMConfigServer(t, "", 0, "", nil)
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	holdLock(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})

	for _, tc := range []struct {
		sig  syscall.Signal
		name string
		code int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		code, _, stderr := runRootInterruptible(interruptAfter(t, tc.sig, 150*time.Millisecond),
			"vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4")
		if code != tc.code {
			t.Errorf("%s: exit %d, want %d; stderr %q", tc.name, code, tc.code, stderr)
		}
		want := "lock qa-pve-01/vm/100: interrupted while waiting for the lock (" + tc.name + "); the operation did not start under it"
		if strings.Count(stderr, "\n") != 1 || !strings.Contains(stderr, want) {
			t.Errorf("%s: stderr %q, want one line containing %q", tc.name, stderr, want)
		}
		if strings.Contains(stderr, "may or may not") {
			t.Errorf("%s: a wait that never got the lock must not suggest a change was sent: %q", tc.name, stderr)
		}
	}
}

// TestInterrupt_WhileHoldingTheLock (B5): a signal while vm set's write is
// in flight exits 130 with the error kept whole between the interrupt
// prefix and the may-or-may-not-have-been-applied note, and the lock is
// released on the way out.
func TestInterrupt_WhileHoldingTheLock(t *testing.T) {
	writeArrived := make(chan struct{}, 1)
	stop := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) {
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"digest":"d1","cores":"2"}}`))
			return
		}
		// Consume the body first: only then does net/http watch the
		// connection, so a client that gives up ends r.Context().
		_ = r.ParseForm()
		select {
		case writeArrived <- struct{}{}:
		default:
		}
		select { // the write hangs until the client gives up
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	defer srv.Close()
	defer close(stop) // runs first: no handler outlives the test
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		select {
		case <-writeArrived:
			cancel(interruptError{sig: syscall.SIGINT})
		case <-time.After(10 * time.Second):
		}
	}()
	code, _, stderr := runRootInterruptible(ctx, "vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4")
	if code != 130 {
		t.Fatalf("exit %d, want 130; stderr %q", code, stderr)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "interrupted (SIGINT): ") ||
		!strings.Contains(stderr, "; any change the command had already sent may or may not have been applied") {
		t.Errorf("stderr %q, want one interrupted line noting the write may or may not have been applied", stderr)
	}
	if strings.Contains(stderr, "did not start") {
		t.Errorf("an interrupt while holding the lock must not claim the operation did not start: %q", stderr)
	}
	unlock, err := lock.Mutation(lock.WithWait(context.Background(), time.Second), rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})
	if err != nil {
		t.Fatalf("the interrupted command left its lock held: %v", err)
	}
	_ = unlock()
}

// TestInterrupt_DuringAPITaskWait (B6): a signal while api post waits for
// its task exits 130; the UPID was printed at dispatch, and the final line
// keeps the task wait's own outcome-unknown error, UPID included, whole.
func TestInterrupt_DuringAPITaskWait(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	f := &apiTaskFake{
		mutPath:     "/nodes/qa-pve-01/qemu/100/status/start",
		body:        `"` + upid + `"`,
		status:      func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "running", "") },
		onFirstPoll: func() { cancel(interruptError{sig: syscall.SIGINT}) },
	}
	rosterPath := newAPITaskServer(t, f)

	code, _, stderr := runRootInterruptible(ctx, "api", "post", "--roster", rosterPath, "/nodes/qa-pve-01/qemu/100/status/start", "qa-pve-01")
	if code != 130 {
		t.Fatalf("exit %d, want 130; stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "dispatched PVE task") || !strings.Contains(lines[0], upid) {
		t.Fatalf("stderr %q: want the dispatch line, then one final line", stderr)
	}
	final := lines[1]
	if !strings.HasPrefix(final, "interrupted (SIGINT): ") || !strings.Contains(final, "wait for task "+upid) ||
		!strings.HasSuffix(final, "may or may not have been applied") {
		t.Errorf("final line %q: want the task wait's own error, UPID included, inside the interrupt prefix and note", final)
	}
}

// TestInterrupt_AfterTheWriteSucceeded (B7): a signal that lands after vm
// set's write succeeded ends only the reads after it. The outcome was
// observed, so the exit is 0: the applied line on stdout; on stderr
// post-apply-err's re-read warning, then (T15, post-apply-verify) the
// pending check's warning, since the cancelled context ends that read too;
// and no "interrupted" line.
func TestInterrupt_AfterTheWriteSucceeded(t *testing.T) {
	var mu sync.Mutex
	config := map[string]string{"digest": "d1", "cores": "2"}
	gets := 0
	reread := make(chan struct{}, 1)
	stop := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			mu.Lock()
			for k, v := range r.PostForm {
				if k != "digest" {
					config[k] = v[0]
				}
			}
			mu.Unlock()
			return
		}
		mu.Lock()
		gets++
		n := gets
		body, _ := json.Marshal(config)
		mu.Unlock()
		if n == 3 { // Run's re-read, after the write
			reread <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-stop:
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + string(body) + `}`))
	}))
	defer srv.Close()
	defer close(stop) // runs first: no handler outlives the test
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		select {
		case <-reread:
			cancel(interruptError{sig: syscall.SIGINT})
		case <-time.After(10 * time.Second):
		}
	}()
	code, stdout, stderr := runRootInterruptible(ctx, "vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (the write was observed); stderr %q", code, stderr)
	}
	if stdout != "qa-pve-01: cores=4\n" {
		t.Errorf("stdout %q, want the applied line", stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 2 ||
		!strings.HasPrefix(lines[0], "warning: qa-pve-01: vm 100: the write was applied but its result could not be re-read: ") ||
		!strings.HasPrefix(lines[1], "warning: qa-pve-01: vm 100: the change was applied but whether it is pending could not be checked: ") ||
		!strings.Contains(lines[1], "SIGINT") {
		t.Errorf("stderr %q, want exactly the re-read warning, then the pending check's, which names the signal", stderr)
	}
	if strings.Contains(stderr, "interrupted (") {
		t.Errorf("a completed command must not be reported as interrupted: %q", stderr)
	}
}

// TestPromptCallSitesUseTheContext (B9): no non-test file of this package
// resolves the roster passphrase without the command's context, which is
// what lets a signal end the prompt. Anti-vacuity: the context-aware form
// is still what the two call sites use.
func TestPromptCallSitesUseTheContext(t *testing.T) {
	const rosterPkg = "github.com/suykerbuyk/pveforge/internal/roster"
	plain := sourceguard.Target{ImportPath: rosterPkg, Name: "ResolvePassphrase"}
	withCtx := sourceguard.Target{ImportPath: rosterPkg, Name: "ResolvePassphraseContext"}
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{Root: "."}, []sourceguard.Target{plain, withCtx})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	uses := 0
	for _, refs := range res.Refs {
		for _, r := range refs {
			switch r.Target {
			case plain:
				t.Errorf("%s: resolve the passphrase with ResolvePassphraseContext(cmd.Context()), so a signal ends the prompt", r)
			case withCtx:
				uses++
			}
		}
	}
	if uses < 2 {
		t.Errorf("ResolvePassphraseContext is referenced %d times, want at least 2 (target.go, bootstrap.go): the guard is not looking at the call sites", uses)
	}
}
