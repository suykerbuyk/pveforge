package pve

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pveforge-vm-rollback-witness (5c).

// guestSentinel is guest output no witness error may ever carry.
const guestSentinel = "GUEST-OUTPUT-SENTINEL"

// witnessFake scripts the two agent endpoints. dispatch answers each
// POST .../agent/exec in turn (the last repeats): "pid" accepts with pid 7,
// "refuse" is PVE's 500, a bare number is that HTTP status, "drop" hijacks
// and closes the connection (a transport error), "hang" never answers.
// status answers each exec-status poll the same way ("hang" included).
type witnessFake struct {
	mu         sync.Mutex // guards dispatch, which W11 swaps mid-run
	dispatch   []string
	status     []string
	dispatches atomic.Int32
	polls      atomic.Int32
	// onDispatch, when set, runs inside each dispatch before it is
	// answered — W9 uses it to end the caller's context mid-request.
	onDispatch func()
	// stop releases every "hang" handler. newWitness closes it in a cleanup
	// that runs BEFORE the server's own Close, which otherwise waits
	// forever on a handler whose client has gone.
	stop chan struct{}
}

func (f *witnessFake) pick(list []string, n int32) string {
	if int(n) <= len(list) {
		return list[n-1]
	}
	return list[len(list)-1]
}

func (f *witnessFake) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/agent/exec") {
		f.mu.Lock()
		answer := f.pick(f.dispatch, f.dispatches.Add(1))
		hook := f.onDispatch
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		if code, err := strconv.Atoi(answer); err == nil {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		switch answer {
		case "hang":
			select {
			case <-r.Context().Done():
			case <-f.stop:
			}
		case "pid":
			_, _ = w.Write([]byte(`{"data":{"pid":7}}`))
		case "refuse":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null,"errors":{"agent":"QEMU guest agent is not running"}}`))
		case "drop":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
		return
	}
	body := f.pick(f.status, f.polls.Add(1))
	if body == "hang" {
		select {
		case <-r.Context().Done():
		case <-f.stop:
		}
		return
	}
	_, _ = w.Write([]byte(`{"data":` + body + `}`))
}

func newWitness(t *testing.T, f *witnessFake) *Client {
	t.Helper()
	orig := defaultAgentExecPollInterval
	defaultAgentExecPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { defaultAgentExecPollInterval = orig })
	f.stop = make(chan struct{})
	c := testClient(t, newFakeAPIServer(t, f.serve))
	t.Cleanup(func() { close(f.stop) }) // registered after the server: runs first
	return c
}

func witnessReason(t *testing.T, err error) WitnessReason {
	t.Helper()
	var we *RollbackWitnessError
	if !errors.As(err, &we) {
		t.Fatalf("err = %v, want a *RollbackWitnessError", err)
	}
	if !IsRollbackNotWitnessed(err) {
		t.Errorf("IsRollbackNotWitnessed = false for %v", err)
	}
	if strings.Contains(err.Error(), guestSentinel) {
		t.Errorf("the error text carries guest output: %q", err)
	}
	return we.Reason
}

// W1: a succeeding command proves the rollback, with the marker in its
// output or with no marker asked for (exit-only proof).
func TestRollbackWitness_W1_Success(t *testing.T) {
	f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":0}`, `{"exited":1,"exitcode":0,"out-data":"mark-1\n"}`}}
	c := newWitness(t, f)
	status, err := c.RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/echo", "mark-1"}, "mark-1", time.Second)
	if err != nil || !status.Succeeded() {
		t.Fatalf("RollbackWitness = %+v, %v; want a witnessed success", status, err)
	}
	if n := f.polls.Load(); n < 2 {
		t.Errorf("polled %d time(s): the witness did not wait for the exit", n)
	}
	f2 := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":1,"exitcode":0}`}}
	if _, err := newWitness(t, f2).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", time.Second); err != nil {
		t.Errorf("no marker asked for: %v", err)
	}
}

// W2: the command ran and did not succeed — a non-zero exit, a signal kill
// (QGA sends no exitcode, so ExitCode reads 0 — Succeeded, never ExitCode,
// must judge it), or an exit with no exit code at all. The status comes
// back as data; the error carries the numbers, never the output.
func TestRollbackWitness_W2_CommandFailed(t *testing.T) {
	for name, tc := range map[string]struct {
		status, want string
	}{
		"non-zero exit":    {`{"exited":1,"exitcode":3,"out-data":"` + guestSentinel + `","err-data":"` + guestSentinel + `"}`, "(exit code 3)"},
		"killed by signal": {`{"exited":1,"signal":9,"out-data":"` + guestSentinel + `"}`, "(killed by signal 9)"},
		"no exit code":     {`{"exited":1,"out-data":"` + guestSentinel + `"}`, "(it exited with no exit code)"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &witnessFake{dispatch: []string{"pid"}, status: []string{tc.status}}
			status, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", time.Second)
			if witnessReason(t, err) != WitnessCommandFailed {
				t.Errorf("reason = %v, want WitnessCommandFailed", err)
			}
			if status == nil || status.OutData != guestSentinel {
				t.Errorf("status = %+v: want the command's status returned as data", status)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want %q", err, tc.want)
			}
		})
	}
}

// W3: the command succeeded but its output lacks the marker.
func TestRollbackWitness_W3_MarkerMissing(t *testing.T) {
	f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":1,"exitcode":0,"out-data":"` + guestSentinel + `"}`}}
	status, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/echo", "m"}, "the-marker", time.Second)
	if witnessReason(t, err) != WitnessMarkerMissing || status == nil {
		t.Errorf("err = %v, status %v; want WitnessMarkerMissing with the status", err, status)
	}
}

// W4: output truncated with the marker absent is WitnessOutputTruncated —
// the marker may be in the part that was cut — never WitnessMarkerMissing;
// truncated WITH the marker present is still a success.
func TestRollbackWitness_W4_Truncated(t *testing.T) {
	f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":1,"exitcode":0,"out-truncated":1,"out-data":"` + guestSentinel + `"}`}}
	_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/echo", "m"}, "the-marker", time.Second)
	if witnessReason(t, err) != WitnessOutputTruncated {
		t.Errorf("err = %v, want WitnessOutputTruncated", err)
	}
	f2 := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":1,"exitcode":0,"out-truncated":true,"out-data":"the-marker then more"}`}}
	if _, err := newWitness(t, f2).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/echo", "m"}, "the-marker", time.Second); err != nil {
		t.Errorf("truncated with the marker present: %v, want success", err)
	}
}

// W5: dispatch refused by PVE (a typed answer: the command did not start)
// is retried until it is accepted.
func TestRollbackWitness_W5_RefusedDispatchIsRetried(t *testing.T) {
	f := &witnessFake{dispatch: []string{"refuse", "refuse", "pid"}, status: []string{`{"exited":1,"exitcode":0}`}}
	if _, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", 2*time.Second); err != nil {
		t.Fatalf("RollbackWitness: %v", err)
	}
	if n := f.dispatches.Load(); n != 3 {
		t.Errorf("dispatches = %d, want 3 (two refusals, then the accepted one)", n)
	}
}

// W6: dispatch refused until the deadline is WitnessNeverResponded, carrying
// PVE's last refusal (typed) and the attempt count.
func TestRollbackWitness_W6_RefusedUntilTheDeadline(t *testing.T) {
	f := &witnessFake{dispatch: []string{"refuse"}}
	_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", 60*time.Millisecond)
	if witnessReason(t, err) != WitnessNeverResponded {
		t.Fatalf("err = %v, want WitnessNeverResponded", err)
	}
	var we *RollbackWitnessError
	errors.As(err, &we)
	// The last attempt may be cut by the deadline before the server sees it,
	// so the server's count is Dispatches or one less.
	_, typed := HTTPStatus(we.Last)
	seen := int(f.dispatches.Load())
	if !typed || we.Dispatches < 2 || (seen != we.Dispatches && seen != we.Dispatches-1) {
		t.Errorf("Last %v, Dispatches %d (server saw %d): want PVE's typed refusal and every attempt counted", we.Last, we.Dispatches, f.dispatches.Load())
	}
	if f.polls.Load() != 0 {
		t.Error("a status poll without an accepted dispatch")
	}
}

// W7: a transport error on dispatch is never retried — the command may have
// run — and is returned as it is, not as a witness reason. The server-side
// count is the proof (a retry on a fresh connection would show as 2).
func TestRollbackWitness_W7_TransportErrorIsNotRetried(t *testing.T) {
	f := &witnessFake{dispatch: []string{"drop", "pid"}, status: []string{`{"exited":1,"exitcode":0}`}}
	_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", time.Second)
	if err == nil || IsRollbackNotWitnessed(err) {
		t.Fatalf("err = %v, want the transport error itself", err)
	}
	if _, typed := HTTPStatus(err); typed {
		t.Fatalf("err = %v: the fixture was meant to be a transport error", err)
	}
	if n := f.dispatches.Load(); n != 1 {
		t.Errorf("dispatches = %d, want exactly 1", n)
	}
}

// W8: a dispatched command whose exit is never observed is
// WitnessNeverResponded, wrapping the exec wait's own timeout.
func TestRollbackWitness_W8_ExitNeverObserved(t *testing.T) {
	f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":0}`}}
	_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", 60*time.Millisecond)
	if witnessReason(t, err) != WitnessNeverResponded || !IsAgentExecTimeoutError(err) {
		t.Errorf("err = %v, want WitnessNeverResponded wrapping the AgentExecTimeoutError", err)
	}
}

// W9: the caller's context ending — while dispatch is being retried, or
// while the exit is awaited, whether the cancel lands between requests or
// in the middle of one — is passed through: never a witness reason, the
// cancellation reachable with errors.Is, the cause on the context. Run
// under -count to cover both landings; a refusal that arrives as the caller
// stops must not come back as a plain PVE failure.
func TestRollbackWitness_W9_CancellationPassesThrough(t *testing.T) {
	cause := errors.New("interrupted by the caller")
	for name, f := range map[string]*witnessFake{
		"during dispatch retries": {dispatch: []string{"refuse"}},
		"during the exit wait":    {dispatch: []string{"pid"}, status: []string{`{"exited":0}`}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newWitness(t, f)
			ctx, cancel := context.WithCancelCause(context.Background())
			var once sync.Once
			go func() {
				time.Sleep(30 * time.Millisecond)
				once.Do(func() { cancel(cause) })
			}()
			_, err := c.RollbackWitness(ctx, "qa-pve-01", 100, []string{"/bin/true"}, "", 5*time.Second)
			if err == nil || IsRollbackNotWitnessed(err) || !errors.Is(err, context.Canceled) {
				t.Errorf("err = %v, want the cancellation itself, not a witness reason", err)
			}
			if !errors.Is(context.Cause(ctx), cause) {
				t.Errorf("cause = %v, want the caller's", context.Cause(ctx))
			}
		})
	}
	// Deterministically in the middle of a dispatch: the fake ends the
	// caller's context inside the request, then refuses it. Whatever the
	// attempt returns — the refusal or the transport's cancellation — the
	// outcome is the caller's stop.
	t.Run("in the middle of a dispatch", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		f := &witnessFake{dispatch: []string{"refuse"}}
		f.onDispatch = func() { cancel(cause) }
		c := newWitness(t, f)
		_, err := c.RollbackWitness(ctx, "qa-pve-01", 100, []string{"/bin/true"}, "", 5*time.Second)
		if err == nil || IsRollbackNotWitnessed(err) || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want the cancellation itself, not a witness reason or the refusal", err)
		}
		if n := f.dispatches.Load(); n != 1 {
			t.Errorf("dispatches = %d, want 1: no retry after the caller stopped", n)
		}
	})
}

// W10: the default command's nonce is fresh on every call, and a stale
// answer — the previous nonce, as a restored agent could replay — fails.
func TestRollbackWitness_W10_DefaultCommandNonce(t *testing.T) {
	cmd1, want1, err1 := DefaultRollbackWitnessCommand()
	cmd2, want2, err2 := DefaultRollbackWitnessCommand()
	if err1 != nil || err2 != nil {
		t.Fatalf("DefaultRollbackWitnessCommand: %v, %v", err1, err2)
	}
	if want1 == want2 || len(want1) < 32 {
		t.Fatalf("nonces %q and %q: want two distinct, long nonces", want1, want2)
	}
	if len(cmd1) != 2 || cmd1[0] != "/bin/echo" || cmd1[1] != want1 || cmd2[1] != want2 {
		t.Errorf("commands %q / %q: want /bin/echo of each nonce", cmd1, cmd2)
	}
	f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":1,"exitcode":0,"out-data":"` + want1 + `\n"}`}}
	_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, cmd2, want2, time.Second)
	if witnessReason(t, err) != WitnessMarkerMissing {
		t.Errorf("a stale nonce: err = %v, want WitnessMarkerMissing", err)
	}
}

// W11: one deadline for everything. Dispatch is refused for most of it,
// then accepted, and the exit never comes: the exec wait gets only what
// remained, so it times out with a Timeout below the witness's, and the
// whole call ends near the witness deadline, not at twice it.
func TestRollbackWitness_W11_OneSharedDeadline(t *testing.T) {
	const timeout = 200 * time.Millisecond
	f := &witnessFake{status: []string{`{"exited":0}`}}
	start := time.Now()
	f.dispatch = []string{"refuse"}
	c := newWitness(t, f)
	go func() {
		time.Sleep(120 * time.Millisecond)
		f.mu.Lock()
		f.dispatch = []string{"pid"}
		f.mu.Unlock()
	}()
	_, err := c.RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", timeout)
	elapsed := time.Since(start)
	if witnessReason(t, err) != WitnessNeverResponded {
		t.Fatalf("err = %v, want WitnessNeverResponded", err)
	}
	var te *AgentExecTimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v: the dispatch was never accepted, so the exec wait was not reached", err)
	}
	// 120ms of the 200ms went to refused dispatches, so the wait had at
	// most 80ms: anything near the full 200ms means its deadline was reset.
	if te.Timeout > timeout-100*time.Millisecond {
		t.Errorf("the exec wait was given %v, not what remained of the %v deadline after 120ms of dispatch", te.Timeout, timeout)
	}
	if elapsed > timeout+100*time.Millisecond {
		t.Errorf("took %v for a %v deadline: the deadline was not shared", elapsed, timeout)
	}
}

// cancelAfterPoll is a transport that answers exec-status polls in full,
// then — before handing the answer back — ends the caller's context and
// waits until past the witness deadline. WaitForAgentExec then meets its
// final select with its context AND its deadline both ready, where Go
// picks at random: the case the caller's-stop-first rule exists for.
type cancelAfterPoll struct {
	next   http.RoundTripper
	cancel func()
	after  time.Duration
}

func (c *cancelAfterPoll) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err != nil || !strings.HasSuffix(r.URL.Path, "/agent/exec-status") {
		return resp, err
	}
	body, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	c.cancel()
	time.Sleep(c.after)
	return resp, nil
}

// W12 (R1): a caller's stop that lands just as the deadline does is still
// the caller's stop — never WitnessNeverResponded. Run 40 times: the race
// it guards is a 50/50 pick, so a missing check survives 2^-40 of runs.
// (About 6s: each run waits out the 150ms sleep.)
func TestRollbackWitness_W12_CancelAtTheDeadline(t *testing.T) {
	cause := errors.New("interrupted at the deadline")
	for i := 0; i < 40; i++ {
		f := &witnessFake{dispatch: []string{"pid"}, status: []string{`{"exited":0}`}}
		c := newWitness(t, f)
		ctx, cancel := context.WithCancelCause(context.Background())
		next := c.httpClient.Transport
		if next == nil {
			next = http.DefaultTransport // netguard's loopback-only clone, under this package's TestMain
		}
		// The dispatch must beat the deadline (100ms, generous under -race),
		// and the transport then sleeps past it (150ms) after cancelling.
		c.httpClient.Transport = &cancelAfterPoll{next: next, cancel: func() { cancel(cause) }, after: 150 * time.Millisecond}
		_, err := c.RollbackWitness(ctx, "qa-pve-01", 100, []string{"/bin/true"}, "", 100*time.Millisecond)
		cancel(nil)
		if err == nil || IsRollbackNotWitnessed(err) || !errors.Is(err, context.Canceled) {
			t.Fatalf("run %d: err = %v, want the caller's stop, not a witness reason", i, err)
		}
	}
}

// W13 (C): the sleep between refused dispatches never runs past the
// deadline. With a poll interval far longer than the deadline, as in
// production (500ms against a short witness), an unclamped sleep would
// overshoot it by the whole interval.
func TestRollbackWitness_W13_RetrySleepStopsAtTheDeadline(t *testing.T) {
	f := &witnessFake{dispatch: []string{"refuse"}}
	c := newWitness(t, f)
	defaultAgentExecPollInterval = 400 * time.Millisecond // newWitness restores it
	start := time.Now()
	_, err := c.RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", 60*time.Millisecond)
	elapsed := time.Since(start)
	if witnessReason(t, err) != WitnessNeverResponded {
		t.Fatalf("err = %v, want WitnessNeverResponded", err)
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("took %v for a 60ms deadline: the retry sleep ran past it", elapsed)
	}
}

// W14 (F): a typed 4xx is not retried — a bad request or a refused
// credential will not change — and is returned at once, as it is: typed,
// with its code, and not as WitnessNeverResponded.
func TestRollbackWitness_W14_A4xxIsNotRetried(t *testing.T) {
	for _, code := range []string{"400", "401", "403", "404"} {
		t.Run(code, func(t *testing.T) {
			f := &witnessFake{dispatch: []string{code, "pid"}, status: []string{`{"exited":1,"exitcode":0}`}}
			_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", time.Second)
			if got, ok := HTTPStatus(err); !ok || strconv.Itoa(got) != code || IsRollbackNotWitnessed(err) {
				t.Errorf("err = %v, want the typed %s itself", err, code)
			}
			if n := f.dispatches.Load(); n != 1 {
				t.Errorf("dispatches = %d, want 1", n)
			}
			if auth := code == "401" || code == "403"; errors.Is(err, ErrNotAuthorized) != auth {
				t.Errorf("errors.Is(err, ErrNotAuthorized) wrong for %s", code)
			}
		})
	}
}

// W15, W16: a request that hangs — a dispatch, or a status poll — cannot
// outlive the witness deadline (the HTTP client's own timeout is 30s): it
// ends as WitnessNeverResponded within the deadline plus the wait's grace.
func TestRollbackWitness_W15_W16_AHungRequestIsBounded(t *testing.T) {
	for name, f := range map[string]*witnessFake{
		"W15 dispatch hangs": {dispatch: []string{"hang"}},
		"W16 poll hangs":     {dispatch: []string{"pid"}, status: []string{"hang"}},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := newWitness(t, f).RollbackWitness(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "", 80*time.Millisecond)
			elapsed := time.Since(start)
			if witnessReason(t, err) != WitnessNeverResponded {
				t.Fatalf("err = %v, want WitnessNeverResponded", err)
			}
			if elapsed > 80*time.Millisecond+witnessWaitGrace+200*time.Millisecond {
				t.Errorf("took %v: a hung request outlived the 80ms deadline", elapsed)
			}
		})
	}
}
