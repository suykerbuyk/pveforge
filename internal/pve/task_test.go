package pve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// wellFormedUPID returns a UPID string shaped like a real one PVE would
// return: 9 colon-separated fields (8 colons) — "UPID:<node>:<pid>:
// <pstart>:<starttime>:<type>:<id>:<user>:" — with node embedded as given.
func wellFormedUPID(node string) string {
	return fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:qmstart:100:root@pam:", node)
}

// taskStatusHandler serves /nodes/{node}/tasks/{upid}/status, returning
// "running" for the first respondRunning calls and "stopped"/exitStatus
// after that. It counts every request it receives so tests can assert the
// server was (or wasn't) ever actually hit.
//
// Every response body echoes back "upid" and "node", matching real PVE
// task-status responses (confirmed against go-proxmox's own recorded
// fixtures in tests/mocks/pve9x/tasks.go). proxmox.Task.UnmarshalJSON
// copies every field present in the response body onto the Task,
// including UPID and Node, so a body missing them clobbers both with zero
// values; on a REUSED Task a later poll would then request
// /nodes//tasks//status or nil-panic inside Ping. WaitForTask polls a
// fresh Task each time, so for it the echo is no longer load-bearing, but
// fixtures keep sending both fields because real PVE always does.
func taskStatusHandler(t *testing.T, upid, node string, respondRunning int, exitStatus string) (http.HandlerFunc, *int32) {
	t.Helper()
	var calls int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if int(n) <= respondRunning {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"running","upid":%q,"node":%q}}`, upid, node)))
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":%q,"upid":%q,"node":%q}}`, exitStatus, upid, node)))
	}
	return handler, &calls
}

// withTaskTimings overrides the package-level poll interval/timeout for
// the duration of one test, restoring the originals afterward — the same
// reason these are vars and not consts: none of these tests can be
// allowed to actually wait out the real 1s/10m production defaults. It
// goes through the exported SetTaskTimingsForTests rather than assigning
// the vars itself, so this package and cmd/pveforge share one mechanism.
func withTaskTimings(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	t.Cleanup(SetTaskTimingsForTests(interval, timeout))
}

// TestWaitForTask_ImmediatelySuccessful covers the case where the very
// first poll already reports the task stopped with exitstatus OK. This
// also serves as this package's integration-style test for WaitForTask:
// it drives the full path (Client.WaitForTask -> proxmox.NewTask ->
// its poll loop -> Task.Ping) through a real httptest.Server over real HTTP,
// with nothing internally mocked — see the task description's requirement
// for one such end-to-end test; this one (together with
// TestWaitForTask_PollsUntilStopped below, which proves the poll loop
// actually loops over real HTTP round trips) satisfies it, so no separate
// TestWaitForTask_Integration is needed.
func TestWaitForTask_ImmediatelySuccessful(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	upid := wellFormedUPID("qa-pve-01")
	handler, calls := taskStatusHandler(t, upid, "qa-pve-01", 0, "OK")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	if err := c.WaitForTask(context.Background(), "qa-pve-01", upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	if got := atomic.LoadInt32(calls); got < 1 {
		t.Fatalf("expected at least one status poll, got %d", got)
	}
}

// TestWaitForTask_PollsUntilStopped proves the poll loop actually loops:
// the first poll reports "running", and only a later poll reports
// "stopped"/OK. Uses a tiny overridden poll interval so the test doesn't
// sleep for a full second.
func TestWaitForTask_PollsUntilStopped(t *testing.T) {
	withTaskTimings(t, 2*time.Millisecond, time.Second)
	upid := wellFormedUPID("qa-pve-01")
	handler, calls := taskStatusHandler(t, upid, "qa-pve-01", 3, "OK")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	if err := c.WaitForTask(context.Background(), "qa-pve-01", upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	if got := atomic.LoadInt32(calls); got < 2 {
		t.Fatalf("expected multiple polls before completion, got %d", got)
	}
}

// TestWaitForTask_FailedExitStatus covers a task that runs to completion
// but with a non-OK exitstatus: WaitForTask must return an error that
// errors.As-matches *TaskFailedError with the right ExitStatus.
func TestWaitForTask_FailedExitStatus(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	upid := wellFormedUPID("qa-pve-01")
	handler, _ := taskStatusHandler(t, upid, "qa-pve-01", 0, "unable to lock config")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	err := c.WaitForTask(context.Background(), "qa-pve-01", upid)
	if err == nil {
		t.Fatal("expected an error for a non-OK exitstatus")
	}
	var failed *TaskFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("expected *TaskFailedError, got: %v", err)
	}
	if failed.ExitStatus != "unable to lock config" {
		t.Fatalf("ExitStatus = %q, want %q", failed.ExitStatus, "unable to lock config")
	}
	if failed.UPID != upid {
		t.Fatalf("UPID = %q, want %q", failed.UPID, upid)
	}
	if IsTaskOutcomeUnknown(err) {
		t.Fatalf("a task that ran and reported failure is an observed outcome, not an unknown one: %v", err)
	}
}

// TestWaitForTask_ContextCanceled covers a context canceled mid-poll:
// WaitForTask must return promptly with an error wrapping ctx.Err(),
// rather than hanging. The fake server always reports "running", and the
// test cancels the context shortly after the first poll — with a tiny
// overridden poll interval, well before the test's own deadline.
func TestWaitForTask_ContextCanceled(t *testing.T) {
	withTaskTimings(t, 2*time.Millisecond, time.Minute)
	upid := wellFormedUPID("qa-pve-01")
	handler, _ := taskStatusHandler(t, upid, "qa-pve-01", 1<<30, "OK") // always "running"
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.WaitForTask(ctx, "qa-pve-01", upid)
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected an error after context cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected error wrapping context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForTask did not return promptly after context cancellation")
	}
}

// TestWaitForTask_Timeout overrides defaultTaskWaitTimeout to a tiny value
// against a task that always reports "running": WaitForTask must return
// an error wrapping proxmox.ErrTimeout, and the test itself must complete
// quickly (nowhere near the real 10-minute default).
func TestWaitForTask_Timeout(t *testing.T) {
	withTaskTimings(t, 5*time.Millisecond, 30*time.Millisecond)
	upid := wellFormedUPID("qa-pve-01")
	handler, _ := taskStatusHandler(t, upid, "qa-pve-01", 1<<30, "OK") // always "running"
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	start := time.Now()
	err := c.WaitForTask(context.Background(), "qa-pve-01", upid)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("WaitForTask took %s, expected it to time out quickly", elapsed)
	}
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, proxmox.ErrTimeout) {
		t.Fatalf("expected error wrapping proxmox.ErrTimeout, got: %v", err)
	}
	if !IsTaskTimeoutError(err) {
		t.Fatalf("expected IsTaskTimeoutError, got: %v", err)
	}
	if !IsTaskOutcomeUnknown(err) {
		t.Fatalf("a timeout leaves the task's outcome unknown; expected IsTaskOutcomeUnknown, got: %v", err)
	}
}

// TestWaitForTask_NodeMismatch covers a well-formed UPID whose embedded
// node differs from the node argument passed to WaitForTask: WaitForTask
// must return an error, and the fake server's status handler must never
// be invoked at all for this node/upid pair.
func TestWaitForTask_NodeMismatch(t *testing.T) {
	upid := wellFormedUPID("other-node")
	handler, calls := taskStatusHandler(t, upid, "other-node", 0, "OK")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	err := c.WaitForTask(context.Background(), "qa-pve-01", upid)
	if err == nil {
		t.Fatal("expected an error for a node/upid mismatch")
	}
	if !IsTaskOutcomeUnknown(err) {
		t.Fatalf("a pre-check refusal still leaves a dispatched task unobserved; expected IsTaskOutcomeUnknown, got: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("expected the fake server to never be called, got %d calls", got)
	}
}

// TestWaitForTask_MalformedUPIDBoundary is the specific gap a design
// review flagged: a UPID with exactly 6 colons / 7 fields — one field
// short of a real UPID's trailing "<user>:". Through v0.8.2-pveforge.1 it
// passed proxmox.NewTask's "len(sp) < 7" guard and then panicked indexing
// sp[7]; v0.8.2-pveforge.2 fixed that (TestForkNewTask_ShortUPIDDoesNotPanic).
// WaitForTask still rejects this shape itself, as outside PVE's UPID
// grammar, before proxmox.NewTask or any network call — this asserts both
// the clean error AND that the fake server never receives a request,
// proving the pre-check short-circuits strictly before NewTask.
func TestWaitForTask_MalformedUPIDBoundary(t *testing.T) {
	const malformed = "UPID:node1:1234:5678:aaaa:qmcreate:100" // 6 colons / 7 fields
	handler, calls := taskStatusHandler(t, malformed, "node1", 0, "OK")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	err := c.WaitForTask(context.Background(), "node1", malformed)
	if err == nil {
		t.Fatal("expected an error for a malformed upid")
	}
	if !IsTaskOutcomeUnknown(err) {
		t.Fatalf("a pre-check refusal still leaves a dispatched task unobserved; expected IsTaskOutcomeUnknown, got: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("expected the fake server to never be called, got %d calls", got)
	}
}

// TestIsTaskTimeoutError covers pve.IsTaskTimeoutError's own contract
// directly: true for proxmox.ErrTimeout both bare and %w-wrapped (the
// shape WaitForTask's own error actually takes), false for nil and for an
// unrelated error. New exported API surface, tested in isolation from
// WaitForTask's own timeout test (TestWaitForTask_Timeout above already
// covers that WaitForTask's error wraps proxmox.ErrTimeout; this test
// covers the predicate built on top of that fact).
func TestIsTaskTimeoutError(t *testing.T) {
	if !IsTaskTimeoutError(proxmox.ErrTimeout) {
		t.Error("expected true for the bare proxmox.ErrTimeout sentinel")
	}
	wrapped := fmt.Errorf("wait for task %s: %w", wellFormedUPID("qa-pve-01"), proxmox.ErrTimeout)
	if !IsTaskTimeoutError(wrapped) {
		t.Error("expected true for a %w-wrapped proxmox.ErrTimeout")
	}
	if IsTaskTimeoutError(nil) {
		t.Error("expected false for a nil error")
	}
	if IsTaskTimeoutError(errors.New("some unrelated failure")) {
		t.Error("expected false for an unrelated error")
	}
}

// TestWaitForTask_RequiresNodeAndUPID covers the plain empty-input guards.
func TestWaitForTask_RequiresNodeAndUPID(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node or upid is empty")
	}))

	if err := c.WaitForTask(context.Background(), "", wellFormedUPID("qa-pve-01")); err == nil || !IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error for an empty node, got %v", err)
	} else if !strings.Contains(err.Error(), "node is required") {
		t.Fatalf("expected the empty-node refusal to say node is required, got %v", err)
	}
	if err := c.WaitForTask(context.Background(), "qa-pve-01", ""); err == nil || !IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected an outcome-unknown error for an empty upid, got %v", err)
	}
}

// --- WaitForTask's poll loop: transient polls and outcome classification --
//
// pveforge-status-error-pin-bump replaced go-proxmox's Task.Wait with
// WaitForTask's own loop. On v0.8.2-pveforge.0 a 404/502-504/595-599 poll
// was swallowed and Task.Wait rode it out by accident; on .1 each is a
// *proxmox.StatusError, which Task.Wait returns at once. The tests below
// pin the loop's contract: up to 3 CONSECUTIVE transient failures ridden
// out, any other failure (and the 4th transient) an outcome-unknown error,
// and only a stopped task with a real non-OK exit status a TaskFailedError.

// pollAction is what the scripted task-status server does with one poll.
type pollAction int

const (
	pollServe  pollAction = iota // answer status/body
	pollHijack                   // close the connection without answering
	pollBlock                    // hold the request until the client gives up
)

// pollStep is one scripted answer to a task-status poll.
type pollStep struct {
	status int
	body   string
	action pollAction
}

// taskScript is a scripted task-status server: poll N gets steps[N], and
// the last step repeats. Keep-alives are OFF, so every poll arrives on a
// fresh connection: net/http transparently retries a replayable GET whose
// REUSED connection was dropped, which would silently absorb a hijacked
// poll and make a transport-error test vacuous. conns counts accepted
// connections, so a test can prove no such retry happened.
type taskScript struct {
	upid, node string
	steps      []pollStep
	hits       int32
	conns      int32
}

func (s *taskScript) running() pollStep {
	return pollStep{200, fmt.Sprintf(`{"data":{"status":"running","upid":%q,"node":%q}}`, s.upid, s.node), pollServe}
}

func (s *taskScript) stopped(exitStatus string) pollStep {
	return pollStep{200, fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":%q,"upid":%q,"node":%q}}`, exitStatus, s.upid, s.node), pollServe}
}

func (s *taskScript) status(status string) pollStep {
	return pollStep{200, fmt.Sprintf(`{"data":{"status":%q,"upid":%q,"node":%q}}`, status, s.upid, s.node), pollServe}
}

func nullPoll(status int) pollStep { return pollStep{status, nullData, pollServe} }

func repeatPoll(step pollStep, n int) []pollStep {
	out := make([]pollStep, n)
	for i := range out {
		out[i] = step
	}
	return out
}

func newTaskScript(node string) *taskScript {
	return &taskScript{upid: wellFormedUPID(node), node: node}
}

// client starts the scripted server and returns a Client pointed at it.
func (s *taskScript) client(t *testing.T, steps ...pollStep) *Client {
	t.Helper()
	s.steps = steps
	wantPrefix := fmt.Sprintf("/nodes/%s/tasks/", s.node)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&s.hits, 1))
		if !strings.HasPrefix(r.URL.Path, wantPrefix) || !strings.HasSuffix(r.URL.Path, "/status") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusTeapot)
			return
		}
		step := s.steps[len(s.steps)-1]
		if n <= len(s.steps) {
			step = s.steps[n-1]
		}
		switch step.action {
		case pollHijack:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		case pollBlock:
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
				t.Errorf("blocked poll was never abandoned by the client")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(step.status)
		_, _ = w.Write([]byte(step.body))
	}))
	srv.Config.SetKeepAlivesEnabled(false)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			atomic.AddInt32(&s.conns, 1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return testClient(t, srv)
}

func (s *taskScript) polls() int { return int(atomic.LoadInt32(&s.hits)) }

func requirePolls(t *testing.T, s *taskScript, want int) {
	t.Helper()
	if got := s.polls(); got != want {
		t.Fatalf("status polls = %d, want exactly %d", got, want)
	}
}

// requireOutcomeUnknown fails unless err is classified as a task whose
// outcome was never observed: IsTaskOutcomeUnknown, and never a claim that
// the task ran and reported failure.
func requireOutcomeUnknown(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var failed *TaskFailedError
	if errors.As(err, &failed) {
		t.Fatalf("got a TaskFailedError (%v) for a task whose outcome was never observed", err)
	}
	if !IsTaskOutcomeUnknown(err) {
		t.Fatalf("expected IsTaskOutcomeUnknown for %v", err)
	}
}

// W1: one 595 mid-wait is ridden out, as .0 did by accident.
func TestWaitForTask_RidesOutOneTransientPoll(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.running(), nullPoll(595), s.stopped("OK"))

	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	requirePolls(t, s, 3)
}

// W2: the tolerance is bounded — the 4th consecutive transient poll aborts,
// long before the deadline, and it is not reported as a task failure or a
// timeout.
func TestWaitForTask_FourthConsecutiveTransientPollAborts(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, append([]pollStep{s.running()}, repeatPoll(nullPoll(595), 4)...)...)

	err := c.WaitForTask(context.Background(), s.node, s.upid)
	requireOutcomeUnknown(t, err)
	if IsTaskTimeoutError(err) {
		t.Fatalf("the bound fired as a timeout, not after 4 transient polls: %v", err)
	}
	var se *proxmox.StatusError
	if !errors.As(err, &se) || se.StatusCode != 595 {
		t.Fatalf("expected the last poll's *proxmox.StatusError 595 in the chain, got %v", err)
	}
	requirePolls(t, s, 5)
}

// W3: exactly 3 consecutive transient polls are still ridden out.
func TestWaitForTask_ThreeConsecutiveTransientPollsAreRiddenOut(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	steps := append([]pollStep{s.running()}, repeatPoll(nullPoll(595), 3)...)
	c := s.client(t, append(steps, s.stopped("OK"))...)

	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	requirePolls(t, s, 5)
}

// W4: the bound counts CONSECUTIVE failures: a successful poll resets it.
func TestWaitForTask_SuccessfulPollResetsTheTransientCount(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	var steps []pollStep
	steps = append(steps, s.running())
	steps = append(steps, repeatPoll(nullPoll(595), 3)...)
	steps = append(steps, s.running())
	steps = append(steps, repeatPoll(nullPoll(595), 3)...)
	c := s.client(t, append(steps, s.stopped("OK"))...)

	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	requirePolls(t, s, 9)
}

// W5: every status in the transient set is ridden out.
func TestWaitForTask_EachTransientStatusIsRiddenOut(t *testing.T) {
	for _, code := range []int{502, 503, 504, 595, 596, 597, 598, 599} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			withTaskTimings(t, time.Millisecond, time.Second)
			s := newTaskScript("qa-pve-01")
			c := s.client(t, s.running(), nullPoll(code), s.stopped("OK"))

			if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
				t.Fatalf("WaitForTask: %v", err)
			}
			requirePolls(t, s, 3)
		})
	}
}

// W6: any other failed poll aborts at once. A 404 means an unknown UPID or
// a wrong path, which polling again cannot fix.
func TestWaitForTask_NonTransientPollAbortsAtOnce(t *testing.T) {
	for _, code := range []int{400, 401, 404, 500, 501} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			withTaskTimings(t, time.Millisecond, time.Second)
			s := newTaskScript("qa-pve-01")
			c := s.client(t, s.running(), nullPoll(code), s.stopped("OK"))

			err := c.WaitForTask(context.Background(), s.node, s.upid)
			requireOutcomeUnknown(t, err)
			requirePolls(t, s, 2)
			if code == 401 {
				// go-proxmox answers 401/403 with its own ErrNotAuthorized,
				// never a StatusError.
				if !proxmox.IsNotAuthorized(err) {
					t.Fatalf("expected proxmox.IsNotAuthorized, got %v", err)
				}
				return
			}
			var se *proxmox.StatusError
			if !errors.As(err, &se) || se.StatusCode != code {
				t.Fatalf("expected *proxmox.StatusError %d in the chain, got %v", code, err)
			}
			if got := proxmox.IsNotFound(err); got != (code == 404) {
				t.Fatalf("proxmox.IsNotFound = %v for a %d", got, code)
			}
		})
	}
}

// W7: a poll with no status is not a finished task. Task.Wait took an
// empty status for "not running", so null answers read as a false
// "task failed" with an empty exit status.
func TestWaitForTask_NullPollsAreNotATaskFailure(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, nullPoll(200), nullPoll(200), s.stopped("OK"))

	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	requirePolls(t, s, 3)
}

// W8: null polls count against the same bound. Only a fresh Task per poll
// can see them: a reused Task keeps its stale "running" through a null
// decode and would ride them all the way to the deadline.
func TestWaitForTask_NullPollsMidWaitAreBounded(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, append([]pollStep{s.running()}, repeatPoll(nullPoll(200), 4)...)...)

	err := c.WaitForTask(context.Background(), s.node, s.upid)
	requireOutcomeUnknown(t, err)
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead in the chain, got %v", err)
	}
	if IsTaskTimeoutError(err) {
		t.Fatalf("null polls rode out to the deadline instead of hitting the bound: %v", err)
	}
	requirePolls(t, s, 5)
}

// W9: a dropped connection mid-wait is a transport error, and transient.
// conns == polls proves net/http did not silently retry the dropped poll.
func TestWaitForTask_RidesOutADroppedConnection(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.running(), pollStep{action: pollHijack}, s.stopped("OK"))

	if err := c.WaitForTask(context.Background(), s.node, s.upid); err != nil {
		t.Fatalf("WaitForTask: %v", err)
	}
	requirePolls(t, s, 3)
	if got := atomic.LoadInt32(&s.conns); got != 3 {
		t.Fatalf("connections = %d, want 3 (one per poll): a transparent retry absorbed the dropped poll", got)
	}
}

// W12: a status outside PVE's "running"/"stopped" contract says nothing
// about how the task ended.
func TestWaitForTask_UnknownStatusIsNotATaskFailure(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.status("weird"))

	err := c.WaitForTask(context.Background(), s.node, s.upid)
	requireOutcomeUnknown(t, err)
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead in the chain, got %v", err)
	}
	// Terminal at once, never retried as a transient poll.
	requirePolls(t, s, 1)
}

// W15: "stopped" without an exit status is not a report of failure: PVE
// always sends one for a finished task.
func TestWaitForTask_StoppedWithoutExitStatusIsNotATaskFailure(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.status("stopped"))

	err := c.WaitForTask(context.Background(), s.node, s.upid)
	requireOutcomeUnknown(t, err)
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead in the chain, got %v", err)
	}
	// Terminal at once, never retried as a transient poll.
	requirePolls(t, s, 1)
}

// waitWithCancel runs WaitForTask, cancels its context after 20ms, and
// returns its error and how long it took, failing if it outlives 2s.
func waitWithCancel(t *testing.T, c *Client, s *taskScript) (error, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(20*time.Millisecond, cancel)

	start := time.Now()
	errCh := make(chan error, 1)
	go func() { errCh <- c.WaitForTask(ctx, s.node, s.upid) }()
	select {
	case err := <-errCh:
		return err, time.Since(start)
	case <-time.After(2 * time.Second):
		t.Fatal("WaitForTask did not return within 2s of its context being canceled")
		return nil, 0
	}
}

// W13: a cancel during the sleep between polls returns at once, not after
// the poll interval.
func TestWaitForTask_CanceledDuringSleepReturnsPromptly(t *testing.T) {
	withTaskTimings(t, 5*time.Second, time.Minute)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, s.running())

	err, _ := waitWithCancel(t, c, s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in the chain, got %v", err)
	}
	requireOutcomeUnknown(t, err)
	requirePolls(t, s, 1)
}

// W13b: a cancel during a poll (not during the sleep W13 covers) returns
// at once, and is outcome-unknown like every other unobserved end. It is
// never classified as a transient poll failure: the error reports the poll
// the cancel interrupted (its *url.Error), not a later wake-up.
func TestWaitForTask_CanceledDuringPollReturnsPromptly(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Minute)
	s := newTaskScript("qa-pve-01")
	c := s.client(t, pollStep{action: pollBlock})

	err, _ := waitWithCancel(t, c, s)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in the chain, got %v", err)
	}
	requireOutcomeUnknown(t, err)
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("expected the interrupted poll's *url.Error in the chain, got %v", err)
	}
	requirePolls(t, s, 1)
}

// W14: IsTaskOutcomeUnknown matches only errors WaitForTask itself marked.
// Its WaitForTask-produced true cases (pre-checks, polls, ctx, deadline)
// are asserted by the tests above; this pins the false side.
func TestIsTaskOutcomeUnknown(t *testing.T) {
	failed := &TaskFailedError{UPID: wellFormedUPID("qa-pve-01"), ExitStatus: "ERROR: x"}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"TaskFailedError", failed},
		{"wrapped TaskFailedError", fmt.Errorf("apply: %w", failed)},
		{"unrelated", errors.New("some unrelated failure")},
		// A proxmox.ErrTimeout that did not come from WaitForTask says
		// nothing about any task.
		{"bare proxmox.ErrTimeout", proxmox.ErrTimeout},
		{"wrapped proxmox.ErrTimeout", fmt.Errorf("other: %w", proxmox.ErrTimeout)},
		{"bare ErrUnverifiableRead", ErrUnverifiableRead},
	} {
		if IsTaskOutcomeUnknown(tc.err) {
			t.Errorf("%s: IsTaskOutcomeUnknown = true, want false", tc.name)
		}
	}
}

// TestUPIDNode_AgreesWithValidateUPIDShape (A9) pins the one shape rule
// WaitForTask and UPIDNode share. For every row, UPIDNode errors exactly
// when validateUPIDShape does — the two can only drift if one of them grows
// shape logic of its own — and never panics, which a 7-field string handed
// to proxmox.NewTask would. The boundary rows are the ones each rule turns
// on: 6 vs 7 colons for the field count, "XPID:" and "upid:" for the
// prefix, and an empty second field for the node.
// runeInUser is an otherwise valid UPID whose user field holds r.
func runeInUser(r string) string {
	return "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root" + r + "pam:"
}

// TestValidateUPIDShape_RuneRowsAreOtherwiseValid: the rune rows of
// TestUPIDNode_AgreesWithValidateUPIDShape are refused for their rune alone,
// never for their shape: the same UPID with an ordinary character there, or
// in the id or type fields, is accepted.
func TestValidateUPIDShape_RuneRowsAreOtherwiseValid(t *testing.T) {
	for _, upid := range []string{
		runeInUser("@"),
		"UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:1x0:root@pam:",
		"UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmxstart:100:root@pam:",
	} {
		if err := validateUPIDShape(upid); err != nil {
			t.Errorf("validateUPIDShape(%q) = %v, want nil", upid, err)
		}
	}
}

func TestUPIDNode_AgreesWithValidateUPIDShape(t *testing.T) {
	for _, c := range []struct {
		name     string
		upid     string
		wantNode string // "" means the shape must be refused
	}{
		{"real", wellFormedUPID("pve1"), "pve1"},
		{"real, captured shape", "UPID:qa-pve-02:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root@pam:", "qa-pve-02"},
		{"lowercase hex", "UPID:pve1:0003a1b2:0001c3d4:66f1a2b3:qmstart:100:root@pam:", "pve1"},
		{"9-digit pstart (long uptime)", "UPID:pve1:0003A1B2:10001C3D4:66F1A2B3:qmstart:100:root@pam:", "pve1"},
		{"10-digit pstart", "UPID:pve1:0003A1B2:110001C3D4:66F1A2B3:qmstart:100:root@pam:", ""},
		{"short pid", "UPID:pve1:0001:0001C3D4:66F1A2B3:qmstart:100:root@pam:", ""},
		{"non-hex starttime", "UPID:pve1:0003A1B2:0001C3D4:66F1A2BZ:qmstart:100:root@pam:", ""},
		{"no trailing colon", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root@pam", ""},
		{"a field too many", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root@pam:x:", ""},
		{"8 fields (7 colons)", "UPID:n:1:2:3:4:5:6", ""},
		{"7 fields (6 colons)", "UPID:n:1:2:3:4:5", ""},
		{"node with a comma", "UPID:qa,pve:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root@pam:", ""},
		{"node ending in a hyphen", "UPID:pve-:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:root@pam:", ""},
		{"slash in the id", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:1/0:root@pam:", ""},
		{"empty type", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3::100:root@pam:", ""},
		{"empty user", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:100::", ""},
		// Each of these differs from an accepted UPID in the one rune only
		// (TestValidateUPIDShape_RuneRowsAreOtherwiseValid).
		{"U+2028 in the user", runeInUser("\u2028"), ""},
		{"U+2029 in the user", runeInUser("\u2029"), ""},
		{"newline in the user", runeInUser("\n"), ""},
		{"space in the user", runeInUser(" "), ""},
		{"U+00A0 in the user", runeInUser("\u00a0"), ""},
		{"U+0085 in the id", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:1\u00850:root@pam:", ""},
		{"tab in the type", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qm\tstart:100:root@pam:", ""},
		{"escape character in the user", runeInUser("\x1b"), ""},
		{"non-ASCII letter in the user", "UPID:pve1:0003A1B2:0001C3D4:66F1A2B3:qmstart:100:j\u00f6rg@pve:", "pve1"},
		{"empty", "", ""},
		{"no prefix", "XPID:pve1:00001234:0000ABCD:5F000000:qmstart:100:root@pam:", ""},
		{"lowercase prefix", "upid:pve1:00001234:0000ABCD:5F000000:qmstart:100:root@pam:", ""},
		{"empty node", "UPID::1:2:3:4:5:6:", ""},
		// A real task with an EMPTY ID field (vzdump of all guests,
		// startall, aptupdate). "::" alone is not an empty node.
		{"empty id field", "UPID:pve1:00000001:00000002:5F000000:vzdump::root@pam:", "pve1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			shapeErr := validateUPIDShape(c.upid)
			node, nodeErr := UPIDNode(c.upid)
			if (shapeErr == nil) != (nodeErr == nil) {
				t.Fatalf("the two guards disagree on %q: validateUPIDShape=%v, UPIDNode=%v", c.upid, shapeErr, nodeErr)
			}
			if c.wantNode == "" {
				if nodeErr == nil {
					t.Fatalf("UPIDNode(%q) = %q, want a shape error", c.upid, node)
				}
				if !strings.Contains(nodeErr.Error(), "malformed upid") || !errors.Is(nodeErr, ErrUnverifiableRead) {
					t.Fatalf("UPIDNode(%q) error %q is not a malformed-upid unverifiable read", c.upid, nodeErr)
				}
				return
			}
			if nodeErr != nil || node != c.wantNode {
				t.Fatalf("UPIDNode(%q) = %q, %v; want %q, nil", c.upid, node, nodeErr, c.wantNode)
			}
		})
	}
}

// TestWaitForTask_RefusesPrefixAndNodeShapeErrorsBeforePolling covers the
// two rules validateUPIDShape added on top of the colon count: a UPID
// without the "UPID:" prefix and one with an empty node field are refused
// as outcome-unknown before any status poll.
func TestWaitForTask_RefusesPrefixAndNodeShapeErrorsBeforePolling(t *testing.T) {
	for _, upid := range []string{
		"XPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:root@pam:",
		"UPID::00001234:0000ABCD:5F000000:qmstart:100:root@pam:",
	} {
		t.Run(upid, func(t *testing.T) {
			handler, calls := taskStatusHandler(t, upid, "qa-pve-01", 0, "OK")
			c := testClient(t, newFakeAPIServer(t, handler))

			err := c.WaitForTask(context.Background(), "qa-pve-01", upid)
			requireOutcomeUnknown(t, err)
			if !strings.Contains(err.Error(), "malformed upid") {
				t.Fatalf("expected a malformed-upid refusal, got: %v", err)
			}
			if got := atomic.LoadInt32(calls); got != 0 {
				t.Fatalf("expected no status poll, got %d", got)
			}
		})
	}
}

// TestWaitForTask_ExitStatusRule pins taskExitSucceeded, PVE's own rule
// (PVE::UPID::status_is_error): "OK" and exactly "WARNINGS: <n>" are a
// success, and a warnings success is reported to ctx's TaskWarningsFunc —
// once, with the node, UPID and exit status — while a clean OK reports
// nothing. Every near miss is the task's error.
func TestWaitForTask_ExitStatusRule(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	upid := wellFormedUPID("qa-pve-01")
	cases := []struct {
		exit     string
		success  bool
		reported bool
	}{
		{"OK", true, false},
		{"WARNINGS: 1", true, true},
		{"WARNINGS: 12", true, true},
		{"WARNINGS: 12345", true, true},
		{"WARNINGS: 0", true, true},
		{"WARNINGS: ", false, false},
		{"WARNINGS: 1x", false, false},
		{"WARNINGS: -1", false, false},
		{"WARNINGS: 1\n", false, false},
		{"x WARNINGS: 1", false, false},
		{"warnings: 1", false, false},
		{"WARNING: 1", false, false},
		{"OK ", false, false},
		{"unable to lock config", false, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%q", tc.exit), func(t *testing.T) {
			handler, _ := taskStatusHandler(t, upid, "qa-pve-01", 0, tc.exit)
			c := testClient(t, newFakeAPIServer(t, handler))
			var reports []string
			ctx := WithTaskWarnings(context.Background(), func(node, u, exit string) {
				reports = append(reports, node+" "+u+" "+exit)
			})

			err := c.WaitForTask(ctx, "qa-pve-01", upid)

			if tc.success {
				if err != nil {
					t.Fatalf("WaitForTask = %v, want success", err)
				}
			} else {
				var failed *TaskFailedError
				if !errors.As(err, &failed) || failed.ExitStatus != tc.exit {
					t.Fatalf("WaitForTask = %v, want *TaskFailedError carrying %q", err, tc.exit)
				}
			}
			var want []string
			if tc.reported {
				want = []string{"qa-pve-01 " + upid + " " + tc.exit}
			}
			if !slices.Equal(reports, want) {
				t.Errorf("warnings reports = %q, want %q", reports, want)
			}
		})
	}
}

// TestWaitForTask_WarningsWithoutASink: a context carrying no
// TaskWarningsFunc still gets the success, and nothing panics.
func TestWaitForTask_WarningsWithoutASink(t *testing.T) {
	withTaskTimings(t, time.Millisecond, time.Second)
	upid := wellFormedUPID("qa-pve-01")
	handler, _ := taskStatusHandler(t, upid, "qa-pve-01", 0, "WARNINGS: 3")
	c := testClient(t, newFakeAPIServer(t, handler))
	if err := c.WaitForTask(context.Background(), "qa-pve-01", upid); err != nil {
		t.Fatalf("WaitForTask = %v, want success", err)
	}
}

// TestForkNewTask_ShortUPIDDoesNotPanic pins the fork behaviour
// WaitForTask's and UPIDNode's comments rely on at v0.8.2-pveforge.2:
// proxmox.NewTask on a UPID of 7 fields (which panicked indexing sp[7]
// through .1) or fewer returns a Task with no fields parsed, and parses a
// full one. pveforge's own validateUPIDShape still refuses these first.
func TestForkNewTask_ShortUPIDDoesNotPanic(t *testing.T) {
	for _, upid := range []string{
		"UPID:node1:1234:5678:aaaa:qmcreate:100", // 7 fields
		"UPID:node1:1234:5678:aaaa:qmcreate",     // 6 fields
		"UPID:node1",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("proxmox.NewTask(%q) panicked: %v", upid, r)
				}
			}()
			task := proxmox.NewTask(proxmox.UPID(upid), nil)
			if task == nil || task.Node != "" || task.User != "" {
				t.Errorf("proxmox.NewTask(%q) = %+v; want a Task with no parts parsed", upid, task)
			}
		}()
	}
	full := proxmox.NewTask("UPID:node1:00001234:0000ABCD:5F000000:qmcreate:100:root@pam:", nil)
	if full == nil || full.Node != "node1" || full.Type != "qmcreate" || full.ID != "100" || full.User != "root@pam" {
		t.Errorf("proxmox.NewTask(full UPID) = %+v", full)
	}
}
