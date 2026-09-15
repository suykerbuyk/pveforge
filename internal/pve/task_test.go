package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	proxmox "github.com/luthermonson/go-proxmox"
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
// fixtures in tests/mocks/pve9x/tasks.go) — deliberately, not for
// cosmetic realism: proxmox.Task.UnmarshalJSON copies every field present
// in the response body onto the Task, including UPID and Node, and a
// response body missing those would clobber them with zero values, which
// then causes a NIL POINTER PANIC inside go-proxmox's own Ping on any
// later poll that errors (NewTask("", ...) returns nil, and Ping
// dereferences that nil Task) — a second, independent manifestation of
// the same upstream fragility WaitForTask's pre-check guards against, and
// a wrinkle only in an incomplete test fixture: real PVE always sends
// these fields.
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
// allowed to actually wait out the real 1s/10m production defaults.
func withTaskTimings(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	origInterval, origTimeout := defaultTaskPollInterval, defaultTaskWaitTimeout
	defaultTaskPollInterval = interval
	defaultTaskWaitTimeout = timeout
	t.Cleanup(func() {
		defaultTaskPollInterval = origInterval
		defaultTaskWaitTimeout = origTimeout
	})
}

// TestWaitForTask_ImmediatelySuccessful covers the case where the very
// first poll already reports the task stopped with exitstatus OK. This
// also serves as this package's integration-style test for WaitForTask:
// it drives the full path (Client.WaitForTask -> proxmox.NewTask ->
// Task.Wait -> Task.Ping) through a real httptest.Server over real HTTP,
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
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("expected the fake server to never be called, got %d calls", got)
	}
}

// TestWaitForTask_MalformedUPIDBoundary is the specific gap a design
// review flagged: a UPID with exactly 6 colons / 7 fields — one field
// short of a real UPID's trailing "<user>:" — passes upstream
// proxmox.NewTask's own "len(sp) < 7" guard, but NewTask would then panic
// indexing sp[7] if it were ever actually invoked on this input (pveforge
// has no panic recovery anywhere). WaitForTask must reject this shape
// itself, before proxmox.NewTask or any network call ever happens — this
// asserts both the clean error AND that the fake server never receives a
// request, proving the pre-check short-circuits strictly before NewTask,
// not merely that some later guard happens to catch the fallout.
func TestWaitForTask_MalformedUPIDBoundary(t *testing.T) {
	const malformed = "UPID:node1:1234:5678:aaaa:qmcreate:100" // 6 colons / 7 fields
	handler, calls := taskStatusHandler(t, malformed, "node1", 0, "OK")
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	err := c.WaitForTask(context.Background(), "node1", malformed)
	if err == nil {
		t.Fatal("expected an error for a malformed upid")
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("expected the fake server to never be called, got %d calls", got)
	}
}

// TestWaitForTask_RequiresNodeAndUPID covers the plain empty-input guards.
func TestWaitForTask_RequiresNodeAndUPID(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node or upid is empty")
	}))

	if err := c.WaitForTask(context.Background(), "", wellFormedUPID("qa-pve-01")); err == nil {
		t.Fatal("expected an error for an empty node")
	}
	if err := c.WaitForTask(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected an error for an empty upid")
	}
}
