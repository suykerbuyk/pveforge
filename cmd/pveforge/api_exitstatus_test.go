package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// runAPIRoot runs `api <verb> args...` through runRoot, the only layer that
// turns an error into an exit status: runAPICmd (the verb's RunE alone) cannot
// see one, so none of the older api tests can tell exit 3 from exit 1.
func runAPIRoot(verb string, args ...string) (code int, stdout, stderr string) {
	return runRootArgs(append([]string{"api", verb}, args...)...)
}

const apiStartPath = "/nodes/qa-pve-01/qemu/100/status/start"

// A1: a wait that ends with its outcome unobserved (the status endpoint keeps
// answering 503) exits 3. stderr and stdout are exactly what they were at exit
// 1 (the baseline measured before the change). polls == 4 proves the 503s
// reached the wait: three transient, the fourth gives up.
func TestAPIExitStatus_A1_OutcomeUnknownExits3(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", upid),
		status: func(int32) (int, string) { return http.StatusServiceUnavailable, "null" }}
	rosterPath := newAPITaskServer(t, f)

	code, stdout, stderr := runAPIRoot("post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 3 {
		t.Errorf("exit %d, want 3", code)
	}
	if stdout != "" {
		t.Errorf("stdout %q, want empty", stdout)
	}
	want := "dispatched PVE task " + upid + "\nwait for task " + upid + ": 503 Service Unavailable\n"
	if stderr != want {
		t.Errorf("stderr %q, want %q", stderr, want)
	}
	if got := atomic.LoadInt32(&f.polls); got != 4 {
		t.Errorf("polls = %d, want 4", got)
	}
}

// A1 for the other two mutating verbs: the classification is not post's alone.
func TestAPIExitStatus_A1_PutAndDeleteToo(t *testing.T) {
	for _, verb := range []string{"put", "delete"} {
		t.Run(verb, func(t *testing.T) {
			withFastTaskPolls(t)
			f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", apiTestUPID("qa-pve-01")),
				status: func(int32) (int, string) { return http.StatusServiceUnavailable, "null" }}
			rosterPath := newAPITaskServer(t, f)
			if code, _, stderr := runAPIRoot(verb, "--roster", rosterPath, f.mutPath, "qa-pve-01"); code != 3 {
				t.Errorf("api %s: exit %d, want 3 (stderr %q)", verb, code, stderr)
			}
		})
	}
}

// A2: --wait-timeout expiring on a task that is still running exits 3, and
// promptly.
func TestAPIExitStatus_A2_WaitTimeoutExits3(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", upid),
		status: func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "running", "") }}
	rosterPath := newAPITaskServer(t, f)

	start := time.Now()
	code, stdout, _ := runAPIRoot("post", "--roster", rosterPath, "--wait-timeout", "50ms", f.mutPath, "qa-pve-01")
	if code != 3 || stdout != "" {
		t.Errorf("exit %d stdout %q, want 3 and empty", code, stdout)
	}
	if time.Since(start) > time.Second {
		t.Errorf("took %s: --wait-timeout was not what ended the wait", time.Since(start))
	}
	if atomic.LoadInt32(&f.polls) < 1 {
		t.Errorf("the task was never polled")
	}
}

// A3: the two pre-poll refusals ("refused" in their older tests' names) are
// UNKNOWN, not REFUSED and not FAILED: a task WAS dispatched and nothing
// observed it (pve.WaitForTask's own doc). Zero polls proves it is the
// pre-check, not a poll failure.
func TestAPIExitStatus_A3_PrePollRefusalsAreStillOutcomeUnknown(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"malformed UPID", `"UPID:n:1:2:3:4:5"`},
		{"UPID for another node", fmt.Sprintf("%q", apiTestUPID("pve9"))},
	} {
		t.Run(c.name, func(t *testing.T) {
			withFastTaskPolls(t)
			f := &apiTaskFake{mutPath: apiStartPath, body: c.body}
			rosterPath := newAPITaskServer(t, f)
			code, stdout, stderr := runAPIRoot("post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
			if code != 3 || stdout != "" {
				t.Errorf("exit %d stdout %q, want 3 and empty (stderr %q)", code, stdout, stderr)
			}
			if got := atomic.LoadInt32(&f.polls); got != 0 {
				t.Errorf("polls = %d, want 0", got)
			}
			if got := atomic.LoadInt32(&f.mutations); got != 1 {
				t.Errorf("mutations = %d, want 1 (the dispatch happened)", got)
			}
		})
	}
}

// A4: a task observed to fail is a known outcome: exit 1.
func TestAPIExitStatus_A4_FailedTaskExits1(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", upid),
		status: func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "stopped", "ERROR: x") }}
	rosterPath := newAPITaskServer(t, f)
	code, stdout, stderr := runAPIRoot("post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 1 || stdout != "" {
		t.Errorf("exit %d stdout %q, want 1 and empty", code, stdout)
	}
	if !strings.Contains(stderr, "failed: ERROR: x") {
		t.Errorf("stderr %q does not name the failure", stderr)
	}
	if got := atomic.LoadInt32(&f.polls); got < 1 {
		t.Errorf("the task was never polled: the failure was not observed")
	}
}

// A5: success with warnings is still 0, with its stderr notice.
func TestAPIExitStatus_A5_WarningsExit0(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", upid),
		status: func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "stopped", "WARNINGS: 2") }}
	rosterPath := newAPITaskServer(t, f)
	code, _, stderr := runAPIRoot("post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 0 || !strings.Contains(stderr, "succeeded with warnings") {
		t.Errorf("exit %d stderr %q, want 0 and the warnings notice", code, stderr)
	}
}

// A6: a dispatch that fails before any task exists is a plain failure, 1, with
// no poll: "outcome unknown" is the task wait's, not the request's.
func TestAPIExitStatus_A6_FailedDispatchExits1(t *testing.T) {
	withFastTaskPolls(t)
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", apiTestUPID("qa-pve-01")), mutStatus: http.StatusInternalServerError}
	rosterPath := newAPITaskServer(t, f)
	code, stdout, stderr := runAPIRoot("post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 1 || stdout != "" {
		t.Errorf("exit %d stdout %q, want 1 and empty (stderr %q)", code, stdout, stderr)
	}
	if got := atomic.LoadInt32(&f.mutations); got != 1 {
		t.Errorf("mutations = %d, want 1: the 500 must come from the dispatch", got)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("polls = %d, want 0", got)
	}
}

// A7: --no-wait dispatches and exits 0 without polling.
func TestAPIExitStatus_A7_NoWaitExits0(t *testing.T) {
	withFastTaskPolls(t)
	f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", apiTestUPID("qa-pve-01"))}
	rosterPath := newAPITaskServer(t, f)
	code, _, _ := runAPIRoot("post", "--roster", rosterPath, "--no-wait", f.mutPath, "qa-pve-01")
	if code != 0 || atomic.LoadInt32(&f.polls) != 0 || atomic.LoadInt32(&f.mutations) != 1 {
		t.Errorf("exit %d polls %d mutations %d, want 0, 0, 1", code, atomic.LoadInt32(&f.polls), atomic.LoadInt32(&f.mutations))
	}
}

// A9: a signal during the wait is 130/143 with runRoot's note, never 3. The
// cancel is delivered mid-wait with an interruptError cause (as
// notifyInterrupt does), on the first poll.
func TestAPIExitStatus_A9_ASignalDuringTheWaitIsNot3(t *testing.T) {
	for _, c := range []struct {
		sig  syscall.Signal
		name string
		want int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		t.Run(c.name, func(t *testing.T) {
			withFastTaskPolls(t)
			upid := apiTestUPID("qa-pve-01")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			f := &apiTaskFake{mutPath: apiStartPath, body: fmt.Sprintf("%q", upid),
				status:      func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "running", "") },
				onFirstPoll: func() { cancel(interruptError{sig: c.sig}) }}
			rosterPath := newAPITaskServer(t, f)
			code, stdout, stderr := runRootInterruptible(ctx, "api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
			if code != c.want || stdout != "" {
				t.Fatalf("exit %d stdout %q, want %d and empty (stderr %q)", code, stdout, c.want, stderr)
			}
			if !strings.Contains(stderr, "interrupted ("+c.name+")") || !strings.Contains(stderr, interruptNote) {
				t.Errorf("stderr %q lacks the interruption and its note", stderr)
			}
		})
	}
}

// P1: the status as the OS sees it. Everything above reads runRoot's return
// value; this re-executes the test binary as pveforge (cliChildEnv, through
// realMain and os.Exit) and reads the child's real exit status, so the one hop
// runRoot's own tests cannot see, runRoot -> os.Exit, is observed. The
// malformed UPID makes the wait end immediately, with the default poll timings
// the child has.
func TestAPIExitStatus_P1_TheProcessExitsWith3(t *testing.T) {
	f := &apiTaskFake{mutPath: apiStartPath, body: `"UPID:n:1:2:3:4:5"`}
	rosterPath := newAPITaskServer(t, f)
	c := startCLIChild(t, cliChildSpec{Args: []string{"api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01"}})
	ws := c.waitExit(t, 30*time.Second)
	if !ws.Exited() || ws.ExitStatus() != 3 {
		t.Errorf("child wait status %v (exited %v, status %d), want a normal exit with 3; stderr %q", ws, ws.Exited(), ws.ExitStatus(), c.stderr.String())
	}
	if got := atomic.LoadInt32(&f.mutations); got != 1 {
		t.Errorf("mutations = %d, want 1: the child never dispatched", got)
	}
}
