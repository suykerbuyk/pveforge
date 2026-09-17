package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- envelope regressions ------------------------------------------------
//
// PVE's guest-agent surface is NOT uniform: agent/exec and
// agent/exec-status put their payloads directly under the data envelope
// RawRequest strips, while agent/network-get-interfaces nests its array
// under an inner "result" key. The two tests below pin both halves of
// that asymmetry, in both directions, because generalising either one
// across the other fails on every live call.

// TestAgentInterfaces_DecodesInnerResultEnvelope is the regression for
// the Critical shape defect: decoding this endpoint as a bare array
// rather than through the inner "result" wrapper fails against any real
// host. The fixture is PVE's own shape, copied from go-proxmox's vendored
// PVE 9.x mock.
func TestAgentInterfaces_DecodesInnerResultEnvelope(t *testing.T) {
	const fixture = `{"data": {"result": [
		{"name": "lo", "hardware-address": "00:00:00:00:00:00", "ip-addresses": []},
		{"name": "eth0", "hardware-address": "BC:24:11:2E:C5:4A", "ip-addresses": [
			{"ip-address": "10.0.0.10", "ip-address-type": "ipv4", "prefix": 24}
		]}
	]}}`

	var gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	})
	c := testClient(t, srv)

	ifaces, err := c.AgentInterfaces(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("AgentInterfaces: %v", err)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/agent/network-get-interfaces" {
		t.Errorf("path = %q", gotPath)
	}
	// "lo" filtered, eth0 kept — asserting on content, not just count.
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1 (lo filtered): %+v", len(ifaces), ifaces)
	}
	if ifaces[0].Name != "eth0" {
		t.Errorf("name = %q, want eth0", ifaces[0].Name)
	}
	if ifaces[0].HardwareAddress != "BC:24:11:2E:C5:4A" {
		t.Errorf("hardware-address = %q", ifaces[0].HardwareAddress)
	}
	// The nested per-address OBJECT must decode, not a flattened string.
	if len(ifaces[0].IPAddresses) != 1 {
		t.Fatalf("got %d addresses, want 1: %+v", len(ifaces[0].IPAddresses), ifaces[0].IPAddresses)
	}
	addr := ifaces[0].IPAddresses[0]
	if addr.Address != "10.0.0.10" || addr.Type != "ipv4" || addr.Prefix != 24 {
		t.Errorf("address = %+v, want {10.0.0.10 ipv4 24}", addr)
	}
}

// TestAgentExecStatus_DecodesWithoutResultEnvelope is the other half of
// the asymmetry: exec-status sits DIRECTLY under data. Adding a "result"
// wrapper to this decoder — the natural generalisation from the
// interfaces endpoint — must fail here.
func TestAgentExecStatus_DecodesWithoutResultEnvelope(t *testing.T) {
	var gotPath, gotQuery, gotMethod string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data": {"exited": 1, "exitcode": 0, "out-data": "hello\n", "out-truncated": false}}`))
	})
	c := testClient(t, srv)

	status, err := c.AgentExecStatus(context.Background(), "qa-pve-01", 100, 1234)
	if err != nil {
		t.Fatalf("AgentExecStatus: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/agent/exec-status" {
		t.Errorf("path = %q", gotPath)
	}
	if gotQuery != "pid=1234" {
		t.Errorf("query = %q, want pid=1234", gotQuery)
	}
	if status.Exited != 1 {
		t.Errorf("Exited = %d, want 1", status.Exited)
	}
	if status.OutData != "hello\n" {
		t.Errorf("OutData = %q, want %q", status.OutData, "hello\n")
	}
	if !status.Succeeded() {
		t.Errorf("Succeeded() = false, want true for exited=1 exitcode=0")
	}
	// Raw must carry PVE's verbatim payload so nothing is lost to typing.
	if !strings.Contains(string(status.Raw), `"out-data"`) {
		t.Errorf("Raw = %q, want the verbatim payload", status.Raw)
	}
}

// --- AgentExec dispatch --------------------------------------------------

// TestAgentExec_SendsCommandAsRepeatedFormValues pins the argv encoding.
// Mutation target: join the command with spaces into a single form value
// — the count assertion below dies, because a three-element argv must
// arrive as three values, not one.
func TestAgentExec_SendsCommandAsRepeatedFormValues(t *testing.T) {
	var gotMethod, gotPath, gotContentType, gotInput string
	var gotCommand []string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			return
		}
		gotCommand = r.PostForm["command"]
		gotInput = r.PostForm.Get("input-data")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"pid":4242}}`))
	})
	c := testClient(t, srv)

	pid, err := c.AgentExec(context.Background(), "qa-pve-01", 100,
		[]string{"/bin/sh", "-c", "echo hi"}, "stdin-payload")
	if err != nil {
		t.Fatalf("AgentExec: %v", err)
	}
	if pid != 4242 {
		t.Errorf("pid = %d, want 4242", pid)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/agent/exec" {
		t.Errorf("path = %q", gotPath)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	want := []string{"/bin/sh", "-c", "echo hi"}
	if len(gotCommand) != len(want) {
		t.Fatalf("command arrived as %d values (%q), want %d — argv must not be joined",
			len(gotCommand), gotCommand, len(want))
	}
	for i := range want {
		if gotCommand[i] != want[i] {
			t.Errorf("command[%d] = %q, want %q", i, gotCommand[i], want[i])
		}
	}
	if gotInput != "stdin-payload" {
		t.Errorf("input-data = %q", gotInput)
	}
}

// TestAgentExec_PIDDecodeRejectsUnusableResponses covers the three ways a
// 2xx response can fail to carry a usable pid. The absent-key case is the
// mutation target that matters most: inferring presence from `pid != 0`
// instead of from a pointer makes `{"data":{}}` return (0, nil) — a
// dispatch that never happened, reported as a successful one.
func TestAgentExec_PIDDecodeRejectsUnusableResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantIn string
	}{
		{"null data", `{"data":null}`, "got null"},
		{"absent pid key", `{"data":{}}`, "no pid field"},
		{"stringified pid", `{"data":{"pid":"4242"}}`, "cannot unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			c := testClient(t, srv)

			pid, err := c.AgentExec(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "")
			if err == nil {
				t.Fatalf("AgentExec returned (%d, nil), want an error", pid)
			}
			if pid != 0 {
				t.Errorf("pid = %d on error, want 0", pid)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantIn)
			}
			// The raw response must reach the caller, not be reworded away.
			if !strings.Contains(err.Error(), "agent exec on vm 100") {
				t.Errorf("error = %q, want the vm context", err)
			}
		})
	}
}

// TestAgentExec_DispatchFailureIsNeverASilentZero pins the boundary this
// unit exists to hold: an absent/stopped/unresponsive agent surfaces as
// an error carrying PVE's verbatim text, never as a zero pid with a nil
// error.
func TestAgentExec_DispatchFailureIsNeverASilentZero(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"errors":{"agent":"QEMU guest agent is not running"}}`))
	})
	c := testClient(t, srv)

	pid, err := c.AgentExec(context.Background(), "qa-pve-01", 100, []string{"/bin/true"}, "")
	if err == nil {
		t.Fatalf("AgentExec returned (%d, nil) for a 500, want an error", pid)
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0", pid)
	}
	// PVE's own diagnostic text must survive end to end — the entire
	// reason this goes through RawRequest rather than go-proxmox.
	if !strings.Contains(err.Error(), "QEMU guest agent is not running") {
		t.Errorf("error = %q, want PVE's verbatim text preserved", err)
	}
	if !IsAgentUnavailableError(err) {
		t.Errorf("IsAgentUnavailableError = false for %q, want true", err)
	}
	// Distinct from a deadline: a dispatch failure is not a timeout.
	if IsAgentExecTimeoutError(err) {
		t.Errorf("IsAgentExecTimeoutError = true for a dispatch failure")
	}
}

// TestIsAgentUnavailableError_MatchesBothPVEMessages pins that the
// classifier covers PVE's SECOND agent-absent message too — the one
// go-proxmox's own matcher misses entirely — and that it does not
// false-positive on an unrelated failure.
func TestIsAgentUnavailableError_MatchesBothPVEMessages(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"agent not running", errors.New("raw request: pve returned 500 QEMU guest agent is not running: "), true},
		{"agent not configured", errors.New(`raw request: pve returned 500 Internal Server Error: {"errors":{"agent":"No QEMU guest agent configured"}}`), true},
		{"unrelated failure", errors.New("raw request: pve returned 500 Internal Server Error: no such vm"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAgentUnavailableError(tc.err); got != tc.want {
				t.Errorf("IsAgentUnavailableError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// --- outcome separation --------------------------------------------------

// TestAgentExecStatus_SeparatesCompletionOutcomes is the core
// anti-conflation test. A clean exit, a non-zero exit and a signal kill
// are three DIFFERENT outcomes and all three are successful execs, so
// none of them is an error. The signal case is the sharp one: QGA omits
// exitcode on a signal kill, so a plain `ExitCode int` with no
// ExitCodeSet flag reads it as 0 — indistinguishable from the clean exit
// in the first row. Mutation: type Signal as bool, or drop ExitCodeSet,
// and this test dies.
//
// The fourth row is not a documented QGA shape, and that is the point —
// see its own comment.
func TestAgentExecStatus_SeparatesCompletionOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		body            string
		wantSucceeded   bool
		wantExitCode    int
		wantExitCodeSet bool
		wantSignal      *int
		wantOut, wantEr string
	}{
		{
			name:            "exited zero",
			body:            `{"data":{"exited":1,"exitcode":0,"out-data":"ok\n"}}`,
			wantSucceeded:   true,
			wantExitCode:    0,
			wantExitCodeSet: true,
			wantOut:         "ok\n",
		},
		{
			name:            "exited non-zero is a successful exec of a failing command",
			body:            `{"data":{"exited":1,"exitcode":3,"err-data":"boom\n"}}`,
			wantSucceeded:   false,
			wantExitCode:    3,
			wantExitCodeSet: true,
			wantEr:          "boom\n",
		},
		{
			name:            "signal kill omits exitcode and must not read as success",
			body:            `{"data":{"exited":1,"signal":9,"out-data":""}}`,
			wantSucceeded:   false,
			wantExitCode:    0,
			wantExitCodeSet: false,
			wantSignal:      intPtr(9),
		},
		{
			// NOT a documented QGA shape: the schema says exitcode is
			// absent whenever a process was signal-terminated, so signal
			// and exitcode are meant to be mutually exclusive. This row
			// exists precisely because of that — it is the only case in
			// which Succeeded()'s explicit Signal check is the thing
			// that DECIDES. For every well-formed signal kill,
			// ExitCodeSet is already false and returns false first, so
			// without this fixture the Signal check could be deleted by
			// a future refactor with a green suite. A PVE or QGA that
			// violated the mutual exclusivity would then report a
			// SIGKILLed command as a clean success.
			name:            "signal and exitcode both present must still not read as success",
			body:            `{"data":{"exited":1,"signal":9,"exitcode":0}}`,
			wantSucceeded:   false,
			wantExitCode:    0,
			wantExitCodeSet: true,
			wantSignal:      intPtr(9),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			c := testClient(t, srv)

			status, err := c.AgentExecStatus(context.Background(), "qa-pve-01", 100, 1)
			// A command that ran is never an error, whatever it did.
			if err != nil {
				t.Fatalf("AgentExecStatus: %v — a completed command is not an error", err)
			}
			if got := status.Succeeded(); got != tc.wantSucceeded {
				t.Errorf("Succeeded() = %v, want %v", got, tc.wantSucceeded)
			}
			if status.ExitCode != tc.wantExitCode {
				t.Errorf("ExitCode = %d, want %d", status.ExitCode, tc.wantExitCode)
			}
			if status.ExitCodeSet != tc.wantExitCodeSet {
				t.Errorf("ExitCodeSet = %v, want %v", status.ExitCodeSet, tc.wantExitCodeSet)
			}
			switch {
			case tc.wantSignal == nil && status.Signal != nil:
				t.Errorf("Signal = %d, want nil", *status.Signal)
			case tc.wantSignal != nil && status.Signal == nil:
				t.Errorf("Signal = nil, want %d", *tc.wantSignal)
			case tc.wantSignal != nil && *status.Signal != *tc.wantSignal:
				t.Errorf("Signal = %d, want %d", *status.Signal, *tc.wantSignal)
			}
			if status.OutData != tc.wantOut {
				t.Errorf("OutData = %q, want %q", status.OutData, tc.wantOut)
			}
			if status.ErrData != tc.wantEr {
				t.Errorf("ErrData = %q, want %q", status.ErrData, tc.wantEr)
			}
		})
	}
}

// TestAgentExecStatus_SignalKillIsDistinguishableFromCleanExit states the
// conflation directly rather than leaving it implicit in the table above:
// the two statuses must not compare equal on the fields a caller judges
// by. This is the test a reviewer collapsing "signal-kill vs exit-0"
// has to defeat.
func TestAgentExecStatus_SignalKillIsDistinguishableFromCleanExit(t *testing.T) {
	clean := decodeStatusForTest(t, `{"exited":1,"exitcode":0,"out-data":""}`)
	killed := decodeStatusForTest(t, `{"exited":1,"signal":9,"out-data":""}`)

	if clean.ExitCode != killed.ExitCode {
		t.Fatalf("precondition changed: ExitCode differs (%d vs %d); this test exists because they are BOTH 0",
			clean.ExitCode, killed.ExitCode)
	}
	if clean.Succeeded() == killed.Succeeded() {
		t.Errorf("Succeeded() is %v for both a clean exit and a SIGKILL — the two outcomes are conflated",
			clean.Succeeded())
	}
	if !clean.Succeeded() {
		t.Errorf("clean exit: Succeeded() = false, want true")
	}
	if killed.Succeeded() {
		t.Errorf("signal kill: Succeeded() = true, want false")
	}
}

// TestAgentExecStatus_ExitedWithNoExitCodeIsNotSuccess covers the case
// where PVE reports a command as exited but sends NEITHER an exitcode nor
// a signal. Nothing about that payload says the command succeeded, so
// claiming it did would be an absence of signal rendered as a definite
// answer.
//
// This is what makes ExitCodeSet independently load-bearing: in every
// other fixture the Signal check fires first, so without this case
// dropping ExitCodeSet from Succeeded() changes no test result.
func TestAgentExecStatus_ExitedWithNoExitCodeIsNotSuccess(t *testing.T) {
	status := decodeStatusForTest(t, `{"exited":1,"out-data":"something\n"}`)
	if status.ExitCodeSet {
		t.Fatalf("ExitCodeSet = true, want false — the fixture sends no exitcode")
	}
	if status.Signal != nil {
		t.Fatalf("Signal = %d, want nil — the fixture sends no signal either", *status.Signal)
	}
	if status.Succeeded() {
		t.Error("Succeeded() = true for a command PVE reported no exit code for, want false")
	}
}

// TestAgentExecStatus_EmptyOutputIsNotAFailure separates "ran and printed
// nothing" from "never ran" — the third pair a reviewer will try to
// collapse. An exited, exit-0 command with empty OutData is a success.
func TestAgentExecStatus_EmptyOutputIsNotAFailure(t *testing.T) {
	status := decodeStatusForTest(t, `{"exited":1,"exitcode":0,"out-data":"","err-data":""}`)
	if !status.Succeeded() {
		t.Errorf("Succeeded() = false for an exit-0 command with no output, want true")
	}
	if status.OutData != "" {
		t.Errorf("OutData = %q, want empty", status.OutData)
	}
}

// TestAgentExecStatus_TruncationFlagsAcceptBareInts is the regression for
// the type asymmetry. PVE intermixes 0/1 and true/false across these
// fields; typing either flag as a plain Go bool fails the whole decode
// with "cannot unmarshal number into Go struct field" the moment PVE
// sends an int — losing the entire status of a command whose output was
// truncated. Mutation: change either field to bool and this dies.
func TestAgentExecStatus_TruncationFlagsAcceptBareInts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		body             string
		wantOut, wantErr bool
	}{
		{"bare ints", `{"exited":1,"exitcode":0,"out-truncated":1,"err-truncated":1}`, true, true},
		{"bare ints false", `{"exited":1,"exitcode":0,"out-truncated":0,"err-truncated":0}`, false, false},
		{"json bools", `{"exited":1,"exitcode":0,"out-truncated":true,"err-truncated":true}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := decodeStatusForTest(t, tc.body)
			if bool(status.OutTruncated) != tc.wantOut {
				t.Errorf("OutTruncated = %v, want %v", bool(status.OutTruncated), tc.wantOut)
			}
			if bool(status.ErrTruncated) != tc.wantErr {
				t.Errorf("ErrTruncated = %v, want %v", bool(status.ErrTruncated), tc.wantErr)
			}
		})
	}
}

// --- WaitForAgentExec ----------------------------------------------------

// agentExecStatusHandler serves canned exec-status bodies in sequence,
// counting calls so a test can prove the poll loop actually polled.
// The last body repeats once the sequence is exhausted.
func agentExecStatusHandler(bodies ...string) (http.HandlerFunc, *int32) {
	var calls int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&calls, 1))
		body := bodies[len(bodies)-1]
		if n <= len(bodies) {
			body = bodies[n-1]
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(body, "HTTP500:") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(strings.TrimPrefix(body, "HTTP500:")))
			return
		}
		_, _ = w.Write([]byte(body))
	}
	return handler, &calls
}

// TestWaitForAgentExec_PollsUntilExit proves this is a poll loop and not
// a single status check: the handler reports the command still running
// twice before it exits, and the call must survive both.
func TestWaitForAgentExec_PollsUntilExit(t *testing.T) {
	handler, calls := agentExecStatusHandler(
		`{"data":{"exited":0}}`,
		`{"data":{"exited":0}}`,
		`{"data":{"exited":1,"exitcode":0,"out-data":"done\n"}}`,
	)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	status, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForAgentExec: %v", err)
	}
	if !status.Succeeded() {
		t.Errorf("Succeeded() = false, want true")
	}
	if status.OutData != "done\n" {
		t.Errorf("OutData = %q, want %q", status.OutData, "done\n")
	}
	if got := atomic.LoadInt32(calls); got < 3 {
		t.Errorf("polled %d times, want at least 3 — a single check is not a poll loop", got)
	}
}

// TestWaitForAgentExec_NeverReadsPayloadBeforeTheExitedGate pins the
// gate. The still-running fixture deliberately carries a stale exitcode
// and out-data; returning them would be the "successful call that
// returns nothing useful" failure this unit exists to prevent.
// Mutation: drop the Exited gate, or loosen it to >= 0, and the loop
// returns the stale payload instead of timing out.
func TestWaitForAgentExec_NeverReadsPayloadBeforeTheExitedGate(t *testing.T) {
	handler, _ := agentExecStatusHandler(`{"data":{"exited":0,"exitcode":7,"out-data":"stale"}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	status, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 60*time.Millisecond)
	if err == nil {
		t.Fatalf("WaitForAgentExec returned (%+v, nil), want a deadline error — exited==0 is not an answer", status)
	}
	if status != nil {
		t.Errorf("status = %+v, want nil on an unobserved outcome", status)
	}
	if !IsAgentExecTimeoutError(err) {
		t.Errorf("IsAgentExecTimeoutError = false for %q, want true", err)
	}
	if strings.Contains(err.Error(), "stale") {
		t.Errorf("error leaked the pre-exit payload: %q", err)
	}
}

// TestWaitForAgentExec_RetriesThroughTransientPollErrors is the test for
// the specified poll-loop error behavior: two failing polls must not end
// the wait, because a blip says nothing about whether the guest command
// ran, and re-executing a non-idempotent command is the one recovery the
// caller must not be pushed into. Mutation: return on the first poll
// error and this dies.
func TestWaitForAgentExec_RetriesThroughTransientPollErrors(t *testing.T) {
	handler, calls := agentExecStatusHandler(
		`HTTP500:{"errors":{"x":"transient blip"}}`,
		`HTTP500:{"errors":{"x":"transient blip"}}`,
		`{"data":{"exited":1,"exitcode":0,"out-data":"recovered\n"}}`,
	)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	status, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForAgentExec: %v — two transient poll errors must not end the wait", err)
	}
	if !status.Succeeded() || status.OutData != "recovered\n" {
		t.Errorf("status = %+v, want a successful exit with OutData %q", status, "recovered\n")
	}
	if got := atomic.LoadInt32(calls); got < 3 {
		t.Errorf("polled %d times, want at least 3", got)
	}
}

// TestWaitForAgentExec_TimeoutDistinguishesPersistentErrorsFromASlowCommand
// is the pair a reviewer will try to collapse: both end at the deadline,
// but "every poll failed, here is PVE's last complaint" and "the agent
// kept answering and the command kept running" are different situations.
// LastErr is what separates them. Mutation: discard LastErr and the
// first subtest's content assertions die.
func TestWaitForAgentExec_TimeoutDistinguishesPersistentErrorsFromASlowCommand(t *testing.T) {
	t.Run("every poll failed", func(t *testing.T) {
		handler, _ := agentExecStatusHandler(`HTTP500:{"errors":{"agent":"QEMU guest agent is not running"}}`)
		srv := newFakeAPIServer(t, handler)
		c := testClient(t, srv)

		_, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 60*time.Millisecond)
		if err == nil {
			t.Fatal("WaitForAgentExec returned nil, want a deadline error")
		}
		if !IsAgentExecTimeoutError(err) {
			t.Errorf("IsAgentExecTimeoutError = false for %q, want true", err)
		}
		var timeoutErr *AgentExecTimeoutError
		if !errors.As(err, &timeoutErr) {
			t.Fatalf("error %q is not an *AgentExecTimeoutError", err)
		}
		if timeoutErr.LastErr == nil {
			t.Fatalf("LastErr = nil, want the last poll error preserved")
		}
		if timeoutErr.VMID != 100 || timeoutErr.PID != 7 {
			t.Errorf("VMID/PID = %d/%d, want 100/7", timeoutErr.VMID, timeoutErr.PID)
		}
		if timeoutErr.Polls < 2 {
			t.Errorf("Polls = %d, want at least 2", timeoutErr.Polls)
		}
		// PVE's own text must reach the caller through the timeout.
		if !strings.Contains(err.Error(), "QEMU guest agent is not running") {
			t.Errorf("error = %q, want PVE's verbatim text carried through", err)
		}
		// errors.Is must find BOTH the sentinel and anything underneath.
		if !errors.Is(err, ErrAgentExecTimeout) {
			t.Errorf("errors.Is(err, ErrAgentExecTimeout) = false")
		}
	})

	t.Run("agent healthy, command slow", func(t *testing.T) {
		handler, _ := agentExecStatusHandler(`{"data":{"exited":0}}`)
		srv := newFakeAPIServer(t, handler)
		c := testClient(t, srv)

		_, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 60*time.Millisecond)
		if err == nil {
			t.Fatal("WaitForAgentExec returned nil, want a deadline error")
		}
		var timeoutErr *AgentExecTimeoutError
		if !errors.As(err, &timeoutErr) {
			t.Fatalf("error %q is not an *AgentExecTimeoutError", err)
		}
		if timeoutErr.LastErr != nil {
			t.Errorf("LastErr = %v, want nil when every poll succeeded", timeoutErr.LastErr)
		}
		if !strings.Contains(err.Error(), "every poll succeeded") {
			t.Errorf("error = %q, want it to say the polls succeeded", err)
		}
	})
}

// TestWaitForAgentExec_TimeoutIsNotACommandFailure pins the second pair:
// a deadline and a non-zero exit must never be reported the same way.
func TestWaitForAgentExec_TimeoutIsNotACommandFailure(t *testing.T) {
	// A command that ran and failed: no error at all.
	handler, _ := agentExecStatusHandler(`{"data":{"exited":1,"exitcode":3,"err-data":"boom"}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	status, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForAgentExec: %v — a non-zero exit is a successful exec, not an error", err)
	}
	if status.ExitCode != 3 || status.Succeeded() {
		t.Errorf("status = %+v, want ExitCode 3 and Succeeded() false", status)
	}
	if IsAgentExecTimeoutError(err) {
		t.Errorf("IsAgentExecTimeoutError = true for a completed command")
	}
}

// TestWaitForAgentExec_ContextCancellationIsNotADeadline pins the third
// pair. A cancelled context and an expired deadline both end the wait,
// but they are different and a caller must be able to tell them apart.
// Mutation: retry through ctx errors too, and the loop runs to the
// deadline and returns the wrong error type.
func TestWaitForAgentExec_ContextCancellationIsNotADeadline(t *testing.T) {
	handler, _ := agentExecStatusHandler(`{"data":{"exited":0}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	status, err := c.WaitForAgentExec(ctx, "qa-pve-01", 100, 7, time.Millisecond, 30*time.Second)
	if err == nil {
		t.Fatalf("WaitForAgentExec returned (%+v, nil), want a cancellation error", status)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %q", err)
	}
	if IsAgentExecTimeoutError(err) {
		t.Errorf("IsAgentExecTimeoutError = true for a cancellation — the two are conflated")
	}
	var timeoutErr *AgentExecTimeoutError
	if errors.As(err, &timeoutErr) {
		t.Errorf("cancellation returned an *AgentExecTimeoutError")
	}
}

// TestWaitForAgentExec_CancellationWinsOverAnAlreadyElapsedDeadline pins
// the case where BOTH endings are available at once: the caller has
// cancelled AND the deadline has passed. A bare select over ctx.Done()
// and the deadline timer picks between two ready cases at random, so
// roughly half of those calls would report a deadline when what actually
// happened is that the caller stopped — a caller cannot act on a
// classification that changes run to run.
//
// Fifty iterations: with the explicit context fail-fast this is
// deterministic, and without it the odds of never once picking the
// deadline branch are 2^-50.
func TestWaitForAgentExec_CancellationWinsOverAnAlreadyElapsedDeadline(t *testing.T) {
	handler, _ := agentExecStatusHandler(`{"data":{"exited":0}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := range 50 {
		// A 1ns deadline is already expired by the time the first poll
		// returns, so both endings are ready on every iteration.
		_, err := c.WaitForAgentExec(ctx, "qa-pve-01", 100, 7, time.Millisecond, time.Nanosecond)
		if err == nil {
			t.Fatalf("iteration %d: returned nil error", i)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: errors.Is(err, context.Canceled) = false for %q", i, err)
		}
		if IsAgentExecTimeoutError(err) {
			t.Fatalf("iteration %d: reported a deadline for a cancelled context: %q", i, err)
		}
	}
}

// TestWaitForAgentExec_TimeoutSentinelIsNotTheTaskTimeoutSentinel keeps
// the two deadline predicates from collapsing into one another: a PVE
// task whose outcome is unknown and a guest command whose outcome is
// unknown imply different recovery.
func TestWaitForAgentExec_TimeoutSentinelIsNotTheTaskTimeoutSentinel(t *testing.T) {
	handler, _ := agentExecStatusHandler(`{"data":{"exited":0}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	_, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, time.Millisecond, 50*time.Millisecond)
	if !IsAgentExecTimeoutError(err) {
		t.Fatalf("IsAgentExecTimeoutError = false for %q", err)
	}
	if IsTaskTimeoutError(err) {
		t.Errorf("IsTaskTimeoutError = true for a guest-exec deadline — sentinels are conflated")
	}
}

// TestWaitForAgentExec_DefaultsApplyOnNonPositiveArguments covers the
// fallback path without waiting out the real production defaults.
func TestWaitForAgentExec_DefaultsApplyOnNonPositiveArguments(t *testing.T) {
	origInterval, origTimeout := defaultAgentExecPollInterval, defaultAgentExecTimeout
	defaultAgentExecPollInterval = time.Millisecond
	defaultAgentExecTimeout = 60 * time.Millisecond
	t.Cleanup(func() {
		defaultAgentExecPollInterval = origInterval
		defaultAgentExecTimeout = origTimeout
	})

	handler, calls := agentExecStatusHandler(`{"data":{"exited":0}}`)
	srv := newFakeAPIServer(t, handler)
	c := testClient(t, srv)

	_, err := c.WaitForAgentExec(context.Background(), "qa-pve-01", 100, 7, 0, 0)
	if !IsAgentExecTimeoutError(err) {
		t.Fatalf("IsAgentExecTimeoutError = false for %q", err)
	}
	if got := atomic.LoadInt32(calls); got < 2 {
		t.Errorf("polled %d times with the default interval, want at least 2", got)
	}
}

// --- MAC join ------------------------------------------------------------

func TestAddressForMAC_Branches(t *testing.T) {
	withAddrs := func(name, mac string, addrs ...AgentIPAddress) AgentInterface {
		return AgentInterface{Name: name, HardwareAddress: mac, IPAddresses: addrs}
	}
	v4 := func(a string) AgentIPAddress { return AgentIPAddress{Address: a, Type: "ipv4", Prefix: 24} }
	v6ll := AgentIPAddress{Address: "fe80::1", Type: "ipv6", Prefix: 64}

	for _, tc := range []struct {
		name    string
		ifaces  []AgentInterface
		mac     string
		wantErr error
		wantIP  string
	}{
		{
			name:    "empty list is not an answer",
			ifaces:  nil,
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoGuestInterfaces,
		},
		{
			name:    "only loopback is still no interfaces",
			ifaces:  []AgentInterface{withAddrs("lo", "00:00:00:00:00:00", v4("127.0.0.1"))},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoInterfaceForMAC,
		},
		{
			name:    "no interface carries the mac",
			ifaces:  []AgentInterface{withAddrs("eth0", "AA:BB:CC:DD:EE:FF", v4("10.0.0.10"))},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoInterfaceForMAC,
		},
		{
			name: "several interfaces carry the mac",
			ifaces: []AgentInterface{
				withAddrs("bond0", "BC:24:11:2E:C5:4A", v4("10.0.0.10")),
				withAddrs("eth0", "BC:24:11:2E:C5:4A", v4("10.0.0.11")),
			},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrAmbiguousInterfaceForMAC,
		},
		{
			name:    "matched but only link-local",
			ifaces:  []AgentInterface{withAddrs("eth0", "BC:24:11:2E:C5:4A", v6ll)},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoAddressForMAC,
		},
		{
			name:    "matched but no addresses at all",
			ifaces:  []AgentInterface{withAddrs("eth0", "BC:24:11:2E:C5:4A")},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoAddressForMAC,
		},
		{
			name:   "link-local filtered out leaves exactly one",
			ifaces: []AgentInterface{withAddrs("eth0", "BC:24:11:2E:C5:4A", v6ll, v4("10.0.0.10"))},
			mac:    "BC:24:11:2E:C5:4A",
			wantIP: "10.0.0.10",
		},
		{
			name:    "two genuinely usable addresses is ambiguous",
			ifaces:  []AgentInterface{withAddrs("eth0", "BC:24:11:2E:C5:4A", v4("10.0.0.10"), v4("10.0.0.11"))},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrAmbiguousAddressForMAC,
		},
		{
			name:   "dash-separated uppercase mac joins colon-separated lowercase",
			ifaces: []AgentInterface{withAddrs("eth0", "bc:24:11:2e:c5:4a", v4("10.0.0.10"))},
			mac:    "BC-24-11-2E-C5-4A",
			wantIP: "10.0.0.10",
		},
		{
			// A guest can report loopback, the unspecified address, or
			// outright garbage on a normal interface. None of them is an
			// answer, and none may push the count into "ambiguous".
			name: "loopback, unspecified and unparseable addresses are all unusable",
			ifaces: []AgentInterface{withAddrs("eth0", "BC:24:11:2E:C5:4A",
				v4("127.0.0.1"), v4("0.0.0.0"), v4("not-an-ip"), v4("10.0.0.10"))},
			mac:    "BC:24:11:2E:C5:4A",
			wantIP: "10.0.0.10",
		},
		{
			name: "an interface reporting no parseable mac cannot match",
			ifaces: []AgentInterface{
				withAddrs("teql0", "", v4("10.0.0.99")),
				withAddrs("eth0", "BC:24:11:2E:C5:4A", v4("10.0.0.10")),
			},
			mac:    "BC:24:11:2E:C5:4A",
			wantIP: "10.0.0.10",
		},
		{
			name:    "an interface with no parseable mac is skipped, not matched",
			ifaces:  []AgentInterface{withAddrs("teql0", "", v4("10.0.0.99"))},
			mac:     "BC:24:11:2E:C5:4A",
			wantErr: ErrNoInterfaceForMAC,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AddressForMAC(tc.ifaces, tc.mac)
			if tc.wantIP != "" {
				if err != nil {
					t.Fatalf("AddressForMAC: %v", err)
				}
				if got.Address != tc.wantIP {
					t.Errorf("address = %q, want %q", got.Address, tc.wantIP)
				}
				return
			}
			if err == nil {
				t.Fatalf("AddressForMAC returned %+v, want an error", got)
			}
			if got.Address != "" {
				t.Errorf("address = %q on error, want empty", got.Address)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %q, want it to wrap %q", err, tc.wantErr)
			}
			// Every refusal names the MAC it was asked about.
			if !strings.Contains(err.Error(), tc.mac) {
				t.Errorf("error = %q, want it to name the mac %q", err, tc.mac)
			}
		})
	}
}

// TestAddressForMAC_UnparseableMACIsNotAMissingInterface keeps a bad
// argument from being reported as a legitimate "no such NIC" answer.
func TestAddressForMAC_UnparseableMACIsNotAMissingInterface(t *testing.T) {
	ifaces := []AgentInterface{{Name: "eth0", HardwareAddress: "bc:24:11:2e:c5:4a"}}
	_, err := AddressForMAC(ifaces, "not-a-mac")
	if err == nil {
		t.Fatal("AddressForMAC returned nil error for an unparseable mac")
	}
	if errors.Is(err, ErrNoInterfaceForMAC) {
		t.Errorf("an unparseable mac was reported as ErrNoInterfaceForMAC: %q", err)
	}
	if !strings.Contains(err.Error(), "unparseable mac address") {
		t.Errorf("error = %q, want it to say the mac was unparseable", err)
	}
}

// TestAddressesForMAC_ReturnsEveryAddressUnfiltered is the escape hatch
// for a caller that wants to choose: the multi-address interface that
// AddressForMAC refuses on must be fully readable here, link-local
// included.
func TestAddressesForMAC_ReturnsEveryAddressUnfiltered(t *testing.T) {
	ifaces := []AgentInterface{{
		Name:            "eth0",
		HardwareAddress: "BC:24:11:2E:C5:4A",
		IPAddresses: []AgentIPAddress{
			{Address: "fe80::1", Type: "ipv6", Prefix: 64},
			{Address: "10.0.0.10", Type: "ipv4", Prefix: 24},
			{Address: "10.0.0.11", Type: "ipv4", Prefix: 24},
		},
	}}

	addrs, err := AddressesForMAC(ifaces, "BC:24:11:2E:C5:4A")
	if err != nil {
		t.Fatalf("AddressesForMAC: %v", err)
	}
	if len(addrs) != 3 {
		t.Fatalf("got %d addresses, want 3 (unfiltered): %+v", len(addrs), addrs)
	}
	if addrs[0].Address != "fe80::1" {
		t.Errorf("addrs[0] = %q, want the link-local kept in order", addrs[0].Address)
	}
	// The interface-level contract still applies here.
	if _, err := AddressesForMAC(ifaces, "AA:BB:CC:DD:EE:FF"); !errors.Is(err, ErrNoInterfaceForMAC) {
		t.Errorf("error = %v, want ErrNoInterfaceForMAC", err)
	}
}

// --- config side of the join ---------------------------------------------

func TestMACFromNetConfig(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		wantErr           error
	}{
		{name: "virtio model key", value: "virtio=BC:24:11:2E:C5:4A,bridge=vmbr0", want: "bc:24:11:2e:c5:4a"},
		{name: "e1000 model key", value: "e1000=AA:BB:CC:DD:EE:FF,bridge=vmbr1,firewall=1", want: "aa:bb:cc:dd:ee:ff"},
		{name: "explicit macaddr wins over a model key", value: "virtio=AA:BB:CC:DD:EE:FF,macaddr=BC:24:11:2E:C5:4A", want: "bc:24:11:2e:c5:4a"},
		{name: "no mac anywhere", value: "bridge=vmbr0,firewall=1", wantErr: ErrNoMACInNetConfig},
		{name: "empty value", value: "", wantErr: ErrNoMACInNetConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MACFromNetConfig(tc.value)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MACFromNetConfig: %v", err)
			}
			if got != tc.want {
				t.Errorf("mac = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestVMNetMACs_ReadsEveryNetIndex deliberately uses a NON-CONTIGUOUS,
// multi-element set of interfaces including one past proxmox's typed
// Net0..Net5 fields. A single-element fixture would let an index bug pass
// — the exact gap mutation testing found in an earlier unit here.
func TestVMNetMACs_ReadsEveryNetIndex(t *testing.T) {
	const fixture = `{"data":{
		"name": "vm100",
		"net0": "virtio=BC:24:11:2E:C5:4A,bridge=vmbr0",
		"net2": "e1000=AA:BB:CC:DD:EE:01,bridge=vmbr1",
		"net10": "virtio=AA:BB:CC:DD:EE:02,bridge=vmbr2",
		"net3": "bridge=vmbr3",
		"network": "not-a-net-key",
		"net-1": "virtio=AA:BB:CC:DD:EE:03,bridge=vmbr9",
		"net+4": "virtio=AA:BB:CC:DD:EE:04,bridge=vmbr9",
		"net99999999999999999999": "virtio=AA:BB:CC:DD:EE:05,bridge=vmbr9",
		"scsi0": "local-lvm:vm-100-disk-0"
	}}`

	var gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fixture))
	})
	c := testClient(t, srv)

	macs, err := c.VMNetMACs(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("VMNetMACs: %v", err)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("path = %q", gotPath)
	}
	want := map[int]string{
		0:  "bc:24:11:2e:c5:4a",
		2:  "aa:bb:cc:dd:ee:01",
		10: "aa:bb:cc:dd:ee:02",
	}
	if len(macs) != len(want) {
		t.Fatalf("got %d macs, want %d: %+v", len(macs), len(want), macs)
	}
	for n, wantMAC := range want {
		if macs[n] != wantMAC {
			t.Errorf("net%d = %q, want %q", n, macs[n], wantMAC)
		}
	}
	// net3 has no MAC and must be skipped, not fail the whole read.
	if _, ok := macs[3]; ok {
		t.Errorf("net3 (no mac) was included: %+v", macs)
	}
	// "net-1" and "net+4" are not netN keys. strconv.Atoi alone accepts
	// both a leading "-" and a leading "+", so without an explicit
	// digits-only check they would land at index -1 and index 4 — the
	// second silently colliding with a real net4 if the VM had one.
	if _, ok := macs[-1]; ok {
		t.Errorf("net-1 was parsed as index -1: %+v", macs)
	}
	if _, ok := macs[4]; ok {
		t.Errorf("net+4 was parsed as index 4: %+v", macs)
	}
	// An all-digits suffix that overflows int is still not an index — the
	// digits-only check passes it through to strconv.Atoi, which must be
	// allowed to reject it rather than yielding a wrapped value.
	for n := range macs {
		if n < 0 || n > 10 {
			t.Errorf("an overflowing netN key produced index %d: %+v", n, macs)
		}
	}
}

// TestVMNetMACs_JoinsAgainstAgentInterfaces is the end-to-end correlation
// of the two independently-fetched sets this unit is named for.
func TestVMNetMACs_JoinsAgainstAgentInterfaces(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			_, _ = w.Write([]byte(`{"data":{"net0":"virtio=BC:24:11:2E:C5:4A,bridge=vmbr0"}}`))
		case strings.HasSuffix(r.URL.Path, "/agent/network-get-interfaces"):
			_, _ = w.Write([]byte(`{"data":{"result":[
				{"name":"lo","hardware-address":"00:00:00:00:00:00","ip-addresses":[]},
				{"name":"eth0","hardware-address":"bc:24:11:2e:c5:4a","ip-addresses":[
					{"ip-address":"fe80::1","ip-address-type":"ipv6","prefix":64},
					{"ip-address":"10.0.0.10","ip-address-type":"ipv4","prefix":24}
				]}
			]}}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	c := testClient(t, srv)
	ctx := context.Background()

	macs, err := c.VMNetMACs(ctx, "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("VMNetMACs: %v", err)
	}
	ifaces, err := c.AgentInterfaces(ctx, "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("AgentInterfaces: %v", err)
	}

	addr, err := AddressForMAC(ifaces, macs[0])
	if err != nil {
		t.Fatalf("AddressForMAC: %v", err)
	}
	if addr.Address != "10.0.0.10" {
		t.Errorf("address = %q, want 10.0.0.10", addr.Address)
	}
	if addr.Type != "ipv4" || addr.Prefix != 24 {
		t.Errorf("address metadata = %+v, want ipv4/24", addr)
	}
}

// --- validation and empty-result boundaries ------------------------------

func TestGuestAgentCalls_RejectMissingNodeBeforeAnyRequest(t *testing.T) {
	var calls int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	c := testClient(t, srv)
	ctx := context.Background()

	if _, err := c.AgentExec(ctx, "", 100, []string{"/bin/true"}, ""); err == nil {
		t.Error("AgentExec with empty node returned nil error")
	}
	if _, err := c.AgentExecStatus(ctx, "", 100, 1); err == nil {
		t.Error("AgentExecStatus with empty node returned nil error")
	}
	if _, err := c.WaitForAgentExec(ctx, "", 100, 1, time.Millisecond, time.Millisecond); err == nil {
		t.Error("WaitForAgentExec with empty node returned nil error")
	}
	if _, err := c.AgentInterfaces(ctx, "", 100); err == nil {
		t.Error("AgentInterfaces with empty node returned nil error")
	}
	if _, err := c.VMNetMACs(ctx, "", 100); err == nil {
		t.Error("VMNetMACs with empty node returned nil error")
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("server was hit %d times, want 0 — validation must short-circuit before any request", got)
	}
}

func TestAgentExec_RejectsEmptyCommandBeforeAnyRequest(t *testing.T) {
	var calls int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"pid":1}}`))
	})
	c := testClient(t, srv)
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		command []string
		wantIn  string
	}{
		{"nil", nil, "command is required"},
		{"empty slice", []string{}, "command is required"},
		{"empty element", []string{"/bin/sh", ""}, "command element 1 is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.AgentExec(ctx, "qa-pve-01", 100, tc.command, "")
			if err == nil {
				t.Fatal("AgentExec returned nil error")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantIn)
			}
		})
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("server was hit %d times, want 0", got)
	}
}

// TestAgentInterfaces_EmptyResultIsAnEmptySliceNotAnError keeps "the
// agent answered and reported nothing" readable as itself. The refusal
// belongs to AddressForMAC, which is asserted here too so the two halves
// stay connected.
func TestAgentInterfaces_EmptyResultIsAnEmptySliceNotAnError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"result":[]}}`))
	})
	c := testClient(t, srv)

	ifaces, err := c.AgentInterfaces(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("AgentInterfaces: %v", err)
	}
	if len(ifaces) != 0 {
		t.Errorf("got %d interfaces, want 0", len(ifaces))
	}
	if _, err := AddressForMAC(ifaces, "BC:24:11:2E:C5:4A"); !errors.Is(err, ErrNoGuestInterfaces) {
		t.Errorf("AddressForMAC error = %v, want ErrNoGuestInterfaces", err)
	}
}

func TestAgentInterfaces_RejectsUnusableResponses(t *testing.T) {
	for _, tc := range []struct{ name, body, wantIn string }{
		{"null data", `{"data":null}`, "got null"},
		{"bare array, no result envelope", `{"data":[{"name":"eth0"}]}`, "cannot unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			c := testClient(t, srv)

			if _, err := c.AgentInterfaces(context.Background(), "qa-pve-01", 100); err == nil {
				t.Fatal("AgentInterfaces returned nil error")
			} else if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantIn)
			}
		})
	}
}

func TestAgentExecStatus_RejectsNullPayload(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	})
	c := testClient(t, srv)

	status, err := c.AgentExecStatus(context.Background(), "qa-pve-01", 100, 1)
	if err == nil {
		t.Fatalf("AgentExecStatus returned (%+v, nil), want an error", status)
	}
	if status != nil {
		t.Errorf("status = %+v, want nil", status)
	}
	if !strings.Contains(err.Error(), "got null") {
		t.Errorf("error = %q, want it to name the null response", err)
	}
}

func TestVMNetMACs_RejectsUnusableResponses(t *testing.T) {
	for _, tc := range []struct{ name, body, wantIn string }{
		{"null data", `{"data":null}`, "got null"},
		{"array instead of object", `{"data":[]}`, "cannot unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			})
			c := testClient(t, srv)

			if _, err := c.VMNetMACs(context.Background(), "qa-pve-01", 100); err == nil {
				t.Fatal("VMNetMACs returned nil error")
			} else if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantIn)
			}
		})
	}
}

func TestAgentExecStatus_SucceededIsFalseBeforeTheGate(t *testing.T) {
	var nilStatus *AgentExecStatus
	if nilStatus.Succeeded() {
		t.Error("nil status reported Succeeded() = true")
	}
	running := decodeStatusForTest(t, `{"exited":0,"exitcode":0}`)
	if running.Succeeded() {
		t.Error("a still-running command reported Succeeded() = true")
	}
}

// --- helpers -------------------------------------------------------------

func intPtr(n int) *int { return &n }

// decodeStatusForTest runs one exec-status payload through the real
// client path, so these tests exercise the production decoder rather
// than a parallel one written for the test.
func decodeStatusForTest(t *testing.T, payload string) *AgentExecStatus {
	t.Helper()
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%s}`, payload)))
	})
	c := testClient(t, srv)
	status, err := c.AgentExecStatus(context.Background(), "qa-pve-01", 100, 1)
	if err != nil {
		t.Fatalf("decoding %s: %v", payload, err)
	}
	return status
}
