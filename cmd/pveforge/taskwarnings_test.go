package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// A PVE task that ends "WARNINGS: <n>" succeeded, as PVE counts it
// (PVE::UPID::status_is_error): the command exits 0 and says so on stderr,
// one quoted notice per task, through the whole CLI (runRoot installs the
// reporter). A clean OK adds no notice, and any other exit status is still
// a failure.

func warningsNotice(upid, exit string) string {
	return fmt.Sprintf("notice: PVE task %s on node %s succeeded with warnings (%s): its task log has them\n",
		kvjson.QuoteValue(upid), kvjson.QuoteValue("qa-pve-01"), kvjson.QuoteValue(exit))
}

func TestRunRoot_APITaskExitStatus(t *testing.T) {
	upid := apiTestUPID("qa-pve-01")
	dispatched := fmt.Sprintf("dispatched PVE task %s\n", kvjson.QuoteValue(upid))
	cases := []struct {
		exit, wantStderr string
		wantCode         int
	}{
		{"OK", dispatched, 0},
		{"WARNINGS: 2", dispatched + warningsNotice(upid, "WARNINGS: 2"), 0},
		{"WARNINGS: 2x", dispatched + fmt.Sprintf("task %s failed: WARNINGS: 2x\n", upid), 1},
	}
	for _, tc := range cases {
		t.Run(tc.exit, func(t *testing.T) {
			withFastTaskPolls(t)
			f := &apiTaskFake{
				mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
				body:    fmt.Sprintf("%q", upid),
				status: func(int32) (int, string) {
					return http.StatusOK, taskPayload(upid, "stopped", tc.exit)
				},
			}
			rosterPath := newAPITaskServer(t, f)

			code, stdout, stderr := runRootArgs("api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01")

			if code != tc.wantCode || stderr != tc.wantStderr {
				t.Errorf("exit %d, stderr %q\nwant exit %d, stderr %q", code, stderr, tc.wantCode, tc.wantStderr)
			}
			if tc.wantCode == 0 && stdout != apiRenderedUPID("kv", upid) {
				t.Errorf("stdout = %q", stdout)
			}
			if got := atomic.LoadInt32(&f.polls); got != 1 {
				t.Errorf("task-status polls = %d, want 1", got)
			}
		})
	}
}

// vm create reaches WaitForTask through idempotent.Run, with the command's
// own context: the notice arrives from there too.
func TestRunRoot_VMCreateTaskWithWarnings(t *testing.T) {
	f := &vmCreateFake{taskExit: "WARNINGS: 1"}
	srv := newVMCreateServer(t, "qa-pve-01", 100, f)
	defer srv.Close()
	code, stdout, stderr := runRootArgs("vm", "create", "--roster", vmCreateRoster(t, srv), "qa-pve-01", "100", "cores=4")
	upid := "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:100:root@pam:"
	if code != 0 || stdout != "qa-pve-01: vm 100 created\n" || stderr != warningsNotice(upid, "WARNINGS: 1") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// TW1: the notice reaches stderr when the root already carries a context,
// as realMain's does (notifyInterrupt): runRoot must add the reporter to
// that context, not only give one to a root that has none.
func TestRunRoot_TaskWarningsWithAContextAlreadySet(t *testing.T) {
	withFastTaskPolls(t)
	upid := apiTestUPID("qa-pve-01")
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "stopped", "WARNINGS: 4") },
	}
	rosterPath := newAPITaskServer(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	code, stderr, _ := runRootWithin(ctx, "api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 0 || !strings.HasSuffix(stderr, warningsNotice(upid, "WARNINGS: 4")) {
		t.Errorf("exit %d, stderr %q; want exit 0 ending in the warnings notice", code, stderr)
	}
}

// TW2: the notice's values come from PVE, so each is quoted and bounded
// like error text. WaitForTask refuses a UPID outside PVE's grammar before
// any poll, so a line-breaking UPID never reaches the notice end to end;
// the quoting is pinned here directly, as defence in depth.
func TestTaskWarningsNotice_QuotesAndBounds(t *testing.T) {
	for _, upid := range []string{
		"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:root\u2028pam:",
		"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:root\npam:",
	} {
		var buf bytes.Buffer
		taskWarningsNotice(&buf)("qa-pve-01", upid, "WARNINGS: 1")
		if got, want := buf.String(), warningsNotice(upid, "WARNINGS: 1"); got != want {
			t.Errorf("notice = %q, want %q", got, want)
		}
		if strings.ContainsAny(buf.String()[:buf.Len()-1], "\n\u2028") {
			t.Errorf("notice %q carries a raw line break", buf.String())
		}
	}
	var buf bytes.Buffer
	taskWarningsNotice(&buf)("qa-pve-01", "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:"+strings.Repeat("u", 6000)+":", "WARNINGS: 1")
	if !strings.Contains(buf.String(), "bytes elided]") || buf.Len() > maxErrTextBytes+200 {
		t.Errorf("notice not bounded (%d bytes)", buf.Len())
	}
}

// A UPID outside PVE's grammar (here, U+2028 in its user field) is refused
// as an unverifiable read before any poll: exit 1, no notice, and the
// character never reaches stderr raw.
func TestRunRoot_UPIDOutsidePVEGrammarIsRefusedBeforeAnyPoll(t *testing.T) {
	withFastTaskPolls(t)
	upid := "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:root\u2028pam:"
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "stopped", "WARNINGS: 1") },
	}
	rosterPath := newAPITaskServer(t, f)
	code, _, stderr := runRootArgs("api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	if code != 1 || !strings.Contains(stderr, "malformed upid") || !strings.Contains(stderr, "unverifiable read") {
		t.Errorf("exit %d, stderr %q; want exit 1 and the malformed-upid refusal", code, stderr)
	}
	if strings.Contains(stderr, "notice: PVE task") || strings.Contains(stderr, "\u2028") {
		t.Errorf("stderr %q carries a notice or a raw U+2028", stderr)
	}
	if got := atomic.LoadInt32(&f.polls); got != 0 {
		t.Errorf("task-status polls = %d, want 0: the UPID is refused before any poll", got)
	}
}

// An over-long UPID inside PVE's grammar reaches the notice, bounded.
func TestRunRoot_TaskWarningsNoticeIsBoundedEndToEnd(t *testing.T) {
	withFastTaskPolls(t)
	upid := "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstart:100:" + strings.Repeat("u", 6000) + ":"
	f := &apiTaskFake{
		mutPath: "/nodes/qa-pve-01/qemu/100/status/start",
		body:    fmt.Sprintf("%q", upid),
		status:  func(int32) (int, string) { return http.StatusOK, taskPayload(upid, "stopped", "WARNINGS: 1") },
	}
	rosterPath := newAPITaskServer(t, f)
	code, _, stderr := runRootArgs("api", "post", "--roster", rosterPath, f.mutPath, "qa-pve-01")
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	last := lines[len(lines)-1]
	if code != 0 || !strings.HasPrefix(last, "notice: PVE task ") || !strings.Contains(last, "bytes elided]") || len(last) > maxErrTextBytes+200 {
		t.Errorf("exit %d; last stderr line not a bounded notice (%d bytes): %.200q", code, len(last), last)
	}
}
