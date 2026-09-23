package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// post-apply-verify, through runRoot: after vm set changed something, the
// keys PVE holds as pending are one quoted notice each on stderr; stdout and
// the exit status are what they were.

// runVMSetPending runs vm set against a deleteFakePVE (VM 100: cores=2,
// description=x) whose /pending answer the test scripts first.
func runVMSetPending(t *testing.T, script func(f *deleteFakePVE), extra ...string) (f *deleteFakePVE, code int, stdout, stderr string) {
	t.Helper()
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	f, srv := newDeleteFakePVE(t, map[string]string{"cores": "2", "description": "x"})
	script(f)
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	code, stdout, stderr = runRootArgs(append([]string{"vm", "set", "--roster", rp, "qa-pve-01", "100"}, extra...)...)
	return f, code, stdout, stderr
}

// T10: one notice per pending key of this run — a write, then a delete — in
// that order; a key someone else left pending is not reported; stdout is
// exactly the applied lines; exit 0.
func TestVMSet_PendingNotices_ThroughRunRoot(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"cores","value":2,"pending":4},{"key":"description","value":"x","delete":1},{"key":"memory","value":2048,"pending":4096}]`
	}, "cores=4", "--delete", "description")
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: cores=4\nqa-pve-01: delete=description\n"; stdout != want {
		t.Errorf("stdout = %q, want exactly the applied lines %q", stdout, want)
	}
	want := "notice: qa-pve-01: vm 100: cores is pending: it takes effect at the VM's next cold boot\n" +
		"notice: qa-pve-01: vm 100: delete=description is pending: it takes effect at the VM's next cold boot\n"
	if stderr != want {
		t.Errorf("stderr:\n got:  %q\n want: %q", stderr, want)
	}
	if f.pendingReads != 1 {
		t.Errorf("pending reads = %d, want 1", f.pendingReads)
	}
}

// T10, quoting: a pending key that is not line-safe is quoted, in the write
// notice and in the delete notice, so it cannot forge a line of its own.
// The keys come from the operator's own arguments, which vm set passes
// through to PVE.
func TestVMSet_PendingNoticeQuotesTheKey(t *testing.T) {
	const set, del = "a\nnotice: forged", "b\nnotice: forged"
	_, code, _, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.config[del] = "x"
		f.pendingBody = `[{"key":"a\nnotice: forged","pending":"1"},{"key":"b\nnotice: forged","delete":1}]`
	}, set+"=1", "--delete", del)
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	want := `notice: qa-pve-01: vm 100: "a\nnotice: forged" is pending: it takes effect at the VM's next cold boot` + "\n" +
		`notice: qa-pve-01: vm 100: delete="b\nnotice: forged" is pending: it takes effect at the VM's next cold boot` + "\n"
	if stderr != want {
		t.Errorf("stderr:\n got:  %q\n want: %q", stderr, want)
	}
}

// T11: a clean /pending — nothing of ours pending — prints nothing on
// stderr, and a run that changed nothing does not read /pending at all.
func TestVMSet_NothingPending_NoStderr(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"cores","value":4},{"key":"memory","value":2048,"pending":4096}]`
	}, "cores=4")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0, the applied line, and no stderr", code, stdout, stderr)
	}
	if f.pendingReads != 1 {
		t.Errorf("pending reads = %d, want 1", f.pendingReads)
	}

	f, code, stdout, stderr = runVMSetPending(t, func(*deleteFakePVE) {}, "cores=2")
	if code != 0 || stdout != "" || stderr != "" || f.pendingReads != 0 {
		t.Fatalf("no-op: exit %d, stdout %q, stderr %q, pending reads %d; want 0, nothing, and no read", code, stdout, stderr, f.pendingReads)
	}
}

// T12: a /pending read that fails — a 5xx whose body carries a newline and
// a forged "notice:" line — is one quoted warning; stdout is unchanged and
// the exit is 0, since the write happened.
func TestVMSet_PendingCheckFails_OneQuotedWarning(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingStatus = http.StatusInternalServerError
		f.pendingBody = "boom\nnotice: forged"
	}, "cores=4")
	if code != 0 {
		t.Fatalf("exit %d, want 0 (the write succeeded); stderr %q", code, stderr)
	}
	if stdout != "qa-pve-01: cores=4\n" {
		t.Errorf("stdout = %q, want exactly the applied line", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasSuffix(stderr, "\n") {
		t.Fatalf("stderr must be exactly one line (a quoted cause cannot forge a second), got %q", stderr)
	}
	const prefix = "warning: qa-pve-01: vm 100: the change was applied but whether it is pending could not be checked: \""
	if !strings.HasPrefix(stderr, prefix) {
		t.Errorf("stderr = %q, want prefix %q", stderr, prefix)
	}
	if !strings.Contains(stderr, "500") || !strings.Contains(stderr, `boom\nnotice: forged`) {
		t.Errorf("stderr = %q, want the quoted cause carrying the 5xx status and body", stderr)
	}
}

// T12, unverifiable: a /pending answer no healthy PVE gives is the same
// warning — never silence, as if nothing were pending.
func TestVMSet_PendingUnverifiable_Warns(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `{"cores":{"pending":4}}`
	}, "cores=4")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" {
		t.Fatalf("exit %d, stdout %q; want 0 and the applied line", code, stdout)
	}
	if !strings.HasPrefix(stderr, "warning: qa-pve-01: vm 100: the change was applied but whether it is pending could not be checked: ") ||
		!strings.Contains(stderr, "not a JSON array") || strings.Count(stderr, "\n") != 1 {
		t.Errorf("stderr = %q, want one warning naming the unverifiable read", stderr)
	}
}

// T13: when the final re-read fails and a key is pending, the re-read
// warning comes first, then the notice — two lines, nothing else.
func TestVMSet_AfterErrThenPendingNotice(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.failGet = 3 // Run's Read, the field's digest re-fetch, then the re-read
		f.pendingBody = `[{"key":"cores","value":2,"pending":4}]`
	}, "cores=4")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" {
		t.Fatalf("exit %d, stdout %q; want 0 and the applied line; stderr %q", code, stdout, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 2 ||
		!strings.HasPrefix(lines[0], "warning: qa-pve-01: vm 100: the write was applied but its result could not be re-read: ") ||
		lines[1] != "notice: qa-pve-01: vm 100: cores is pending: it takes effect at the VM's next cold boot" {
		t.Errorf("stderr = %q, want the re-read warning, then the pending notice", stderr)
	}
}
