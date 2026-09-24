package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
)

// P2′ through runRoot: a cloud-init change vm set made that is not yet on the
// VM's cloud-init drive is one quoted stderr notice; stdout and the exit
// status are what they were.

const ciNotice = " is saved but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n"

// CT1: a write and a delete of cloud-init keys, both not yet on the drive,
// are one notice each, in that order; stdout is exactly the applied lines.
func TestVMSet_CloudInitNotices_ThroughRunRoot(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.config["ciuser"] = "old"
		f.cloudInitBody = `[{"key":"ipconfig0","value":"ip=dhcp","pending":"ip=10.0.0.5/24"},{"key":"ciuser","value":"old","delete":1}]`
	}, "ipconfig0=ip=10.0.0.5/24", "--delete", "ciuser")
	if code != 0 {
		t.Fatalf("exit %d; stderr %q", code, stderr)
	}
	if want := "qa-pve-01: ipconfig0=ip=10.0.0.5/24\nqa-pve-01: delete=ciuser\n"; stdout != want {
		t.Errorf("stdout = %q, want exactly %q", stdout, want)
	}
	want := "notice: qa-pve-01: vm 100: ipconfig0" + ciNotice + "notice: qa-pve-01: vm 100: delete=ciuser" + ciNotice
	if stderr != want {
		t.Errorf("stderr:\n got:  %q\n want: %q", stderr, want)
	}
	if f.pendingReads != 1 || f.cloudInitReads != 1 {
		t.Errorf("reads: pending %d, cloud-init %d; want 1 and 1", f.pendingReads, f.cloudInitReads)
	}
}

// CT2: a cloud-init change already on the drive prints nothing.
func TestVMSet_CloudInitClean_NoStderr(t *testing.T) {
	f, code, _, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.cloudInitBody = `[{"key":"sshkeys","value":"k"}]`
	}, "sshkeys=k")
	if code != 0 || stderr != "" || f.cloudInitReads != 1 {
		t.Fatalf("exit %d, stderr %q, cloud-init reads %d; want 0, nothing, 1", code, stderr, f.cloudInitReads)
	}
}

// CT3: a failed cloud-init check — a 5xx whose body carries a line break and
// a forged notice — is one quoted warning saying it is the cloud-init drive
// that could not be checked (RCI2: /pending was answered); exit 0, stdout
// unchanged.
func TestVMSet_CloudInitCheckFails_OneQuotedWarning(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.cloudInitStatus = http.StatusInternalServerError
		f.cloudInitBody = "boom\nnotice: forged"
	}, "nameserver=9.9.9.9")
	if code != 0 || stdout != "qa-pve-01: nameserver=9.9.9.9\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if strings.Count(stderr, "\n") != 1 ||
		!strings.HasPrefix(stderr, `warning: qa-pve-01: vm 100: the change was applied but whether it has reached the cloud-init drive could not be checked: "`) ||
		!strings.Contains(stderr, "cloud-init") || !strings.Contains(stderr, `boom\nnotice: forged`) {
		t.Errorf("stderr = %q, want one quoted warning naming the cloud-init read", stderr)
	}
}

// CT4: a change to no cloud-init key never reads /cloudinit.
func TestVMSet_NoCloudInitKey_NoCloudInitRead(t *testing.T) {
	f, code, _, stderr := runVMSetPending(t, func(*deleteFakePVE) {}, "cores=4")
	if code != 0 || stderr != "" || f.cloudInitReads != 0 {
		t.Fatalf("exit %d, stderr %q, cloud-init reads %d; want 0, nothing, 0", code, stderr, f.cloudInitReads)
	}
}

// CT5: a cloud-init key /pending already reports is its pending notice
// only, never a second, cloud-init one — and /cloudinit is not read.
func TestVMSet_CloudInitKeyAlreadyPending_ReportedOnce(t *testing.T) {
	f, code, _, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"ipconfig0","pending":"ip=10.0.0.5/24"}]`
		f.cloudInitBody = `[{"key":"ipconfig0","pending":"ip=10.0.0.5/24"}]`
	}, "ipconfig0=ip=10.0.0.5/24")
	want := "notice: qa-pve-01: vm 100: ipconfig0 is pending: it takes effect at the VM's next cold boot\n"
	if code != 0 || stderr != want || f.cloudInitReads != 0 {
		t.Fatalf("exit %d, cloud-init reads %d, stderr %q; want 0, 0, %q", code, f.cloudInitReads, stderr, want)
	}
}

// CT6: when /pending found something and the cloud-init check then fails,
// the pending notice still prints, before the warning.
func TestVMSet_PendingNoticeSurvivesACloudInitFailure(t *testing.T) {
	_, code, _, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"cores","pending":4}]`
		f.cloudInitStatus = http.StatusBadGateway
		f.cloudInitBody = "proxy down"
	}, "cores=4", "sshkeys=k")
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if code != 0 || len(lines) != 2 ||
		lines[0] != "notice: qa-pve-01: vm 100: cores is pending: it takes effect at the VM's next cold boot" ||
		!strings.HasPrefix(lines[1], "warning: qa-pve-01: vm 100: the change was applied but whether it has reached the cloud-init drive could not be checked: ") {
		t.Fatalf("exit %d, stderr %q; want the pending notice, then the warning", code, stderr)
	}
}

// CT7 (RCI2): when /pending itself fails, the warning is P1's — whether the
// change is pending could not be checked — and /cloudinit is not read.
func TestVMSet_PendingCheckFailsFirst_P1Warning(t *testing.T) {
	f, code, _, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingStatus = http.StatusInternalServerError
		f.pendingBody = "boom"
	}, "sshkeys=k")
	if code != 0 || f.cloudInitReads != 0 || strings.Count(stderr, "\n") != 1 ||
		!strings.HasPrefix(stderr, "warning: qa-pve-01: vm 100: the change was applied but whether it is pending could not be checked: ") {
		t.Fatalf("exit %d, cloud-init reads %d, stderr %q; want 0, 0 and P1's one warning", code, f.cloudInitReads, stderr)
	}
}

// CT8 (RCI1): a hostname change (name) is a cloud-init change too.
func TestVMSet_NameChangeIsACloudInitNotice(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.cloudInitBody = `[{"key":"name","value":"web-01","pending":"web-02"}]`
	}, "name=web-02")
	if code != 0 || stdout != "qa-pve-01: name=web-02\n" || stderr != "notice: qa-pve-01: vm 100: name"+ciNotice || f.cloudInitReads != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q, reads %d", code, stdout, stderr, f.cloudInitReads)
	}
}

// The cloud-init notices quote their key like P1's. No line-unsafe key can
// reach them through vm set today — isCloudInitKey admits only fixed names
// and digit-indexed ones — so the rendering is pinned directly: a key that
// could forge a line is written as one JSON string, in both notices.
func TestReportPending_CloudInitNoticeQuotesTheKey(t *testing.T) {
	op := &idempotent.VMFieldsEnsure{
		CloudInitStale:        []string{"a\nnotice: forged"},
		CloudInitStaleDeletes: []string{"b\nnotice: forged"},
	}
	var out strings.Builder
	reportPending(&out, "qa-pve-01", 100, op, nil)
	want := `notice: qa-pve-01: vm 100: "a\nnotice: forged"` + ciNotice + `notice: qa-pve-01: vm 100: delete="b\nnotice: forged"` + ciNotice
	if out.String() != want {
		t.Errorf("notices:\n got:  %q\n want: %q", out.String(), want)
	}
	if strings.Count(out.String(), "\n") != 2 {
		t.Errorf("a key forged a line: %q", out.String())
	}
}
