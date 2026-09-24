package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-post-apply-verification-and-pending, P3, through runRoot: vm
// create's created-not-found and re-read warnings, user and group ensure's
// read-back warning, and vm set's already-set-but-pending notices and its
// no-op check's warning — each advisory: exit 0 and stdout unchanged.

const createdNotFoundPrefix = "warning: qa-pve-01: vm 101: the change was applied but PVE then reported it does not exist: "

// CV1: a create whose task succeeded but whose VM PVE then says does not
// exist is exactly one warning, and not the re-read one; a clean create, the
// control, prints nothing on stderr.
func TestVMCreate_CreatedButNotFound_Warns(t *testing.T) {
	f := newTagCluster(nil)
	f.afterCreate = "missing"
	rp := f.start(t)
	code, stdout, stderr := createTagged(rp, 101, "x")
	if code != 0 || stdout != "qa-pve-01: vm 101 created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0 and the created line", code, stdout, stderr)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, createdNotFoundPrefix) || !strings.Contains(stderr, "does not exist") {
		t.Errorf("stderr = %q, want exactly one line starting %q", stderr, createdNotFoundPrefix)
	}
	if strings.Contains(stderr, "could not be re-read") {
		t.Errorf("stderr = %q: the re-read was answered, so no re-read warning", stderr)
	}

	f = newTagCluster(nil)
	rp = f.start(t)
	if code, stdout, stderr := createTagged(rp, 101, "x"); code != 0 || stdout != "qa-pve-01: vm 101 created\n" || stderr != "" {
		t.Errorf("clean create: exit %d, stdout %q, stderr %q; want 0, the created line, no stderr", code, stdout, stderr)
	}
}

// CV2: the order on stderr is the re-read's warning or the post-create
// check's (they cannot both occur), then the --unique-tag visibility
// warning — all after the created line, none on stdout.
func TestVMCreate_WarningOrder(t *testing.T) {
	for mode, first := range map[string]string{
		"missing": createdNotFoundPrefix,
		"fail":    "warning: qa-pve-01: vm 101: the write was applied but its result could not be re-read: ",
	} {
		t.Run(mode, func(t *testing.T) {
			f := newTagCluster(nil)
			f.lag = 1 << 30
			f.afterCreate = mode
			rp := f.start(t)
			tagVisibilityBound = 50 * time.Millisecond
			code, stdout, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
			if code != 0 || stdout != "qa-pve-01: vm 101 created\n" {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], first) ||
				!strings.HasPrefix(lines[1], "warning: qa-pve-01: vm 101: tag x is not yet in PVE's cluster resource list") {
				t.Errorf("stderr lines = %q, want %q… then the tag visibility warning", lines, first)
			}
		})
	}
}

// accessFailAfterWrite is accessSetup whose token REST answers the list
// route from before until root has run a pveum write, then a 500: the
// re-read after a write that succeeded fails.
func accessFailAfterWrite(t *testing.T, route, before string, answers map[string]string) string {
	t.Helper()
	var written atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method+" "+r.URL.Path != route {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if written.Load() {
			http.Error(w, "pve says no", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(before))
	}))
	t.Cleanup(srv.Close)
	answer := pveumFake(answers)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if isPveumWrite(cmd) {
			written.Store(true)
		}
		return answer(cmd)
	})
	path := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return path
}

// UA1: user ensure whose write PVE accepted but whose re-read lacks the
// user warns once, after the created line and before the password notice.
// UA2 (Chair ruling 2): a re-read that fails is the re-read warning only,
// never a false read-back mismatch.
func TestUserEnsure_ReadBackWarnings(t *testing.T) {
	answers := map[string]string{"pveum role list": cliRoleList, "pveum acl list": `[]`}
	// The fake never reflects the add: the re-read still lacks alice.
	path, _, _ := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, answers)
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "ops")
	if code != 0 || stdout != "qa-pve-01: user alice@pve created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	const mismatch = "warning: qa-pve-01: user alice@pve: the change was applied but it does not read back as requested: "
	if len(lines) != 2 || !strings.HasPrefix(lines[0], mismatch) || !strings.Contains(lines[0], "reads back as absent") ||
		!strings.HasPrefix(lines[1], "notice: qa-pve-01: user alice@pve has no password") {
		t.Errorf("stderr lines = %q, want the mismatch warning then the password notice", lines)
	}

	path = accessFailAfterWrite(t, "GET /api2/json/access/users", usersWithoutAlice, answers)
	code, stdout, stderr = runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "ops")
	if code != 0 || stdout != "qa-pve-01: user alice@pve created\n" {
		t.Fatalf("failed re-read: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !strings.HasPrefix(stderr, "warning: qa-pve-01: user alice@pve: the write was applied but its result could not be re-read: ") ||
		strings.Contains(stderr, "does not read back") {
		t.Errorf("failed re-read: stderr %q, want the re-read warning and no mismatch", stderr)
	}
}

// GA1/GA2: the same for group ensure.
func TestGroupEnsure_ReadBackWarnings(t *testing.T) {
	path, _, _ := accessSetup(t, map[string]string{"GET /api2/json/access/groups": `{"data":[{"groupid":"dev"}]}`}, nil)
	code, stdout, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops", "--comment", "Ops team")
	const mismatch = "warning: qa-pve-01: group ops: the change was applied but it does not read back as requested: "
	if code != 0 || stdout != "qa-pve-01: group ops created\n" || strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, mismatch) {
		t.Errorf("exit %d, stdout %q, stderr %q; want one mismatch warning", code, stdout, stderr)
	}

	path = accessFailAfterWrite(t, "GET /api2/json/access/groups", `{"data":[{"groupid":"dev"}]}`, nil)
	code, stdout, stderr = runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops", "--comment", "Ops team")
	if code != 0 || stdout != "qa-pve-01: group ops created\n" || strings.Count(stderr, "\n") != 1 ||
		!strings.HasPrefix(stderr, "warning: qa-pve-01: group ops: the write was applied but its result could not be re-read: ") {
		t.Errorf("failed re-read: exit %d, stdout %q, stderr %q; want the re-read warning only", code, stdout, stderr)
	}
}

const alreadyPendingSuffix = " is already set but still pending: it takes effect at the VM's next cold boot\n"

// VS1: a no-op vm set of a field PVE still holds pending is one notice for
// it — not for a pending key the command did not ask for — with one
// /pending read, nothing on stdout, exit 0.
func TestVMSet_Noop_AlreadySetButPending(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"cores","value":1,"pending":2},{"key":"memory","value":2048,"pending":4096}]`
	}, "cores=2")
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0 and nothing on stdout", code, stdout, stderr)
	}
	if want := "notice: qa-pve-01: vm 100: cores" + alreadyPendingSuffix; stderr != want {
		t.Errorf("stderr:\n got:  %q\n want: %q", stderr, want)
	}
	if f.pendingReads != 1 || f.cloudInitReads != 0 {
		t.Errorf("pending reads %d, cloud-init reads %d; want 1 and 0", f.pendingReads, f.cloudInitReads)
	}
}

// VS2 (ruling c2): a no-op --delete of a key already absent whose removal
// PVE still holds pending is one notice.
func TestVMSet_Noop_AlreadyDeletedButPending(t *testing.T) {
	_, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"tags","value":"a","delete":1},{"key":"agent","value":"1","delete":1}]`
	}, "--delete", "tags")
	want := "notice: qa-pve-01: vm 100: delete=tags is already done but still pending: it takes effect at the VM's next cold boot\n"
	if code != 0 || stdout != "" || stderr != want {
		t.Errorf("exit %d, stdout %q, stderr:\n got:  %q\n want: %q", code, stdout, stderr, want)
	}
}

// VS3: a no-op of a cloud-init field not yet on the drive is one notice.
func TestVMSet_Noop_AlreadySetButNotOnTheCloudInitDrive(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.config["ipconfig0"] = "ip=dhcp"
		f.cloudInitBody = `[{"key":"ipconfig0","value":"ip=10.0.0.5/24","pending":"ip=dhcp"}]`
	}, "ipconfig0=ip=dhcp")
	want := "notice: qa-pve-01: vm 100: ipconfig0 is already set but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start\n"
	if code != 0 || stdout != "" || stderr != want {
		t.Errorf("exit %d, stdout %q, stderr:\n got:  %q\n want: %q", code, stdout, stderr, want)
	}
	if f.pendingReads != 1 || f.cloudInitReads != 1 {
		t.Errorf("pending reads %d, cloud-init reads %d; want 1 each", f.pendingReads, f.cloudInitReads)
	}
}

// VS4 (ruling c3): a no-op whose check fails is one quoted warning that says
// nothing needed changing — it must never say a change was applied — for
// /pending and for the cloud-init drive alike. (T12 and CT3 pin the
// Changed=true wording at this same site.)
func TestVMSet_Noop_CheckFails_NeverSaysApplied(t *testing.T) {
	for name, tc := range map[string]struct {
		extra  []string
		script func(f *deleteFakePVE)
		prefix string
	}{
		"pending": {[]string{"cores=2"}, func(f *deleteFakePVE) {
			f.pendingStatus = http.StatusInternalServerError
			f.pendingBody = "boom\nnotice: forged"
		}, "warning: qa-pve-01: vm 100: nothing needed changing but whether it is pending could not be checked: "},
		"cloud-init": {[]string{"ciuser=a"}, func(f *deleteFakePVE) {
			f.config["ciuser"] = "a"
			f.cloudInitStatus = http.StatusInternalServerError
			f.cloudInitBody = "boom\nnotice: forged"
		}, "warning: qa-pve-01: vm 100: nothing needed changing but whether it has reached the cloud-init drive could not be checked: "},
	} {
		t.Run(name, func(t *testing.T) {
			_, code, stdout, stderr := runVMSetPending(t, tc.script, tc.extra...)
			if code != 0 || stdout != "" {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, tc.prefix) || !strings.Contains(stderr, `boom\nnotice: forged`) {
				t.Errorf("stderr = %q, want one line starting %q, quoting the cause", stderr, tc.prefix)
			}
			if strings.Contains(stderr, "was applied") {
				t.Errorf("stderr = %q: a no-op must not say a change was applied", stderr)
			}
		})
	}
}

// VS5 (ruling c1): a mixed batch — cores changes, description is skipped
// because it already reads as set but PVE still holds it pending — gets P1's
// notice for cores, then the already-set notice for description, from one
// /pending read.
func TestVMSet_MixedBatch_ReportsTheSkippedPendingKey(t *testing.T) {
	f, code, stdout, stderr := runVMSetPending(t, func(f *deleteFakePVE) {
		f.pendingBody = `[{"key":"cores","value":2,"pending":4},{"key":"description","value":"old","pending":"x"},{"key":"memory","pending":4096}]`
	}, "cores=4", "description=x")
	if code != 0 || stdout != "qa-pve-01: cores=4\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0 and only the changed line", code, stdout, stderr)
	}
	want := "notice: qa-pve-01: vm 100: cores is pending: it takes effect at the VM's next cold boot\n" +
		"notice: qa-pve-01: vm 100: description" + alreadyPendingSuffix
	if stderr != want {
		t.Errorf("stderr:\n got:  %q\n want: %q", stderr, want)
	}
	if f.pendingReads != 1 || f.cloudInitReads != 0 {
		t.Errorf("pending reads %d, cloud-init reads %d; want 1 and 0", f.pendingReads, f.cloudInitReads)
	}
}

// WP1 (ruling c3): warnPostCheck words its lead by changed. The sites where
// Changed=false cannot carry a PostApplyErr (vm create refuses a no-op
// before it reports; UserEnsure and GroupEnsure are not NoopCheckers) share
// this one helper, so its false branch is pinned here.
func TestWarnPostCheck_WordsByChanged(t *testing.T) {
	cause := errors.New("boom\nwarning: forged")
	for _, kind := range []struct{ kind, id, question string }{
		{"vm", "101", "PVE then reported it does not exist"},
		{"user", "alice@pve", "it does not read back as requested"},
		{"group", "ops", "it does not read back as requested"},
		{"vm", "100", "whether it is pending could not be checked"},
	} {
		var applied, noop, none strings.Builder
		warnPostCheck(&applied, "qa-pve-01", kind.kind, kind.id, true, kind.question, cause)
		warnPostCheck(&noop, "qa-pve-01", kind.kind, kind.id, false, kind.question, cause)
		warnPostCheck(&none, "qa-pve-01", kind.kind, kind.id, true, kind.question, nil)
		head := "warning: qa-pve-01: " + kind.kind + " " + kind.id + ": "
		if want := head + "the change was applied but " + kind.question + `: "boom\nwarning: forged"` + "\n"; applied.String() != want {
			t.Errorf("changed:\n got:  %q\n want: %q", applied.String(), want)
		}
		if want := head + "nothing needed changing but " + kind.question + `: "boom\nwarning: forged"` + "\n"; noop.String() != want {
			t.Errorf("no-op:\n got:  %q\n want: %q", noop.String(), want)
		}
		if strings.Contains(noop.String(), "was applied") {
			t.Errorf("no-op wording says a change was applied: %q", noop.String())
		}
		if none.Len() != 0 {
			t.Errorf("no error printed %q", none.String())
		}
	}
}

// The already-set notices quote their key like P1's, pinned directly: a
// key that could forge a line is written as one JSON string, in all four.
func TestReportPending_AlreadyNoticesQuoteTheKey(t *testing.T) {
	op := &idempotent.VMFieldsEnsure{
		AlreadyPending:               []string{"a\nnotice: forged"},
		AlreadyPendingDeletes:        []string{"b\nnotice: forged"},
		AlreadyCloudInitStale:        []string{"c\nnotice: forged"},
		AlreadyCloudInitStaleDeletes: []string{"d\nnotice: forged"},
	}
	var out strings.Builder
	reportPending(&out, "qa-pve-01", 100, op, false, nil)
	want := `notice: qa-pve-01: vm 100: "a\nnotice: forged"` + alreadyPendingSuffix +
		`notice: qa-pve-01: vm 100: delete="b\nnotice: forged" is already done but still pending: it takes effect at the VM's next cold boot` + "\n" +
		`notice: qa-pve-01: vm 100: "c\nnotice: forged" is already set but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start` + "\n" +
		`notice: qa-pve-01: vm 100: delete="d\nnotice: forged" is already done but not yet on the cloud-init drive: the guest sees it after the drive is regenerated at the VM's next start` + "\n"
	if out.String() != want {
		t.Errorf("notices:\n got:  %q\n want: %q", out.String(), want)
	}
	if strings.Count(out.String(), "\n") != 4 {
		t.Errorf("a key forged a line: %q", out.String())
	}
}
