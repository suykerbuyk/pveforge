package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-vm-snapshot-cli, through runRoot, over snapshotFakePVE: a
// stateful fake of VM 100's snapshot, task and guest-agent endpoints on
// node qa-pve-01.

type fakeSnap struct {
	snaptime int64
	vmstate  int
	desc     string
	seq      int // the fake's list order, which breaks a snaptime tie
}

type snapshotFakePVE struct {
	t          *testing.T
	mu         sync.Mutex
	snaps      map[string]fakeSnap
	nextTime   int64
	requests   []string // "METHOD path" in order
	createForm url.Values
	deleteFail map[string]bool
	taskFail   map[string]bool // rollback target -> the task ends in failure
	taskN      int
	tasks      map[string]string // upid -> exitstatus

	// witness scripts the guest agent: "ok" echoes the command's last
	// argument, "fail" exits 1, "nomarker" exits 0 without it, "truncated"
	// exits 0 with out-truncated set, "never" refuses every dispatch (500).
	witness     string
	witnessOut  string // overrides the output for fail and nomarker
	execForms   []url.Values
	onExec      func() // called on each agent exec dispatch
	lastCommand []string
}

func newSnapshotFake(t *testing.T, names ...string) *snapshotFakePVE {
	f := &snapshotFakePVE{t: t, snaps: map[string]fakeSnap{}, nextTime: 1700000000, deleteFail: map[string]bool{}, taskFail: map[string]bool{}, tasks: map[string]string{}, witness: "ok"}
	for i, n := range names {
		f.nextTime += 100
		f.snaps[n] = fakeSnap{snaptime: f.nextTime, vmstate: 1, desc: "about " + n, seq: i}
	}
	return f
}

// start serves f over TLS and returns a roster path whose target qa-pve-01
// points at it, with fast task polling.
func (f *snapshotFakePVE) start() string {
	t := f.t
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 5*time.Second))
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
}

func (f *snapshotFakePVE) issueTask(kind string, fail bool) string {
	f.taskN++
	upid := fmt.Sprintf("UPID:qa-pve-01:%08X:0000ABCD:5F000000:%s:100:root@pam:", f.taskN, kind)
	f.tasks[upid] = "OK"
	if fail {
		f.tasks[upid] = "snapshot rollback failed: disk error"
	}
	return upid
}

func (f *snapshotFakePVE) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// count counts the requests whose "METHOD path" starts with prefix.
func (f *snapshotFakePVE) count(prefix string) int {
	n := 0
	for _, r := range f.got() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

const snapBase = "/api2/json/nodes/qa-pve-01/qemu/100"

func writeData(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(map[string]any{"data": v})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (f *snapshotFakePVE) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	onExec := f.onExec
	f.mu.Unlock()
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == snapBase+"/snapshot":
		f.mu.Lock()
		list := []map[string]any{{"name": "current", "description": "You are here!"}}
		names := make([]string, 0, len(f.snaps))
		for n := range f.snaps {
			names = append(names, n)
		}
		sort.Slice(names, func(i, j int) bool {
			a, b := f.snaps[names[i]], f.snaps[names[j]]
			if a.snaptime != b.snaptime {
				return a.snaptime < b.snaptime
			}
			return a.seq < b.seq
		})
		for i, n := range names {
			s := f.snaps[n]
			e := map[string]any{"name": n, "snaptime": s.snaptime, "vmstate": s.vmstate, "description": s.desc}
			if i > 0 {
				e["parent"] = names[i-1]
			}
			list = append(list, e)
		}
		f.mu.Unlock()
		writeData(w, list)
	case r.Method == http.MethodPost && path == snapBase+"/snapshot":
		_ = r.ParseForm()
		f.mu.Lock()
		f.createForm = r.PostForm
		f.nextTime += 100
		vmstate := 0
		if r.PostForm.Get("vmstate") == "1" {
			vmstate = 1
		}
		f.snaps[r.PostForm.Get("snapname")] = fakeSnap{snaptime: f.nextTime, vmstate: vmstate, desc: r.PostForm.Get("description")}
		upid := f.issueTask("qmsnapshot", false)
		f.mu.Unlock()
		writeData(w, upid)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, snapBase+"/snapshot/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api2/json/nodes/qa-pve-01/qemu/100/snapshot/"))
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.deleteFail[name] {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("snapshot '" + name + "' is locked"))
			return
		}
		delete(f.snaps, name)
		writeData(w, f.issueTask("qmdelsnapshot", false))
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/rollback") && strings.HasPrefix(path, snapBase+"/snapshot/"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, snapBase+"/snapshot/"), "/rollback")
		f.mu.Lock()
		upid := f.issueTask("qmrollback", f.taskFail[name])
		f.mu.Unlock()
		writeData(w, upid)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/api2/json/nodes/qa-pve-01/tasks/"):
		upid := strings.TrimSuffix(strings.TrimPrefix(path, "/api2/json/nodes/qa-pve-01/tasks/"), "/status")
		f.mu.Lock()
		exit := f.tasks[upid]
		f.mu.Unlock()
		writeData(w, map[string]any{"status": "stopped", "exitstatus": exit, "upid": upid, "node": "qa-pve-01"})
	case r.Method == http.MethodPost && path == snapBase+"/agent/exec":
		_ = r.ParseForm()
		f.mu.Lock()
		f.execForms = append(f.execForms, r.PostForm)
		f.lastCommand = r.PostForm["command"]
		mode := f.witness
		f.mu.Unlock()
		if onExec != nil {
			onExec()
		}
		if mode == "never" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("QEMU guest agent is not running"))
			return
		}
		writeData(w, map[string]any{"pid": 7})
	case r.Method == http.MethodGet && path == snapBase+"/agent/exec-status":
		f.mu.Lock()
		cmd, mode, out := f.lastCommand, f.witness, f.witnessOut
		f.mu.Unlock()
		st := map[string]any{"exited": 1, "exitcode": 0}
		switch mode {
		case "ok":
			st["out-data"] = cmd[len(cmd)-1] + "\n"
		case "fail":
			st["exitcode"], st["out-data"] = 1, out
		case "nomarker":
			st["out-data"] = out
		case "truncated":
			st["out-data"], st["out-truncated"] = "partial", 1
		}
		writeData(w, st)
	default:
		f.t.Errorf("snapshotFakePVE: unexpected request %s %s", r.Method, path)
		http.NotFound(w, r)
	}
}

func snap(rp string, args ...string) (int, string, string) {
	return runRootArgs(append(append([]string{"vm", "snapshot"}, args...), "--roster", rp)...)
}

// S1: list prints the real snapshots oldest first — never PVE's "current" —
// in kv and json.
func TestVMSnapshot_S1_List(t *testing.T) {
	f := newSnapshotFake(t, "a", "b")
	rp := f.start()
	code, stdout, stderr := snap(rp, "list", "qa-pve-01", "100")
	want := `snapshots=[{"name":"a","snaptime":1700000100,"vmstate":1,"description":"about a"},{"name":"b","snaptime":1700000200,"parent":"a","vmstate":1,"description":"about b"}]` + "\n"
	if code != 0 || stdout != want || stderr != "" {
		t.Fatalf("exit %d, stderr %q\nstdout %q\nwant   %q", code, stderr, stdout, want)
	}
	code, stdout, _ = snap(rp, "list", "qa-pve-01", "100", "-o", "json")
	var got struct{ Snapshots []snapshotView }
	if code != 0 || json.Unmarshal([]byte(stdout), &got) != nil || len(got.Snapshots) != 2 || got.Snapshots[0].Name != "a" {
		t.Errorf("json: exit %d, %q", code, stdout)
	}
}

// S2: create sends one POST with the name, vmstate=1 and the description,
// prints its result; reserved names are refused with no request; an
// existing name is refused, never adopted.
func TestVMSnapshot_S2_Create(t *testing.T) {
	f := newSnapshotFake(t, "a")
	rp := f.start()
	code, stdout, stderr := snap(rp, "create", "qa-pve-01", "100", "pre-upgrade", "--description", "before the upgrade")
	if want := "result=created\nsnapshot=pre-upgrade\ntarget=qa-pve-01\nvmid=100\n"; code != 0 || stdout != want || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if fm := f.createForm; fm.Get("snapname") != "pre-upgrade" || fm.Get("vmstate") != "1" || fm.Get("description") != "before the upgrade" {
		t.Errorf("create form = %v", fm)
	}
	for _, name := range []string{"current", "Pending"} {
		before := len(f.got())
		if code, _, stderr := snap(rp, "create", "qa-pve-01", "100", name); code != 1 || !strings.Contains(stderr, "reserved") || len(f.got()) != before {
			t.Errorf("create %q: exit %d, %d request(s), stderr %q; want a refusal before any request", name, code, len(f.got())-before, stderr)
		}
	}
	posts := f.count("POST " + snapBase + "/snapshot")
	if code, _, stderr := snap(rp, "create", "qa-pve-01", "100", "a"); code != 1 || !strings.Contains(stderr, "already exists") || f.count("POST "+snapBase+"/snapshot") != posts {
		t.Errorf("an existing name: exit %d, stderr %q; want a refusal with no POST", code, stderr)
	}
}

// S3: delete removes the named snapshots newest first, whatever order they
// are given in; reports absent names; a partial failure names what was
// already deleted, and a re-run finishes.
func TestVMSnapshot_S3_Delete(t *testing.T) {
	f := newSnapshotFake(t, "a", "b", "c")
	rp := f.start()
	code, stdout, stderr := snap(rp, "delete", "qa-pve-01", "100", "b", "c", "zz")
	if want := "absent=[\"zz\"]\ndeleted=[\"c\",\"b\"]\ntarget=qa-pve-01\nvmid=100\n"; code != 0 || stdout != want || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	var dels []string
	for _, r := range f.got() {
		if strings.HasPrefix(r, "DELETE ") {
			dels = append(dels, strings.TrimPrefix(r, "DELETE "+snapBase+"/snapshot/"))
		}
	}
	if !slices.Equal(dels, []string{"c", "b"}) {
		t.Errorf("DELETE order = %q, want [c b]: newest first", dels)
	}

	f = newSnapshotFake(t, "a", "b", "c")
	f.deleteFail["b"] = true
	rp = f.start()
	code, stdout, stderr = snap(rp, "delete", "qa-pve-01", "100", "c", "b")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "deleted so far: c") || !strings.Contains(stderr, "running the same command again is safe") {
		t.Fatalf("partial failure: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	f.mu.Lock()
	f.deleteFail["b"] = false
	f.mu.Unlock()
	if code, stdout, _ := snap(rp, "delete", "qa-pve-01", "100", "c", "b"); code != 0 || stdout != "absent=[\"c\"]\ndeleted=[\"b\"]\ntarget=qa-pve-01\nvmid=100\n" {
		t.Errorf("re-run: exit %d, stdout %q", code, stdout)
	}
}

// S4: a rollback with newer snapshots is refused before anything is sent —
// no rollback, no delete — and names them and the command that discards
// them, newest first.
func TestVMSnapshot_S4_RollbackRefusesNewer(t *testing.T) {
	f := newSnapshotFake(t, "a", "b", "c")
	rp := f.start()
	code, stdout, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a")
	if code != 1 || stdout != "" || !strings.Contains(stderr, `2 newer snapshots exist`) ||
		!strings.Contains(stderr, "to discard them first, run: pveforge vm snapshot delete 'qa-pve-01' 100 'c' 'b'") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, r := range f.got() {
		if strings.HasSuffix(r, "/rollback") || strings.HasPrefix(r, "DELETE") {
			t.Errorf("%s was sent for a refused rollback", r)
		}
	}
}

// S5: a rollback runs the witness, under ONE lock hold: the fake's agent
// handler tries the VM's lock and must find it held.
func TestVMSnapshot_S5_RollbackAndWitnessUnderOneLock(t *testing.T) {
	f := newSnapshotFake(t, "a")
	rp := f.start()
	var probed, held bool
	f.onExec = func() {
		probed = true
		ctx := lock.WithWait(context.Background(), 20*time.Millisecond)
		unlock, err := lock.Mutation(ctx, rp, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})
		if err != nil {
			held = true
			return
		}
		_ = unlock()
	}
	code, stdout, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a")
	if want := "rollback=completed\nsnapshot=a\ntarget=qa-pve-01\nvmid=100\nwitness=verified\n"; code != 0 || stdout != want || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !probed || !held {
		t.Errorf("witness ran %v, VM lock held during it %v: want one hold across rollback and witness", probed, held)
	}
	if n := f.count("POST " + snapBase + "/snapshot/a/rollback"); n != 1 {
		t.Errorf("rollback POSTs = %d, want 1", n)
	}
	var order []string
	for _, r := range f.got() {
		if strings.HasSuffix(r, "/rollback") || strings.HasSuffix(r, "/agent/exec") {
			order = append(order, r[strings.LastIndex(r, "/")+1:])
		}
	}
	if !slices.Equal(order, []string{"rollback", "exec"}) {
		t.Errorf("order = %q, want the rollback, then the witness", order)
	}
}

// S6: --no-witness skips the guest agent entirely.
func TestVMSnapshot_S6_NoWitness(t *testing.T) {
	f := newSnapshotFake(t, "a")
	rp := f.start()
	code, stdout, _ := snap(rp, "rollback", "qa-pve-01", "100", "a", "--no-witness")
	if code != 0 || !strings.Contains(stdout, "witness=skipped\n") || f.count("POST "+snapBase+"/agent") != 0 {
		t.Fatalf("exit %d, stdout %q, agent requests %d", code, stdout, f.count("POST "+snapBase+"/agent"))
	}
}

// S7: each way the witness fails exits 1 with nothing on stdout, and says
// the rollback completed but could not be proven, with the reason. A command
// that ran shows a bounded, quoted excerpt of its output.
func TestVMSnapshot_S7_WitnessFailures(t *testing.T) {
	huge := strings.Repeat("x", 2000) + "\nwarning: forged"
	for _, tc := range []struct {
		mode, out, reason string
		excerpt, quoted   bool
	}{
		{"fail", "boom\nwarning: forged", string(pve.WitnessCommandFailed), true, true},
		{"nomarker", huge, string(pve.WitnessMarkerMissing), true, false},
		{"truncated", "", string(pve.WitnessOutputTruncated), false, false},
		{"never", "", string(pve.WitnessNeverResponded), false, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newSnapshotFake(t, "a")
			f.witness, f.witnessOut = tc.mode, tc.out
			rp := f.start()
			start := time.Now()
			code, stdout, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a", "--witness-timeout", "1s")
			// --witness-timeout is honoured: never waiting out the 2m default.
			if took := time.Since(start); took > 15*time.Second {
				t.Fatalf("took %s with --witness-timeout 1s", took)
			}
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			last := lines[len(lines)-1]
			if code != 1 || stdout != "" || !strings.Contains(last, `rollback vm 100 to snapshot "a" completed, but it could not be proven`) || !strings.Contains(last, tc.reason) {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if !tc.excerpt {
				if len(lines) != 1 {
					t.Errorf("stderr has %d lines, want only the error: %q", len(lines), stderr)
				}
				return
			}
			// One line (a line break in the output is quoted, so it cannot
			// forge a second), bounded to the excerpt size.
			prefix := "warning: qa-pve-01: vm 100: witness output: "
			if tc.quoted {
				prefix += `"`
			}
			if len(lines) != 2 || !strings.HasPrefix(lines[0], prefix) || len(lines[0]) > 700 {
				t.Errorf("want one bounded excerpt line (quoted: %v) before the error, got %q", tc.quoted, stderr)
			}
			if tc.mode == "nomarker" && !strings.HasSuffix(lines[0], " bytes elided]") {
				t.Errorf("a huge output was not cut: %q", lines[0])
			}
		})
	}
}

// S8: a custom witness command and marker reach the guest exactly; a
// command without a marker, or a marker without a command, is refused
// before any request.
func TestVMSnapshot_S8_CustomWitness(t *testing.T) {
	f := newSnapshotFake(t, "a")
	rp := f.start()
	code, stdout, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a",
		"--witness-command", "cmd.exe", "--witness-command", "/c", "--witness-command", "echo hi", "--witness-marker", "echo hi")
	if code != 0 || !strings.Contains(stdout, "witness=verified") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got := f.execForms[0]["command"]; !slices.Equal(got, []string{"cmd.exe", "/c", "echo hi"}) {
		t.Errorf("guest command = %q", got)
	}
	for _, extra := range [][]string{{"--witness-command", "x"}, {"--witness-marker", "y"}} {
		f := newSnapshotFake(t, "a")
		rp := f.start()
		if code, _, stderr := snap(rp, append([]string{"rollback", "qa-pve-01", "100", "a"}, extra...)...); code != 1 || len(f.got()) != 0 {
			t.Errorf("%v: exit %d, %d request(s), stderr %q; want a refusal before any request", extra, code, len(f.got()), stderr)
		}
	}
}

// S9: --witness-timeout must be more than 0 and at most 30m, checked before
// any request.
func TestVMSnapshot_S9_WitnessTimeoutBounds(t *testing.T) {
	for _, d := range []string{"0s", "-1s", "31m"} {
		f := newSnapshotFake(t, "a")
		rp := f.start()
		if code, _, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a", "--witness-timeout", d); code != 1 || !strings.Contains(stderr, "--witness-timeout") || len(f.got()) != 0 {
			t.Errorf("%s: exit %d, %d request(s), stderr %q", d, code, len(f.got()), stderr)
		}
	}
}

// S10: each command waits for the VM's lock only as long as --lock-wait,
// and sends nothing while another pveforge process holds it.
func TestVMSnapshot_S10_LockWaitBoundsEveryCommand(t *testing.T) {
	f := newSnapshotFake(t, "a", "b")
	rp := f.start()
	unlock, err := lock.Mutation(context.Background(), rp, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	for _, args := range [][]string{
		{"list", "qa-pve-01", "100"},
		{"create", "qa-pve-01", "100", "n"},
		{"delete", "qa-pve-01", "100", "b"},
		{"rollback", "qa-pve-01", "100", "b"},
	} {
		if code, _, stderr := snap(rp, append(args, "--lock-wait", "20ms")...); code != 1 || !strings.Contains(stderr, "lock") {
			t.Errorf("%s: exit %d, stderr %q; want a lock timeout", args[0], code, stderr)
		}
	}
	if n := len(f.got()); n != 0 {
		t.Errorf("%d request(s) sent while the VM was locked: %q", n, f.got())
	}
}

// S11: a signal during the witness exits 130 with one line that says the
// rollback completed and the witness was interrupted — and NOT runRoot's
// generic "may or may not have been applied", which would contradict it.
func TestVMSnapshot_S11_SignalDuringTheWitness(t *testing.T) {
	f := newSnapshotFake(t, "a")
	f.witness = "never"
	rp := f.start()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var once sync.Once
	f.onExec = func() { once.Do(func() { cancel(interruptError{sig: syscall.SIGINT}) }) }
	code, stdout, stderr := runRootInterruptible(ctx, "vm", "snapshot", "rollback", "qa-pve-01", "100", "a", "--roster", rp, "--witness-timeout", "10s")
	if code != 130 || stdout != "" || strings.Count(stderr, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "the rollback completed; the witness was interrupted before it could prove it") || strings.Contains(stderr, "may or may not have been applied") {
		t.Errorf("stderr = %q", stderr)
	}
	if n := f.count("POST " + snapBase + "/snapshot/a/rollback"); n != 1 {
		t.Errorf("rollback POSTs = %d, want 1", n)
	}
}

// S11, runRoot's own side: an error marked
// errRollbackCompletedWitnessInterrupted is printed as it is, with the
// signal's exit status — the same exemption as ErrLockWaitInterrupted's.
func TestRunRoot_RollbackCompletedWitnessInterruptedIsExempt(t *testing.T) {
	err := fmt.Errorf("rollback vm 100 to snapshot %q: %w: %w", "a", errRollbackCompletedWitnessInterrupted, context.Canceled)
	code, stderr := runRootFailing(t, err, func(cancel context.CancelCauseFunc) { cancel(interruptError{sig: syscall.SIGTERM}) })
	if code != 143 || stderr != err.Error()+"\n" {
		t.Errorf("exit %d, stderr %q; want 143 and the error as it is", code, stderr)
	}
	if !errors.Is(err, errRollbackCompletedWitnessInterrupted) {
		t.Fatal("the marker does not match through the wrap")
	}
}

// S12: a rollback whose task fails exits 1 and runs no witness.
func TestVMSnapshot_S12_FailedRollbackRunsNoWitness(t *testing.T) {
	f := newSnapshotFake(t, "a")
	f.taskFail["a"] = true
	rp := f.start()
	code, stdout, _ := snap(rp, "rollback", "qa-pve-01", "100", "a")
	if code != 1 || stdout != "" || f.count("POST "+snapBase+"/agent") != 0 {
		t.Fatalf("exit %d, stdout %q, agent requests %d", code, stdout, f.count("POST "+snapBase+"/agent"))
	}
}

// S13: the default witness is /bin/echo with a fresh random marker each run.
func TestVMSnapshot_S13_FreshNonce(t *testing.T) {
	hex32 := regexp.MustCompile(`^pveforge-witness-[0-9a-f]{32}$`)
	var nonces []string
	for i := 0; i < 2; i++ {
		f := newSnapshotFake(t, "a")
		rp := f.start()
		if code, _, stderr := snap(rp, "rollback", "qa-pve-01", "100", "a"); code != 0 {
			t.Fatalf("exit %d, %q", code, stderr)
		}
		c := f.execForms[0]["command"]
		if len(c) != 2 || c[0] != "/bin/echo" || !hex32.MatchString(c[1]) {
			t.Fatalf("witness command = %q", c)
		}
		nonces = append(nonces, c[1])
	}
	if nonces[0] == nonces[1] {
		t.Errorf("two runs used the same nonce %q", nonces[0])
	}
}

// S16 (R2): delete refuses PVE's "current" entry, padded or not, before any
// request.
func TestVMSnapshot_S16_DeleteRefusesCurrent(t *testing.T) {
	for _, name := range []string{"current", " current "} {
		f := newSnapshotFake(t, "a")
		rp := f.start()
		if code, _, stderr := snap(rp, "delete", "qa-pve-01", "100", "a", name); code != 1 || !strings.Contains(stderr, "reserved") || len(f.got()) != 0 {
			t.Errorf("delete %q: exit %d, %d request(s), stderr %q", name, code, len(f.got()), stderr)
		}
	}
}

// S17: the excerpt never splits a rune straddling its bound, and invalid
// UTF-8 does not make the cut walk back more than a rune's worth.
func TestWitnessExcerpt_S17_RuneBoundary(t *testing.T) {
	for _, r := range []string{"é", "€", "𝄞"} {
		for off := 1; off < len(r); off++ {
			head := strings.Repeat("a", witnessExcerptBytes-off)
			got := witnessExcerpt(head + r + strings.Repeat("z", 100))
			if !strings.HasPrefix(got, head+" … [") || !utf8.ValidString(got) {
				t.Errorf("%q at offset %d: got …%q", r, off, got[len(head)-3:])
			}
		}
	}
	bad := strings.Repeat("\x80", witnessExcerptBytes+50)
	if got := witnessExcerpt(bad); len(got) < witnessExcerptBytes-utf8.UTFMax {
		t.Errorf("invalid UTF-8 cut back to %d bytes", len(got))
	}
}

// S18: --no-witness cannot be combined with the witness's own flags, and a
// blank marker is refused — both before any request.
func TestVMSnapshot_S18_WitnessFlagRules(t *testing.T) {
	for _, extra := range [][]string{
		{"--no-witness", "--witness-command", "x", "--witness-marker", "y"},
		{"--no-witness", "--witness-marker", "y"},
		{"--witness-command", "x", "--witness-marker", "  "},
	} {
		f := newSnapshotFake(t, "a")
		rp := f.start()
		if code, _, stderr := snap(rp, append([]string{"rollback", "qa-pve-01", "100", "a"}, extra...)...); code != 1 || len(f.got()) != 0 {
			t.Errorf("%v: exit %d, %d request(s), stderr %q", extra, code, len(f.got()), stderr)
		}
	}
}

// S19: a signal that lands after the witness already returned its verdict
// is still marked, so runRoot never adds its generic note to "completed".
func TestWitnessFailure_S19_SignalAfterTheVerdictIsMarked(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(interruptError{sig: syscall.SIGINT})
	cmd := newVMSnapshotRollbackCmd()
	cmd.SetContext(ctx)
	verdict := &pve.RollbackWitnessError{VMID: 100, Reason: pve.WitnessNeverResponded}
	err := witnessFailure(io.Discard, cmd, "qa-pve-01", 100, "a", nil, verdict)
	if !errors.Is(err, errRollbackCompletedWitnessInterrupted) || !errors.Is(err, pve.ErrRollbackNotWitnessed) {
		t.Errorf("err = %v; want it marked as interrupted, with the verdict kept", err)
	}
}

// S20: names whose snaptimes tie are deleted in PVE's list order reversed
// (ErrNotNewestSnapshot.CascadeOrder's), whatever order they were typed in.
func TestVMSnapshot_S20_DeleteTiesInListOrder(t *testing.T) {
	f := newSnapshotFake(t, "p", "q")
	f.snaps["q"] = fakeSnap{snaptime: f.snaps["p"].snaptime, vmstate: 1, seq: 1}
	rp := f.start()
	if code, stdout, stderr := snap(rp, "delete", "qa-pve-01", "100", "p", "q"); code != 0 || !strings.Contains(stdout, `deleted=["q","p"]`) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
