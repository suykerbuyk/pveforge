package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Command-level tests for `harness golden` / `harness reset` (U-GOLDEN/RESET),
// driven through runRootArgs against a stateful multi-VM fake PVE, with the
// nested acceptance injected via the harnessAccept seam (no live cluster). The
// outcome is asserted on the exit code, the returned cause (stderr), the fake's
// write log and the evidence steps — never a shell exit integer.

const (
	grDescPrefix = "pveforge harness golden point "
	grStamp      = "20260924T120000Z" // a golden.sh run's stamp used in reset fixtures
	grOld        = "20260101T000000Z"
)

func grGolden(snaptime int64, stamp string) string {
	return fmt.Sprintf(`{"name":"pvh-golden","snaptime":%d,"vmstate":0,"description":%q}`, snaptime, grDescPrefix+stamp)
}

// grsnap is one real snapshot in the mutable per-VM state (golden paths create
// and the cascade deletes them).
type grsnap struct {
	name     string
	snaptime int64
	vmstate  int
	desc     string
}

type grvm struct {
	config  string // raw GET config JSON (scsi0/tags/lock)
	running bool
	snaps   []grsnap
	snapRaw string // if set, GET snapshot returns this verbatim (refusal fixtures)

	shutdownKeepsRunning    bool
	stopKeepsRunning        bool
	recordVmstate1          bool // a created golden is stored vmstate=1 (read-back fail)
	recordOldStamp          bool // a created golden is stored with the old stamp
	dropOnCreate            bool // a created golden is not stored (read-back sees none)
	goldenGoneAfterShutdown bool // the golden is removed from state once this VM is shut down (C4b)
}

type grfake struct {
	mu sync.Mutex

	storage    string
	statusJSON string // storage /status override
	vms        map[int]*grvm

	failShutdown map[int]bool
	failStop     map[int]bool
	failStart    map[int]bool
	failDelete   map[int]bool
	failRollback map[int]bool
	failSnapshot map[int]bool

	acceptErr func(why string) error

	// injectNewerAfterFirstRead makes the snapshot GET return an extra snapshot
	// newer than golden on the SECOND+ read of a VM (C1): the first read (the
	// planning read) sees golden as newest, but by rollback time a newer
	// snapshot exists — so client.Rollback refuses-without-POST while the raw
	// leaf posts. snapGets counts GET snapshot per VM.
	injectNewerAfterFirstRead bool
	snapGets                  map[int]int

	// shutdownTimeout records the `timeout` form value of each shutdown POST
	// (the fake otherwise drops the form), so timeout=300 can be asserted (C3).
	shutdownTimeout map[int]string

	writes  []string // "post 690 status/stop" / "delete 690 snapshot/t2" / "delete 690" (bare = destroy)
	snapCtr int64
}

func grDefaultVM(running bool, snaps []grsnap) *grvm {
	return &grvm{
		config:  `{"scsi0":"pveforge-harness:vm-disk-0,size=128G","tags":"pveforge-harness","cores":"8"}`,
		running: running,
		snaps:   snaps,
	}
}

func (f *grfake) vm(vmid int) *grvm {
	if f.vms[vmid] == nil {
		f.vms[vmid] = grDefaultVM(false, nil)
	}
	return f.vms[vmid]
}

func (v *grvm) snapshotJSON() string {
	if v.snapRaw != "" {
		return v.snapRaw
	}
	parts := make([]string, 0, len(v.snaps)+1)
	for _, s := range v.snaps {
		parts = append(parts, fmt.Sprintf(`{"name":%q,"snaptime":%d,"vmstate":%d,"description":%q}`, s.name, s.snaptime, s.vmstate, s.desc))
	}
	parts = append(parts, `{"name":"current","snaptime":0}`)
	return "[" + strings.Join(parts, ",") + "]"
}

func (f *grfake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data := func(raw string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, raw)
	}
	fail500 := func() { w.WriteHeader(http.StatusInternalServerError); fmt.Fprint(w, `{"data":null}`) }
	p, m := r.URL.Path, r.Method

	// Storage / pool / task routes first.
	switch {
	case m == http.MethodGet && strings.HasSuffix(p, "/storage/"+f.storage+"/status"):
		if f.statusJSON != "" {
			data(f.statusJSON)
		} else {
			data(fmt.Sprintf(`{"type":"zfspool","enabled":1,"active":1,"content":"images,rootdir","avail":%d,"used":0}`, int64(100)<<30))
		}
		return
	case m == http.MethodGet && strings.Contains(p, "/pools"):
		var ms []string
		for _, vmid := range []int{690, 691, 692} {
			ms = append(ms, fmt.Sprintf(`{"type":"qemu","vmid":%d,"node":%q}`, vmid, pnode))
		}
		data(`[{"poolid":"pveforge-harness","members":[` + strings.Join(ms, ",") + `]}]`)
		return
	case m == http.MethodGet && strings.Contains(p, "/tasks/") && strings.HasSuffix(p, "/status"):
		upid := taskUPIDFromPath(p)
		typ, id := parseUPIDTypeID(upid)
		data(fmt.Sprintf(`{"upid":%q,"type":%q,"id":%q,"node":%q,"status":"stopped","exitstatus":"OK"}`, upid, typ, id, pnode))
		return
	}

	// Per-VM /qemu routes.
	i := strings.Index(p, "/qemu/")
	if i < 0 {
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route for "+m+" "+p))
		return
	}
	after := p[i+len("/qemu/"):]
	parts := strings.SplitN(after, "/", 2)
	vmid, _ := strconv.Atoi(parts[0])
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	v := f.vm(vmid)
	record := func() { f.writes = append(f.writes, fmt.Sprintf("%s %d %s", strings.ToLower(m), vmid, sub)) }

	switch {
	case m == http.MethodGet && sub == "config":
		data(v.config)
	case m == http.MethodGet && sub == "status/current":
		st := "stopped"
		if v.running {
			st = "running"
		}
		data(fmt.Sprintf(`{"vmid":%d,"status":%q}`, vmid, st))
	case m == http.MethodGet && sub == "snapshot":
		if f.snapGets == nil {
			f.snapGets = map[int]int{}
		}
		f.snapGets[vmid]++
		js := v.snapshotJSON()
		if f.injectNewerAfterFirstRead && f.snapGets[vmid] > 1 {
			// Insert a snapshot newer than golden right after '['; so the second
			// (rollback-time) read sees a newer peer the first read did not.
			js = `[{"name":"late","snaptime":9999,"vmstate":0,"description":""},` + js[1:]
		}
		data(js)
	case m == http.MethodPost && sub == "status/shutdown":
		record()
		if f.shutdownTimeout == nil {
			f.shutdownTimeout = map[int]string{}
		}
		f.shutdownTimeout[vmid] = r.FormValue("timeout")
		if f.failShutdown[vmid] {
			fail500()
			return
		}
		if !v.shutdownKeepsRunning {
			v.running = false
		}
		if v.goldenGoneAfterShutdown { // C4b: golden disappears before the replace re-read
			kept := v.snaps[:0]
			for _, s := range v.snaps {
				if s.name != "pvh-golden" {
					kept = append(kept, s)
				}
			}
			v.snaps = kept
		}
		data(fmt.Sprintf("%q", pUPID("qmshutdown", vmid)))
	case m == http.MethodPost && sub == "status/stop":
		record()
		if f.failStop[vmid] {
			fail500()
			return
		}
		if !v.stopKeepsRunning {
			v.running = false
		}
		data(fmt.Sprintf("%q", pUPID("qmstop", vmid)))
	case m == http.MethodPost && sub == "status/start":
		record()
		if f.failStart[vmid] {
			fail500()
			return
		}
		v.running = true
		data(fmt.Sprintf("%q", pUPID("qmstart", vmid)))
	case m == http.MethodPost && sub == "snapshot":
		record()
		if f.failSnapshot[vmid] {
			fail500()
			return
		}
		f.snapCtr++
		vmstate := 0
		if r.FormValue("vmstate") == "1" || v.recordVmstate1 {
			vmstate = 1
		}
		desc := r.FormValue("description")
		if v.recordOldStamp {
			desc = grDescPrefix + grOld
		}
		if !v.dropOnCreate {
			v.snaps = append(v.snaps, grsnap{name: r.FormValue("snapname"), snaptime: f.snapCtr, vmstate: vmstate, desc: desc})
		}
		data(fmt.Sprintf("%q", pUPID("qmsnapshot", vmid)))
	case m == http.MethodPost && strings.HasPrefix(sub, "snapshot/") && strings.HasSuffix(sub, "/rollback"):
		record()
		if f.failRollback[vmid] {
			fail500()
			return
		}
		data(fmt.Sprintf("%q", pUPID("qmrollback", vmid)))
	case m == http.MethodDelete && strings.HasPrefix(sub, "snapshot/"):
		record()
		if f.failDelete[vmid] {
			fail500()
			return
		}
		name := sub[strings.LastIndex(sub, "/")+1:]
		kept := v.snaps[:0]
		for _, s := range v.snaps {
			if s.name != name {
				kept = append(kept, s)
			}
		}
		v.snaps = kept
		data(fmt.Sprintf("%q", pUPID("qmdelsnapshot", vmid)))
	case m == http.MethodDelete && sub == "":
		record() // a bare DELETE /qemu/<vmid> is a DESTROY — must never happen
		data(fmt.Sprintf("%q", pUPID("qmdestroy", vmid)))
	default:
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route for "+m+" "+p))
	}
}

// newGRTest wires the fake behind a TLS server, a roster target "h" on pnode,
// the passphrase, a per-test HOME, the two nested-roster env vars (so the
// pre-change roster gate passes), and the injected acceptance.
func newGRTest(t *testing.T, f *grfake) (rosterPath, home string) {
	t.Helper()
	if f.storage == "" {
		f.storage = "pveforge-harness"
	}
	if f.vms == nil {
		f.vms = map[int]*grvm{}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PVEFORGE_HARNESS_ROSTER", filepath.Join(home, "nested.toml"))
	t.Setenv("PVEFORGE_HARNESS_OUTER_ROSTERS", filepath.Join(home, "outer.toml"))

	// C2: the never-destroy write-log check fires on EVERY scenario that goes
	// through newGRTest (the shared harness), not just the six that called
	// assertNoDestroy explicitly — a destroy issued on any path, at any point,
	// fails the test it ran under.
	t.Cleanup(func() { assertNoDestroy(t, f.writeLog()) })

	saved := harnessAccept
	t.Cleanup(func() { harnessAccept = saved })
	harnessAccept = func(ctx context.Context, deadline time.Duration, why string) error {
		f.mu.Lock()
		fn := f.acceptErr
		f.mu.Unlock()
		if fn != nil {
			return fn(why)
		}
		return nil
	}
	return newTestRosterWithTLSTarget(t, srv, "h", pnode), home
}

func (f *grfake) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func grSteps(t *testing.T, home, what string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(home, ".config/pveforge/harness-evidence", what, "*", "steps"))
	if len(matches) == 0 {
		return ""
	}
	b, _ := os.ReadFile(matches[len(matches)-1])
	return string(b)
}

// assertNoDestroy is the never-destroy write-log check on EVERY scenario: no
// bare DELETE /qemu/<vmid> (a snapshot delete always carries a /snapshot/ sub).
func assertNoDestroy(t *testing.T, writes []string) {
	t.Helper()
	for _, w := range writes {
		fields := strings.Fields(w)
		if len(fields) == 2 && fields[0] == "delete" { // "delete <vmid>" with no sub
			t.Errorf("a VM was destroyed: %q (writes: %v)", w, writes)
		}
	}
}

// ---- golden -------------------------------------------------------------

func grGoldenWorld() *grfake {
	f := &grfake{vms: map[int]*grvm{}}
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid] = grDefaultVM(true, nil) // running, no golden yet
	}
	return f
}

func TestGolden_TheGoldenPoint(t *testing.T) {
	f := grGoldenWorld()
	rosterPath, home := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := []string{
		"post 691 status/shutdown", "post 690 status/shutdown", "post 692 status/shutdown",
		"post 690 snapshot", "post 691 snapshot", "post 692 snapshot",
		"post 692 status/start", "post 690 status/start", "post 691 status/start",
	}
	got := f.writeLog()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	assertNoDestroy(t, got)
	steps := grSteps(t, home, "golden")
	if !strings.Contains(steps, "RESULT golden point taken") || strings.Contains(steps, "no golden exists") {
		t.Errorf("steps:\n%s", steps)
	}
}

func TestGolden_ExistingGoldenNeedsReplace(t *testing.T) {
	f := grGoldenWorld()
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
	}
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stderr, "needs --replace-golden") {
		t.Fatalf("exit %d stderr %q, want a 'needs --replace-golden' refusal", code, stderr)
	}
	assertNoDestroy(t, f.writeLog())
	if w := f.writeLog(); len(w) != 0 {
		t.Errorf("an existing golden without --replace-golden wrote %v, want zero writes", w)
	}
}

func TestGolden_Replace(t *testing.T) {
	f := grGoldenWorld()
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
	}
	rosterPath, home := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--replace-golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	want := []string{
		"post 691 status/shutdown", "post 690 status/shutdown", "post 692 status/shutdown",
		"delete 690 snapshot/pvh-golden", "delete 691 snapshot/pvh-golden", "delete 692 snapshot/pvh-golden",
		"post 690 snapshot", "post 691 snapshot", "post 692 snapshot",
		"post 692 status/start", "post 690 status/start", "post 691 status/start",
	}
	got := f.writeLog()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	assertNoDestroy(t, got)
	steps := grSteps(t, home, "golden")
	gone := strings.Index(steps, "no golden exists on 690 691 692")
	if gone < 0 || gone < strings.LastIndex(steps, "the old pvh-golden deleted") || gone > strings.Index(steps, "VM 690: pvh-golden taken") {
		t.Errorf("steps order wrong:\n%s", steps)
	}
}

func TestGolden_StopsWhereItFails(t *testing.T) {
	t.Run("a shutdown that leaves the VM running", func(t *testing.T) {
		f := grGoldenWorld()
		f.vms[691].shutdownKeepsRunning = true
		rosterPath, _ := newGRTest(t, f)
		code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 || !strings.Contains(stderr, "'running' after its stop reported success") {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		// Only the first shutdown ran (691 is first in stop order).
		if got := f.writeLog(); strings.Join(got, "\n") != "post 691 status/shutdown" {
			t.Errorf("writes %v, want only the 691 shutdown", got)
		}
	})
	t.Run("a golden that does not read back (vmstate=1)", func(t *testing.T) {
		f := grGoldenWorld()
		f.vms[690].recordVmstate1 = true
		rosterPath, home := newGRTest(t, f)
		code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 || !strings.Contains(stderr, "does not read back") {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		assertNoDestroy(t, f.writeLog())
		if s := grSteps(t, home, "golden"); !strings.HasSuffix(s, "FAILED; golden state: 690=new 691=none 692=none\n") {
			t.Errorf("steps did not record the gr_fail golden-state suffix:\n%s", s)
		}
	})
	t.Run("a golden with the old stamp does not read back", func(t *testing.T) {
		f := grGoldenWorld()
		f.vms[690].recordOldStamp = true
		rosterPath, _ := newGRTest(t, f)
		code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 || !strings.Contains(stderr, "does not read back") {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
	})
}

func TestGolden_AReplaceThatFails(t *testing.T) {
	t.Run("the second old golden's delete", func(t *testing.T) {
		f := grGoldenWorld()
		for _, vmid := range []int{690, 691, 692} {
			f.vms[vmid].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
		}
		f.failDelete = map[int]bool{691: true}
		rosterPath, home := newGRTest(t, f)
		code, _, _ := runRootArgs("harness", "golden", "--replace-golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 {
			t.Fatal("a failed delete exited 0")
		}
		assertNoDestroy(t, f.writeLog())
		s := grSteps(t, home, "golden")
		if !strings.HasSuffix(s, "FAILED exit 1; golden state: 690=none 691=old 692=old\n") || strings.Contains(s, "no golden exists") {
			t.Errorf("steps:\n%s", s)
		}
	})
	t.Run("the second new golden", func(t *testing.T) {
		f := grGoldenWorld()
		for _, vmid := range []int{690, 691, 692} {
			f.vms[vmid].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
		}
		f.failSnapshot = map[int]bool{691: true} // 691's new golden POST fails
		rosterPath, home := newGRTest(t, f)
		code, _, _ := runRootArgs("harness", "golden", "--replace-golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 {
			t.Fatal("a failed golden snapshot exited 0")
		}
		s := grSteps(t, home, "golden")
		if !strings.Contains(s, "no golden exists on 690 691 692") || !strings.HasSuffix(s, "FAILED exit 1; golden state: 690=new 691=none 692=none\n") {
			t.Errorf("steps:\n%s", s)
		}
	})
}

func TestGolden_NeverOfABrokenCluster(t *testing.T) {
	f := grGoldenWorld()
	f.acceptErr = func(why string) error { return fmt.Errorf("not quorate") }
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stderr, "before the golden point") {
		t.Fatalf("exit %d stderr %q, want the accept failure before the golden point", code, stderr)
	}
	// No shutdown ran: the accept gate is before the shutdowns.
	if w := f.writeLog(); len(w) != 0 {
		t.Errorf("writes %v, want zero (accept fails before any change)", w)
	}
}

// ---- reset --------------------------------------------------------------

func grResetWorld() *grfake {
	f := &grfake{vms: map[int]*grvm{}}
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid] = grDefaultVM(true, []grsnap{
			{name: "early", snaptime: 500, vmstate: 0},
			{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld},
			{name: "t1", snaptime: 2000, vmstate: 0},
			{name: "t2", snaptime: 3000, vmstate: 0},
		})
	}
	return f
}

func resetWrites(stopped ...int) []string {
	skip := map[int]bool{}
	for _, v := range stopped {
		skip[v] = true
	}
	var w []string
	for _, v := range []int{691, 690, 692} {
		if !skip[v] {
			w = append(w, fmt.Sprintf("post %d status/stop", v))
		}
	}
	for _, v := range []int{690, 691, 692} {
		w = append(w, fmt.Sprintf("delete %d snapshot/t2", v), fmt.Sprintf("delete %d snapshot/t1", v), fmt.Sprintf("post %d snapshot/pvh-golden/rollback", v))
	}
	for _, v := range []int{692, 690, 691} {
		w = append(w, fmt.Sprintf("post %d status/start", v))
	}
	return w
}

func TestReset_TheFullReset(t *testing.T) {
	f := grResetWorld()
	rosterPath, home := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	got := f.writeLog()
	if strings.Join(got, "\n") != strings.Join(resetWrites(), "\n") {
		t.Errorf("writes:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(resetWrites(), "\n  "))
	}
	assertNoDestroy(t, got)
	s := grSteps(t, home, "reset")
	if !strings.Contains(s, "the goldens are one point: stamp "+grOld) || !strings.Contains(s, "RESULT reset to pvh-golden") {
		t.Errorf("steps:\n%s", s)
	}
}

func TestReset_AlreadyStopped(t *testing.T) {
	f := grResetWorld()
	f.vms[690].running = false
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	got := f.writeLog()
	if strings.Join(got, "\n") != strings.Join(resetWrites(690), "\n") {
		t.Errorf("writes:\n  %s\nwant (no 690 stop):\n  %s", strings.Join(got, "\n  "), strings.Join(resetWrites(690), "\n  "))
	}
}

func TestReset_NothingNewer(t *testing.T) {
	f := grResetWorld()
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid].snaps = []grsnap{
			{name: "early", snaptime: 500, vmstate: 0},
			{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld},
		}
	}
	rosterPath, home := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	for _, w := range f.writeLog() {
		if strings.HasPrefix(w, "delete ") {
			t.Errorf("a delete ran with nothing newer than the golden: %q", w)
		}
	}
	if s := grSteps(t, home, "reset"); strings.Contains(s, "deleted") {
		t.Errorf("steps record a delete:\n%s", s)
	}
}

func TestReset_CascadeByTimeNotName(t *testing.T) {
	f := grResetWorld()
	for _, vmid := range []int{690, 691, 692} {
		// Names in the OPPOSITE order to their times: alphabetical is aa<mm<zz
		// but newest-first by time is zz(3000),mm(2500),aa(2000). A name-order
		// (or ascending-time) mutant would delete aa,mm,zz and be caught HERE,
		// not only by the full-reset list (C9).
		f.vms[vmid].snaps = []grsnap{
			{name: "aa", snaptime: 2000, vmstate: 0},
			{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld},
			{name: "zz", snaptime: 3000, vmstate: 0},
			{name: "mm", snaptime: 2500, vmstate: 0},
		}
	}
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	// 690's deletes must be zz, mm, aa (newest first by TIME, the reverse of
	// the alphabetical order).
	var seq []string
	for _, w := range f.writeLog() {
		if strings.HasPrefix(w, "delete 690 snapshot/") {
			seq = append(seq, strings.TrimPrefix(w, "delete 690 snapshot/"))
		}
	}
	if strings.Join(seq, ",") != "zz,mm,aa" {
		t.Errorf("690 cascade order = %v, want zz,mm,aa (by time, not name)", seq)
	}
}

func TestReset_PreBuildFloorNotApplied(t *testing.T) {
	f := grResetWorld()
	t.Setenv("HARNESS_RESET_MIN_FREE_GIB", "200") // grResetWorld avail is 100 GiB
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stderr, "below HARNESS_PROBE_MIN_FREE_GIB=200") || !strings.Contains(stderr, "static layer refused") {
		t.Fatalf("exit %d stderr %q, want a wrapped floor refusal", code, stderr)
	}
}

func TestReset_StopsWhereItFails(t *testing.T) {
	t.Run("a stop that leaves the VM running", func(t *testing.T) {
		f := grResetWorld()
		f.vms[690].stopKeepsRunning = true
		rosterPath, _ := newGRTest(t, f)
		code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 || !strings.Contains(stderr, "'running' after its stop reported success") {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		if got := f.writeLog(); strings.Join(got, "\n") != "post 691 status/stop\npost 690 status/stop" {
			t.Errorf("writes %v, want the 691 then 690 stops only", got)
		}
	})
	t.Run("a failed rollback", func(t *testing.T) {
		f := grResetWorld()
		f.failRollback = map[int]bool{691: true}
		rosterPath, home := newGRTest(t, f)
		code, _, _ := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 {
			t.Fatal("a failed rollback exited 0")
		}
		s := grSteps(t, home, "reset")
		if !strings.Contains(s, "VM 690: rolled back to pvh-golden") || strings.Contains(s, "VM 691: rolled back") || !strings.HasSuffix(s, "FAILED exit 1\n") {
			t.Errorf("steps:\n%s", s)
		}
	})
	t.Run("acceptance fails", func(t *testing.T) {
		f := grResetWorld()
		f.acceptErr = func(why string) error { return fmt.Errorf("boom") }
		rosterPath, home := newGRTest(t, f)
		code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 || !strings.Contains(stderr, "was not accepted") {
			t.Fatalf("exit %d stderr %q", code, stderr)
		}
		s := grSteps(t, home, "reset")
		if !strings.Contains(s, "FAILED accept") || strings.Contains(s, "FAILED exit") {
			t.Errorf("steps:\n%s", s)
		}
	})
	t.Run("a failed start", func(t *testing.T) {
		f := grResetWorld()
		f.failStart = map[int]bool{690: true}
		rosterPath, home := newGRTest(t, f)
		code, _, _ := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		if code == 0 {
			t.Fatal("a failed start exited 0")
		}
		if s := grSteps(t, home, "reset"); !strings.HasSuffix(s, "FAILED exit 1\n") {
			t.Errorf("steps:\n%s", s)
		}
	})
}

func TestReset_RefusedBeforeAnyChange(t *testing.T) {
	seeded := func(mut func(f *grfake)) *grfake {
		f := grResetWorld()
		mut(f)
		return f
	}
	snapRaw := func(f *grfake, vmid int, raw string) { f.vms[vmid].snapRaw = raw }
	cases := []struct {
		name   string
		f      *grfake
		args   []string
		env    map[string]string
		noRost bool
		want   string
	}{
		{"no golden", seeded(func(f *grfake) { snapRaw(f, 691, `[{"name":"t1","snaptime":2000},{"name":"current","snaptime":0}]`) }), nil, nil, false, "exactly one pvh-golden"},
		{"two snapshots at one time", seeded(func(f *grfake) {
			snapRaw(f, 692, `[`+grGolden(1000, grOld)+`,{"name":"t1","snaptime":2000},{"name":"t2","snaptime":2000},{"name":"current","snaptime":0}]`)
		}), nil, nil, false, "no two at the same time"},
		{"a snapshot without a time", seeded(func(f *grfake) {
			snapRaw(f, 690, `[`+grGolden(1000, grOld)+`,{"name":"t1"},{"name":"current","snaptime":0}]`)
		}), nil, nil, false, "a time on each"},
		{"a snapshot list of the wrong shape", seeded(func(f *grfake) { snapRaw(f, 690, `{}`) }), nil, nil, false, "unexpected shape"},
		{"current without a snaptime still completes decision", seeded(func(f *grfake) {
			snapRaw(f, 690, `[`+grGolden(1000, grOld)+`,{"name":"current"}]`)
		}), nil, nil, false, ""}, // "" → expect success
		{"system disk on another storage", seeded(func(f *grfake) {
			f.vms[691].config = `{"scsi0":"local-lvm:vm-691-disk-0","tags":"pveforge-harness"}`
		}), nil, nil, false, "not the required storage"},
		{"a lock", seeded(func(f *grfake) {
			f.vms[692].config = `{"scsi0":"pveforge-harness:vm-692-disk-0","tags":"pveforge-harness","lock":"rollback"}`
		}), nil, nil, false, "qm unlock 692"},
		{"the probe refuses the storage", seeded(func(f *grfake) {
			f.statusJSON = `{"type":"zfspool","enabled":1,"active":0,"content":"images","avail":107374182400}`
		}), nil, nil, false, "static layer refused"},
		{"the reset's free-space floor", seeded(func(f *grfake) {
			f.statusJSON = `{"type":"zfspool","enabled":1,"active":1,"content":"images","avail":10737418240}`
		}), nil, nil, false, "static layer refused"},
		{"goldens of two points", seeded(func(f *grfake) {
			snapRaw(f, 692, `[`+grGolden(1000, "20260102T000000Z")+`,{"name":"current","snaptime":0}]`)
		}), nil, nil, false, "the goldens are not one point: 690=" + grOld + " 691=" + grOld + " 692=20260102T000000Z"},
		{"a golden taken with its memory", seeded(func(f *grfake) {
			f.vms[691].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"vmstate":1,"description":%q},{"name":"current","snaptime":0}]`, grDescPrefix+grOld)
		}), nil, nil, false, "must be disk-only (vmstate 0)"},
		{"a golden with no stamp", seeded(func(f *grfake) {
			f.vms[690].snapRaw = `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point"},{"name":"current","snaptime":0}]`
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a golden with no description", seeded(func(f *grfake) {
			f.vms[690].snapRaw = `[{"name":"pvh-golden","snaptime":1000},{"name":"current","snaptime":0}]`
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a bare stamp without the prefix", seeded(func(f *grfake) {
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"description":%q},{"name":"current","snaptime":0}]`, grOld)
			}
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a stamp with a line after it", seeded(func(f *grfake) {
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"description":%q},{"name":"current","snaptime":0}]`, grDescPrefix+grOld+"\nmore")
			}
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a stamp with two trailing newlines", seeded(func(f *grfake) {
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"description":%q},{"name":"current","snaptime":0}]`, grDescPrefix+grOld+"\n\n")
			}
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a golden whose stamp is not a stamp", seeded(func(f *grfake) {
			f.vms[690].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"description":%q},{"name":"current","snaptime":0}]`, grDescPrefix+"20260101T000000Z trailing")
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"no golden stamped", seeded(func(f *grfake) { // C5: the 20th shell leg (spec :411-415)
			// All three carry the prefix exactly (trailing space) but no stamp, so
			// they pass HasPrefix and are refused by stampRE on the empty stamp —
			// a stampRE drop turns this leg red.
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"description":%q},{"name":"current","snaptime":0}]`, grDescPrefix)
			}
		}), nil, nil, false, "carry golden.sh's run stamp"},
		{"a snapshot list missing current", seeded(func(f *grfake) { // C4a: the verifiable-view fail-closed skip
			f.vms[690].snapRaw = fmt.Sprintf(`[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":%q}]`, grDescPrefix+grOld)
		}), nil, nil, false, "unverifiable"},
		{"no nested roster", grResetWorld(), nil, nil, true, "PVEFORGE_HARNESS_ROSTER"},
		{"no storage", grResetWorld(), []string{"harness", "reset", "h"}, nil, false, "there is no default"},
		{"an unknown argument", grResetWorld(), []string{"harness", "reset", "--force", "--storage", "pveforge-harness", "h"}, nil, false, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, _ := newGRTest(t, c.f)
			if c.noRost {
				t.Setenv("PVEFORGE_HARNESS_ROSTER", "")
			}
			args := c.args
			if args == nil {
				args = []string{"harness", "reset", "--storage", "pveforge-harness", "h"}
			}
			full := append([]string{args[0], args[1]}, "--roster", rosterPath)
			full = append(full, args[2:]...)
			code, _, stderr := runRootArgs(full...)
			if c.want == "" {
				if code != 0 {
					t.Fatalf("exit %d stderr %q, want success", code, stderr)
				}
				return
			}
			if code == 0 {
				t.Fatalf("a refusal exited 0; stderr %q", stderr)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("stderr %q, want it to contain %q", stderr, c.want)
			}
			// Zero PVE writes on a pre-change refusal.
			for _, w := range c.f.writeLog() {
				t.Errorf("a refusal issued a write: %q", w)
			}
		})
	}
}

func TestGoldenReset_HoldsLockAcrossRun(t *testing.T) {
	f := grResetWorld()
	rosterPath, _ := newGRTest(t, f)
	holdLock(t, rosterPath, harnessVMKey("h", 690))
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--lock-wait", "7ms", "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stderr, "acquire lock") {
		t.Fatalf("exit %d stderr %q, want an 'acquire lock' failure", code, stderr)
	}
	if w := f.writeLog(); len(w) != 0 {
		t.Errorf("%d write(s) ran while VM 690's lock was held: the lock does not cover the run", len(w))
	}
}

// C1: pins the Chair-settled B1 raw-rollback leaf against a client.Rollback
// swap. Golden is newest at planning time (no cascade), but a newer snapshot
// exists by rollback time (injectNewerAfterFirstRead). The raw leaf posts the
// rollback unconditionally; client.Rollback would re-read, see the newer peer,
// and refuse WITHOUT posting — so the rollback writes are present here and
// vanish under the swap.
func TestReset_RawRollbackPostsPastANewerSnapshot(t *testing.T) {
	f := &grfake{vms: map[int]*grvm{}, injectNewerAfterFirstRead: true}
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid] = grDefaultVM(true, []grsnap{
			{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld},
		})
	}
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	want := []string{
		"post 691 status/stop", "post 690 status/stop", "post 692 status/stop",
		"post 690 snapshot/pvh-golden/rollback", "post 691 snapshot/pvh-golden/rollback", "post 692 snapshot/pvh-golden/rollback",
		"post 692 status/start", "post 690 status/start", "post 691 status/start",
	}
	got := f.writeLog()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes:\n  %s\nwant (the raw leaf posts the rollback past a newer snapshot):\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// C3: every graceful shutdown must carry timeout=300. The fake records the
// shutdown form param (which it otherwise drops); dropping timeout=300 → nil
// fails here.
func TestGolden_ShutdownCarriesTimeout(t *testing.T) {
	f := grGoldenWorld()
	rosterPath, _ := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, vmid := range []int{690, 691, 692} {
		if f.shutdownTimeout[vmid] != "300" {
			t.Errorf("VM %d graceful shutdown timeout = %q, want 300", vmid, f.shutdownTimeout[vmid])
		}
	}
}

// C4b: --replace-golden where the golden is already GONE on the post-shutdown
// re-read must NOT try to delete it. Forcing the delete of an absent golden
// (hasGolden(snaps) || true) writes a spurious "deleted" step → RED.
func TestGolden_ReplaceSkipsAbsentGolden(t *testing.T) {
	f := grGoldenWorld()
	for _, vmid := range []int{690, 691, 692} {
		f.vms[vmid].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
		f.vms[vmid].goldenGoneAfterShutdown = true
	}
	rosterPath, home := newGRTest(t, f)
	code, _, stderr := runRootArgs("harness", "golden", "--replace-golden", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if s := grSteps(t, home, "golden"); strings.Contains(s, "the old pvh-golden deleted") {
		t.Errorf("replace deleted a golden that was already gone:\n%s", s)
	}
	for _, w := range f.writeLog() {
		if strings.HasPrefix(w, "delete") && strings.Contains(w, "snapshot/pvh-golden") {
			t.Errorf("a DELETE of the already-absent golden was issued: %q", w)
		}
	}
}
