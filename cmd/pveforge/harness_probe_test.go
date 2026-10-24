package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// runProbeCtx runs the CLI with a caller-controlled context (so a test can
// cancel cmd.Context mid-run). runRoot wraps root.Context() but keeps it as
// the parent, so cancelling ctx cancels every command's context.
func runProbeCtx(ctx context.Context, args ...string) (code int, stdout, stderr string) {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	code = runRoot(root, &errOut)
	return code, out.String(), errOut.String()
}

// pfake is a stateful fake PVE for the probe verb: it tracks the pool
// membership of 690, the snapshot set, and the destroy, so a full
// create→snapshot→rollback→cascade→destroy→gone run can be driven through
// `pveforge harness probe` and its outcome asserted on STDOUT and the rule
// file (never an exit integer).
type pfake struct {
	mu sync.Mutex

	storage string

	// static-layer status override (empty → a healthy zfspool is built).
	statusJSON string
	usedNow    string // `used` the status reports now (default "0")

	// pre-create world knobs.
	pre690        bool // 690 already in the pool before create (690MustNotExist)
	poolX         bool // an extra member makes the pool non-empty
	nextid        string
	contentPre    string // content before create (non-empty → leftover refusal)
	poolMemberRaw string // a raw pre-create pool member object (e.g. a string vmid) — CR3

	// behaviour knobs.
	rollbackAny           bool   // the STORAGE allows a non-latest rollback (rollback task OK)
	rollbackOtherErr      bool   // the rollback task fails with an unrelated (non-"most recent") error
	rollbackBusy          bool   // the rollback fails with text CONTAINING "snapshot" but not the refusal (CR2)
	destroyExit           string // the destroy task's exitstatus (WARNINGS → gone-proof fails)
	snapFail              bool   // the s1 create POST answers 500 (force a failure after create)
	leftoverVol           bool   // storage content still lists a 690 volume after destroy
	cleanupReDestroyEmpty bool   // a SECOND destroy DELETE answers an empty body (CR5 main-UPID fallback)

	// rollbackResult is decided at each rollback POST and read back by the
	// task-status route (the raw rollback classifier is what the probe now
	// measures): "notmostrecent" | "other" | "busy" | "ok".
	rollbackResult string

	// state.
	created       bool
	createPooled  bool   // 690 joined the pool (the create POST carried pool=<pool>) — CR1
	createPool    string // the pool= value the create POST carried — CR1
	destroyed     bool
	snaps         map[string]int64
	snapCtr       int64
	tags          string
	destroyCalls  int
	postQemuCalls int    // POSTs/DELETEs to any /qemu path (CR4: lock must cover these)
	rollbackPath  string // the path of the last raw rollback POST (CR4: must be /qemu/690/…)

	recordVmstate func(string) // called with the vmstate of each snapshot create
	afterCreate   func()       // fired once on the first snapshot POST, i.e. AFTER createAndTag (CR5 cancel hook)
	hookFired     bool
}

const pnode = "qa-pve-07"

func pUPID(typ string, id int) string {
	return fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:%s:%d:root@pam:", pnode, typ, id)
}

func (f *pfake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snaps == nil {
		f.snaps = map[string]int64{}
	}
	data := func(raw string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, raw)
	}
	fail500 := func() { w.WriteHeader(http.StatusInternalServerError); fmt.Fprint(w, `{"data":null}`) }
	p, m := r.URL.Path, r.Method

	switch {
	case m == http.MethodGet && strings.HasSuffix(p, "/storage/"+f.storage+"/status"):
		if f.statusJSON != "" {
			data(f.statusJSON)
			return
		}
		data(fmt.Sprintf(`{"type":"zfspool","enabled":1,"active":1,"content":"images,rootdir","avail":%d,"used":%s}`,
			int64(600)<<30, f.or(f.usedNow, "0")))
	case m == http.MethodGet && strings.HasSuffix(p, "/content"):
		if !f.created && f.contentPre != "" {
			data(f.contentPre)
			return
		}
		if f.destroyed && f.leftoverVol {
			data(`[{"volid":"` + f.storage + `:vm-690-disk-0"}]`)
			return
		}
		data(`[]`)
	case m == http.MethodGet && strings.Contains(p, "/pools"):
		data(f.poolJSON())
	case m == http.MethodGet && strings.Contains(p, "/cluster/nextid"):
		data(f.or(f.nextid, "690"))
	case m == http.MethodGet && strings.Contains(p, "/tasks/") && strings.HasSuffix(p, "/status"):
		upid := taskUPIDFromPath(p)
		typ, id := parseUPIDTypeID(upid)
		exit := "OK"
		if typ == "qmdestroy" && f.destroyExit != "" {
			exit = f.destroyExit
		}
		if typ == "qmrollback" {
			switch f.rollbackResult {
			case "notmostrecent":
				exit = "can't rollback, 's1' is not most recent snapshot on 'pveforge-harness:vm-690-disk-0'"
			case "busy":
				// Contains "snapshot" but is NOT the latest-only refusal (CR2).
				exit = "can't rollback snapshot 's1': storage is busy"
			case "other":
				exit = "some unrelated rollback failure"
			}
		}
		data(fmt.Sprintf(`{"upid":%q,"type":%q,"id":%q,"node":%q,"status":"stopped","exitstatus":%q}`, upid, typ, id, pnode, exit))
	case m == http.MethodGet && strings.HasSuffix(p, "/qemu/690/status/current"):
		data(`{"vmid":690,"name":"pveforge-probe","status":"stopped"}`)
	case m == http.MethodGet && strings.HasSuffix(p, "/qemu/690/config"):
		data(fmt.Sprintf(`{"tags":%q}`, f.tags))
	case m == http.MethodGet && strings.HasSuffix(p, "/qemu/690/snapshot"):
		data(f.snapListJSON())
	case m == http.MethodPost && strings.HasSuffix(p, "/qemu"): // CreateVM
		f.postQemuCalls++
		f.created = true
		f.createPool = r.FormValue("pool")
		if f.createPool == "pveforge-harness" {
			f.createPooled = true // 690 joins the pool only when pool= is sent
		}
		data(fmt.Sprintf("%q", pUPID("qmcreate", 690)))
	case m == http.MethodPut && strings.HasSuffix(p, "/qemu/690/config"): // SetVMConfigField(tags)
		if v := r.FormValue("tags"); v != "" {
			f.tags = v
		}
		data(`null`)
	case m == http.MethodPost && strings.Contains(p, "/snapshot/") && strings.HasSuffix(p, "/rollback"):
		// Decide what the STORAGE does with this rollback: refuse a non-latest
		// one (s2 still present) unless the storage allows any rollback.
		// The knobs act only on the CLASSIFICATION rollback (s2 still present);
		// the cascade rollback (s2 deleted, s1 newest) always succeeds, as a
		// real storage allows rolling back to the newest snapshot. This keeps
		// the unrelated-error fixture isolated to the classifier.
		f.postQemuCalls++
		f.rollbackPath = p
		_, s2Present := f.snaps["s2"]
		switch {
		case f.rollbackBusy && s2Present:
			f.rollbackResult = "busy"
		case f.rollbackOtherErr && s2Present:
			f.rollbackResult = "other"
		case !f.rollbackAny && s2Present:
			f.rollbackResult = "notmostrecent"
		default:
			f.rollbackResult = "ok"
		}
		data(fmt.Sprintf("%q", pUPID("qmrollback", 690)))
	case m == http.MethodPost && strings.HasSuffix(p, "/qemu/690/snapshot"): // create snapshot
		f.postQemuCalls++
		if f.afterCreate != nil && !f.hookFired { // fire once, AFTER createAndTag completed (d.created set)
			f.hookFired = true
			f.afterCreate()
		}
		if f.recordVmstate != nil {
			f.recordVmstate(r.FormValue("vmstate"))
		}
		if f.snapFail {
			fail500()
			return
		}
		name := r.FormValue("snapname")
		f.snapCtr++
		f.snaps[name] = f.snapCtr
		data(fmt.Sprintf("%q", pUPID("qmsnapshot", 690)))
	case m == http.MethodDelete && strings.Contains(p, "/qemu/690/snapshot/"): // delete snapshot
		f.postQemuCalls++
		name := p[strings.LastIndex(p, "/")+1:]
		delete(f.snaps, name)
		data(fmt.Sprintf("%q", pUPID("qmdelsnapshot", 690)))
	case m == http.MethodDelete && strings.HasSuffix(p, "/qemu/690"): // destroy
		f.postQemuCalls++
		// A SECOND destroy (the cleanup re-destroy) can "print nothing" — 690
		// already left the pool — so the cleanup must fall back to the MAIN
		// destroy's UPID to judge it (CR5 / CleanupKeepsTheRealCause).
		if f.destroyed && f.cleanupReDestroyEmpty {
			data(`null`)
			return
		}
		f.destroyCalls++
		f.destroyed = true
		data(fmt.Sprintf("%q", pUPID("qmdestroy", 690)))
	default:
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route for "+m+" "+p))
	}
}

func (f *pfake) or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (f *pfake) poolJSON() string {
	var ms []string
	if f.poolX {
		ms = append(ms, `{"type":"qemu","vmid":700,"node":"`+pnode+`"}`)
	}
	if !f.created && f.poolMemberRaw != "" {
		ms = append(ms, f.poolMemberRaw)
	}
	// 690 is a pool member only if the create actually carried pool=<pool>
	// (CR1): a create that omitted pool does NOT pool 690.
	present := f.pre690
	if f.createPooled && !f.destroyed {
		present = true
	}
	if present {
		ms = append(ms, `{"type":"qemu","vmid":690,"node":"`+pnode+`"}`)
	}
	return `[{"poolid":"pveforge-harness","members":[` + strings.Join(ms, ",") + `]}]`
}

func (f *pfake) snapListJSON() string {
	type sv struct {
		name string
		t    int64
	}
	var all []sv
	for n, t := range f.snaps {
		all = append(all, sv{n, t})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t < all[j].t })
	parts := make([]string, 0, len(all)+1)
	for _, s := range all {
		parts = append(parts, fmt.Sprintf(`{"name":%q,"snaptime":%d}`, s.name, s.t))
	}
	parts = append(parts, `{"name":"current","snaptime":0}`)
	return "[" + strings.Join(parts, ",") + "]"
}

// newProbeTest wires pfake behind a TLS server, a roster target "h" on pnode,
// the passphrase, and a per-test HOME (for the evidence + rule dirs).
func newProbeTest(t *testing.T, f *pfake) (rosterPath, home string) {
	t.Helper()
	if f.storage == "" {
		f.storage = "pveforge-harness"
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	home = t.TempDir()
	t.Setenv("HOME", home)
	return newTestRosterWithTLSTarget(t, srv, "h", pnode), home
}

func ruleFile(home, storage string) string {
	return filepath.Join(home, ".config/pveforge/harness-state/rollback-rule."+storage)
}

func readRule(home, storage string) (string, bool) {
	b, err := os.ReadFile(ruleFile(home, storage))
	if err != nil {
		return "", false
	}
	return strings.TrimRight(string(b), "\n"), true
}

// --- happy path ----------------------------------------------------------

func TestProbe_ZFSPool_LatestOnly(t *testing.T) {
	f := &pfake{}
	rosterPath, home := newProbeTest(t, f)
	code, stdout, stderr := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if want := "rollback-rule=rollback-latest-only storage=pveforge-harness\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if rule, ok := readRule(home, "pveforge-harness"); !ok || rule != "rollback-latest-only" {
		t.Errorf("rule file = %q (ok=%v), want rollback-latest-only", rule, ok)
	}
	// CR4: the raw classification rollback must POST to VM 690's own path (a
	// mutant posting a different VMID would go red here).
	if rp := func() string { f.mu.Lock(); defer f.mu.Unlock(); return f.rollbackPath }(); !strings.Contains(rp, "/qemu/690/snapshot/s1/rollback") {
		t.Errorf("rollback POST path = %q, want it to target /qemu/690/snapshot/s1/rollback", rp)
	}
}

func TestProbe_StaticOnly(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "--static-only", "h")
	if code != 0 || !strings.Contains(stdout, "passes the static checks") {
		t.Fatalf("exit %d stdout %q", code, stdout)
	}
	if _, ok := readRule(home, "pveforge-harness"); ok {
		t.Error("static-only wrote a rule file")
	}
}

// --- static refusals (assert the STDOUT cause, never exit 3) -------------

func TestProbe_StaticRefusals(t *testing.T) {
	healthy := func(mut string) string { return mut }
	cases := []struct {
		name   string
		status string
		want   string
	}{
		{"not enabled", `{"type":"zfspool","enabled":0,"active":1,"content":"images","avail":644245094400,"used":0}`, "not enabled"},
		{"not active", `{"type":"zfspool","enabled":1,"active":0,"content":"images","avail":644245094400,"used":0}`, "not active"},
		{"imagesx element not substring", `{"type":"zfspool","enabled":1,"active":1,"content":"imagesx","avail":644245094400,"used":0}`, "does not include images"},
		{"lvmthin by name", `{"type":"lvmthin","enabled":1,"active":1,"content":"images","avail":644245094400,"used":0}`, "type lvmthin is not supported"},
		{"dir by name", `{"type":"dir","enabled":1,"active":1,"content":"images","avail":644245094400,"used":0}`, "type dir cannot hold the harness"},
		{"too little space", `{"type":"zfspool","enabled":1,"active":1,"content":"images","avail":557842739200,"used":0}`, "below HARNESS_PROBE_MIN_FREE_GIB=520"},
		{"boolean enabled accepted but inactive", `{"type":"zfspool","enabled":true,"active":false,"content":"images","avail":644245094400,"used":0}`, "not active"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, home := newProbeTest(t, &pfake{statusJSON: healthy(c.status)})
			code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
			if code == 0 {
				t.Fatalf("a refused storage exited 0: %q", stdout)
			}
			if !strings.Contains(stdout, "refusing storage") || !strings.Contains(stdout, c.want) {
				t.Errorf("stdout = %q, want refusal containing %q", stdout, c.want)
			}
			if _, ok := readRule(home, "pveforge-harness"); ok {
				t.Error("a refused storage wrote a rule file")
			}
		})
	}
}

func TestProbe_690MustNotExist(t *testing.T) {
	cases := []struct {
		name string
		f    *pfake
		want string
	}{
		{"690 already in pool", &pfake{pre690: true}, "already exists in pool"},
		{"pool not empty", &pfake{poolX: true}, "is not empty"},
		{"storage not empty", &pfake{usedNow: "2097152"}, "is not empty"}, // 2 MiB > 1 MiB slack
		{"content holds 690", &pfake{contentPre: `[{"volid":"x"}]`}, "already holds volumes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, _ := newProbeTest(t, c.f)
			code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
			if code == 0 || !strings.Contains(stdout, c.want) {
				t.Errorf("exit %d stdout %q, want refusal containing %q", code, stdout, c.want)
			}
		})
	}
}

// --- rollback-any: a storage that ALLOWS a non-latest rollback (now genuinely
// reachable — under P4 the probe always pre-refused and this was dead) -------
func TestProbe_RollbackAny(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{rollbackAny: true})
	code, stdout, stderr := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, stderr, stdout)
	}
	if want := "rollback-rule=rollback-any storage=pveforge-harness\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if rule, ok := readRule(home, "pveforge-harness"); !ok || rule != "rollback-any" {
		t.Errorf("rule file = %q (ok=%v), want rollback-any", rule, ok)
	}
}

// --- headline mutant (M1): an unrelated rollback error must FAIL, not
// latest-only (correct: FAILED stdout, no rule file). ----------------------
func TestProbe_Mut_RollbackUnrelatedErrorFails(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{rollbackOtherErr: true})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatalf("an unrelated rollback error exited 0: %q", stdout)
	}
	if !strings.Contains(stdout, "FAILED") || strings.Contains(stdout, "rollback-rule=") {
		t.Errorf("stdout = %q, want a FAILED line and no rollback-rule", stdout)
	}
	if _, ok := readRule(home, "pveforge-harness"); ok {
		t.Error("an unrelated rollback error wrote a rule file")
	}
}

// --- gone-proof reuse: a WARNINGS destroy task must FAIL the probe ---------
func TestProbe_Mut_GoneProofWarnings(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{destroyExit: "WARNINGS: 1"})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stdout, "not proven gone") {
		t.Errorf("exit %d stdout %q, want 'not proven gone'", code, stdout)
	}
	if _, ok := readRule(home, "pveforge-harness"); ok {
		t.Error("a WARNINGS destroy wrote a rule file")
	}
}

// --- vmstate=0: the probe's snapshots must be disk-only --------------------
func TestProbe_Mut_Vmstate0(t *testing.T) {
	f := &pfake{}
	rosterPath, _ := newProbeTest(t, f)
	// Intercept the snapshot POST params by wrapping: assert via a recording
	// in the handler. Simplest: run and confirm success implies vmstate=0 was
	// accepted. We additionally record the last snapshot vmstate.
	var gotVmstate string
	f.recordVmstate = func(v string) { gotVmstate = v }
	code, _, stderr := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if gotVmstate != "0" {
		t.Errorf("snapshot vmstate = %q, want 0 (disk-only)", gotVmstate)
	}
}

// --- rule-file: a symlink at the rule path must be refused ----------------
func TestProbe_Mut_RuleFileSymlinkRefused(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{})
	state := filepath.Join(home, ".config/pveforge/harness-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/evil", ruleFile(home, "pveforge-harness")); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stdout, "FAILED") {
		t.Errorf("exit %d stdout %q, want FAILED (symlink refused)", code, stdout)
	}
}

// --- leftover bound: a storage that never clears must FAIL after the bound -
func TestProbe_Mut_LeftoverBound(t *testing.T) {
	// D1: the outer seam is gone; shorten the bound via package main's seam so
	// the "never clears" leftover is detected after a short bound, not 180s.
	savedB, savedP := probeLeftoverBound, probeLeftoverPoll
	probeLeftoverBound, probeLeftoverPoll = 30*time.Millisecond, 5*time.Millisecond
	defer func() { probeLeftoverBound, probeLeftoverPoll = savedB, savedP }()
	rosterPath, home := newProbeTest(t, &pfake{leftoverVol: true})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stdout, "leftover") {
		t.Errorf("exit %d stdout %q, want a leftover FAILED", code, stdout)
	}
	if _, ok := readRule(home, "pveforge-harness"); ok {
		t.Error("a leftover wrote a rule file")
	}
}

// --- cleanup ledger-gate: a failure after create with NO ledger must NOT
// destroy 690 (report a leftover instead) -----------------------------------
func TestProbe_Mut_CleanupLedgerGate(t *testing.T) {
	f := &pfake{snapFail: true} // s1 create fails → the run fails after create
	rosterPath, _ := newProbeTest(t, f)
	// No --created-file: the ledger does not list 690.
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatalf("a post-create failure exited 0: %q", stdout)
	}
	f.mu.Lock()
	dc := f.destroyCalls
	f.mu.Unlock()
	if dc != 0 {
		t.Errorf("cleanup destroyed an un-ledgered VM (%d destroy calls); it must report a leftover", dc)
	}
}

// --- CR4: the VM lock must cover the MUTATIONS, not just be acquired -------
// While the test holds the VM lock, the command must fail to acquire it AND
// make ZERO POST/DELETE /qemu calls (no create/snapshot/rollback/destroy ran
// without the lock). A mutant moving lock.Mutation after d.Run would still
// error "acquire lock" at the end but would have run the mutations unlocked.
func TestProbe_HoldsLockAcrossRun(t *testing.T) {
	f := &pfake{}
	rosterPath, _ := newProbeTest(t, f)
	holdLock(t, rosterPath, harnessVMKey("h", 690))
	code, _, stderr := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--lock-wait", "7ms", "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatalf("probe ran without acquiring the VM lock")
	}
	if !strings.Contains(stderr, "acquire lock") {
		t.Errorf("stderr = %q, want an 'acquire lock' failure", stderr)
	}
	f.mu.Lock()
	n := f.postQemuCalls
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("%d POST/DELETE /qemu call(s) ran while the lock was held: the lock does not cover the mutations", n)
	}
}

// --- CR1: the create POST must carry pool=<harness pool> (how 690 joins the
// pool; harness_vm_create lib.sh:12). Without it, the fake does not pool 690
// and the first Guard(ModeChange) refuses it. --------------------------------
func TestProbe_CreateSendsPool(t *testing.T) {
	f := &pfake{}
	rosterPath, _ := newProbeTest(t, f)
	code, _, stderr := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	f.mu.Lock()
	cp := f.createPool
	f.mu.Unlock()
	if cp != "pveforge-harness" {
		t.Errorf("create POST carried pool=%q, want pveforge-harness", cp)
	}
}

// --- CR2: a rollback failure whose text CONTAINS "snapshot" but is NOT the
// not-most-recent refusal must FAIL, never be recorded as latest-only. ------
func TestProbe_RollbackBusyIsNotLatestOnly(t *testing.T) {
	rosterPath, home := newProbeTest(t, &pfake{rollbackBusy: true})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatalf("a 'storage is busy' rollback error exited 0: %q", stdout)
	}
	if !strings.Contains(stdout, "FAILED") || strings.Contains(stdout, "rollback-rule=") {
		t.Errorf("stdout = %q, want FAILED and no rollback-rule", stdout)
	}
	if _, ok := readRule(home, "pveforge-harness"); ok {
		t.Error("a busy-storage rollback error wrote a rule file")
	}
}

// --- CR3: a pre-create pool member with a STRING vmid "690" must be refused
// as an unexpected shape, never read as absent (nor aliased to the number). -
func TestProbe_StringPoolMemberRefused(t *testing.T) {
	rosterPath, _ := newProbeTest(t, &pfake{poolMemberRaw: `{"type":"qemu","vmid":"690","node":"qa-pve-07"}`})
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatalf("a string-vmid pool member exited 0: %q", stdout)
	}
	if !strings.Contains(stdout, "not a number") {
		t.Errorf("stdout = %q, want an 'unexpected shape / not a number' failure", stdout)
	}
}

// --- CR5: cleanup runs on a DETACHED context — a signal cancelling
// cmd.Context AFTER the create must still destroy 690 and prove it gone. -----
func TestProbe_CleanupDetachedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &pfake{}
	f.afterCreate = func() {
		// Fired on the first snapshot POST — createAndTag has completed, so
		// d.created is set. Cancel cmd.Context: the in-flight snapshot request
		// aborts and the run fails, so cleanup must run on its OWN detached
		// context to still destroy 690. The short sleep lets the cancellation
		// propagate before this request returns.
		cancel()
		time.Sleep(40 * time.Millisecond)
	}
	rosterPath, _ := newProbeTest(t, f)
	code, _, _ := runProbeCtx(ctx, "harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatal("a cancelled run exited 0; expected a failure")
	}
	f.mu.Lock()
	dc, destroyed := f.destroyCalls, f.destroyed
	f.mu.Unlock()
	if dc == 0 || !destroyed {
		t.Errorf("cleanup did not destroy 690 on the detached context (destroyCalls=%d destroyed=%v)", dc, destroyed)
	}
}

// --- CR5: the cleanup re-destroy prints nothing (690 already gone) → the
// main-path UPID (a WARNINGS task) must be the one judged, so the LEFTOVER
// note keeps the REAL cause, not "printed no UPID". -------------------------
func TestProbe_CleanupKeepsTheRealCause(t *testing.T) {
	f := &pfake{destroyExit: "WARNINGS: 1", cleanupReDestroyEmpty: true}
	rosterPath, home := newProbeTest(t, f)
	code, stdout, _ := runRootArgs("harness", "probe", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stdout, "not proven gone") {
		t.Fatalf("exit %d stdout %q, want a not-proven-gone failure", code, stdout)
	}
	leftover := readEvidence(t, home, "LEFTOVER")
	if !strings.Contains(leftover, "WARNINGS") || strings.Contains(leftover, "printed no UPID") {
		t.Errorf("LEFTOVER note = %q, want the real WARNINGS cause (fallback to the main-path UPID), not 'printed no UPID'", leftover)
	}
}

// readEvidence reads a named evidence file from this run's probe evidence dir.
func readEvidence(t *testing.T, home, name string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(home, ".config/pveforge/harness-evidence/probe/*", name))
	if len(matches) == 0 {
		return ""
	}
	b, _ := os.ReadFile(matches[len(matches)-1])
	return string(b)
}
