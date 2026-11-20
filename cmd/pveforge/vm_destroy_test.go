package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// These tests drive `pveforge vm destroy` THROUGH runRoot (so the exit status
// and the report are what an operator sees) against internal/pvefake's VMREST
// over TLS. Every "zero requests" assertion has a control: the same fixture, on
// its positive path, records at least one. The package is non-parallel.

const (
	dNode   = "qa-pve-01"
	dTarget = "qa-pve-01"
	dVMID   = 691
)

var (
	dDeletePrefix = "DELETE /api2/json/nodes/" + dNode + "/qemu/" + strconv.Itoa(dVMID)
	dStopPrefix   = "POST /api2/json/nodes/" + dNode + "/qemu/" + strconv.Itoa(dVMID) + "/status/stop"
)

func dUPID(kind string, n int) string {
	return fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%d:root@pam!pveforge:", dNode, n, n, 0x5F000000+n, kind, dVMID)
}

// dRow is a TERMINAL task row for the vmid, in the archive half of the log.
func dRow(kind string, n int, exit string) pvefake.TaskRow {
	return pvefake.TaskRow{UPID: dUPID(kind, n), Type: kind, ID: strconv.Itoa(dVMID), StartTime: int64(1000 + n),
		Status: exit, EndTime: int64(1002 + n), Saved: true, Node: dNode, User: "root@pam"}
}

// dRunning is a NON-terminal row (no endtime), as PVE's active branch serves it.
func dRunning(kind string, n int) pvefake.TaskRow {
	return pvefake.TaskRow{UPID: dUPID(kind, n), Type: kind, ID: strconv.Itoa(dVMID), StartTime: int64(1000 + n),
		Status: "RUNNING", Node: dNode, User: "root@pam"}
}

type dEnv struct {
	t      *testing.T
	s      *pvefake.VMREST
	srv    *httptest.Server
	roster string
	faults *atomic.Int32
}

// newDEnv is a present, stopped VM whose destroy ends OK once dispatched
// (Reflect + ReflectEnd: the row appears only AFTER the dispatch), with the
// vmid free afterwards. mut edits the fixture before it is served.
func newDEnv(t *testing.T, mut func(*pvefake.VMREST)) *dEnv {
	return newDEnvFault(t, mut, nil)
}

// newDEnvFault is newDEnv behind a proxy that hijacks and closes the
// connection of every request fail selects, counting them (faults).
func newDEnvFault(t *testing.T, mut func(*pvefake.VMREST), fail func(*http.Request) bool) *dEnv {
	t.Helper()
	s := pvefake.NewVMREST(t, dNode)
	s.VMConfig = `{"name":"vm691"}`
	s.NextIDFree = true
	s.Reflect, s.ReflectEnd = true, "OK"
	s.DestroyUPID, s.StopUPID = dUPID("qmdestroy", 1), dUPID("qmstop", 2)
	if mut != nil {
		mut(s)
	}
	e := &dEnv{t: t, s: s}
	if fail == nil {
		e.srv = s.ServerTLS()
	} else {
		up := s.Server()
		t.Cleanup(up.Close)
		u, err := url.Parse(up.URL)
		if err != nil {
			t.Fatal(err)
		}
		rp := httputil.NewSingleHostReverseProxy(u)
		e.faults = new(atomic.Int32)
		e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if fail(r) {
				e.faults.Add(1)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			rp.ServeHTTP(w, r)
		}))
		e.srv.StartTLS()
	}
	t.Cleanup(e.srv.Close)
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 2*time.Second))
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	e.roster = newTestRosterWithTLSTarget(t, e.srv, dTarget, dNode)
	return e
}

type dRes struct {
	code           int
	stdout, stderr string
	m              map[string]any
}

func (r dRes) str(k string) string {
	if v, ok := r.m[k]; ok {
		s, _ := v.(string)
		return s
	}
	return ""
}
func (r dRes) has(k string) bool { _, ok := r.m[k]; return ok }

func parseDRes(t *testing.T, code int, stdout, stderr string) dRes {
	t.Helper()
	r := dRes{code: code, stdout: stdout, stderr: stderr}
	if strings.TrimSpace(stdout) != "" {
		if err := json.Unmarshal([]byte(stdout), &r.m); err != nil {
			t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
		}
	}
	return r
}

// run is `vm destroy --roster R -o json [args] <target> <vmid>`.
func (e *dEnv) runVMID(vmid string, args ...string) dRes {
	e.t.Helper()
	full := append([]string{"vm", "destroy", "--roster", e.roster, "-o", "json"}, args...)
	full = append(full, dTarget, vmid)
	code, out, errOut := runRootArgs(full...)
	return parseDRes(e.t, code, out, errOut)
}
func (e *dEnv) run(args ...string) dRes { e.t.Helper(); return e.runVMID(strconv.Itoa(dVMID), args...) }
func (e *dEnv) runYes(args ...string) dRes {
	e.t.Helper()
	return e.run(append([]string{"--yes"}, args...)...)
}

func (e *dEnv) count(prefix string) int {
	n := 0
	for _, r := range e.s.Requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}
func (e *dEnv) deletes() int { return e.count(dDeletePrefix) }
func (e *dEnv) stops() int   { return e.count(dStopPrefix) }

func (e *dEnv) index(sub string, from int) int {
	for i, r := range e.s.Requests() {
		if i >= from && strings.Contains(r, sub) {
			return i
		}
	}
	return -1
}

func want(t *testing.T, r dRes, code int, outcome, situation string) {
	t.Helper()
	if r.code != code || r.str("outcome") != outcome || (situation != "" && r.str("situation") != situation) {
		t.Fatalf("exit %d outcome %q situation %q, want %d %q %q\nstdout %s\nstderr %q", r.code, r.str("outcome"), r.str("situation"), code, outcome, situation, r.stdout, r.stderr)
	}
}

// refusalShape is held by EVERY refusal row: it dispatched nothing, so it has
// no destroy identity and no reason, and it names the vmid, an observation and
// what would change the answer (spec I5).
func refusalShape(t *testing.T, r dRes) {
	t.Helper()
	if r.code != 4 || r.str("outcome") != "refused" {
		t.Fatalf("not a refusal: exit %d, %s", r.code, r.stdout)
	}
	for _, k := range []string{"upid", "reason", "already_destroyed", "stop_upid", "exitstatus"} {
		if r.has(k) {
			t.Errorf("a refusal carries %q: %s", k, r.stdout)
		}
	}
	if int(r.m["vmid"].(float64)) != dVMID || r.str("condition") == "" || (r.str("observed") == "" && r.str("read") == "") {
		t.Errorf("a refusal must name the vmid, what was observed and what would change the answer: %s", r.stdout)
	}
}

// ---------------------------------------------------------------- surface

func TestVMDestroy_FlagsAreExactly(t *testing.T) {
	cmd := newVMDestroyCmd()
	var got []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) { got = append(got, f.Name) })
	slices.Sort(got)
	if !slices.Equal(got, []string{"lock-wait", "output", "roster", "yes"}) {
		t.Errorf("flags = %v, want exactly lock-wait, output, roster, yes", got)
	}
	for _, bad := range []string{"purge", "destroy-unreferenced-disks", "force", "no-wait", "wait-timeout", "created-file", "pool", "tag"} {
		if cmd.Flags().Lookup(bad) != nil {
			t.Errorf("vm destroy has --%s", bad)
		}
	}
	if cmd.Annotations[mutationAnnotationKey] != mutationDestructive {
		t.Errorf("tier = %q, want destructive", cmd.Annotations[mutationAnnotationKey])
	}
}

func TestVMDestroy_UsageErrorsExitOneBeforeAnyContact(t *testing.T) {
	e := newDEnv(t, nil)
	for _, args := range [][]string{
		{"vm", "destroy", "--roster", e.roster},
		{"vm", "destroy", "--roster", e.roster, dTarget},
		{"vm", "destroy", "--roster", e.roster, dTarget, "691", "x"},
		{"vm", "destroy", "--roster", e.roster, dTarget, "abc"},
		{"vm", "destroy", "--roster", e.roster, dTarget, "+691"},
		{"vm", "destroy", "--roster", e.roster, dTarget, "-1"},
		{"vm", "destroy", "--roster", e.roster, dTarget, "0691"},
		{"vm", "destroy", "--roster", e.roster, dTarget, "0"},
		{"vm", "destroy", "--roster", e.roster, dTarget, ""},
		{"vm", "destroy", "--roster", e.roster, "-o", "yaml", dTarget, "691", "--yes"},
		{"vm", "destroy", "--roster", e.roster, "--yes", "no-such-target", "691"},
	} {
		code, out, errOut := runRootArgs(args...)
		if code != 1 || out != "" || errOut == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q, want exit 1, empty stdout, a message", args, code, out, errOut)
		}
	}
	if n := len(e.s.Requests()); n != 0 {
		t.Errorf("a malformed invocation reached PVE: %d requests %q", n, e.s.Requests())
	}
	// Control: the same fixture, well formed, does reach it.
	if r := e.runYes(); r.code != 0 || len(e.s.Requests()) == 0 {
		t.Fatalf("control: exit %d, %d requests, %s", r.code, len(e.s.Requests()), r.stdout)
	}
}

func TestVMDestroy_AcceptsAVMIDOutsideTheHarnessBand(t *testing.T) {
	// 100 is not one of the harness verb's 690-699 and must be accepted here.
	e := newDEnv(t, func(s *pvefake.VMREST) { s.DestroyUPID = strings.ReplaceAll(dUPID("qmdestroy", 1), ":691:", ":100:") })
	r := e.runVMID("100", "--yes")
	if r.code == 1 && r.stdout == "" {
		t.Fatalf("vmid 100 refused as a usage error: %s", r.stderr)
	}
	code, _, errOut := runRootArgs("harness", "vm", "destroy", "--roster", e.roster, "--yes", dTarget, "100")
	if code == 0 || !strings.Contains(errOut, "690-699") {
		t.Errorf("the harness verb must still refuse vmid 100: exit %d, %q", code, errOut)
	}
}

// ---------------------------------------------------------------- B1

func TestVMDestroy_B1_OKOnlyAfterTheGoneProof(t *testing.T) {
	e := newDEnv(t, nil)
	r := e.runYes()
	want(t, r, 0, "ok", "B1")
	if r.str("upid") != dUPID("qmdestroy", 1) || r.str("exitstatus") != "OK" || r.stderr != "" {
		t.Errorf("B1: %s stderr %q", r.stdout, r.stderr)
	}
	for _, k := range []string{"reason", "inflight_upid", "stop_upid", "prior_upid", "error", "privilege", "already_destroyed"} {
		if r.has(k) {
			t.Errorf("an ok row carries %q: %s", k, r.stdout)
		}
	}
	if e.deletes() != 1 || e.stops() != 0 {
		t.Errorf("DELETEs %d STOPs %d, want 1 and 0 (stopped VM)", e.deletes(), e.stops())
	}
	// purge, and nothing else.
	wantReq := dDeletePrefix + " ?purge=1"
	if !slices.Contains(e.s.Requests(), wantReq) {
		t.Errorf("no %q in %q", wantReq, e.s.Requests())
	}
	for _, q := range e.s.Requests() {
		if strings.Contains(q, "destroy-unreferenced-disks") {
			t.Errorf("destroy-unreferenced-disks was sent: %q", q)
		}
	}
	// The free-proof was read: ok is not the task's exit status alone.
	if e.count("GET /api2/json/cluster/nextid") == 0 {
		t.Error("ok without reading /cluster/nextid")
	}
	// Order: probe, then the task list, then the node-local config.
	probe := e.index("GET /api2/json/nodes/"+dNode+"/status", 0)
	list := e.index("GET /api2/json/nodes/"+dNode+"/tasks ?", 0)
	cfg := e.index("GET /api2/json/nodes/"+dNode+"/qemu/691/config", 0)
	if !(probe >= 0 && probe < list && list < cfg) {
		t.Errorf("request order probe %d, list %d, config %d: %q", probe, list, cfg, e.s.Requests())
	}
}

func TestVMDestroy_B1_RunningVMIsStoppedFirst_AndDoesNotRefuseItself(t *testing.T) {
	e := newDEnv(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}` })
	r := e.runYes()
	want(t, r, 0, "ok", "B1")
	if e.stops() != 1 || e.deletes() != 1 || e.index(dStopPrefix, 0) > e.index(dDeletePrefix, 0) {
		t.Errorf("stops %d deletes %d: %q", e.stops(), e.deletes(), e.s.Requests())
	}
	// I1f: this fixture REFLECTS the verb's own stop and destroy as rows (a
	// static fixture never grows them, so it could not show a self-collision).
	if !e.s.Reflect {
		t.Fatal("the fixture is not reflecting")
	}
}

func TestVMDestroy_B1_WarningsAndErrorStringsAreNeverOK(t *testing.T) {
	// WaitForTask returns nil for "WARNINGS: n"; ok must come from DestroyEnd's
	// exact exit string, read from the PER-TASK status endpoint.
	for _, tc := range []struct{ end, situation, reason string }{
		{"WARNINGS: 1", "B1-unclean", "unclean"},
		{"ERROR: disk busy", "task-failed", "task-failed"},
	} {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = tc.end })
		r := e.runYes()
		want(t, r, 1, "failed", tc.situation)
		if r.str("reason") != tc.reason || r.str("exitstatus") != tc.end || e.deletes() != 1 {
			t.Errorf("%q: %s", tc.end, r.stdout)
		}
		if tc.end == "WARNINGS: 1" && !strings.Contains(r.stderr, "succeeded with warnings") {
			t.Errorf("the warnings notice is PVE's accounting and is still printed: %q", r.stderr)
		}
	}
}

// ---------------------------------------------------------------- B2 / B3

func TestVMDestroy_B2_DeadlineIsUnknownAndDispatchesOnce(t *testing.T) {
	e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" }) // the destroy stays running
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 150*time.Millisecond))
	r := e.runYes()
	want(t, r, 3, "unknown", "B2")
	if r.str("reason") != "deadline" || r.str("upid") != dUPID("qmdestroy", 1) || e.deletes() != 1 {
		t.Errorf("B2: %s, deletes %d", r.stdout, e.deletes())
	}
	// AC-O7 second half: a second run against the reflected, still-running
	// destroy is refused, not dispatched.
	r2 := e.runYes()
	want(t, r2, 4, "refused", "B4")
	refusalShape(t, r2)
	if r2.str("inflight_upid") != dUPID("qmdestroy", 1) || e.deletes() != 1 {
		t.Errorf("B4 after B2: %s, deletes %d", r2.stdout, e.deletes())
	}
}

func TestVMDestroy_B3_PollFailuresAreUnknownWithAReadFailureReason(t *testing.T) {
	statusKey := "GET /nodes/" + dNode + "/tasks/" + dUPID("qmdestroy", 1) + "/status"
	e := newDEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{statusKey: {{Code: 595, Message: "no route to host"}}}
	})
	r := e.runYes()
	want(t, r, 3, "unknown", "B3")
	if r.str("reason") != "read-failure" || r.str("upid") == "" || e.deletes() != 1 {
		t.Errorf("B3: %s", r.stdout)
	}
}

// ---------------------------------------------------------------- B4 family

func TestVMDestroy_B4_NonTerminalHazardousTaskRefusesWithZeroDeleteAndZeroStop(t *testing.T) {
	for _, tc := range []struct{ kind, situation string }{
		{"qmdestroy", "B4"},
		{"qmigrate", "B4b"}, {"hamigrate", "B4b"}, {"qmclone", "B4b"}, {"qmrestore", "B4b"},
		{"qmstop", "B4c"}, {"qmshutdown", "B4c"},
	} {
		// VMStatus running: the status gate WOULD stop it, so 0 STOP is real.
		e := newDEnv(t, func(s *pvefake.VMREST) {
			s.VMStatus = `{"status":"running"}`
			s.Tasks = []pvefake.TaskRow{dRunning(tc.kind, 7)}
		})
		r := e.runYes()
		want(t, r, 4, "refused", tc.situation)
		refusalShape(t, r)
		if r.str("inflight_upid") != dUPID(tc.kind, 7) || r.str("inflight_type") != tc.kind {
			t.Errorf("%s: %s", tc.kind, r.stdout)
		}
		if e.deletes() != 0 || e.stops() != 0 || e.count("GET /api2/json/nodes/"+dNode+"/qemu/") != 0 {
			t.Errorf("%s: DELETEs %d STOPs %d, requests %q", tc.kind, e.deletes(), e.stops(), e.s.Requests())
		}
		// Control: the same fixture without the row stops and destroys.
		c := newDEnv(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}` })
		if cr := c.runYes(); cr.code != 0 || c.deletes() != 1 || c.stops() != 1 {
			t.Fatalf("%s control: exit %d DELETEs %d STOPs %d", tc.kind, cr.code, c.deletes(), c.stops())
		}
	}
}

func TestVMDestroy_B4e_ResetAndRebootAreAllowed(t *testing.T) {
	for _, kind := range []string{"qmreset", "qmreboot"} {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.Tasks = []pvefake.TaskRow{dRunning(kind, 7)} })
		r := e.runYes()
		want(t, r, 0, "ok", "B1")
		if e.deletes() != 1 {
			t.Errorf("%s: DELETEs %d, want exactly 1", kind, e.deletes())
		}
	}
}

func TestVMDestroy_B4_TheFirstRowInPageOrderIsNamed(t *testing.T) {
	// The oracle is the fixture's OWN served page (asked over HTTP with the
	// determination's query), not the order the test happened to script: the
	// verb must name the first non-terminal hazardous row of that page, whatever
	// its type, and must neither re-sort nor prefer a type.
	firsts := map[string]bool{}
	for _, rows := range [][]pvefake.TaskRow{
		{dRunning("qmigrate", 8), dRunning("qmdestroy", 9)},
		{dRunning("qmdestroy", 9), dRunning("qmigrate", 8)},
	} {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.Tasks = rows })
		resp, err := e.srv.Client().Get(e.srv.URL + "/api2/json/nodes/" + dNode + "/tasks?source=all&vmid=" + strconv.Itoa(dVMID) + "&limit=2000&since=0")
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Data []struct {
				UPID string `json:"upid"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil || len(page.Data) != 2 {
			t.Fatalf("served page: %v %+v", err, page)
		}
		resp.Body.Close()
		firsts[page.Data[0].UPID] = true
		r := e.runYes()
		want(t, r, 4, "refused", "")
		if got := r.str("inflight_upid"); got != page.Data[0].UPID {
			t.Errorf("named %q, but the first row of the served page is %q", got, page.Data[0].UPID)
		}
	}
	// Anti-vacuity: the two scripts serve DIFFERENT first rows, or the
	// comparison above could not tell the first from the last.
	if len(firsts) != 2 {
		t.Errorf("both scripts served the same first row: %v", firsts)
	}
}

func TestVMDestroy_B4d_NoYesReadsFirstAndThenStopsDead(t *testing.T) {
	e := newDEnv(t, nil)
	r := e.run() // no --yes
	want(t, r, 4, "refused", "B4d")
	refusalShape(t, r)
	if !strings.Contains(r.str("condition"), "--yes") {
		t.Errorf("the refusal must say --yes: %s", r.stdout)
	}
	if e.count("GET /api2/json/nodes/"+dNode+"/status") == 0 || e.count("GET /api2/json/nodes/"+dNode+"/tasks ?") == 0 {
		t.Errorf("the determination's reads were not made before B4d: %q", e.s.Requests())
	}
	if e.count("GET /api2/json/nodes/"+dNode+"/qemu/") != 0 || e.stops() != 0 || e.deletes() != 0 {
		t.Errorf("B4d went past --yes: %q", e.s.Requests())
	}
	// With --yes the next expected read is the node-local config.
	e2 := newDEnv(t, nil)
	e2.runYes()
	if e2.count("GET /api2/json/nodes/"+dNode+"/qemu/691/config") == 0 {
		t.Error("with --yes the config read did not follow the list read")
	}
}

func TestVMDestroy_NoYesAndAnInFlightDestroy_NamesTheInFlightTask(t *testing.T) {
	e := newDEnv(t, func(s *pvefake.VMREST) { s.Tasks = []pvefake.TaskRow{dRunning("qmdestroy", 7)} })
	r := e.run()
	want(t, r, 4, "refused", "B4")
	if r.str("inflight_upid") != dUPID("qmdestroy", 7) {
		t.Errorf("only --yes was reported: %s", r.stdout)
	}
}

// ---------------------------------------------------------------- B5 / B6

func retryEnv(t *testing.T, rows []pvefake.TaskRow, mut func(*pvefake.VMREST)) *dEnv {
	return newDEnv(t, func(s *pvefake.VMREST) {
		s.VMConfig = "" // PVE's real "does not exist" answer
		s.Reflect = false
		s.Tasks = rows
		if mut != nil {
			mut(s)
		}
	})
}

func TestVMDestroy_B5_RetryRows(t *testing.T) {
	// D1b: the SAME fixture, only the terminal row's exit string differs.
	ok := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, nil)
	r := ok.runYes()
	want(t, r, 0, "ok", "B5-gone")
	if r.m["already_destroyed"] != true || r.str("upid") != dUPID("qmdestroy", 3) || r.str("exitstatus") != "OK" || ok.deletes() != 0 || ok.stops() != 0 {
		t.Errorf("B5-gone: %s, deletes %d", r.stdout, ok.deletes())
	}
	for _, end := range []string{"WARNINGS: 1", "ERROR: busy"} {
		e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, end)}, nil)
		r := e.runYes()
		want(t, r, 1, "failed", "B5-unclean")
		if r.str("exitstatus") != end || r.has("already_destroyed") || e.deletes() != 0 {
			t.Errorf("B5-unclean %q: %s", end, r.stdout)
		}
	}
	// In use cluster-wide: refused, never ok.
	e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.NextIDFree = false })
	r = e.runYes()
	want(t, r, 4, "refused", "B5-elsewhere")
	refusalShape(t, r)
	// Free but no destroy visible: absence alone is not a gone-proof.
	e = retryEnv(t, nil, nil)
	r = e.runYes()
	want(t, r, 4, "refused", "B5-absent-without-task")
	refusalShape(t, r)
	if e.deletes() != 0 {
		t.Error("dispatched on a retry")
	}
}

func TestVMDestroy_B5_ARetryReadsEveryMemberFresh(t *testing.T) {
	// A newer WARNINGS destroy on another member must not be certified by an
	// older OK on the roster node.
	e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) {
		n2 := dRow("qmdestroy", 9, "WARNINGS: 1")
		n2.Node = "n2"
		s.Peers = map[string]*pvefake.PeerNode{"n2": {Tasks: []pvefake.TaskRow{n2}}}
	})
	r := e.runYes()
	want(t, r, 1, "failed", "B5-unclean")
	if r.str("exitstatus") != "WARNINGS: 1" {
		t.Errorf("%s", r.stdout)
	}
}

func TestVMDestroy_PresenceUnreadableIsRefusedByTheVerb(t *testing.T) {
	for name, mut := range map[string]func(*pvefake.VMREST){
		"config 500": func(s *pvefake.VMREST) { s.ConfigStatus = 500 },
		"config 502": func(s *pvefake.VMREST) { s.ConfigStatus = 502 },
	} {
		e := newDEnv(t, mut)
		r := e.runYes()
		want(t, r, 4, "refused", "B10")
		refusalShape(t, r)
		if !strings.Contains(r.str("read"), "/config") || e.deletes() != 0 || e.stops() != 0 {
			t.Errorf("%s: %s", name, r.stdout)
		}
	}
}

func TestVMDestroy_PresenceForbidden(t *testing.T) {
	// A 403 on the config read: the token cannot see the VM. In use cluster-wide
	// it is B5-elsewhere (invisible), never a dispatch; free with an OK destroy
	// it is gone — and the pool is NEVER read (the harness proof's pool leg
	// 403s once PVE removes the guest's pool membership).
	e := newDEnv(t, func(s *pvefake.VMREST) {
		s.ConfigStatus, s.NextIDFree, s.Reflect = 403, false, false
		s.PoolStatus = 403
		s.Tasks = []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}
	})
	r := e.runYes()
	want(t, r, 4, "refused", "B5-elsewhere")
	if e.deletes() != 0 || e.stops() != 0 {
		t.Errorf("dispatched against an invisible VM: %q", e.s.Requests())
	}
	// The 403 is what makes it "present and invisible" in the wording; without
	// it (a plain missing config) the report must NOT claim invisibility.
	if !strings.Contains(r.str("observed"), "cannot see it") {
		t.Errorf("a 403 on the config read must be reported as invisible: %s", r.stdout)
	}
	plain := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.NextIDFree = false }).runYes()
	if strings.Contains(plain.str("observed"), "cannot see it") {
		t.Errorf("a missing config is not an invisible one: %s", plain.stdout)
	}
	e = newDEnv(t, func(s *pvefake.VMREST) {
		s.ConfigStatus, s.Reflect, s.PoolStatus = 403, false, 403
		s.Tasks = []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}
	})
	r = e.runYes()
	want(t, r, 0, "ok", "B5-gone")
	if e.count("GET /api2/json/pools/") != 0 {
		t.Errorf("the pool was read: %q", e.s.Requests())
	}
}

func TestVMDestroy_B6_AFailedPriorDestroyIsANewAttempt(t *testing.T) {
	for _, tc := range []struct {
		end  string
		code int
		out  string
	}{{"OK", 0, "ok"}, {"ERROR: x", 1, "failed"}, {"", 3, "unknown"}} {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			s.Tasks = []pvefake.TaskRow{dRow("qmdestroy", 3, "ERROR: earlier")}
			s.ReflectEnd = tc.end
		})
		if tc.end == "" {
			t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 100*time.Millisecond))
		}
		r := e.runYes()
		if r.code != tc.code || r.str("outcome") != tc.out {
			t.Fatalf("end %q: exit %d %s", tc.end, r.code, r.stdout)
		}
		if e.deletes() != 1 || r.str("prior_upid") != dUPID("qmdestroy", 3) || r.str("prior_exitstatus") != "ERROR: earlier" {
			t.Errorf("end %q: deletes %d, %s", tc.end, e.deletes(), r.stdout)
		}
		// One notice line; B1's empty-stderr assertion is NOT this one.
		if n := strings.Count(r.stderr, "a prior destroy"); n != 1 || !strings.Contains(r.stderr, "this is a new attempt") {
			t.Errorf("end %q: stderr %q", tc.end, r.stderr)
		}
	}
}

// ---------------------------------------------------------------- B10

func TestVMDestroy_B10_Refusals(t *testing.T) {
	big := make([]pvefake.TaskRow, 2000)
	for i := range big {
		big[i] = pvefake.TaskRow{UPID: dUPID("qmconfig", 100+i), Type: "qmconfig", ID: strconv.Itoa(dVMID), StartTime: int64(100 + i), Status: "OK", EndTime: int64(101 + i), Saved: true, Node: dNode, User: "root@pam"}
	}
	for _, tc := range []struct {
		name string
		mut  func(*pvefake.VMREST)
		read string
		priv string
	}{
		{"probe 403", func(s *pvefake.VMREST) { s.NodeStatus = 403 }, "/nodes/" + dNode + "/status", "Sys.Audit on /nodes/" + dNode},
		{"probe 500", func(s *pvefake.VMREST) { s.NodeStatus = 500 }, "/nodes/" + dNode + "/status", ""},
		{"task list 500", func(s *pvefake.VMREST) { s.TasksStatus = 500 }, "task list", ""},
		{"a full page", func(s *pvefake.VMREST) { s.Tasks = big }, "task list", ""},
		{"status gate", func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /nodes/" + dNode + "/qemu/691/status/current": {{Code: 500, Message: "boom"}}}
		}, "status gate", ""},
	} {
		e := newDEnv(t, tc.mut)
		r := e.runYes()
		want(t, r, 4, "refused", "B10")
		refusalShape(t, r)
		if !strings.Contains(r.str("read"), tc.read) || r.str("privilege") != tc.priv {
			t.Errorf("%s: %s", tc.name, r.stdout)
		}
		if e.deletes() != 0 || e.stops() != 0 {
			t.Errorf("%s: dispatched: %q", tc.name, e.s.Requests())
		}
	}
}

func TestVMDestroy_B10_ARetryNeedsSysAuditOnRoot(t *testing.T) {
	e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.ClusterNodesStatus = 403 })
	r := e.runYes()
	want(t, r, 4, "refused", "B10")
	refusalShape(t, r)
	if r.str("privilege") != "Sys.Audit on /" || e.deletes() != 0 {
		t.Errorf("%s", r.stdout)
	}
}

func TestVMDestroy_B10_PVEUnreachable(t *testing.T) {
	e := newDEnv(t, nil)
	e.srv.Close()
	r := e.runYes()
	want(t, r, 4, "refused", "B10")
	refusalShape(t, r)
	if e.deletes() != 0 || e.stops() != 0 {
		t.Error("dispatched with PVE unreachable")
	}
}

func TestVMDestroy_B10_TheLockIsHeldElsewhere(t *testing.T) {
	e := newDEnv(t, nil)
	holdLock(t, e.roster, lock.ObjectKey{TargetID: dTarget, Kind: "vm", ID: strconv.Itoa(dVMID)})
	r := e.runYes("--lock-wait", "50ms")
	want(t, r, 4, "refused", "B10")
	refusalShape(t, r)
	if r.str("read") != "lock" || len(e.s.Requests()) != 0 {
		t.Errorf("%s, requests %q", r.stdout, e.s.Requests())
	}
}

// The lock precedes ANY network contact, and a dial that fails is not a reason
// to lock afterwards: with the listener closed the refusal is the PROBE's
// (B10, the probe path named), not the lock's timeout.
func TestVMDestroy_TheLockPrecedesTheNetwork_VerbLevel(t *testing.T) {
	e := newDEnv(t, nil)
	holdLock(t, e.roster, lock.ObjectKey{TargetID: dTarget, Kind: "vm", ID: strconv.Itoa(dVMID)})
	e.srv.Close() // a verb that dialed first would refuse on the PROBE
	r := e.runYes("--lock-wait", "50ms")
	want(t, r, 4, "refused", "B10")
	if r.str("read") != "lock" {
		t.Errorf("the lock was not the first gate: %s", r.stdout)
	}
	// And with the lock free and PVE refusing the dial, the refusal is the probe's.
	e2 := newDEnv(t, nil)
	e2.srv.Close()
	r2 := e2.runYes()
	want(t, r2, 4, "refused", "B10")
	if !strings.Contains(r2.str("read"), "/status") || strings.Contains(r2.str("error"), "timed out waiting for the lock") {
		t.Errorf("%s", r2.stdout)
	}
}

func TestVMDestroy_LockWaitBoundsTheLockNotTheTask(t *testing.T) {
	statusKey := "GET /nodes/" + dNode + "/tasks/" + dUPID("qmdestroy", 1) + "/status"
	body := func(status, exit string) string {
		x := ""
		if exit != "" {
			x = `,"exitstatus":"` + exit + `"`
		}
		return fmt.Sprintf(`{"upid":%q,"type":"qmdestroy","id":"%d","node":%q,"user":"root@pam","status":%q%s}`, dUPID("qmdestroy", 1), dVMID, dNode, status, x)
	}
	replies := make([]pvefake.Reply, 0, 80)
	for i := 0; i < 60; i++ {
		replies = append(replies, pvefake.Reply{Body: body("running", "")})
	}
	replies = append(replies, pvefake.Reply{Body: body("stopped", "OK")})
	e := newDEnv(t, func(s *pvefake.VMREST) { s.Script = map[string][]pvefake.Reply{statusKey: replies} })
	r := e.runYes("--lock-wait", "1ms")
	want(t, r, 0, "ok", "B1")
}

func TestVMDestroy_B8_TheSecondInvocationAddsNoRequestWhileTheLockIsHeld(t *testing.T) {
	e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" })
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 600*time.Millisecond))
	done := make(chan dRes, 1)
	go func() { done <- e.runYes() }()
	deadline := time.Now().Add(10 * time.Second)
	for e.deletes() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first invocation never dispatched")
		}
		time.Sleep(2 * time.Millisecond)
	}
	probes := e.count("GET /api2/json/nodes/" + dNode + "/status")
	r := e.runYes("--lock-wait", "50ms")
	want(t, r, 4, "refused", "B10")
	if r.str("read") != "lock" || e.deletes() != 1 || e.count("GET /api2/json/nodes/"+dNode+"/status") != probes {
		t.Errorf("the second invocation did not serialise: %s, deletes %d", r.stdout, e.deletes())
	}
	first := <-done
	want(t, first, 3, "unknown", "B2")
	// Once the first is done the second falls into B4 (never a lock error).
	again := e.runYes()
	want(t, again, 4, "refused", "B4")
}

// ---------------------------------------------------------------- stop (C1)

func TestVMDestroy_Stop_ClassifiedOnTheErrorNotThePhase(t *testing.T) {
	running := func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}` }
	stopKey := "POST /nodes/" + dNode + "/qemu/691/status/stop"
	// A stop PVE ANSWERED with an error: the known-failure class.
	for _, code := range []int{400, 403, 500} {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			running(s)
			s.Script = map[string][]pvefake.Reply{stopKey: {{Code: code, Message: "stop refused"}}}
		})
		r := e.runYes()
		want(t, r, 1, "failed", "stop-failed")
		if r.str("reason") != "stop-failed" || e.deletes() != 0 || e.stops() != 1 {
			t.Errorf("stop %d: %s, deletes %d stops %d", code, r.stdout, e.deletes(), e.stops())
		}
	}
	// No definite answer: unknown, no stop_upid, 0 DELETE, exit 3 (not 1).
	for name, reply := range map[string]pvefake.Reply{
		"502": {Code: 502, Message: "bad gateway"}, "504": {Code: 504, Message: "x"}, "595": {Code: 595, Message: "x"},
		"200 without a UPID": {Body: "null"},
	} {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			running(s)
			s.Script = map[string][]pvefake.Reply{stopKey: {reply}}
		})
		r := e.runYes()
		want(t, r, 3, "unknown", "stop-unknown")
		if r.str("reason") != "stop-unknown" || r.has("stop_upid") || r.has("upid") || e.deletes() != 0 {
			t.Errorf("%s: %s, deletes %d", name, r.stdout, e.deletes())
		}
	}
}

func TestVMDestroy_Stop_NoAnswerIsUnknown_AndNeverDestroys(t *testing.T) {
	e := newDEnvFault(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}` },
		func(r *http.Request) bool {
			return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/status/stop")
		})
	r := e.runYes()
	// The fault must have ARRIVED (instrument #7: a transport fault test can
	// pass with the fault never delivered); GetBody is nil on this client's
	// request, so a started empty-body request may be retried on a reused
	// connection — the count is reported, not assumed to be 1.
	if e.faults.Load() < 1 {
		t.Fatal("the stop request never reached the fault")
	}
	want(t, r, 3, "unknown", "stop-unknown")
	if r.has("stop_upid") || e.deletes() != 0 {
		t.Errorf("%s, deletes %d", r.stdout, e.deletes())
	}
	t.Logf("stop POST attempts that hit the fault: %d", e.faults.Load())
}

func TestVMDestroy_Stop_TaskOutcomes(t *testing.T) {
	// A stop task that runs past WaitForTask's own deadline with the COMMAND
	// context still live is stop-unknown (not "interrupted"), carries stop_upid,
	// and never reaches the DELETE.
	e := newDEnv(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}`; s.ReflectEnd = "" })
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 120*time.Millisecond))
	r := e.runYes()
	want(t, r, 3, "unknown", "stop-unknown")
	if r.str("reason") != "stop-unknown" || r.str("stop_upid") != dUPID("qmstop", 2) || e.deletes() != 0 {
		t.Errorf("%s, deletes %d", r.stdout, e.deletes())
	}
	// A stop task that ends with an error: stop-failed.
	e = newDEnv(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}`; s.ReflectEnd = "ERROR: stop failed" })
	r = e.runYes()
	want(t, r, 1, "failed", "stop-failed")
	if r.str("stop_upid") != dUPID("qmstop", 2) || e.deletes() != 0 {
		t.Errorf("%s, deletes %d", r.stdout, e.deletes())
	}
}

// ---------------------------------------------------------------- dispatch (C2)

func TestVMDestroy_Dispatch_FailureClasses(t *testing.T) {
	// PVE answered: nothing was destroyed, a known failure.
	for _, code := range []int{400, 500} {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.DestroyCode = code })
		r := e.runYes()
		want(t, r, 1, "failed", "dispatch-refused")
		if r.str("reason") != "dispatch-refused" || r.has("upid") || r.has("privilege") {
			t.Errorf("DELETE %d: %s", code, r.stdout)
		}
	}
	// A 403 names VM.Allocate and quotes PVE's OWN sentence — never an
	// invented path ("VM.Allocate on /vms/<vmid>" is PVE's to say, not ours);
	// a 401 names NO privilege (a bad token is not a missing privilege).
	delKey403 := "DELETE /nodes/" + dNode + "/qemu/691"
	pveSentence := "Permission check failed (/vms/691, VM.Allocate)"
	e403 := newDEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{delKey403: {{Code: 403, Message: pveSentence}}}
	})
	r403 := e403.runYes()
	want(t, r403, 1, "failed", "dispatch-refused")
	if r403.str("privilege") != "VM.Allocate" || !strings.Contains(r403.str("observed"), `"`+pveSentence+`"`) || strings.Contains(r403.stdout, "VM.Allocate on /vms") || r403.has("upid") {
		t.Errorf("DELETE 403: %s", r403.stdout)
	}
	e401 := newDEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{delKey403: {{Code: 401, Message: "no ticket"}}}
	})
	r401 := e401.runYes()
	want(t, r401, 1, "failed", "dispatch-refused")
	if r401.has("privilege") || strings.Contains(r401.stdout, "VM.Allocate") || !strings.Contains(r401.str("observed"), "401") {
		t.Errorf("DELETE 401 must name no privilege: %s", r401.stdout)
	}
	// A 2xx without a UPID, and no answer: a worker may exist. unknown, no upid.
	delKey := "DELETE /nodes/" + dNode + "/qemu/691"
	e := newDEnv(t, func(s *pvefake.VMREST) { s.Script = map[string][]pvefake.Reply{delKey: {{Body: "null"}}} })
	r := e.runYes()
	want(t, r, 3, "unknown", "dispatch-unconfirmed")
	if r.str("reason") != "dispatch-unconfirmed" || r.has("upid") {
		t.Errorf("200 null: %s", r.stdout)
	}
	e = newDEnvFault(t, nil, func(r *http.Request) bool { return r.Method == http.MethodDelete })
	r = e.runYes()
	if e.faults.Load() < 1 {
		t.Fatal("the DELETE never reached the fault")
	}
	want(t, r, 3, "unknown", "dispatch-unconfirmed")
	if r.has("upid") || e.deletes() != 0 {
		t.Errorf("no answer: %s", r.stdout)
	}
	t.Logf("DELETE attempts that hit the fault: %d", e.faults.Load())
	// A gateway status is not an answer either.
	e = newDEnv(t, func(s *pvefake.VMREST) { s.Script = map[string][]pvefake.Reply{delKey: {{Code: 502, Message: "x"}}} })
	r = e.runYes()
	want(t, r, 3, "unknown", "dispatch-unconfirmed")
}

// ---------------------------------------------------------------- gone-proof

func TestVMDestroy_PostDispatchProofFailuresAreUnknown_NeverRefused(t *testing.T) {
	// The destroy ENDED OK, but PVE still says the vmid is in use / cannot say:
	// this invocation dispatched, so the answer is 3 and keeps the identity.
	for name, mut := range map[string]func(*pvefake.VMREST){
		"in use": func(s *pvefake.VMREST) { s.NextIDFree = false },
		"unverified": func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{strconv.Itoa(dVMID): {Code: 500, Body: `{"message":"boom"}`}}
		},
	} {
		e := newDEnv(t, mut)
		r := e.runYes()
		want(t, r, 3, "unknown", "B1-unproven")
		if r.str("reason") != "proof-unestablished" || r.str("upid") != dUPID("qmdestroy", 1) {
			t.Errorf("%s: %s", name, r.stdout)
		}
	}
	// And on a RETRY the same free-proof failures are refusals (4).
	for name, mut := range map[string]func(*pvefake.VMREST){
		"in use": func(s *pvefake.VMREST) { s.NextIDFree = false },
		"unverified": func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{strconv.Itoa(dVMID): {Code: 500, Body: `{"message":"boom"}`}}
		},
	} {
		e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, mut)
		r := e.runYes()
		want(t, r, 4, "refused", "")
		refusalShape(t, r)
		if e.deletes() != 0 {
			t.Errorf("%s: dispatched on a retry", name)
		}
	}
}

// R1.6 at the verb level: a stalled gone-proof read never hangs the verb, and
// its budget expiry is never reported as an interrupt.
func TestVMDestroy_VerdictBudget_NeitherHangsNorMasqueradesAsAnInterrupt(t *testing.T) {
	// Driven through runVMDestroy directly with a 1ns budget, because the
	// production constant is 120s. Post-dispatch the verdict reads cannot be
	// made: unknown (3). On a retry: a B10 refusal (4).
	for _, retry := range []bool{false, true} {
		var env *dEnv
		if retry {
			env = retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, nil)
		} else {
			env = newDEnv(t, nil)
		}
		res := runWithBudget(t, env, 1*time.Nanosecond)
		if res.rep.Reason == reasonInterrupted || res.rep.Situation == "B9" {
			t.Errorf("retry=%v: a budget expiry was reported as an interrupt: %+v", retry, res.rep)
		}
		if retry {
			if res.rep.Outcome != outcomeRefused || res.rep.Situation != "B10" {
				t.Errorf("retry: want refused B10, got %+v", res.rep)
			}
		} else {
			if res.rep.Outcome != outcomeUnknown || res.rep.Reason != reasonProofUnestablished {
				t.Errorf("post-dispatch: want unknown proof-unestablished, got %+v", res.rep)
			}
		}
	}
}

// runWithBudget runs the flow in-process with a verdict budget of d.
func runWithBudget(t *testing.T, e *dEnv, d time.Duration) destroyResult {
	t.Helper()
	rp := mustRoutedClient(t, e)
	defer func() { _ = rp.Close() }()
	var errOut strings.Builder
	return runVMDestroy(t.Context(), destroyDeps{client: rp, target: dTarget, stderr: &errOut, verdictBudget: d}, destroyInput{vmid: dVMID, yes: true})
}

// ---------------------------------------------------------------- output

func parseKV(t *testing.T, out string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("not a kv line: %q", line)
		}
		if strings.HasPrefix(k, `"`) {
			_ = json.Unmarshal([]byte(k), &k)
		}
		if strings.HasPrefix(v, `"`) {
			_ = json.Unmarshal([]byte(v), &v)
		}
		m[k] = v
	}
	return m
}

func flatten(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		switch x := v.(type) {
		case string:
			out[k] = x
		case float64:
			out[k] = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(x)
		}
	}
	return out
}

func TestVMDestroy_KVAndJSONAgree_ForEveryOutcome(t *testing.T) {
	scenarios := map[string]func() *dEnv{
		"ok":      func() *dEnv { return newDEnv(t, nil) },
		"failed":  func() *dEnv { return newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "ERROR: x" }) },
		"unknown": func() *dEnv { return newDEnv(t, func(s *pvefake.VMREST) { s.NextIDFree = false }) },
		"refused": func() *dEnv { return newDEnv(t, nil) },
	}
	for outcome, mk := range scenarios {
		var kvOut, jsOut string
		for _, format := range []string{"kv", "json"} {
			e := mk()
			args := []string{"vm", "destroy", "--roster", e.roster, "-o", format, dTarget, strconv.Itoa(dVMID)}
			if outcome != "refused" {
				args = append([]string{args[0], args[1], "--yes"}, args[2:]...)
			}
			_, out, _ := runRootArgs(args...)
			if format == "kv" {
				kvOut = out
			} else {
				jsOut = out
			}
		}
		var jm map[string]any
		if err := json.Unmarshal([]byte(jsOut), &jm); err != nil {
			t.Fatalf("%s: %v\n%s", outcome, err, jsOut)
		}
		kv, js := parseKV(t, kvOut), flatten(jm)
		if js["outcome"] != outcome {
			t.Errorf("%s: outcome %q", outcome, js["outcome"])
		}
		if len(kv) != len(js) {
			t.Errorf("%s: kv has %d fields, json %d:\nkv %v\njson %v", outcome, len(kv), len(js), kv, js)
		}
		for k, v := range js {
			if kv[k] != v {
				t.Errorf("%s: %s: kv %q, json %q", outcome, k, kv[k], v)
			}
		}
		for k, v := range jm {
			if v == nil || v == "" {
				t.Errorf("%s: %s is present but empty/null in json", outcome, k)
			}
		}
		if outcome == "refused" && (js["upid"] != "" || js["reason"] != "") {
			t.Errorf("a refusal carries upid/reason: %v", js)
		}
	}
}

func TestVMDestroy_ValuesAreQuotedNotAssembled(t *testing.T) {
	// A UPID (and a PVE message) with a newline and an '=' round-trips through
	// the renderer unchanged and cannot forge a line.
	evil := "UPID:x\nforged=1"
	e := newDEnv(t, func(s *pvefake.VMREST) { s.DestroyUPID = evil })
	code, out, _ := runRootArgs("vm", "destroy", "--roster", e.roster, "--yes", "-o", "kv", dTarget, strconv.Itoa(dVMID))
	if code != 3 {
		t.Fatalf("exit %d, %s", code, out)
	}
	if strings.Contains(out, "\nforged=1") {
		t.Fatalf("a crafted value forged a kv line: %q", out)
	}
	if got := parseKV(t, out)["upid"]; got != evil {
		t.Errorf("upid round-tripped as %q, want %q", got, evil)
	}
}

func TestVMDestroy_PVETextIsBoundedOnStdout(t *testing.T) {
	huge := strings.Repeat("A", 6000)
	e := newDEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{"DELETE /nodes/" + dNode + "/qemu/691": {{Code: 500, Message: huge}}}
	})
	r := e.runYes()
	want(t, r, 1, "failed", "dispatch-refused")
	if n := len(r.str("error")); n == 0 || n > 4096+64 || !strings.Contains(r.str("error"), "bytes elided") {
		t.Errorf("stdout error field is %d bytes: not bounded", n)
	}
	if len(r.stdout) > 3*4096 {
		t.Errorf("stdout is %d bytes", len(r.stdout))
	}
	// A refusal's text comes from the determination's own strings (not from
	// errText), so only the struct-field bound stands between a huge PVE
	// answer and stdout: a probe that fails with a 6 KiB body.
	e = newDEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{"GET /nodes/" + dNode + "/status": {{Code: 500, Message: huge}}}
	})
	r = e.runYes()
	want(t, r, 4, "refused", "B10")
	if n := len(r.str("error")); n == 0 || n > 4096+64 {
		t.Errorf("a refusal's error field is %d bytes on stdout: not bounded", n)
	}
}

func TestVMDestroy_ExitStatusesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, e := range map[string]*dEnv{
		"ok":      newDEnv(t, nil),
		"failed":  newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "ERROR: x" }),
		"unknown": newDEnv(t, func(s *pvefake.VMREST) { s.NextIDFree = false }),
		"refused": newDEnv(t, func(s *pvefake.VMREST) { s.NodeStatus = 403 }),
	} {
		r := e.runYes()
		if other, dup := seen[r.code]; dup {
			t.Errorf("%s and %s share exit %d", name, other, r.code)
		}
		seen[r.code] = name
		if r.code == 130 || r.code == 143 {
			t.Errorf("%s exits as a signal: %d", name, r.code)
		}
	}
	if want := (map[int]string{0: "ok", 1: "failed", 3: "unknown", 4: "refused"}); fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("statuses %v, want %v", seen, want)
	}
}

// mustRoutedClient builds the same client the verb's RunE does, for the
// in-process budget test.
func mustRoutedClient(t *testing.T, e *dEnv) *pve.RoutedClient {
	t.Helper()
	pass, err := roster.ResolvePassphraseContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r, err := roster.Load(e.roster)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := pve.NewRoutedClient(r.Find(dTarget), pass)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// dTaskStatus is the per-task status endpoint's answer for one of this VM's tasks.
func dTaskStatus(upid, kind, status, exit string) string {
	x := ""
	if exit != "" {
		x = `,"exitstatus":"` + exit + `"`
	}
	return fmt.Sprintf(`{"upid":%q,"type":%q,"id":"%d","node":%q,"user":"root@pam","status":%q%s}`, upid, kind, dVMID, dNode, status, x)
}

// I1f, meaningful ONLY against a fixture that REFLECTS the verb's own dispatch:
// here the list keeps the reflected qmstop and qmdestroy rows NON-terminal
// (ReflectEnd empty) while the per-task status says they ended OK, so a verb
// that re-ran its determination after its own stop would find its own running
// qmstop and refuse itself. The control: a SECOND run, against that same
// state, IS refused (the reflected rows are what the determination sees).
func TestVMDestroy_I1f_TheVerbNeverRefusesItsOwnStop(t *testing.T) {
	stopU, delU := dUPID("qmstop", 2), dUPID("qmdestroy", 1)
	e := newDEnv(t, func(s *pvefake.VMREST) {
		s.VMStatus, s.ReflectEnd = `{"status":"running"}`, ""
		s.Script = map[string][]pvefake.Reply{
			"GET /nodes/" + dNode + "/tasks/" + stopU + "/status": {{Body: dTaskStatus(stopU, "qmstop", "stopped", "OK")}},
			"GET /nodes/" + dNode + "/tasks/" + delU + "/status":  {{Body: dTaskStatus(delU, "qmdestroy", "stopped", "OK")}},
		}
	})
	r := e.runYes()
	want(t, r, 0, "ok", "B1")
	if e.stops() != 1 || e.deletes() != 1 {
		t.Fatalf("stops %d deletes %d", e.stops(), e.deletes())
	}
	r2 := e.runYes()
	want(t, r2, 4, "refused", "")
	if e.deletes() != 1 {
		t.Errorf("the second run dispatched: %d", e.deletes())
	}
}
