package pvefake

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// The FIXTURE's own fidelity suite. U3 ships no production code, so these are
// the only rows it owns — and they exist so that a mutation of the fixture
// (ignoring a parameter, softening a trap, losing reflection) is observed RED
// here, in this package, rather than silently making a consumer's test green
// somewhere else.

func vmrestFixture(t *testing.T) (*VMREST, string) {
	t.Helper()
	s := NewVMREST(t, "n1")
	s.Tasks = []TaskRow{
		{UPID: "UPID:n1:A:A:A:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 100, Status: "running"},
		{UPID: "UPID:n1:B:B:B:qmcreate:690:root@pam:", Type: "qmcreate", ID: "690", StartTime: 90, Status: "stopped", EndTime: 95},
		{UPID: "UPID:n1:C:C:C:qmstart:691:root@pam:", Type: "qmstart", ID: "691", StartTime: 80, Status: "stopped", EndTime: 85},
	}
	srv := s.Server()
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func getRows(t *testing.T, url string) (int, []map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var env struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(b, &env)
	return resp.StatusCode, env.Data
}

// F1: limit is honoured, and limit=0 reproduces PVE's trap — HTTP 200 with
// ZERO rows. A fixture that read 0 as "no limit" would let a consumer built
// on limit=0 answer "nothing in flight" unconditionally and stay green.
func TestVMREST_F1_LimitIsHonouredAndZeroMeansNothing(t *testing.T) {
	_, u := vmrestFixture(t)
	for _, tc := range []struct{ limit, want int }{{0, 0}, {1, 1}, {2, 2}, {99, 3}} {
		code, rows := getRows(t, fmt.Sprintf("%s/api2/json/nodes/n1/tasks?source=all&limit=%d", u, tc.limit))
		if code != 200 || len(rows) != tc.want {
			t.Errorf("limit=%d: got HTTP %d, %d rows; want 200, %d", tc.limit, code, len(rows), tc.want)
		}
	}
	// Truncation: a page of exactly limit rows is what a consumer must not
	// read as a negative answer, so the fixture has to be able to serve one.
	if _, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&limit=3"); len(rows) != 3 {
		t.Errorf("a full page of 3: %d rows, want 3", len(rows))
	}
}

// F2: source partitions the log — active and archive are genuinely different
// sets, as measured on a live node at one moment.
func TestVMREST_F2_SourcePartitionsTheSet(t *testing.T) {
	_, u := vmrestFixture(t)
	for _, tc := range []struct {
		source string
		want   int
	}{{"all", 3}, {"active", 1}, {"archive", 2}} {
		code, rows := getRows(t, fmt.Sprintf("%s/api2/json/nodes/n1/tasks?source=%s&limit=99", u, tc.source))
		if code != 200 || len(rows) != tc.want {
			t.Errorf("source=%s: got HTTP %d, %d rows; want 200, %d", tc.source, code, len(rows), tc.want)
		}
	}
	// Anti-vacuity: counts that fail to diverge are the lie. Equal counts
	// here mean the parameter was accepted and ignored.
	_, all := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&limit=99")
	_, act := getRows(t, u+"/api2/json/nodes/n1/tasks?source=active&limit=99")
	if len(all) == len(act) {
		t.Errorf("source=all and source=active returned the same count (%d): the parameter is not partitioning", len(all))
	}
}

// F3: vmid and typefilter are honoured.
func TestVMREST_F3_VmidAndTypefilter(t *testing.T) {
	_, u := vmrestFixture(t)
	if _, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&vmid=690&limit=99"); len(rows) != 2 {
		t.Errorf("vmid=690: %d rows, want 2", len(rows))
	}
	if _, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&vmid=99999&limit=99"); len(rows) != 0 {
		t.Errorf("vmid=99999: %d rows, want 0", len(rows))
	}
	if _, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&typefilter=qmdestroy&limit=99"); len(rows) != 1 {
		t.Errorf("typefilter=qmdestroy: %d rows, want 1", len(rows))
	}
	// since is honoured too, so a non-zero since leaking into a query is
	// VISIBLE as missing rows rather than silently harmless.
	if _, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&vmid=690&limit=99&since=95"); len(rows) != 1 {
		t.Errorf("since=95: %d rows, want 1 (the starttime-90 row is older)", len(rows))
	}
}

// F4: what it does not implement, it REFUSES, with PVE's measured shapes. A
// fixture that accepted statusfilter=running would let a consumer ship a
// query real PVE rejects with a 400, and every test would pass.
func TestVMREST_F4_RefusesWhatPVERefuses(t *testing.T) {
	_, u := vmrestFixture(t)
	for _, tc := range []struct{ query, wantIn string }{
		{"running=1", "property is not defined in schema"},
		{"zzznotaparam=1", "property is not defined in schema"},
		{"statusfilter=running", "property is not defined in schema"},
		{"limit=-1", "value must have a minimum value of 0"},
		{"source=bogus", "invalid format"},
	} {
		resp, err := http.Get(u + "/api2/json/nodes/n1/tasks?" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 || !strings.Contains(string(b), tc.wantIn) {
			t.Errorf("%s: HTTP %d %s; want 400 containing %q", tc.query, resp.StatusCode, b, tc.wantIn)
		}
	}
}

// F5: the 403 ASYMMETRY, pinned in BOTH directions. A fixture that cannot
// 403 the probe while the task list still 200s with rows cannot drive the
// visibility precondition at all; a fixture that ignores its scripted 403 and
// always answers 200 is KINDER than PVE and leaves that row green against
// nothing.
func TestVMREST_F5_ProbeMay403WhileTheTaskListStill200s(t *testing.T) {
	s, u := vmrestFixture(t)

	// Control first: unscripted, the probe is 200 — so the 403 below is this
	// fixture obeying NodeStatus, not a constant.
	if code, _ := getRows(t, u+"/api2/json/nodes/n1/status"); code != 200 {
		t.Fatalf("unscripted probe: HTTP %d, want 200", code)
	}

	s.NodeStatus = http.StatusForbidden
	resp, err := http.Get(u + "/api2/json/nodes/n1/status")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("probe: HTTP %d, want 403 — the fixture ignored NodeStatus and is kinder than PVE", resp.StatusCode)
	}
	if !strings.Contains(string(b), "Sys.Audit") {
		t.Errorf("probe body %s does not name Sys.Audit", b)
	}
	code, rows := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&limit=99")
	if code != 200 || len(rows) == 0 {
		t.Errorf("task list under a 403 probe: HTTP %d, %d rows; want 200 and a non-empty list", code, len(rows))
	}
}

// F6: the recorder holds a READ's parameters to account, with the weaker
// accessors as the control that they genuinely cannot.
func TestVMREST_F6_RequestsRecordsTheQueryString(t *testing.T) {
	s, u := vmrestFixture(t)
	getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&vmid=690&limit=200&since=0")
	want := "GET /api2/json/nodes/n1/tasks ?limit=200&since=0&source=all&vmid=690"
	if !slices.Contains(s.Requests(), want) {
		t.Errorf("Requests() = %q\nwant it to contain %q", s.Requests(), want)
	}
	for _, h := range s.Hits() {
		if strings.Contains(h, "source=all") {
			t.Errorf("Hits() unexpectedly carries the query: %q", h)
		}
	}
	if len(s.Writes()) != 0 {
		t.Errorf("Writes() = %q, want empty: a GET is not a write", s.Writes())
	}
	// Hits() and Writes() still behave as four other packages expect: a
	// write is recorded by both, with its query.
	req, _ := http.NewRequest(http.MethodDelete, u+"/api2/json/nodes/n1/qemu/690?purge=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if w := s.Writes(); len(w) != 1 || w[0] != "DELETE /api2/json/nodes/n1/qemu/690 ?purge=1" {
		t.Errorf("Writes() = %q, want the one DELETE with ?purge=1", w)
	}
}

// F7: DISPATCH REFLECTION. A mutation this fixture accepts appears in a
// subsequent ACTIVE read as a NON-TERMINAL row of the matching type, the way
// PVE's node-local index does. Without it, a re-run determination never sees
// the mutation this process itself issued, and a "no self-collision"
// criterion passes vacuously.
//
// Both halves are asserted, because a reflection that is PRESENT but marks
// the row terminal is just as useless as none at all: the row must lack
// endtime, must be visible under source=active, and must NOT appear under
// source=archive.
func TestVMREST_F7_DispatchIsReflectedIntoTheTaskList(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, wantType string
	}{
		{"stop", http.MethodPost, "/api2/json/nodes/n1/qemu/690/status/stop", "qmstop"},
		{"destroy", http.MethodDelete, "/api2/json/nodes/n1/qemu/690", "qmdestroy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewVMREST(t, "n1")
			s.Reflect = true
			srv := s.Server()
			defer srv.Close()
			active := srv.URL + "/api2/json/nodes/n1/tasks?source=active&vmid=690&limit=99"

			if _, before := getRows(t, active); len(before) != 0 {
				t.Fatalf("before: %d active rows, want 0 — the row found below would not be the dispatch's", len(before))
			}

			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			_, after := getRows(t, active)
			if len(after) != 1 {
				t.Fatalf("after the %s: %d active rows, want 1 — the dispatch was not reflected, or was reflected as TERMINAL; either way a re-run determination cannot see it and a self-collision criterion cannot fail", tc.name, len(after))
			}
			row := after[0]
			if row["type"] != tc.wantType {
				t.Errorf("reflected row type = %v, want %q", row["type"], tc.wantType)
			}
			if row["id"] != "690" {
				t.Errorf("reflected row id = %v, want \"690\"", row["id"])
			}
			if _, ok := row["endtime"]; ok {
				t.Errorf("reflected row carries endtime %v: it must be NON-terminal", row["endtime"])
			}
			if _, arch := getRows(t, srv.URL+"/api2/json/nodes/n1/tasks?source=archive&vmid=690&limit=99"); len(arch) != 0 {
				t.Errorf("source=archive returned %d rows: a non-terminal reflection leaked into the archive half", len(arch))
			}
			// The per-task read agrees with the collection: one fixture, one
			// answer, so a consumer cannot be told two different stories.
			upid, _ := row["upid"].(string)
			resp2, err := http.Get(srv.URL + "/api2/json/nodes/n1/tasks/" + upid + "/status")
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			if !strings.Contains(string(b), `"type":"`+tc.wantType+`"`) {
				t.Errorf("per-task status for %s = %s, want the same %s row", upid, b, tc.wantType)
			}
		})
	}
}

// F8: reflection is OPT-IN and off by default, so a fixture that never asks
// for it keeps the static behaviour every other case depends on.
func TestVMREST_F8_ReflectionIsOptIn(t *testing.T) {
	s := NewVMREST(t, "n1")
	srv := s.Server()
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api2/json/nodes/n1/qemu/690", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, rows := getRows(t, srv.URL+"/api2/json/nodes/n1/tasks?source=active&vmid=690&limit=99"); len(rows) != 0 {
		t.Errorf("Reflect=false: %d active rows after a destroy, want 0", len(rows))
	}
}

// F9: the remaining scripted surfaces answer as specified — the free-proof in
// both directions, the placement fixture, the config 404, and the stall.
func TestVMREST_F9_TheOtherScriptedSurfaces(t *testing.T) {
	s, u := vmrestFixture(t)

	// nextid: taken is a 400 carrying the message in the BODY, because a
	// 500's body does not reach a *StatusError's Error() text.
	resp, err := http.Get(u + "/api2/json/cluster/nextid?vmid=690")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(string(b), "VM 690 already exists") {
		t.Errorf("nextid taken: HTTP %d %s; want 400 naming the vmid", resp.StatusCode, b)
	}
	s.NextIDFree = true
	resp, err = http.Get(u + "/api2/json/cluster/nextid?vmid=699")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"699"`) {
		t.Errorf("nextid free: HTTP %d %s; want 200 echoing the vmid", resp.StatusCode, b)
	}

	// placement: the ONLY way this server models another node.
	s.Resources = `[{"type":"qemu","vmid":690,"node":"n2"}]`
	if _, rows := getRows(t, u+"/api2/json/cluster/resources?type=vm"); len(rows) != 1 || rows[0]["node"] != "n2" {
		t.Errorf("placement: %v, want one qemu row on n2", rows)
	}

	// config: "" means a 404.
	resp, err = http.Get(u + "/api2/json/nodes/n1/qemu/690/config")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("config with VMConfig unset: HTTP %d, want 404", resp.StatusCode)
	}

	// the task collection can be refused independently of the probe.
	s.TasksStatus = http.StatusForbidden
	if code, _ := getRows(t, u+"/api2/json/nodes/n1/tasks?source=all&limit=9"); code != 403 {
		t.Errorf("TasksStatus=403: HTTP %d, want 403", code)
	}
	s.TasksStatus = 0

	// the stall aborts on the request's context rather than hanging.
	s.StallTasks = 30 * time.Second
	client := &http.Client{Timeout: 150 * time.Millisecond}
	start := time.Now()
	if _, err := client.Get(u + "/api2/json/nodes/n1/tasks?source=all&limit=9"); err == nil {
		t.Errorf("StallTasks: the request completed, want a client timeout")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("StallTasks took %s to abort: the stall is not watching the request context", d)
	}
}

// F10: the parameters COMPOSE in PVE's order — filter first, truncate second.
//
// F1–F9 each ask "does the fixture honour this parameter?". None asks "does it
// apply them in the right ORDER?", and a Chair break-test walked straight
// through that gap: moving the truncation above the filter loop left every one
// of them green while changing the answers the fixture gives.
//
// The two orderings are only distinguishable when MORE THAN `limit`
// non-matching rows precede a matching one, so each case below is built that
// way on purpose:
//
//	filter-then-limit (this fixture) -> the matching row comes back
//	limit-then-filter                -> an empty page, and the match is lost
//
// An assertion on the row count alone would be satisfied by either ordering on
// any other fixture, so the arrangement IS the test.
//
// 🔴 This pins a CHOICE, not a measured fact: the order is read from
// Tasks.pm:186-205 and is unverified against a live host. See the composition
// paragraph on serveTaskList. If a live check settles it the other way, this
// test changes with the handler — it is not evidence about PVE.
func TestVMREST_F10_FilterComposesBeforeLimit(t *testing.T) {
	for _, tc := range []struct {
		name, filter string
	}{
		{"typefilter", "typefilter=qmdestroy"},
		{"vmid", "vmid=690"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewVMREST(t, "n1")
			// Two non-matching rows FIRST, the match LAST, and limit=2 — so
			// limit-then-filter truncates the match away before the filter
			// can see it.
			s.Tasks = []TaskRow{
				{UPID: "u1", Type: "qmcreate", ID: "691", StartTime: 10, Status: "stopped", EndTime: 11},
				{UPID: "u2", Type: "qmstart", ID: "691", StartTime: 20, Status: "stopped", EndTime: 21},
				{UPID: "u3", Type: "qmdestroy", ID: "690", StartTime: 30, Status: "running"},
			}
			srv := s.Server()
			defer srv.Close()

			code, rows := getRows(t, fmt.Sprintf("%s/api2/json/nodes/n1/tasks?source=all&%s&limit=2", srv.URL, tc.filter))
			if code != 200 {
				t.Fatalf("HTTP %d, want 200", code)
			}
			if len(rows) != 1 {
				t.Fatalf("%s with limit=2 over 2 non-matching rows then the match: %d rows, want 1 — the truncation ran BEFORE the filter, which changes what this fixture tells a consumer (see serveTaskList's composition paragraph)", tc.filter, len(rows))
			}
			if rows[0]["upid"] != "u3" {
				t.Errorf("row = %v, want the matching row u3", rows[0])
			}

			// Anti-vacuity: the arrangement really does make the orderings
			// differ. Without the filter, limit=2 takes the first two rows —
			// neither of which is the match — so a fixture that truncated
			// first could only ever have returned those.
			_, unfiltered := getRows(t, srv.URL+"/api2/json/nodes/n1/tasks?source=all&limit=2")
			if len(unfiltered) != 2 {
				t.Fatalf("unfiltered limit=2: %d rows, want 2", len(unfiltered))
			}
			for _, r := range unfiltered {
				if r["upid"] == "u3" {
					t.Fatalf("the first two unfiltered rows already contain the match: this fixture cannot distinguish the two orderings, so F10 is vacuous")
				}
			}
		})
	}
}
