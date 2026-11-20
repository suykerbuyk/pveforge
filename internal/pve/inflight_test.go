package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// These tests call the determination DIRECTLY and assert its VERDICT.
//
// 🔴 None of them asserts "zero destroy requests". The determination never
// dispatches, so no request log of it could ever contain a DELETE, correct
// implementation or not — such an assertion would be green by construction and
// is the verb's (U6), not this unit's. What is asserted here is what the
// determination ANSWERS, because the answer is the only thing that stands
// between a caller and a second destroy.

const detNode = "n1"
const detVMID = 690

// detRow builds a fixture row for detVMID. saved false + endTime 0 is a running
// task; saved false + endTime > 0 is finished-but-unarchived; saved true is the
// archive.
func detRow(upid, typ string, start int64, status string, endTime int64, saved bool) pvefake.TaskRow {
	return pvefake.TaskRow{
		UPID: upid, Type: typ, ID: fmt.Sprint(detVMID), StartTime: start,
		Status: status, EndTime: endTime, Saved: saved, Node: detNode, User: "root@pam",
	}
}

func running(upid, typ string) pvefake.TaskRow { return detRow(upid, typ, 1000, "RUNNING", 0, false) }
func archived(upid, typ, status string, start int64) pvefake.TaskRow {
	return detRow(upid, typ, start, status, start+5, true)
}

// detServer serves rows from the scripted VM/task fixture and returns it with a
// client pointed at it.
func detServer(t *testing.T, rows ...pvefake.TaskRow) (*pvefake.VMREST, *Client) {
	t.Helper()
	s := pvefake.NewVMREST(t, detNode)
	s.Tasks = rows
	srv := s.Server()
	t.Cleanup(srv.Close)
	return s, detClient(t, srv.URL+"/api2/json")
}

func detClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{BaseURLOverride: base, TokenID: "root@pam!det", TokenSecret: "s"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func determineOn(c *Client) *InFlightDetermination {
	return c.DetermineDestroyInFlight(context.Background(), detNode, detVMID)
}

func mustProceed(t *testing.T, d *InFlightDetermination, what string) {
	t.Helper()
	if d == nil {
		t.Fatalf("%s: nil determination", what)
	}
	if !d.Proceed || d.Refusal != nil {
		t.Fatalf("%s: refused (%+v), want proceed", what, d.Refusal)
	}
}

func mustRefuse(t *testing.T, d *InFlightDetermination, what string, sit Situation) *InFlightRefusal {
	t.Helper()
	if d == nil {
		t.Fatalf("%s: nil determination", what)
	}
	if d.Proceed || d.Refusal == nil {
		t.Fatalf("%s: PROCEEDED (%+v), want a %s refusal — a false proceed", what, d, sit)
	}
	if d.Refusal.Situation != sit {
		t.Fatalf("%s: situation %s, want %s (%+v)", what, d.Refusal.Situation, sit, d.Refusal)
	}
	return d.Refusal
}

// refusalText is every string a refusal carries, for "must not say X" checks.
func refusalText(r *InFlightRefusal) string {
	return strings.Join([]string{string(r.Situation), r.Node, r.UPID, r.TaskType, r.Read, r.ReadErr, r.Privilege, r.Condition}, "\n")
}

// wantHazard is the hazardous set written out INDEPENDENTLY of the production
// map, from the spec (I1): the check and the thing checked must not be the
// same object.
var wantHazard = map[string]Situation{
	"qmdestroy": SituationDestroy,
	"qmigrate":  SituationInFlightOther, "hamigrate": SituationInFlightOther,
	"qmclone": SituationInFlightOther, "qmrestore": SituationInFlightOther,
	"qmstop": SituationStop, "qmshutdown": SituationStop,
}

func TestDetermine_HazardousSetIsExactlySeven(t *testing.T) {
	if len(wantHazard) != 7 {
		t.Fatalf("the test's own literal has %d entries, want 7", len(wantHazard))
	}
	if len(hazardousTypes) != len(wantHazard) {
		t.Errorf("production set has %d types, spec has %d: %v", len(hazardousTypes), len(wantHazard), hazardousTypes)
	}
	for typ, sit := range wantHazard {
		if got, ok := hazardousTypes[typ]; !ok || got != sit {
			t.Errorf("type %q: production maps to (%q, %v), spec says %q", typ, got, ok, sit)
		}
	}
	for typ := range hazardousTypes {
		if _, ok := wantHazard[typ]; !ok {
			t.Errorf("production set holds %q, which the spec does not (qmreset, qmreboot and qmmove must NOT be here)", typ)
		}
	}
}

// U4-1. Each of the seven types, driven separately, refuses with the situation
// its TYPE chooses — and carries the UPID and the type. The same-run control
// (an ignored non-terminal type) proves the harness is live: a loop whose
// variable was captured wrongly, or a determination that refuses everything,
// would fail the control.
func TestDetermine_EachHazardousTypeRefusesWithItsSituation(t *testing.T) {
	for typ, sit := range wantHazard {
		t.Run(typ, func(t *testing.T) {
			_, ctl := detServer(t, running("UPID:n1:CTL:qmstart:690", "qmstart"))
			mustProceed(t, determineOn(ctl), "control (non-hazardous non-terminal)")

			upid := "UPID:n1:00000001:00000001:00000001:" + typ + ":690:root@pam:"
			_, c := detServer(t, running(upid, typ))
			r := mustRefuse(t, determineOn(c), typ, sit)
			if r.UPID != upid || r.TaskType != typ {
				t.Errorf("refusal names (%q, %q), want (%q, %q)", r.UPID, r.TaskType, upid, typ)
			}
			if r.VMID != detVMID || r.Node != detNode || r.Condition == "" {
				t.Errorf("refusal %+v is missing the vmid, node or the change-condition", r)
			}
		})
	}
}

// U4-2. Allowed and ignored types never refuse, non-terminal, id == vmid. The
// qmmove row has a PLAIN decimal id (the storage-move form), so it is excluded
// by the TYPE check — pinning the operator's ruling as a decision. A composite
// id would be excluded by the id check and exercise nothing.
func TestDetermine_AllowedAndIgnoredTypesProceed(t *testing.T) {
	types := []string{"qmreset", "qmreboot", "qmmove", "qmcreate", "qmstart", "qmconfig", "vncproxy",
		"hastart", "hastop", "qmresume", "qmsuspend", "qmpause", "resize", "qmsnapshot", "qmrollback",
		"qmdelsnapshot", "qmtemplate", "qmtunnel"}
	for _, typ := range types {
		if _, bad := wantHazard[typ]; bad {
			t.Fatalf("test bug: %q is hazardous", typ)
		}
		t.Run(typ, func(t *testing.T) {
			_, c := detServer(t, running("UPID:n1:X:"+typ+":690", typ))
			mustProceed(t, determineOn(c), typ)
		})
	}
	// An empty log is not hazardous either: "no destroy is visible" proceeds.
	_, c := detServer(t)
	d := determineOn(c)
	mustProceed(t, d, "empty log")
	if d.LastDestroy != nil || d.LastDestroyEndedOK {
		t.Errorf("empty log: LastDestroy %v ok=%v, want none", d.LastDestroy, d.LastDestroyEndedOK)
	}
}

// U4-3 and U4-8(b). Terminal rows never refuse — including a failed destroy
// (B6: refusing on the strength of an earlier failure is the defect) and a
// finished-but-unarchived destroy that lives in the ACTIVE half. Each is paired
// with the same row made non-terminal, which must refuse, so a row ignored for
// the wrong reason (wrong id, wrong type) cannot pass.
func TestDetermine_TerminalRowsNeverRefuse_AndFailedDestroyIsReturned(t *testing.T) {
	for typ := range wantHazard {
		t.Run(typ, func(t *testing.T) {
			_, c := detServer(t, archived("UPID:t:"+typ, typ, "OK", 100))
			mustProceed(t, determineOn(c), typ+" terminal archived")
			_, c = detServer(t, running("UPID:t:"+typ, typ))
			mustRefuse(t, determineOn(c), typ+" same row, running", wantHazard[typ])
		})
	}

	_, c := detServer(t, archived("UPID:F", "qmdestroy", "command 'x' failed: exit code 1", 100))
	d := determineOn(c)
	mustProceed(t, d, "failed destroy")
	if d.LastDestroy == nil || d.LastDestroy.UPID != "UPID:F" || d.LastDestroyEndedOK {
		t.Errorf("failed destroy: LastDestroy %+v ok=%v, want UPID:F not OK", d.LastDestroy, d.LastDestroyEndedOK)
	}

	// Finished-unarchived: EndTime > 0, Saved false, status OK — in the active
	// half. Terminal by endtime; must neither refuse nor be missed as D1(b).
	_, c = detServer(t, detRow("UPID:U", "qmdestroy", 100, "OK", 150, false))
	d = determineOn(c)
	mustProceed(t, d, "finished-unarchived destroy")
	if d.LastDestroy == nil || d.LastDestroy.UPID != "UPID:U" || !d.LastDestroyEndedOK {
		t.Errorf("finished-unarchived destroy: LastDestroy %+v ok=%v, want UPID:U OK", d.LastDestroy, d.LastDestroyEndedOK)
	}
}

// U4-4. Row-level positive evidence: a row is terminal ONLY by a positive
// endtime. No endtime, whatever the status says — empty, OK, either spelling of
// running, an unrecognised word — is in flight.
func TestDetermine_RowWithoutEndtimeIsInFlight(t *testing.T) {
	for _, status := range []string{"", "OK", "RUNNING", "running", "weird", "stopped"} {
		for _, saved := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%q/saved=%v", status, saved), func(t *testing.T) {
				_, c := detServer(t, detRow("UPID:NE", "qmdestroy", 100, status, 0, saved))
				r := mustRefuse(t, determineOn(c), "no endtime", SituationDestroy)
				if r.UPID != "UPID:NE" {
					t.Errorf("refusal names %q, want UPID:NE", r.UPID)
				}
			})
		}
	}
	// A NEGATIVE endtime is not positive evidence of finishing either. Terminal()
	// is `EndTime > 0`; a classifier written `EndTime != 0` reads -1 as finished
	// and would proceed (and report the row as the newest destroy). VMREST cannot
	// serve this (its rows render endtime only when non-zero and never negative),
	// so it is a raw-server row: a qmdestroy for the vmid, endtime -1, status OK.
	t.Run("endtime=-1/status=OK", func(t *testing.T) {
		_, c := newRawPVE(t, rawRows(rawRow("690", "qmdestroy", `,"endtime":-1,"status":"OK"`)))
		d := determineOn(c)
		r := mustRefuse(t, d, "negative endtime", SituationDestroy)
		if r.UPID == "" || r.TaskType != "qmdestroy" {
			t.Errorf("refusal %+v must name the in-flight destroy", r)
		}
		if d.LastDestroy != nil || d.LastDestroyEndedOK {
			t.Errorf("a row with endtime -1 was returned as the newest terminal destroy: %+v ok=%v", d.LastDestroy, d.LastDestroyEndedOK)
		}
	})
}

// ---- raw canned-body server: ignores the query, so the CLIENT's checks run ----

type rawPVE struct {
	mu       sync.Mutex
	requests []string
	statusAt int    // probe status code; 0 = 200
	probe    string // probe body; "" = a normal one
	list     string // task-list body
}

func newRawPVE(t *testing.T, list string) (*rawPVE, *Client) {
	t.Helper()
	r := &rawPVE{list: list}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.requests = append(r.requests, req.Method+" "+req.URL.Path+"?"+req.URL.RawQuery)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(req.URL.Path, "/status"):
			if r.statusAt != 0 && r.statusAt != 200 {
				w.WriteHeader(r.statusAt)
			}
			if r.probe != "" {
				_, _ = w.Write([]byte(r.probe))
			} else {
				_, _ = w.Write([]byte(`{"data":{"uptime":1}}`))
			}
		case strings.HasSuffix(req.URL.Path, "/tasks"):
			_, _ = w.Write([]byte(r.list))
		default:
			t.Errorf("rawPVE: unscripted %s", req.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return r, detClient(t, srv.URL)
}

func (r *rawPVE) reqs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}

func rawRows(rows ...string) string { return `{"data":[` + strings.Join(rows, ",") + `]}` }

func rawRow(id, typ string, extra string) string {
	return fmt.Sprintf(`{"upid":"UPID:n1:R:%s:%s","type":%q,"id":%q,"starttime":10,"node":"n1","user":"root@pam"%s}`, typ, id, typ, id, extra)
}

// C2. The client-side id check. VMREST filters vmid= server-side, so every row
// it returns already matches and a determination with NO client-side check
// would pass every VMREST test. This server ignores the query and hands back
// rows whose ids only LOOK like the vmid; none may refuse. The control — the
// exact id — does, so the body is being read.
func TestDetermine_ClientSideIDMatch_RawServer(t *testing.T) {
	for _, id := range []string{"6900", "69", "", "690-scsi0>691-scsi0", " 690", "0690", "6901"} {
		t.Run(fmt.Sprintf("id=%q", id), func(t *testing.T) {
			_, c := newRawPVE(t, rawRows(rawRow(id, "qmdestroy", "")))
			mustProceed(t, determineOn(c), "look-alike id")
		})
	}
	_, c := newRawPVE(t, rawRows(rawRow("690", "qmdestroy", "")))
	mustRefuse(t, determineOn(c), "control: the exact id", SituationDestroy)
	// And the TYPE check, the idiom FindTaskUPID exists to get right: an id-only
	// match would refuse on a qmstart that shares the id.
	_, c = newRawPVE(t, rawRows(rawRow("690", "qmstart", ""), rawRow("690", "qmcreate", "")))
	mustProceed(t, determineOn(c), "same id, ignored types")
}

// U4-5. Response-level fail-closed. A body the reader cannot decode is a READ
// FAILURE (B10): never a refusal naming a half-decoded row, never a proceed.
// Neither implies the server's log is complete — PVE drops malformed log lines
// itself before the response (accepted residual R-MALFORMED).
func TestDetermine_UndecodableResponseIsAReadFailure(t *testing.T) {
	good := rawRow("690", "qmdestroy", "")
	_, ctl := newRawPVE(t, rawRows(good))
	mustRefuse(t, determineOn(ctl), "control", SituationDestroy)

	for name, body := range map[string]string{
		// one off-type endtime beside a valid in-flight destroy
		"off-type endtime": rawRows(rawRow("691", "qmstart", `,"endtime":"soon"`), good),
		// a JSON NUMBER id cannot decode into the string field
		"numeric id": rawRows(`{"upid":"UPID:n1:N","type":"qmdestroy","id":690,"starttime":10,"node":"n1","user":"root@pam"}`),
		"not json":   `<html>proxy says hi</html>`,
		"wrong data": `{"data":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newRawPVE(t, body)
			r := mustRefuse(t, determineOn(c), name, SituationUnreadable)
			if r.UPID != "" || r.TaskType != "" {
				t.Errorf("a read failure named a task (%q, %q) from a body it could not decode", r.UPID, r.TaskType)
			}
			if !strings.Contains(r.Read, "task list") || r.ReadErr == "" || r.Condition == "" {
				t.Errorf("read failure %+v does not name the read, its error and the change-condition", r)
			}
		})
	}
}

// U4-6. Truncation is not a negative answer, through `determine` with a small
// limit (nobody builds 2000 rows twice) — the production constant is checked on
// the wire below. With start absent: a page of exactly `limit` refuses, a page
// of limit-1 proceeds, and a full page that DOES hold a non-terminal hazardous
// row refuses with THAT row, not the generic message.
func TestDetermine_TruncationRules(t *testing.T) {
	three := []pvefake.TaskRow{
		archived("UPID:1", "qmcreate", "OK", 10), archived("UPID:2", "qmstart", "OK", 20), archived("UPID:3", "qmconfig", "OK", 30),
	}
	do := func(limit int, rows ...pvefake.TaskRow) *InFlightDetermination {
		_, c := detServer(t, rows...)
		return determine(context.Background(), c, detNode, detVMID, limit, time.Minute)
	}
	r := mustRefuse(t, do(3, three...), "exactly limit, none matching", SituationUnreadable)
	if !strings.Contains(r.ReadErr, "full page") || r.UPID != "" {
		t.Errorf("truncation refusal %+v should say a full page may be truncated and name no task", r)
	}
	mustProceed(t, do(4, three...), "limit-1 rows")
	mustProceed(t, do(3, three[:2]...), "limit-1 rows (3 limit, 2 rows)")

	full := append(slices.Clone(three[:2]), running("UPID:HZ", "qmdestroy"))
	r = mustRefuse(t, do(3, full...), "full page holding a hazard", SituationDestroy)
	if r.UPID != "UPID:HZ" {
		t.Errorf("full page holding a hazard: refusal names %q, want UPID:HZ — the generic truncation message masked the specific one", r.UPID)
	}
}

// U4-7. The request, parsed and compared EXACTLY. This is also the only killer
// for omitting vmid= (C3): with a client-side id check and a small log the
// behaviour is identical without it.
func TestDetermine_SendsExactlyTheDestroyQuery(t *testing.T) {
	s, c := detServer(t)
	mustProceed(t, determineOn(c), "empty log")
	reqs := s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests %q, want exactly 2 (probe, one task list)", len(reqs), reqs)
	}
	if reqs[0] != "GET /api2/json/nodes/n1/status" {
		t.Errorf("first request = %q, want the visibility probe", reqs[0])
	}
	path, rawQuery, _ := strings.Cut(strings.TrimPrefix(reqs[1], "GET "), " ?")
	if path != "/api2/json/nodes/n1/tasks" {
		t.Fatalf("second request path = %q, want the task list", path)
	}
	got, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"source": {"all"}, "vmid": {"690"}, "limit": {fmt.Sprint(destroyTaskListLimit)}}
	if len(got) != len(want) {
		t.Errorf("query %v carries parameters beyond %v (start, since, typefilter must be absent)", got, want)
	}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("query %s = %v, want %v", k, got[k], v)
		}
	}
	if destroyTaskListLimit <= 0 {
		t.Errorf("destroyTaskListLimit = %d, want a positive explicit limit", destroyTaskListLimit)
	}
	if destroyTaskListLimit != 2000 {
		t.Errorf("destroyTaskListLimit = %d, want the ruled 2000", destroyTaskListLimit)
	}
	if destroyDeterminationTimeout != 30*time.Second {
		t.Errorf("destroyDeterminationTimeout = %s, want the provisional 30s", destroyDeterminationTimeout)
	}
	// vmid has no leading zeros however the caller produced it.
	s2, c2 := detServer(t)
	c2.DetermineDestroyInFlight(context.Background(), detNode, 100)
	if rs := s2.Requests(); len(rs) != 2 || !strings.Contains(rs[1], "vmid=100") {
		t.Errorf("vmid 100 requests = %q", rs)
	}
}

// U4-8. Active rows are SEEN, against the corrected Saved partition. (a) a
// running row is returned by the production query and refuses; (c) the same
// fixture queried the way FindTaskUPID queries (source=archive) does NOT return
// it, which is what makes the FindTaskUPID idiom in this position fail open.
// (b) is in TestDetermine_TerminalRows… above.
func TestDetermine_SeesActiveRows_AgainstTheSavedPartition(t *testing.T) {
	rows := []pvefake.TaskRow{
		running("UPID:RUN", "qmdestroy"),
		detRow("UPID:UNARCH", "qmcreate", 500, "OK", 550, false),
		archived("UPID:ARCH", "qmcreate", "OK", 100),
	}
	_, c := detServer(t, rows...)
	r := mustRefuse(t, determineOn(c), "running row in the active half", SituationDestroy)
	if r.UPID != "UPID:RUN" {
		t.Errorf("refusal names %q, want UPID:RUN", r.UPID)
	}

	// (c) The fixture itself, read as FindTaskUPID reads: the running row is not
	// in the archive half, so an archive-source determination would proceed.
	page, err := c.TaskList(context.Background(), TaskListQuery{Node: detNode, Source: TaskListArchive, Limit: findTaskUPIDLimit, VMID: "690"})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range page.Rows {
		if row.UPID == "UPID:RUN" {
			t.Fatalf("the running row is in the archive half: the fixture cannot tell source=archive from source=all, so this test would be vacuous")
		}
	}
	if len(page.Rows) != 1 || page.Rows[0].UPID != "UPID:ARCH" {
		t.Errorf("archive half = %+v, want only UPID:ARCH", page.Rows)
	}
}

// U4-9 / C7 / C8. D1(b): the newest terminal qmdestroy by greatest starttime,
// whatever order the page lists it in (real PVE lists the active half before
// the archive half and does NOT order the active half newest-first), and on a
// tie the row that did NOT end OK wins. In the tie fixtures the OK row carries
// the lexicographically GREATER upid, so a string-max tie-break (which picks
// the OK row) fails alongside a >=/> flip and a first/last-row pick.
func TestDetermine_NewestTerminalDestroy_BothOrders_AndTies(t *testing.T) {
	older := archived("UPID:a-older-OK", "qmdestroy", "OK", 100)
	newer := archived("UPID:b-newer-FAILED", "qmdestroy", "WARNINGS: 1", 200)
	clone := archived("UPID:z-clone", "qmclone", "OK", 900)
	unarch := detRow("UPID:c-unarchived-newest", "qmdestroy", 300, "command failed", 310, false)

	check := func(name string, wantUPID string, wantOK bool, rows ...pvefake.TaskRow) {
		for _, order := range []string{"as-given", "reversed"} {
			rs := slices.Clone(rows)
			if order == "reversed" {
				slices.Reverse(rs)
			}
			_, c := detServer(t, rs...)
			d := determineOn(c)
			mustProceed(t, d, name+"/"+order)
			if d.LastDestroy == nil || d.LastDestroy.UPID != wantUPID || d.LastDestroyEndedOK != wantOK {
				t.Errorf("%s/%s: LastDestroy %+v ok=%v, want %s ok=%v", name, order, d.LastDestroy, d.LastDestroyEndedOK, wantUPID, wantOK)
			}
		}
	}
	check("newer failed", "UPID:b-newer-FAILED", false, older, newer, clone)
	check("newer OK", "UPID:z-newer-OK", true,
		archived("UPID:a-older-FAILED", "qmdestroy", "unexpected status", 100),
		archived("UPID:z-newer-OK", "qmdestroy", "OK", 200), clone)
	check("unarchived is newest", "UPID:c-unarchived-newest", false, older, newer, unarch)

	// Ties: same starttime, the OK row has the GREATER upid and the failed row
	// the smaller; non-OK must win in both orders, and with an archived/unarchived mix.
	tieOK := archived("UPID:zz-tie-OK", "qmdestroy", "OK", 150)
	tieBad := archived("UPID:aa-tie-FAILED", "qmdestroy", "WARNINGS: 2", 150)
	if !(tieOK.UPID > tieBad.UPID) {
		t.Fatal("test bug: the OK row must carry the lexicographically greater UPID")
	}
	check("tie", "UPID:aa-tie-FAILED", false, tieOK, tieBad)
	check("tie with an older OK and a clone", "UPID:aa-tie-FAILED", false, older, tieOK, clone, tieBad)

	// Neither a terminal non-destroy nor an in-flight allowed row is "the destroy".
	_, c := detServer(t, clone, running("UPID:RST", "qmreset"))
	d := determineOn(c)
	mustProceed(t, d, "only a clone and a reset")
	if d.LastDestroy != nil {
		t.Errorf("LastDestroy = %+v, want none: a qmclone is not a destroy", d.LastDestroy)
	}
}

// U4-10. EndedOK is the EXACT string OK. The near-spellings stay in the table
// even though PVE's read_status cannot emit most of them: a permissive compare
// fails open for the gone-proof, and the table is not to be shrunk to the two
// statuses read_status returns on the success path.
func TestDetermine_EndedOKIsExact(t *testing.T) {
	for status, want := range map[string]bool{
		"OK": true, "WARNINGS: 1": false, "ok": false, "OK ": false, " OK": false, "OKAY": false,
		"unexpected status": false, "command 'qm destroy 690' failed: exit code 255": false, "": false,
	} {
		t.Run(fmt.Sprintf("%q", status), func(t *testing.T) {
			_, c := detServer(t, archived("UPID:S", "qmdestroy", status, 100))
			d := determineOn(c)
			mustProceed(t, d, "terminal destroy")
			if d.LastDestroy == nil {
				t.Fatal("no LastDestroy")
			}
			if d.LastDestroyEndedOK != want {
				t.Errorf("status %q: LastDestroyEndedOK = %v, want %v", status, d.LastDestroyEndedOK, want)
			}
			if (TaskRow{Status: status}).EndedOK() != want {
				t.Errorf("TaskRow.EndedOK(%q) disagrees", status)
			}
		})
	}
}

// U4-11. The probe, by STATUS CODE. 403 names the privilege (from the code, so
// the 401/500 bodies — which no longer carry the wording — are not mislabelled)
// and sends ZERO task-list requests; every other failure names the read and
// says nothing of Sys.Audit; the probe precedes the list on the wire.
func TestDetermine_ProbeStatusCodes(t *testing.T) {
	// Control first: the same fixture with a 200 probe proceeds, probe then list.
	s, c := detServer(t)
	mustProceed(t, determineOn(c), "200 probe")
	if rs := s.Requests(); len(rs) != 2 || !strings.HasSuffix(rs[0], "/status") || !strings.Contains(rs[1], "/tasks") {
		t.Fatalf("control requests = %q, want probe then one list", rs)
	}

	s, c = detServer(t, running("UPID:RUN", "qmdestroy"))
	s.NodeStatus = http.StatusForbidden
	r := mustRefuse(t, determineOn(c), "403", SituationUnreadable)
	if r.Privilege != "Sys.Audit on /nodes/n1" || !strings.Contains(r.Condition, "Sys.Audit") || r.VMID != detVMID {
		t.Errorf("403 refusal %+v must name the vmid and Sys.Audit on /nodes/n1", r)
	}
	for _, q := range s.Requests() {
		if strings.Contains(q, "/tasks") {
			t.Errorf("a task-list request %q was sent after a 403 probe", q)
		}
	}

	for _, code := range []int{http.StatusUnauthorized, http.StatusInternalServerError, http.StatusBadGateway} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s, c := detServer(t, running("UPID:RUN", "qmdestroy"))
			s.NodeStatus = code
			r := mustRefuse(t, determineOn(c), fmt.Sprint(code), SituationUnreadable)
			if r.Privilege != "" || strings.Contains(refusalText(r), "Sys.Audit") {
				t.Errorf("a %d claims a missing privilege: %+v", code, r)
			}
			if !strings.Contains(r.Read, "/status") || r.ReadErr == "" {
				t.Errorf("a %d refusal %+v does not name the failing read and its error", code, r)
			}
			for _, q := range s.Requests() {
				if strings.Contains(q, "/tasks") {
					t.Errorf("a task-list request %q was sent after a %d probe", q, code)
				}
			}
		})
	}

	// The privilege is named from the CODE, not from PVE's words. A 403 whose body
	// does not mention Sys.Audit still names it (the verb knows which privilege
	// the probe stands for); a 500 whose body DOES mention it does not (a server
	// fault is not a missing privilege). A classifier that greps the body's text
	// gets both wrong — and VMREST alone cannot show that, because its 403 always
	// carries the wording.
	rawCode := func(code int, body string) *InFlightRefusal {
		raw, c := newRawPVE(t, rawRows())
		raw.statusAt, raw.probe = code, body
		return mustRefuse(t, determineOn(c), fmt.Sprint("raw ", code), SituationUnreadable)
	}
	if r := rawCode(403, `{"message":"denied","data":null}`); r.Privilege != "Sys.Audit on /nodes/n1" {
		t.Errorf("a 403 without the wording in its body: Privilege = %q, want it named from the code", r.Privilege)
	}
	if r := rawCode(500, `{"message":"Permission check failed (/nodes/n1, Sys.Audit)","data":null}`); r.Privilege != "" || strings.Contains(r.Condition, "Sys.Audit") {
		t.Errorf("a 500 whose body mentions Sys.Audit claims a missing privilege: %+v", r)
	}
	// A 200 is a 200: an empty or null payload still proves the token may read
	// the node's status, so the list is not owner-filtered. It must not be refused.
	//
	// The odd-but-valid 200 bodies below are the ones a typed node-status read
	// (GetNode) REJECTS and the raw read accepts — measured by running both
	// readers over the same bodies. They are what separates a probe on RawRequest
	// from one on GetNode in this direction; no body was found that the raw read
	// rejects and GetNode accepts, so "a garbage 200 is accepted" cannot be what
	// kills a GetNode probe (a 401 naming Sys.Audit does, see above).
	for _, body := range []string{`{"data":null}`, ` `, `{"data":"x"}`, `{"data":{"uptime":"soon"}}`} {
		raw, c := newRawPVE(t, rawRows())
		raw.probe = body
		mustProceed(t, determineOn(c), fmt.Sprintf("200 probe with body %q", body))
	}

	// garbage 200: not an envelope the raw reader accepts.
	raw, c2 := newRawPVE(t, rawRows())
	raw.probe = `<html>captive portal</html>`
	r = mustRefuse(t, determineOn(c2), "garbage-200 probe", SituationUnreadable)
	if r.Privilege != "" || !strings.Contains(r.Read, "/status") {
		t.Errorf("garbage-200 refusal %+v", r)
	}
	for _, q := range raw.reqs() {
		if strings.Contains(q, "/tasks") {
			t.Errorf("a task-list request %q followed a garbage-200 probe", q)
		}
	}

	// PVE unreachable: the listener is closed, which is the real condition.
	s3 := pvefake.NewVMREST(t, detNode)
	srv := s3.Server()
	c3 := detClient(t, srv.URL+"/api2/json")
	srv.Close()
	r = mustRefuse(t, determineOn(c3), "refused listener", SituationUnreadable)
	if !strings.Contains(r.Read, "/status") || r.ReadErr == "" {
		t.Errorf("unreachable refusal %+v must name the read and the error", r)
	}
}

// U4-12. A3.4a/b: the owner-filtered 200. Control first — the identical fixture
// with a 200 probe PROCEEDS — then the 403 probe over the same 200 task list
// refuses. Both halves in one test, so "always refuse" cannot pass. A3.4b is a
// pin of "no extra completeness check", not evidence that omission is handled:
// a list omitting another principal's destroy and an empty list are the same
// bytes (spec C9; the privilege identity is a SOURCE assertion).
func TestDetermine_VisibilityPair_ControlFirst(t *testing.T) {
	s, c := detServer(t, archived("UPID:MINE", "qmcreate", "OK", 100))
	mustProceed(t, determineOn(c), "control: probe 200, list 200")

	s.NodeStatus = http.StatusForbidden
	if code, rows := func() (int, int) {
		page, err := c.TaskList(context.Background(), inFlightQuery(detNode, detVMID))
		if err != nil {
			t.Fatal(err)
		}
		return 200, len(page.Rows)
	}(); code != 200 || rows == 0 {
		t.Fatalf("under a 403 probe the task list must still answer 200 with rows (got %d rows): the fixture is not reproducing the owner-filtered 200", rows)
	}
	r := mustRefuse(t, determineOn(c), "probe 403 over a 200 task list", SituationUnreadable)
	if r.Privilege == "" {
		t.Errorf("refusal %+v does not name the privilege", r)
	}
}

// U4-13. The budget bounds each read and the refusal names WHICH read ran out.
// The probe answers at once and the LIST stalls, so the timeout is the list's;
// a test whose deadline fired in the probe's dial would never reach the list.
// The wrapper's own budget argument is not observable without a real 30s stall
// (accepted: the verb-level deadline test closes it) — its constants are pinned
// by value in the query test.
func TestDetermine_BudgetBoundsEachRead_AndNamesWhich(t *testing.T) {
	s, c := detServer(t)
	s.StallTasks = 30 * time.Second
	start := time.Now()
	d := determine(context.Background(), c, detNode, detVMID, destroyTaskListLimit, 150*time.Millisecond)
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %s: the budget did not bound the stalled read", el)
	}
	r := mustRefuse(t, d, "stalled list", SituationUnreadable)
	if !strings.Contains(r.Read, "task list") || r.ReadErr == "" {
		t.Errorf("refusal %+v must name the task list as the read that ran out", r)
	}
	if rs := s.Requests(); len(rs) < 2 || !strings.HasSuffix(rs[0], "/status") {
		t.Errorf("requests %q: the probe must have completed before the list stalled", rs)
	}

	// A caller context that is already cancelled refuses too, and never proceeds.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, c2 := detServer(t)
	mustRefuse(t, c2.DetermineDestroyInFlight(ctx, detNode, detVMID), "cancelled context", SituationUnreadable)
}

// U4-14. I5: every refusal carries the vmid, a specific observation and a
// change-condition, and the conditions differ — a table over every refusal the
// determination can produce.
func TestDetermine_RefusalCarriesAllThreeTokens(t *testing.T) {
	type tc struct {
		name string
		sit  Situation
		mk   func(t *testing.T) *InFlightDetermination
		obs  func(r *InFlightRefusal) bool
	}
	hz := func(typ string) func(*testing.T) *InFlightDetermination {
		return func(t *testing.T) *InFlightDetermination {
			_, c := detServer(t, running("UPID:HZ-"+typ, typ))
			return determineOn(c)
		}
	}
	cases := []tc{
		{"B4", SituationDestroy, hz("qmdestroy"), func(r *InFlightRefusal) bool { return r.UPID == "UPID:HZ-qmdestroy" && r.TaskType == "qmdestroy" }},
		{"B4b", SituationInFlightOther, hz("qmigrate"), func(r *InFlightRefusal) bool { return r.UPID == "UPID:HZ-qmigrate" && r.TaskType == "qmigrate" }},
		{"B4c", SituationStop, hz("qmshutdown"), func(r *InFlightRefusal) bool { return r.UPID == "UPID:HZ-qmshutdown" && r.TaskType == "qmshutdown" }},
		{"probe403", SituationUnreadable, func(t *testing.T) *InFlightDetermination {
			s, c := detServer(t)
			s.NodeStatus = 403
			return determineOn(c)
		}, func(r *InFlightRefusal) bool {
			return r.Privilege == "Sys.Audit on /nodes/n1" && strings.Contains(r.Condition, "Sys.Audit")
		}},
		{"readfail", SituationUnreadable, func(t *testing.T) *InFlightDetermination {
			s, c := detServer(t)
			s.TasksStatus = 500
			return determineOn(c)
		}, func(r *InFlightRefusal) bool { return strings.Contains(r.Read, "task list") && r.ReadErr != "" }},
		{"truncated", SituationUnreadable, func(t *testing.T) *InFlightDetermination {
			_, c := detServer(t, archived("UPID:1", "qmcreate", "OK", 1), archived("UPID:2", "qmcreate", "OK", 2))
			return determine(context.Background(), c, detNode, detVMID, 2, time.Minute)
		}, func(r *InFlightRefusal) bool { return strings.Contains(r.ReadErr, "full page") }},
	}
	seen := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustRefuse(t, c.mk(t), c.name, c.sit)
			if r.VMID != detVMID || r.Node != detNode {
				t.Errorf("refusal %+v does not name the vmid and node", r)
			}
			if !c.obs(r) {
				t.Errorf("refusal %+v does not carry this situation's specific observation", r)
			}
			if r.Condition == "" {
				t.Errorf("refusal %+v has no change-condition", r)
			}
			if prev, dup := seen[r.Condition]; dup {
				t.Errorf("condition %q is shared with %s: the conditions must differ", r.Condition, prev)
			}
			seen[r.Condition] = c.name
		})
	}
}

// U4-15 / C12. The control for the verb's no-self-collision criterion (I1f): a
// stop or destroy the verb dispatched at a REFLECTING fixture is refused by the
// determination that follows. If the determination ignored stops, I1f would
// pass vacuously, so this is supplied from below. The reflected row is asserted
// to exist, as PVE's active branch serves it, before the verdict is believed.
func TestDetermine_ReflectedStopIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		sit                Situation
		typ                string
	}{
		{"stop", http.MethodPost, "/api2/json/nodes/n1/qemu/690/status/stop", SituationStop, "qmstop"},
		{"destroy", http.MethodDelete, "/api2/json/nodes/n1/qemu/690", SituationDestroy, "qmdestroy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := pvefake.NewVMREST(t, detNode)
			s.Reflect = true
			s.StopUPID = "UPID:n1:00000009:00000009:00000009:qmstop:690:root@pam:"
			s.DestroyUPID = "UPID:n1:0000000A:0000000A:0000000A:qmdestroy:690:root@pam:"
			srv := s.Server()
			defer srv.Close()
			c := detClient(t, srv.URL+"/api2/json")

			mustProceed(t, determineOn(c), "before the dispatch")

			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()

			page, err := c.TaskList(context.Background(), TaskListQuery{Node: detNode, Source: TaskListActive, Limit: 10, VMID: "690"})
			if err != nil || len(page.Rows) != 1 {
				t.Fatalf("reflected rows = %+v err=%v, want exactly one", page, err)
			}
			if row := page.Rows[0]; row.Type != tc.typ || row.Status != "RUNNING" || row.EndTime != 0 {
				t.Fatalf("reflected row %+v, want %s, status RUNNING, no endtime", row, tc.typ)
			}
			r := mustRefuse(t, determineOn(c), "after the dispatch", tc.sit)
			if r.TaskType != tc.typ {
				t.Errorf("refusal names type %q, want %q", r.TaskType, tc.typ)
			}
		})
	}
}

// C5. The determination's query carries no since (and none of start or
// typefilter). TaskList ignores Since entirely today, so a determination that
// set one would be invisible at behaviour level; this pins the builder, and the
// wire test above will catch it the day TaskList starts sending it.
func TestDetermine_InFlightQueryHasNoSince(t *testing.T) {
	q := inFlightQuery("n1", 690)
	if q.Since != 0 {
		t.Errorf("Since = %d, want 0: a process-derived since is forbidden", q.Since)
	}
	if err := q.Validate(); err != nil {
		t.Errorf("the determination's own query does not validate: %v", err)
	}
	if q.Source != TaskListAll || q.VMID != "690" || q.Limit != destroyTaskListLimit || q.Node != "n1" {
		t.Errorf("query = %+v", q)
	}
	keys := make([]string, 0, 3)
	for k := range q.params() {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"limit", "source", "vmid"}) {
		t.Errorf("wire parameters = %v, want exactly limit, source, vmid", keys)
	}
}

// U4-18. The RoutedClient forwarder binds the TARGET's node and the caller's
// vmid, in the right places. Two distinct nodes and two distinct non-adjacent
// vmids, so a swap, a literal or vmid±1 changes the path or the query.
func TestRoutedForwarding_DetermineDestroyInFlight(t *testing.T) {
	for _, c := range []struct {
		node string
		vmid int
	}{{fwdTargetNode, fwdVMID}, {fwdTargetNode2, fwdVMID2}} {
		t.Run(c.node, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/status") {
					writeData(w, `{"uptime":1}`)
					return
				}
				writeData(w, `[]`)
			})
			d := fwdClientOn(t, srv, c.node).DetermineDestroyInFlight(context.Background(), c.vmid)
			if d == nil || !d.Proceed {
				t.Fatalf("determination = %+v, want proceed", d)
			}
			assertRequests(t, rec.got(),
				fmt.Sprintf("GET /nodes/%s/status", c.node),
				fmt.Sprintf("GET /nodes/%s/tasks?limit=%d&source=all&vmid=%d", c.node, destroyTaskListLimit, c.vmid))
		})
	}
}
