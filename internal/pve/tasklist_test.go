package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// tlClient builds a Client against a canned raw response, the shape the other
// task-list tests in this package already use.
func tlClient(t *testing.T, statusLine, body string) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURLOverride: rawStatusServer(t, statusLine, body),
		TokenID:         "root@pam!tl",
		TokenSecret:     "s",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// recorder is an httptest server that records every request line it is asked
// for. It exists because rawStatusServer answers any request with the same
// bytes and therefore cannot witness what was SENT — and "no request was sent"
// is half of what the limit guard has to prove.
type recorder struct {
	mu   sync.Mutex
	gets []string
	srv  *httptest.Server
}

func newRecorder(t *testing.T, body string) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.gets = append(r.gets, req.URL.Path+"?"+req.URL.RawQuery)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) hits() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.gets...)
}

func (r *recorder) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{BaseURLOverride: r.srv.URL, TokenID: "root@pam!tl", TokenSecret: "s"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func tlBody(rows ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"data": rows})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func okQuery() TaskListQuery {
	return TaskListQuery{Node: "pvh-n1", Source: TaskListAll, Limit: 500}
}

// INV-1. limit <= 0 is refused BEFORE any network contact. PVE's schema gives
// `limit` a minimum of 0, and limit=0 was measured live to return zero rows
// with HTTP 200 — a reader that sent it would answer "no task matched" forever
// while every status stayed green. The zero-request half is the point: an
// assertion that only checks the error would still pass a reader that sent the
// request and then threw the answer away.
func TestTaskList_LimitMustBePositive_AndNothingIsSent(t *testing.T) {
	for _, limit := range []int{0, -1} {
		r := newRecorder(t, tlBody())
		q := okQuery()
		q.Limit = limit

		if err := q.Validate(); err == nil {
			t.Errorf("limit=%d: Validate returned nil, want a refusal", limit)
		}
		page, err := r.client(t).TaskList(context.Background(), q)
		if err == nil {
			t.Fatalf("limit=%d: TaskList returned nil error, want a refusal", limit)
		}
		if page != nil {
			t.Errorf("limit=%d: TaskList returned a page alongside its error", limit)
		}
		if !strings.Contains(err.Error(), "limit must be > 0") {
			t.Errorf("limit=%d: error %q does not say what is wrong", limit, err)
		}
		if h := r.hits(); len(h) != 0 {
			t.Errorf("limit=%d: %d request(s) reached the server: %v; want none", limit, len(h), h)
		}
	}
	// Anti-vacuity: the SAME recorder and client do send a request when the
	// query is valid, so the zero above is a refusal and not a broken fixture.
	r := newRecorder(t, tlBody())
	if _, err := r.client(t).TaskList(context.Background(), okQuery()); err != nil {
		t.Fatalf("control: a valid query must reach the server: %v", err)
	}
	if h := r.hits(); len(h) != 1 {
		t.Fatalf("control: %d request(s), want exactly 1: the recorder is not observing", len(h))
	}
}

// INV-4. source has no default: a request that did not ask for active tasks
// cannot see a running one, and its empty answer is indistinguishable from
// "none in flight". Refused before the network, same as the limit.
func TestTaskList_SourceIsRequired_AndNothingIsSent(t *testing.T) {
	for _, src := range []string{"", "archived", "ALL", "running"} {
		r := newRecorder(t, tlBody())
		q := okQuery()
		q.Source = src
		page, err := r.client(t).TaskList(context.Background(), q)
		if err == nil || page != nil {
			t.Errorf("source=%q: got (%v, %v), want (nil, a refusal)", src, page, err)
		}
		if h := r.hits(); len(h) != 0 {
			t.Errorf("source=%q: %d request(s) reached the server; want none", src, len(h))
		}
	}
}

// The request carries exactly what the query says, and nothing it does not.
func TestTaskList_SendsTheQueryItWasGiven(t *testing.T) {
	r := newRecorder(t, tlBody())
	q := TaskListQuery{Node: "pvh-n1", Source: TaskListAll, Limit: 500, VMID: "690"}
	if _, err := r.client(t).TaskList(context.Background(), q); err != nil {
		t.Fatalf("TaskList: %v", err)
	}
	h := r.hits()
	if len(h) != 1 {
		t.Fatalf("%d requests, want 1: %v", len(h), h)
	}
	for _, want := range []string{"/nodes/pvh-n1/tasks", "source=all", "limit=500", "vmid=690"} {
		if !strings.Contains(h[0], want) {
			t.Errorf("request %q does not carry %q", h[0], want)
		}
	}
	// No vmid filter when the query names no vmid.
	r2 := newRecorder(t, tlBody())
	q2 := okQuery()
	if _, err := r2.client(t).TaskList(context.Background(), q2); err != nil {
		t.Fatalf("TaskList: %v", err)
	}
	if strings.Contains(r2.hits()[0], "vmid=") {
		t.Errorf("request %q carries a vmid filter the query did not ask for", r2.hits()[0])
	}
}

// INV-2. A full page is not a negative answer. PVE stops at `limit`, so a page
// holding exactly Limit rows may be the head of a longer list; the reader says
// so rather than letting a caller read a cut-off list as a complete one.
func TestTaskList_FullPageIsReportedTruncated(t *testing.T) {
	row := func(i int) map[string]any {
		return map[string]any{"upid": "UPID:pvh-n1:x", "type": "qmdestroy", "id": "690", "starttime": 1000 + i}
	}
	cases := []struct {
		name  string
		rows  int
		limit int
		want  bool
	}{
		{"short page is complete", 2, 3, false},
		{"empty page is complete", 0, 3, false},
		{"full page may be cut off", 3, 3, true},
		{"one row, limit one", 1, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rows []map[string]any
			for i := 0; i < tc.rows; i++ {
				rows = append(rows, row(i))
			}
			q := okQuery()
			q.Limit = tc.limit
			page, err := tlClient(t, "200 OK", tlBody(rows...)).TaskList(context.Background(), q)
			if err != nil {
				t.Fatalf("TaskList: %v", err)
			}
			if len(page.Rows) != tc.rows {
				t.Fatalf("decoded %d rows, want %d", len(page.Rows), tc.rows)
			}
			if page.Truncated != tc.want {
				t.Errorf("Truncated = %v, want %v (%d rows, limit %d)", page.Truncated, tc.want, tc.rows, tc.limit)
			}
		})
	}
}

// INV-3. A row this reader cannot decode fails the whole read, and no rows
// leak out beside the error.
//
// encoding/json reports an UnmarshalTypeError for an off-type field and STILL
// fills the slice, leaving that field at its zero value. A reader that returned
// those rows would hand a caller a list in which an undecodable endtime reads
// as 0 — not terminal, but also not trustworthy — and the caller could not tell
// the difference. The test asserts the nil page, not just the error.
func TestTaskList_AnUndecodableRowFailsTheWholeRead(t *testing.T) {
	rows := []map[string]any{
		{"upid": "UPID:pvh-n1:1", "type": "qmdestroy", "id": "690", "starttime": 1000, "endtime": 2000},
		{"upid": "UPID:pvh-n1:2", "type": "qmdestroy", "id": "691", "starttime": 1000, "endtime": "not-a-number"},
	}
	page, err := tlClient(t, "200 OK", tlBody(rows...)).TaskList(context.Background(), okQuery())
	if err == nil {
		t.Fatal("an off-type endtime decoded without error")
	}
	if page != nil {
		t.Fatalf("TaskList returned %d row(s) alongside its error: a partially decoded list must not escape", len(page.Rows))
	}
	if !strings.Contains(err.Error(), "task list shape") {
		t.Errorf("error %q does not name the shape problem", err)
	}
}

// INV-6. Terminal is positive-evidence-only, and every other shape — including
// a status this code has never seen — is NOT terminal.
//
// This is the fail-closed direction and it is not symmetric. A caller about to
// dispatch an irreversible destroy must read "I cannot tell" as "it may still
// be running". A status-driven classification would have to enumerate PVE's
// terminal spellings and would call an unrecognised one terminal, which fails
// OPEN; the unknown-status rows below are exactly that mutant's victims.
func TestTaskRow_TerminalIsPositiveEvidenceOnly(t *testing.T) {
	cases := []struct {
		name string
		row  TaskRow
		want bool
	}{
		{"finished with OK", TaskRow{Status: "OK", EndTime: 1793000000}, true},
		{"finished with an error", TaskRow{Status: "some error", EndTime: 1793000000}, true},
		{"finished with WARNINGS", TaskRow{Status: "WARNINGS: 1", EndTime: 1793000000}, true},
		{"running: no endtime", TaskRow{Status: "running"}, false},
		{"no endtime, no status at all", TaskRow{}, false},
		{"endtime present but zero", TaskRow{Status: "OK", EndTime: 0}, false},
		{"a status this code has never seen, no endtime", TaskRow{Status: "stopping"}, false},
		{"a status this code has never seen, no endtime (2)", TaskRow{Status: "suspended"}, false},
		{"status OK but no endtime", TaskRow{Status: "OK"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.row.Terminal(); got != tc.want {
				t.Errorf("Terminal() = %v, want %v for %+v", got, tc.want, tc.row)
			}
		})
	}
}

// The wire carries status and endtime, and this reader decodes them. An earlier
// reading of taskRow concluded PVE supplied no task state; that was true of the
// struct and false of PVE.
func TestTaskList_DecodesStatusAndEndTime(t *testing.T) {
	rows := []map[string]any{{
		"upid": "UPID:pvh-n1:0002AC4B:0059ECA6:6ADE4E0C:qmdestroy:690:root@pam:",
		"type": "qmdestroy", "id": "690", "starttime": 1792953868,
		"status": "OK", "endtime": 1792953868, "node": "pvh-n1", "user": "root@pam",
	}}
	page, err := tlClient(t, "200 OK", tlBody(rows...)).TaskList(context.Background(), okQuery())
	if err != nil {
		t.Fatalf("TaskList: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("%d rows, want 1", len(page.Rows))
	}
	r := page.Rows[0]
	if r.Status != "OK" || r.EndTime != 1792953868 || r.Node != "pvh-n1" || r.User != "root@pam" {
		t.Errorf("decoded %+v: status/endtime/node/user not all carried through", r)
	}
	if !r.Terminal() {
		t.Error("a row with a positive endtime is not Terminal()")
	}
}

// item 69/70: FindTaskUPID filters on TYPE AND id, so a qmstart sharing the id
// is never mistaken for the qmcreate.
func TestFindTaskUPID_TypeAndID(t *testing.T) {
	// Both a qmcreate and a qmstart for id 150; the create is OLDER.
	rows := []map[string]any{
		{"upid": "UPID:pvh-n1:0001:0002:66AC0000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 1000},
		{"upid": "UPID:pvh-n1:0003:0004:66AC0005:qmstart:150:root@pam:", "type": "qmstart", "id": "150", "starttime": 2000},
	}
	body, _ := json.Marshal(map[string]any{"data": rows})
	c := tlClient(t, "200 OK", string(body))

	got, err := c.FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 0)
	if err != nil {
		t.Fatalf("FindTaskUPID: %v", err)
	}
	if got != "UPID:pvh-n1:0001:0002:66AC0000:qmcreate:150:root@pam:" {
		t.Errorf("got %q, want the qmcreate row (not the qmstart with the same id)", got)
	}

	// No qmcreate present → an error, never a silent wrong pick.
	only := []map[string]any{{"upid": "UPID:pvh-n1:0003:0004:66AC0005:qmstart:150:root@pam:", "type": "qmstart", "id": "150", "starttime": 2000}}
	b2, _ := json.Marshal(map[string]any{"data": only})
	if _, err := tlClient(t, "200 OK", string(b2)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 0); err == nil {
		t.Error("want an error when no qmcreate matches")
	}
}

// A `since` window excludes a STALE qmcreate (a reused id from an earlier run)
// and keeps the one in this run's create window.
func TestFindTaskUPID_SinceWindow(t *testing.T) {
	rows := []map[string]any{
		{"upid": "UPID:pvh-n1:00AA:00BB:66000000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 500},  // stale, before the window
		{"upid": "UPID:pvh-n1:00CC:00DD:66AC0000:qmcreate:150:root@pam:", "type": "qmcreate", "id": "150", "starttime": 1500}, // this run
	}
	body, _ := json.Marshal(map[string]any{"data": rows})
	got, err := tlClient(t, "200 OK", string(body)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 1000)
	if err != nil {
		t.Fatalf("FindTaskUPID: %v", err)
	}
	if got != "UPID:pvh-n1:00CC:00DD:66AC0000:qmcreate:150:root@pam:" {
		t.Errorf("got %q, want the in-window qmcreate (not the stale one before since)", got)
	}
	// If ONLY the stale row exists and the window excludes it → an error.
	stale := []map[string]any{rows[0]}
	sb, _ := json.Marshal(map[string]any{"data": stale})
	if _, err := tlClient(t, "200 OK", string(sb)).FindTaskUPID(context.Background(), "pvh-n1", "qmcreate", "150", 1000); err == nil {
		t.Error("want an error when the only qmcreate is before the since window")
	}
}
