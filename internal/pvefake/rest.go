package pvefake

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// NetworkUPID is a well-formed PVE network-reload task UPID for node/iface.
func NetworkUPID(node, iface string) string {
	return fmt.Sprintf("UPID:%s:00001234:00ABCDEF:5F000000:qmnetwork:%s:root@pam:", node, iface)
}

// hitLog records every request a scripted server received: its endpoint
// ("METHOD path", Hits) and, for every request but a GET, what it carried
// (Writes). Endpoints and order alone do not prove a payload: a stage that
// sent the wrong value to the right path would pass a Hits check.
type hitLog struct {
	mu     sync.Mutex
	hits   []string
	writes []string
}

func (l *hitLog) add(r *http.Request) {
	var write string
	if r.Method != http.MethodGet {
		write = describeWrite(r)
	}
	l.mu.Lock()
	l.hits = append(l.hits, r.Method+" "+r.URL.Path)
	if r.Method != http.MethodGet {
		l.writes = append(l.writes, write)
	}
	l.mu.Unlock()
}

// describeWrite renders a mutating request deterministically as
// "METHOD path", then " ?<query>" if it has a query string and " <body>" if
// it has a body, each decoded as form values and re-encoded with sorted keys
// (a body that is not form-encoded is kept verbatim, prefixed "raw:"). So a
// request carrying nothing is exactly "METHOD path".
func describeWrite(r *http.Request) string {
	out := r.Method + " " + r.URL.Path
	if q := r.URL.Query(); len(q) > 0 {
		out += " ?" + q.Encode()
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) > 0 {
		if form, err := url.ParseQuery(string(body)); err == nil {
			out += " " + form.Encode()
		} else {
			out += " raw:" + string(body)
		}
	}
	return out
}

// Writes returns every non-GET request received so far, in arrival order,
// as describeWrite renders it.
func (l *hitLog) Writes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.writes))
	copy(out, l.writes)
	return out
}

// Hits returns every request received so far, in arrival order.
func (l *hitLog) Hits() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.hits))
	copy(out, l.hits)
	return out
}

// next returns replies[*n] and advances *n, repeating the last reply once
// the list runs out. The caller holds hitLog.mu.
func next(replies []string, n *int) string {
	i := *n
	*n++
	if i < len(replies) {
		return replies[i]
	}
	return replies[len(replies)-1]
}

// writeIface answers an interface GET with body, with PVE's
// missing-interface error for IfaceAbsent, or with HTTP 500 and the given
// body for IfaceServerError.
func writeIface(w http.ResponseWriter, body string) {
	if raw, ok := strings.CutPrefix(body, ifaceServerErrorMark); ok {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(raw))
		return
	}
	if body == IfaceAbsent {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":{"iface":"interface does not exist"},"data":null}`))
		return
	}
	_, _ = fmt.Fprintf(w, `{"data":%s}`, body)
}

// unexpected fails the test for a request the script does not know. It uses
// Errorf, not Fatalf: a handler runs on the server's goroutine, where
// FailNow is not allowed. The 500 makes the client fail too, so the test
// still stops on the path it did not expect.
func unexpected(t testing.TB, script string, w http.ResponseWriter, r *http.Request) {
	t.Errorf("pvefake: %s: unexpected request %s %s", script, r.Method, r.URL.Path)
	w.WriteHeader(http.StatusInternalServerError)
}

// taskStatusPrefix is the path prefix of node's task-status polls.
func taskStatusPrefix(node string) string {
	return fmt.Sprintf("/api2/json/nodes/%s/tasks/", node)
}

// IfaceAbsent, as an entry of an IfaceResponses list, answers that GET
// the way PVE reports a missing interface: HTTP 400 with an "iface"
// parameter error saying it does not exist.
const IfaceAbsent = "\x00absent"

// ifaceServerErrorMark prefixes an IfaceServerError entry.
const ifaceServerErrorMark = "\x00server-error:"

// IfaceServerError, as an entry of an IfaceResponses list, answers that GET
// with HTTP 500 and body as it is: a read that fails with server text, such
// as the final re-read after a network write
// (pveforge-run-post-apply-read-error-signal).
func IfaceServerError(body string) string {
	return ifaceServerErrorMark + body
}

// BridgeREST scripts exactly the PVE calls NetworkBridgeEnsure issues:
// GETs of the management bridge vmbr0 and of the target interface, the
// stage POST (create) or DELETE (destroy), an optional revert DELETE of the
// collection, the commit PUT, and the commit task's status poll, which
// reports it stopped OK at once. Set the exported fields, then call Server.
type BridgeREST struct {
	MgmtFields  string // JSON object for GET .../network/vmbr0
	IfaceFields string // JSON object for GET .../network/<iface>
	// IfaceResponses, when set, answers the interface GETs in order instead
	// of IfaceFields, repeating the last: a JSON object, or IfaceAbsent. A
	// whole idempotent.Run needs it — its Read sees the interface before
	// Apply changes it, and its final re-read sees it after.
	IfaceResponses []string
	StageResp      string // JSON for the stage POST/DELETE; default null
	RevertResp     string // JSON for the revert DELETE; default null
	CommitUPID     string // UPID the commit PUT returns

	t          testing.TB
	node       string
	ifaceCalls int // guarded by hitLog.mu
	hitLog
}

// NewBridgeREST returns a script for node with null stage/revert replies.
func NewBridgeREST(t testing.TB, node string) *BridgeREST {
	t.Helper()
	return &BridgeREST{t: t, node: node, StageResp: `null`, RevertResp: `null`}
}

// Server starts the scripted TLS server; the caller closes it.
func (s *BridgeREST) Server() *httptest.Server {
	mgmtPath := fmt.Sprintf("/api2/json/nodes/%s/network/vmbr0", s.node)
	collectionPath := fmt.Sprintf("/api2/json/nodes/%s/network", s.node)

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == mgmtPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.MgmtFields)

		case r.Method == http.MethodGet && r.URL.Path != mgmtPath && strings.HasPrefix(r.URL.Path, collectionPath+"/") && !strings.Contains(r.URL.Path, "/tasks/"):
			body := s.IfaceFields
			if len(s.IfaceResponses) > 0 {
				s.mu.Lock()
				body = next(s.IfaceResponses, &s.ifaceCalls)
				s.mu.Unlock()
			}
			writeIface(w, body)

		case r.Method == http.MethodPost && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.StageResp)

		case r.Method == http.MethodDelete && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.RevertResp)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, collectionPath+"/"):
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.StageResp)

		case r.Method == http.MethodPut && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.CommitUPID)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, taskStatusPrefix(s.node)) && strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, s.CommitUPID, s.node)

		default:
			unexpected(s.t, "BridgeREST", w, r)
		}
	}))
}

// FieldsREST scripts exactly the PVE calls NetworkFieldsEnsure issues: the
// raw LIST GETs of the collection (answered from ListResponses in order,
// repeating the last), the interface GETs of its Read (IfaceResponses, the
// same way), the stage PUT of the interface, an optional revert DELETE of
// the collection, the commit PUT, and the commit task's status poll. Set
// the exported fields, then call Server.
type FieldsREST struct {
	ListResponses []string // sequential JSON arrays for GET .../network
	// IfaceResponses answers GET .../network/<iface> in order, repeating
	// the last: a JSON object, or IfaceAbsent. Only a whole idempotent.Run
	// needs it (Read and its final re-read); Apply alone never reads it.
	IfaceResponses []string
	StageResp      string // JSON for the stage PUT; default null
	RevertResp     string // JSON for the revert DELETE; default null
	CommitUPID     string // UPID the commit PUT returns

	t          testing.TB
	node       string
	iface      string
	listCalls  int // guarded by hitLog.mu
	ifaceCalls int // guarded by hitLog.mu
	hitLog
}

// NewFieldsREST returns a script for node/iface with null stage/revert
// replies.
func NewFieldsREST(t testing.TB, node, iface string) *FieldsREST {
	t.Helper()
	return &FieldsREST{t: t, node: node, iface: iface, StageResp: `null`, RevertResp: `null`}
}

// Server starts the scripted TLS server; the caller closes it.
func (s *FieldsREST) Server() *httptest.Server {
	collectionPath := fmt.Sprintf("/api2/json/nodes/%s/network", s.node)
	ifacePath := fmt.Sprintf("%s/%s", collectionPath, s.iface)

	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == collectionPath:
			s.mu.Lock()
			body := next(s.ListResponses, &s.listCalls)
			s.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"data":%s}`, body)

		case r.Method == http.MethodGet && r.URL.Path == ifacePath && len(s.IfaceResponses) > 0:
			s.mu.Lock()
			body := next(s.IfaceResponses, &s.ifaceCalls)
			s.mu.Unlock()
			writeIface(w, body)

		case r.Method == http.MethodPut && r.URL.Path == ifacePath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.StageResp)

		case r.Method == http.MethodPut && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.CommitUPID)

		case r.Method == http.MethodDelete && r.URL.Path == collectionPath:
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.RevertResp)

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, taskStatusPrefix(s.node)) && strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, s.CommitUPID, s.node)

		default:
			unexpected(s.t, "FieldsREST", w, r)
		}
	}))
}
