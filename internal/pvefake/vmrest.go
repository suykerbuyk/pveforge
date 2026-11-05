package pvefake

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TaskRow is one row of PVE's task list as the WIRE carries it. EndTime 0
// means the field is ABSENT from the rendered row, which is what makes the
// row non-terminal: a consumer that classifies on "endtime present and
// non-zero" sees exactly what PVE would have shown it.
type TaskRow struct {
	UPID      string
	Type      string
	ID        string
	StartTime int64
	Status    string
	EndTime   int64
	Node      string
	User      string
}

// VMREST is the scripted VM/task server: the fixture a destroy-side
// determination is driven against.
//
// Its contract is FIDELITY. It honours every parameter it serves, REFUSES
// with PVE's own measured 400 shape every parameter it does not, and is never
// KINDER than PVE. Silently ignoring a parameter, or softening a trap, is the
// lie this fixture exists not to tell: a consumer tested against a fake that
// ignores `limit` passes while the production query is wrong.
//
// Three refusals are reproduced deliberately rather than smoothed away:
//
//   - limit=0 returns ZERO rows at HTTP 200. It does not mean "no limit".
//   - limit=-1 is a 400 "value must have a minimum value of 0".
//   - an unknown parameter (statusfilter, running, anything) is a 400
//     "property is not defined in schema".
//
// SINGLE-NODE BY CONSTRUCTION, and the reason is written here so the next
// reader does not rebuild a cluster-wide task view: a guest config lives on
// exactly one node, PVE's destroy_vm is proxyto => 'node' and forks its
// worker on the node holding the config, and the task index is node-local.
// Cross-node state is modelled by Resources — the PLACEMENT read — and by
// NextIDFree, NEVER by the task list.
//
// "PVE is unreachable" is not a field here: close the *httptest.Server that
// Server returns and its listener refuses, which is the real condition.
type VMREST struct {
	// Tasks is the node's task log, newest or oldest in any order; the
	// collection handler filters and truncates it per the query.
	Tasks []TaskRow

	// NodeStatus is the status code GET /nodes/{n}/status answers with; 0
	// means 200. A 403 carries PVE's own wording, naming Sys.Audit, and does
	// NOT change what the task collection answers — that asymmetry is the
	// hazard a visibility precondition exists for, and it is scripted here
	// independently on purpose.
	NodeStatus int

	// TasksStatus is the status code the task COLLECTION answers with; 0
	// means 200. Independent of NodeStatus.
	TasksStatus int

	// StallTasks delays the task-list response by up to this long, aborting
	// early when the request's context is cancelled, so a deadline test never
	// hangs the suite.
	StallTasks time.Duration

	// DestroyUPID is served verbatim for DELETE /nodes/{n}/qemu/{vmid}; the
	// fixture does NOT validate it, so a caller can drive a UPID carrying a
	// newline or an '=' through the renderer. A fixture stricter than PVE is
	// also a fixture that lies.
	DestroyUPID string
	// DestroyCode is the status code the DELETE answers with; 0 means 200.
	DestroyCode int
	// StopUPID is served verbatim for POST /nodes/{n}/qemu/{vmid}/status/stop.
	StopUPID string

	// NextIDFree makes GET /cluster/nextid?vmid=N echo N (free). Otherwise it
	// answers 400 with "VM N already exists" IN THE BODY: go-proxmox folds a
	// 400's body into StatusError.Error(), which a 500's it does not, and
	// net/http's SERVER cannot set a reason phrase.
	NextIDFree bool

	// Resources is the JSON array GET /cluster/resources answers with. It is
	// the PLACEMENT fixture — "which node is this guest on" — and it is the
	// ONLY way this server models another node. It is not a second task list.
	Resources string

	// VMConfig is the JSON the config read answers with; "" means a 404.
	VMConfig string
	// VMStatus is the JSON the status/current read answers with.
	VMStatus string

	// Reflect makes a mutation this server ACCEPTS appear in the task list as
	// a NON-TERMINAL row of the matching type, the way PVE's node-local index
	// does. Opt-in, and off by default, so a fixture that never asks for it
	// keeps the static behaviour every other case depends on.
	//
	// Without it a re-run determination cannot see what this process just
	// issued, so a "no self-collision" criterion passes vacuously.
	Reflect bool

	t    testing.TB
	node string
	seq  int64 // guarded by hitLog.mu
	hitLog
}

// taskListParams are the ONLY parameters the task collection accepts. PVE
// answers an unknown one with 400 "property is not defined in schema"
// (measured; a deliberately bogus zzznotaparam=1 returns the identical 400,
// so that is PVE's schema refusing it and not a client-side screen).
var taskListParams = map[string]bool{
	"source": true, "vmid": true, "limit": true, "since": true,
	"typefilter": true, "start": true, "errors": true,
}

// NewVMREST returns a server for node with an empty task log, an empty
// placement list and a stopped guest.
func NewVMREST(t testing.TB, node string) *VMREST {
	t.Helper()
	return &VMREST{t: t, node: node, Resources: `[]`, VMStatus: `{"status":"stopped"}`}
}

// reflect appends a non-terminal row for a mutation this fixture just
// accepted. hitLog.mu guards both Tasks and seq, so the fixture needs no
// second synchronisation primitive and no new package import.
//
// It appends ONE row of the type the endpoint implies and nothing else: it
// does not decide whether that row is hazardous, does not age it to terminal,
// and does not model PVE's worker scheduling. Making the fixture "realistic"
// past that point is how a fake starts testing itself.
func (s *VMREST) reflect(taskType, vmid, upid string) {
	if !s.Reflect {
		return
	}
	s.mu.Lock()
	s.seq++
	n := s.seq
	if upid == "" {
		upid = fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%s:root@pam:", s.node, n, n, n, taskType, vmid)
	}
	s.Tasks = append(s.Tasks, TaskRow{
		UPID: upid, Type: taskType, ID: vmid, StartTime: 1000 + n,
		Status: "running", Node: s.node, User: "root@pam",
	})
	s.mu.Unlock()
}

// vmidFromPath pulls the decimal vmid out of /…/qemu/<vmid>[/…].
func vmidFromPath(path string) string {
	i := strings.Index(path, "/qemu/")
	if i < 0 {
		return ""
	}
	rest := path[i+len("/qemu/"):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// Server starts the scripted server; the caller closes it. Closing it is also
// how "PVE is unreachable" is driven.
func (s *VMREST) Server() *httptest.Server {
	base := "/api2/json"
	nodeStatus := base + "/nodes/" + s.node + "/status"
	tasks := base + "/nodes/" + s.node + "/tasks"
	qemu := base + "/nodes/" + s.node + "/qemu/"

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == nodeStatus:
			if s.NodeStatus != 0 && s.NodeStatus != http.StatusOK {
				pveErr(w, s.NodeStatus, fmt.Sprintf("Permission check failed (/nodes/%s, Sys.Audit)", s.node))
				return
			}
			_, _ = fmt.Fprint(w, `{"data":{"uptime":1}}`)

		case r.URL.Path == tasks:
			s.serveTaskList(w, r)

		case strings.HasPrefix(r.URL.Path, tasks+"/"):
			s.serveTaskStatus(w, r)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/status/stop"):
			s.reflect("qmstop", vmidFromPath(r.URL.Path), s.StopUPID)
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.StopUPID)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, qemu):
			if s.DestroyCode != 0 && s.DestroyCode != http.StatusOK {
				pveErr(w, s.DestroyCode, "destroy refused")
				return
			}
			s.reflect("qmdestroy", vmidFromPath(r.URL.Path), s.DestroyUPID)
			_, _ = fmt.Fprintf(w, `{"data":%q}`, s.DestroyUPID)

		case r.URL.Path == base+"/cluster/nextid":
			vmid := r.URL.Query().Get("vmid")
			if s.NextIDFree {
				_, _ = fmt.Fprintf(w, `{"data":%q}`, vmid)
				return
			}
			pveErr(w, http.StatusBadRequest, fmt.Sprintf("VM %s already exists", vmid))

		case r.URL.Path == base+"/cluster/resources":
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.Resources)

		case strings.HasSuffix(r.URL.Path, "/status/current"):
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.VMStatus)

		case strings.HasSuffix(r.URL.Path, "/config"):
			if s.VMConfig == "" {
				pveErr(w, http.StatusNotFound, "Configuration file does not exist")
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.VMConfig)

		default:
			// An unscripted path FAILS the test rather than answering
			// something plausible. A fake that answers what it was never
			// told is the purest lie available.
			s.t.Errorf("pvefake VMREST: unscripted %s %s", r.Method, r.URL.Path)
			pveErr(w, http.StatusNotFound, "unscripted")
		}
	}))
}

// serveTaskStatus answers the per-task read with the row whose UPID the path
// names, as PVE's own /nodes/{n}/tasks/{upid}/status does. An unknown UPID is
// a null payload, not an invention.
func (s *VMREST) serveTaskStatus(w http.ResponseWriter, r *http.Request) {
	upid := strings.TrimSuffix(r.URL.Path[strings.LastIndex(r.URL.Path, "/tasks/")+len("/tasks/"):], "/status")
	s.mu.Lock()
	rows := make([]TaskRow, len(s.Tasks))
	copy(rows, s.Tasks)
	s.mu.Unlock()
	for _, t := range rows {
		if t.UPID == upid {
			_, _ = fmt.Fprintf(w, `{"data":%s}`, joinRows([]TaskRow{t}))
			return
		}
	}
	_, _ = fmt.Fprint(w, `{"data":null}`)
}

// serveTaskList is the fidelity surface. Every refusal below mirrors a
// measured PVE answer; every filter below is honoured rather than ignored.
//
// 🔴 THE COMPOSITION IS A CHOICE, NOT A MEASURED FACT. READ THIS BEFORE
// EDITING THE ORDER BELOW.
//
// This handler applies the filters (vmid, typefilter, source, since) FIRST and
// truncates to `limit` SECOND. That reading is taken from pve-manager's
// Tasks.pm:186-205, and it has NOT been verified against a live host. The
// other reading — PVE taking the first `limit` rows off the log and filtering
// what it took — is equally plausible from the API docs alone, and the two
// give DIFFERENT answers whenever more than `limit` non-matching rows precede
// a matching one: filter-then-limit returns the match, limit-then-filter
// returns an empty page.
//
// The consequence, which is why this is worth a paragraph rather than a line:
// a consumer treats "the page came back full" (len(rows) >= limit) as "this
// answer may be truncated, so it is not a negative result". Under
// filter-then-limit a page SHORTER than limit genuinely means the filtered set
// is exhausted and there is nothing more to find. Under limit-then-filter it
// means no such thing — a short, or even empty, filtered page can sit in front
// of any number of matching rows further down the log, so "shorter than limit"
// would stop implying "complete" and a truncation check built on it would read
// as a guarantee while being none.
//
// Pinned by TestVMREST_F10_FilterComposesBeforeLimit, which fails under the
// other ordering. If a live check ever settles this the other way, change the
// order HERE, change F10's expectation, and re-read every consumer that keys
// on a short page meaning completeness. The live check is one call: on a node
// with enough retained tasks, GET /nodes/{n}/tasks with source=all, a
// typefilter (or vmid) selecting a row that more than `limit` non-matching
// rows precede, and that `limit` — then see whether the matching row comes
// back. It is recorded as a live residual alongside the unit's other one.
func (s *VMREST) serveTaskList(w http.ResponseWriter, r *http.Request) {
	if s.StallTasks > 0 {
		select {
		case <-time.After(s.StallTasks):
		case <-r.Context().Done():
			return
		}
	}
	if s.TasksStatus != 0 && s.TasksStatus != http.StatusOK {
		pveErr(w, s.TasksStatus, "task list refused")
		return
	}
	q := r.URL.Query()
	for k := range q {
		if !taskListParams[k] {
			pveErr(w, http.StatusBadRequest, fmt.Sprintf("property is not defined in schema and the schema does not allow additional properties - %s", k))
			return
		}
	}
	limit, hasLimit := -1, false
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			pveErr(w, http.StatusBadRequest, "value must have a minimum value of 0")
			return
		}
		limit, hasLimit = n, true
	}

	s.mu.Lock()
	all := make([]TaskRow, len(s.Tasks))
	copy(all, s.Tasks)
	s.mu.Unlock()

	rows := make([]TaskRow, 0, len(all))
	for _, t := range all {
		if v := q.Get("vmid"); v != "" && t.ID != v {
			continue
		}
		if v := q.Get("typefilter"); v != "" && t.Type != v {
			continue
		}
		// source partitions the log: active holds what has not ended,
		// archive holds what has, all holds both. Measured: active and
		// archive return genuinely different sets on one node at one moment.
		switch q.Get("source") {
		case "active":
			if t.EndTime != 0 {
				continue
			}
		case "archive", "":
			if t.EndTime == 0 {
				continue
			}
		case "all":
		default:
			pveErr(w, http.StatusBadRequest, "invalid format - value does not match the regex pattern")
			return
		}
		if v := q.Get("since"); v != "" {
			n, _ := strconv.ParseInt(v, 10, 64)
			if t.StartTime < n {
				continue
			}
		}
		rows = append(rows, t)
	}
	// Truncation runs AFTER the filter loop above, never before it — see the
	// composition paragraph on this function. Moving these five lines above
	// the loop changes the answers this fixture gives (a Chair break-test
	// proved it: same query, 1 row here and 0 rows there), and
	// TestVMREST_F10_FilterComposesBeforeLimit exists to catch exactly that
	// move.
	//
	// limit=0 returns NOTHING. Truncating to exactly limit is also how a
	// caller scripts a full page, which a consumer must not read as a
	// negative answer.
	if hasLimit && len(rows) > limit {
		rows = rows[:limit]
	}
	_, _ = fmt.Fprintf(w, `{"data":[%s]}`, joinRows(rows))
}

// joinRows renders rows the way the wire carries them: status only when set,
// and endtime only when non-zero, so a non-terminal row genuinely LACKS the
// field rather than carrying a zero.
func joinRows(rows []TaskRow) string {
	out := make([]string, 0, len(rows))
	for _, t := range rows {
		f := fmt.Sprintf(`"upid":%q,"type":%q,"id":%q,"starttime":%d,"node":%q,"user":%q`,
			t.UPID, t.Type, t.ID, t.StartTime, t.Node, t.User)
		if t.Status != "" {
			f += fmt.Sprintf(`,"status":%q`, t.Status)
		}
		if t.EndTime != 0 {
			f += fmt.Sprintf(`,"endtime":%d`, t.EndTime)
		}
		out = append(out, "{"+f+"}")
	}
	return strings.Join(out, ",")
}

// pveErr writes PVE's body shape. net/http's SERVER cannot set a reason
// phrase, so a message that has to reach a *StatusError's Error() goes in the
// BODY — which works for a 400 and NOT for a 500.
func pveErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"message":%q,"data":null}`, msg)
}
