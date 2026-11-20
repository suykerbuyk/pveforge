package pvefake

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TaskRow is one row of PVE's task list as the WIRE carries it. EndTime 0
// means the field is ABSENT from the rendered row, which is what makes the
// row non-terminal: a consumer that classifies on "endtime present and
// non-zero" sees exactly what PVE would have shown it.
//
// Saved is PVE's `saved` bit — the ONLY thing that decides which half of the
// log a row is in, and NOT the same thing as EndTime. PVE keeps a task in its
// ACTIVE file until the task has finished AND been written to the archive
// index; a finished-but-not-yet-archived task (up to 25 of them, RESTEnvironment
// active_workers' $MAX_FINISHED) therefore has EndTime > 0 and Saved false, and
// `source=active` returns it. Saved defaults to FALSE, so a row meant to be an
// archived one must say Saved: true; a running row is Saved false by nature.
type TaskRow struct {
	UPID      string
	Type      string
	ID        string
	StartTime int64
	Status    string
	EndTime   int64
	Saved     bool
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
// ONE CONFIG NODE BY CONSTRUCTION, and the reason is written here so the next
// reader does not rebuild a cluster-wide task view (see Peers for the
// per-member, node-local indexes that ARE served): a guest config lives on
// exactly one node, PVE's destroy_vm is proxyto => 'node' and forks its
// worker on the node holding the config, and the task index is node-local.
// Cross-node state is modelled by Resources — the PLACEMENT read — and by
// NextIDFree, NEVER by a merged task list.
//
// What U5 added is NOT a cluster model. A roster client reaches another member's
// /nodes/{peer}/status and /nodes/{peer}/tasks through the roster node (PVE's
// own proxyto => 'node'), so this one server also answers those two paths for
// each name in Peers — each peer with its OWN, separately scripted, node-local
// task index, and no reasoning that spans nodes. The member list endpoints
// (/cluster/config/nodes and /nodes) are scripted, not computed.
//
// "PVE is unreachable" is not a field here: close the *httptest.Server that
// Server returns and its listener refuses, which is the real condition.
type VMREST struct {
	// Tasks is the node's task log, newest or oldest in any order; the
	// collection handler filters and truncates it per the query.
	Tasks []TaskRow

	// NodeStatus is the status code GET /nodes/{n}/status answers with; 0
	// means 200. A 403 carries PVE's own wording, naming Sys.Audit, and ONLY a
	// 403 does: any other code answers a generic body that does not name the
	// privilege, so a consumer that classifies by the body's text instead of the
	// status code is told apart from one that reads the code. The status does
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
	// the PLACEMENT fixture — "which node is this guest on". It is not a task
	// list; another member's node-local task index is scripted in Peers.
	Resources string

	// VMConfig is the JSON the config read answers with; "" means PVE's real
	// missing-config answer (a 500 naming nodes/<node>/qemu-server/<vmid>.conf),
	// not a 404.
	VMConfig string
	// VMStatus is the JSON the status/current read answers with.
	VMStatus string

	// Peers are the OTHER cluster members, reached through this server the way a
	// roster client reaches them through the roster node. See the type comment.
	Peers map[string]*PeerNode

	// TaskSnapshots scripts a node's task index as an ORDERED list of snapshots,
	// selected by how many times that node's task collection has been read (the
	// last snapshot repeats): "the first read sees the old row, the next one a
	// newer row". Keyed by node name, the roster node included. When a node has
	// an entry here it replaces Tasks / the peer's Tasks.
	TaskSnapshots map[string][][]TaskRow

	// Script replaces ANY endpoint's answer with an ordered list of replies,
	// selected by how many times that "METHOD path" has been requested (the last
	// reply repeats). It is how one test says "nextid answers Free, THEN the member
	// endpoints collapse to empty". Static fields stay the default.
	Script map[string][]Reply

	// NextID scripts GET /cluster/nextid?vmid=N per vmid; a vmid with no entry
	// falls back to NextIDFree.
	NextID map[string]NextIDAnswer

	// ClusterNodes and NodesIndex are the bodies (the JSON "data" value) of
	// GET /cluster/config/nodes and GET /nodes. Unset means a healthy cluster of
	// this node plus Peers. *Status is the status code, 0 meaning 200; a 403
	// carries PVE's own wording, naming Sys.Audit.
	ClusterNodes       string
	ClusterNodesStatus int
	NodesIndex         string
	NodesIndexStatus   int

	// ConfigStatus and StatusCurrentStatus script the node-local VM reads. 0 is
	// the default: 200 when VMConfig/VMStatus are set, else PVE's real
	// "Configuration file '...' does not exist" 500. 403 answers PVE's own
	// "Permission check failed (/vms/N, VM.Audit)" — what a token that cannot see
	// the VM gets whether or not it exists.
	ConfigStatus        int
	StatusCurrentStatus int

	// ResourcesStatus is the status code of GET /cluster/resources; 0 is 200.
	ResourcesStatus int

	// PoolStatus is the status code of GET /pools/{id}; 0 is 200 with an empty
	// pool. The production gone-proof must never read it (the harness's pool leg
	// is wrong for a token whose pool membership PVE removes first), so a fixture
	// that SERVES it lets a mutant that does read it be observed red.
	PoolStatus int

	// Reflect makes a mutation this server ACCEPTS appear in the task list as
	// a NON-TERMINAL row of the matching type — status RUNNING, no endtime,
	// Saved false, exactly what PVE's active branch serves — the way PVE's
	// node-local index does. Opt-in, and off by default, so a fixture that never asks for it
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

// PeerNode is another cluster member's node-local view, served through the
// roster node.
type PeerNode struct {
	Tasks       []TaskRow
	NodeStatus  int // 0 = 200; 403 names Sys.Audit
	TasksStatus int
	StallTasks  time.Duration
	// Offline answers both of this peer's paths with a proxy failure (595), the
	// way PVE answers for a member it cannot reach.
	Offline bool
}

// Reply is one scripted answer. Code 0 means 200 and Body is the JSON "data"
// value; any other code answers PVE's error shape with Message (or Body, as the
// complete response body, when Message is empty and Body is set).
type Reply struct {
	Code    int
	Body    string
	Message string
}

// NextIDAnswer scripts one vmid's /cluster/nextid answer. Code 0 is 200 and Body
// the JSON data value (`"690"` for PVE's string echo, `690` for a number, or any
// wrong-shaped body); another code answers Body as the complete response body.
type NextIDAnswer struct {
	Code int
	Body string
}

// NextIDInUseBody is the production in-use answer's body for vmid at 9.2.11: PVE
// puts the sentence under errors.vmid and the reason phrase is only "Parameter
// verification failed." (a net/http server cannot set a reason phrase, so a
// consumer must classify from the BODY).
func NextIDInUseBody(vmid string) string {
	return fmt.Sprintf(`{"message":"Parameter verification failed.\n","errors":{"vmid":"VM %s already exists"},"data":null}`, vmid)
}

// NextIDInUseMasterBody is the same for master (pve-manager 0b2f7eea).
func NextIDInUseMasterBody(vmid string) string {
	return fmt.Sprintf(`{"message":"Parameter verification failed.\n","errors":{"vmid":"guest ID %s is already in use"},"data":null}`, vmid)
}

// taskListParams are the ONLY parameters the task collection accepts. PVE
// answers an unknown one with 400 "property is not defined in schema"
// (measured; a deliberately bogus zzznotaparam=1 returns the identical 400,
// so that is PVE's schema refusing it and not a client-side screen).
//
// `start` is DELIBERATELY ABSENT, and that is STRICTER than PVE: PVE's schema
// does define `start` (minimum 0) and honours it. This fixture refuses a
// parameter the production determination must never send, because honouring it
// is a kindness (a non-zero `start` skips filter-passing rows before the limit
// test, so a short page stops meaning "the filtered set is exhausted") and
// silently ignoring it — what this fixture did before — is the other. Either
// would let a query that sends `start` pass here and be wrong on a real node.
var taskListParams = map[string]bool{
	"source": true, "vmid": true, "limit": true, "since": true,
	"typefilter": true, "errors": true,
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
		Status: "RUNNING", Node: s.node, User: "root@pam",
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
	qemu := base + "/nodes/" + s.node + "/qemu/"

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.add(r)
		w.Header().Set("Content-Type", "application/json")

		// A scripted reply, selected by how often this endpoint was requested,
		// outranks every static answer below.
		key := r.Method + " " + strings.TrimPrefix(r.URL.Path, base)
		if reps := s.Script[key]; len(reps) > 0 {
			n := s.countHits(r.Method + " " + r.URL.Path)
			if n > len(reps) {
				n = len(reps)
			}
			writeReply(w, reps[n-1])
			return
		}

		// /nodes/{n}/status and /nodes/{n}/tasks, for the roster node and for
		// every scripted peer.
		if node, leaf, ok := nodeLeaf(r.URL.Path, base); ok && (leaf == "status" || leaf == "tasks") {
			s.serveNodeLeaf(w, r, node, leaf)
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, base+"/nodes/"+s.node+"/tasks/"):
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
			if a, ok := s.NextID[vmid]; ok {
				if a.Code != 0 && a.Code != http.StatusOK {
					w.WriteHeader(a.Code)
					_, _ = fmt.Fprint(w, a.Body)
					return
				}
				_, _ = fmt.Fprintf(w, `{"data":%s}`, a.Body)
				return
			}
			if s.NextIDFree {
				_, _ = fmt.Fprintf(w, `{"data":%q}`, vmid)
				return
			}
			pveErr(w, http.StatusBadRequest, fmt.Sprintf("VM %s already exists", vmid))

		case r.URL.Path == base+"/cluster/config/nodes":
			s.serveMemberList(w, s.ClusterNodesStatus, s.ClusterNodes, "/")
		case r.URL.Path == base+"/nodes" && r.Method == http.MethodGet:
			s.serveMemberList(w, s.NodesIndexStatus, s.NodesIndex, "")

		case r.URL.Path == base+"/cluster/resources":
			if s.ResourcesStatus != 0 && s.ResourcesStatus != http.StatusOK {
				pveErr(w, s.ResourcesStatus, "resources refused")
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.Resources)

		case strings.HasPrefix(r.URL.Path, base+"/pools/"):
			if s.PoolStatus != 0 && s.PoolStatus != http.StatusOK {
				msg := fmt.Sprintf("pool read refused (%d)", s.PoolStatus)
				if s.PoolStatus == http.StatusForbidden {
					msg = "Permission check failed (/pool, Pool.Audit)"
				}
				pveErr(w, s.PoolStatus, msg)
				return
			}
			_, _ = fmt.Fprint(w, `{"data":{"members":[]}}`)

		case strings.HasSuffix(r.URL.Path, "/status/current"):
			if s.StatusCurrentStatus == http.StatusForbidden {
				pveErr(w, http.StatusForbidden, fmt.Sprintf("Permission check failed (/vms/%s, VM.Audit)", vmidFromPath(r.URL.Path)))
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":%s}`, s.VMStatus)

		case strings.HasSuffix(r.URL.Path, "/config"):
			vmid := vmidFromPath(r.URL.Path)
			switch {
			case s.ConfigStatus == http.StatusForbidden:
				pveErr(w, http.StatusForbidden, fmt.Sprintf("Permission check failed (/vms/%s, VM.Audit)", vmid))
			case s.ConfigStatus != 0 && s.ConfigStatus != http.StatusOK:
				pveErr(w, s.ConfigStatus, "config read refused")
			case s.VMConfig == "":
				// PVE's die() in load_config, surfaced as a 500: the text names the
				// vmid-specific config path, which is what a missing-config
				// classifier anchors on. NOT a 404.
				pveErr(w, http.StatusInternalServerError, fmt.Sprintf("Configuration file 'nodes/%s/qemu-server/%s.conf' does not exist", s.node, vmid))
			default:
				_, _ = fmt.Fprintf(w, `{"data":%s}`, s.VMConfig)
			}

		default:
			// An unscripted path FAILS the test rather than answering
			// something plausible. A fake that answers what it was never
			// told is the purest lie available.
			s.t.Errorf("pvefake VMREST: unscripted %s %s", r.Method, r.URL.Path)
			pveErr(w, http.StatusNotFound, "unscripted")
		}
	}))
}

// nodeLeaf splits /api2/json/nodes/{node}/{leaf} (exactly one segment after the
// node) into its parts.
func nodeLeaf(path, base string) (node, leaf string, ok bool) {
	rest, found := strings.CutPrefix(path, base+"/nodes/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// countHits is how many requests for exactly "METHOD path" have been seen,
// including the one being served (add runs first).
func (s *VMREST) countHits(hit string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		if h == hit {
			n++
		}
	}
	return n
}

// Count is the exported form of countHits for tests: how many times "METHOD path"
// (path as sent, e.g. "/api2/json/nodes/n1/tasks") has been requested. It is how
// a sequenced-script test asserts that its SECOND scripted answer was served,
// not just scripted.
func (s *VMREST) Count(method, path string) int { return s.countHits(method + " " + path) }

func writeReply(w http.ResponseWriter, rep Reply) {
	if rep.Code == 0 || rep.Code == http.StatusOK {
		body := rep.Body
		if body == "" {
			body = "null"
		}
		_, _ = fmt.Fprintf(w, `{"data":%s}`, body)
		return
	}
	if rep.Message == "" && rep.Body != "" {
		w.WriteHeader(rep.Code)
		_, _ = fmt.Fprint(w, rep.Body)
		return
	}
	pveErr(w, rep.Code, rep.Message)
}

// serveMemberList answers the two member-list endpoints. need names the path a
// 403 reports the missing privilege on ("" = a status code with no privilege
// sentence).
func (s *VMREST) serveMemberList(w http.ResponseWriter, code int, body, need string) {
	if code != 0 && code != http.StatusOK {
		msg := fmt.Sprintf("member list refused (%d)", code)
		if code == http.StatusForbidden && need != "" {
			msg = fmt.Sprintf("Permission check failed (%s, Sys.Audit)", need)
		}
		pveErr(w, code, msg)
		return
	}
	if body == "" {
		names := []string{s.node}
		for n := range s.Peers {
			names = append(names, n)
		}
		sort.Strings(names)
		var parts []string
		for _, n := range names {
			parts = append(parts, fmt.Sprintf(`{"node":%q}`, n))
		}
		body = "[" + strings.Join(parts, ",") + "]"
	}
	_, _ = fmt.Fprintf(w, `{"data":%s}`, body)
}

// serveNodeLeaf answers /nodes/{node}/status and /nodes/{node}/tasks for the
// roster node and for every scripted peer. An unknown node FAILS the test.
func (s *VMREST) serveNodeLeaf(w http.ResponseWriter, r *http.Request, node, leaf string) {
	var (
		nodeStatus, tasksStatus int
		stall                   time.Duration
		offline                 bool
	)
	switch {
	case node == s.node:
		nodeStatus, tasksStatus, stall = s.NodeStatus, s.TasksStatus, s.StallTasks
	case s.Peers[node] != nil:
		p := s.Peers[node]
		nodeStatus, tasksStatus, stall, offline = p.NodeStatus, p.TasksStatus, p.StallTasks, p.Offline
	default:
		s.t.Errorf("pvefake VMREST: unscripted node %q for %s %s", node, r.Method, r.URL.Path)
		pveErr(w, http.StatusNotFound, "unscripted")
		return
	}
	if offline {
		// How PVE answers for a member it cannot reach through the proxy.
		pveErr(w, 595, fmt.Sprintf("no route to host (%s)", node))
		return
	}
	if leaf == "status" {
		if nodeStatus != 0 && nodeStatus != http.StatusOK {
			msg := fmt.Sprintf("node status refused (%d)", nodeStatus)
			if nodeStatus == http.StatusForbidden {
				msg = fmt.Sprintf("Permission check failed (/nodes/%s, Sys.Audit)", node)
			}
			pveErr(w, nodeStatus, msg)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"uptime":1}}`)
		return
	}
	s.serveTaskList(w, r, node, tasksStatus, stall)
}

// rowsFor is node's task index for THIS read: its snapshot for the nth read when
// scripted, else its static rows.
func (s *VMREST) rowsFor(node string, path string) []TaskRow {
	n := s.countHits("GET " + path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if snaps := s.TaskSnapshots[node]; len(snaps) > 0 {
		i := n - 1
		if i >= len(snaps) {
			i = len(snaps) - 1
		}
		return append([]TaskRow(nil), snaps[i]...)
	}
	src := s.Tasks
	if node != s.node {
		src = s.Peers[node].Tasks
	}
	return append([]TaskRow(nil), src...)
}

// serveTaskStatus answers the per-task read (GET /nodes/{n}/tasks/{upid}/status)
// in the shape PVE's read_task_status serves — NOT the list-row shape: `status`
// is "running" or "stopped" (lower case; the LIST spells a running row RUNNING),
// and `exitstatus` appears only once stopped and carries the exit string
// (OK / WARNINGS: n / an error), which the LIST carries in `status`. An unknown
// UPID is a null payload, not an invention.
func (s *VMREST) serveTaskStatus(w http.ResponseWriter, r *http.Request) {
	upid := strings.TrimSuffix(r.URL.Path[strings.LastIndex(r.URL.Path, "/tasks/")+len("/tasks/"):], "/status")
	s.mu.Lock()
	rows := make([]TaskRow, len(s.Tasks))
	copy(rows, s.Tasks)
	s.mu.Unlock()
	for _, t := range rows {
		if t.UPID == upid {
			f := fmt.Sprintf(`"upid":%q,"type":%q,"id":%q,"starttime":%d,"node":%q,"user":%q,"pid":1,"pstart":1`,
				t.UPID, t.Type, t.ID, t.StartTime, t.Node, t.User)
			if t.EndTime != 0 {
				f += fmt.Sprintf(`,"status":"stopped","exitstatus":%q`, t.Status)
			} else {
				f += `,"status":"running"`
			}
			_, _ = fmt.Fprintf(w, `{"data":{%s}}`, f)
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
func (s *VMREST) serveTaskList(w http.ResponseWriter, r *http.Request, node string, tasksStatus int, stallFor time.Duration) {
	if stallFor > 0 {
		select {
		case <-time.After(stallFor):
		case <-r.Context().Done():
			return
		}
	}
	if tasksStatus != 0 && tasksStatus != http.StatusOK {
		pveErr(w, tasksStatus, "task list refused")
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

	all := s.rowsFor(node, r.URL.Path)

	rows := make([]TaskRow, 0, len(all))
	for _, t := range all {
		if v := q.Get("vmid"); v != "" && t.ID != v {
			continue
		}
		if v := q.Get("typefilter"); v != "" && t.Type != v {
			continue
		}
		// source partitions the log by the SAVED bit, never by EndTime: active
		// holds every row not yet written to the archive index (running ones
		// AND finished-but-unarchived ones), archive holds the saved ones, all
		// holds both, and an absent source is archive (PVE's default).
		// Measured: active and archive return genuinely different sets on one
		// node at one moment.
		switch q.Get("source") {
		case "active":
			if t.Saved {
				continue
			}
		case "archive", "":
			if !t.Saved {
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
