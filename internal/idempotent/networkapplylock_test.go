package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// This file is the end-to-end serialization proof for the per-node network
// apply lock (NetworkLockKey, networkbridge.go): two DIFFERENT network Ops
// on the SAME node but DIFFERENT interfaces, driven through real
// idempotent.Run calls against one shared fake PVE server, must never have
// their stage->commit->reload windows overlap.
//
// WHAT THIS FILE COVERS THAT internal/lock's OWN TESTS DO NOT.
// internal/lock/lock_test.go's TestMutation_SerializesConcurrentMutationsOnSameKey
// already proves the lock PRIMITIVE serializes raw simultaneous
// contention on one key — eight goroutines racing from a standing start,
// asserting at most one holder at a time. That is not this file's job and
// must not be duplicated here. This file's job is the one thing that test
// cannot see: whether the lock's hold actually SPANS the window the
// network Ops need it to span — PVE's commit is an ASYNC task, so "Apply
// finished" is not "the node finished reloading its network config", and
// idempotent.Run releases the lock the instant Apply returns.
//
// WHY THE SECOND OP STARTS ON A BARRIER, NOT SIMULTANEOUSLY.
// The second Op deliberately waits until the first Op has recorded its
// commit call before it even attempts idempotent.Run. This is NOT a
// weakening of the test and must not be "improved" back into a
// simultaneous start:
//
//   - Aiming the second Op at the first Op's already-open async-reload
//     window is strictly SHARPER than a coin-flip start: it is the exact
//     window this lock exists to cover, and a simultaneous start hits it
//     only by luck.
//   - A coin-flip start makes the sensitivity test
//     (TestNetworkApplyLock_HarnessFailsWhenTheLockReleasesBeforeTheReloadCompletes
//     below) FLAKY: if the early-releasing Op happens to lose the lock
//     race it runs second and no violation is observable at all. A flaky
//     sensitivity test is worse than none, because it eventually gets
//     muted — and then this whole file silently stops proving anything.
//   - Raw simultaneous contention is already covered upstream, in
//     internal/lock/lock_test.go, as described above.
//
// The second Op still genuinely contends for the real lock: when it calls
// idempotent.Run, the first Op is mid-WaitForTask and holding it.
//
// WHY THE FAKE MUST REPORT "running" AT LEAST TWICE.
// go-proxmox's Task.Wait (tasks.go:145 @ v0.8.1) pings ONCE up front
// ("ping it quick to fill in all the details"), then pings AGAIN at the
// top of its first loop iteration, and only sleeps for the poll interval
// after that second ping still reports running. So a fake that reports
// "running" for exactly one poll completes with the poll loop never
// sleeping at all — a ZERO-LENGTH reload window, which is precisely the
// vacuous-fake failure mode this test exists to avoid: it would show no
// interleaving while never once exercising the window the lock covers.
// applyLockRunningPolls is therefore 2, and the test ASSERTS the fake
// actually served that many running polls per commit, so trimming it back
// to 1 fails loudly instead of silently gutting the test.

const (
	applyLockNodeName     = "qa-pve-01"
	applyLockTargetID     = "qa-pve-01"
	applyLockMgmtIface    = "vmbr0"
	applyLockCreateIface  = "vmbr1"
	applyLockFieldsIface  = "vmbr2"
	applyLockRunningPolls = 2

	applyLockFirstLabel  = "bridge-ensure"
	applyLockSecondLabel = "fields-ensure"
)

// --- the shared fake PVE node -------------------------------------------

// applyLockReload is one simulated node-wide network reload: the async PVE
// task a commit PUT returns a UPID for. start is when the commit landed;
// end is when the task-status endpoint first reported success, and stays
// ZERO for as long as the simulated reload is still running — including
// forever, if nobody ever polls it to completion (which is exactly what an
// Op that releases its lock early looks like from the server's side).
type applyLockReload struct {
	upid   string
	ifaces []string
	start  time.Time
	end    time.Time
}

// applyLockNode is a small, stateful fake of ONE PVE node's network-config
// REST surface plus its task-status endpoint — enough for both
// NetworkBridgeEnsure and NetworkFieldsEnsure to run their real Apply
// sequences against it, and specifically modeling the thing a naive fake
// gets wrong: the commit is ASYNC, so staged changes become visible in the
// config immediately but the node's KERNEL state (see linkState) only
// catches up when the reload task reports success.
type applyLockNode struct {
	t    *testing.T
	node string

	// runningPolls is how many task-status polls report "running" before
	// the first "stopped"/OK — see this file's own doc comment on why 1 is
	// not enough.
	runningPolls int

	mu            sync.Mutex
	order         []string                     // stable list-endpoint order
	committed     map[string]map[string]string // applied config
	pending       map[string]map[string]string // staged (interfaces.new)
	pendingDelete map[string]bool              // staged removals
	live          map[string]bool              // kernel-visible interfaces
	upidSeq       int
	pollsServed   map[string]int
	runningServed map[string]int
	reloads       []*applyLockReload
}

func newApplyLockNode(t *testing.T) *applyLockNode {
	t.Helper()
	return &applyLockNode{
		t:            t,
		node:         applyLockNodeName,
		runningPolls: applyLockRunningPolls,
		order:        []string{applyLockMgmtIface, applyLockFieldsIface},
		committed: map[string]map[string]string{
			applyLockMgmtIface: {
				"iface": applyLockMgmtIface, "type": "bridge",
				"bridge_ports": "eth0", "cidr": "10.0.0.5/24", "active": "1",
			},
			applyLockFieldsIface: {
				"iface": applyLockFieldsIface, "type": "bridge",
				"bridge_ports": "eth2", "mtu": "1500", "active": "1",
			},
		},
		pending:       map[string]map[string]string{},
		pendingDelete: map[string]bool{},
		live: map[string]bool{
			applyLockMgmtIface:   true,
			applyLockFieldsIface: true,
		},
		pollsServed:   map[string]int{},
		runningServed: map[string]int{},
	}
}

func applyLockCloneFields(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// stanzaLocked renders what GET /nodes/{node}/network/{iface} reports right
// now: committed config with any staged change overlaid. A staged-but-never
// -committed interface carries NO "active" marker, which is the PVE-native
// half of NetworkBridgeEnsure's step-4 guard self-check; a staged DELETE is
// likewise not applied until commit, so the interface stays present and
// active — the inverse half of the same guard.
func (n *applyLockNode) stanzaLocked(iface string) (map[string]string, bool) {
	committed, isCommitted := n.committed[iface]

	if n.pendingDelete[iface] {
		if !isCommitted {
			return nil, false
		}
		return applyLockCloneFields(committed), true
	}

	staged, isStaged := n.pending[iface]
	if !isStaged {
		if !isCommitted {
			return nil, false
		}
		return applyLockCloneFields(committed), true
	}

	out := map[string]string{}
	if isCommitted {
		out = applyLockCloneFields(committed)
	}
	for k, v := range staged {
		out[k] = v
	}
	out["iface"] = iface
	if !isCommitted {
		delete(out, "active")
	}
	return out, true
}

func (n *applyLockNode) listLocked() []map[string]string {
	entries := make([]map[string]string, 0, len(n.order))
	for _, iface := range n.order {
		if fields, ok := n.stanzaLocked(iface); ok {
			entries = append(entries, fields)
		}
	}
	return entries
}

func (n *applyLockNode) appendOrderLocked(iface string) {
	for _, existing := range n.order {
		if existing == iface {
			return
		}
	}
	n.order = append(n.order, iface)
}

func (n *applyLockNode) stageCreate(form url.Values) {
	n.mu.Lock()
	defer n.mu.Unlock()
	iface := form.Get("iface")
	fields := map[string]string{}
	for k := range form {
		fields[k] = form.Get(k)
	}
	n.pending[iface] = fields
	delete(n.pendingDelete, iface)
	n.appendOrderLocked(iface)
}

func (n *applyLockNode) stageUpdate(iface string, form url.Values) {
	n.mu.Lock()
	defer n.mu.Unlock()
	fields := n.pending[iface]
	if fields == nil {
		fields = map[string]string{}
	}
	for k := range form {
		fields[k] = form.Get(k)
	}
	n.pending[iface] = fields
	delete(n.pendingDelete, iface)
	n.appendOrderLocked(iface)
}

func (n *applyLockNode) stageDelete(iface string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.pending, iface)
	n.pendingDelete[iface] = true
}

func (n *applyLockNode) revert() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pending = map[string]map[string]string{}
	n.pendingDelete = map[string]bool{}
}

// commit applies every staged change to the config and opens a simulated
// reload window. Note what it deliberately does NOT do: touch n.live. The
// kernel does not catch up until the async task reports success (see
// completeReloadLocked) — modeling that gap is this fake's entire reason
// for existing.
func (n *applyLockNode) commit() string {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.upidSeq++
	upid := fmt.Sprintf("UPID:%s:0000%04X:00ABCDEF:5F000000:srvreload:networking:root@pam:", n.node, n.upidSeq)

	touched := make([]string, 0, len(n.pending)+len(n.pendingDelete))
	for iface := range n.pendingDelete {
		touched = append(touched, iface)
		delete(n.committed, iface)
	}
	for iface, staged := range n.pending {
		touched = append(touched, iface)
		merged := map[string]string{}
		if cur, ok := n.committed[iface]; ok {
			merged = applyLockCloneFields(cur)
		}
		for k, v := range staged {
			merged[k] = v
		}
		merged["iface"] = iface
		merged["active"] = "1"
		n.committed[iface] = merged
	}
	sort.Strings(touched)

	n.pending = map[string]map[string]string{}
	n.pendingDelete = map[string]bool{}
	n.reloads = append(n.reloads, &applyLockReload{upid: upid, ifaces: touched, start: time.Now()})
	return upid
}

func (n *applyLockNode) completeReloadLocked(upid string) {
	for _, rl := range n.reloads {
		if rl.upid != upid || !rl.end.IsZero() {
			continue
		}
		rl.end = time.Now()
		for _, iface := range rl.ifaces {
			if _, ok := n.committed[iface]; ok {
				n.live[iface] = true
			} else {
				delete(n.live, iface)
			}
		}
	}
}

func (n *applyLockNode) reloadWindows() []applyLockReload {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]applyLockReload, 0, len(n.reloads))
	for _, rl := range n.reloads {
		out = append(out, *rl)
	}
	return out
}

func (n *applyLockNode) runningPollsServed(upid string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.runningServed[upid]
}

// linkState answers Client.LinkState for this fake node.
//
// STUBBED, DELIBERATELY — and this is the one primitive in this test that
// is NOT served by the shared fake PVE server. In production LinkState is
// an SSH primitive (internal/sshexec.LinkState runs `ip -j link show` over
// the standing SSH vector); it never touches PVE's REST API, so a fake
// REST server cannot serve it at all. The alternative —
// networkbridge_integration_test.go's real fake SSH server plus
// pve.SetSSHPortForIntegrationTests — was considered and rejected here for
// two reasons: LinkState is orthogonal to the stage->commit->reload window
// this test measures, and SetSSHPortForIntegrationTests is PROCESS-GLOBAL
// mutable state, which has no business inside a test whose whole subject
// is isolation between concurrent actors.
//
// WHAT THIS THEREFORE DOES NOT COVER: nothing in this file exercises the
// real SSH path, sshexec.LinkState's own `ip` output parsing, or
// RoutedClient's SSH dialing/routing. Those are covered by
// internal/sshexec's own tests and by
// networkbridge_integration_test.go's full-stack REST+SSH tests. Do not
// read a pass here as evidence about any of them.
//
// What it DOES model, faithfully and load-bearingly: an interface is
// kernel-visible only once its commit's reload task has actually completed
// — which is what makes NetworkBridgeEnsure's step-4 (pre-commit: not yet
// live) and step-8 (post-reload: live) guards meaningful against this fake.
func (n *applyLockNode) linkState(iface string) sshexec.LinkState {
	n.mu.Lock()
	defer n.mu.Unlock()
	live := n.live[iface]
	return sshexec.LinkState{Exists: live, Up: live}
}

func (n *applyLockNode) writeData(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		n.t.Errorf("applyLockNode: marshal response: %v", err)
		http.Error(w, "marshal failed", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

// writeTaskStatus is the endpoint backing WaitForTask. Every response
// echoes upid and node back deliberately, not for cosmetic realism:
// proxmox.Task's UnmarshalJSON copies every field present in the body onto
// the Task, so a body omitting these zeroes them and can nil-panic inside
// go-proxmox's own Ping on a later poll — the same upstream wrinkle
// internal/pve/task_test.go documents at length.
func (n *applyLockNode) writeTaskStatus(w http.ResponseWriter, upid string) {
	n.mu.Lock()
	n.pollsServed[upid]++
	running := n.pollsServed[upid] <= n.runningPolls
	if running {
		n.runningServed[upid]++
	} else {
		n.completeReloadLocked(upid)
	}
	n.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if running {
		_, _ = fmt.Fprintf(w, `{"data":{"status":"running","upid":%q,"node":%q}}`, upid, n.node)
		return
	}
	_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, upid, n.node)
}

func (n *applyLockNode) handle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		n.t.Errorf("applyLockNode: parse form for %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// pve.Client is constructed with BaseURLOverride pointed straight at
	// the httptest server, so paths arrive without the "/api2/json"
	// prefix a host-derived base URL would carry — tolerate both.
	path := strings.TrimPrefix(r.URL.Path, "/api2/json")
	collection := "/nodes/" + n.node + "/network"
	taskPrefix := "/nodes/" + n.node + "/tasks/"

	switch {
	case r.Method == http.MethodGet && path == collection:
		n.mu.Lock()
		entries := n.listLocked()
		n.mu.Unlock()
		n.writeData(w, entries)

	case r.Method == http.MethodGet && strings.HasPrefix(path, collection+"/"):
		iface := strings.TrimPrefix(path, collection+"/")
		n.mu.Lock()
		fields, ok := n.stanzaLocked(iface)
		n.mu.Unlock()
		if !ok {
			// pve.Client.RawRequest turns any non-2xx into an error
			// carrying this body verbatim ("raw request: pve returned
			// %s: %s"), and networkbridge.go's
			// isMissingNetworkInterfaceError accepts exactly this
			// unstructured shape: the interface noun, the quoted name,
			// then "does not exist", adjacent.
			http.Error(w, fmt.Sprintf("interface '%s' does not exist", iface), http.StatusInternalServerError)
			return
		}
		n.writeData(w, fields)

	case r.Method == http.MethodPost && path == collection:
		n.stageCreate(r.PostForm)
		n.writeData(w, nil)

	case r.Method == http.MethodPut && path == collection:
		n.writeData(w, n.commit())

	case r.Method == http.MethodDelete && path == collection:
		n.revert()
		n.writeData(w, nil)

	case r.Method == http.MethodPut && strings.HasPrefix(path, collection+"/"):
		n.stageUpdate(strings.TrimPrefix(path, collection+"/"), r.PostForm)
		n.writeData(w, nil)

	case r.Method == http.MethodDelete && strings.HasPrefix(path, collection+"/"):
		n.stageDelete(strings.TrimPrefix(path, collection+"/"))
		n.writeData(w, nil)

	case r.Method == http.MethodGet && strings.HasPrefix(path, taskPrefix) && strings.HasSuffix(path, "/status"):
		n.writeTaskStatus(w, strings.TrimSuffix(strings.TrimPrefix(path, taskPrefix), "/status"))

	default:
		n.t.Errorf("applyLockNode: unexpected request %s %s", r.Method, path)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}
}

// --- the event recorder --------------------------------------------------

const (
	applyLockEvRawRequest   = "rawrequest"
	applyLockEvCommit       = "commit"
	applyLockEvWaitStart    = "waitfortask-start"
	applyLockEvWaitReturned = "waitfortask-return"
)

type applyLockEvent struct {
	seq    int
	label  string
	kind   string
	detail string
	at     time.Time
}

// applyLockRecorder is the single, globally-ordered event log both Ops
// write to. Ordering assertions compare seq (a total order established
// under one mutex); reload-window containment compares at (wall-clock
// against the fake's own window timestamps).
type applyLockRecorder struct {
	mu     sync.Mutex
	events []applyLockEvent
}

func (r *applyLockRecorder) add(label, kind, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, applyLockEvent{
		seq:    len(r.events) + 1,
		label:  label,
		kind:   kind,
		detail: detail,
		at:     time.Now(),
	})
}

func (r *applyLockRecorder) snapshot() []applyLockEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]applyLockEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *applyLockRecorder) has(label, kind string) bool {
	for _, e := range r.snapshot() {
		if e.label == label && e.kind == kind {
			return true
		}
	}
	return false
}

// awaitEvent blocks until label has recorded at least one kind event, or
// timeout elapses. Used as the start barrier — see this file's own doc
// comment on why the second Op starts on a barrier rather than racing.
func (r *applyLockRecorder) awaitEvent(label, kind string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if r.has(label, kind) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *applyLockRecorder) format() string {
	events := r.snapshot()
	if len(events) == 0 {
		return "  (no events recorded)"
	}
	base := events[0].at
	var b strings.Builder
	for _, e := range events {
		fmt.Fprintf(&b, "  #%-3d %+9s  %-14s %-18s %s\n",
			e.seq, e.at.Sub(base).Round(time.Millisecond), e.label, e.kind, e.detail)
	}
	return strings.TrimRight(b.String(), "\n")
}

func applyLockFirstMatch(events []applyLockEvent, label, kind string) *applyLockEvent {
	for i := range events {
		if events[i].label == label && events[i].kind == kind {
			return &events[i]
		}
	}
	return nil
}

func applyLockLastMatch(events []applyLockEvent, label, kind string) *applyLockEvent {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].label == label && events[i].kind == kind {
			return &events[i]
		}
	}
	return nil
}

// --- the recording client ------------------------------------------------

// recordingNetworkClient is the composite client both Ops run against:
// RawRequest and WaitForTask are REAL — a genuine *pve.Client issuing real
// HTTP against the shared fake node, and therefore go-proxmox's real
// Task.Wait poll loop at the real production poll interval, not a
// synchronous stand-in — while LinkState is stubbed (see
// applyLockNode.linkState for why, and for what that does not cover).
//
// Every call is recorded with an op label so the assertions can tell the
// two Ops' requests apart, which an HTTP-level recorder on the server side
// could not do.
type recordingNetworkClient struct {
	label string
	node  *applyLockNode
	rest  *pve.Client
	rec   *applyLockRecorder
}

var (
	_ NetworkBridgeClient = (*recordingNetworkClient)(nil)
	_ NetworkFieldsClient = (*recordingNetworkClient)(nil)
)

func newRecordingNetworkClient(t *testing.T, label string, node *applyLockNode, srv *httptest.Server, rec *applyLockRecorder) *recordingNetworkClient {
	t.Helper()
	rest, err := pve.NewClient(pve.ClientConfig{
		BaseURLOverride: srv.URL,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("pve.NewClient: %v", err)
	}
	return &recordingNetworkClient{label: label, node: node, rest: rest, rec: rec}
}

func (c *recordingNetworkClient) Node() string { return c.node.node }

func (c *recordingNetworkClient) RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	// Recorded BEFORE the call: the assertion is about when a request
	// LANDS at the fake, not when its response came back.
	c.rec.add(c.label, applyLockEvRawRequest, method+" "+path)
	raw, err := c.rest.RawRequest(ctx, method, path, params)
	if err == nil && method == http.MethodPut && path == "/nodes/"+c.node.node+"/network" {
		if upid, scalarErr := kvjson.Scalar(raw); scalarErr == nil && upid != "" {
			c.rec.add(c.label, applyLockEvCommit, upid)
		}
	}
	return raw, err
}

func (c *recordingNetworkClient) WaitForTask(ctx context.Context, node, upid string) error {
	c.rec.add(c.label, applyLockEvWaitStart, upid)
	err := c.rest.WaitForTask(ctx, node, upid)
	c.rec.add(c.label, applyLockEvWaitReturned, upid)
	return err
}

func (c *recordingNetworkClient) LinkState(_ context.Context, iface string) (sshexec.LinkState, error) {
	return c.node.linkState(iface), nil
}

// --- the scenario harness ------------------------------------------------

type applyLockRun struct {
	node    *applyLockNode
	rec     *applyLockRecorder
	first   string
	second  string
	endedAt time.Time

	mu   sync.Mutex
	errs map[string]error
}

func (r *applyLockRun) setErr(label string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[label] = err
}

func (r *applyLockRun) errSummary() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	labels := make([]string, 0, len(r.errs))
	for label := range r.errs {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, fmt.Sprintf("%s=%v", label, r.errs[label]))
	}
	if len(parts) == 0 {
		return "(none recorded)"
	}
	return strings.Join(parts, ", ")
}

// runNetworkApplyLockScenario runs makeFirst's Op and makeSecond's Op
// concurrently through REAL idempotent.Run calls under the SAME
// NetworkLockKey — the very key cmd/pveforge/network.go builds at all
// three of its mutating call sites — against one shared fake PVE node.
func runNetworkApplyLockScenario(t *testing.T, makeFirst, makeSecond func(*recordingNetworkClient) Op) *applyLockRun {
	t.Helper()

	node := newApplyLockNode(t)
	srv := httptest.NewServer(http.HandlerFunc(node.handle))
	t.Cleanup(srv.Close)

	rec := &applyLockRecorder{}
	firstClient := newRecordingNetworkClient(t, applyLockFirstLabel, node, srv, rec)
	secondClient := newRecordingNetworkClient(t, applyLockSecondLabel, node, srv, rec)

	rosterPath := testRosterPath(t)
	key := NetworkLockKey(applyLockTargetID, node.node)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	run := &applyLockRun{
		node:   node,
		rec:    rec,
		first:  applyLockFirstLabel,
		second: applyLockSecondLabel,
		errs:   map[string]error{},
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := Run(ctx, rosterPath, key, makeFirst(firstClient), false)
		run.setErr(applyLockFirstLabel, err)
	}()

	go func() {
		defer wg.Done()
		// Barrier, not a race — see this file's own doc comment.
		if !rec.awaitEvent(applyLockFirstLabel, applyLockEvCommit, 90*time.Second) {
			t.Errorf("%s never reached a commit call: the second op has no reload window to aim at, so this run proves nothing", applyLockFirstLabel)
			return
		}
		_, err := Run(ctx, rosterPath, key, makeSecond(secondClient), false)
		run.setErr(applyLockSecondLabel, err)
	}()

	wg.Wait()
	run.endedAt = time.Now()
	return run
}

// applyLockViolations reports every way run's recorded event log shows the
// per-node lock failing to cover the FULL stage->commit->reload window.
// Returning strings (rather than failing directly) is what lets the
// sensitivity test assert these same checks actually FIRE.
func applyLockViolations(run *applyLockRun) []string {
	events := run.rec.snapshot()
	var violations []string

	// (1) Anti-vacuity: an Op that never committed exercised no window at
	// all, so any "no interleaving observed" conclusion from it is empty.
	for _, label := range []string{run.first, run.second} {
		if applyLockFirstMatch(events, label, applyLockEvCommit) == nil {
			violations = append(violations, fmt.Sprintf(
				"op %q never reached a commit call, so it never opened a reload window: this run proves nothing about serialization", label))
		}
	}

	// (2) The ordering assertion across the FULL window: the second Op's
	// FIRST RawRequest must land strictly after the first Op's WaitForTask
	// RETURNS — not merely after its commit response arrived. A first Op
	// with no WaitForTask return at all is the same defect in its most
	// direct form: it released the lock without ever waiting for the
	// reload.
	waitReturned := applyLockLastMatch(events, run.first, applyLockEvWaitReturned)
	secondFirstRequest := applyLockFirstMatch(events, run.second, applyLockEvRawRequest)
	switch {
	case waitReturned == nil:
		violations = append(violations, fmt.Sprintf(
			"op %q released the per-node lock without ever returning from WaitForTask: its commit task was never polled to completion, so the lock cannot have covered pve's async reload window", run.first))
	case secondFirstRequest == nil:
		violations = append(violations, fmt.Sprintf(
			"op %q never issued a RawRequest: there is nothing to order against op %q's reload", run.second, run.first))
	case secondFirstRequest.seq < waitReturned.seq:
		violations = append(violations, fmt.Sprintf(
			"op %q's first RawRequest (#%d %s) landed BEFORE op %q's WaitForTask returned (#%d): the lock released early, during the async reload",
			run.second, secondFirstRequest.seq, secondFirstRequest.detail, run.first, waitReturned.seq))
	}

	// (3) Window containment: no Op may touch the node while ANOTHER Op's
	// simulated reload is still running. A window whose end is still zero
	// never completed at all, so it is treated as open through the end of
	// the run.
	for _, window := range run.node.reloadWindows() {
		owner := ""
		for _, e := range events {
			if e.kind == applyLockEvCommit && e.detail == window.upid {
				owner = e.label
				break
			}
		}
		if owner == "" {
			continue
		}
		end, openEnded := window.end, false
		if end.IsZero() {
			end, openEnded = run.endedAt, true
		}

		var intruders []applyLockEvent
		for _, e := range events {
			if e.kind != applyLockEvRawRequest || e.label == owner {
				continue
			}
			if e.at.Before(window.start) || e.at.After(end) {
				continue
			}
			intruders = append(intruders, e)
		}
		if len(intruders) == 0 {
			continue
		}
		note := ""
		if openEnded {
			note = " (that reload NEVER completed — nobody polled it)"
		}
		extra := ""
		if len(intruders) > 1 {
			extra = fmt.Sprintf(" (and %d more)", len(intruders)-1)
		}
		violations = append(violations, fmt.Sprintf(
			"op %q issued %q (#%d) INSIDE op %q's simulated reload window for task %s%s%s",
			intruders[0].label, intruders[0].detail, intruders[0].seq, owner, window.upid, note, extra))
	}

	return violations
}

func applyLockBridgeOp(c *recordingNetworkClient) Op {
	return &NetworkBridgeEnsure{
		Client:           c,
		Node:             c.Node(),
		Iface:            applyLockCreateIface,
		ManagementBridge: applyLockMgmtIface,
		Wanted:           map[string]string{"type": "bridge", "bridge_ports": "eth1"},
	}
}

func applyLockFieldsOp(c *recordingNetworkClient) Op {
	return &NetworkFieldsEnsure{
		Client: c,
		Node:   c.Node(),
		Iface:  applyLockFieldsIface,
		Pairs:  []kvjson.Pair{{Field: "mtu", Value: "9000"}},
	}
}

// --- the tests -----------------------------------------------------------

// TestNetworkApplyLock_SerializesConcurrentNetworkOpsAcrossTheReloadWindow
// is this task's end-to-end serialization proof. NetworkBridgeEnsure
// (creating vmbr1) and NetworkFieldsEnsure (setting mtu on vmbr2) — two
// DIFFERENT Ops, SAME node, DIFFERENT interfaces — run concurrently
// through real idempotent.Run calls under the same NetworkLockKey against
// one shared fake PVE server whose commit is genuinely asynchronous.
//
// The assertion is ordering across the FULL window (see
// applyLockViolations), not just non-interleaved HTTP: the second Op's
// first RawRequest must land strictly after the first Op's WaitForTask
// returns, and neither Op may touch the node during the other's still-
// running simulated reload.
//
// See this file's own doc comment for why the second Op starts on a
// barrier rather than racing from a standing start (raw simultaneous
// contention is already covered by internal/lock/lock_test.go's
// TestMutation_SerializesConcurrentMutationsOnSameKey; this test's subject
// is the stage->commit->reload window specifically), and for why the fake
// must report "running" more than once.
func TestNetworkApplyLock_SerializesConcurrentNetworkOpsAcrossTheReloadWindow(t *testing.T) {
	run := runNetworkApplyLockScenario(t, applyLockBridgeOp, applyLockFieldsOp)

	if v := applyLockViolations(run); len(v) > 0 {
		t.Fatalf("the per-node network lock did not cover both ops' full stage->commit->reload windows:\n  - %s\n\nop errors: %s\n\nevent log:\n%s",
			strings.Join(v, "\n  - "), run.errSummary(), run.rec.format())
	}

	for _, label := range []string{run.first, run.second} {
		if err := run.errs[label]; err != nil {
			t.Fatalf("op %q: idempotent.Run: %v\n\nevent log:\n%s", label, err, run.rec.format())
		}
	}

	// Anti-vacuity, the part that matters most: prove the fake genuinely
	// simulated an async reload rather than resolving the commit task
	// synchronously. go-proxmox's Task.Wait pings once up front AND again
	// at the top of its first loop iteration before it ever sleeps, so
	// anything under applyLockRunningPolls running responses means the
	// poll loop never slept and the reload window had zero length — a test
	// that would show no interleaving while covering nothing.
	windows := run.node.reloadWindows()
	if len(windows) != 2 {
		t.Fatalf("expected exactly 2 simulated reloads (one per op), got %d", len(windows))
	}
	for _, w := range windows {
		if got := run.node.runningPollsServed(w.upid); got < applyLockRunningPolls {
			t.Fatalf("fake served only %d \"running\" task-status polls for %s, want >= %d: go-proxmox's Task.Wait pings once up front and again at the top of its first loop iteration BEFORE it ever sleeps, so fewer than %d completes with a ZERO-LENGTH reload window and this test covers nothing",
				got, w.upid, applyLockRunningPolls, applyLockRunningPolls)
		}
		if w.end.IsZero() {
			t.Fatalf("simulated reload %s never completed", w.upid)
		}
		if d := w.end.Sub(w.start); d <= 0 {
			t.Fatalf("simulated reload %s had non-positive duration %v: there was no window for the lock to cover", w.upid, d)
		}
	}
}

// earlyReleaseBridgeOp reproduces, on purpose, the exact regression
// NetworkBridgeEnsure.Apply's step 6b (networkbridge.go's
// `Client.WaitForTask` call) exists to prevent, and which the 2026-09-14
// review named as the reason this task could not be completed before 3a's
// fix landed: it stages and commits through the very same primitives the
// real Op uses, then RETURNS WITHOUT POLLING THE COMMIT TASK — so
// idempotent.Run releases the per-node lock while pve's reload is still
// running.
//
// This is the sensitivity proof's subject. It is test-only and must never
// be used as a template for a real Op.
type earlyReleaseBridgeOp struct {
	client NetworkBridgeClient
	node   string
	iface  string
	wanted map[string]string
}

var _ Op = (*earlyReleaseBridgeOp)(nil)

func (o *earlyReleaseBridgeOp) Read(ctx context.Context) (string, error) {
	fields, exists, err := fetchInterface(ctx, o.client, o.node, o.iface)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (o *earlyReleaseBridgeOp) Satisfied(string) bool { return false }

func (o *earlyReleaseBridgeOp) Apply(ctx context.Context) error {
	params := url.Values{}
	for field, value := range o.wanted {
		params.Set(field, value)
	}
	params.Set("iface", o.iface)
	if _, err := o.client.RawRequest(ctx, http.MethodPost, "/nodes/"+o.node+"/network", params); err != nil {
		return err
	}
	if _, err := commitNetworkStage(ctx, o.client, o.node); err != nil {
		return err
	}
	// THE DEFECT, DELIBERATELY: no WaitForTask. Apply returns, so
	// idempotent.Run's deferred unlock fires while the node is still
	// reloading.
	return nil
}

// TestNetworkApplyLock_HarnessFailsWhenTheLockReleasesBeforeTheReloadCompletes
// is the sensitivity proof for the test above: it drives the IDENTICAL
// harness and the IDENTICAL assertions with a first Op that releases the
// lock before its commit task completes, and asserts those assertions
// actually FIRE.
//
// Without this, TestNetworkApplyLock_SerializesConcurrentNetworkOpsAcrossTheReloadWindow
// would be a test never observed failing — which is not a test that has
// been shown to work. If a future edit weakens applyLockViolations (for
// instance by comparing only HTTP call ordering, or by letting a missing
// WaitForTask return pass silently), this test goes red.
func TestNetworkApplyLock_HarnessFailsWhenTheLockReleasesBeforeTheReloadCompletes(t *testing.T) {
	run := runNetworkApplyLockScenario(t,
		func(c *recordingNetworkClient) Op {
			return &earlyReleaseBridgeOp{
				client: c,
				node:   c.Node(),
				iface:  applyLockCreateIface,
				wanted: map[string]string{"type": "bridge", "bridge_ports": "eth1"},
			}
		},
		applyLockFieldsOp,
	)

	violations := applyLockViolations(run)
	if len(violations) == 0 {
		t.Fatalf("expected the serialization assertions to FIRE against an op that releases the lock before its commit task completes, but nothing was reported — the assertions are not sensitive to the defect they exist to catch\n\nevent log:\n%s",
			run.rec.format())
	}

	// It must fire for the RIGHT reason, not incidentally.
	wantOrdering := "released the per-node lock without ever returning from WaitForTask"
	wantWindow := "simulated reload window"
	var sawOrdering, sawWindow bool
	for _, v := range violations {
		if strings.Contains(v, wantOrdering) {
			sawOrdering = true
		}
		if strings.Contains(v, wantWindow) {
			sawWindow = true
		}
	}
	if !sawOrdering {
		t.Fatalf("expected a violation naming the un-awaited commit task (%q), got:\n  - %s\n\nevent log:\n%s",
			wantOrdering, strings.Join(violations, "\n  - "), run.rec.format())
	}
	if !sawWindow {
		t.Fatalf("expected a violation naming a request that landed inside the still-running simulated reload window, got:\n  - %s\n\nevent log:\n%s",
			strings.Join(violations, "\n  - "), run.rec.format())
	}

	// And the defect must be the one described: the first op's reload was
	// never polled to completion, so its window stayed open while the
	// second op was already mutating the node.
	windows := run.node.reloadWindows()
	if len(windows) == 0 {
		t.Fatal("expected at least one simulated reload window")
	}
	if !windows[0].end.IsZero() {
		t.Fatalf("expected the early-releasing op's reload %s to still be un-completed (nobody polled it), but it reported completion at %v",
			windows[0].upid, windows[0].end)
	}
	if got := run.node.runningPollsServed(windows[0].upid); got != 0 {
		t.Fatalf("expected the early-releasing op to have polled its commit task 0 times, got %d", got)
	}
}
