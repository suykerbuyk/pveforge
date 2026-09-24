package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pve9xSnapshotList is the exact three-entry shape go-proxmox's own
// recorded PVE 9.x fixture serves for GET .../snapshot
// (tests/mocks/pve9x/virtual_machines.go:898-925): the synthetic
// "current" pseudo-entry with no vmstate, one real snapshot that captured
// RAM state (vmstate 1), and one real snapshot that did not (vmstate
// absent, decoding to 0).
const pve9xSnapshotList = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"snap1","description":"Before upgrade","snaptime":1693252591,"vmstate":1,"parent":"current"},
	{"name":"snap2","description":"After upgrade","snaptime":1693252600,"parent":"snap1"}
]}`

// snapshotFixture is a fake PVE serving every endpoint the snapshot
// primitives touch — the snapshot list (GET), the snapshot create (POST),
// a snapshot rollback (POST .../{name}/rollback), a snapshot delete
// (DELETE .../{name}), and the task-status poll WaitForTask drives — while
// counting each one, so a test can assert not just what a call returned
// but which endpoints it did and did not reach.
//
// listBodies is consumed one per GET; the last entry repeats once
// exhausted. A create-then-verify flow therefore reads listBodies[0] for
// its pre-flight collision check and listBodies[1] for its post-create
// verification, which is what lets the two dual-verify failure cases
// below differ only in that second body.
type snapshotFixture struct {
	t          *testing.T
	node       string
	vmid       int
	listBodies []string

	listCalls   int32
	createCalls int32
	createForm  url.Values

	// listStatus, when set, is the HTTP status served with the listBodies
	// entry at the same index (same last-repeats rule); a missing or zero
	// entry means 200. It exists so a test can replay the measured
	// read-status swallow exactly — a 595 carrying {"data":null}, which
	// go-proxmox decodes to an empty list with a nil error — rather than a
	// 200 that merely happens to decode the same way.
	listStatus []int

	// The rollback and snapshot-delete endpoints 5b adds. Paths are
	// recorded ESCAPED (r.URL.EscapedPath), so a test can see that a name
	// was path-escaped rather than only that it decoded back correctly.
	rollbackCalls int32
	deleteCalls   int32

	mu            sync.Mutex
	rollbackPaths []string
	deletePaths   []string
	deleteSeq     []string // snapshot names, in the order DELETEs arrived

	// deleteHTTPFail makes the DELETE for that snapshot name answer 500
	// with PVE-style text instead of a UPID; deleteNullUPID makes it answer
	// 200 {"data":null} — accepted, but with no task to wait on.
	deleteHTTPFail map[string]bool
	deleteNullUPID map[string]bool
	// rollbackHTTPFail and rollbackNullUPID are the same two knobs for the
	// rollback POST.
	rollbackHTTPFail bool
	rollbackNullUPID bool
	// taskFail maps a task key — "rollback", or "delete/<name>" — to the
	// exitstatus its worker task finishes with. Unlisted keys finish "OK".
	taskFail map[string]string
	nextPID  int32
	taskKeys map[string]string // upid -> task key, for tasks this fixture issued
}

// issueTask mints a real-shaped UPID for a mutating request and remembers
// which task key it belongs to. Real PVE puts the vmid, not the snapshot
// name, in a UPID's id field, so the pid field carries a per-fixture
// counter instead; WaitForTask and go-proxmox's NewTask never parse it.
func (f *snapshotFixture) issueTask(typ, key string) string {
	pid := atomic.AddInt32(&f.nextPID, 1)
	upid := fmt.Sprintf("UPID:%s:%08X:0000ABCD:5F000000:%s:%d:root@pam:", f.node, pid, typ, f.vmid)
	f.mu.Lock()
	if f.taskKeys == nil {
		f.taskKeys = make(map[string]string)
	}
	f.taskKeys[upid] = key
	f.mu.Unlock()
	return upid
}

func (f *snapshotFixture) recorded() (rollbackPaths, deletePaths, deleteSeq []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.rollbackPaths...), append([]string(nil), f.deletePaths...), append([]string(nil), f.deleteSeq...)
}

func (f *snapshotFixture) handler(w http.ResponseWriter, r *http.Request) {
	snapPath := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", f.node, f.vmid)
	// The rollback and delete routes match the ESCAPED path, so a request
	// that forgot to escape the node (or the name) falls through to the
	// default arm instead of being quietly accepted.
	escSnapPath := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", url.PathEscape(f.node), f.vmid)
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.URL.Path == snapPath && r.Method == http.MethodGet:
		n := int(atomic.AddInt32(&f.listCalls, 1))
		if len(f.listBodies) == 0 {
			f.t.Errorf("snapshot list requested but the fixture serves no list bodies")
			http.Error(w, "no list body", http.StatusInternalServerError)
			return
		}
		idx := n - 1
		if idx >= len(f.listBodies) {
			idx = len(f.listBodies) - 1
		}
		if idx < len(f.listStatus) && f.listStatus[idx] != 0 {
			w.WriteHeader(f.listStatus[idx])
		}
		_, _ = w.Write([]byte(f.listBodies[idx]))

	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.EscapedPath(), escSnapPath+"/") && strings.HasSuffix(r.URL.EscapedPath(), "/rollback"):
		atomic.AddInt32(&f.rollbackCalls, 1)
		f.mu.Lock()
		f.rollbackPaths = append(f.rollbackPaths, r.URL.EscapedPath())
		f.mu.Unlock()
		switch {
		case f.rollbackHTTPFail:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf("VM %d qmp command 'loadvm' failed - snapshot is locked (backup)", f.vmid)))
		case f.rollbackNullUPID:
			_, _ = w.Write([]byte(`{"data":null}`))
		default:
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, f.issueTask("qmrollback", "rollback"))))
		}

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.EscapedPath(), escSnapPath+"/"):
		atomic.AddInt32(&f.deleteCalls, 1)
		name, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), escSnapPath+"/"))
		if err != nil {
			f.t.Errorf("unescape delete path %q: %v", r.URL.EscapedPath(), err)
		}
		f.mu.Lock()
		f.deletePaths = append(f.deletePaths, r.URL.EscapedPath())
		f.deleteSeq = append(f.deleteSeq, name)
		failHTTP, nullUPID := f.deleteHTTPFail[name], f.deleteNullUPID[name]
		f.mu.Unlock()
		if failHTTP {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf("snapshot '%s' is locked (delete)", name)))
			return
		}
		if nullUPID {
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, f.issueTask("qmdelsnapshot", "delete/"+name))))

	case r.URL.Path == snapPath && r.Method == http.MethodPost:
		atomic.AddInt32(&f.createCalls, 1)
		if err := r.ParseForm(); err != nil {
			f.t.Errorf("ParseForm: %v", err)
		}
		f.createForm = r.PostForm
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, wellFormedUPID(f.node))))

	case strings.HasPrefix(r.URL.Path, fmt.Sprintf("/nodes/%s/tasks/", f.node)):
		// Always immediately stopped: none of these tests are about the
		// poll loop itself (task_test.go covers that), only about what the
		// caller does once the task has finished. A task this fixture
		// issued (rollback, delete) finishes with its taskFail status, or
		// OK; any other UPID — CreateSnapshot's, which predates issueTask —
		// keeps the original always-OK answer. The body always echoes the
		// real upid and node: see taskStatusHandler for why that matters.
		upid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/nodes/%s/tasks/", f.node)), "/status")
		f.mu.Lock()
		key, issued := f.taskKeys[upid]
		exit := f.taskFail[key]
		f.mu.Unlock()
		if !issued {
			upid = wellFormedUPID(f.node)
		}
		if exit == "" {
			exit = "OK"
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":%q,"upid":%q,"node":%q}}`,
			exit, upid, f.node)))

	default:
		f.t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

// newSnapshotFixture wires a fixture to a fake API server and a Client,
// and shortens the task poll timings so a create's WaitForTask doesn't
// wait out the real one-second production interval.
func newSnapshotFixture(t *testing.T, node string, vmid int, listBodies ...string) (*snapshotFixture, *Client) {
	t.Helper()
	withTaskTimings(t, time.Millisecond, 2*time.Second)
	f := &snapshotFixture{t: t, node: node, vmid: vmid, listBodies: listBodies}
	return f, testClient(t, newFakeAPIServer(t, f.handler))
}

// --- ListSnapshots -------------------------------------------------------

// TestListSnapshots_ReturnsRawListIncludingCurrent pins ListSnapshots'
// deliberate contract: it returns what PVE returned, "current" included.
// Filtering belongs to realSnapshots, and a future consumer that wants
// the whole chain must still be able to see it.
func TestListSnapshots_ReturnsRawListIncludingCurrent(t *testing.T) {
	var gotPath, gotMethod string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pve9xSnapshotList))
	})
	c := testClient(t, srv)

	snaps, err := c.ListSnapshots(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/snapshot" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100/snapshot", gotPath)
	}
	if len(snaps) != 3 {
		t.Fatalf("got %d entries, want 3 (the raw list, current included): %+v", len(snaps), snaps)
	}
	if snaps[0].Name != currentPseudoSnapshot {
		t.Errorf("entry 0 name = %q, want %q — ListSnapshots must not filter", snaps[0].Name, currentPseudoSnapshot)
	}
	if snaps[1].Name != "snap1" || snaps[1].Vmstate != 1 {
		t.Errorf("entry 1 = %q/vmstate %d, want snap1/vmstate 1", snaps[1].Name, snaps[1].Vmstate)
	}
	// snap2's fixture omits "vmstate" entirely — the absent-field case
	// that decodes to 0 and that the dual post-verify has to catch.
	if snaps[2].Name != "snap2" || snaps[2].Vmstate != 0 {
		t.Errorf("entry 2 = %q/vmstate %d, want snap2/vmstate 0", snaps[2].Name, snaps[2].Vmstate)
	}
	if snaps[1].Parent != "current" || snaps[1].Snaptime != 1693252591 {
		t.Errorf("entry 1 parent/snaptime = %q/%d, want current/1693252591", snaps[1].Parent, snaps[1].Snaptime)
	}
}

// TestListSnapshots_EscapesNodeInURL mirrors vms_test.go's
// TestGetVM_EscapesNodeInURL: an unescaped node containing '/' would
// silently corrupt the request path rather than failing loudly.
func TestListSnapshots_EscapesNodeInURL(t *testing.T) {
	var gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	if _, err := c.ListSnapshots(context.Background(), "weird node/name", 100); err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if want := "/nodes/weird%20node%2Fname/qemu/100/snapshot"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestListSnapshots_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("should not reach the network when node is empty")
	}))
	if _, err := c.ListSnapshots(context.Background(), "", 100); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

func TestListSnapshots_ServerError(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if _, err := c.ListSnapshots(context.Background(), "qa-pve-01", 100); err == nil {
		t.Fatal("expected an error for a rejected list")
	}
}

// --- realSnapshots -------------------------------------------------------

// TestRealSnapshots_DropsCurrentPseudoEntry covers the filter directly,
// including the two boundary shapes its callers can hand it: a nil slice
// and a nil element.
func TestRealSnapshots_DropsCurrentPseudoEntry(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pve9xSnapshotList))
	})
	c := testClient(t, srv)
	snaps, err := c.ListSnapshots(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}

	real := realSnapshots(snaps)
	if len(real) != 2 {
		t.Fatalf("got %d real snapshots, want 2 (current dropped): %+v", len(real), real)
	}
	for _, s := range real {
		if s.Name == currentPseudoSnapshot {
			t.Errorf("the %q pseudo-entry survived the filter", currentPseudoSnapshot)
		}
	}
	if real[0].Name != "snap1" || real[1].Name != "snap2" {
		t.Errorf("filtered order = %q,%q, want snap1,snap2", real[0].Name, real[1].Name)
	}
	if len(snaps) != 3 {
		t.Errorf("realSnapshots mutated its input: %d entries left, want 3", len(snaps))
	}

	if got := realSnapshots(nil); got == nil || len(got) != 0 {
		t.Errorf("realSnapshots(nil) = %v, want an empty non-nil slice", got)
	}
	if got := realSnapshots([]*proxmox.VirtualMachineSnapshot{nil}); len(got) != 0 {
		t.Errorf("realSnapshots dropped no nil element: %v", got)
	}
}

// --- CreateSnapshot: refusals --------------------------------------------

// TestCreateSnapshot_ReservedNameNeverTouchesAnyEndpoint is the test the
// Critical review finding exists for. It asserts the reserved-name guard
// is INDEPENDENT of realSnapshots rather than merely producing the right
// end result: against the exact three-entry pve9x fixture shape, creating
// a snapshot named "current" must come back *ErrReservedSnapshotName with
// NEITHER the list endpoint NOR the create endpoint ever reached. A guard
// folded back into the collision check would necessarily hit the list
// endpoint first — and, because realSnapshots removes "current" by
// construction before that comparison runs, would then find no collision
// and POST snapname=current at PVE for real.
func TestCreateSnapshot_ReservedNameNeverTouchesAnyEndpoint(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "current", "should never be sent")
	var reserved *ErrReservedSnapshotName
	if !errors.As(err, &reserved) {
		t.Fatalf("CreateSnapshot err = %v, want *ErrReservedSnapshotName", err)
	}
	if reserved.VMID != 100 || reserved.Name != "current" {
		t.Errorf("error carried vmid/name %d/%q, want 100/current", reserved.VMID, reserved.Name)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 0 {
		t.Errorf("the snapshot list endpoint was hit %d times, want 0: the reserved-name guard must run before ListSnapshots", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("the create endpoint was hit %d times, want 0: a snapshot named %q must never be POSTed", got, currentPseudoSnapshot)
	}
}

// TestCreateSnapshot_ReservedNameIsCaseInsensitive covers the EqualFold
// half of the guard — PVE reserves the concept, and "Current" must not be
// a way around the refusal.
func TestCreateSnapshot_ReservedNameIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"Current", "CURRENT", "cUrReNt"} {
		t.Run(name, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)
			err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, name, "")
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("CreateSnapshot(%q) err = %v, want *ErrReservedSnapshotName", name, err)
			}
			if got := atomic.LoadInt32(&f.listCalls) + atomic.LoadInt32(&f.createCalls); got != 0 {
				t.Errorf("%d endpoint(s) reached for %q, want 0", got, name)
			}
		})
	}
}

// TestCreateSnapshot_NullListEntryIsSkippedNotDereferenced is the input
// that proves CreateSnapshot's own two realSnapshots calls are load-bearing
// rather than redundant with the reserved-name guard.
//
// An earlier mutation pass replaced realSnapshots(existing)/realSnapshots(after)
// with the raw slices and every test still passed, which was recorded as an
// equivalent mutant on the reasoning that "current" is the only name the
// filter changes the answer for and the guard rejects it first. That
// reasoning was wrong: the filter ALSO drops nil elements, and nothing
// about a name-based guard upstream can substitute for that.
//
// PVE's list decodes into a slice of POINTERS, so a JSON null in the array
// becomes a nil element. This test first proves that decode really happens
// (rather than asserting against a hand-built fixture shape), then drives a
// full create across it. Without the filter at either loop, s.Name
// dereferences nil and CreateSnapshot panics — there is no panic recovery
// anywhere in this package.
func TestCreateSnapshot_NullListEntryIsSkippedNotDereferenced(t *testing.T) {
	const withNull = `{"data":[
		null,
		{"name":"current","description":"You are here!","snaptime":0},
		{"name":"snap1","snaptime":1693252591,"vmstate":1}
	]}`
	const afterNull = `{"data":[
		null,
		{"name":"current","description":"You are here!","snaptime":0},
		{"name":"snap1","snaptime":1693252591,"vmstate":1},
		{"name":"fresh","snaptime":1693252900,"vmstate":1,"parent":"snap1"}
	]}`
	// Three bodies: the standalone ListSnapshots below consumes the first,
	// then CreateSnapshot's pre-flight takes the second and its post-verify
	// the third.
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, withNull, withNull, afterNull)

	// Prove the premise before relying on it: a JSON null really does land
	// as a nil element on the real decode path.
	snaps, err := c.ListSnapshots(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 3 {
		t.Fatalf("got %d entries, want 3 (null included): %+v", len(snaps), snaps)
	}
	if snaps[0] != nil {
		t.Fatalf("expected the JSON null to decode to a nil element, got %+v", snaps[0])
	}

	// The create must cross that nil twice — pre-flight collision check and
	// post-create verification — without dereferencing it.
	if err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "fresh", ""); err != nil {
		t.Fatalf("CreateSnapshot across a list containing a null entry: %v", err)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 3 {
		t.Errorf("list endpoint hit %d times, want 3 (standalone + pre-flight + post-verify)", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create endpoint hit %d times, want 1", got)
	}
}

// TestCreateSnapshot_ReservedNameIgnoresSurroundingWhitespace closes the
// padding bypass. Case folding alone normalizes spelling but not padding,
// so " current", "current " and "\tcurrent" would otherwise clear the
// guard, clear the collision check (they match no real entry), and reach
// PVE's create endpoint with the padding intact. "PVE will reject it" is
// exactly the assumption this guard exists in order not to depend on.
func TestCreateSnapshot_ReservedNameIgnoresSurroundingWhitespace(t *testing.T) {
	for _, name := range []string{" current", "current ", "\tcurrent", "  CURRENT  ", "\ncurrent\t"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)
			err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, name, "")
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("CreateSnapshot(%q) err = %v, want *ErrReservedSnapshotName", name, err)
			}
			// The error reports what the caller actually passed, untrimmed —
			// the guard refuses the padded name, it does not rewrite it.
			if reserved.Name != name {
				t.Errorf("error reported name %q, want the caller's own %q", reserved.Name, name)
			}
			if got := atomic.LoadInt32(&f.listCalls) + atomic.LoadInt32(&f.createCalls); got != 0 {
				t.Errorf("%d endpoint(s) reached for %q, want 0", got, name)
			}
		})
	}
}

// TestCreateSnapshot_CollisionNeverTouchesCreateEndpoint covers the
// proactive, client-side duplicate refusal: the existing real snapshot
// snap1 must be found in the pre-flight list and the create endpoint must
// never be reached.
func TestCreateSnapshot_CollisionNeverTouchesCreateEndpoint(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "snap1", "")
	var exists *ErrSnapshotExists
	if !errors.As(err, &exists) {
		t.Fatalf("CreateSnapshot err = %v, want *ErrSnapshotExists", err)
	}
	if exists.VMID != 100 || exists.Name != "snap1" {
		t.Errorf("error carried vmid/name %d/%q, want 100/snap1", exists.VMID, exists.Name)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 1 {
		t.Errorf("the list endpoint was hit %d times, want exactly 1 (the pre-flight check)", got)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("the create endpoint was hit %d times, want 0: the collision must be refused before PVE is asked", got)
	}
}

// TestCreateSnapshot_CollisionIsCaseSensitive is the counterpart to the
// reserved-name guard's deliberate case-INsensitivity: PVE snapshot names
// themselves are case-sensitive, so "SNAP1" is a genuinely different name
// and must be allowed through to a real create.
func TestCreateSnapshot_CollisionIsCaseSensitive(t *testing.T) {
	after := `{"data":[
		{"name":"current","snaptime":0},
		{"name":"snap1","snaptime":1693252591,"vmstate":1},
		{"name":"SNAP1","snaptime":1693252700,"vmstate":1,"parent":"snap1"}
	]}`
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList, after)

	if err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "SNAP1", ""); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create endpoint hit %d times, want 1", got)
	}
}

// TestCreateSnapshot_RequiresNodeAndName covers the two local validation
// refusals. Each case asserts three things, not one: that an error came
// back, that the error names the specific missing input, and that NO
// request ever reached the network.
//
// The last two are what make this fail directly rather than incidentally
// if a guard is removed. Without the name guard an empty snapname falls
// straight through the reserved-name check (which "" is not), through
// ListSnapshots, and into a POST carrying snapname= — so the fake server
// deliberately serves a VALID empty list rather than failing on contact:
// the call still ends in some error, and a test that only checked
// err != nil would pass on the mutant. The network-count and
// error-text assertions are what actually kill it.
func TestCreateSnapshot_RequiresNodeAndName(t *testing.T) {
	for _, tc := range []struct {
		desc, node, name, wantIn string
	}{
		// The expected text pins the OPERATION as well as the missing
		// input. That matters for the node case specifically:
		// ListSnapshots has its own "node is required" guard, so a
		// substring check for that phrase alone passes even with
		// CreateSnapshot's own node guard deleted (measured — the
		// mutant survived until this assertion was tightened). Pinning
		// the "create snapshot" prefix is what distinguishes the two.
		{"empty node", "", "snap", "create snapshot on vm 100: node is required"},
		{"empty name", "qa-pve-01", "", "create snapshot on vm 100: name is required"},
		// Whitespace-only names are the same padding-defeats-a-guard class
		// as the reserved-name bypass, and they land in a worse spot: "   "
		// trims to "", which never equals "current", so the reserved-name
		// guard cannot catch them either. They must be refused HERE, by the
		// same error an empty name gets.
		{"spaces-only name", "qa-pve-01", "   ", "create snapshot on vm 100: name is required"},
		{"mixed-whitespace name", "qa-pve-01", "\t\n ", "create snapshot on vm 100: name is required"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var reqs int32
			c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&reqs, 1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":[]}`))
			}))

			err := c.CreateSnapshot(context.Background(), tc.node, 100, tc.name, "")
			if err == nil {
				t.Fatalf("expected an error for %s", tc.desc)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want one containing %q", err, tc.wantIn)
			}
			if got := atomic.LoadInt32(&reqs); got != 0 {
				t.Errorf("%d request(s) reached the network, want 0: a locally-invalid call must be refused before PVE is contacted at all", got)
			}
		})
	}
}

// --- CreateSnapshot: the happy path --------------------------------------

// TestCreateSnapshot_SendsVmstateAndVerifies is the full success path:
// pre-flight list, POST carrying snapname/vmstate/description, WaitForTask
// on the returned UPID, and a post-create list showing the new entry with
// a non-zero vmstate.
func TestCreateSnapshot_SendsVmstateAndVerifies(t *testing.T) {
	after := `{"data":[
		{"name":"current","snaptime":0},
		{"name":"snap1","snaptime":1693252591,"vmstate":1},
		{"name":"snap2","snaptime":1693252600},
		{"name":"pre-upgrade","snaptime":1693252800,"vmstate":1,"parent":"snap2"}
	]}`
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList, after)

	if err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "pre-upgrade", "before the 9.2 upgrade"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Fatalf("create endpoint hit %d times, want exactly 1", got)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 2 {
		t.Errorf("list endpoint hit %d times, want 2 (pre-flight + post-verify)", got)
	}
	if got := f.createForm.Get("snapname"); got != "pre-upgrade" {
		t.Errorf("form snapname = %q, want pre-upgrade", got)
	}
	if got := f.createForm.Get("vmstate"); got != "1" {
		t.Errorf("form vmstate = %q, want 1 — vmstate must ALWAYS be sent", got)
	}
	if got := f.createForm.Get("description"); got != "before the 9.2 upgrade" {
		t.Errorf("form description = %q, want the description passed in", got)
	}
}

// TestCreateSnapshot_OmitsEmptyDescription proves an empty description
// sends no description parameter at all rather than an empty one.
func TestCreateSnapshot_OmitsEmptyDescription(t *testing.T) {
	after := `{"data":[{"name":"current","snaptime":0},{"name":"plain","snaptime":1,"vmstate":1}]}`
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, `{"data":[{"name":"current","snaptime":0}]}`, after)

	if err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "plain", ""); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if _, ok := f.createForm["description"]; ok {
		t.Errorf("form carried a description key for an empty description: %v", f.createForm["description"])
	}
	if got := f.createForm.Get("vmstate"); got != "1" {
		t.Errorf("form vmstate = %q, want 1", got)
	}
}

// --- CreateSnapshot: the dual post-verify --------------------------------
//
// Two DISTINCT fixtures, deliberately not conflated into one: each proves
// one half of the dual check independently. A single fixture that was
// both absent AND vmstate-0 would pass even if only one half of the check
// existed.

// TestCreateSnapshot_VerifyFailsWhenEntryAbsent covers half one: PVE's
// task reported success, but the snapshot is not in the resulting list.
// The post-create list here is byte-for-byte the pre-flight list — the
// new entry simply never appeared.
func TestCreateSnapshot_VerifyFailsWhenEntryAbsent(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList, pve9xSnapshotList)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "ghost", "")
	if err == nil {
		t.Fatal("expected an error: the task succeeded but the snapshot is absent from the list")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error = %v, want one naming the snapshot's absence from the list", err)
	}
	// The create genuinely happened — this is a verification failure on a
	// real attempt, not one of the two pre-flight refusals.
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create endpoint hit %d times, want 1", got)
	}
	var exists *ErrSnapshotExists
	var reserved *ErrReservedSnapshotName
	if errors.As(err, &exists) || errors.As(err, &reserved) {
		t.Errorf("a post-verify failure must not masquerade as a pre-flight refusal: %v", err)
	}
}

// TestCreateSnapshot_VerifyFailsWhenVmstateZero covers half two: the
// snapshot IS in the list, so a list-membership check alone would pass —
// but it captured no RAM state, so it can only restore disks. The entry's
// fixture omits "vmstate" entirely, which is exactly how PVE reports a
// snapshot taken without it (see snap2 in the pve9x fixture).
func TestCreateSnapshot_VerifyFailsWhenVmstateZero(t *testing.T) {
	after := `{"data":[
		{"name":"current","snaptime":0},
		{"name":"snap1","snaptime":1693252591,"vmstate":1},
		{"name":"snap2","snaptime":1693252600},
		{"name":"half-done","snaptime":1693252800,"parent":"snap2"}
	]}`
	f, c := newSnapshotFixture(t, "qa-pve-01", 100, pve9xSnapshotList, after)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "half-done", "")
	if err == nil {
		t.Fatal("expected an error: the snapshot is listed but captured no vm state")
	}
	if !strings.Contains(err.Error(), "vmstate") {
		t.Errorf("error = %v, want one naming the missing vm state", err)
	}
	if strings.Contains(err.Error(), "absent") {
		t.Errorf("error = %v, want the vmstate failure, not the absence failure — the entry IS present", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create endpoint hit %d times, want 1", got)
	}
}

// TestCreateSnapshot_ReservedNameHoldsWhenCurrentLooksLikeASnapshot is
// the adversarial shape of the reserved-name test: the served list gives
// the "current" pseudo-entry a vmstate of 1, so it is indistinguishable
// from a real, successfully-created snapshot to any check that looks at
// the raw list. The refusal must still be the reserved-name one.
//
// It deliberately does NOT claim to prove that CreateSnapshot's own
// collision check and post-verify consult realSnapshots rather than the
// raw list. They do, but that is unobservable by construction and
// measured as such: mutating either loop to iterate the unfiltered list
// leaves every test in this file passing. "current" is the only name the
// filter changes the answer for, and the reserved-name guard rejects
// that name before either loop runs, so the filter at those two sites is
// unreachable defense in depth, not behavior. What IS load-bearing — and
// what the mutation evidence does cover — is that the guard runs first
// and independently.
func TestCreateSnapshot_ReservedNameHoldsWhenCurrentLooksLikeASnapshot(t *testing.T) {
	_, c := newSnapshotFixture(t, "qa-pve-01", 100,
		`{"data":[{"name":"current","snaptime":0,"vmstate":1}]}`,
		`{"data":[{"name":"current","snaptime":0,"vmstate":1}]}`)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "current", "")
	var reserved *ErrReservedSnapshotName
	if !errors.As(err, &reserved) {
		t.Fatalf("CreateSnapshot err = %v, want *ErrReservedSnapshotName", err)
	}
}

// TestCreateSnapshot_ServerErrorBodyIsVisible is the regression test for
// the design reason CreateSnapshot writes through RawRequest rather than
// go-proxmox's own VirtualMachine.NewSnapshot: go-proxmox's
// handleResponse discards the response body entirely on HTTP 500/501
// (proxmox.go:446-449), which is exactly the status PVE uses for most
// create-time rejections. PVE's own text must reach the caller.
func TestCreateSnapshot_ServerErrorBodyIsVisible(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"name":"current","snaptime":0}]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  VM 100 qmp command 'savevm-start' failed - not enough space  \n"))
	})
	c := testClient(t, srv)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "snap", "")
	if err == nil {
		t.Fatal("expected an error for a 500 from the create endpoint")
	}
	if !strings.Contains(err.Error(), "not enough space") {
		t.Errorf("error = %v, want PVE's own response body text preserved verbatim", err)
	}
}

// TestCreateSnapshot_TaskFailureIsReported proves a create whose PVE
// worker task ends unsuccessfully fails the call — and does so before any
// post-verify list, since the snapshot's state is whatever the failed task
// left behind.
func TestCreateSnapshot_TaskFailureIsReported(t *testing.T) {
	withTaskTimings(t, time.Millisecond, 2*time.Second)
	var listCalls int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/snapshot"):
			atomic.AddInt32(&listCalls, 1)
			_, _ = w.Write([]byte(`{"data":[{"name":"current","snaptime":0}]}`))
		case r.Method == http.MethodPost:
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, wellFormedUPID("qa-pve-01"))))
		default:
			_, _ = w.Write([]byte(fmt.Sprintf(
				`{"data":{"status":"stopped","exitstatus":"command 'qm snapshot' failed","upid":%q,"node":"qa-pve-01"}}`,
				wellFormedUPID("qa-pve-01"))))
		}
	})
	c := testClient(t, srv)

	err := c.CreateSnapshot(context.Background(), "qa-pve-01", 100, "snap", "")
	var failed *TaskFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("CreateSnapshot err = %v, want a wrapped *TaskFailedError", err)
	}
	if got := atomic.LoadInt32(&listCalls); got != 1 {
		t.Errorf("list endpoint hit %d times, want 1: a failed task must not be followed by a post-verify", got)
	}
}

// --- RoutedClient pass-throughs ------------------------------------------

// TestRoutedClient_Snapshot_Forwards proves both snapshot pass-throughs
// actually reach the REST client against this target's own node, rather
// than being dead/stubbed methods.
func TestRoutedClient_Snapshot_Forwards(t *testing.T) {
	withTaskTimings(t, time.Millisecond, 2*time.Second)
	var gotCreatePath string
	var gotForm url.Values
	var listCalls int32
	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/nodes/qa-pve-01/qemu/100/snapshot":
			if atomic.AddInt32(&listCalls, 1) == 1 {
				_, _ = w.Write([]byte(pve9xSnapshotList))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"name":"current","snaptime":0},{"name":"fresh","snaptime":9,"vmstate":1}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/nodes/qa-pve-01/qemu/100/snapshot":
			gotCreatePath = r.URL.Path
			if err := r.ParseForm(); err != nil {
				t.Errorf("ParseForm: %v", err)
			}
			gotForm = r.PostForm
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, wellFormedUPID("qa-pve-01"))))
		default:
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":"qa-pve-01"}}`,
				wellFormedUPID("qa-pve-01"))))
		}
	}))
	defer restSrv.Close()

	tg := &roster.Target{ID: "qa-pve-01", Host: "qa-pve-01.example.com", Node: "qa-pve-01"}
	// Built via NewClient (BaseURLOverride), not NewClientForTarget: see
	// routed_test.go's TestRoutedClient_TypedReadForwarding's identical note.
	rest := testClient(t, restSrv)
	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	ctx := context.Background()

	snaps, err := rc.ListSnapshots(ctx, 100)
	if err != nil || len(snaps) != 3 {
		t.Fatalf("ListSnapshots: snaps=%+v err=%v", snaps, err)
	}
	// Rewind the list sequence so CreateSnapshot below starts from the
	// same pre-flight body ListSnapshots just consumed, rather than
	// inheriting the post-create body (which already contains "fresh"
	// and would make the pre-flight check refuse a collision).
	atomic.StoreInt32(&listCalls, 0)

	if err := rc.CreateSnapshot(ctx, 100, "fresh", "via routed"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if gotCreatePath != "/nodes/qa-pve-01/qemu/100/snapshot" {
		t.Errorf("create path = %q, want the target's own node", gotCreatePath)
	}
	if gotForm.Get("snapname") != "fresh" || gotForm.Get("vmstate") != "1" || gotForm.Get("description") != "via routed" {
		t.Errorf("form = %v, want snapname=fresh vmstate=1 description='via routed'", gotForm)
	}
}

// --- 5b: shared values ---------------------------------------------------
//
// Every 5b test uses vmid 4242 and the names alpha/bravo/charlie/delta, never
// 100/101 or snap1/snap2 side by side: a ±1 on the vmid, a transposed
// argument or an index slip must produce a DIFFERENT literal, not a
// similar-looking one. Snaptimes are an hour apart, so > versus >= is only
// observable in the dedicated tie test.

const rbVMID = 4242

// chainABCD is four real snapshots, alpha oldest and delta newest, plus the
// "current" pseudo-entry, in chronological order.
const chainABCD = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"alpha","snaptime":1700000000,"vmstate":1,"parent":"current"},
	{"name":"bravo","snaptime":1700003600,"vmstate":1,"parent":"alpha"},
	{"name":"charlie","snaptime":1700007200,"vmstate":1,"parent":"bravo"},
	{"name":"delta","snaptime":1700010800,"vmstate":1,"parent":"charlie"}
]}`

// chainABC is chainABCD without delta.
const chainABC = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"alpha","snaptime":1700000000,"vmstate":1,"parent":"current"},
	{"name":"bravo","snaptime":1700003600,"vmstate":1,"parent":"alpha"},
	{"name":"charlie","snaptime":1700007200,"vmstate":1,"parent":"bravo"}
]}`

// chainA is only alpha — what chainABCD looks like after a cascade that
// deleted delta, charlie and bravo.
const chainA = `{"data":[
	{"name":"current","description":"You are here!","snaptime":0},
	{"name":"alpha","snaptime":1700000000,"vmstate":1,"parent":"current"}
]}`

// swallowedList is the body of the measured read-status swallow. Served with
// status 595 (PVE's own "cannot reach that node" range), go-proxmox's Get
// decodes it to an empty list and a NIL error.
const swallowedList = `{"data":null}`

// emptyList is a well-formed 200 carrying an empty snapshot list. It is the
// fixture every unverifiable-read GUARD test uses, rather than the 595
// replay above, because it is the one shape that only
// listSnapshotsVerifiable's own invariant — "current" is always present —
// can catch. A 595 is due to become a typed status error before any
// snapshot code runs, and a null payload is due to be refused by
// ListSnapshots itself; once either lands, a guard test built on
// swallowedList would still pass with the guard deleted. The 595 replays
// survive as cause-agnostic scenario tests (see
// TestSnapshotOps_SwallowedReadIsRefusedWithoutSideEffects).
const emptyList = `{"data":[]}`

func namesOf(snaps []*proxmox.VirtualMachineSnapshot) []string {
	out := make([]string, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, s.Name)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// countingValidListServer serves a VALID snapshot list to every request and
// counts them. Refusal tests use it so that `err != nil` alone cannot carry
// the test: a guard that is deleted lets the call reach a server that would
// happily answer, and the request count is what catches it.
func countingValidListServer(t *testing.T) (*Client, *int32) {
	t.Helper()
	var reqs int32
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqs, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(chainABCD))
	}))
	return c, &reqs
}

// --- NewerSnapshots / Rollback: local refusals ---------------------------

// TestRollback_ReservedNameNeverTouchesAnyEndpoint: a rollback to "current",
// padded or not, is refused with *ErrReservedSnapshotName before the network
// is touched. Exactly "current": a real snapshot named "Current" is a valid
// rollback target (TestSnapshotNameCase_S2).
//
// The prefix assertion is what makes this Rollback's OWN guard under test.
// NewerSnapshots carries the same guard and also refuses before any network
// call, so with Rollback's guard deleted the counters stay at zero and
// errors.As still matches — the callee masks the deletion. Only the prefix
// differs: Rollback's own refusal reads "rollback vm 4242: …", a refusal
// passed up from NewerSnapshots reads "rollback vm 4242 to snapshot …".
func TestRollback_ReservedNameNeverTouchesAnyEndpoint(t *testing.T) {
	for _, name := range []string{"current", " current\t"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
			err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, name)
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("Rollback(%q) err = %v, want *ErrReservedSnapshotName", name, err)
			}
			if reserved.Name != name || reserved.VMID != rbVMID {
				t.Errorf("refusal = %+v, want Name %q (as given, untrimmed) and VMID %d", reserved, name, rbVMID)
			}
			if want := fmt.Sprintf("rollback vm %d: ", rbVMID); !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error = %q, want prefix %q — Rollback's OWN guard must fire, not NewerSnapshots'", err, want)
			}
			if got := atomic.LoadInt32(&f.listCalls) + atomic.LoadInt32(&f.rollbackCalls); got != 0 {
				t.Errorf("%d request(s) reached the fake PVE, want 0", got)
			}
		})
	}
}

// TestNewerSnapshots_RequiresNodeAndTarget pins NewerSnapshots' own local
// refusals, including its reserved-name guard. The handler serves a VALID
// list, so a deleted guard is caught by the request count rather than
// hidden behind some later error. The expected text pins the operation
// prefix, because ListSnapshots has its own "node is required" guard and a
// bare substring check would survive deleting this one (5a measured exactly
// that mask — see TestCreateSnapshot_RequiresNodeAndName).
func TestNewerSnapshots_RequiresNodeAndTarget(t *testing.T) {
	for _, tc := range []struct {
		desc, node, target, wantPrefix string
		reserved                       bool
	}{
		{"empty node", "", "alpha", "newer snapshots of vm 4242: node is required", false},
		{"empty target", "qa-pve-01", "", "newer snapshots of vm 4242: snapshot name is required", false},
		{"spaces-only target", "qa-pve-01", "   ", "newer snapshots of vm 4242: snapshot name is required", false},
		{"mixed-whitespace target", "qa-pve-01", "\t\n ", "newer snapshots of vm 4242: snapshot name is required", false},
		// Without this guard "current" reaches the list read, realSnapshots
		// filters it, and the call fails AFTER the network as "not found".
		{"reserved target", "qa-pve-01", " current", "newer snapshots of vm 4242: ", true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, reqs := countingValidListServer(t)
			_, err := c.NewerSnapshots(context.Background(), tc.node, rbVMID, tc.target)
			if err == nil {
				t.Fatalf("expected an error for %s", tc.desc)
			}
			if !strings.HasPrefix(err.Error(), tc.wantPrefix) {
				t.Errorf("error = %v, want prefix %q — NewerSnapshots' own guard, not ListSnapshots'", err, tc.wantPrefix)
			}
			if tc.reserved {
				var reserved *ErrReservedSnapshotName
				if !errors.As(err, &reserved) {
					t.Errorf("error = %v, want *ErrReservedSnapshotName", err)
				}
			}
			if got := atomic.LoadInt32(reqs); got != 0 {
				t.Errorf("%d request(s) reached the network, want 0: a locally-invalid call must be refused before PVE is contacted at all", got)
			}
		})
	}
}

// TestRollback_RequiresNodeAndTarget pins Rollback's OWN node and name
// guards. NewerSnapshots and ListSnapshots would both still refuse a blank
// node or name before the network, in almost the same words, so the count
// alone cannot tell whose guard fired; the pinned "rollback vm 4242: "
// prefix can. A refusal passed up from the callee is prefixed
// "rollback vm 4242 to snapshot …" instead.
func TestRollback_RequiresNodeAndTarget(t *testing.T) {
	for _, tc := range []struct {
		desc, node, target, want string
	}{
		{"empty node", "", "alpha", "rollback vm 4242: node is required"},
		{"empty target", "qa-pve-01", "", "rollback vm 4242: snapshot name is required"},
		{"spaces-only target", "qa-pve-01", "   ", "rollback vm 4242: snapshot name is required"},
		{"mixed-whitespace target", "qa-pve-01", "\t\n ", "rollback vm 4242: snapshot name is required"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, reqs := countingValidListServer(t)
			err := c.Rollback(context.Background(), tc.node, rbVMID, tc.target)
			if err == nil {
				t.Fatalf("expected an error for %s", tc.desc)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want exactly %q — Rollback's own guard, not a callee's", err, tc.want)
			}
			if got := atomic.LoadInt32(reqs); got != 0 {
				t.Errorf("%d request(s) reached the network, want 0", got)
			}
		})
	}
}

// --- NewerSnapshots: the pre-flight --------------------------------------

// TestNewerSnapshots_NullListEntryIsSkippedNotDereferenced: a JSON null in
// the list decodes to a nil element, and realSnapshots is the only thing
// between it and a nil dereference — there is no panic recovery anywhere in
// this package.
func TestNewerSnapshots_NullListEntryIsSkippedNotDereferenced(t *testing.T) {
	const withNull = `{"data":[
		null,
		{"name":"current","snaptime":0},
		{"name":"alpha","snaptime":1700000000,"vmstate":1},
		null,
		{"name":"bravo","snaptime":1700003600,"vmstate":1,"parent":"alpha"}
	]}`
	_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, withNull)
	newer, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "alpha")
	if err != nil {
		t.Fatalf("NewerSnapshots across a list containing null entries: %v", err)
	}
	if got := namesOf(newer); !sameStrings(got, []string{"bravo"}) {
		t.Errorf("newer = %q, want [bravo]", got)
	}
}

// TestNewerSnapshots_AscendingOrder proves the result is SORTED, not merely
// passed through. The fixture serves the list in an order that is neither
// ascending nor the reverse of it, so deleting the sort, or reversing it,
// both change the answer. (A chronologically-ordered fixture would let a
// deleted sort pass by accident.)
func TestNewerSnapshots_AscendingOrder(t *testing.T) {
	const shuffled = `{"data":[
		{"name":"charlie","snaptime":1700007200,"vmstate":1},
		{"name":"current","snaptime":0},
		{"name":"delta","snaptime":1700010800,"vmstate":1},
		{"name":"bravo","snaptime":1700003600,"vmstate":1},
		{"name":"alpha","snaptime":1700000000,"vmstate":1}
	]}`
	_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, shuffled)
	newer, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "alpha")
	if err != nil {
		t.Fatalf("NewerSnapshots: %v", err)
	}
	if got, want := namesOf(newer), []string{"bravo", "charlie", "delta"}; !sameStrings(got, want) {
		t.Errorf("newer = %q, want %q (ascending by snaptime, oldest-of-the-newer first)", got, want)
	}
}

// TestNewerSnapshots_EqualSnaptimeIsRefused: Snaptime is whole seconds, so
// two snapshots can share one. Under a strict > alone, the older of a
// same-second pair reads as newest and a rollback to it silently discards
// its peer. NewerSnapshots must refuse instead — and must NOT report the
// peer as Newer, which would invite a cascade-delete of a snapshot that may
// be older. Both members of the pair are checked, and a Rollback to either
// must never reach the rollback endpoint.
func TestNewerSnapshots_EqualSnaptimeIsRefused(t *testing.T) {
	const tied = `{"data":[
		{"name":"current","snaptime":0},
		{"name":"alpha","snaptime":1700000000,"vmstate":1},
		{"name":"bravo","snaptime":1700003600,"vmstate":1,"parent":"alpha"},
		{"name":"charlie","snaptime":1700003600,"vmstate":1,"parent":"bravo"}
	]}`
	for _, target := range []string{"bravo", "charlie"} {
		t.Run(target, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, tied)
			newer, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, target)
			if err == nil {
				t.Fatalf("NewerSnapshots(%q) = %q, nil; want a same-snaptime refusal", target, namesOf(newer))
			}
			if !strings.Contains(err.Error(), "same snaptime") {
				t.Errorf("error = %v, want the same-snaptime refusal", err)
			}
			var notNewest *ErrNotNewestSnapshot
			if errors.As(err, &notNewest) {
				t.Errorf("error = %v is *ErrNotNewestSnapshot: an ambiguous peer must never be offered up as Newer", err)
			}

			rerr := c.Rollback(context.Background(), "qa-pve-01", rbVMID, target)
			if rerr == nil || !strings.Contains(rerr.Error(), "same snaptime") {
				t.Errorf("Rollback(%q) err = %v, want the same-snaptime refusal propagated", target, rerr)
			}
			if got := atomic.LoadInt32(&f.rollbackCalls); got != 0 {
				t.Errorf("rollback endpoint hit %d times, want 0", got)
			}
		})
	}
}

// TestNewerSnapshots_EmptyListIsUnverifiableNotNotFound: an empty snapshot
// list (emptyList — see its comment for why this shape and not the 595
// replay) cannot describe a live VM, which always has "current". Without
// listSnapshotsVerifiable the pre-flight read still fails closed — but as
// "snapshot not found", naming a cause that is false. So the test asserts
// the truthful cause (errors.Is ErrUnverifiableRead) AND the absence of the
// false one; err != nil alone could not tell them apart. Rollback on the
// same read must not reach the rollback endpoint.
func TestNewerSnapshots_EmptyListIsUnverifiableNotNotFound(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, emptyList)

	_, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "alpha")
	if !errors.Is(err, ErrUnverifiableRead) || !strings.HasPrefix(err.Error(), "newer snapshots of vm 4242: ") {
		t.Errorf("error = %v, want the newer-snapshots read refused with ErrUnverifiableRead", err)
	}
	if err != nil && strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v says \"not found\": an unverifiable read must not be reported as a missing snapshot", err)
	}

	rerr := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "alpha")
	if !errors.Is(rerr, ErrUnverifiableRead) || strings.Contains(rerr.Error(), "not found") {
		t.Errorf("Rollback err = %v, want ErrUnverifiableRead propagated", rerr)
	}
	if got := atomic.LoadInt32(&f.rollbackCalls); got != 0 {
		t.Errorf("rollback endpoint hit %d times, want 0", got)
	}
}

// --- Rollback ------------------------------------------------------------

// TestRollback_NotNewestNeverTouchesRollbackEndpoint is the proactive
// pre-flight itself: rolling back to alpha while bravo and charlie exist is
// refused with *ErrNotNewestSnapshot carrying the blocking set, and PVE's
// rollback endpoint is NEVER reached. Asserting the endpoint count, not
// just the error, is what catches a refusal that is computed and then
// fallen through.
func TestRollback_NotNewestNeverTouchesRollbackEndpoint(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "alpha")
	var notNewest *ErrNotNewestSnapshot
	if !errors.As(err, &notNewest) {
		t.Fatalf("Rollback err = %v, want *ErrNotNewestSnapshot", err)
	}
	if notNewest.VMID != rbVMID || notNewest.Target != "alpha" {
		t.Errorf("refusal = %+v, want VMID %d, Target alpha", notNewest, rbVMID)
	}
	if !sameStrings(notNewest.Newer, []string{"bravo", "charlie"}) {
		t.Errorf("Newer = %q, want [bravo charlie] (ascending)", notNewest.Newer)
	}
	if want := `rollback vm 4242 to snapshot "alpha" refused: 2 newer snapshots exist and would be discarded: "bravo", "charlie"`; err.Error() != want {
		t.Errorf("error text = %q, want %q", err, want)
	}
	if got := atomic.LoadInt32(&f.rollbackCalls); got != 0 {
		t.Errorf("rollback endpoint hit %d times, want 0: a refused rollback must never be POSTed", got)
	}
}

// TestRollback_NewestProceeds is the other half: a rollback to the actual
// newest snapshot is not refused, reaches the rollback endpoint exactly
// once, and waits for its task.
func TestRollback_NewestProceeds(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	if err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "charlie"); err != nil {
		t.Fatalf("Rollback to the newest snapshot: %v", err)
	}
	if got := atomic.LoadInt32(&f.rollbackCalls); got != 1 {
		t.Errorf("rollback endpoint hit %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 1 {
		t.Errorf("list endpoint hit %d times, want 1 (the pre-flight)", got)
	}
}

// TestRollback_TaskFailureIsReported: PVE's rollback is asynchronous, so the
// POST succeeding proves nothing. A worker task that finishes unsuccessfully
// must fail the call as a *TaskFailedError — which only happens if Rollback
// actually waits for the task.
func TestRollback_TaskFailureIsReported(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	f.taskFail = map[string]string{"rollback": "command 'qm rollback' failed"}
	err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "charlie")
	var failed *TaskFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Rollback err = %v, want a wrapped *TaskFailedError", err)
	}
	if failed.ExitStatus != "command 'qm rollback' failed" {
		t.Errorf("exit status = %q, want PVE's own", failed.ExitStatus)
	}
}

// TestRollback_EndpointAndEscaping pins the literal rollback path: this VM,
// this snapshot, path-escaped. A vmid off by one or a snapshot name that
// escapes its path segment would roll back something else.
func TestRollback_EndpointAndEscaping(t *testing.T) {
	for _, tc := range []struct {
		desc, list, name, wantPath string
	}{
		{"plain name", chainABC, "charlie", "/nodes/qa-pve-01/qemu/4242/snapshot/charlie/rollback"},
		{"name needing escaping", `{"data":[
			{"name":"current","snaptime":0},
			{"name":"alpha","snaptime":1700000000,"vmstate":1},
			{"name":"odd/name","snaptime":1700003600,"vmstate":1}
		]}`, "odd/name", "/nodes/qa-pve-01/qemu/4242/snapshot/odd%2Fname/rollback"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, tc.list)
			if err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, tc.name); err != nil {
				t.Fatalf("Rollback: %v", err)
			}
			paths, _, _ := f.recorded()
			if len(paths) != 1 || paths[0] != tc.wantPath {
				t.Errorf("rollback paths = %q, want exactly [%q]", paths, tc.wantPath)
			}
		})
	}
}

// --- ErrNotNewestSnapshot ------------------------------------------------

// TestErrNotNewestSnapshot_CascadeOrderIsNewestFirst: Newer is ascending and
// CascadeDeleteSnapshots wants newest-first. CascadeOrder is the one place
// that reversal lives, so it must reverse, and must not reverse Newer in
// place. Three distinct names: they catch an unreversed return, and also a
// rotation or a partial swap, which two names cannot tell apart from a
// correct reversal.
func TestErrNotNewestSnapshot_CascadeOrderIsNewestFirst(t *testing.T) {
	e := &ErrNotNewestSnapshot{VMID: rbVMID, Target: "alpha", Newer: []string{"bravo", "charlie", "delta"}}
	if got, want := e.CascadeOrder(), []string{"delta", "charlie", "bravo"}; !sameStrings(got, want) {
		t.Errorf("CascadeOrder() = %q, want %q", got, want)
	}
	if !sameStrings(e.Newer, []string{"bravo", "charlie", "delta"}) {
		t.Errorf("CascadeOrder modified Newer in place: %q", e.Newer)
	}
}

// --- CascadeDeleteSnapshots: local refusals ------------------------------

// TestCascadeDeleteSnapshots_ReservedNameNeverTouchesAnyEndpoint: an entry
// naming "current", anywhere in names and padded or not, refuses the whole
// call before the list is read. Exactly "current": a "Current" is a real
// snapshot a cascade must be able to delete (TestSnapshotNameCase_S1).
// (Without the guard the pre-state read happens, realSnapshots filters
// "current" out, and the name is skipped as absent — so no DELETE is sent
// either way. What the guard buys is refusing a nonsensical request
// outright, before PVE is contacted; the zero list count is what pins
// that.)
func TestCascadeDeleteSnapshots_ReservedNameNeverTouchesAnyEndpoint(t *testing.T) {
	for _, names := range [][]string{{"current"}, {"bravo", " current"}} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
			deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, names)
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("err = %v, want *ErrReservedSnapshotName", err)
			}
			if len(deleted) != 0 {
				t.Errorf("deleted = %q, want nothing", deleted)
			}
			if got := atomic.LoadInt32(&f.listCalls) + atomic.LoadInt32(&f.deleteCalls); got != 0 {
				t.Errorf("%d request(s) reached the fake PVE, want 0: the reserved-name guard must precede the list read", got)
			}
		})
	}
}

// TestCascadeDeleteSnapshots_RequiresNodeAndNames pins the remaining local
// refusals, against a server serving a VALID list so a deleted guard shows
// up as a request rather than hiding behind a later error.
func TestCascadeDeleteSnapshots_RequiresNodeAndNames(t *testing.T) {
	for _, tc := range []struct {
		desc, node string
		names      []string
		want       string
	}{
		{"empty node", "", []string{"delta"}, "cascade delete snapshots of vm 4242: node is required"},
		{"nil names", "qa-pve-01", nil, "cascade delete snapshots of vm 4242: at least one snapshot name is required"},
		{"empty names", "qa-pve-01", []string{}, "cascade delete snapshots of vm 4242: at least one snapshot name is required"},
		{"blank entry", "qa-pve-01", []string{""}, "cascade delete snapshots of vm 4242: snapshot name 1 of 1 is blank"},
		{"whitespace entry after a valid one", "qa-pve-01", []string{"delta", " \t"}, "cascade delete snapshots of vm 4242: snapshot name 2 of 2 is blank"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c, reqs := countingValidListServer(t)
			deleted, err := c.CascadeDeleteSnapshots(context.Background(), tc.node, rbVMID, tc.names)
			if err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want exactly %q", err, tc.want)
			}
			if len(deleted) != 0 {
				t.Errorf("deleted = %q, want nothing", deleted)
			}
			if got := atomic.LoadInt32(reqs); got != 0 {
				t.Errorf("%d request(s) reached the network, want 0", got)
			}
		})
	}
}

// --- CascadeDeleteSnapshots: the cascade ---------------------------------

// TestCascadeDeleteSnapshots_DeletesInGivenOrder: DELETEs go out strictly in
// the caller's order, one per name, and deleted reports exactly them. Three
// distinct names, recorded as a sequence: with one or two, a reversed loop
// is unobservable or indistinguishable from a coincidence.
func TestCascadeDeleteSnapshots_DeletesInGivenOrder(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD, chainA)
	names := []string{"delta", "charlie", "bravo"}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, names)
	if err != nil {
		t.Fatalf("CascadeDeleteSnapshots: %v", err)
	}
	_, paths, seq := f.recorded()
	if !sameStrings(seq, names) {
		t.Errorf("DELETE sequence = %q, want %q", seq, names)
	}
	if !sameStrings(deleted, names) {
		t.Errorf("deleted = %q, want %q", deleted, names)
	}
	wantPaths := []string{
		"/nodes/qa-pve-01/qemu/4242/snapshot/delta",
		"/nodes/qa-pve-01/qemu/4242/snapshot/charlie",
		"/nodes/qa-pve-01/qemu/4242/snapshot/bravo",
	}
	if !sameStrings(paths, wantPaths) {
		t.Errorf("delete paths = %q, want %q", paths, wantPaths)
	}

	// Each name is path-escaped into its own segment: an unescaped name
	// containing '/' would address some other path under this VM.
	t.Run("name needing escaping", func(t *testing.T) {
		f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, `{"data":[
			{"name":"current","snaptime":0},
			{"name":"odd/name","snaptime":1700000000,"vmstate":1}
		]}`, `{"data":[{"name":"current","snaptime":0}]}`)
		if _, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"odd/name"}); err != nil {
			t.Fatalf("CascadeDeleteSnapshots: %v", err)
		}
		_, paths, _ := f.recorded()
		if want := "/nodes/qa-pve-01/qemu/4242/snapshot/odd%2Fname"; len(paths) != 1 || paths[0] != want {
			t.Errorf("delete paths = %q, want exactly [%q]", paths, want)
		}
	})
}

// TestCascadeDeleteSnapshots_StopsAtFirstFailure: when a DELETE is rejected,
// no later DELETE is issued — observed twice, independently: in the request
// sequence the server saw, and in deleted, which must hold only the prefix
// that actually succeeded. The post-verify must not run either (list read
// once, for the pre-state), and PVE's own rejection text must reach the
// caller.
func TestCascadeDeleteSnapshots_StopsAtFirstFailure(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	f.deleteHTTPFail = map[string]bool{"charlie": true}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie", "bravo"})
	if err == nil {
		t.Fatal("expected an error when a DELETE is rejected")
	}
	if !strings.Contains(err.Error(), `delete "charlie"`) || !strings.Contains(err.Error(), "is locked") {
		t.Errorf("error = %v, want it to name charlie and carry PVE's own text", err)
	}
	_, _, seq := f.recorded()
	if !sameStrings(seq, []string{"delta", "charlie"}) {
		t.Errorf("DELETE sequence = %q, want [delta charlie]: nothing may be issued after the first failure", seq)
	}
	if !sameStrings(deleted, []string{"delta"}) {
		t.Errorf("deleted = %q, want [delta]", deleted)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 1 {
		t.Errorf("list endpoint hit %d times, want 1: no post-verify after a failed cascade", got)
	}
}

// TestCascadeDeleteSnapshots_DeletedRecordsOnlyWhatWasDeleted: deleted is
// recorded as each delete succeeds, never reconstructed from names. One
// name is absent (skipped, so not deleted) and one fails; a deleted derived
// from names would report both.
func TestCascadeDeleteSnapshots_DeletedRecordsOnlyWhatWasDeleted(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	f.deleteHTTPFail = map[string]bool{"charlie": true}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"echo", "delta", "charlie"})
	if err == nil {
		t.Fatal("expected an error when a DELETE is rejected")
	}
	if !sameStrings(deleted, []string{"delta"}) {
		t.Errorf("deleted = %q, want exactly [delta]: echo was never present and charlie's delete failed", deleted)
	}
}

// TestCascadeDeleteSnapshots_TaskFailureStopsCascade: a DELETE that PVE
// accepts but whose worker task fails is a failure, and stops the cascade
// just like a rejected request. That only happens if each delete is waited
// on before the next is issued.
func TestCascadeDeleteSnapshots_TaskFailureStopsCascade(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	f.taskFail = map[string]string{"delete/charlie": "command 'qm delsnapshot' failed"}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie", "bravo"})
	var failed *TaskFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("err = %v, want a wrapped *TaskFailedError", err)
	}
	_, _, seq := f.recorded()
	if !sameStrings(seq, []string{"delta", "charlie"}) {
		t.Errorf("DELETE sequence = %q, want [delta charlie]", seq)
	}
	if !sameStrings(deleted, []string{"delta"}) {
		t.Errorf("deleted = %q, want [delta]", deleted)
	}
}

// TestCascadeDeleteSnapshots_SkipsAlreadyAbsentNames: a name missing from the
// pre-state read is skipped, which is what makes a re-run after a partial
// failure safe; a name repeated in names is deleted once. Skipped names are
// not reported as deleted.
func TestCascadeDeleteSnapshots_SkipsAlreadyAbsentNames(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC, `{"data":[
		{"name":"current","snaptime":0},
		{"name":"alpha","snaptime":1700000000,"vmstate":1},
		{"name":"bravo","snaptime":1700003600,"vmstate":1}
	]}`)
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie", "charlie"})
	if err != nil {
		t.Fatalf("CascadeDeleteSnapshots: %v", err)
	}
	_, _, seq := f.recorded()
	if !sameStrings(seq, []string{"charlie"}) {
		t.Errorf("DELETE sequence = %q, want [charlie]: delta was absent, and charlie is deleted once", seq)
	}
	if !sameStrings(deleted, []string{"charlie"}) {
		t.Errorf("deleted = %q, want [charlie]", deleted)
	}
}

// --- CascadeDeleteSnapshots: verification --------------------------------

// TestCascadeDeleteSnapshots_VerifyCatchesALyingDelete: every DELETE and
// every task reports success, but the list afterwards still shows the
// names. The cascade must refuse on what the list says, not on what the
// DELETEs said.
func TestCascadeDeleteSnapshots_VerifyCatchesALyingDelete(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD, chainABCD)
	names := []string{"delta", "charlie"}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, names)
	if err == nil {
		t.Fatal("expected the post-verify to refuse: the list still shows both names")
	}
	if !strings.Contains(err.Error(), "still present") || !strings.Contains(err.Error(), `"delta"`) || !strings.Contains(err.Error(), `"charlie"`) {
		t.Errorf("error = %v, want it to name both snapshots still present", err)
	}
	if !sameStrings(deleted, names) {
		t.Errorf("deleted = %q, want %q: both deletes did report success", deleted, names)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 2 {
		t.Errorf("list endpoint hit %d times, want 2 (pre-state + verify)", got)
	}
}

// TestCascadeDeleteSnapshots_EmptyVerifyReadIsUnverifiableNotSuccess is the
// case the whole unverifiable-read guard exists for. The post-verify asks
// "are these names absent?", and a swallowed read — empty list, nil error —
// answers YES: without the guard, the cascade reports success precisely
// when its verification failed. Two 200 shapes only the guard's own
// invariant catches: an empty list (emptyList), and a list of nothing but
// JSON nulls, which realSnapshots reduces to the same empty set.
func TestCascadeDeleteSnapshots_EmptyVerifyReadIsUnverifiableNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		desc, body string
		status     int
	}{
		{"200 with an empty list", emptyList, 200},
		{"200 with a list of only nulls", `{"data":[null]}`, 200},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD, tc.body)
			f.listStatus = []int{200, tc.status}
			names := []string{"delta", "charlie"}
			deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, names)
			if err == nil {
				t.Fatal("cascade reported success over a verify read that proves nothing")
			}
			if !errors.Is(err, ErrUnverifiableRead) || !strings.Contains(err.Error(), "verify: ") {
				t.Errorf("error = %v, want the verify read refused with ErrUnverifiableRead", err)
			}
			if !sameStrings(deleted, names) {
				t.Errorf("deleted = %q, want %q", deleted, names)
			}
		})
	}
}

// TestCascadeDeleteSnapshots_EmptyPreStateReadIsUnverifiable: the pre-state
// read decides which names to skip, and a swallowed read makes EVERY name
// look absent. Without the guard the cascade issues no DELETE at all, reads
// the list again, and refuses there with a misleading "still present". The
// test pins three independent facts the unguarded path gets wrong: the read
// count (it stops after one read), the DELETE count (zero), and the cause
// (the pre-state read, unverifiable).
func TestCascadeDeleteSnapshots_EmptyPreStateReadIsUnverifiable(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, emptyList, chainABCD)
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie"})
	if !errors.Is(err, ErrUnverifiableRead) || !strings.Contains(err.Error(), "pre-state read: ") {
		t.Errorf("error = %v, want the pre-state read refused with ErrUnverifiableRead", err)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 1 {
		t.Errorf("list endpoint hit %d times, want 1", got)
	}
	if got := atomic.LoadInt32(&f.deleteCalls); got != 0 {
		t.Errorf("delete endpoint hit %d times, want 0", got)
	}
	if len(deleted) != 0 {
		t.Errorf("deleted = %q, want nothing", deleted)
	}
}

// --- CreateSnapshot: unverifiable reads (5a, fixed alongside 5b) ---------

// TestCreateSnapshot_EmptyPreflightReadIsUnverifiable: CreateSnapshot's
// collision check REFUSES on presence, so a swallowed read hides any
// collision and lets the create POST through — onto a name that may
// already exist, which is the one thing that check is for. The create
// endpoint must never be reached.
func TestCreateSnapshot_EmptyPreflightReadIsUnverifiable(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, emptyList)
	err := c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "")
	if !errors.Is(err, ErrUnverifiableRead) || !strings.HasPrefix(err.Error(), `create snapshot "echo" on vm 4242: `) {
		t.Errorf("error = %v, want the create pre-flight read refused with ErrUnverifiableRead", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 0 {
		t.Errorf("create endpoint hit %d times, want 0: an unverified collision check must not let the POST through", got)
	}
	if got := atomic.LoadInt32(&f.listCalls); got != 1 {
		t.Errorf("list endpoint hit %d times, want 1", got)
	}
}

// TestCreateSnapshot_EmptyVerifyReadIsUnverifiableNotAbsent: the post-create
// verify already failed closed on a swallowed read, so err != nil proves
// nothing here. What was wrong was the cause it named — "absent from the
// snapshot list" — about a snapshot that may well exist. The test asserts
// the truthful cause and the absence of the false one.
func TestCreateSnapshot_EmptyVerifyReadIsUnverifiableNotAbsent(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC, emptyList)
	err := c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "")
	if !errors.Is(err, ErrUnverifiableRead) || !strings.HasPrefix(err.Error(), `verify snapshot "echo" on vm 4242: `) {
		t.Errorf("error = %v, want the verify read refused with ErrUnverifiableRead", err)
	}
	if err != nil && strings.Contains(err.Error(), "absent") {
		t.Errorf("error = %v says \"absent\": a swallowed read must not be reported as a missing snapshot", err)
	}
	if got := atomic.LoadInt32(&f.createCalls); got != 1 {
		t.Errorf("create endpoint hit %d times, want 1", got)
	}
}

// --- RoutedClient pass-throughs: 5b --------------------------------------

// TestRoutedClient_SnapshotRollback_Forwards covers the seam between the
// three 5b pass-throughs and the Client methods they forward to — the seam
// that is otherwise untested, because this package's own tests call Client
// directly. Every argument uses a value that cannot be confused with any
// other in this test: the target's node rt-node-7 appears nowhere else, the
// vmid is 4242, and each call uses a different snapshot name, so a
// transposed, dropped or substituted argument produces a path the fake
// rejects or a result that is visibly wrong. The fake is stateful — a
// DELETE really removes the snapshot from later listings — so the cascade's
// post-verify runs against honest data.
func TestRoutedClient_SnapshotRollback_Forwards(t *testing.T) {
	withTaskTimings(t, time.Millisecond, 2*time.Second)
	const node = "rt-node-7"
	const snapBase = "/nodes/rt-node-7/qemu/4242/snapshot"
	type snap struct {
		name string
		time int64
	}
	var mu sync.Mutex
	live := []snap{{"alpha", 1700000000}, {"bravo", 1700003600}, {"charlie", 1700007200}}
	var rollbackPaths, deleteSeq []string
	var pid int32
	upid := func(typ string) string {
		return fmt.Sprintf("UPID:%s:%08X:0000ABCD:5F000000:%s:4242:root@pam:", node, atomic.AddInt32(&pid, 1), typ)
	}

	restSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.EscapedPath()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && p == snapBase:
			entries := []string{`{"name":"current","snaptime":0}`}
			for _, s := range live {
				entries = append(entries, fmt.Sprintf(`{"name":%q,"snaptime":%d,"vmstate":1}`, s.name, s.time))
			}
			_, _ = w.Write([]byte(`{"data":[` + strings.Join(entries, ",") + `]}`))
		case r.Method == http.MethodPost && strings.HasPrefix(p, snapBase+"/") && strings.HasSuffix(p, "/rollback"):
			rollbackPaths = append(rollbackPaths, p)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, upid("qmrollback"))))
		case r.Method == http.MethodDelete && strings.HasPrefix(p, snapBase+"/"):
			name := strings.TrimPrefix(p, snapBase+"/")
			deleteSeq = append(deleteSeq, name)
			kept := live[:0]
			for _, s := range live {
				if s.name != name {
					kept = append(kept, s)
				}
			}
			live = kept
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, upid("qmdelsnapshot"))))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/nodes/"+node+"/tasks/"):
			u := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/nodes/"+node+"/tasks/"), "/status")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, u, node)))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, p)
			http.NotFound(w, r)
		}
	}))
	defer restSrv.Close()

	tg := &roster.Target{ID: "rt-target-id", Host: "rt-host.example.com", Node: node}
	// Built via NewClient (BaseURLOverride), not NewClientForTarget: see
	// routed_test.go's TestRoutedClient_TypedReadForwarding's identical note.
	rc := &RoutedClient{rest: testClient(t, restSrv), target: tg, passphrase: "roster-pass"}
	ctx := context.Background()

	newer, err := rc.NewerSnapshots(ctx, rbVMID, "alpha")
	if err != nil {
		t.Fatalf("NewerSnapshots: %v", err)
	}
	if got := namesOf(newer); !sameStrings(got, []string{"bravo", "charlie"}) {
		t.Errorf("NewerSnapshots(alpha) = %q, want [bravo charlie] — the target argument must reach the Client", got)
	}

	deleted, err := rc.CascadeDeleteSnapshots(ctx, rbVMID, []string{"charlie", "bravo"})
	if err != nil {
		t.Fatalf("CascadeDeleteSnapshots: %v", err)
	}
	if !sameStrings(deleteSeq, []string{"charlie", "bravo"}) {
		t.Errorf("DELETE sequence = %q, want [charlie bravo]", deleteSeq)
	}
	if !sameStrings(deleted, []string{"charlie", "bravo"}) {
		t.Errorf("deleted = %q, want [charlie bravo] — the pass-through must return what the Client deleted", deleted)
	}

	if err := rc.Rollback(ctx, rbVMID, "alpha"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if want := snapBase + "/alpha/rollback"; len(rollbackPaths) != 1 || rollbackPaths[0] != want {
		t.Errorf("rollback paths = %q, want exactly [%q]", rollbackPaths, want)
	}
}

// --- 5b: gaps closed after independent code review -----------------------
//
// Each test below exists because an independent reviewer found a mutant of
// the 5b code that survived every test above it. The doc comment on each
// names the mutant.

// TestNewerSnapshots_TargetAbsentFromValidListIsNotFound: a target that is
// simply not in a perfectly good list is an error, and a Rollback to it
// never reaches the rollback endpoint. Mutant killed: "not found" replaced
// by `return nil, nil` — an empty newer-set reads as "target is newest", and
// Rollback would POST .../snapshot/zulu/rollback for a snapshot that does
// not exist. Every earlier not-found path came from a SWALLOWED read; none
// served a valid list lacking the target.
func TestNewerSnapshots_TargetAbsentFromValidListIsNotFound(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	_, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "zulu")
	if err == nil || err.Error() != `newer snapshots of vm 4242: snapshot "zulu" not found` {
		t.Errorf("NewerSnapshots(zulu) err = %v, want exactly the not-found refusal", err)
	}
	rerr := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "zulu")
	if rerr == nil || !strings.Contains(rerr.Error(), `snapshot "zulu" not found`) {
		t.Errorf("Rollback(zulu) err = %v, want the not-found refusal propagated", rerr)
	}
	if got := atomic.LoadInt32(&f.rollbackCalls); got != 0 {
		t.Errorf("rollback endpoint hit %d times, want 0: a snapshot that does not exist must never be rolled back to", got)
	}
}

// TestRollback_ServerErrorBodyIsVisible mirrors 5a's
// TestCreateSnapshot_ServerErrorBodyIsVisible for the rollback POST: a 500
// from PVE's rollback endpoint fails the call, and PVE's own text reaches
// the caller — the reason the POST goes through RawRequest rather than
// go-proxmox's body-discarding handleResponse. Mutant killed: the POST's
// error branch replaced by `return nil`, which reported a rejected rollback
// as a successful one.
func TestRollback_ServerErrorBodyIsVisible(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	f.rollbackHTTPFail = true
	err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "charlie")
	if err == nil {
		t.Fatal("expected an error for a 500 from the rollback endpoint")
	}
	if !strings.Contains(err.Error(), "snapshot is locked (backup)") {
		t.Errorf("error = %v, want PVE's own response text preserved", err)
	}
	if got := atomic.LoadInt32(&f.rollbackCalls); got != 1 {
		t.Errorf("rollback endpoint hit %d times, want 1", got)
	}
}

// TestRollback_NullUPIDIsAnError: a rollback POST that PVE accepts but
// answers with {"data":null} has started no task anyone can wait on, so
// nothing proves the rollback happened. It must fail, not succeed. Mutants
// killed: the UPID-decode error branch replaced by `return nil`; and, found
// by the delta re-review, that branch's wrapped %w replaced by a fixed
// "decode upid" string — which is why the whole wrapped text, including the
// rejected body only the decoder's own error carries, is pinned rather than
// a prefix.
func TestRollback_NullUPIDIsAnError(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABC)
	f.rollbackNullUPID = true
	err := c.Rollback(context.Background(), "qa-pve-01", rbVMID, "charlie")
	if err == nil {
		t.Fatal("Rollback succeeded on a response that carried no task")
	}
	if want := `rollback vm 4242 to snapshot "charlie": decode upid: unexpected response null: expected a UPID string, got null`; err.Error() != want {
		t.Errorf("error = %q, want exactly %q — the decoder's own error, wrapped, not a summary of it", err, want)
	}
}

// TestCascadeDeleteSnapshots_NullUPIDStopsCascade: a DELETE answered 200
// {"data":null} started no task, so the snapshot may well still exist —
// and here it does, it stays listed. The cascade must stop there with an
// error, report only the earlier delete as done, and issue nothing after
// it. Mutant killed: the decode-error branch replaced by
// `return deleted, nil`, which ended the cascade early and reported
// SUCCESS with delta deleted and charlie and bravo still present; and, by
// the same reasoning as TestRollback_NullUPIDIsAnError, that branch's
// wrapped %w replaced by a fixed string — so the rejected body, which only
// the decoder's own error carries, is pinned too.
func TestCascadeDeleteSnapshots_NullUPIDStopsCascade(t *testing.T) {
	f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
	f.deleteNullUPID = map[string]bool{"charlie": true}
	deleted, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie", "bravo"})
	if err == nil {
		t.Fatal("cascade succeeded although charlie's delete started no task")
	}
	if want := `cascade delete snapshots of vm 4242: delete "charlie": decode upid: unexpected response null: expected a UPID string, got null`; err.Error() != want {
		t.Errorf("error = %q, want exactly %q — the decoder's own error, wrapped, not a summary of it", err, want)
	}
	if !sameStrings(deleted, []string{"delta"}) {
		t.Errorf("deleted = %q, want [delta]", deleted)
	}
	_, _, seq := f.recorded()
	if !sameStrings(seq, []string{"delta", "charlie"}) {
		t.Errorf("DELETE sequence = %q, want [delta charlie]", seq)
	}
}

// TestReservedNameRefusal_CarriesVMIDAndName: every operation that refuses
// the reserved "current" name hands back an *ErrReservedSnapshotName that
// actually says which VM and which name — the name as the caller gave it,
// untrimmed. Mutants killed: &ErrReservedSnapshotName{} with its fields
// dropped, in NewerSnapshots and in CascadeDeleteSnapshots; errors.As still
// matched an empty struct, so the earlier tests could not tell.
func TestReservedNameRefusal_CarriesVMIDAndName(t *testing.T) {
	const given = " current\t"
	for _, tc := range []struct {
		op   string
		call func(c *Client) error
	}{
		{"NewerSnapshots", func(c *Client) error {
			_, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, given)
			return err
		}},
		{"Rollback", func(c *Client) error {
			return c.Rollback(context.Background(), "qa-pve-01", rbVMID, given)
		}},
		{"CascadeDeleteSnapshots", func(c *Client) error {
			_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", given})
			return err
		}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD)
			err := tc.call(c)
			var reserved *ErrReservedSnapshotName
			if !errors.As(err, &reserved) {
				t.Fatalf("err = %v, want *ErrReservedSnapshotName", err)
			}
			if reserved.VMID != rbVMID || reserved.Name != given {
				t.Errorf("refusal = %+v, want VMID %d and Name %q (untrimmed)", reserved, rbVMID, given)
			}
		})
	}
}

// TestSnapshotMutations_EscapeNodeInPath: the node is path-escaped in both
// new mutating paths, not only the snapshot name. The node "qa,pve" is not
// a realistic PVE node name; it is chosen because url.PathEscape encodes
// ',' in a path segment, so the escaping is observable. Mutants killed:
// url.PathEscape(node) dropped from the rollback path and from the delete
// path.
//
// No PVE node name holds a comma, so the fake's UPID for this node is outside
// PVE's UPID grammar and the wait refuses it as an unverifiable read, before
// any poll. The request path, which is what this test pins, was sent first.
func TestSnapshotMutations_EscapeNodeInPath(t *testing.T) {
	const node = "qa,pve"
	refusedWait := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnverifiableRead) || !strings.Contains(err.Error(), "malformed upid") {
			t.Fatalf("err = %v, want the wait's malformed-upid refusal", err)
		}
	}
	t.Run("rollback", func(t *testing.T) {
		f, c := newSnapshotFixture(t, node, rbVMID, chainABC)
		refusedWait(t, c.Rollback(context.Background(), node, rbVMID, "charlie"))
		paths, _, _ := f.recorded()
		if want := "/nodes/qa%2Cpve/qemu/4242/snapshot/charlie/rollback"; len(paths) != 1 || paths[0] != want {
			t.Errorf("rollback paths = %q, want exactly [%q]", paths, want)
		}
	})
	t.Run("delete", func(t *testing.T) {
		f, c := newSnapshotFixture(t, node, rbVMID, chainABC, `{"data":[{"name":"current","snaptime":0}]}`)
		_, err := c.CascadeDeleteSnapshots(context.Background(), node, rbVMID, []string{"charlie"})
		refusedWait(t, err)
		_, paths, _ := f.recorded()
		if want := "/nodes/qa%2Cpve/qemu/4242/snapshot/charlie"; len(paths) != 1 || paths[0] != want {
			t.Errorf("delete paths = %q, want exactly [%q]", paths, want)
		}
	})
}

// TestErrNotNewestSnapshot_ErrorTextSingular pins the one-newer-snapshot
// wording. Every earlier refusal had two or more newer snapshots. Mutant
// killed: the singular branch made unreachable.
func TestErrNotNewestSnapshot_ErrorTextSingular(t *testing.T) {
	e := &ErrNotNewestSnapshot{VMID: rbVMID, Target: "bravo", Newer: []string{"charlie"}}
	if want := `rollback vm 4242 to snapshot "bravo" refused: 1 newer snapshot exists and would be discarded: "charlie"`; e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
}

// TestCascadeDeleteSnapshots_VerifyNamesEachStillPresentSnapshotOnce: when
// names repeats a snapshot that is still present after the cascade, the
// verify refusal counts and names it once, and still names every other
// survivor. Mutant killed: the de-duplication in the verify message
// removed, which reported "3 snapshot(s)" and named delta twice.
func TestCascadeDeleteSnapshots_VerifyNamesEachStillPresentSnapshotOnce(t *testing.T) {
	_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, chainABCD, chainABCD)
	_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "delta", "charlie"})
	if err == nil {
		t.Fatal("expected the post-verify to refuse: the list still shows delta and charlie")
	}
	msg := err.Error()
	if !strings.Contains(msg, "2 snapshot(s) still present") {
		t.Errorf("error = %v, want a count of 2 distinct snapshots", err)
	}
	if n := strings.Count(msg, `"delta"`); n != 1 {
		t.Errorf("error = %v names delta %d times, want once", err, n)
	}
	if !strings.Contains(msg, `"charlie"`) {
		t.Errorf("error = %v, want charlie named too", err)
	}
}

// TestNewerSnapshots_NewerTieKeepsListOrder: snapshots that are all newer
// than the target but share a Snaptime among themselves are not refused
// (the target is not tied, so "these would be discarded" is right either
// way), and they keep the order PVE listed them in — see NewerSnapshots'
// doc comment on why that order is only a guess, and why a wrong guess
// fails safe. The list is generated rather than written out: four tied
// snapshots interleaved with twelve distinct ones whose times descend in
// list order. With a two- or three-element tie, or with every entry tied,
// Go's sort.Slice happens to preserve order too (measured), so the
// mutation sort.SliceStable -> sort.Slice would survive. On this input
// sort.Slice reorders the ties under Go's current pdqsort (measured: tie2,
// tie0, tie1, tie3). That kill is tied to sort.Slice's algorithm; the
// ordering assertion itself holds for any correct stable sort.
func TestNewerSnapshots_NewerTieKeepsListOrder(t *testing.T) {
	const tieTime = 1700007200
	entries := []string{
		`{"name":"current","snaptime":0}`,
		`{"name":"alpha","snaptime":1700000000,"vmstate":1}`,
	}
	var wantTies []string
	const k, m = 4, 12
	for i := 0; i < k+m; i++ {
		if i%((k+m)/k) == 0 && len(wantTies) < k {
			name := fmt.Sprintf("tie%d", len(wantTies))
			wantTies = append(wantTies, name)
			entries = append(entries, fmt.Sprintf(`{"name":%q,"snaptime":%d,"vmstate":1}`, name, tieTime))
			continue
		}
		entries = append(entries, fmt.Sprintf(`{"name":"d%02d","snaptime":%d,"vmstate":1}`, i, 1700100000-i*3600))
	}
	_, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, `{"data":[`+strings.Join(entries, ",")+`]}`)

	newer, err := c.NewerSnapshots(context.Background(), "qa-pve-01", rbVMID, "alpha")
	if err != nil {
		t.Fatalf("NewerSnapshots: %v — a tie among NEWER snapshots must not be refused", err)
	}
	if len(newer) != k+m {
		t.Fatalf("got %d newer snapshots, want %d", len(newer), k+m)
	}
	var gotTies []string
	for _, s := range newer {
		if s.Snaptime == tieTime {
			gotTies = append(gotTies, s.Name)
		}
	}
	if !sameStrings(gotTies, wantTies) {
		t.Errorf("tied newer snapshots came out as %q, want list order %q", gotTies, wantTies)
	}
	for i := 1; i < len(newer); i++ {
		if newer[i-1].Snaptime > newer[i].Snaptime {
			t.Errorf("result not ascending at %d: %d then %d", i, newer[i-1].Snaptime, newer[i].Snaptime)
		}
	}
}

// --- 5b: swallowed-read scenarios (cause-agnostic) -----------------------

// TestSnapshotOps_SwallowedReadIsRefusedWithoutSideEffects replays the
// measured read-status swallow — a 595 carrying {"data":null} — at every
// snapshot read a 5b operation makes, and asserts only the OUTCOME: the
// operation refuses, and nothing it would have mutated after that read was
// mutated. It deliberately does not assert which layer refused or with what
// text. Today listSnapshotsVerifiable refuses it; once ListSnapshots refuses
// a null payload itself, or once a 595 becomes a typed status error before
// any snapshot code runs, a different layer will — and this test must keep
// passing across that change. The guard itself is pinned separately, by
// the emptyList-based tests above.
//
// Where a site's refusal has no side effect left to prevent (the two
// post-verifies, which run after their mutations), the scenario asserts
// the refusal alone.
func TestSnapshotOps_SwallowedReadIsRefusedWithoutSideEffects(t *testing.T) {
	for _, tc := range []struct {
		desc   string
		bodies []string
		status []int
		run    func(c *Client) error
		// sideEffects reports the mutations that must not have happened.
		sideEffects func(f *snapshotFixture) int32
	}{
		{"rollback pre-flight read", []string{swallowedList}, []int{595},
			func(c *Client) error { return c.Rollback(context.Background(), "qa-pve-01", rbVMID, "alpha") },
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.rollbackCalls) }},
		{"cascade pre-state read", []string{swallowedList, chainABCD}, []int{595, 200},
			func(c *Client) error {
				_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie"})
				return err
			},
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.deleteCalls) }},
		{"cascade verify read", []string{chainABCD, swallowedList}, []int{200, 595},
			func(c *Client) error {
				_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie"})
				return err
			},
			nil},
		{"create pre-flight read", []string{swallowedList}, []int{595},
			func(c *Client) error { return c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "") },
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.createCalls) }},
		{"create verify read", []string{chainABC, swallowedList}, []int{200, 595},
			func(c *Client) error { return c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "") },
			nil},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, tc.bodies...)
			f.listStatus = tc.status
			if err := tc.run(c); err == nil {
				t.Errorf("operation succeeded over a swallowed read at the %s", tc.desc)
			}
			if tc.sideEffects != nil {
				if got := tc.sideEffects(f); got != 0 {
					t.Errorf("%d mutating request(s) issued after a swallowed %s, want 0", got, tc.desc)
				}
			}
		})
	}
}

// TestSnapshotOps_ListWithoutCurrentIsUnverifiable: a well-formed, non-empty
// 200 list that looks healthy but lacks PVE's "current" pseudo-entry is not
// a real PVE response — every live VM's list includes "current" — so every
// 5b snapshot read refuses it with ErrUnverifiableRead, and nothing after
// that read is mutated. The bodies are chosen to be the worst case for each
// site: ones the operation would otherwise have ACCEPTED as a correct
// answer. The cascade's verify body no longer lists the deleted names, and
// the create's verify body lists the new snapshot with its RAM state. With
// only a "some non-nil entry" check, both report success.
func TestSnapshotOps_ListWithoutCurrentIsUnverifiable(t *testing.T) {
	const noCurrent = `{"data":[{"name":"alpha","snaptime":1700000000,"vmstate":1}]}`
	const createdNoCurrent = `{"data":[{"name":"alpha","snaptime":1700000000,"vmstate":1},{"name":"echo","snaptime":1700003600,"vmstate":1}]}`
	for _, tc := range []struct {
		desc        string
		bodies      []string
		run         func(c *Client) error
		sideEffects func(f *snapshotFixture) int32
	}{
		{"rollback pre-flight read", []string{noCurrent},
			func(c *Client) error { return c.Rollback(context.Background(), "qa-pve-01", rbVMID, "alpha") },
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.rollbackCalls) }},
		{"cascade pre-state read", []string{noCurrent, chainABCD},
			func(c *Client) error {
				_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"alpha"})
				return err
			},
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.deleteCalls) }},
		{"cascade verify read", []string{chainABCD, noCurrent},
			func(c *Client) error {
				_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"delta", "charlie"})
				return err
			},
			nil},
		{"create pre-flight read", []string{noCurrent},
			func(c *Client) error { return c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "") },
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.createCalls) }},
		{"create verify read", []string{chainABC, createdNoCurrent},
			func(c *Client) error { return c.CreateSnapshot(context.Background(), "qa-pve-01", rbVMID, "echo", "") },
			nil},
		// The match is exact, for realSnapshots' reason: "Current" is a
		// legitimate, distinct REAL snapshot name, not PVE's pseudo-entry,
		// so a list whose only near-match is it still lacks "current".
		{"cascade pre-state read, only a real snapshot named Current", []string{
			`{"data":[{"name":"Current","snaptime":1699990000,"vmstate":1},{"name":"alpha","snaptime":1700000000,"vmstate":1}]}`, chainABCD},
			func(c *Client) error {
				_, err := c.CascadeDeleteSnapshots(context.Background(), "qa-pve-01", rbVMID, []string{"alpha"})
				return err
			},
			func(f *snapshotFixture) int32 { return atomic.LoadInt32(&f.deleteCalls) }},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f, c := newSnapshotFixture(t, "qa-pve-01", rbVMID, tc.bodies...)
			if err := tc.run(c); !errors.Is(err, ErrUnverifiableRead) {
				t.Errorf("err = %v, want ErrUnverifiableRead: a list without %q is not a PVE response", err, currentPseudoSnapshot)
			}
			if tc.sideEffects != nil {
				if got := tc.sideEffects(f); got != 0 {
					t.Errorf("%d mutating request(s) issued after a list without %q, want 0", got, currentPseudoSnapshot)
				}
			}
		})
	}
}
