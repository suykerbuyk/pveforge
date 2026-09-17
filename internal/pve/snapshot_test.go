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
	"sync/atomic"
	"testing"
	"time"

	proxmox "github.com/luthermonson/go-proxmox"

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

// snapshotFixture is a fake PVE serving the three endpoints a
// CreateSnapshot call touches — the snapshot list (GET), the snapshot
// create (POST), and the task-status poll WaitForTask drives — while
// counting each one, so a test can assert not just what CreateSnapshot
// returned but which endpoints it did and did not reach.
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
}

func (f *snapshotFixture) handler(w http.ResponseWriter, r *http.Request) {
	snapPath := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", f.node, f.vmid)
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
		_, _ = w.Write([]byte(f.listBodies[idx]))

	case r.URL.Path == snapPath && r.Method == http.MethodPost:
		atomic.AddInt32(&f.createCalls, 1)
		if err := r.ParseForm(); err != nil {
			f.t.Errorf("ParseForm: %v", err)
		}
		f.createForm = r.PostForm
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":%q}`, wellFormedUPID(f.node))))

	case strings.HasPrefix(r.URL.Path, fmt.Sprintf("/nodes/%s/tasks/", f.node)):
		// Always immediately stopped/OK: none of these tests are about
		// the poll loop itself (task_test.go covers that), only about
		// what CreateSnapshot does once the task has finished.
		_, _ = w.Write([]byte(fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`,
			wellFormedUPID(f.node), f.node)))

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
