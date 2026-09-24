package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-vm-create-existing-tag-guard and
// pveforge-unique-tag-containers-and-acl-holes: `vm create --unique-tag X`,
// through runRoot, over tagClusterFake — a stateful cluster whose guests
// (VMs and containers) are listed by root's pvesh read over a pvefake SSH
// server, each only once `lag` further listings have passed. Its REST side
// answers /cluster/resources with an empty list, as a token whose view
// hides every guest would: the check must never trust that list.

type tagVM struct {
	typ     string // "qemu" or "lxc"
	tags    string
	visible int // listings still to pass before it is listed
}

type tagClusterFake struct {
	mu        sync.Mutex
	vms       map[int]*tagVM
	lag       int    // a created VM is listed only after this many listings
	resources string // root's read: "" normal, or "exit", "null", "garbage", "badentry", "node"
	sshDown   bool   // root cannot be reached at all
	hangFrom  int    // when > 0, root's read hangs from this listing on, until the test ends
	release   chan struct{}
	posts     int
	listings  int
	requests  []string // REST requests
	rootCmds  []string // commands root ran
	onCreate  func()   // runs inside the create POST, before it is recorded
	onListing func()   // runs on each /cluster/resources read
}

func newTagCluster(existing map[int]string) *tagClusterFake {
	f := &tagClusterFake{vms: map[int]*tagVM{}}
	for id, tags := range existing {
		f.vms[id] = &tagVM{typ: "qemu", tags: tags}
	}
	return f
}

// addCT adds a container carrying tags.
func (f *tagClusterFake) addCT(id int, tags string) *tagClusterFake {
	f.vms[id] = &tagVM{typ: "lxc", tags: tags}
	return f
}

func (f *tagClusterFake) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 5*time.Second))
	origBound, origPoll := tagVisibilityBound, tagVisibilityPoll
	tagVisibilityBound, tagVisibilityPoll = 2*time.Second, 2*time.Millisecond
	t.Cleanup(func() { tagVisibilityBound, tagVisibilityPoll = origBound, origPoll })
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	origRead := tagReadTimeout
	t.Cleanup(func() { tagReadTimeout = origRead })
	f.release = make(chan struct{})
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(f.exec)
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Cleanup(func() { close(f.release) }) // registered after the server's own cleanup, so it runs first
	rootAt(t, fs)
	if f.sshDown {
		newAccessTransport = func() bootstrap.SSHTransport {
			return addrRewrite{inner: bootstrap.NewSSHTransport(), addr: "127.0.0.1:1"}
		}
	}
	return rp
}

// sent reports how many REST requests and root commands were made.
func (f *tagClusterFake) sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests) + len(f.rootCmds)
}

// exec is root's side: the one pvesh read, answered from the fake's guests.
// Any other command fails loudly, and is recorded, so a test sees it.
func (f *tagClusterFake) exec(cmd string) (string, string, int) {
	f.mu.Lock()
	f.rootCmds = append(f.rootCmds, cmd)
	if cmd != bootstrap.ClusterGuestsCommand {
		f.mu.Unlock()
		return "", "unexpected command", 127
	}
	f.listings++
	mode, hook, hang := f.resources, f.onListing, f.hangFrom > 0 && f.listings >= f.hangFrom
	release := f.release
	list := []map[string]any{}
	for id, vm := range f.vms {
		if vm.visible > 0 {
			vm.visible--
			continue
		}
		list = append(list, map[string]any{"id": fmt.Sprintf("%s/%d", vm.typ, id), "type": vm.typ, "vmid": id, "node": "qa-pve-01", "tags": vm.tags})
	}
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if hang {
		<-release // a pmxcfs that never answers
	}
	switch mode {
	case "exit":
		return "", "ipcc_send_rec[1] failed: Connection refused", 255
	case "null":
		return "null\n", "", 0
	case "garbage":
		return "not json\n", "", 0
	case "badentry":
		return `[{"type":"qemu","vmid":"150","tags":"x"}]`, "", 0
	case "node":
		return `[{"type":"node","vmid":1}]`, "", 0
	}
	b, _ := json.Marshal(list)
	return string(b) + "\n", "", 0
}

func (f *tagClusterFake) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (f *tagClusterFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	data := func(v any) {
		b, _ := json.Marshal(map[string]any{"data": v})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}
	const base = "/api2/json"
	path := r.URL.Path
	switch {
	case path == base+"/cluster/resources":
		// The token's view: every guest hidden (a per-VM ACL, a pool
		// NoAccess). The check must never read this.
		data([]any{})
	case path == base+"/cluster/nextid":
		id, _ := strconv.Atoi(r.URL.Query().Get("vmid"))
		f.mu.Lock()
		_, taken := f.vms[id]
		f.mu.Unlock()
		if taken {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"errors":{"vmid":"VM %d already exists"},"data":null}`, id)
			return
		}
		data(strconv.Itoa(id))
	case r.Method == http.MethodPost && path == base+"/nodes/qa-pve-01/qemu":
		_ = r.ParseForm()
		if f.onCreate != nil {
			f.onCreate()
		}
		id, _ := strconv.Atoi(r.PostForm.Get("vmid"))
		f.mu.Lock()
		f.posts++
		// PVE stores tags ';'-joined, whatever separators the create used
		// (UNVERIFIED against a live host).
		f.vms[id] = &tagVM{typ: "qemu", tags: strings.Join(tagSplit.Split(strings.TrimSpace(r.PostForm.Get("tags")), -1), ";"), visible: f.lag}
		f.mu.Unlock()
		data(fmt.Sprintf("UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:%d:root@pam:", id))
	case strings.HasPrefix(path, base+"/nodes/qa-pve-01/tasks/"):
		upid := strings.TrimSuffix(strings.TrimPrefix(path, base+"/nodes/qa-pve-01/tasks/"), "/status")
		data(map[string]any{"status": "stopped", "exitstatus": "OK", "upid": upid, "node": "qa-pve-01"})
	case strings.HasPrefix(path, base+"/nodes/qa-pve-01/qemu/"):
		rest := strings.TrimPrefix(path, base+"/nodes/qa-pve-01/qemu/")
		id, _ := strconv.Atoi(strings.SplitN(rest, "/", 2)[0])
		f.mu.Lock()
		_, ok := f.vms[id]
		f.mu.Unlock()
		if !ok {
			http.Error(w, "no such vm", http.StatusNotFound)
			return
		}
		if strings.HasSuffix(path, "/status/current") {
			data(map[string]any{"status": "stopped", "vmid": id})
			return
		}
		data(map[string]any{"name": "vm"})
	default:
		http.Error(w, "unexpected "+path, http.StatusNotFound)
	}
}

func createTagged(rp string, vmid int, tags string, extra ...string) (int, string, string) {
	args := append([]string{"vm", "create", "--roster", rp, "qa-pve-01", strconv.Itoa(vmid), "tags=" + tags}, extra...)
	return runRootArgs(args...)
}

// T1: a VM already carries the tag → refused, naming it, with no create.
func TestUniqueTag_T1_AlreadyCarried(t *testing.T) {
	f := newTagCluster(map[int]string{150: "web;x"})
	rp := f.start(t)
	code, stdout, stderr := createTagged(rp, 101, "x;web", "--unique-tag", "x")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "already carried by vm 150") || f.posts != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q, POSTs %d", code, stdout, stderr, f.posts)
	}
}

// T2: two VMs carry it → refused, no create.
func TestUniqueTag_T2_Ambiguous(t *testing.T) {
	f := newTagCluster(map[int]string{150: "x", 151: "x"})
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 1 || !strings.Contains(stderr, "more than one guest") || f.posts != 0 {
		t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
	}
}

// T3, T4, T5 / H2: root's read failing — pvesh exiting non-zero, printing
// null, non-JSON, an entry PVE would not print, a non-guest type — or root
// not reachable at all, refuses; it is never read as "nobody has the tag".
func TestUniqueTag_T3_T4_T5_AFailedListingRefuses(t *testing.T) {
	for _, mode := range []string{"exit", "null", "garbage", "badentry", "node", "ssh-down"} {
		t.Run(mode, func(t *testing.T) {
			f := newTagCluster(nil)
			if mode == "ssh-down" {
				f.sshDown = true
			} else {
				f.resources = mode
			}
			rp := f.start(t)
			want := "cannot verify tag uniqueness"
			if mode == "ssh-down" {
				want = "connect as root" // refused before the tag lock is even taken (S1)
			}
			code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
			if code != 1 || !strings.Contains(stderr, want) || f.posts != 0 {
				t.Fatalf("exit %d, stderr %q, POSTs %d; want %q", code, stderr, f.posts, want)
			}
		})
	}
}

// T6: no VM carries it → exactly one create; stdout is exactly what vm
// create always prints, and stderr is empty once the VM is listed.
func TestUniqueTag_T6_NoMatchCreates(t *testing.T) {
	f := newTagCluster(map[int]string{150: "other"})
	rp := f.start(t)
	code, stdout, stderr := createTagged(rp, 101, "x;web", "--unique-tag", "x")
	if code != 0 || stdout != "qa-pve-01: vm 101 created\n" || stderr != "" || f.posts != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q, POSTs %d", code, stdout, stderr, f.posts)
	}
	// Root ran the one read, for the check and for the wait, and nothing
	// else: the root channel stays read-only.
	want := []string{bootstrap.ClusterGuestsCommand, bootstrap.ClusterGuestsCommand}
	if !slices.Equal(f.rootCmds, want) {
		t.Errorf("root ran %q, want %q", f.rootCmds, want)
	}
}

// T8: two concurrent --unique-tag creates of one tag, at different vmids,
// create exactly one VM. The first create waits (up to 300ms) for the
// second's listing; under the tag lock that listing cannot happen until the
// first is done.
func TestUniqueTag_T8_ConcurrentCreatesMakeOne(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	secondListed := make(chan struct{}, 1)
	var first sync.Once
	var listings int
	f.onListing = func() {
		f.mu.Lock()
		listings++
		n := listings
		f.mu.Unlock()
		if n == 2 {
			secondListed <- struct{}{}
		}
	}
	f.onCreate = func() {
		first.Do(func() {
			select {
			case <-secondListed:
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
	type out struct {
		code   int
		stderr string
	}
	res := make(chan out, 2)
	for _, id := range []int{101, 102} {
		go func(id int) {
			code, _, stderr := createTagged(rp, id, "x", "--unique-tag", "x")
			res <- out{code, stderr}
		}(id)
	}
	a, b := <-res, <-res
	if f.posts != 1 || a.code+b.code != 1 {
		t.Fatalf("POSTs %d, exits %d and %d (%q, %q); want exactly one create", f.posts, a.code, b.code, a.stderr, b.stderr)
	}
}

// T9: the listing lags. The create waits, holding the tag lock, until its VM
// is listed, so the next --unique-tag create sees it; and if it is never
// listed within the bound, the create still succeeds with one warning.
func TestUniqueTag_T9_VisibilityLag(t *testing.T) {
	f := newTagCluster(nil)
	f.lag = 3
	rp := f.start(t)
	if code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x"); code != 0 || stderr != "" {
		t.Fatalf("first create: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := createTagged(rp, 102, "x", "--unique-tag", "x"); code != 1 || !strings.Contains(stderr, "already carried by vm 101") || f.posts != 1 {
		t.Fatalf("second create: exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
	}

	f = newTagCluster(nil)
	f.lag = 1 << 30
	rp = f.start(t)
	tagVisibilityBound = 50 * time.Millisecond
	code, stdout, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 0 || stdout != "qa-pve-01: vm 101 created\n" || strings.Count(stderr, "\n") != 1 ||
		!strings.HasPrefix(stderr, "warning: qa-pve-01: vm 101: tag x is not yet in PVE's cluster resource list after 50ms") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// T9, concurrent (G7): a second --unique-tag create that starts while the
// first is still waiting for its VM to be listed waits for the tag lock,
// and then sees the VM. Released before the wait, the lock would let the
// second check the lagging list, find nothing, and create a duplicate.
func TestUniqueTag_T9_ConcurrentCreateDuringTheLagWaits(t *testing.T) {
	f := newTagCluster(nil)
	f.lag = 1 << 30 // the first VM stays unlisted until the hook lists it
	rp := f.start(t)
	type out struct {
		code   int
		stderr string
	}
	second := make(chan out, 1)
	var started atomic.Bool
	f.onListing = func() {
		f.mu.Lock()
		n := f.listings
		f.mu.Unlock()
		// Listing 1 is the first create's own check; listing 2 its first
		// visibility poll. Only that one acts, and no other listing (the
		// second create's among them) ever waits on it.
		if n < 2 || !started.CompareAndSwap(false, true) {
			return
		}
		func() {
			go func() {
				code, _, stderr := createTagged(rp, 102, "x", "--unique-tag", "x")
				second <- out{code, stderr}
			}()
			// Held by the lock, the second cannot finish here; the window
			// only has to be long enough for an unlocked one to.
			select {
			case o := <-second:
				second <- o
			case <-time.After(500 * time.Millisecond):
			}
			f.mu.Lock()
			f.vms[101].visible = 0
			f.mu.Unlock()
		}()
	}
	if code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x"); code != 0 {
		t.Fatalf("first create: exit %d, stderr %q", code, stderr)
	}
	o := <-second
	f.mu.Lock()
	posts := f.posts
	f.mu.Unlock()
	if posts != 1 || o.code != 1 || !strings.Contains(o.stderr, "already carried by vm 101") {
		t.Fatalf("POSTs %d, second create exit %d, stderr %q; want one create and the second refused", posts, o.code, o.stderr)
	}
}

// T10 / C3: without --unique-tag, two creates with the same tags both
// succeed, nothing is listed or checked, and root is never dialed.
func TestUniqueTag_T10_OffByDefault(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	for _, id := range []int{101, 102} {
		if code, _, stderr := createTagged(rp, id, "x"); code != 0 {
			t.Fatalf("create %d: exit %d, %q", id, code, stderr)
		}
	}
	if f.posts != 2 || f.count("GET /api2/json/cluster/resources") != 0 || len(f.rootCmds) != 0 {
		t.Errorf("POSTs %d, REST listings %d, root commands %q; want 2, 0, none", f.posts, f.count("GET /api2/json/cluster/resources"), f.rootCmds)
	}
}

// T11: --unique-tag must be one of the create's own tags, without PVE's ';'
// — checked before any request.
func TestUniqueTag_T11_MustBeOneOfTheCreatesTags(t *testing.T) {
	for _, tc := range []struct{ tags, unique, want string }{
		{"web,db", "x", "is not one of this create's tags"},
		{"x;y", "x;y", "contains PVE's tag separator"},
		{"xy", "x", "is not one of this create's tags"},
		// TG1: given, the flag is on; an empty or blank value is refused,
		// never read as "no guard".
		{"x", "", "empty tag"},
		{"x", "   ", "empty tag"},
		{"a/b", "a/b", "is not a PVE tag"},
		{"-x", "-x", "is not a PVE tag"},
	} {
		f := newTagCluster(nil)
		rp := f.start(t)
		code, _, stderr := createTagged(rp, 101, tc.tags, "--unique-tag", tc.unique)
		if code != 1 || !strings.Contains(stderr, tc.want) || f.sent() != 0 {
			t.Errorf("tags=%s --unique-tag %s: exit %d, %d request(s), stderr %q", tc.tags, tc.unique, code, f.sent(), stderr)
		}
	}
	f := newTagCluster(nil)
	rp := f.start(t)
	if code, _, stderr := createTagged(rp, 101, "web x", "--unique-tag", "x"); code != 0 {
		t.Errorf("a space-separated tags= list: exit %d, %q", code, stderr)
	}
	// TG4: one of the create's tags in another letter case is the same tag.
	f = newTagCluster(nil)
	rp = f.start(t)
	if code, _, stderr := createTagged(rp, 101, "web;Foo", "--unique-tag", "foo"); code != 0 || f.posts != 1 {
		t.Errorf("tags=web;Foo --unique-tag foo: exit %d, POSTs %d, %q", code, f.posts, stderr)
	}
}

// TG1, the --flag= spelling: an explicitly empty --unique-tag is refused
// before any request, not taken as the flag left out.
func TestUniqueTag_T11_EqualsEmptyIsRefused(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag=")
	if code != 1 || !strings.Contains(stderr, "empty tag") || f.sent() != 0 {
		t.Fatalf("exit %d, %d request(s), stderr %q", code, f.sent(), stderr)
	}
}

// TG4: PVE matches tags case-insensitively, so a VM tagged "Foo" holds
// "foo" and "FOO" too.
func TestUniqueTag_T14_CaseInsensitive(t *testing.T) {
	for _, unique := range []string{"foo", "FOO"} {
		f := newTagCluster(map[int]string{150: "web;Foo"})
		rp := f.start(t)
		code, _, stderr := createTagged(rp, 101, unique, "--unique-tag", unique)
		if code != 1 || !strings.Contains(stderr, "already carried by vm 150") || f.posts != 0 {
			t.Errorf("--unique-tag %s beside a VM tagged Foo: exit %d, stderr %q, POSTs %d", unique, code, stderr, f.posts)
		}
	}
}

// TG4: two concurrent creates whose --unique-tag differ only in case are one
// tag to PVE, so they take one lock and create exactly one VM (the T8
// mechanism, with the second spelled differently).
func TestUniqueTag_T14_CaseVariantsShareTheLock(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	secondListed := make(chan struct{}, 1)
	var first sync.Once
	var listings int
	f.onListing = func() {
		f.mu.Lock()
		listings++
		n := listings
		f.mu.Unlock()
		if n == 2 {
			secondListed <- struct{}{}
		}
	}
	f.onCreate = func() {
		first.Do(func() {
			select {
			case <-secondListed:
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
	res := make(chan int, 2)
	for id, tag := range map[int]string{101: "Foo", 102: "foo"} {
		go func(id int, tag string) {
			code, _, _ := createTagged(rp, id, tag, "--unique-tag", tag)
			res <- code
		}(id, tag)
	}
	a, b := <-res, <-res
	f.mu.Lock()
	posts := f.posts
	f.mu.Unlock()
	if posts != 1 || a+b != 1 {
		t.Fatalf("POSTs %d, exits %d and %d; want exactly one create", posts, a, b)
	}
}

// Survivor C: the wait is for THIS VM. Another VM carrying the tag (made
// outside pveforge, mid-create) being listed is not this one being listed,
// so the wait runs to its bound and warns.
func TestUniqueTag_T9_AnotherVMIsNotThisOne(t *testing.T) {
	f := newTagCluster(nil)
	f.lag = 1 << 30
	f.onCreate = func() {
		f.mu.Lock()
		f.vms[150] = &tagVM{typ: "qemu", tags: "x"}
		f.mu.Unlock()
	}
	rp := f.start(t)
	tagVisibilityBound = 50 * time.Millisecond
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 0 || !strings.HasPrefix(stderr, "warning: qa-pve-01: vm 101: tag x is not yet in PVE's cluster resource list") {
		t.Fatalf("exit %d, stderr %q; want exit 0 and the not-yet-listed warning", code, stderr)
	}
}

// TG2: a signal during the visibility wait exits 130 (the VM WAS created),
// with one line saying so and that the wait was cut short — never exit 0
// with a claim that the whole bound elapsed, and never runRoot's generic
// "may or may not have been applied".
func TestUniqueTag_T13_SignalDuringTheVisibilityWait(t *testing.T) {
	f := newTagCluster(nil)
	f.lag = 1 << 30
	rp := f.start(t)
	tagVisibilityBound = 3 * time.Second
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	f.onListing = func() {
		f.mu.Lock()
		n := f.listings
		f.mu.Unlock()
		if n == 2 { // the first visibility poll
			cancel(interruptError{sig: syscall.SIGINT})
		}
	}
	start := time.Now()
	code, stdout, stderr := runRootInterruptible(ctx, "vm", "create", "--roster", rp, "qa-pve-01", "101", "tags=x", "--unique-tag", "x")
	if code != 130 || stdout != "qa-pve-01: vm 101 created\n" || strings.Count(stderr, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "the VM WAS created") || !strings.Contains(stderr, "interrupted") ||
		strings.Contains(stderr, "may or may not have been applied") || strings.Contains(stderr, "not yet in PVE's cluster resource list after") {
		t.Errorf("stderr = %q", stderr)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s: the wait did not stop at the signal", d)
	}
	if f.posts != 1 {
		t.Errorf("POSTs %d, want 1", f.posts)
	}
}

// TG2 and D1, the signal landing as the bound runs out: a read that returns
// only after the deadline, with the parent's context cancelled meanwhile,
// is still an interruption, never "the bound elapsed". The lister ignores
// its own deadline, so this holds however the read was bounded.
func TestWaitTagVisible_SignalAtTheBound(t *testing.T) {
	origBound := tagVisibilityBound
	t.Cleanup(func() { tagVisibilityBound = origBound })
	tagVisibilityBound = 50 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	late := listerFunc(func(context.Context) ([]pve.Guest, error) {
		cancel(interruptError{sig: syscall.SIGTERM})
		time.Sleep(150 * time.Millisecond) // past the bound
		return nil, errors.New("read cut short")
	})
	visible, err := waitTagVisible(ctx, late, "x", 101)
	var ie interruptError
	if visible || !errors.As(err, &ie) {
		t.Fatalf("waitTagVisible = %t, %v; want false and the interruption", visible, err)
	}
}

// listerFunc adapts a func to guestLister.
type listerFunc func(ctx context.Context) ([]pve.Guest, error)

func (f listerFunc) ClusterGuests(ctx context.Context) ([]pve.Guest, error) { return f(ctx) }

// hung is a root read that never answers: it returns only when its own
// context ends, as sshexec's Run does.
var hung = listerFunc(func(ctx context.Context) ([]pve.Guest, error) {
	<-ctx.Done()
	return nil, ctx.Err()
})

// within runs fn and fails the test if it has not returned within d: a
// guard against the very hang these tests are about.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("still running after %s: a root read is not bounded", d)
	}
}

// D1: the check's root read has its own deadline, and running out of it
// refuses the create (fail closed).
func TestCheckTagUnique_AHungReadRefusesInTime(t *testing.T) {
	orig := tagReadTimeout
	t.Cleanup(func() { tagReadTimeout = orig })
	tagReadTimeout = 100 * time.Millisecond
	within(t, 3*time.Second, func() {
		err := checkTagUnique(context.Background(), hung, "x")
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "cannot verify tag uniqueness") {
			t.Errorf("checkTagUnique = %v; want a refusal on the read's deadline", err)
		}
	})
}

// D1: each poll of the wait is bounded, by tagReadTimeout and by the time
// left before the bound, and a poll that times out is polled past: the
// wait ends at the bound with visible=false and NO interruption error.
func TestWaitTagVisible_HungReadsEndAtTheBound(t *testing.T) {
	origBound, origPoll, origRead := tagVisibilityBound, tagVisibilityPoll, tagReadTimeout
	t.Cleanup(func() { tagVisibilityBound, tagVisibilityPoll, tagReadTimeout = origBound, origPoll, origRead })
	tagVisibilityBound, tagVisibilityPoll = 300*time.Millisecond, 5*time.Millisecond
	for name, readTimeout := range map[string]time.Duration{
		"reads shorter than the bound": 40 * time.Millisecond,
		"a read longer than the bound": time.Hour, // cut to the time left
	} {
		t.Run(name, func(t *testing.T) {
			tagReadTimeout = readTimeout
			var polls atomic.Int32
			counting := listerFunc(func(ctx context.Context) ([]pve.Guest, error) {
				polls.Add(1)
				return hung(ctx)
			})
			within(t, 3*time.Second, func() {
				visible, err := waitTagVisible(context.Background(), counting, "x", 101)
				if visible || err != nil {
					t.Errorf("waitTagVisible = %t, %v; want false and no error (a timed-out read is not an interruption)", visible, err)
				}
			})
			if readTimeout < tagVisibilityBound && polls.Load() < 2 {
				t.Errorf("%d poll(s); a timed-out read must be polled past", polls.Load())
			}
		})
	}
}

// D1 end to end, over SSH: pmxcfs hangs. In the check, the create is
// refused within the read's deadline, with nothing created; in the wait,
// the create ends at the bound with its warning and exit 0.
func TestUniqueTag_D1_AHungRootReadIsBounded(t *testing.T) {
	f := newTagCluster(nil)
	f.hangFrom = 1
	rp := f.start(t)
	tagReadTimeout = 200 * time.Millisecond
	within(t, 5*time.Second, func() {
		code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
		if code != 1 || !strings.Contains(stderr, "cannot verify tag uniqueness") || f.posts != 0 {
			t.Errorf("hung check: exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
		}
	})

	f = newTagCluster(nil)
	f.hangFrom = 2 // the check answers; every poll of the wait hangs
	rp = f.start(t)
	tagVisibilityBound, tagReadTimeout = 300*time.Millisecond, 100*time.Millisecond
	within(t, 5*time.Second, func() {
		code, stdout, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
		if code != 0 || stdout != "qa-pve-01: vm 101 created\n" || !strings.HasPrefix(stderr, "warning: qa-pve-01: vm 101: tag x is not yet in PVE's cluster resource list after 300ms") {
			t.Errorf("hung wait: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}

// S1: root is reached, the password asked for and the session dialed,
// BEFORE the tag lock is taken. With the lock held elsewhere and a
// 20ms --lock-wait, a dial or password failure is what is reported: the
// lock was never waited for.
func TestUniqueTag_S1_RootIsReachedBeforeTheLock(t *testing.T) {
	hold := func(t *testing.T, rp string) {
		unlock, err := lock.Mutation(context.Background(), rp, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm-tag", ID: "x"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unlock() })
	}
	t.Run("the dial", func(t *testing.T) {
		f := newTagCluster(nil)
		f.sshDown = true
		rp := f.start(t)
		hold(t, rp)
		code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x", "--lock-wait", "20ms")
		if code != 1 || !strings.Contains(stderr, "connect as root") || strings.Contains(stderr, "lock") {
			t.Fatalf("exit %d, stderr %q; want the dial's failure, not the lock's", code, stderr)
		}
	})
	t.Run("the password", func(t *testing.T) {
		f := newTagCluster(nil)
		srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
		t.Cleanup(srv.Close)
		t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
		t.Setenv(pvePasswordEnvVar, "")
		rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
		hold(t, rp)
		code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x", "--no-ssh-key", "--lock-wait", "20ms")
		if code != 1 || !strings.Contains(stderr, "no PVE password available") || strings.Contains(stderr, "lock") {
			t.Fatalf("exit %d, stderr %q; want the password's failure, not the lock's", code, stderr)
		}
	})
}

// TG2, runRoot's own side: an error marked errVMCreatedTagWaitInterrupted is
// printed as it is, with the signal's exit status.
func TestRunRoot_VMCreatedTagWaitInterruptedIsExempt(t *testing.T) {
	err := fmt.Errorf("vm create: vm 101 on qa-pve-01: %w: tag x (%w)", errVMCreatedTagWaitInterrupted, context.Canceled)
	code, stderr := runRootFailing(t, err, func(cancel context.CancelCauseFunc) { cancel(interruptError{sig: syscall.SIGTERM}) })
	if code != 143 || stderr != err.Error()+"\n" {
		t.Errorf("exit %d, stderr %q; want 143 and the error as it is", code, stderr)
	}
}

// T12: --lock-wait bounds the wait for the tag's lock, held here by another
// pveforge process, and nothing is sent meanwhile.
func TestUniqueTag_T12_LockWaitBoundsTheTagLock(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	unlock, err := lock.Mutation(context.Background(), rp, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm-tag", ID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x", "--lock-wait", "20ms")
	if code != 1 || !strings.Contains(stderr, "acquire the lock for tag x") || f.sent() != 0 {
		t.Fatalf("exit %d, %d request(s), stderr %q", code, f.sent(), stderr)
	}
}

// C1: a container carrying the tag refuses the create, named "ct N", in any
// letter case: the tag namespace is shared by VMs and containers.
func TestUniqueTag_C1_AContainerCarriesTheTag(t *testing.T) {
	for _, tags := range []string{"x", "db;X"} {
		f := newTagCluster(nil).addCT(200, tags)
		rp := f.start(t)
		code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
		if code != 1 || !strings.Contains(stderr, "already carried by ct 200") || f.posts != 0 {
			t.Errorf("a container tagged %q: exit %d, stderr %q, POSTs %d", tags, code, stderr, f.posts)
		}
	}
}

// C2: a container and a VM both carrying it is ambiguous, and refused.
func TestUniqueTag_C2_AContainerAndAVM(t *testing.T) {
	f := newTagCluster(map[int]string{150: "x"}).addCT(200, "x")
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 1 || !strings.Contains(stderr, "more than one guest") || f.posts != 0 {
		t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
	}
}

// H1: the fail-open case the token cannot see. The token's list hides VM
// 150 (an ACL on /vms/150, a pool NoAccess: the fake's REST list is empty),
// root's list shows it: refused. Neither the token's list nor its rights
// are ever read.
func TestUniqueTag_H1_AGuestHiddenFromTheTokenIsSeen(t *testing.T) {
	f := newTagCluster(map[int]string{150: "x"})
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 1 || !strings.Contains(stderr, "already carried by vm 150") || f.posts != 0 {
		t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
	}
	if n := f.count("GET /api2/json/cluster/resources") + f.count("GET /api2/json/access/"); n != 0 {
		t.Errorf("the token's list or rights were read %d time(s)", n)
	}
}

// H3: --unique-tag needs root. A target holding no SSH key is refused
// without --no-ssh-key, before anything is sent; with it, root is reached
// with the PVE password. --no-ssh-key without --unique-tag is refused.
func TestUniqueTag_H3_RootAccessRules(t *testing.T) {
	f := newTagCluster(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 5*time.Second))
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(f.exec)
	fs.AllowPassword("root", "root-pw")
	fs.Start()
	rootAt(t, fs)
	rp := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01") // no [targets.ssh]

	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 1 || !strings.Contains(stderr, "holds no SSH key: pass --no-ssh-key") || f.sent() != 0 {
		t.Fatalf("keyless, no flag: exit %d, %d sent, stderr %q", code, f.sent(), stderr)
	}
	code, _, stderr = createTagged(rp, 101, "x", "--no-ssh-key")
	if code != 1 || !strings.Contains(stderr, "--no-ssh-key only applies with --unique-tag") || f.sent() != 0 {
		t.Fatalf("--no-ssh-key alone: exit %d, %d sent, stderr %q", code, f.sent(), stderr)
	}
	t.Setenv(pvePasswordEnvVar, "root-pw")
	code, stdout, stderr := createTagged(rp, 101, "x", "--unique-tag", "x", "--no-ssh-key")
	if code != 0 || stdout != "qa-pve-01: vm 101 created\n" || f.posts != 1 {
		t.Fatalf("keyless with --no-ssh-key: exit %d, stdout %q, stderr %q, POSTs %d", code, stdout, stderr, f.posts)
	}
	for _, c := range f.rootCmds {
		if c != bootstrap.ClusterGuestsCommand {
			t.Errorf("root ran %q", c)
		}
	}
}
