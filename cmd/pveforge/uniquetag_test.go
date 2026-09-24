package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-vm-create-existing-tag-guard: `vm create --unique-tag X`, through
// runRoot, over tagClusterFake — a stateful cluster whose /cluster/resources
// lists the VMs it holds, each only once `lag` further listings have passed.

type tagVM struct {
	tags    string
	visible int // listings still to pass before it is listed
}

type tagClusterFake struct {
	mu        sync.Mutex
	vms       map[int]*tagVM
	lag       int    // a created VM is listed only after this many listings
	resources string // "" normal, or "error", "null", "404"
	audit     bool   // the token holds VM.Audit on /vms, propagating
	perms     string // "" normal, or "error", "404", "malformed": the rights read
	posts     int
	listings  int
	requests  []string
	onCreate  func() // runs inside the create POST, before it is recorded
	onListing func() // runs on each /cluster/resources read
}

func newTagCluster(existing map[int]string) *tagClusterFake {
	f := &tagClusterFake{vms: map[int]*tagVM{}, audit: true}
	for id, tags := range existing {
		f.vms[id] = &tagVM{tags: tags}
	}
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
	return newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
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
	case path == base+"/access/permissions":
		f.mu.Lock()
		audit, mode := f.audit, f.perms
		f.mu.Unlock()
		switch mode {
		case "error":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "404":
			w.WriteHeader(http.StatusNotFound)
			return
		case "malformed":
			data([]string{"not", "a", "tree"})
			return
		}
		perms := map[string]int{"VM.Console": 1}
		if audit {
			perms["VM.Audit"] = 1
		}
		data(map[string]any{r.URL.Query().Get("path"): perms})
	case path == base+"/cluster/resources":
		f.mu.Lock()
		f.listings++
		mode, hook := f.resources, f.onListing
		var list []map[string]any
		for id, vm := range f.vms {
			if vm.visible > 0 {
				vm.visible--
				continue
			}
			list = append(list, map[string]any{"id": fmt.Sprintf("qemu/%d", id), "type": "qemu", "vmid": id, "node": "qa-pve-01", "tags": vm.tags})
		}
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
		switch mode {
		case "error":
			w.WriteHeader(http.StatusInternalServerError)
			return
		case "404":
			w.WriteHeader(http.StatusNotFound)
			return
		case "null":
			data(nil)
			return
		}
		if list == nil {
			list = []map[string]any{}
		}
		data(list)
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
		f.vms[id] = &tagVM{tags: strings.Join(tagSplit.Split(strings.TrimSpace(r.PostForm.Get("tags")), -1), ";"), visible: f.lag}
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
	if code != 1 || !strings.Contains(stderr, "more than one VM") || f.posts != 0 {
		t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
	}
}

// T3, T4, T5: a listing that fails, reads as null, or answers 404 (a failed
// read, not "no match") refuses; it is never read as "nobody has the tag".
func TestUniqueTag_T3_T4_T5_AFailedListingRefuses(t *testing.T) {
	for _, mode := range []string{"error", "null", "404"} {
		t.Run(mode, func(t *testing.T) {
			f := newTagCluster(nil)
			f.resources = mode
			rp := f.start(t)
			code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
			if code != 1 || !strings.Contains(stderr, "cannot verify tag uniqueness") || f.posts != 0 {
				t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
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
}

// T7: a token without VM.Audit on /vms cannot see every VM, so "no match"
// cannot be trusted: refused, no listing trusted, no create.
func TestUniqueTag_T7_NoAuditRightsRefuses(t *testing.T) {
	f := newTagCluster(nil)
	f.audit = false
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
	if code != 1 || !strings.Contains(stderr, "cannot verify tag uniqueness") || !strings.Contains(stderr, "VM.Audit on /vms") || f.posts != 0 {
		t.Fatalf("exit %d, stderr %q, POSTs %d", code, stderr, f.posts)
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

// T10: without --unique-tag, two creates with the same tags both succeed,
// and nothing is listed or checked.
func TestUniqueTag_T10_OffByDefault(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	for _, id := range []int{101, 102} {
		if code, _, stderr := createTagged(rp, id, "x"); code != 0 {
			t.Fatalf("create %d: exit %d, %q", id, code, stderr)
		}
	}
	if f.posts != 2 || f.count("GET /api2/json/cluster/resources") != 0 || f.count("GET /api2/json/access/") != 0 {
		t.Errorf("POSTs %d, listings %d, rights reads %d; want 2, 0, 0", f.posts, f.count("GET /api2/json/cluster/resources"), f.count("GET /api2/json/access/"))
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
		if code != 1 || !strings.Contains(stderr, tc.want) || f.count("") != 0 {
			t.Errorf("tags=%s --unique-tag %s: exit %d, %d request(s), stderr %q", tc.tags, tc.unique, code, f.count(""), stderr)
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
	if code != 1 || !strings.Contains(stderr, "empty tag") || f.count("") != 0 {
		t.Fatalf("exit %d, %d request(s), stderr %q", code, f.count(""), stderr)
	}
}

// TG3, T7b: the rights read itself failing — a 500, a 404, or an answer
// that is not a permission tree — refuses, with no listing trusted and no
// create: an unreadable right is never read as held.
func TestUniqueTag_T7b_RightsReadFailureRefuses(t *testing.T) {
	for _, mode := range []string{"error", "404", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newTagCluster(nil)
			f.perms = mode
			rp := f.start(t)
			code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x")
			if code != 1 || !strings.Contains(stderr, "cannot verify tag uniqueness") || !strings.Contains(stderr, "rights on /vms") ||
				f.posts != 0 || f.count("GET /api2/json/cluster/resources") != 0 {
				t.Fatalf("exit %d, stderr %q, POSTs %d, listings %d", code, stderr, f.posts, f.count("GET /api2/json/cluster/resources"))
			}
		})
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
		f.vms[150] = &tagVM{tags: "x"}
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

// TG2, the signal landing as the bound runs out: the last poll returns
// after the deadline with the context already cancelled. That is still an
// interruption, never "the bound elapsed".
func TestUniqueTag_T13_SignalAtTheBound(t *testing.T) {
	f := newTagCluster(nil)
	f.lag = 1 << 30
	rp := f.start(t)
	tagVisibilityBound = 50 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	f.onListing = func() {
		f.mu.Lock()
		n := f.listings
		f.mu.Unlock()
		if n == 2 {
			time.Sleep(150 * time.Millisecond) // past the bound, then the signal
			cancel(interruptError{sig: syscall.SIGTERM})
		}
	}
	code, _, stderr := runRootInterruptible(ctx, "vm", "create", "--roster", rp, "qa-pve-01", "101", "tags=x", "--unique-tag", "x")
	if code != 143 || !strings.Contains(stderr, "the VM WAS created") {
		t.Fatalf("exit %d, stderr %q; want 143 and the interruption", code, stderr)
	}
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
	if code != 1 || !strings.Contains(stderr, "acquire the lock for tag x") || f.count("") != 0 {
		t.Fatalf("exit %d, %d request(s), stderr %q", code, f.count(""), stderr)
	}
}
