package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/lock/lockguard"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Contract plan unit U-A, family S1 (vm): exit 3 (a dispatched change whose
// outcome was not observed) and exit 4 (refused before anything was changed)
// on `vm create`, `vm set`, `vm snapshot create|delete|rollback` and `vm
// destroy`, through runRoot, with THREE write logs per fixture (the REST
// front's non-GET log, the root-SSH command log, the roster snapshot) and
// the run's own write gate agreeing with them (writeEnv.observe).
//
// Every refusal row has a post-write twin: the SAME verb advanced past its
// first write, which must exit anything but 4 and must really have written.

// ------------------------------------------------------------ fixtures

const uaNode = "qa-pve-01"

// uaFix is one fixture: the argv, the three logs, and what the dispatch is.
type uaFix struct {
	args  []string
	env   writeEnv
	front *uaFront
	// isDispatch picks the request that creates the PVE task (the verb's POST
	// or DELETE), for the "response carries no UPID" case.
	isDispatch func(r *http.Request) bool
	// dispatches is how many writes the verb sends before its wait: the exact
	// length of the REST write log on a run that reaches the wait.
	dispatches int
}

func uaTimings(t *testing.T) {
	t.Helper()
	t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 2*time.Second))
}

func (f *uaFix) writes() []string { return f.env.restWrites() }

// uaCreateFix is `vm create` against the stateful create fake, fronted.
func uaCreateFix(t *testing.T, fake *vmCreateFake, extra ...string) *uaFix {
	t.Helper()
	const vmid = 100
	srv := newVMCreateServer(t, uaNode, vmid, fake)
	t.Cleanup(srv.Close)
	front := newUAFront(t, srv.URL)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rp := newTestRosterWithTLSTarget(t, front.srv, uaNode, uaNode)
	return &uaFix{
		args:  append([]string{"vm", "create", "--roster", rp, uaNode, strconv.Itoa(vmid), "cores=4"}, extra...),
		env:   writeEnv{roster: rp, restWrites: front.writeLog, sshWrites: noLog}, // a REST-only verb: no root SSH
		front: front,
		isDispatch: func(r *http.Request) bool {
			return r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/"+uaNode+"/qemu"
		},
		dispatches: 1,
	}
}

// uaSnapFix is `vm snapshot <verb>` against the snapshot fake, fronted.
func uaSnapFix(t *testing.T, fake *snapshotFakePVE, args ...string) *uaFix {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(fake.serve))
	t.Cleanup(srv.Close)
	front := newUAFront(t, srv.URL)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rp := newTestRosterWithTLSTarget(t, front.srv, uaNode, uaNode)
	verb := args[0]
	return &uaFix{
		args:  append([]string{"vm", "snapshot", args[0], "--roster", rp}, args[1:]...),
		env:   writeEnv{roster: rp, restWrites: front.writeLog, sshWrites: noLog},
		front: front,
		isDispatch: func(r *http.Request) bool {
			switch verb {
			case "create":
				return r.Method == http.MethodPost && r.URL.Path == snapBase+"/snapshot"
			case "delete":
				return r.Method == http.MethodDelete
			}
			return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rollback")
		},
		dispatches: 1,
	}
}

func (f *uaFix) lockKey() lock.ObjectKey {
	return lock.ObjectKey{TargetID: uaNode, Kind: "vm", ID: "100"}
}

// ------------------------------------------------------------ the wait boundaries (AC-W2)

// uaWaitMatrix is the per-wait-boundary fixture set. build makes a FRESH
// fixture (every fake is stateful). Each case asserts the dispatch count (the
// exact REST write log), the poll count (the poll is really reached, or really
// not), the exit status, and the three-log/gate agreement.
func uaWaitMatrix(t *testing.T, boundary string, build func(t *testing.T) *uaFix) {
	t.Helper()
	// Poll failure: the status endpoint answers 503 forever: three transient
	// polls, the fourth gives up. The wait STARTED and did not observe: exit 3,
	// the UPID on stderr, the dispatch happened once.
	t.Run(boundary+"/poll fails -> 3", func(t *testing.T) {
		uaTimings(t)
		fx := build(t)
		fx.front.override = func(r *http.Request) uaReply {
			if _, ok := isTaskPoll(r); ok {
				return uaStatus(http.StatusServiceUnavailable)
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("%s: exit %d, want 3; stderr %q", boundary, o.code, o.stderr)
		}
		if got := len(o.rest); got != fx.dispatches {
			t.Errorf("%s: dispatches = %d (%q), want %d", boundary, got, o.rest, fx.dispatches)
		}
		if got := fx.front.polls.Load(); got != 4 {
			t.Errorf("%s: polls = %d, want 4 (three transient, the fourth gives up): the wait was not the thing that failed", boundary, got)
		}
		if !strings.Contains(o.stderr, "UPID:") {
			t.Errorf("%s: the UPID is not on stderr: %q", boundary, o.stderr)
		}
	})
	// A wait that never leaves "running" ends at its deadline: exit 3.
	t.Run(boundary+"/poll times out -> 3", func(t *testing.T) {
		t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 120*time.Millisecond))
		fx := build(t)
		fx.front.override = func(r *http.Request) uaReply {
			if upid, ok := isTaskPoll(r); ok {
				return uaAnswer(taskPayload(upid, "running", ""))
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 || fx.front.polls.Load() < 2 || len(o.rest) != fx.dispatches {
			t.Fatalf("%s: exit %d polls %d dispatches %d, want 3, >=2, %d; stderr %q", boundary, o.code, fx.front.polls.Load(), len(o.rest), fx.dispatches, o.stderr)
		}
	})
	// A response with no UPID is not a wait: the decode failure stays 1 and no
	// poll is made (the A6 residual, unchanged).
	t.Run(boundary+"/no UPID in the response -> 1", func(t *testing.T) {
		uaTimings(t)
		fx := build(t)
		fx.front.override = func(r *http.Request) uaReply {
			if fx.isDispatch(r) {
				return uaAnswer("null")
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || fx.front.polls.Load() != 0 {
			t.Fatalf("%s: exit %d polls %d, want 1 and 0; stderr %q", boundary, o.code, fx.front.polls.Load(), o.stderr)
		}
	})
	// A task SEEN to fail is a known outcome: 1.
	t.Run(boundary+"/task seen to fail -> 1", func(t *testing.T) {
		uaTimings(t)
		fx := build(t)
		fx.front.override = func(r *http.Request) uaReply {
			if upid, ok := isTaskPoll(r); ok {
				return uaAnswer(taskPayload(upid, "stopped", "ERROR: it failed"))
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || fx.front.polls.Load() < 1 {
			t.Fatalf("%s: exit %d polls %d, want 1 and >=1; stderr %q", boundary, o.code, fx.front.polls.Load(), o.stderr)
		}
	})
	// OK and WARNINGS are success.
	for _, exit := range []string{"OK", "WARNINGS: 2"} {
		t.Run(boundary+"/task "+exit+" -> 0", func(t *testing.T) {
			uaTimings(t)
			fx := build(t)
			fx.front.override = func(r *http.Request) uaReply {
				if upid, ok := isTaskPoll(r); ok {
					return uaAnswer(taskPayload(upid, "stopped", exit))
				}
				return uaReply{}
			}
			o := fx.env.observe(t, fx.args...)
			o.wantNotRefusedAfterWrite(t)
			if o.code != 0 || fx.front.polls.Load() < 1 {
				t.Fatalf("%s: exit %d polls %d, want 0 and >=1; stderr %q", boundary, o.code, fx.front.polls.Load(), o.stderr)
			}
		})
	}
}

func TestUAS1_WaitBoundary_VMCreate(t *testing.T) {
	uaWaitMatrix(t, "vm create (idempotent/vmcreate.go wait)", func(t *testing.T) *uaFix { return uaCreateFix(t, &vmCreateFake{}) })
}

func TestUAS1_WaitBoundary_SnapshotCreate(t *testing.T) {
	uaWaitMatrix(t, "vm snapshot create (pve/snapshot.go create wait)", func(t *testing.T) *uaFix {
		return uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "n")
	})
}

func TestUAS1_WaitBoundary_SnapshotDelete(t *testing.T) {
	uaWaitMatrix(t, "vm snapshot delete (pve/snapshot.go cascade wait)", func(t *testing.T) *uaFix {
		return uaSnapFix(t, newSnapshotFake(t, "a", "b"), "delete", uaNode, "100", "b")
	})
}

func TestUAS1_WaitBoundary_SnapshotRollback(t *testing.T) {
	uaWaitMatrix(t, "vm snapshot rollback (pve/snapshot.go rollback wait)", func(t *testing.T) *uaFix {
		return uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", "--no-witness", uaNode, "100", "a")
	})
}

// ------------------------------------------------------------ vm create: refusals and twins

func TestUAS1_VMCreate_RefusalBoundaries_Exit4_ZeroWrites(t *testing.T) {
	type row struct {
		name  string
		fake  *vmCreateFake
		extra []string
		args  func(fx *uaFix) []string // optional argv rewrite
		hold  bool                     // hold the VM's lock elsewhere
	}
	rows := []row{
		{name: "vmid taken (pre-check)", fake: &vmCreateFake{nextIDTaken: true}},
		{name: "vmid check cannot be made (fails closed)", fake: &vmCreateFake{nextIDBroken: true}},
		{name: "orphan ipconfig (Validate)", fake: &vmCreateFake{}, args: func(fx *uaFix) []string { return append(fx.args, "ipconfig1=ip=dhcp") }},
		{name: "taken between the check and the create (Changed==false backstop)", fake: newPresentFake()},
		{name: "object lock held elsewhere", fake: &vmCreateFake{}, extra: []string{"--lock-wait", "50ms"}, hold: true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			fx := uaCreateFix(t, r.fake, r.extra...)
			args := fx.args
			if r.args != nil {
				args = r.args(fx)
			}
			if r.hold {
				holdLock(t, fx.env.roster, fx.lockKey())
			}
			o := fx.env.observe(t, args...)
			o.wantRefusedBeforeAnyWrite(t)
			if r.hold {
				// POSITIVE CONTROL: the lock acquisition created bookkeeping
				// beside the roster, and exit 4 still holds with zero entries
				// in all three logs, so the exclusion list does not hide a write.
				if _, err := os.Stat(fx.env.roster + ".locks"); err != nil {
					t.Fatalf("positive control: no %s.locks was created: %v", fx.env.roster, err)
				}
			}
		})
	}
}

// The twins: the SAME verb, advanced past the create POST, must not exit 4.
func TestUAS1_VMCreate_PostWriteTwins_NotExit4(t *testing.T) {
	// The POST itself is rejected by PVE (the collision at the create call): the
	// write left the process, the answer is a plain failure.
	t.Run("create POST rejected by PVE -> 1", func(t *testing.T) {
		fx := uaCreateFix(t, &vmCreateFake{createRejects: true})
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || len(o.rest) != 1 {
			t.Fatalf("exit %d writes %q, want 1 and one POST; stderr %q", o.code, o.rest, o.stderr)
		}
	})
	// The same "already exists" refusal as the backstop's, but raised AFTER this
	// run wrote: the write happens (POST answered, task OK), and the VM is then
	// reported not found: advisory, exit 0, never 4.
	t.Run("created, then the re-read finds nothing -> 0", func(t *testing.T) {
		uaTimings(t)
		fx := uaCreateFix(t, &vmCreateFake{})
		fx.front.override = func(r *http.Request) uaReply {
			// after the create POST the VM's reads fail: the re-read cannot confirm
			if len(fx.front.writeLog()) > 0 && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status/current") {
				return uaStatus(http.StatusInternalServerError)
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, want 0 (advisory); stderr %q", o.code, o.stderr)
		}
	})
}

// --unique-tag: the root-SSH side and the tag lock. Refusals (the tag is
// carried; more than one guest carries it; the listing cannot be verified;
// the tag lock is held) are 4 with zero writes in REST, SSH and the roster;
// the twin is the create POST failing after the check passed.
func uaTagFix(t *testing.T, f *tagClusterFake, front func(*uaFront)) (rp string, fr *uaFront, env writeEnv) {
	t.Helper()
	backend := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(backend.Close)
	fr = newUAFront(t, backend.URL)
	if front != nil {
		front(fr)
	}
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
	rp = newTestRosterWithSSHTarget(t, fr.srv, fs)
	t.Cleanup(func() { close(f.release) })
	rootAt(t, fs)
	env = writeEnv{roster: rp, restWrites: fr.writeLog, sshWrites: func() []string {
		// Root is only ever used for the one pvesh READ; any other command is a write.
		f.mu.Lock()
		defer f.mu.Unlock()
		var w []string
		for _, c := range f.rootCmds {
			if c != bootstrap.ClusterGuestsCommand {
				w = append(w, c)
			}
		}
		return w
	}}
	return rp, fr, env
}

func TestUAS1_VMCreate_UniqueTag_RefusalsAndTwin(t *testing.T) {
	rows := []struct {
		name string
		mk   func() *tagClusterFake
		hold bool
	}{
		{"tag carried by a VM", func() *tagClusterFake { return newTagCluster(map[int]string{150: "web;x"}) }, false},
		{"tag carried by a container", func() *tagClusterFake { return newTagCluster(nil).addCT(200, "x") }, false},
		{"tag carried by more than one guest", func() *tagClusterFake { return newTagCluster(map[int]string{150: "x", 151: "x"}) }, false},
		{"listing cannot be verified (fails closed)", func() *tagClusterFake { f := newTagCluster(nil); f.resources = "garbage"; return f }, false},
		{"tag lock held elsewhere", func() *tagClusterFake { return newTagCluster(nil) }, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := r.mk()
			rp, _, env := uaTagFix(t, f, nil)
			args := []string{"vm", "create", "--roster", rp, uaNode, "101", "tags=x;web", "--unique-tag", "x"}
			if r.hold {
				holdLock(t, rp, lock.ObjectKey{TargetID: uaNode, Kind: "vm-tag", ID: "x"})
				args = append(args, "--lock-wait", "50ms")
			}
			o := env.observe(t, args...)
			o.wantRefusedBeforeAnyWrite(t)
			// The SSH side was live: root ran its one read before the refusal
			// (except where the refusal is the lock, which precedes the read).
			f.mu.Lock()
			reads := len(f.rootCmds)
			f.mu.Unlock()
			if !r.hold && reads == 0 {
				t.Fatalf("vacuous: root's listing was never read, so the SSH log was never exercised")
			}
			if r.hold {
				if _, err := os.Stat(rp + ".locks"); err != nil {
					t.Fatalf("positive control: no lock bookkeeping was created: %v", err)
				}
			}
		})
	}
	// Twin: the check passes, the create POST is then rejected: the write left
	// the process, so the exit is not 4.
	t.Run("twin: check passed, create POST rejected -> 1", func(t *testing.T) {
		f := newTagCluster(nil)
		rp, _, env := uaTagFix(t, f, func(fr *uaFront) {
			fr.override = func(r *http.Request) uaReply {
				if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/qemu") {
					return uaStatus(http.StatusInternalServerError)
				}
				return uaReply{}
			}
		})
		o := env.observe(t, "vm", "create", "--roster", rp, uaNode, "101", "tags=x;web", "--unique-tag", "x")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
}

// ------------------------------------------------------------ vm set

func uaSetFix(t *testing.T, failField string, extra ...string) *uaFix {
	t.Helper()
	srv := newVMConfigServer(t, failField, 500, "pve says no", nil)
	t.Cleanup(srv.Close)
	front := newUAFront(t, srv.URL)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rp := newTestRosterWithTLSTarget(t, front.srv, uaNode, uaNode)
	return &uaFix{
		args:  append([]string{"vm", "set", "--roster", rp}, append(extra, uaNode, "100")...),
		env:   writeEnv{roster: rp, restWrites: front.writeLog, sshWrites: noLog},
		front: front,
	}
}

func TestUAS1_VMSet_RefusalBoundaries_Exit4_ZeroWrites(t *testing.T) {
	for _, c := range []struct {
		name string
		tail []string
		hold bool
	}{
		{"a field both set and deleted", []string{"--delete", "cores", "cores=4"}, false},
		{"a field deleted twice", []string{"--delete", "cores", "--delete", "cores"}, false},
		{"object lock held elsewhere", []string{"--lock-wait", "50ms", "cores=4"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			fx := uaSetFix(t, "")
			args := append([]string{"vm", "set", "--roster", fx.env.roster, uaNode, "100"}, c.tail...)
			if c.hold {
				holdLock(t, fx.env.roster, fx.lockKey())
			}
			o := fx.env.observe(t, args...)
			o.wantRefusedBeforeAnyWrite(t)
			if c.hold {
				if _, err := os.Stat(fx.env.roster + ".locks"); err != nil {
					t.Fatalf("positive control: no lock bookkeeping: %v", err)
				}
			}
		})
	}
}

func TestUAS1_VMSet_PostWriteTwins_NotExit4(t *testing.T) {
	// PVE rejects the config PUT: a plain failure after the write left.
	t.Run("PUT rejected -> 1", func(t *testing.T) {
		fx := uaSetFix(t, "cores")
		o := fx.env.observe(t, "vm", "set", "--roster", fx.env.roster, uaNode, "100", "cores=4")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	// The named residual: vm set is a SYNCHRONOUS REST write with no task wait,
	// so a PUT whose response is lost is exit 1 (not 3, not 4): not proof that
	// nothing changed. The fault must ARRIVE (instrument #7).
	t.Run("PUT response lost -> 1 (named residual)", func(t *testing.T) {
		fx := uaSetFix(t, "")
		fx.front.override = func(r *http.Request) uaReply {
			if r.Method == http.MethodPut {
				return uaDrop()
			}
			return uaReply{}
		}
		o := fx.env.observe(t, "vm", "set", "--roster", fx.env.roster, uaNode, "100", "cores=4")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1 (lost PUT response); stderr %q", o.code, o.stderr)
		}
		if fx.front.faults.Load() < 1 || len(o.rest) < 1 {
			t.Fatalf("the fault never arrived: faults %d writes %q", fx.front.faults.Load(), o.rest)
		}
	})
}

// ------------------------------------------------------------ vm snapshot

func TestUAS1_Snapshot_RefusalBoundaries_Exit4_ZeroWrites(t *testing.T) {
	type row struct {
		name string
		mk   func(t *testing.T) *uaFix
		hold bool
	}
	rows := []row{
		{"create: reserved name current", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "current")
		}, false},
		{"create: reserved name pending (any case)", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "Pending")
		}, false},
		{"create: name exists", func(t *testing.T) *uaFix { return uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "a") }, false},
		{"create: collision list unreadable (fails closed)", func(t *testing.T) *uaFix {
			f := newSnapshotFake(t, "a")
			f.listFail = true
			return uaSnapFix(t, f, "create", uaNode, "100", "n")
		}, false},
		{"create: object lock held", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "n", "--lock-wait", "50ms")
		}, true},
		{"delete: reserved name", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "delete", uaNode, "100", "a", "current")
		}, false},
		{"delete: pre-state list unreadable", func(t *testing.T) *uaFix {
			f := newSnapshotFake(t, "a")
			f.listFail = true
			return uaSnapFix(t, f, "delete", uaNode, "100", "a")
		}, false},
		{"delete: object lock held", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "delete", uaNode, "100", "a", "--lock-wait", "50ms")
		}, true},
		{"rollback: newer snapshots exist", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a", "b", "c"), "rollback", uaNode, "100", "a")
		}, false},
		{"rollback: target not in the list", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", uaNode, "100", "zzz")
		}, false},
		{"rollback: list unreadable", func(t *testing.T) *uaFix {
			f := newSnapshotFake(t, "a")
			f.listFail = true
			return uaSnapFix(t, f, "rollback", uaNode, "100", "a")
		}, false},
		// --no-witness skips the verb's own list read, so these reach pve.NewerSnapshots.
		{"rollback --no-witness: target not in the list (NewerSnapshots)", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", "--no-witness", uaNode, "100", "zzz")
		}, false},
		{"rollback --no-witness: list unreadable (NewerSnapshots)", func(t *testing.T) *uaFix {
			f := newSnapshotFake(t, "a")
			f.listFail = true
			return uaSnapFix(t, f, "rollback", "--no-witness", uaNode, "100", "a")
		}, false},
		{"rollback --no-witness: two snapshots share a snaptime (cannot pre-flight)", func(t *testing.T) *uaFix {
			f := newSnapshotFake(t, "a", "b")
			sb := f.snaps["b"]
			sb.snaptime = f.snaps["a"].snaptime
			f.snaps["b"] = sb
			return uaSnapFix(t, f, "rollback", "--no-witness", uaNode, "100", "a")
		}, false},
		{"rollback: reserved name", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", "--no-witness", uaNode, "100", "current")
		}, false},
		{"rollback: object lock held", func(t *testing.T) *uaFix {
			return uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", uaNode, "100", "a", "--lock-wait", "50ms")
		}, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			fx := r.mk(t)
			if r.hold {
				holdLock(t, fx.env.roster, fx.lockKey())
			}
			o := fx.env.observe(t, fx.args...)
			o.wantRefusedBeforeAnyWrite(t)
			if r.hold {
				if _, err := os.Stat(fx.env.roster + ".locks"); err != nil {
					t.Fatalf("positive control: no lock bookkeeping: %v", err)
				}
			}
		})
	}
}

// The twins of the snapshot refusals. The pre-write snapshot LIST read that
// refuses with 4 is the same read, by the same code, that the verify step makes
// after the write: raised there it must be 1.
func TestUAS1_Snapshot_PostWriteTwins_NotExit4(t *testing.T) {
	listFailsAfterFirstWrite := func(fx *uaFix) {
		fx.front.override = func(r *http.Request) uaReply {
			if r.Method == http.MethodGet && r.URL.Path == snapBase+"/snapshot" && len(fx.front.writeLog()) > 0 {
				return uaStatus(http.StatusInternalServerError)
			}
			return uaReply{}
		}
	}
	t.Run("create: the verify list fails after the POST -> 1", func(t *testing.T) {
		uaTimings(t)
		fx := uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "n")
		listFailsAfterFirstWrite(fx)
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || len(o.rest) != 1 {
			t.Fatalf("exit %d writes %q, want 1 and one POST; stderr %q", o.code, o.rest, o.stderr)
		}
	})
	t.Run("create: the POST is rejected -> 1", func(t *testing.T) {
		fx := uaSnapFix(t, newSnapshotFake(t, "a"), "create", uaNode, "100", "n")
		fx.front.override = func(r *http.Request) uaReply {
			if fx.isDispatch(r) {
				return uaStatus(http.StatusInternalServerError)
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("delete: the verify list fails after the DELETE -> 1", func(t *testing.T) {
		uaTimings(t)
		fx := uaSnapFix(t, newSnapshotFake(t, "a", "b"), "delete", uaNode, "100", "b")
		listFailsAfterFirstWrite(fx)
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || len(o.rest) != 1 {
			t.Fatalf("exit %d writes %q, want 1 and one DELETE; stderr %q", o.code, o.rest, o.stderr)
		}
	})
	t.Run("delete: the DELETE is refused by PVE -> 1", func(t *testing.T) {
		f := newSnapshotFake(t, "a", "b")
		f.deleteFail["b"] = true
		fx := uaSnapFix(t, f, "delete", uaNode, "100", "b")
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("rollback: the task fails -> 1", func(t *testing.T) {
		uaTimings(t)
		f := newSnapshotFake(t, "a")
		f.taskFail["a"] = true
		fx := uaSnapFix(t, f, "rollback", "--no-witness", uaNode, "100", "a")
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	// rollback's own sentinel keeps its meaning: the rollback COMPLETED and the
	// witness could not prove it: exit 1 and the message says so, never 4, and
	// never 3 (the outcome of the rollback was observed).
	t.Run("rollback: completed, witness fails -> 1 (its own sentinel)", func(t *testing.T) {
		uaTimings(t)
		f := newSnapshotFake(t, "a")
		f.witness = "fail"
		fx := uaSnapFix(t, f, "rollback", uaNode, "100", "a")
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "completed, but it could not be proven") {
			t.Fatalf("exit %d, want 1 with the completed-but-unproven text; stderr %q", o.code, o.stderr)
		}
		if len(o.rest) < 2 {
			t.Fatalf("writes %q: want the rollback POST and the witness exec POST", o.rest)
		}
	})
	t.Run("rollback: the POST is rejected -> 1", func(t *testing.T) {
		fx := uaSnapFix(t, newSnapshotFake(t, "a"), "rollback", "--no-witness", uaNode, "100", "a")
		fx.front.override = func(r *http.Request) uaReply {
			if fx.isDispatch(r) {
				return uaStatus(http.StatusInternalServerError)
			}
			return uaReply{}
		}
		o := fx.env.observe(t, fx.args...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
}

// ------------------------------------------------------------ vm destroy (already 3/4 by its own structure)

// destroyArgs is `vm destroy --yes ...` as the three-log helper runs it.
func (e *dEnv) destroyArgs(extra ...string) []string {
	a := []string{"vm", "destroy", "--roster", e.roster, "-o", "json"}
	a = append(a, extra...)
	return append(a, dTarget, strconv.Itoa(dVMID))
}

// destroyLogs is the vm destroy fixture's three logs: the pvefake request log
// (non-GET only), no root SSH (the verb is token-only: stated with noLog), and
// the roster snapshot.
func (e *dEnv) destroyLogs() writeEnv {
	return writeEnv{roster: e.roster, sshWrites: noLog, restWrites: func() []string {
		var w []string
		for _, r := range e.s.Requests() {
			if !strings.HasPrefix(r, "GET ") && !strings.HasPrefix(r, "HEAD ") {
				w = append(w, r)
			}
		}
		return w
	}}
}

func TestUAS1_VMDestroy_RefusalBoundaries_Exit4_ZeroWrites(t *testing.T) {
	rows := []struct {
		name string
		mut  func(*pvefake.VMREST)
		args []string
		hold bool
		down bool
	}{
		{"B4d: --yes not given", nil, nil, false, false},
		{"B10: the status gate cannot be read", func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /nodes/" + dNode + "/qemu/691/status/current": {{Code: 500, Message: "boom"}}}
		}, []string{"--yes"}, false, false},
		{"B10: the node probe fails", func(s *pvefake.VMREST) { s.NodeStatus = 500 }, []string{"--yes"}, false, false},
		{"B10: the task list fails", func(s *pvefake.VMREST) { s.TasksStatus = 500 }, []string{"--yes"}, false, false},
		{"B10: the node-local config is unreadable", func(s *pvefake.VMREST) { s.ConfigStatus = 500 }, []string{"--yes"}, false, false},
		{"B4: a destroy is already in flight", func(s *pvefake.VMREST) { s.Tasks = []pvefake.TaskRow{dRunning("qmdestroy", 7)} }, []string{"--yes"}, false, false},
		{"B10: PVE unreachable", nil, []string{"--yes"}, false, true},
		{"B10: the object lock is held elsewhere", nil, []string{"--yes", "--lock-wait", "50ms"}, true, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := newDEnv(t, func(s *pvefake.VMREST) {
				s.VMStatus = `{"status":"running"}` // the gate WOULD stop it, so a missing refusal shows as a stop POST
				if r.mut != nil {
					r.mut(s)
				}
			})
			if r.down {
				e.srv.Close()
			}
			if r.hold {
				holdLock(t, e.roster, lock.ObjectKey{TargetID: dTarget, Kind: "vm", ID: strconv.Itoa(dVMID)})
			}
			o := e.destroyLogs().observe(t, e.destroyArgs(r.args...)...)
			o.wantRefusedBeforeAnyWrite(t)
			if r.hold {
				if _, err := os.Stat(e.roster + ".locks"); err != nil {
					t.Fatalf("positive control: no lock bookkeeping: %v", err)
				}
			}
		})
	}
}

// The post-write twins of vm destroy's refusals: the same verb after its first
// write (the stop POST, then the DELETE) never exits 4.
func TestUAS1_VMDestroy_PostWriteTwins_NotExit4(t *testing.T) {
	statusKey := func(kind string, n int) string {
		return "GET /nodes/" + dNode + "/tasks/" + dUPID(kind, n) + "/status"
	}
	run := func(t *testing.T, e *dEnv) writeObservation {
		t.Helper()
		o := e.destroyLogs().observe(t, e.destroyArgs("--yes")...)
		o.wantNotRefusedAfterWrite(t)
		return o
	}
	t.Run("stop POST sent, the stop task fails -> 1, the DELETE is never sent", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.VMStatus = `{"status":"running"}`; s.ReflectEnd = "ERROR: stop failed" })
		o := run(t, e)
		if o.code != 1 || e.deletes() != 0 || e.stops() != 1 {
			t.Fatalf("exit %d deletes %d stops %d, want 1, 0, 1; %s", o.code, e.deletes(), e.stops(), o.stdout)
		}
	})
	t.Run("the DELETE is refused by PVE -> 1", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.DestroyCode = 500 })
		if o := run(t, e); o.code != 1 || e.deletes() != 1 {
			t.Fatalf("exit %d deletes %d, want 1 and 1; %s", o.code, e.deletes(), o.stdout)
		}
	})
	t.Run("the destroy task fails -> 1", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "ERROR: destroy failed" })
		if o := run(t, e); o.code != 1 || e.deletes() != 1 {
			t.Fatalf("exit %d deletes %d, want 1 and 1; %s", o.code, e.deletes(), o.stdout)
		}
	})
	// The free-proof failures that are refusals (4) on a retry are UNKNOWN (3)
	// after this run's own dispatch: same evidence, the gate decides.
	t.Run("destroy ended OK but the vmid cannot be proven free -> 3", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.NextIDFree = false })
		if o := run(t, e); o.code != 3 || e.deletes() != 1 {
			t.Fatalf("exit %d deletes %d, want 3 and 1; %s", o.code, e.deletes(), o.stdout)
		}
	})
	// Wait boundaries (idempotent/vmdestroy.go:279 via StatusGatedStop, and
	// cmd/pveforge/vm_destroy.go's own destroy wait).
	t.Run("stop wait: the poll fails -> 3, the DELETE is never sent", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			s.VMStatus = `{"status":"running"}`
			s.Script = map[string][]pvefake.Reply{statusKey("qmstop", 2): {{Code: 503, Message: "x"}, {Code: 503, Message: "x"}, {Code: 503, Message: "x"}, {Code: 503, Message: "x"}}}
		})
		o := run(t, e)
		polls := e.count("GET /api2/json/nodes/" + dNode + "/tasks/" + dUPID("qmstop", 2) + "/status")
		if o.code != 3 || e.stops() != 1 || e.deletes() != 0 || polls != 4 {
			t.Fatalf("exit %d stops %d deletes %d polls %d, want 3, 1, 0, 4; %s", o.code, e.stops(), e.deletes(), polls, o.stdout)
		}
		if !strings.Contains(o.stdout, dUPID("qmstop", 2)) {
			t.Errorf("the stop's UPID is not reported: %s", o.stdout)
		}
	})
	t.Run("destroy wait: the poll fails -> 3", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{statusKey("qmdestroy", 1): {{Code: 503, Message: "x"}, {Code: 503, Message: "x"}, {Code: 503, Message: "x"}, {Code: 503, Message: "x"}}}
		})
		o := run(t, e)
		polls := e.count("GET /api2/json/nodes/" + dNode + "/tasks/" + dUPID("qmdestroy", 1) + "/status")
		if o.code != 3 || e.deletes() != 1 || polls != 4 {
			t.Fatalf("exit %d deletes %d polls %d, want 3, 1, 4; %s", o.code, e.deletes(), polls, o.stdout)
		}
		if !strings.Contains(o.stdout, dUPID("qmdestroy", 1)) {
			t.Errorf("the destroy's UPID is not reported: %s", o.stdout)
		}
	})
	t.Run("destroy dispatch: 200 without a UPID -> 3 (a worker may exist), not a wait", func(t *testing.T) {
		e := newDEnv(t, func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"DELETE /nodes/" + dNode + "/qemu/691": {{Body: "null"}}}
		})
		if o := run(t, e); o.code != 3 || e.deletes() != 1 {
			t.Fatalf("exit %d deletes %d, want 3 and 1; %s", o.code, e.deletes(), o.stdout)
		}
	})
	t.Run("OK -> 0", func(t *testing.T) {
		e := newDEnv(t, nil)
		if o := run(t, e); o.code != 0 || e.deletes() != 1 {
			t.Fatalf("exit %d deletes %d, want 0 and 1; %s", o.code, e.deletes(), o.stdout)
		}
	})
}

// ------------------------------------------------------------ the wait-boundary table meets the call-site list (AC-W2 VAC)

// uaS1WaitSites is every WaitForTask call of family S1 in non-test source, by
// file, with the fixture that gives it its exit-3 observation. A new wait (or
// one the walk stopped seeing) fails here until it has a fixture.
var uaS1WaitSites = map[string]struct {
	count   int
	fixture string
}{
	"internal/idempotent/vmcreate.go":  {1, "TestUAS1_WaitBoundary_VMCreate (through runRoot)"},
	"internal/idempotent/vmclone.go":   {1, "TestUAS1_VMClone_WaitSiteIsUnobserved (library-only: the CLI has no --clone)"},
	"internal/idempotent/vmdestroy.go": {2, "stop wait: TestUAS1_VMDestroy_PostWriteTwins_NotExit4 (stop wait); Apply wait: TestUAS1_VMDestroyOp_WaitSitesAreUnobserved (library-only)"},
	"cmd/pveforge/vm_destroy.go":       {1, "TestUAS1_VMDestroy_PostWriteTwins_NotExit4 (destroy wait)"},
	"internal/pve/snapshot.go":         {3, "TestUAS1_WaitBoundary_SnapshotCreate|Delete|Rollback"},
}

func TestUAS1_WaitBoundaryTableCoversEveryWaitSiteOfTheFamily(t *testing.T) {
	sc, err := lockguard.ScanModule("../..")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, c := range sc.TaskWaits {
		if _, mine := uaS1WaitSites[c.Ref.File]; mine {
			got[c.Ref.File]++
		}
	}
	for file, w := range uaS1WaitSites {
		if got[file] != w.count {
			t.Errorf("%s: %d WaitForTask call(s), the fixture table says %d (%s): a wait site changed without a fixture", file, got[file], w.count, w.fixture)
		}
	}
	if len(got) != len(uaS1WaitSites) {
		t.Errorf("the walk found waits in %d of the family's %d files: %v", len(got), len(uaS1WaitSites), got)
	}
}
