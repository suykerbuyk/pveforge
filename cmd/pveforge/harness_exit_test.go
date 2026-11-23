package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
)

// Exit 3 / exit 4 for the harness verbs (contract plan §3.5, §4 rows
// `harness build|probe|golden|reset|vm …`, AC-W2, AC-W3, AC-W10).
//
// Every refusal fixture reads THREE write logs through writeEnv.observe (the
// fake PVE's non-GET request log, the root-SSH command log, the roster-file
// snapshot) and asserts the run's write gate agrees with them. The harness has
// NO root-SSH side: the SSH log is the explicit noLog. Every refusal row has a
// post-write twin: the same family advanced past its first write, which must
// exit anything but 4. Every wait row dispatches a real UPID, makes the status
// poll fail, and asserts exit 3, the dispatch count and the poll count.
//
// BOOKKEEPING (D17/D18): evidence directories and files, the harness ledger,
// <roster>.lock/.locks and the probe's harness-state/ file are NOT mutations:
// the positive-control rows below create an evidence dir (and append the ledger)
// and still exit 4 with all three logs empty.

// reqLog is embedded in each harness fake. It records EVERY non-GET request
// the fake receives (REST write log, (i) of AC-W3) and counts task-status polls
// per task type, and can make one task type's status endpoint answer 503 so a
// wait that started cannot observe its outcome.
type reqLog struct {
	rlMu     sync.Mutex
	rlNonGET []string
	rlPolls  map[string]int
	rlDown   func(typ string, nth int) bool // nth is this type's poll number, from 1
}

// see logs the request. It reports true when it answered (a downed poll).
func (l *reqLog) see(w http.ResponseWriter, r *http.Request) bool {
	l.rlMu.Lock()
	defer l.rlMu.Unlock()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		l.rlNonGET = append(l.rlNonGET, r.Method+" "+r.URL.Path)
		return false
	}
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tasks/") && strings.HasSuffix(r.URL.Path, "/status") {
		typ, _ := parseUPIDTypeID(taskUPIDFromPath(r.URL.Path))
		if l.rlPolls == nil {
			l.rlPolls = map[string]int{}
		}
		l.rlPolls[typ]++
		if l.rlDown != nil && l.rlDown(typ, l.rlPolls[typ]) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"data":null}`)
			return true
		}
	}
	return false
}

func (l *reqLog) restWrites() []string {
	l.rlMu.Lock()
	defer l.rlMu.Unlock()
	return append([]string(nil), l.rlNonGET...)
}

func (l *reqLog) polls(typ string) int {
	l.rlMu.Lock()
	defer l.rlMu.Unlock()
	return l.rlPolls[typ]
}

func (l *reqLog) breakTask(typ string) {
	l.rlMu.Lock()
	defer l.rlMu.Unlock()
	l.rlDown = func(t string, _ int) bool { return t == typ }
}

// breakTaskFrom downs typ from its nth poll on (the earlier waits of the same
// type observe normally).
func (l *reqLog) breakTaskFrom(typ string, nth int) {
	l.rlMu.Lock()
	defer l.rlMu.Unlock()
	l.rlDown = func(t string, n int) bool { return t == typ && n >= nth }
}

func (l *reqLog) countWrites(prefix string) int {
	n := 0
	for _, w := range l.restWrites() {
		if strings.HasPrefix(w, prefix) {
			n++
		}
	}
	return n
}

func harnessEnv(rosterPath string, l *reqLog) writeEnv {
	return writeEnv{roster: rosterPath, restWrites: l.restWrites, sshWrites: noLog}
}

func (o writeObservation) text() string { return o.stderr + "\n" + o.stdout }

// wantRefused: exit 4, zero writes in all three logs, the intended refusal text.
func (o writeObservation) wantRefusedWith(t *testing.T, phrase string) {
	t.Helper()
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.text(), phrase) {
		t.Fatalf("exit 4 but not the intended refusal: want %q in stderr %q stdout %q", phrase, o.stderr, o.stdout)
	}
}

// wantTwin: the same family advanced past its first write: exit `code`, never 4.
func (o writeObservation) wantTwin(t *testing.T, code int, phrase string) {
	t.Helper()
	o.wantNotRefusedAfterWrite(t)
	if o.code != code {
		t.Fatalf("post-write twin exit %d, want %d; stderr %q stdout %q", o.code, code, o.stderr, o.stdout)
	}
	if !strings.Contains(o.text(), phrase) {
		t.Fatalf("post-write twin: want %q in stderr %q stdout %q", phrase, o.stderr, o.stdout)
	}
}

// wantUnobserved: exit 3 at a wait boundary: a real dispatch (>= writes), the
// poll count exactly `polls`, and the UPID on stderr.
func (o writeObservation) wantUnobserved(t *testing.T, l *reqLog, typ string, writes, polls int, upid string) {
	t.Helper()
	if o.code != 3 {
		t.Fatalf("exit %d, want 3 (a dispatched %s whose outcome was not observed); stderr %q stdout %q", o.code, typ, o.stderr, o.stdout)
	}
	if !o.wrote() || !o.opened {
		t.Fatalf("vacuous: nothing was dispatched (rest %q)", o.rest)
	}
	if got := len(o.rest); got != writes {
		t.Fatalf("dispatch count %d (%q), want %d", got, o.rest, writes)
	}
	if got := l.polls(typ); got != polls {
		t.Fatalf("%s status polls = %d, want %d (the wait must have polled and then given up)", typ, got, polls)
	}
	if upid != "" && !strings.Contains(o.stderr, upid) {
		t.Fatalf("stderr %q does not carry the UPID %q", o.stderr, upid)
	}
}

// ---- harness vm (hfake) -------------------------------------------------

func hvmEnv(t *testing.T, f *hfake) (writeEnv, string) {
	t.Helper()
	rosterPath := newHarnessTest(t, f)
	return harnessEnv(rosterPath, &f.reqLog), rosterPath
}

// Refusal boundaries of the harness VM verbs, each before the first request that
// changes anything: the VMID band, the Guard (pool, node, tag, ledger), the
// destroy --yes confirmation, and the lock acquisition.
func TestHarnessVMExit4_RefusedBeforeAnyWrite(t *testing.T) {
	ledgerWith := func(t *testing.T, vmids ...int) string { return harnessLedgerFile(t, vmids...) }
	type row struct {
		name   string
		f      *hfake
		args   func(t *testing.T, roster string) []string
		phrase string
	}
	rows := []row{
		{"stop/band", &hfake{}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "stop", "--roster", r, "h", "700"}
		}, "not one of 690-699"},
		{"stop/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "stop", "--roster", r, "h", "690"}
		}, "does not carry tag"},
		{"stop/guard-node", &hfake{memberNode: "qa-pve-03"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "stop", "--roster", r, "h", "690"}
		}, "is on node qa-pve-03"},
		{"stop/guard-member", &hfake{memberType: "lxc"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "stop", "--roster", r, "h", "690"}
		}, "not a qemu member"},
		{"shutdown-plain/band", &hfake{}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "shutdown", "--roster", r, "h", "689"}
		}, "not one of 690-699"},
		{"shutdown-plain/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "shutdown", "--roster", r, "h", "690"}
		}, "does not carry tag"},
		{"shutdown-leaf/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "shutdown", "--timeout", "30", "--roster", r, "h", "690"}
		}, "does not carry tag"},
		{"destroy/band", &hfake{}, func(t *testing.T, r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--created-file", ledgerWith(t, 690), "--yes", "h", "800"}
		}, "not one of 690-699"},
		{"destroy/guard-not-created", &hfake{}, func(t *testing.T, r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--created-file", ledgerWith(t, 698), "--yes", "h", "690"}
		}, "was not created by this run"},
		{"destroy/guard-no-ledger", &hfake{}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--yes", "h", "690"}
		}, "needs a created-VM ledger"},
		{"destroy/guard-tag", &hfake{tags: "other"}, func(t *testing.T, r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--created-file", ledgerWith(t, 690), "--yes", "h", "690"}
		}, "does not carry tag"},
		{"destroy/no-yes", &hfake{}, func(t *testing.T, r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--created-file", ledgerWith(t, 690), "h", "690"}
		}, "--yes"},
		{"snapshot-create/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "snapshot", "create", "--roster", r, "h", "690", "s1"}
		}, "does not carry tag"},
		{"snapshot-create/band", &hfake{}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "snapshot", "create", "--roster", r, "h", "701", "s1"}
		}, "not one of 690-699"},
		{"snapshot-delete/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "snapshot", "delete", "--roster", r, "h", "690", "s1"}
		}, "does not carry tag"},
		{"snapshot-rollback/guard-tag", &hfake{tags: "other"}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "snapshot", "rollback", "--roster", r, "h", "690", "s1"}
		}, "does not carry tag"},
		{"snapshot-rollback/band", &hfake{}, func(_ *testing.T, r string) []string {
			return []string{"harness", "vm", "snapshot", "rollback", "--roster", r, "h", "10", "s1"}
		}, "not one of 690-699"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			env, rosterPath := hvmEnv(t, c.f)
			o := env.observe(t, c.args(t, rosterPath)...)
			o.wantRefusedWith(t, c.phrase)
		})
	}
}

// The lock-acquisition refusal: another holder has the object's lock, the
// wait times out before the Guard and before any request. The lock files are
// bookkeeping (<roster>.lock/.locks), so the 4 is true although they were
// created; the gate-log agreement still holds.
func TestHarnessVMExit4_LockWaitRefusedBeforeAnyWrite(t *testing.T) {
	cases := []struct {
		name string
		args func(r string) []string
	}{
		{"stop", func(r string) []string {
			return []string{"harness", "vm", "stop", "--lock-wait", "7ms", "--roster", r, "h", "690"}
		}},
		{"shutdown-leaf", func(r string) []string {
			return []string{"harness", "vm", "shutdown", "--force-stop", "--lock-wait", "7ms", "--roster", r, "h", "690"}
		}},
		{"shutdown-plain(idempotent.Run)", func(r string) []string {
			return []string{"harness", "vm", "shutdown", "--lock-wait", "7ms", "--roster", r, "h", "690"}
		}},
		{"snapshot-create", func(r string) []string {
			return []string{"harness", "vm", "snapshot", "create", "--lock-wait", "7ms", "--roster", r, "h", "690", "s1"}
		}},
		{"snapshot-delete", func(r string) []string {
			return []string{"harness", "vm", "snapshot", "delete", "--lock-wait", "7ms", "--roster", r, "h", "690", "s1"}
		}},
		{"snapshot-rollback", func(r string) []string {
			return []string{"harness", "vm", "snapshot", "rollback", "--lock-wait", "7ms", "--roster", r, "h", "690", "s1"}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, rosterPath := hvmEnv(t, &hfake{})
			holdLock(t, rosterPath, harnessVMKey("h", 690))
			o := env.observe(t, c.args(rosterPath)...)
			o.wantRefusedWith(t, "lock")
		})
	}
	t.Run("destroy", func(t *testing.T) {
		env, rosterPath := hvmEnv(t, &hfake{})
		holdLock(t, rosterPath, harnessVMKey("h", 690))
		o := env.observe(t, "harness", "vm", "destroy", "--lock-wait", "7ms", "--roster", rosterPath, "--created-file", harnessLedgerFile(t, 690), "--yes", "h", "690")
		o.wantRefusedWith(t, "lock")
	})
}

// Usage errors and read-only verbs stay exit 1 (not a refusal): a VMID that is
// not a number, and the read-only verbs' own bad VMID.
func TestHarnessVMExit1_UsageAndReadOnlyStayPlain(t *testing.T) {
	env, rosterPath := hvmEnv(t, &hfake{})
	for _, args := range [][]string{
		{"harness", "vm", "stop", "--roster", rosterPath, "h", "abc"},
		{"harness", "vm", "snapshot", "create", "--roster", rosterPath, "h", "690", "current"},
		{"harness", "vm", "gone", "--roster", rosterPath, "--destroy-task", "x", "h", "700"},
		{"harness", "vm", "snapshot", "list", "--roster", rosterPath, "h", "700"},
	} {
		o := env.observe(t, args...)
		if o.code != 1 || o.wrote() {
			t.Errorf("%v: exit %d writes %v, want exit 1 and no write (stderr %q)", args, o.code, o.rest, o.stderr)
		}
	}
}

// The rollback not-newest refusal is raised in pve.Rollback before the POST (no
// write is sent), so through the write gate it is exit 4 (the S1 family made
// pve.Rollback's pre-POST refusals dispatch.Refuse); the reason contract on
// stdout is unchanged ("consumers parse the reason, never the exit code").
func TestHarnessVMExit4_RollbackNotNewestIsRefusedBeforeTheWrite(t *testing.T) {
	env, rosterPath := hvmEnv(t, &hfake{snapshots: `[{"name":"s1","snaptime":100},{"name":"s2","snaptime":200},{"name":"current","snaptime":0}]`})
	o := env.observe(t, "harness", "vm", "snapshot", "rollback", "--roster", rosterPath, "-o", "json", "h", "690", "s1")
	if o.code != 4 || o.wrote() || !strings.Contains(o.stdout, "not-newest") {
		t.Fatalf("exit %d writes %q stdout %q, want exit 4, no write, reason not-newest", o.code, o.rest, o.stdout)
	}
}

// Post-write twins: the same verbs advanced past the POST/DELETE. A failure after
// the request left the process is exit 1, never 4 (and never 3: the task was
// observed).
func TestHarnessVMExit_PostWriteTwins(t *testing.T) {
	t.Run("destroy/not-proven-gone-after-DELETE", func(t *testing.T) {
		env, rosterPath := hvmEnv(t, &hfake{taskExit: "WARNINGS: 1"})
		o := env.observe(t, "harness", "vm", "destroy", "--roster", rosterPath, "--created-file", harnessLedgerFile(t, 690), "--yes", "h", "690")
		o.wantTwin(t, 1, "not proven gone")
	})
	t.Run("snapshot-create/absent-after-POST", func(t *testing.T) {
		env, rosterPath := hvmEnv(t, &hfake{})
		o := env.observe(t, "harness", "vm", "snapshot", "create", "--roster", rosterPath, "h", "690", "s9")
		o.wantTwin(t, 1, "not present")
	})
	t.Run("snapshot-create/unverifiable-list-after-POST", func(t *testing.T) {
		env, rosterPath := hvmEnv(t, &hfake{snapshots: `[]`})
		o := env.observe(t, "harness", "vm", "snapshot", "create", "--roster", rosterPath, "h", "690", "s1")
		o.wantTwin(t, 1, "unverifiable")
	})
	t.Run("stop/task-seen-to-fail", func(t *testing.T) {
		// a task SEEN to fail is exit 1 (TaskFailedError), not 3 and not 4
		env, rosterPath := hvmEnv(t, &hfake{taskExit: "ERROR: boom"})
		o := env.observe(t, "harness", "vm", "stop", "--roster", rosterPath, "h", "690")
		o.wantTwin(t, 1, "boom")
	})
}

// Exit 3 at every wait boundary of the harness VM verbs (harness_vm.go:120,
// 207, 292, 502, and the pve snapshot waits behind delete and rollback): a real
// UPID is dispatched, the status poll fails, the verb exits 3.
func TestHarnessVMExit3_WaitBoundaries(t *testing.T) {
	withFastTaskPolls(t)
	cases := []struct {
		name   string
		typ    string
		f      func() *hfake
		args   func(r string) []string
		writes int // dispatched non-GET requests
	}{
		{"stop", "qmstop", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "stop", "--roster", r, "h", "690"}
		}, 1},
		{"shutdown-leaf", "qmshutdown", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "shutdown", "--timeout", "30", "--roster", r, "h", "690"}
		}, 1},
		{"shutdown-plain(idempotent.Run)", "qmshutdown", func() *hfake { return &hfake{vmStatus: "running"} }, func(r string) []string {
			return []string{"harness", "vm", "shutdown", "--roster", r, "h", "690"}
		}, 1},
		{"snapshot-delete", "qmdelsnapshot", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "snapshot", "delete", "--roster", r, "h", "690", "s1"}
		}, 1},
		{"snapshot-rollback", "qmrollback", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "snapshot", "rollback", "--roster", r, "h", "690", "s1"}
		}, 1},
		{"destroy", "qmdestroy", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "destroy", "--roster", r, "--created-file", harnessLedgerFile(t, 690), "--yes", "h", "690"}
		}, 1},
		{"snapshot-create", "qmsnapshot", func() *hfake { return &hfake{} }, func(r string) []string {
			return []string{"harness", "vm", "snapshot", "create", "--roster", r, "h", "690", "s1"}
		}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.f()
			f.breakTask(c.typ)
			env, rosterPath := hvmEnv(t, f)
			o := env.observe(t, c.args(rosterPath)...)
			o.wantUnobserved(t, &f.reqLog, c.typ, c.writes, 4, mkUPID(c.typ, 690))
		})
	}
}

// ---- harness build (bfake) ----------------------------------------------

func buildArgs(rosterPath, ledger string, extra ...string) []string {
	return append([]string{"harness", "build", "--roster", rosterPath, "--created-file", ledger, "--storage", "pveforge-harness"}, append(extra, "h")...)
}

func evidenceDirs(t *testing.T, home, what string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(home, ".config/pveforge/harness-evidence", what, "*"))
	return m
}

// Build refusals before any create. The POSITIVE CONTROL rows are the ones whose
// run has already created the evidence directory (every preflight refusal) and
// still exit 4 with zero entries in all three logs.
func TestBuildExit4_PreflightRefusedBeforeAnyCreate(t *testing.T) {
	cases := []struct {
		name   string
		f      *bfake
		mutate func(t *testing.T, home string)
		args   []string
		phrase string
		evid   bool // the evidence dir exists at the refusal (positive control)
	}{
		{"pool-not-empty", &bfake{pre: map[int]bool{691: true}}, nil, nil, "already exists in pool", true},
		{"vmid-not-free", &bfake{nextidBusy: map[int]bool{690: true}}, nil, nil, "is not free in the cluster", true},
		{"storage-leftover", &bfake{contentPre: map[int]string{692: `[{"volid":"x"}]`}}, nil, nil, "already holds volumes", true},
		{"iso-missing", &bfake{noISO: map[int]bool{690: true}}, nil, nil, "is not on", true},
		{"import-missing", &bfake{noImport: true}, nil, nil, "is not on", true},
		{"nested-key-missing", &bfake{}, func(t *testing.T, home string) {
			if err := os.Remove(filepath.Join(home, ".config/pveforge/harness-nested_ed25519.pub")); err != nil {
				t.Fatal(err)
			}
		}, nil, "does not exist", true},
		{"site-file-missing", &bfake{}, func(t *testing.T, home string) {
			if err := os.Remove(filepath.Join(home, ".config/pveforge/harness-build.env")); err != nil {
				t.Fatal(err)
			}
		}, nil, "harness-build.env", false}, // LoadSite refuses BEFORE openEvidence: no dir yet
		{"known-hosts-pinned", &bfake{}, func(t *testing.T, home string) {
			p := filepath.Join(home, ".config/pveforge/harness-nested.known_hosts")
			if err := os.WriteFile(p, []byte("192.0.2.90 ssh-ed25519 AAAA\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, nil, "already pins a host key", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, home := newBuildTest(t, c.f)
			if c.mutate != nil {
				c.mutate(t, home)
			}
			ledger := harnessLedgerFile(t)
			env := harnessEnv(rosterPath, &c.f.reqLog)
			o := env.observe(t, buildArgs(rosterPath, ledger)...)
			o.wantRefusedWith(t, c.phrase)
			if got := len(evidenceDirs(t, home, "build")); c.evid && got != 1 {
				t.Fatalf("positive control is vacuous: %d evidence dirs at the refusal, want 1 (bookkeeping must have been written and still exit 4)", got)
			} else if !c.evid && got != 0 {
				t.Fatalf("%d evidence dirs, want 0 before openEvidence", got)
			}
		})
	}
}

// A lock-wait refusal in build (lock files created, nothing sent) is 4.
func TestBuildExit4_LockWaitRefusedBeforeAnyCreate(t *testing.T) {
	f := &bfake{}
	rosterPath, _ := newBuildTest(t, f)
	holdLock(t, rosterPath, harnessVMKey("h", 691))
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, buildArgs(rosterPath, harnessLedgerFile(t), "--lock-wait", "7ms")...)
	o.wantRefusedWith(t, "lock")
}

// Usage: no --storage is exit 1 (a usage error, not a preflight refusal).
func TestBuildExit1_NoStorageIsUsage(t *testing.T) {
	f := &bfake{}
	rosterPath, _ := newBuildTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	t.Setenv("HARNESS_STORAGE", "")
	o := env.observe(t, "harness", "build", "--roster", rosterPath, "h")
	if o.code != 1 || o.wrote() {
		t.Fatalf("exit %d writes %v, want exit 1, no write (stderr %q)", o.code, o.rest, o.stderr)
	}
}

// The post-write twin of the build's tag guard: AFTER CreateVM + wait the same
// Guard refusal text is exit 1, never 4 (build.go: Guard(ModeTag) after create).
func TestBuildExit_TagGuardAfterCreateIsPostWrite(t *testing.T) {
	f := &bfake{poolNode: "qa-pve-03"}
	rosterPath, _ := newBuildTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, buildArgs(rosterPath, harnessLedgerFile(t))...)
	o.wantTwin(t, 1, "is on node qa-pve-03")
	if !strings.Contains(strings.Join(o.rest, "\n"), "POST /api2/json/nodes/qa-pve-07/qemu") {
		t.Fatalf("the create POST is not in the log: %q", o.rest)
	}
}

// Same boundary, the membership leg of the same Guard: after the create the
// pool no longer lists the VM as a qemu member: exit 1.
func TestBuildExit_MembershipGuardAfterCreateIsPostWrite(t *testing.T) {
	f := &bfake{poolType: "lxc"}
	rosterPath, _ := newBuildTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, buildArgs(rosterPath, harnessLedgerFile(t))...)
	o.wantTwin(t, 1, "not a qemu member")
}

// Exit 3: the create wait (build.go waitTask), and the start wait.
func TestBuildExit3_WaitBoundaries(t *testing.T) {
	withFastTaskPolls(t)
	t.Run("create", func(t *testing.T) {
		f := &bfake{}
		f.breakTask("qmcreate")
		rosterPath, _ := newBuildTest(t, f)
		env := harnessEnv(rosterPath, &f.reqLog)
		o := env.observe(t, buildArgs(rosterPath, harnessLedgerFile(t))...)
		// one create POST dispatched; its wait polled 4 times and gave up. The VM
		// was never ledgered, so the deferred cleanup destroys nothing.
		o.wantUnobserved(t, &f.reqLog, "qmcreate", 1, 4, pUPID("qmcreate", 690))
	})
	t.Run("start", func(t *testing.T) {
		f := &bfake{}
		f.breakTask("qmstart")
		rosterPath, _ := newBuildTest(t, f)
		env := harnessEnv(rosterPath, &f.reqLog)
		o := env.observe(t, buildArgs(rosterPath, harnessLedgerFile(t))...)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
		if n := f.countWrites("POST /api2/json/nodes/qa-pve-07/qemu/690/status/start"); n != 1 {
			t.Fatalf("start POSTs for 690 = %d, want 1 (the wait that failed); log %q", n, o.rest)
		}
		if got := f.polls("qmstart"); got != 4 {
			t.Fatalf("qmstart polls = %d, want 4", got)
		}
		if !strings.Contains(o.stderr, pUPID("qmstart", 690)) {
			t.Fatalf("stderr %q has no UPID", o.stderr)
		}
	})
}

// ---- harness probe (pfake) ----------------------------------------------

func probeArgs(rosterPath, ledger string, extra ...string) []string {
	return append([]string{"harness", "probe", "--roster", rosterPath, "--created-file", ledger, "--storage", "pveforge-harness"}, append(extra, "h")...)
}

func TestProbeExit4_RefusedBeforeCreate(t *testing.T) {
	statusBad := `{"type":"zfspool","enabled":0,"active":1,"content":"images","avail":644245094400,"used":0}`
	cases := []struct {
		name   string
		f      *pfake
		phrase string
	}{
		{"static/not-enabled", &pfake{statusJSON: statusBad}, "not enabled"},
		{"690-in-pool", &pfake{pre690: true}, "already exists in pool"},
		{"pool-not-empty", &pfake{poolX: true}, "is not empty"},
		{"storage-not-empty", &pfake{usedNow: "2097152"}, "is not empty"},
		{"content-holds-690", &pfake{contentPre: `[{"volid":"x"}]`}, "already holds volumes"},
		{"vmid-not-free", &pfake{nextid: "700"}, "is not free in the cluster"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, home := newProbeTest(t, c.f)
			env := harnessEnv(rosterPath, &c.f.reqLog)
			o := env.observe(t, probeArgs(rosterPath, harnessLedgerFile(t))...)
			o.wantRefusedWith(t, c.phrase)
			// positive control: the evidence dir exists, and no harness-state file
			// was written, at an exit-4 refusal
			if got := len(evidenceDirs(t, home, "probe")); got != 1 {
				t.Fatalf("positive control vacuous: %d probe evidence dirs, want 1", got)
			}
			if _, ok := readRule(home, "pveforge-harness"); ok {
				t.Fatal("a refused probe wrote the rule file")
			}
		})
	}
	t.Run("lock-wait", func(t *testing.T) {
		f := &pfake{}
		rosterPath, _ := newProbeTest(t, f)
		holdLock(t, rosterPath, harnessVMKey("h", 690))
		env := harnessEnv(rosterPath, &f.reqLog)
		o := env.observe(t, probeArgs(rosterPath, harnessLedgerFile(t), "--lock-wait", "7ms")...)
		o.wantRefusedWith(t, "lock")
	})
}

// A static-only probe never writes the rule file and never opens the gate
// (D18's harness-state/ is bookkeeping): exit 0, zero writes in all three logs.
func TestProbeStaticOnly_WritesNothingAndOpensNoGate(t *testing.T) {
	f := &pfake{}
	rosterPath, home := newProbeTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, "harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "--static-only", "h")
	if o.code != 0 || o.wrote() || o.opened {
		t.Fatalf("exit %d writes %q gate %v, want a clean no-write run", o.code, o.rest, o.opened)
	}
	if got := len(evidenceDirs(t, home, "probe")); got != 1 {
		t.Fatalf("evidence dirs %d, want 1", got)
	}
}

// Post-write twin: the probe's guard AFTER the create (probe.go empirical)
// returns the same refusal text as exit 1.
func TestProbeExit_GuardAfterCreateIsPostWrite(t *testing.T) {
	f := &pfake{memberNode: "qa-pve-03"}
	rosterPath, _ := newProbeTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, probeArgs(rosterPath, harnessLedgerFile(t))...)
	o.wantTwin(t, 1, "is on node qa-pve-03")
}

// The destroy leg's ledger guard AFTER the create and the snapshots: with no
// ledger at all, and with a ledger that lost the VM mid-run, the same two
// refusals that are exit 4 for `harness vm destroy` are exit 1 here.
func TestProbeExit_LedgerGuardAfterCreateIsPostWrite(t *testing.T) {
	t.Run("no-ledger", func(t *testing.T) {
		f := &pfake{}
		rosterPath, _ := newProbeTest(t, f)
		t.Setenv("HARNESS_CREATED_FILE", "")
		env := harnessEnv(rosterPath, &f.reqLog)
		o := env.observe(t, "harness", "probe", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
		o.wantTwin(t, 1, "needs a created-VM ledger")
	})
	t.Run("ledger-lost-the-vm", func(t *testing.T) {
		ledger := filepath.Join(t.TempDir(), "created")
		f := &pfake{afterCreate: func() { _ = os.Remove(ledger) }}
		rosterPath, _ := newProbeTest(t, f)
		env := harnessEnv(rosterPath, &f.reqLog)
		o := env.observe(t, probeArgs(rosterPath, ledger)...)
		o.wantTwin(t, 1, "was not created by this run")
	})
}

// Exit 3 at the probe's wait boundaries.
func TestProbeExit3_WaitBoundaries(t *testing.T) {
	withFastTaskPolls(t)
	cases := []struct {
		name  string
		typ   string
		nth   int // downed from this poll on (1 = every wait of the type)
		extra func(f *pfake)
		// the number of status polls the type saw before the wait that gave up
		pollsWant int
	}{
		{"create", "qmcreate", 1, nil, 4},
		{"snapshot", "qmsnapshot", 1, nil, 4},
		{"raw-rollback", "qmrollback", 1, nil, 4},
		{"cascade-delete-s2", "qmdelsnapshot", 1, nil, -1}, // the deferred cleanup deletes snapshots too: >= 4
		{"cascade-delete-s1", "qmdelsnapshot", 2, nil, -1}, // the first cascade delete (s2) observed, the second (s1) gives up
		{"cascade-rollback-s1", "qmrollback", 2, nil, 5},   // the classification rollback observed once, the cascade's gives up
		{"destroy", "qmdestroy", 1, nil, -1},               // the cleanup re-destroy polls too: checked as >= 4
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &pfake{}
			f.breakTaskFrom(c.typ, c.nth)
			rosterPath, _ := newProbeTest(t, f)
			env := harnessEnv(rosterPath, &f.reqLog)
			o := env.observe(t, probeArgs(rosterPath, harnessLedgerFile(t))...)
			if o.code != 3 {
				t.Fatalf("exit %d, want 3; stdout %q stderr %q", o.code, o.stdout, o.stderr)
			}
			if !o.wrote() || !o.opened {
				t.Fatal("vacuous: nothing dispatched")
			}
			got := f.polls(c.typ)
			if c.pollsWant >= 0 && got != c.pollsWant {
				t.Fatalf("%s polls = %d, want %d", c.typ, got, c.pollsWant)
			}
			if c.pollsWant < 0 && got < 4 {
				t.Fatalf("%s polls = %d, want >= 4", c.typ, got)
			}
			if !strings.Contains(o.stderr, "UPID:") {
				t.Fatalf("stderr %q carries no UPID", o.stderr)
			}
		})
	}
}

// A task SEEN to fail with a refusal text the probe does not recognise is exit
// 1 (TaskFailedError), not 3 and not 4.
func TestProbeExit1_UnrecognisedRollbackFailureIsPlain(t *testing.T) {
	f := &pfake{rollbackOtherErr: true}
	rosterPath, _ := newProbeTest(t, f)
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, probeArgs(rosterPath, harnessLedgerFile(t))...)
	o.wantTwin(t, 1, "unrecognised reason")
}

// ---- harness golden / reset (grfake) ------------------------------------

func goldenArgs(rosterPath string, extra ...string) []string {
	return append([]string{"harness", "golden", "--roster", rosterPath, "--storage", "pveforge-harness"}, append(extra, "h")...)
}
func resetArgs(rosterPath string, extra ...string) []string {
	return append([]string{"harness", "reset", "--roster", rosterPath, "--storage", "pveforge-harness"}, append(extra, "h")...)
}

func setTag(f *grfake, vmid int, tags string) {
	f.vm(vmid).config = fmt.Sprintf(`{"scsi0":"pveforge-harness:vm-disk-0,size=128G","tags":%q,"cores":"8"}`, tags)
}

func TestGoldenResetExit4_RefusedBeforeAnyWrite(t *testing.T) {
	inactive := `{"type":"zfspool","enabled":1,"active":0,"content":"images","avail":644245094400,"used":0}`
	cases := []struct {
		name   string
		world  func() *grfake
		setup  func(t *testing.T, f *grfake)
		args   func(r string) []string
		phrase string
		evid   int // evidence dirs expected at the refusal (golden/reset)
	}{
		{"golden/static-layer", grGoldenWorld, func(_ *testing.T, f *grfake) { f.statusJSON = inactive }, func(r string) []string { return goldenArgs(r) }, "static layer refused", 0},
		{"golden/roster-gate", grGoldenWorld, func(t *testing.T, _ *grfake) { t.Setenv("PVEFORGE_HARNESS_ROSTER", "") }, func(r string) []string { return goldenArgs(r) }, "PVEFORGE_HARNESS_ROSTER", 0},
		{"golden/outer-rosters-gate", grGoldenWorld, func(t *testing.T, _ *grfake) { t.Setenv("PVEFORGE_HARNESS_OUTER_ROSTERS", "") }, func(r string) []string { return goldenArgs(r) }, "PVEFORGE_HARNESS_OUTER_ROSTERS", 0},
		{"golden/disk-on-wrong-storage", grGoldenWorld, func(_ *testing.T, f *grfake) {
			f.vm(690).config = `{"scsi0":"other:vm-disk-0","tags":"pveforge-harness"}`
		}, func(r string) []string { return goldenArgs(r) }, "system disk is on", 1},
		{"golden/vm-locked", grGoldenWorld, func(_ *testing.T, f *grfake) {
			f.vm(692).config = `{"scsi0":"pveforge-harness:vm-disk-0","tags":"pveforge-harness","lock":"backup"}`
		}, func(r string) []string { return goldenArgs(r) }, "holds lock", 1},
		{"golden/existing-golden-needs-replace", func() *grfake {
			f := grGoldenWorld()
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
			}
			return f
		}, nil, func(r string) []string { return goldenArgs(r) }, "needs --replace-golden", 1},
		{"golden/first-acceptance", grGoldenWorld, func(_ *testing.T, f *grfake) {
			f.acceptErr = func(why string) error {
				if strings.Contains(why, "before") {
					return errors.New("nested cluster down")
				}
				return nil
			}
		}, func(r string) []string { return goldenArgs(r) }, "was not accepted", 1},
		{"golden/guard-before-first-shutdown", grGoldenWorld, func(_ *testing.T, f *grfake) { setTag(f, 691, "other") }, func(r string) []string { return goldenArgs(r) }, "does not carry tag", 1},
		{"reset/static-layer", grResetWorld, func(_ *testing.T, f *grfake) { f.statusJSON = inactive }, func(r string) []string { return resetArgs(r) }, "static layer refused", 0},
		{"reset/roster-gate", grResetWorld, func(t *testing.T, _ *grfake) { t.Setenv("PVEFORGE_HARNESS_ROSTER", "") }, func(r string) []string { return resetArgs(r) }, "PVEFORGE_HARNESS_ROSTER", 0},
		{"reset/vm-locked", grResetWorld, func(_ *testing.T, f *grfake) {
			f.vm(691).config = `{"scsi0":"pveforge-harness:vm-disk-0","tags":"pveforge-harness","lock":"backup"}`
		}, func(r string) []string { return resetArgs(r) }, "holds lock", 1},
		{"reset/goldens-not-one-point", func() *grfake {
			f := grResetWorld()
			f.vms[692].snaps[1].desc = grDescPrefix + "20260202T000000Z"
			return f
		}, nil, func(r string) []string { return resetArgs(r) }, "goldens are not one point", 1},
		{"reset/no-golden", func() *grfake {
			f := grResetWorld()
			f.vms[690].snaps = []grsnap{{name: "t1", snaptime: 2000}}
			return f
		}, nil, func(r string) []string { return resetArgs(r) }, "exactly one pvh-golden", 1},
		{"reset/golden-not-disk-only", func() *grfake {
			f := grResetWorld()
			f.vms[690].snaps[1].vmstate = 1
			return f
		}, nil, func(r string) []string { return resetArgs(r) }, "must be disk-only", 1},
		{"reset/guard-before-first-stop", grResetWorld, func(_ *testing.T, f *grfake) { setTag(f, 691, "other") }, func(r string) []string { return resetArgs(r) }, "does not carry tag", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.world()
			rosterPath, home := newGRTest(t, f)
			if c.setup != nil {
				c.setup(t, f)
			}
			env := harnessEnv(rosterPath, &f.reqLog)
			o := env.observe(t, c.args(rosterPath)...)
			o.wantRefusedWith(t, c.phrase)
			what := "golden"
			if strings.HasPrefix(c.name, "reset") {
				what = "reset"
			}
			if got := len(evidenceDirs(t, home, what)); got != c.evid {
				t.Fatalf("%d %s evidence dirs at the refusal, want %d (positive control: bookkeeping written, still exit 4)", got, what, c.evid)
			}
		})
	}
}

// The lock-wait refusal of golden and reset (three per-VM locks, ascending: the
// second is held by another process; the first was taken - bookkeeping - and is
// released): exit 4, nothing sent.
func TestGoldenResetExit4_LockWaitRefusedBeforeAnyWrite(t *testing.T) {
	for _, c := range []struct {
		name  string
		world func() *grfake
		args  func(r string) []string
	}{
		{"golden", grGoldenWorld, func(r string) []string { return goldenArgs(r, "--lock-wait", "7ms") }},
		{"reset", grResetWorld, func(r string) []string { return resetArgs(r, "--lock-wait", "7ms") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := c.world()
			rosterPath, _ := newGRTest(t, f)
			holdLock(t, rosterPath, harnessVMKey("h", 691))
			o := harnessEnv(rosterPath, &f.reqLog).observe(t, c.args(rosterPath)...)
			o.wantRefusedWith(t, "lock")
		})
	}
}

// The ledger positive control (D17): a golden run that APPENDS the created-VM
// ledger through the real Ledger.Add, creates its evidence directory, and is
// then refused by the acceptance seam (before any request that changes state)
// still exits 4 with zero entries in all three logs. Without this row a gate
// that opened for bookkeeping would be invisible.
func TestGoldenExit4_PositiveControl_LedgerAndEvidenceAreBookkeeping(t *testing.T) {
	f := grGoldenWorld()
	rosterPath, home := newGRTest(t, f)
	ledger := filepath.Join(t.TempDir(), "created")
	saved := harnessAccept
	t.Cleanup(func() { harnessAccept = saved })
	harnessAccept = func(ctx context.Context, deadline time.Duration, why string) error {
		if err := outer.OpenLedger(ledger).Add(690); err != nil {
			t.Errorf("ledger append: %v", err)
		}
		return errors.New("nested cluster down")
	}
	env := harnessEnv(rosterPath, &f.reqLog)
	o := env.observe(t, goldenArgs(rosterPath)...)
	o.wantRefusedWith(t, "was not accepted")
	if b, err := os.ReadFile(ledger); err != nil || string(b) != "690\n" {
		t.Fatalf("ledger = %q (%v): the run did not append it, the control is vacuous", b, err)
	}
	if n := len(evidenceDirs(t, home, "golden")); n != 1 {
		t.Fatalf("%d evidence dirs, want 1", n)
	}
	// the lock files were created beside the roster too
	if _, err := os.Stat(rosterPath + ".locks"); err != nil {
		t.Fatalf("the .locks dir was not created (%v): the control is vacuous", err)
	}
}

// Post-write twins of golden and reset: the same Guard refusal text AFTER the
// first request is exit 1; so is a failed acceptance after the writes.
func TestGoldenResetExit_PostWriteTwins(t *testing.T) {
	t.Run("golden/guard-after-first-shutdown", func(t *testing.T) {
		f := grGoldenWorld()
		setTag(f, 690, "other") // 691 is shut down first (a write), THEN 690's guard refuses
		rosterPath, _ := newGRTest(t, f)
		o := harnessEnv(rosterPath, &f.reqLog).observe(t, goldenArgs(rosterPath)...)
		o.wantTwin(t, 1, "does not carry tag")
		if got := f.writeLog(); len(got) != 1 || got[0] != "post 691 status/shutdown" {
			t.Fatalf("writes %q, want exactly the first shutdown", got)
		}
	})
	t.Run("golden/second-acceptance", func(t *testing.T) {
		f := grGoldenWorld()
		f.acceptErr = func(why string) error {
			if strings.Contains(why, "after") {
				return errors.New("nested cluster down")
			}
			return nil
		}
		rosterPath, _ := newGRTest(t, f)
		o := harnessEnv(rosterPath, &f.reqLog).observe(t, goldenArgs(rosterPath)...)
		o.wantTwin(t, 1, "was not accepted")
	})
	t.Run("reset/guard-after-first-stop", func(t *testing.T) {
		f := grResetWorld()
		setTag(f, 690, "other") // 691 stops first (a write), THEN 690's guard refuses
		rosterPath, _ := newGRTest(t, f)
		o := harnessEnv(rosterPath, &f.reqLog).observe(t, resetArgs(rosterPath)...)
		o.wantTwin(t, 1, "does not carry tag")
	})
	t.Run("reset/acceptance-after-the-reset", func(t *testing.T) {
		f := grResetWorld()
		f.acceptErr = func(string) error { return errors.New("nested cluster down") }
		rosterPath, _ := newGRTest(t, f)
		o := harnessEnv(rosterPath, &f.reqLog).observe(t, resetArgs(rosterPath)...)
		o.wantTwin(t, 1, "was not accepted")
	})
	t.Run("golden/task-seen-to-fail", func(t *testing.T) {
		f := grGoldenWorld()
		f.failShutdown = map[int]bool{691: true}
		rosterPath, _ := newGRTest(t, f)
		o := harnessEnv(rosterPath, &f.reqLog).observe(t, goldenArgs(rosterPath)...)
		o.wantTwin(t, 1, "the shutdown failed")
	})
}

// Exit 3 at the reset driver's wait boundary (reset.go postLeaf: the one
// WaitForTask site) for every request type it issues, plus the cascade delete.
func TestGoldenResetExit3_WaitBoundaries(t *testing.T) {
	withFastTaskPolls(t)
	cases := []struct {
		name  string
		world func() *grfake
		args  func(r string) []string
		typ   string
		first string // the dispatched write whose wait gave up (the log's last entry)
	}{
		{"golden/shutdown", grGoldenWorld, func(r string) []string { return goldenArgs(r) }, "qmshutdown", "post 691 status/shutdown"},
		{"golden/snapshot", grGoldenWorld, func(r string) []string { return goldenArgs(r) }, "qmsnapshot", "post 690 snapshot"},
		{"golden/start", grGoldenWorld, func(r string) []string { return goldenArgs(r) }, "qmstart", "post 692 status/start"},
		{"golden/replace-delete", func() *grfake {
			f := grGoldenWorld()
			for _, v := range []int{690, 691, 692} {
				f.vms[v].snaps = []grsnap{{name: "pvh-golden", snaptime: 1000, vmstate: 0, desc: grDescPrefix + grOld}}
			}
			return f
		}, func(r string) []string { return goldenArgs(r, "--replace-golden") }, "qmdelsnapshot", "delete 690 snapshot/pvh-golden"},
		{"reset/stop", grResetWorld, func(r string) []string { return resetArgs(r) }, "qmstop", "post 691 status/stop"},
		{"reset/cascade-delete", grResetWorld, func(r string) []string { return resetArgs(r) }, "qmdelsnapshot", "delete 690 snapshot/t2"},
		{"reset/rollback", grResetWorld, func(r string) []string { return resetArgs(r) }, "qmrollback", "post 690 snapshot/pvh-golden/rollback"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.world()
			f.breakTask(c.typ)
			rosterPath, _ := newGRTest(t, f)
			o := harnessEnv(rosterPath, &f.reqLog).observe(t, c.args(rosterPath)...)
			if o.code != 3 {
				t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
			}
			if !o.opened || !o.wrote() {
				t.Fatal("vacuous: nothing dispatched")
			}
			w := f.writeLog()
			if last := w[len(w)-1]; last != c.first {
				t.Fatalf("the wait that gave up followed %q, want %q (writes %q)", last, c.first, w)
			}
			if got := f.polls(c.typ); got < 4 {
				t.Fatalf("%s polls = %d, want >= 4", c.typ, got)
			}
			if !strings.Contains(o.stderr, "UPID:") {
				t.Fatalf("stderr %q has no UPID", o.stderr)
			}
		})
	}
}
