package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// These are the U-CORE command-level tests: each drives the whole CLI
// (runRootArgs → runRoot → the harness verb) against hfake, a stateful TLS
// fake PVE, so a mutant reverting a guard or gone-proof line is caught
// through the command, reading the mutated field (plan §5, S5). The seven
// mutation tests are named below; each asserts the CORRECT behaviour, so
// reverting the fix it guards turns it red.

const harnessNode = "qa-pve-07"

// hfake is a stateful fake PVE for the harness verbs. Zero value is a
// happy-path VM 690 (stopped, tagged, a qemu member of the harness pool on
// harnessNode); individual fields override one response for a mutation
// fixture.
type hfake struct {
	mu        sync.Mutex
	destroyed bool

	// pool member (before a destroy); overridable for guard fixtures.
	memberType string // default "qemu"
	memberVMID string // default "690" (a JSON token)
	memberNode string // default harnessNode
	poolEmpty  bool   // force empty members regardless of destroyed (for `gone`)

	tags     string // config tags; default the harness tag
	vmStatus string // status/current; default "stopped"
	nextid   string // /cluster/nextid; default "690"

	destroyUPID string // the UPID the DELETE returns; default a valid qmdestroy/690

	// task status BODY overrides (default: parsed from the polled UPID).
	taskType, taskID, taskNode, taskStatus, taskExit string

	snapshots string // GET /snapshot data array; default [s1]
}

func mkUPID(typ string, id int) string {
	return fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:%s:%d:root@pam:", harnessNode, typ, id)
}

func (f *hfake) or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (f *hfake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data := func(raw string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, raw)
	}
	p := r.URL.Path

	switch {
	case r.Method == http.MethodGet && strings.Contains(p, "/pools"):
		if f.poolEmpty || f.destroyed {
			data(`[{"poolid":"pveforge-harness","members":[]}]`)
			return
		}
		data(fmt.Sprintf(`[{"poolid":"pveforge-harness","members":[{"type":%q,"vmid":%s,"node":%q}]}]`,
			f.or(f.memberType, "qemu"), f.or(f.memberVMID, "690"), f.or(f.memberNode, harnessNode)))
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/status/current"):
		data(fmt.Sprintf(`{"vmid":690,"name":"h690","status":%q}`, f.or(f.vmStatus, "stopped")))
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/config"):
		data(fmt.Sprintf(`{"tags":%q}`, f.or(f.tags, "pveforge-harness")))
	case r.Method == http.MethodGet && strings.Contains(p, "/cluster/nextid"):
		data(f.or(f.nextid, "690"))
	case r.Method == http.MethodGet && strings.Contains(p, "/tasks/") && strings.HasSuffix(p, "/status"):
		upid := taskUPIDFromPath(p)
		typ, id := parseUPIDTypeID(upid)
		data(fmt.Sprintf(`{"upid":%q,"type":%q,"id":%q,"node":%q,"status":%q,"exitstatus":%q}`,
			upid, f.or(f.taskType, typ), f.or(f.taskID, id), f.or(f.taskNode, harnessNode),
			f.or(f.taskStatus, "stopped"), f.or(f.taskExit, "OK")))
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/snapshot"):
		data(f.or(f.snapshots, `[{"name":"s1","snaptime":100},{"name":"current","snaptime":0}]`))
	case r.Method == http.MethodPost && strings.Contains(p, "/status/stop"):
		data(fmt.Sprintf("%q", mkUPID("qmstop", 690)))
	case r.Method == http.MethodPost && strings.Contains(p, "/status/shutdown"):
		data(fmt.Sprintf("%q", mkUPID("qmshutdown", 690)))
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/snapshot"):
		data(fmt.Sprintf("%q", mkUPID("qmsnapshot", 690)))
	case r.Method == http.MethodDelete && strings.HasSuffix(p, "/qemu/690"):
		f.destroyed = true
		data(fmt.Sprintf("%q", f.or(f.destroyUPID, mkUPID("qmdestroy", 690))))
	default:
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route for "+r.Method+" "+p))
	}
}

func taskUPIDFromPath(p string) string {
	i := strings.Index(p, "/tasks/")
	j := strings.LastIndex(p, "/status")
	if i < 0 || j < 0 || j <= i+7 {
		return ""
	}
	u, err := url.PathUnescape(p[i+7 : j])
	if err != nil {
		return p[i+7 : j]
	}
	return u
}

func parseUPIDTypeID(upid string) (typ, id string) {
	f := strings.Split(upid, ":")
	if len(f) >= 7 {
		return f[5], f[6]
	}
	return "", ""
}

// newHarnessTest wires hfake behind a TLS server and a roster target named
// "h" on harnessNode, and sets the roster passphrase.
func newHarnessTest(t *testing.T, f *hfake) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return newTestRosterWithTLSTarget(t, srv, "h", harnessNode)
}

// harnessLedgerFile writes a created-VM ledger listing vmids and returns its
// path (for destroy's unconditional created-by-run gate, C7).
func harnessLedgerFile(t *testing.T, vmids ...int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "created")
	var b strings.Builder
	for _, v := range vmids {
		fmt.Fprintf(&b, "%d\n", v)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- happy paths ---------------------------------------------------------

func TestHarness_Destroy_HappyPath_ProvesGone(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{})
	ledger := harnessLedgerFile(t, 690)
	code, stdout, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "--yes", "-o", "json", "h", "690")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout not JSON: %q (%v)", stdout, err)
	}
	if got["proof"] != "gone" || got["result"] != "destroyed" {
		t.Errorf("stdout = %q, want proof=gone result=destroyed", stdout)
	}
}

func TestHarness_SnapshotCreate_DiskOnly(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{snapshots: `[{"name":"s1","snaptime":100},{"name":"current","snaptime":0}]`})
	code, stdout, stderr := runRootArgs("harness", "vm", "snapshot", "create", "--roster", rosterPath, "--vmstate", "0", "-o", "json", "h", "690", "s1")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout not JSON: %q (%v)", stdout, err)
	}
	if got["result"] != "created" || got["snapshot"] != "s1" {
		t.Errorf("stdout = %q, want result=created snapshot=s1", stdout)
	}
}

func TestHarness_VMIDBoundEnforced(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{})
	code, _, stderr := runRootArgs("harness", "vm", "stop", "--roster", rosterPath, "h", "700")
	if code == 0 || !strings.Contains(stderr, "not one of 690-699") {
		t.Errorf("exit %d stderr %q, want 690-699 refusal", code, stderr)
	}
}

// --- mutation test 1: gone-proof exitstatus gate -------------------------
// Guards DestroyTaskOK's exitstatus=="OK" (internal/harness/outer/goneproof.go).
// A WARNINGS task passes WaitForTask (warnings = success) but must fail the
// command through the gone-proof.
func TestHarness_Mutation1_WarningsTaskFailsDestroy(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{taskExit: "WARNINGS: 1"})
	ledger := harnessLedgerFile(t, 690)
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "--yes", "h", "690")
	if code == 0 {
		t.Fatalf("WARNINGS destroy exited 0; the gone-proof did not fail it")
	}
	if !strings.Contains(stderr, "not proven gone") {
		t.Errorf("stderr = %q, want 'not proven gone'", stderr)
	}
}

// --- mutation test 2: status-body re-assert (S1) -------------------------
// Guards DestroyTaskOK's BODY re-check: the UPID string parses fine, but the
// status body names a different id.
func TestHarness_Mutation2_StatusBodyMismatchFailsDestroy(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{taskID: "691"})
	ledger := harnessLedgerFile(t, 690)
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "--yes", "h", "690")
	if code == 0 {
		t.Fatalf("destroy with a mismatched status-body id exited 0")
	}
	if !strings.Contains(stderr, "not proven gone") {
		t.Errorf("stderr = %q, want 'not proven gone'", stderr)
	}
}

// --- mutation test 3: UPID-string binding --------------------------------
// Guards DestroyTaskOK's UPID-string type/id/node check: the DELETE returns a
// valid-format UPID whose type is NOT qmdestroy, while the status body is
// otherwise correct — so only the UPID-string check can catch it.
func TestHarness_Mutation3_WrongUPIDTypeFailsDestroy(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{
		destroyUPID: mkUPID("qmstart", 690), // wrong type in the UPID string
		taskType:    "qmdestroy",            // body is otherwise correct
	})
	ledger := harnessLedgerFile(t, 690)
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "--yes", "h", "690")
	if code == 0 {
		t.Fatalf("destroy whose UPID names a non-qmdestroy task exited 0")
	}
	if !strings.Contains(stderr, "not proven gone") {
		t.Errorf("stderr = %q, want 'not proven gone'", stderr)
	}
}

// --- mutation test 4: nextid raw-JSON decode (S2) ------------------------
// Guards scalarEqualsInt's string case (goneproof.go): nextid answers with a
// JSON string that is NOT the decimal of N; the real decode rejects it, a
// mutant that accepts any string (pve.vmidFree semantics) would not.
func TestHarness_Mutation4_NextidMustEqualN(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{poolEmpty: true, nextid: `"691"`})
	upid := mkUPID("qmdestroy", 690)
	code, _, stderr := runRootArgs("harness", "vm", "gone", "--roster", rosterPath, "--destroy-task", upid, "h", "690")
	if code == 0 {
		t.Fatalf("gone accepted nextid \"691\" as free for 690")
	}
	if !strings.Contains(stderr, "not proven gone") {
		t.Errorf("stderr = %q, want 'not proven gone'", stderr)
	}
}

// --- mutation test 5: created-by-run ledger ------------------------------
// Guards Guard's ModeDestroy created-by-run check (guard.go): destroy without
// --yes and with a ledger that does NOT list the VMID must refuse before any
// DELETE.
func TestHarness_Mutation5_DestroyRequiresCreatedByRun(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{})
	ledger := filepath.Join(t.TempDir(), "created") // empty: VMID not recorded
	if err := os.WriteFile(ledger, []byte("698\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "h", "690")
	if code == 0 {
		t.Fatalf("destroy of a VM not in the ledger exited 0 without --yes")
	}
	if !strings.Contains(stderr, "was not created by this run") {
		t.Errorf("stderr = %q, want created-by-run refusal", stderr)
	}
}

// --- mutation test 6: guard tag / node / membership ----------------------
// Guards Guard's three predicates (guard.go), each isolated so exactly one
// check refuses; reverting that check lets `stop` proceed to exit 0.
func TestHarness_Mutation6_GuardTagNodeMembership(t *testing.T) {
	cases := []struct {
		name string
		f    *hfake
		want string
	}{
		{"tag", &hfake{tags: "other"}, "does not carry tag"},
		{"node", &hfake{memberNode: "qa-pve-03"}, "is on node qa-pve-03"},
		{"membership", &hfake{memberType: "lxc"}, "not a qemu member"}, // tag present, but not a qemu member
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath := newHarnessTest(t, c.f)
			code, _, stderr := runRootArgs("harness", "vm", "stop", "--roster", rosterPath, "h", "690")
			if code == 0 {
				t.Fatalf("%s: stop exited 0; the guard did not refuse", c.name)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("%s: stderr = %q, want %q", c.name, stderr, c.want)
			}
		})
	}
}

// --- mutation test 7: not-latest reason contract (R3) --------------------
// Guards the rollback leaf's typed-refusal → JSON reason render
// (cmd/pveforge/harness_vm.go). A newer snapshot exists, so pve.Rollback
// refuses with *ErrNotNewestSnapshot; the command must print
// reason=not-newest on stdout (exit stays 1).
func TestHarness_Mutation7_RollbackNotNewestReason(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{
		snapshots: `[{"name":"s1","snaptime":100},{"name":"s2","snaptime":200},{"name":"current","snaptime":0}]`,
	})
	code, stdout, _ := runRootArgs("harness", "vm", "snapshot", "rollback", "--roster", rosterPath, "-o", "json", "h", "690", "s1")
	if code != 1 {
		t.Fatalf("rollback-to-not-newest exit = %d, want 1", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %q (%v)", stdout, err)
	}
	if got["reason"] != "not-newest" || got["rollback"] != "refused" {
		t.Errorf("stdout = %q, want reason=not-newest rollback=refused", stdout)
	}
	// The cascade_order carries the newer snapshot the consumer must clear.
	if co, _ := got["cascade_order"].([]any); len(co) != 1 || co[0] != "s2" {
		t.Errorf("cascade_order = %v, want [s2]", got["cascade_order"])
	}
}

// --- C2: the force-stop/timeout leaf lock is held across the POST --------
// A command-level pin (the per-command flag-presence test cannot catch a
// deleted leaf lock, since the plain path's idempotent.Run is already a
// sink). The object's lock is held before the run, so `shutdown` with a leaf
// flag must FAIL to acquire it (lock-wait timeout) rather than proceed to the
// status/shutdown POST. If the leaf lock.Mutation is removed, the command
// reaches the POST and exits 0 — this test goes RED.
func TestHarness_C2_ShutdownLeafPathHoldsLock(t *testing.T) {
	for _, flag := range []string{"--force-stop", "--timeout"} {
		t.Run(flag, func(t *testing.T) {
			rosterPath := newHarnessTest(t, &hfake{})
			holdLock(t, rosterPath, harnessVMKey("h", 690))
			args := []string{"harness", "vm", "shutdown", flag}
			if flag == "--timeout" {
				args = append(args, "5")
			}
			args = append(args, "--lock-wait", "7ms", "--roster", rosterPath, "h", "690")
			code, _, stderr := runRootArgs(args...)
			if code == 0 {
				t.Fatalf("%s: shutdown proceeded without the leaf lock (exit 0)", flag)
			}
			if !strings.Contains(stderr, "lock") {
				t.Errorf("%s: stderr = %q, want a lock-acquisition failure", flag, stderr)
			}
		})
	}
}

// --- C5: snapshot delete fails CLOSED on a swallowed/empty list ----------
// An empty [] list (no "current") is an unverifiable read, not "no
// snapshots". Pre-fix (realSnapshots) reported every name absent and exited
// 0; the verifiable list must refuse.
func TestHarness_C5_SnapshotDeleteSwallowedListFailsClosed(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{snapshots: `[]`})
	code, _, stderr := runRootArgs("harness", "vm", "snapshot", "delete", "--roster", rosterPath, "h", "690", "s1")
	if code == 0 {
		t.Fatalf("delete on a swallowed/empty list exited 0 (fail-open)")
	}
	if !strings.Contains(stderr, "unverifiable") {
		t.Errorf("stderr = %q, want an 'unverifiable' refusal", stderr)
	}
}

// --- C5: snapshot create post-verify catches a list lacking the name -----
// The verifiable post-create list has "current" but not the created name →
// the create must fail "not present" (pins the post-verify).
func TestHarness_C5_SnapshotCreatePostVerifyMissing(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{snapshots: `[{"name":"s1","snaptime":100},{"name":"current","snaptime":0}]`})
	code, _, stderr := runRootArgs("harness", "vm", "snapshot", "create", "--roster", rosterPath, "h", "690", "s9")
	if code == 0 {
		t.Fatalf("create exited 0 though its name is absent from the post-create list")
	}
	if !strings.Contains(stderr, "not present") {
		t.Errorf("stderr = %q, want a post-verify 'not present' failure", stderr)
	}
}

// --- C7: --yes must NOT bypass created-by-run ----------------------------
// created-by-run is lib.sh:484's unconditional destroy gate. With a ledger
// that does NOT list the VMID, `destroy --yes` must still refuse. Pre-fix
// (--yes → ModeChange) this skipped the ledger and destroyed (exit 0).
func TestHarness_C7_YesDoesNotBypassCreatedByRun(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{})
	ledger := harnessLedgerFile(t, 698) // 690 NOT listed
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "--yes", "h", "690")
	if code == 0 {
		t.Fatalf("destroy --yes of a VMID absent from the ledger exited 0 (created-by-run bypassed)")
	}
	if !strings.Contains(stderr, "was not created by this run") {
		t.Errorf("stderr = %q, want created-by-run refusal", stderr)
	}
}

// --- C7: --yes is additively required (a valid ledger still needs it) ----
func TestHarness_C7_DestroyNeedsYesConfirmation(t *testing.T) {
	rosterPath := newHarnessTest(t, &hfake{})
	ledger := harnessLedgerFile(t, 690) // 690 IS listed, but no --yes
	code, _, stderr := runRootArgs("harness", "vm", "destroy", "--roster", rosterPath, "--created-file", ledger, "h", "690")
	if code == 0 {
		t.Fatalf("destroy of a created VM without --yes exited 0 (no confirmation gate)")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Errorf("stderr = %q, want a --yes confirmation requirement", stderr)
	}
}
