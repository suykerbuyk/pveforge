package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Process-level rows of `vm destroy`: a REAL SIGKILL (B7), a REAL SIGINT and
// SIGTERM (B9), the absence of any SSH fallback, and the absence of any local
// record. Each re-executes the test binary as pveforge (startCLIChild), as
// signal_subprocess_test.go does.

func childDestroyArgs(e *dEnv, format string) []string {
	return []string{"vm", "destroy", "--roster", e.roster, "-o", format, "--yes", dTarget, strconv.Itoa(dVMID)}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// B7: the first process is SIGKILLed mid-wait, after the fixture recorded its
// DELETE; a second invocation then behaves EXACTLY as it does for the same PVE
// state reached WITHOUT a kill (a control, byte for byte), at each state the
// task passes through. Nothing the killed process was to have written can be
// what decides.
func TestVMDestroy_B7_SIGKILLThenRetryEqualsTheNoKillControl(t *testing.T) {
	killed := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" })
	child := startCLIChild(t, cliChildSpec{Args: childDestroyArgs(killed, "json")})
	waitFor(t, "the child's DELETE", func() bool { return killed.deletes() == 1 })
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	ws := child.waitExit(t, 10*time.Second)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the child did not die by SIGKILL: %v", ws)
	}

	control := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" })
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, 100*time.Millisecond))
	if r := control.runYes(); r.code != 3 {
		t.Fatalf("control first run: %d %s", r.code, r.stdout)
	}

	// State 1: the destroy is still running -> B4, identical either way.
	a, b := killed.runYes(), control.runYes()
	want(t, a, 4, "refused", "B4")
	if a.stdout != b.stdout || a.code != b.code {
		t.Errorf("after a kill: exit %d %s\nwithout a kill: exit %d %s", a.code, a.stdout, b.code, b.stdout)
	}
	if killed.deletes() != 1 || control.deletes() != 1 {
		t.Errorf("a second DELETE was dispatched: %d / %d", killed.deletes(), control.deletes())
	}

	// State 2: the destroy ended OK and the VM is gone -> B5-gone, identical.
	for _, e := range []*dEnv{killed, control} {
		e.s.Tasks = []pvefake.TaskRow{dRow("qmdestroy", 1, "OK")}
		e.s.VMConfig, e.s.Reflect = "", false
	}
	a, b = killed.runYes(), control.runYes()
	want(t, a, 0, "ok", "B5-gone")
	if a.stdout != b.stdout {
		t.Errorf("B5 after a kill: %s\nwithout: %s", a.stdout, b.stdout)
	}

	// State 3: the destroy FAILED and the VM is still here -> a fresh attempt (B6).
	for _, e := range []*dEnv{killed, control} {
		e.s.Tasks = []pvefake.TaskRow{dRow("qmdestroy", 3, "ERROR: x")}
		e.s.VMConfig, e.s.Reflect, e.s.ReflectEnd = `{"name":"vm691"}`, true, "OK"
	}
	a, b = killed.runYes(), control.runYes()
	want(t, a, 0, "ok", "B1")
	if a.str("prior_exitstatus") != "ERROR: x" || a.stdout != b.stdout {
		t.Errorf("B6 after a kill: %s\nwithout: %s", a.stdout, b.stdout)
	}
}

// B9: SIGINT and SIGTERM after the destroy was dispatched exit 130 / 143 and
// still say outcome=unknown, with the destroy's identity, ON STDOUT.
//
// Deviation from the plan (recorded in the report): the plan asks the parent to
// wait on the child's STDOUT before signalling, but the verb renders its report
// only at the END, so there is no stdout to wait on. The parent instead waits
// for the child's first poll of the destroy task's status — which proves the
// child holds the UPID and is inside WaitForTask, so the signal cannot land in
// the window between the DELETE and the render that would give exit 130 with
// an empty stdout (the B7 kill window, accepted by the spec).
func TestVMDestroy_B9_RealSignalsAfterDispatch(t *testing.T) {
	for _, tc := range []struct {
		sig  syscall.Signal
		name string
		code int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		e := newDEnv(t, func(s *pvefake.VMREST) { s.ReflectEnd = "" })
		child := startCLIChild(t, cliChildSpec{Args: childDestroyArgs(e, "kv")})
		pollPrefix := "GET /api2/json/nodes/" + dNode + "/tasks/" + dUPID("qmdestroy", 1) + "/status"
		waitFor(t, "the child's first task poll", func() bool { return e.count(pollPrefix) >= 1 })
		if err := child.cmd.Process.Signal(tc.sig); err != nil {
			t.Fatal(err)
		}
		ws := child.waitExit(t, 10*time.Second)
		if !ws.Exited() || ws.ExitStatus() != tc.code {
			t.Fatalf("%s: child ended %v, want exit %d; stderr %q", tc.name, ws, tc.code, child.stderr.String())
		}
		var lines []string
	drain:
		for {
			select {
			case l := <-child.lines:
				lines = append(lines, l)
			default:
				break drain
			}
		}
		kv := parseKV(t, strings.Join(lines, "\n"))
		if kv["outcome"] != "unknown" || kv["upid"] != dUPID("qmdestroy", 1) || kv["reason"] != "interrupted" || kv["situation"] != "B9" {
			t.Errorf("%s: stdout %v", tc.name, kv)
		}
		if !strings.Contains(child.stderr.String(), "may or may not have been applied") {
			t.Errorf("%s: stderr %q", tc.name, child.stderr.String())
		}
		if e.deletes() != 1 {
			t.Errorf("%s: DELETEs %d", tc.name, e.deletes())
		}
	}
}

// S12.2: a destroy the token is refused (403) is a failure naming the
// credential — never a root-over-SSH retry. The control comes FIRST, against
// the same SSH server: a command that does reach PVE over SSH must be seen to
// move the counter, or the zero below measures nothing.
func TestVMDestroy_NeverFallsBackToRootOverSSH(t *testing.T) {
	s := pvefake.NewVMREST(t, dNode)
	s.VMConfig, s.DestroyCode, s.NextIDFree = `{"name":"vm691"}`, 403, true
	srv := s.ServerTLS()
	t.Cleanup(srv.Close)
	t.Cleanup(pve.SetTaskTimingsForTests(time.Millisecond, time.Second))
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(inventoryExec)
	path := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)

	before := fs.Connections()
	if code, _, errOut := runRootArgs("access", "inventory", "--roster", path, dTarget); code != 0 {
		t.Fatalf("control: access inventory exited %d: %s", code, errOut)
	}
	if fs.Connections() <= before {
		t.Fatalf("control: a command that reaches PVE over SSH did not move Connections (%d -> %d): the zero below would measure nothing", before, fs.Connections())
	}
	after := fs.Connections()

	code, out, _ := runRootArgs("vm", "destroy", "--roster", path, "-o", "json", "--yes", dTarget, strconv.Itoa(dVMID))
	r := parseDRes(t, code, out, "")
	want(t, r, 1, "failed", "dispatch-refused")
	if fs.Connections() != after {
		t.Errorf("vm destroy opened %d SSH connection(s): a root fallback was attempted", fs.Connections()-after)
	}
}

// D2/D3 tripwire. The spec admits the "no local record decides" half has no
// acceptance row; this is a TRIPWIRE, not a proof: a stale record planted in
// the places a record might live does not change the decision, and a run
// creates no file anywhere but the lock files.
func TestVMDestroy_NoLocalRecordDecidesOrAppears(t *testing.T) {
	cwd, home, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	t.Chdir(cwd)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("TMPDIR", tmp)
	e := newDEnv(t, nil)
	rosterDir := filepath.Dir(e.roster)

	for _, dir := range []string{cwd, home, tmp, rosterDir} {
		for _, name := range []string{".pveforge-destroy-state", "destroy.json", "pveforge-destroy-691.inflight"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"vmid":691,"state":"in-flight"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	snap := func() map[string]int64 {
		m := map[string]int64{}
		for _, dir := range []string{cwd, home, tmp, rosterDir} {
			_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					info, _ := d.Info()
					m[p] = info.Size()
				}
				return nil
			})
		}
		return m
	}
	before := snap()
	r := e.runYes()
	want(t, r, 0, "ok", "B1") // a planted "in flight" record did not refuse it
	after := snap()
	var created []string
	for p, size := range after {
		if old, ok := before[p]; !ok && !strings.Contains(p, ".locks") {
			created = append(created, p)
		} else if ok && old != size {
			created = append(created, p+" (changed)")
		}
	}
	slices.Sort(created)
	if len(created) != 0 {
		t.Errorf("the run left files behind: %q", created)
	}
}

// M60-M62 as SOURCE pins: the idioms that must not be pasted into the verb.
// This is a test in cmd/pveforge, not an edit to internal/sourceguard: the
// module-wide DestroyVM call-site guard is
// internal/sourceguard/vmdestroy_callsites_test.go (U7).
func TestVMDestroy_SourcePins(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "vm_destroy.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		if strings.Contains(imp.Path.Value, "harness") {
			t.Errorf("vm_destroy.go imports %s: the harness gone-proof (outer.VMGone) is wrong for a production destroy", imp.Path.Value)
		}
	}
	calls := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			calls[x.Sel.Name]++
		case *ast.Ident:
			calls["ident:"+x.Name]++
		}
		return true
	})
	for _, banned := range []string{"Apply", "VMGone", "RawRequest", "TaskList", "SSHExec", "Exec"} {
		if calls[banned] != 0 || calls["ident:"+banned] != 0 {
			t.Errorf("vm_destroy.go uses %s", banned)
		}
	}
	for name, n := range map[string]int{"DestroyEnd": 1, "JudgeGone": 1, "DetermineDestroyInFlight": 1, "StatusGatedStop": 1, "DestroyVM": 1, "WaitForTask": 1} {
		if calls[name] < n {
			t.Errorf("vm_destroy.go has %d uses of %s, want at least %d", calls[name], name, n)
		}
	}
	if calls["DestroyVM"] != 1 || calls["WaitForTask"] != 1 {
		t.Errorf("DestroyVM used %d times and WaitForTask %d, want exactly one each", calls["DestroyVM"], calls["WaitForTask"])
	}
	// Anti-vacuity: the walk saw the file it guards.
	if calls["ident:newVMDestroyCmd"] == 0 {
		t.Fatal("the walk did not reach newVMDestroyCmd")
	}
}
