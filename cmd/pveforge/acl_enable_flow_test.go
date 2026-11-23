package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The operator flow of `acl enable-vm-destroy`: plan, confirm, write, verdict
// (task pveforge-enable-vm-destroy-one-step-operator-flow, plan
// .build/chair/enable-flow-plan.md). Every "writes nothing" assertion has a
// twin on the identical fixture that DOES write, and every fixture here has a
// REST side that is coupled to what root wrote, so a verdict taken before the
// write cannot pass (instruments-that-lie-green #7, #13, #15).

const flowTarget = "qa-pve-01"

// flowEnv is a root host (enableHost) plus a token REST side, with one event
// log ordering both.
type flowEnv struct {
	t      *testing.T
	host   *enableHost
	srv    *httptest.Server
	roster string

	mu     sync.Mutex
	events []string // "ssh: <cmd>" and "rest: <METHOD> <path>", in arrival order
	// Overrides for the REST answers (0 / "" = the coupled default).
	statusCode  int      // GET /nodes/<n>/status
	clusterCode int      // GET /cluster/config/nodes
	clusterBody string   // GET /cluster/config/nodes body when clusterCode is 0 or 200
	vmPrivs     []string // what GET /access/permissions?path=/vms/N answers
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	e := &flowEnv{t: t, host: newEnableHost(), vmPrivs: []string{"VM.PowerMgmt", "VM.Allocate"}}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serveREST))
	t.Cleanup(e.srv.Close)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		e.record("ssh: " + cmd)
		return e.host.exec(cmd)
	})
	e.roster = newTestRosterWithSSHTarget(t, e.srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return e
}

func (e *flowEnv) record(ev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
}

func (e *flowEnv) log() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.events)
}

// held is true once root has put a role on the token's row (the upgrade's
// only write that matters to the token, or a fixture that starts enabled).
func (e *flowEnv) held() bool {
	e.host.mu.Lock()
	defer e.host.mu.Unlock()
	return len(e.host.rows) > 0
}

// preEnable makes the host start already enabled: the role exists with D and
// the token holds it on /.
func (e *flowEnv) preEnable() {
	d := append(slices.Clone(enableVMAdmin), "Sys.Audit")
	e.host.mu.Lock()
	e.host.roles["ForgeVMAdminAudit"] = d
	e.host.rows = append(e.host.rows, "ForgeVMAdminAudit")
	e.host.mu.Unlock()
}

func (e *flowEnv) serveREST(w http.ResponseWriter, r *http.Request) {
	e.record("rest: " + r.Method + " " + r.URL.Path)
	e.mu.Lock()
	status, cluster, clusterBody, vmPrivs := e.statusCode, e.clusterCode, e.clusterBody, e.vmPrivs
	e.mu.Unlock()
	held := e.held()
	reply := func(code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
	switch r.URL.Path {
	case "/api2/json/nodes/" + flowTarget + "/status":
		switch {
		case status != 0:
			reply(status, `{"data":null}`)
		case held:
			reply(200, `{"data":{"uptime":1}}`)
		default:
			reply(403, `{"data":null}`)
		}
	case "/api2/json/cluster/config/nodes":
		switch {
		case cluster != 0 && cluster != 200:
			reply(cluster, `{"data":null}`)
		case clusterBody != "":
			reply(200, clusterBody)
		case held:
			reply(200, `{"data":[{"node":"`+flowTarget+`"}]}`)
		default:
			reply(403, `{"data":null}`)
		}
	case "/api2/json/nodes":
		reply(200, `{"data":[{"node":"`+flowTarget+`"}]}`)
	case "/api2/json/access/permissions":
		// keyed by exactly the requested path, as PVE answers a path query
		path := r.URL.Query().Get("path")
		privs := map[string]int{}
		if strings.HasPrefix(path, "/vms/") {
			for _, p := range vmPrivs {
				privs[p] = 1
			}
		} else if held {
			privs["Sys.Audit"] = 1
		}
		b, _ := json.Marshal(map[string]any{"data": map[string]any{path: privs}})
		reply(200, string(b))
	default:
		reply(404, `{"data":null}`)
	}
}

// ssh returns the root commands in the log that are writes.
func (e *flowEnv) sshWrites() []string { return e.host.writes() }

// lastWriteIdx / firstRESTIdx order the two sides of the log.
func (e *flowEnv) idx(pred func(string) bool) (first, last int) {
	first, last = -1, -1
	for i, ev := range e.log() {
		if pred(ev) {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	return
}

func isSSHWrite(ev string) bool {
	return strings.HasPrefix(ev, "ssh: pveum role add") || strings.HasPrefix(ev, "ssh: pveum acl modify")
}
func isVerdictRead(ev string) bool {
	return ev == "rest: GET /api2/json/nodes/"+flowTarget+"/status" || ev == "rest: GET /api2/json/cluster/config/nodes"
}

// ---- the terminal and prompt seams ----

type flowTTY struct {
	asks    atomic.Int32 // times the question was put
	answers atomic.Int32 // times a line was consumed
}

// setTTY makes a terminal available, answering with input. The REAL askYesNo
// still parses the answer (it is what production runs); only the file
// descriptors are replaced.
func setTTY(t *testing.T, input string) *flowTTY {
	t.Helper()
	return setTTYReader(t, strings.NewReader(input))
}

func setTTYReader(t *testing.T, in io.Reader) *flowTTY {
	t.Helper()
	c := &flowTTY{}
	oTerm, oIn, oAsk := confirmTerminal, confirmInput, confirmAsk
	confirmTerminal = func() bool { return true }
	confirmInput = func() io.Reader { return countingFlowReader{in, &c.answers} }
	confirmAsk = func(ctx context.Context, in io.Reader, w io.Writer) (bool, error) {
		c.asks.Add(1)
		return askYesNo(ctx, in, w)
	}
	t.Cleanup(func() { confirmTerminal, confirmInput, confirmAsk = oTerm, oIn, oAsk })
	return c
}

type countingFlowReader struct {
	r io.Reader
	n *atomic.Int32
}

func (c countingFlowReader) Read(p []byte) (int, error) {
	c.n.Add(1)
	return c.r.Read(p)
}

// setNoTTY makes the run have no terminal, whatever the test binary's stdio is.
func setNoTTY(t *testing.T) {
	t.Helper()
	o := confirmTerminal
	confirmTerminal = func() bool { return false }
	t.Cleanup(func() { confirmTerminal = o })
}

// forbidPrompt fails the test if the question is ever put.
func forbidPrompt(t *testing.T) *flowTTY {
	t.Helper()
	c := setTTY(t, "y\n")
	return c
}

// ---- running ----

type flowRes struct {
	code           int
	stdout, stderr string
	m              map[string]any
}

func (r flowRes) str(k string) string { s, _ := r.m[k].(string); return s }
func (r flowRes) boolean(k string) (bool, bool) {
	b, ok := r.m[k].(bool)
	return b, ok
}

// run is a run that reached the verb: it MUST have rendered one JSON object on
// stdout, whatever its exit status (the verb's report is how every outcome, a
// refusal and a declined plan included, is told). A run with no report fails
// here, so a verdict path that forgot to render cannot read as a pass.
func (e *flowEnv) run(args ...string) flowRes { e.t.Helper(); return e.runArgs(true, args...) }

// runNoReport is the one other kind of run, and it asserts the opposite: a
// refusal the verb makes BEFORE it has anything to report (a role name or role
// conflict refused in the plan pass: an error on stderr, nothing on stdout, a
// non-zero exit). Usage and flag errors never go through either helper: they
// are tested with runRootArgs directly, which has no report to demand. The
// helper fails on a zero exit or on any stdout, so it cannot be used to excuse
// a missing report on a run that succeeded or rendered something.
func (e *flowEnv) runNoReport(args ...string) flowRes {
	e.t.Helper()
	r := e.runArgs(false, args...)
	if r.code == 0 || strings.TrimSpace(r.stdout) != "" {
		e.t.Fatalf("runNoReport: exit %d, stdout %q: a run that succeeded or rendered is not a report-less refusal", r.code, r.stdout)
	}
	return r
}

func (e *flowEnv) runArgs(wantReport bool, args ...string) flowRes {
	e.t.Helper()
	full := append([]string{"acl", "enable-vm-destroy", "--roster", e.roster, "-o", "json"}, args...)
	full = append(full, flowTarget)
	code, out, errOut := runRootArgs(full...)
	r := flowRes{code: code, stdout: out, stderr: errOut}
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &r.m); err != nil {
			e.t.Fatalf("stdout is not one JSON object: %v\n%s", err, out)
		}
	}
	if wantReport {
		assertReadyIsTheSentence(e.t, r)
	}
	return r
}

// assertReadyIsTheSentence: `ready` and "privileges are ready" in the verdict
// are the same bool on EVERY report (G2); a report with a verdict but no
// ready key, or the reverse, is a disagreement too.
func assertReadyIsTheSentence(t *testing.T, r flowRes) {
	t.Helper()
	if r.m == nil {
		// Asked to check a verdict path with no report: that is a failure, not
		// a pass. (A path that renders nothing is the bug this pins.)
		t.Fatalf("no report on stdout (exit %d, stderr %q): nothing to check, and a verdict path must render", r.code, r.stderr)
	}
	ready, hasReady := r.boolean("ready")
	verdict, hasVerdict := r.m["verdict"].(string)
	if hasReady != hasVerdict {
		t.Fatalf("ready present=%v but verdict present=%v: %s", hasReady, hasVerdict, r.stdout)
	}
	if hasReady && ready != strings.Contains(verdict, "privileges are ready") {
		t.Fatalf("ready=%v but the verdict says %q: %s", ready, verdict, r.stdout)
	}
}

func wantExit(t *testing.T, r flowRes, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
}

// ---- AC1 + F1: no TTY, no --yes, something would be written ----

func TestEnableFlow_T1_NoTTYNoYes_RefusesWithZeroWrites(t *testing.T) {
	// F1: the fixture is --role-only with the role ABSENT.
	for _, args := range [][]string{{"--role-only"}, {}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			setNoTTY(t)
			e := newFlowEnv(t)
			r := e.run(args...)
			wantExit(t, r, 4)
			if w := e.sshWrites(); len(w) != 0 {
				t.Fatalf("no confirmation, yet wrote: %q", w)
			}
			if !strings.Contains(r.stderr, "--yes") {
				t.Errorf("stderr does not name --yes: %q", r.stderr)
			}
			// the plan was computed (the run got to the decision) and is in the report
			if len(e.host.log) == 0 || r.str("outcome") != "refused" || r.m["planned"] == nil {
				t.Errorf("vacuous: root ran %d commands, outcome %q, planned %v", len(e.host.log), r.str("outcome"), r.m["planned"])
			}
			if b, _ := r.boolean("wrote"); b {
				t.Errorf("wrote=true on a refusal")
			}
			// the twin: the identical run with --yes writes.
			setNoTTY(t)
			e2 := newFlowEnv(t)
			r2 := e2.run(append([]string{"--yes"}, args...)...)
			wantExit(t, r2, 0)
			if len(e2.sshWrites()) == 0 {
				t.Fatal("twin: --yes did not write: the refusal above proves nothing")
			}
		})
	}
}

// ---- AC2: --yes skips the prompt ----

func TestEnableFlow_T2_YesSkipsThePrompt(t *testing.T) {
	c := setTTY(t, "y\n")
	e := newFlowEnv(t)
	r := e.run("--yes")
	wantExit(t, r, 0)
	if c.asks.Load() != 0 || c.answers.Load() != 0 || len(e.sshWrites()) != 2 {
		t.Fatalf("--yes: asked %d, read %d, writes %q", c.asks.Load(), c.answers.Load(), e.sshWrites())
	}
	// control: the same fixture without --yes asks exactly once.
	c2 := setTTY(t, "y\n")
	e2 := newFlowEnv(t)
	wantExit(t, e2.run(), 0)
	if c2.asks.Load() != 1 || len(e2.sshWrites()) != 2 {
		t.Fatalf("control: asked %d, writes %q", c2.asks.Load(), e2.sshWrites())
	}
}

// --yes is a flag-wiring site (#12): through runRoot, and it must reach the
// flow. With the terminal gone, --yes is what makes the run write.
func TestEnableFlow_T16_YesFlagIsWired(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	if cmd := newACLEnableVMDestroyCmd(); cmd.Flags().Lookup("yes") == nil || cmd.Flags().Lookup("output") == nil || cmd.Flags().Lookup("vmid") == nil {
		t.Fatal("--yes, -o or --vmid is missing")
	}
	wantExit(t, e.run("--yes"), 0)
	if len(e.sshWrites()) != 2 {
		t.Fatalf("--yes wrote %q", e.sshWrites())
	}
}

// ---- AC3 + F3: the answers ----

func TestEnableFlow_T3_PromptAnswers(t *testing.T) {
	type tc struct {
		name   string
		input  string
		reader func() io.Reader
		write  bool
	}
	cases := []tc{
		{name: "y", input: "y\n", write: true},
		{name: "yes", input: "yes\n", write: true},
		{name: "Y", input: "Y\n", write: true},
		{name: "YES", input: "YES\n", write: true},
		{name: "padded y", input: "  y \n", write: true},
		{name: "y at EOF without newline", input: "y", write: true},
		{name: "n", input: "n\n"},
		{name: "N", input: "N\n"},
		{name: "empty line", input: "\n"},
		{name: "EOF", input: ""},
		{name: "whitespace only", input: "   \t \n"},
		{name: "y NUL", input: "y\x00\n"},
		{name: "yes please", input: "yes please\n"},
		{name: "no", input: "no\n"},
		{name: "read error", reader: func() io.Reader { return errReader{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var tty *flowTTY
			if c.reader != nil {
				tty = setTTYReader(t, c.reader())
			} else {
				tty = setTTY(t, c.input)
			}
			e := newFlowEnv(t)
			r := e.run()
			if tty.asks.Load() != 1 || tty.answers.Load() == 0 {
				t.Fatalf("the answer was not consulted (asks %d, reads %d): the case proves nothing", tty.asks.Load(), tty.answers.Load())
			}
			if c.write {
				wantExit(t, r, 0)
				w := e.sshWrites()
				if len(w) != 2 {
					t.Fatalf("writes %q", w)
				}
				// what was written is what was shown (the stderr plan block).
				shown := planFromStderr(t, r.stderr)
				if len(shown) != 2 || w[0] != shown[0] || w[1] != shown[1] {
					t.Fatalf("shown %q, sent %q", shown, w)
				}
				return
			}
			wantExit(t, r, 4)
			if w := e.sshWrites(); len(w) != 0 {
				t.Fatalf("answer %q wrote: %q", c.input, w)
			}
			if r.str("outcome") != "declined" {
				t.Errorf("outcome %q, want declined", r.str("outcome"))
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// planFromStderr decodes the pre-prompt block (the first JSON object on
// stderr) and returns its planned commands.
func planFromStderr(t *testing.T, stderr string) []string {
	t.Helper()
	i := strings.Index(stderr, "{")
	j := strings.LastIndex(stderr, "}")
	if i < 0 || j < i {
		t.Fatalf("no plan block on stderr: %q", stderr)
	}
	var blk struct {
		Outcome string   `json:"outcome"`
		Planned []string `json:"planned"`
	}
	if err := json.Unmarshal([]byte(stderr[i:j+1]), &blk); err != nil {
		t.Fatalf("plan block: %v\n%s", err, stderr)
	}
	if blk.Outcome != "plan" {
		t.Fatalf("plan block outcome %q", blk.Outcome)
	}
	return blk.Planned
}

// The affirmative parse, called directly (the mutants' target).
func TestEnableFlow_T3b_IsAffirmative(t *testing.T) {
	yes := []string{"y", "Y", "yes", "YES", "Yes", " y", "y ", "\ty\n", "yes\r\n"}
	no := []string{"", " ", "\n", "n", "N", "no", "yes please", "y\x00", "ye", "yy", "yes!", "1", "true", "ok", "sure", "y\x00\n"}
	for _, s := range yes {
		if !isAffirmative(s) {
			t.Errorf("%q must be affirmative", s)
		}
	}
	for _, s := range no {
		if isAffirmative(s) {
			t.Errorf("%q must not be affirmative", s)
		}
	}
}

// ---- AC4: no prompt when nothing would be written ----

func TestEnableFlow_T4_NoPromptWhenNothingToWrite(t *testing.T) {
	t.Run("already enabled, with a terminal", func(t *testing.T) {
		c := forbidPrompt(t)
		e := newFlowEnv(t)
		e.preEnable()
		r := e.run()
		wantExit(t, r, 0)
		if c.asks.Load() != 0 || len(e.sshWrites()) != 0 || r.str("outcome") != "already_enabled" {
			t.Fatalf("asked %d, writes %q, outcome %q", c.asks.Load(), e.sshWrites(), r.str("outcome"))
		}
	})
	t.Run("already enabled, no terminal, no --yes", func(t *testing.T) {
		setNoTTY(t)
		e := newFlowEnv(t)
		e.preEnable()
		r := e.run()
		wantExit(t, r, 0)
		if r.str("outcome") != "already_enabled" {
			t.Fatalf("outcome %q", r.str("outcome"))
		}
	})
	t.Run("role-only with the role present", func(t *testing.T) {
		c := forbidPrompt(t)
		e := newFlowEnv(t)
		e.host.roles["ForgeVMAdminAudit"] = append(slicesClone(enableVMAdmin), "Sys.Audit")
		r := e.run("--role-only")
		wantExit(t, r, 0)
		if c.asks.Load() != 0 || len(e.sshWrites()) != 0 {
			t.Fatalf("asked %d, writes %q", c.asks.Load(), e.sshWrites())
		}
	})
	// every pre-write refusal comes BEFORE any question
	refusals := map[string]func(e *flowEnv){
		"role conflict": func(e *flowEnv) { e.host.roles["ForgeVMAdminAudit"] = []string{"Sys.Audit"} },
	}
	for name, setup := range refusals {
		t.Run(name, func(t *testing.T) {
			c := forbidPrompt(t)
			e := newFlowEnv(t)
			setup(e)
			r := e.runNoReport()
			if r.code == 4 && len(e.host.log) == 0 {
				t.Fatalf("exit %d: %s", r.code, r.stderr)
			}
			if c.asks.Load() != 0 || len(e.sshWrites()) != 0 {
				t.Fatalf("asked %d, writes %q before a refusal", c.asks.Load(), e.sshWrites())
			}
			if !strings.Contains(r.stderr, "different privilege set") {
				t.Errorf("stderr %q", r.stderr)
			}
		})
	}
	t.Run("a refused role name", func(t *testing.T) {
		c := forbidPrompt(t)
		e := newFlowEnv(t)
		r := e.runNoReport("--role", "PVEForgeX")
		if r.code == 0 || c.asks.Load() != 0 || len(e.host.log) != 0 {
			t.Fatalf("exit %d, asked %d, root ran %q", r.code, c.asks.Load(), e.host.log)
		}
	})
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// ---- AC6: --dry-run ----

func TestEnableFlow_T6_DryRun(t *testing.T) {
	for _, withTTY := range []bool{true, false} {
		for _, yes := range []bool{false, true} {
			name := fmt.Sprintf("tty=%v yes=%v", withTTY, yes)
			t.Run(name, func(t *testing.T) {
				var c *flowTTY
				if withTTY {
					c = forbidPrompt(t)
				} else {
					setNoTTY(t)
				}
				e := newFlowEnv(t)
				args := []string{"--dry-run"}
				if yes {
					args = append(args, "--yes")
				}
				r := e.run(args...)
				wantExit(t, r, 0)
				if len(e.sshWrites()) != 0 || len(e.host.log) == 0 {
					t.Fatalf("writes %q, root ran %d commands", e.sshWrites(), len(e.host.log))
				}
				if c != nil && c.asks.Load() != 0 {
					t.Fatalf("--dry-run asked")
				}
				for _, ev := range e.log() {
					if strings.HasPrefix(ev, "rest:") {
						t.Fatalf("--dry-run ran the verdict: %s", ev)
					}
				}
				if d, _ := r.boolean("dry_run"); !d || r.m["ready"] != nil || r.m["planned"] == nil {
					t.Fatalf("report: %s", r.stdout)
				}
			})
		}
	}
	// control: the same fixture without --dry-run does reach REST.
	setNoTTY(t)
	e := newFlowEnv(t)
	wantExit(t, e.run("--yes"), 0)
	if first, _ := e.idx(isVerdictRead); first < 0 {
		t.Fatal("control: a real run made no verdict read: the zero above measured nothing")
	}
}

// ---- AC7 / AC8 / AC9: the verdict ----

func TestEnableFlow_T8_VerdictAfterTheWrite_StateCoupled(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	// the coupled fake: before the write doctor itself says not ready
	pre := doctorOn(t, e)
	if got := doctorRowVerdict(t, pre, "Sys.Audit on /nodes/"+flowTarget); got != "missing" {
		t.Fatalf("pre-write doctor says the node row is %q, want missing (the fake must be state-coupled; exit 4 alone proves nothing, the VM rows are not checked either way): %s", got, pre.stdout)
	}
	e.mu.Lock()
	e.events = nil
	e.mu.Unlock()
	r := e.run("--yes")
	wantExit(t, r, 0)
	if ready, ok := r.boolean("ready"); !ok || !ready {
		t.Fatalf("ready after the write: %s", r.stdout)
	}
	if !strings.Contains(r.str("verdict"), "privileges are ready on "+flowTarget) {
		t.Errorf("verdict %q", r.str("verdict"))
	}
	_, lastWrite := e.idx(isSSHWrite)
	firstRead, _ := e.idx(isVerdictRead)
	if lastWrite < 0 || firstRead < 0 || firstRead < lastWrite {
		t.Fatalf("verdict read at %d, last write at %d: the verdict must come after the last write\n%q", firstRead, lastWrite, e.log())
	}
	if b, _ := r.boolean("wrote"); !b {
		t.Errorf("wrote not true")
	}
	if !strings.Contains(r.str("after_rule"), "--grant /:ForgeVMAdminAudit::1") || !strings.Contains(r.str("after_rule"), "REVOKES") {
		t.Errorf("after_rule %q", r.str("after_rule"))
	}
	if r.str("scope") != "node" {
		t.Errorf("scope %q", r.str("scope"))
	}
	// doctor agrees now
	post := doctorOn(t, e)
	if got := doctorRowVerdict(t, post, "Sys.Audit on /nodes/"+flowTarget); got != "held" {
		t.Fatalf("post-write doctor says the node row is %q, want held: %s", got, post.stdout)
	}
	if got := doctorRowVerdict(t, post, "Sys.Audit on /"); got != "held" {
		t.Fatalf("post-write doctor says the cluster row is %q, want held: %s", got, post.stdout)
	}
}

func doctorOn(t *testing.T, e *flowEnv, args ...string) flowRes {
	t.Helper()
	full := append([]string{"doctor", "--roster", e.roster, "-o", "json"}, args...)
	full = append(full, flowTarget)
	code, out, errOut := runRootArgs(full...)
	r := flowRes{code: code, stdout: out, stderr: errOut}
	if strings.TrimSpace(out) != "" {
		if err := json.Unmarshal([]byte(out), &r.m); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func doctorRowVerdict(t *testing.T, r flowRes, requirement string) string {
	t.Helper()
	rows, _ := r.m["rows"].([]any)
	for _, x := range rows {
		row, _ := x.(map[string]any)
		if row["requirement"] == requirement {
			v, _ := row["verdict"].(string)
			return v
		}
	}
	t.Fatalf("no row %q in %s", requirement, r.stdout)
	return ""
}

func TestEnableFlow_T8b_AlreadyEnabledRunsTheVerdict(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	e.preEnable()
	r := e.run()
	wantExit(t, r, 0)
	if ready, ok := r.boolean("ready"); !ok || !ready || r.str("verdict") == "" {
		t.Fatalf("already enabled, no verdict: %s", r.stdout)
	}
	if b, _ := r.boolean("wrote"); b {
		t.Errorf("wrote=true with nothing written")
	}
}

func TestEnableFlow_T9_WrittenButNotReady(t *testing.T) {
	type tc struct {
		name  string
		setup func(e *flowEnv)
		want  string // text the verdict must name
	}
	cases := []tc{
		{"/nodes override: status 403", func(e *flowEnv) { e.statusCode = 403 }, "Sys.Audit on /nodes/" + flowTarget},
		{"member list 403", func(e *flowEnv) { e.clusterCode = 403 }, "missing: Sys.Audit on /"},
		{"member list 500", func(e *flowEnv) { e.clusterCode = 500 }, "unknown: Sys.Audit on /"},
		{"member list incomplete", func(e *flowEnv) { e.clusterBody = `{"data":[]}` }, "unknown: Sys.Audit on /"},
		{"status 500", func(e *flowEnv) { e.statusCode = 500 }, "unknown: Sys.Audit on /nodes/" + flowTarget},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setNoTTY(t)
			e := newFlowEnv(t)
			c.setup(e)
			r := e.run("--yes")
			wantExit(t, r, 1)
			if len(e.sshWrites()) != 2 {
				t.Fatalf("the write did not happen (%q): the scenario is wrong", e.sshWrites())
			}
			if b, _ := r.boolean("wrote"); !b {
				t.Errorf("wrote not true")
			}
			if ready, ok := r.boolean("ready"); !ok || ready {
				t.Fatalf("ready after a not-ready verdict: %s", r.stdout)
			}
			v := r.str("verdict")
			if !strings.Contains(v, c.want) || !strings.Contains(v, "are not ready") || strings.Contains(v, "privileges are ready") {
				t.Errorf("verdict %q lacks %q", v, c.want)
			}
			if strings.Contains(r.stdout, "privileges are ready") {
				t.Errorf("the output says ready beside a not-ready verdict:\n%s", r.stdout)
			}
			// the token IS changed, so the after-rule is still printed
			if r.str("after_rule") == "" {
				t.Errorf("no after_rule after a write")
			}
			if !strings.Contains(r.stderr, "the grant was written") {
				t.Errorf("stderr %q", r.stderr)
			}
			if len(r.m["rows"].([]any)) == 0 {
				t.Errorf("no rows")
			}
		})
	}
}

// With nothing written and a not-ready verdict, the exit is 1 and the text
// says nothing was written.
func TestEnableFlow_T9b_AlreadyEnabledButNotReady(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	e.preEnable()
	e.statusCode = 403
	r := e.run()
	wantExit(t, r, 1)
	if b, _ := r.boolean("wrote"); b || !strings.Contains(r.stderr, "nothing was written") {
		t.Fatalf("wrote %v, stderr %q", b, r.stderr)
	}
}

// --vmid reaches the verdict: the VM rows are checked, and a missing VM
// privilege makes it not ready; without --vmid they are only not checked.
func TestEnableFlow_T9c_VMIDPassesThrough(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	e.preEnable()
	e.vmPrivs = []string{"VM.PowerMgmt"} // no VM.Allocate
	r := e.run("--vmid", "691")
	wantExit(t, r, 1)
	if !strings.Contains(r.str("verdict"), "missing: VM.Allocate on /vms/691") || r.str("scope") != "node+vm" {
		t.Fatalf("verdict %q scope %q", r.str("verdict"), r.str("scope"))
	}
	// without --vmid the same fixture is node-ready, VM rows not checked
	r = e.run()
	wantExit(t, r, 0)
	if !strings.Contains(r.str("verdict"), "not checked") {
		t.Errorf("verdict %q", r.str("verdict"))
	}
	if code, _, _ := runRootArgs("acl", "enable-vm-destroy", "--roster", e.roster, "--vmid", "0691", flowTarget); code == 0 {
		t.Errorf("a non-canonical --vmid was accepted")
	}
}

// The role-only and no-verdict cases: no `ready` key, and the next step.
func TestEnableFlow_T9d_RoleOnlyRunsNoVerdict(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	r := e.run("--role-only", "--yes")
	wantExit(t, r, 0)
	if r.m["ready"] != nil || r.m["verdict"] != nil || r.m["after_rule"] != nil {
		t.Fatalf("role-only claimed a verdict: %s", r.stdout)
	}
	if !strings.Contains(r.str("next"), "pveforge bootstrap "+flowTarget+" --grant /:ForgeVMAdminAudit::1") {
		t.Errorf("next %q", r.str("next"))
	}
	for _, ev := range e.log() {
		if strings.HasPrefix(ev, "rest:") {
			t.Fatalf("role-only read REST: %s", ev)
		}
	}
}

// ---- AC10: the after-rule names the role in use ----

func TestEnableFlow_T13_AfterRuleNamesTheRealRole(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	r := e.run("--yes", "--role", "ForgeCustomRole")
	wantExit(t, r, 0)
	ar := r.str("after_rule")
	if !strings.Contains(ar, "--grant /:ForgeCustomRole::1") || strings.Contains(ar, "ForgeVMAdminAudit") || !strings.Contains(ar, "bootstrap "+flowTarget) {
		t.Fatalf("after_rule %q", ar)
	}
	// never on a path that changed nothing about the token
	for name, args := range map[string][]string{"dry-run": {"--dry-run"}} {
		e2 := newFlowEnv(t)
		r2 := e2.run(args...)
		if r2.m["after_rule"] != nil {
			t.Errorf("%s printed an after_rule", name)
		}
	}
	setNoTTY(t)
	e3 := newFlowEnv(t)
	if r3 := e3.run(); r3.m["after_rule"] != nil || r3.code != 4 {
		t.Errorf("a refusal printed an after_rule: %s", r3.stdout)
	}
}

// ---- AC12: one bounded render ----

// The pre-prompt block, through the REAL terminal path, is valid kv and valid
// json with one bounded line per key (F4).
func TestEnableFlow_PrePromptPlanIsValidKV(t *testing.T) {
	for _, format := range []string{"kv", "json"} {
		t.Run(format, func(t *testing.T) {
			setTTY(t, "n\n")
			e := newFlowEnv(t)
			code, _, errOut := runRootArgs("acl", "enable-vm-destroy", "--roster", e.roster, "-o", format, flowTarget)
			if code != 4 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			block := errOut[:strings.Index(errOut, confirmPrompt)]
			if format == "json" {
				var m map[string]any
				if err := json.Unmarshal([]byte(block), &m); err != nil || m["outcome"] != "plan" {
					t.Fatalf("pre-prompt block is not one JSON object: %v\n%s", err, block)
				}
				return
			}
			keys := map[string]bool{}
			for _, line := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
				k, _, ok := strings.Cut(line, "=")
				if !ok || k == "" || keys[k] || len(line) > 4096 {
					t.Fatalf("bad kv line %q (dup %v)", line, keys[k])
				}
				keys[k] = true
			}
			for _, want := range []string{"target", "role", "outcome", "planned", "privileges"} {
				if !keys[want] {
					t.Errorf("block lacks key %s: %q", want, block)
				}
			}
		})
	}
}

// Hostile text in every string of the report: one line per key in kv, valid
// JSON in json, each bounded. Rendered through the verb's own renderer, both
// as the stdout report and as the stderr plan block.
func TestEnableFlow_T11_HostileStringsStayOneLinePerKey(t *testing.T) {
	hostile := "x\nready=true privileges=[]\x85y=\"z"
	rep := func() enableReport {
		yes := true
		r := enableReport{
			Target: hostile, Role: hostile, Privileges: []string{hostile}, Outcome: hostile, Token: hostile,
			Widened: []string{hostile}, Planned: []string{hostile}, Notes: []string{hostile}, Ready: &yes,
			Scope: hostile, Verdict: hostile + strings.Repeat("A", 6000), AfterRule: hostile, Next: hostile,
			Rows: []doctorRow{{Requirement: hostile, Path: hostile, Verdict: hostile, Hint: hostile, Detail: hostile}},
		}
		r.bound()
		return r
	}
	var kv, js bytes.Buffer
	if err := kvjson.Render(&kv, kvjson.KV, rep()); err != nil {
		t.Fatal(err)
	}
	if err := kvjson.Render(&js, kvjson.JSON, rep()); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(kv.String(), "\n"), "\n")
	seen := map[string]bool{}
	for _, l := range lines {
		k, _, ok := strings.Cut(l, "=")
		if !ok || seen[k] || len(l) > 8192 {
			t.Fatalf("a field produced a second or oversized line: %q", l)
		}
		seen[k] = true
	}
	if len(lines) != 15 {
		t.Fatalf("%d lines for 15 keys:\n%s", len(lines), kv.String())
	}
	if !strings.Contains(kv.String(), `\n`) {
		t.Fatalf("vacuous: the hostile text did not reach the output:\n%s", kv.String())
	}
	var m map[string]any
	if err := json.Unmarshal(js.Bytes(), &m); err != nil {
		t.Fatalf("json: %v", err)
	}
	// and through the terminal path: a hostile plan block on stderr
	for _, format := range []kvjson.Format{kvjson.KV, kvjson.JSON} {
		setTTY(t, "n\n")
		cmd := &cobra.Command{}
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetContext(context.Background())
		f := enableFlow{format: format}
		err := f.confirm(cmd, rep())
		var rf refusedError
		if !errors.As(err, &rf) {
			t.Fatalf("declined: %v", err)
		}
		block := errOut.String()[:strings.Index(errOut.String(), confirmPrompt)]
		if format == kvjson.JSON {
			if err := json.Unmarshal([]byte(block), &m); err != nil {
				t.Fatalf("pre-prompt json: %v", err)
			}
			continue
		}
		bl := strings.Split(strings.TrimRight(block, "\n"), "\n")
		if len(bl) != 15 {
			t.Fatalf("pre-prompt kv block has %d lines for 15 keys:\n%s", len(bl), block)
		}
	}
}

// ---- AC9: the exit table, through runRoot ----

func TestEnableFlow_T12_ExitStatusTable(t *testing.T) {
	type row struct {
		name  string
		setup func(t *testing.T) (*flowEnv, []string)
		code  int
		wrote bool
	}
	rows := []row{
		{"written and ready", func(t *testing.T) (*flowEnv, []string) { setNoTTY(t); return newFlowEnv(t), []string{"--yes"} }, 0, true},
		{"declined", func(t *testing.T) (*flowEnv, []string) { setTTY(t, "n\n"); return newFlowEnv(t), nil }, 4, false},
		{"no terminal", func(t *testing.T) (*flowEnv, []string) { setNoTTY(t); return newFlowEnv(t), nil }, 4, false},
		{"written, not ready", func(t *testing.T) (*flowEnv, []string) {
			setNoTTY(t)
			e := newFlowEnv(t)
			e.statusCode = 403
			return e, []string{"--yes"}
		}, 1, true},
		{"already enabled, ready", func(t *testing.T) (*flowEnv, []string) { setNoTTY(t); e := newFlowEnv(t); e.preEnable(); return e, nil }, 0, false},
		{"role-only", func(t *testing.T) (*flowEnv, []string) {
			setNoTTY(t)
			return newFlowEnv(t), []string{"--role-only", "--yes"}
		}, 0, true},
		{"dry-run", func(t *testing.T) (*flowEnv, []string) { setNoTTY(t); return newFlowEnv(t), []string{"--dry-run"} }, 0, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e, args := r.setup(t)
			res := e.run(args...)
			wantExit(t, res, r.code)
			if got := len(e.sshWrites()) > 0; got != r.wrote {
				t.Fatalf("writes %q, want written=%v", e.sshWrites(), r.wrote)
			}
			if b, _ := res.boolean("wrote"); b != r.wrote {
				t.Fatalf("wrote=%v in the report, want %v: %s", b, r.wrote, res.stdout)
			}
		})
	}
}

// R1: a signal at the prompt ends the wait (130/143), writes nothing, and is
// not the refusal's 4.
func TestEnableFlow_R1_SignalAtThePrompt(t *testing.T) {
	for _, tc := range []struct {
		sig  syscall.Signal
		name string
		code int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe() // an answer that never comes
			t.Cleanup(func() { _ = pw.Close() })
			c := setTTYReader(t, pr)
			e := newFlowEnv(t)
			code, _, stderr := runRootInterruptible(interruptAfter(t, tc.sig, 300*time.Millisecond),
				"acl", "enable-vm-destroy", "--roster", e.roster, flowTarget)
			if c.asks.Load() != 1 {
				t.Fatalf("the prompt was never reached (asks %d): %q", c.asks.Load(), stderr)
			}
			if code != tc.code {
				t.Fatalf("exit %d, want %d; stderr %q", code, tc.code, stderr)
			}
			if w := e.sshWrites(); len(w) != 0 {
				t.Fatalf("a signal at the prompt wrote %q", w)
			}
			if strings.Contains(stderr, "may or may not") || !strings.Contains(stderr, "confirmation prompt") {
				t.Errorf("stderr %q", stderr)
			}
		})
	}
}

// AC13: the prompt is never inside bootstrap's lock: a bootstrap-keyed lock is
// free while the question is waiting.
func TestEnableFlow_T14_PromptIsNotUnderTheLock(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	c := setTTYReader(t, pr)
	e := newFlowEnv(t)
	done := make(chan flowRes, 1)
	go func() { done <- e.run() }()
	deadline := time.Now().Add(5 * time.Second)
	for c.asks.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the prompt was never reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	unlock, err := lock.Mutation(ctx, e.roster, lock.ObjectKey{TargetID: flowTarget, Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatalf("bootstrap's lock is held while the prompt waits: %v", err)
	}
	_ = unlock()
	go func() { _, _ = io.WriteString(pw, "y\n") }() // a reader that never reads must not hang the test
	if r := <-done; r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
}

var _ = os.Stdin
var _ = bootstrap.DefaultVMDestroyRole

// ---- the verdict decision, called directly (the mutants' target) ----

func TestEnableFlow_RowsReadyTable(t *testing.T) {
	row := func(req, verdict string) doctorRow { return doctorRow{Requirement: req, Verdict: verdict} }
	node, cl := "Sys.Audit on /nodes/n1", "Sys.Audit on /"
	pow, alloc := "VM.PowerMgmt on /vms/7", "VM.Allocate on /vms/7"
	cases := []struct {
		name  string
		rows  []doctorRow
		vmid  int
		ready bool
	}{
		{"node rows held, vm rows not checked, no vmid", []doctorRow{row(node, "held"), row(cl, "held"), row(pow, "not checked"), row(alloc, "not checked")}, 0, true},
		{"all held with vmid", []doctorRow{row(node, "held"), row(cl, "held"), row(pow, "held"), row(alloc, "held")}, 7, true},
		{"node row missing", []doctorRow{row(node, "missing"), row(cl, "held"), row(pow, "not checked"), row(alloc, "not checked")}, 0, false},
		{"cluster row unknown", []doctorRow{row(node, "held"), row(cl, "unknown"), row(pow, "not checked"), row(alloc, "not checked")}, 0, false},
		{"vm row missing with vmid", []doctorRow{row(node, "held"), row(cl, "held"), row(pow, "held"), row(alloc, "missing")}, 7, false},
		{"vm row unknown with vmid", []doctorRow{row(node, "held"), row(cl, "held"), row(pow, "unknown"), row(alloc, "held")}, 7, false},
		{"a verdict word nobody knows is never held", []doctorRow{row(node, "held"), row(cl, "garbage"), row(pow, "not checked"), row(alloc, "not checked")}, 0, false},
		{"a row not checked although a vmid was named", []doctorRow{row(node, "held"), row(cl, "held"), row(pow, "not checked"), row(alloc, "held")}, 7, false},
	}
	for _, c := range cases {
		rep := doctorReport{Verb: "vm destroy", Node: "n1", Rows: c.rows}
		ready, line := decideVerdict(rep, c.vmid, "")
		if ready != c.ready {
			t.Errorf("%s: decideVerdict ready = %v, want %v", c.name, ready, c.ready)
		}
		if says := strings.Contains(line, "privileges are ready"); says != ready {
			t.Errorf("%s: verdict line %q disagrees with ready=%v", c.name, line, ready)
		}
	}
}

// ---- docs: the flow is REQUIRED in the documents (a dropped sentence is red) ----

func TestEnableFlow_T15_DocsDescribeTheFlow(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(b)), " ")
	}
	readme, prd, guide := read("../../README.md"), read("../../docs/prd.md"), read("../../docs/operations/secrets-and-keys.md")
	for name, want := range map[string][]string{
		"README": {"`Proceed? [y/N]`", "`--yes`", "no terminal", "carries `ready` and `verdict`", "the check did not run", "no confirmed-plan comparison", "not that every VM can be destroyed", "`acl enable-vm-destroy` also exits 1", "names this command as its `fix`", "`doctor` exits 4 when any privilege is missing"},
		"PRD":    {"`acl enable-vm-destroy` exits 1, not 4", "`ErrPlanChangedSinceConfirm`", "never across its confirmation prompt", "`doctorVerdict`"},
		"guide":  {"Run one command", "`Proceed? [y/N]`", "Manual fallback", "`--yes` answers the question", "The report carries `ready` and `verdict`", "the check did not run", "no confirmed-plan comparison under `--yes`", "not that every VM can be destroyed"},
	} {
		doc := map[string]string{"README": readme, "PRD": prd, "guide": guide}[name]
		for _, w := range want {
			if !strings.Contains(doc, w) {
				t.Errorf("%s lacks %q", name, w)
			}
		}
	}
	for name, doc := range map[string]string{"README": readme, "guide": guide} {
		if strings.Contains(doc, "report ends in `ready`") || strings.Contains(doc, "ends with the same check") {
			t.Errorf("%s still says the report ends in ready (kv output is key-sorted: it carries ready and verdict)", name)
		}
	}
	// the procedure no longer teaches the five-step sequence
	if strings.Contains(guide, "enable-vm-destroy qa-pve-07 --roster ./pveforge.toml --dry-run\n") {
		t.Error("the guide still lists the dry-run/real/role-only sequence")
	}
}
