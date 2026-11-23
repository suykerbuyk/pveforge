package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Fix round 1 of the operator flow (Chair rulings G1, G2, I1, I2, I3, I4).

// G1: an unread verdict is never ready. Two arms: the node read lock cannot be
// taken (driven through the real CLI: the write happens, then the verdict
// cannot be read), and there is no token client (driven through finish).
func TestEnableFlow_G1_UnreadVerdictIsNeverReady_LockArm(t *testing.T) {
	for _, preEnabled := range []bool{false, true} {
		name := map[bool]string{false: "written", true: "already enabled"}[preEnabled]
		t.Run(name, func(t *testing.T) {
			setNoTTY(t)
			e := newFlowEnv(t)
			if preEnabled {
				e.preEnable()
			}
			// the verdict's own lock is held by someone else
			holdLock(t, e.roster, lock.ObjectKey{TargetID: flowTarget, Kind: "node", ID: flowTarget})
			r := e.run("--yes", "--lock-wait", "300ms")
			wantExit(t, r, 1)
			wrote := !preEnabled
			if got := len(e.sshWrites()) > 0; got != wrote {
				t.Fatalf("writes %q, want written=%v: the scenario is wrong", e.sshWrites(), wrote)
			}
			if b, _ := r.boolean("wrote"); b != wrote {
				t.Errorf("wrote=%v, want %v", b, wrote)
			}
			if ready, ok := r.boolean("ready"); !ok || ready {
				t.Fatalf("ready after an unread verdict: %s", r.stdout)
			}
			if v := r.str("verdict"); strings.Contains(v, "privileges are ready") || !strings.Contains(v, "the check did not run") {
				t.Errorf("verdict %q", v)
			}
			if !strings.Contains(r.stderr, "the verdict could not be read") {
				t.Errorf("stderr %q", r.stderr)
			}
			// the control: the same run with the lock free reads the verdict
			e2 := newFlowEnv(t)
			if preEnabled {
				e2.preEnable()
			}
			if r2 := e2.run("--yes"); r2.code != 0 || r2.m["ready"] != true {
				t.Fatalf("control: exit %d: %s", r2.code, r2.stdout)
			}
		})
	}
}

func TestEnableFlow_G1_UnreadVerdictIsNeverReady_NoClientArm(t *testing.T) {
	for _, tc := range []struct {
		outcome string
		wrote   bool
	}{{bootstrap.EnableUpgraded, true}, {bootstrap.EnableAlreadyEnabled, false}} {
		t.Run(tc.outcome, func(t *testing.T) {
			cmd := &cobra.Command{}
			var out, errOut bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errOut)
			cmd.SetContext(context.Background())
			f := enableFlow{format: kvjson.JSON, target: flowTarget, rest: nil}
			err := f.finish(cmd, &bootstrap.EnableVMDestroyResult{Role: "ForgeVMAdminAudit", Outcome: tc.outcome, Privileges: []string{"Sys.Audit"}, TokenID: "root@pam!pveforge"})
			var rf refusedError
			var ou outcomeUnknownError
			if err == nil || errors.As(err, &rf) || errors.As(err, &ou) {
				t.Fatalf("want a plain error (exit 1), got %v", err)
			}
			var m map[string]any
			if e := json.Unmarshal(out.Bytes(), &m); e != nil {
				t.Fatalf("report: %v\n%s", e, out.String())
			}
			r := flowRes{stdout: out.String(), m: m}
			assertReadyIsTheSentence(t, r)
			if ready, ok := r.boolean("ready"); !ok || ready || strings.Contains(r.str("verdict"), "privileges are ready") {
				t.Fatalf("ready after no client: %s", out.String())
			}
			if b, _ := r.boolean("wrote"); b != tc.wrote {
				t.Errorf("wrote=%v, want %v", b, tc.wrote)
			}
		})
	}
}

// G2: the single decision, called directly with the unread reason: never
// ready, and the sentence never says ready.
func TestEnableFlow_G2_DecideVerdictUnreadIsNeverReady(t *testing.T) {
	allHeld := doctorReport{Verb: "vm destroy", Node: "n1", Rows: []doctorRow{{Requirement: "Sys.Audit on /", Verdict: "held"}}}
	for _, unread := range []string{"no token client", "the verdict read failed"} {
		ready, line := decideVerdict(allHeld, 0, unread)
		if ready || strings.Contains(line, "privileges are ready") || !strings.Contains(line, unread) {
			t.Errorf("unread %q: ready=%v line %q", unread, ready, line)
		}
	}
	// and the read verdict of the same rows is ready: the arm is the only difference
	if ready, _ := decideVerdict(allHeld, 0, ""); !ready {
		t.Error("control: all rows held is not ready")
	}
}

// I1: through runRoot on the TTY path, the cluster changes between the dry
// pass and the real pass (a root editor creates the role with the same set
// while the question is on screen): the run refuses with the plan-changed
// error and writes nothing.
func TestEnableFlow_I1_PlanChangedBetweenThePasses_Refuses(t *testing.T) {
	run := func(mutate bool) (flowRes, *flowEnv, bool) {
		setTTY(t, "y\n")
		e := newFlowEnv(t)
		fired := false
		real := confirmAsk
		confirmAsk = func(ctx context.Context, in io.Reader, w io.Writer) (bool, error) {
			if mutate {
				d := append(slicesClone(enableVMAdmin), "Sys.Audit")
				e.host.mu.Lock()
				e.host.roles["ForgeVMAdminAudit"] = d
				e.host.mu.Unlock()
				fired = true
			}
			return real(ctx, in, w)
		}
		if mutate {
			// the plan-changed refusal is an error before any report
			return e.runNoReport(), e, fired
		}
		return e.run(), e, fired
	}
	r, e, fired := run(true)
	if !fired {
		t.Fatal("the between-passes hook did not fire")
	}
	if r.code == 0 || !strings.Contains(r.stderr, "the plan changed since it was confirmed") {
		t.Fatalf("exit %d, stderr %q: want the plan-changed refusal", r.code, r.stderr)
	}
	if w := e.sshWrites(); len(w) != 0 {
		t.Fatalf("a changed plan was written: %q", w)
	}
	// the twin: with no change between the passes the same run writes both
	r2, e2, _ := run(false)
	if r2.code != 0 || len(e2.sshWrites()) != 2 {
		t.Fatalf("twin: exit %d, writes %q", r2.code, e2.sshWrites())
	}
}

// I2: the grant is correct but a node path keeps no Sys.Audit (the token's own
// override row): carried as a structured field, so ready is false, a row names
// the path, and the exit is 1. The control (no override) is ready.
func TestEnableFlow_I2_AuditNotEffectiveOnANodeIsNotReady(t *testing.T) {
	setNoTTY(t)
	e := newFlowEnv(t)
	e.host.nodeOverride = true
	r := e.run("--yes")
	if len(e.sshWrites()) != 2 {
		t.Fatalf("the upgrade did not write (%q): the fixture is wrong: %s %s", e.sshWrites(), r.stdout, r.stderr)
	}
	wantExit(t, r, 1)
	if ready, ok := r.boolean("ready"); !ok || ready {
		t.Fatalf("ready beside an override row: %s", r.stdout)
	}
	if v := r.str("verdict"); !strings.Contains(v, "missing: Sys.Audit on /nodes/pve1") {
		t.Errorf("verdict %q does not name the row", v)
	}
	if got := doctorRowVerdict(t, r, "Sys.Audit on /nodes/pve1"); got != "missing" {
		t.Errorf("row verdict %q", got)
	}
	// the two REST rows were read and held: the not-ready comes from the
	// structured field alone
	if doctorRowVerdict(t, r, "Sys.Audit on /nodes/"+flowTarget) != "held" {
		t.Errorf("the roster node row should be held: %s", r.stdout)
	}
	if b, _ := r.boolean("wrote"); !b || !strings.Contains(r.stderr, "the grant was written") {
		t.Errorf("wrote=%v stderr %q", b, r.stderr)
	}
	// control
	e2 := newFlowEnv(t)
	if r2 := e2.run("--yes"); r2.code != 0 || r2.m["ready"] != true {
		t.Fatalf("control: exit %d: %s", r2.code, r2.stdout)
	}
}

// I3: the terminal decision as a pure function of the two descriptors.
func TestEnableFlow_I3_TerminalAvailableTable(t *testing.T) {
	for _, c := range []struct{ in, errOut, want bool }{
		{true, true, true}, {true, false, false}, {false, true, false}, {false, false, false},
	} {
		if got := terminalAvailable(c.in, c.errOut); got != c.want {
			t.Errorf("terminalAvailable(stdin=%v, stderr=%v) = %v, want %v", c.in, c.errOut, got, c.want)
		}
	}
	// the production seam is wired to it: on this test's pipes it is false
	if confirmTerminal() {
		t.Error("the default seam says a terminal is available under go test")
	}
}

// I4: a line that arrives together with a signal is not an answer. select picks
// at random when both are ready, so the check is repeated until a missing one
// cannot hide.
func TestEnableFlow_I4_AnswerWithACancelledContextIsInterrupted(t *testing.T) {
	for i := 0; i < 300; i++ {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(errors.New("SIGINT"))
		ok, err := askYesNo(ctx, strings.NewReader("y\n"), io.Discard)
		if ok || !errors.Is(err, roster.ErrPromptInterrupted) {
			t.Fatalf("iteration %d: ok=%v err=%v: an answer taken with the context done", i, ok, err)
		}
	}
	// The deterministic form: the context ends AFTER the line was received (the
	// writer cancels on the newline askYesNo prints once it has the line), so
	// select already took the answer's case and only the post-read check can
	// see the signal. The loop above only ever reaches the ctx.Done() case.
	ctx, cancel := context.WithCancelCause(context.Background())
	w := &cancelOnSecondWrite{cancel: func() { cancel(errors.New("SIGINT")) }}
	if ok, err := askYesNo(ctx, strings.NewReader("y\n"), w); ok || !errors.Is(err, roster.ErrPromptInterrupted) {
		t.Fatalf("a line received, then the context ended: ok=%v err=%v", ok, err)
	}
	if !w.fired {
		t.Fatal("the cancelling writer never fired: the case measured nothing")
	}
	// control: with a live context the same input is an affirmative answer
	if ok, err := askYesNo(context.Background(), strings.NewReader("y\n"), io.Discard); !ok || err != nil {
		t.Fatalf("control: ok=%v err=%v", ok, err)
	}
	_ = time.Second
}

// cancelOnSecondWrite cancels on its second Write: the first is the prompt, the
// second the newline askYesNo prints after it has the line.
type cancelOnSecondWrite struct {
	n      int
	fired  bool
	cancel func()
}

func (c *cancelOnSecondWrite) Write(p []byte) (int, error) {
	c.n++
	if c.n == 2 {
		c.fired = true
		c.cancel()
	}
	return len(p), nil
}
