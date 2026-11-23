package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// exec writes nothing before the handover: its gate stays closed for the whole
// run, so every refusal before the handover is exit 4 with all three logs
// empty, and the execve failure (the token was NOT handed over) is exit 1, not
// a refusal. After a successful handover the exit status is the CHILD's own and
// is never classified (named state child_status).
func inProcessExec(t *testing.T) (execFixture, writeEnv) {
	t.Helper()
	f := newExecFixture(t)
	t.Setenv("PVEFORGE_ROSTER", f.roster)
	t.Setenv(roster.PassphraseEnvVar, execPassphrase)
	origHarden, origExecve := execHarden, execve
	execHarden = func() error { return nil }
	t.Cleanup(func() { execHarden, execve = origHarden, origExecve })
	return f, writeEnv{roster: f.roster, restWrites: noLog, sshWrites: noLog}
}

func TestS5Exec_RefusalsBeforeHandoverAre4_ExecveFailureIs1(t *testing.T) {
	handedOver := false
	f, env := inProcessExec(t)
	_ = f
	execve = func(string, []string, []string) error { handedOver = true; return errors.New("exec format error") }
	bin := os.Args[0]
	for _, tc := range []struct{ name, target, has string }{
		{"target not exported", "qa-noexp", "is not marked export"},
		{"target holds no token", "qa-notoken", "holds no API token"},
		{"unknown target", "qa-nope", "not found in roster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := env.observe(t, "exec", tc.target, "--", bin, "x")
			o.wantRefusedBeforeAnyWrite(t)
			if !strings.Contains(o.stderr, tc.has) || handedOver {
				t.Fatalf("stderr %q handedOver %v", o.stderr, handedOver)
			}
		})
	}
	t.Run("command not found", func(t *testing.T) {
		env.observe(t, "exec", "qa-exp", "--", "pveforge-no-such-command-xyz").wantRefusedBeforeAnyWrite(t)
	})
	t.Run("execve fails: the token was not handed over: 1, never 4", func(t *testing.T) {
		o := env.observe(t, "exec", "qa-exp", "--", bin, "x")
		if o.code != 1 || o.wrote() || !handedOver || !strings.Contains(o.stderr, "the token was not handed over") {
			t.Fatalf("exit %d wrote=%v handedOver=%v stderr %q; want 1, nothing written, the failing execve reached", o.code, o.wrote(), handedOver, o.stderr)
		}
	})
}

// child_status (AC-W9): after the handover the exit status is the child's. A
// child that exits 3 or 4 is NOT a pveforge outcome-unknown or refusal: the
// process (run for real, execve and all) exits with exactly that status and
// the child ran.
func TestS5Exec_ChildStatusIsTheChildsOwn(t *testing.T) {
	for _, code := range []string{"0", "3", "4", "7"} {
		t.Run("child exits "+code, func(t *testing.T) {
			f := newExecFixture(t)
			r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "exit:"+code)...)
			if r.record == nil {
				t.Fatalf("the child never ran: stderr %q", r.stderr)
			}
			if got := r.state.ExitCode(); got != atoiS5(t, code) {
				t.Fatalf("exit %d, want the child's own %s", got, code)
			}
		})
	}
}

func atoiS5(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
