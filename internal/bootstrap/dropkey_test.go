package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Operator ruling T2k (2026-09-26): a run that installed its own fresh key
// and failed before the roster held it removes exactly that key again;
// nothing else, and nothing on success.

// removeScriptPrefix is how RemoveAuthorizedKeyScript begins.
var removeScriptPrefix = strings.SplitN(sshexec.RemoveAuthorizedKeyScript("x"), "\nsnap=", 2)[0]

// removals is every removal script the session ran.
func removals(s *fakeSession) []string {
	var out []string
	for _, c := range s.commands {
		if strings.HasPrefix(c, removeScriptPrefix) {
			out = append(out, c)
		}
	}
	return out
}

// answerRemoval makes the session answer the removal script as the node
// would when the line was there once.
func answerRemoval(s *fakeSession, r fakeRunResult) {
	if s.byCmd == nil {
		s.byCmd = map[string]fakeRunResult{}
	}
	s.byCmd[removeScriptPrefix] = r
}

var removedOK = fakeRunResult{res: RunResult{Stdout: "removed\n"}}

// requireRemovedExactly: the session ran exactly one removal, and it is the
// script for the one line this run installed.
func requireRemovedExactly(t *testing.T, s *fakeSession, tr *fakeTransport) {
	t.Helper()
	if len(tr.installedKeyLines) != 1 {
		t.Fatalf("installed %d key(s), want 1", len(tr.installedKeyLines))
	}
	got := removals(s)
	if len(got) != 1 || got[0] != sshexec.RemoveAuthorizedKeyScript(tr.installedKeyLines[0]) {
		t.Fatalf("removals %q, want exactly the script for the installed line %q", got, tr.installedKeyLines[0])
	}
}

// Each failure between the install and the roster write removes exactly
// the installed key, keeps the original error, and says the key was removed.
func TestRun_FailedFirstRunRemovesItsOwnKey(t *testing.T) {
	t.Run("capture fails", func(t *testing.T) {
		_, opts := bareTarget(t)
		opts.HostKeyFingerprint = testHostKey
		session := &fakeSession{byCmd: map[string]fakeRunResult{captureCmdPrefix: {res: RunResult{ExitCode: 1}}}}
		answerRemoval(session, removedOK)
		tr := &fakeTransport{session: session}
		_, err := Run(context.Background(), opts, tr, &fakeValidator{})
		if !errors.Is(err, ErrTLSCapture) || !strings.Contains(err.Error(), "was removed from root's authorized_keys again") {
			t.Fatalf("err = %v", err)
		}
		requireRemovedExactly(t, session, tr)
	})
	t.Run("the address serves another key", func(t *testing.T) {
		_, opts := bareTarget(t)
		opts.HostKeyFingerprint = testHostKey
		session, v := &fakeSession{}, &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		v.served = newCapturePair(t).pin
		answerRemoval(session, removedOK)
		tr := &fakeTransport{session: session}
		_, err := Run(context.Background(), opts, tr, v)
		if !errors.Is(err, ErrTLSPinMismatch) || !strings.Contains(err.Error(), "removed from root's authorized_keys again") {
			t.Fatalf("err = %v", err)
		}
		requireRemovedExactly(t, session, tr)
	})
	t.Run("the roster write fails", func(t *testing.T) {
		_, opts := bareTarget(t)
		opts.HostKeyFingerprint = testHostKey
		session, v := &fakeSession{}, &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		answerRemoval(session, removedOK)
		orig := writeSSHAuthFn
		t.Cleanup(func() { writeSSHAuthFn = orig })
		writeSSHAuthFn = func(string, string, roster.SSHWrite, roster.Passphrase) error { return errors.New("disk full") }
		tr := &fakeTransport{session: session}
		_, err := Run(context.Background(), opts, tr, v)
		if err == nil || !strings.Contains(err.Error(), "persist ssh auth: disk full") || !strings.Contains(err.Error(), "removed from root's authorized_keys again") {
			t.Fatalf("err = %v", err)
		}
		requireRemovedExactly(t, session, tr)
	})
	t.Run("a reprovision's roster write loses its compare-and-set", func(t *testing.T) {
		old := newCapturePair(t)
		rosterPath, opts := rebuiltKeyful(t, old)
		cp := newCapturePair(t)
		session, v := rebuiltNode(cp)
		answerRemoval(session, removedOK)
		// Another writer re-pins the SSH key while this run captures.
		r := session.byCmd[captureCmdPrefix]
		r.onRun = func(context.Context, string) {
			if err := roster.ReplaceSSHAuth(rosterPath, opts.TargetID, testHostKey, roster.SSHWrite{User: "root", PublicKey: "ssh-ed25519 AAAAother pveforge@x", HostKeyFingerprint: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", PrivateKeyPlaintext: []byte("k"), HostKeySource: "ssh-verified"}, opts.Passphrase); err != nil {
				t.Errorf("the concurrent writer: %v", err)
			}
		}
		session.byCmd[captureCmdPrefix] = r
		tr := &fakeTransport{session: session}
		_, err := Run(context.Background(), opts, tr, v)
		if !errors.Is(err, roster.ErrSSHPinChanged) || !strings.Contains(err.Error(), "removed from root's authorized_keys again") {
			t.Fatalf("err = %v", err)
		}
		requireRemovedExactly(t, session, tr)
	})
}

// A run that succeeds, or fails only after the roster holds its key, never
// removes anything: from the roster write on, the key is the target's.
func TestRun_KeyTheRosterHoldsIsNeverRemoved(t *testing.T) {
	_, opts := bareTarget(t)
	opts.HostKeyFingerprint = testHostKey
	session, v := &fakeSession{}, &fakeValidator{}
	scriptCapture(session, v, newCapturePair(t))
	answerRemoval(session, removedOK)
	if _, err := Run(context.Background(), opts, &fakeTransport{session: session}, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := removals(session); len(got) != 0 {
		t.Fatalf("a successful run removed %q", got)
	}

	// A preflight failure (an unknown role), after the SSH auth is stored.
	rosterPath2, opts2 := bareTarget(t)
	opts2.HostKeyFingerprint = testHostKey
	session2, v2 := &fakeSession{}, &fakeValidator{}
	scriptCapture(session2, v2, newCapturePair(t))
	answerRemoval(session2, removedOK)
	session2.byCmd["pveum role list"] = fakeRunResult{res: RunResult{Stdout: "[]"}}
	_, err := Run(context.Background(), opts2, &fakeTransport{session: session2}, v2)
	if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("err = %v, want the preflight's ErrUnknownRole: the test is not reaching the phase after the roster write", err)
	}
	if ssh := sshBlock(t, rosterPath2, opts2.TargetID); ssh == nil || ssh.PublicKey == "" {
		t.Fatal("the roster does not hold the key: the failure was not after the roster write")
	}
	if got := removals(session2); len(got) != 0 {
		t.Fatalf("a run that failed after the roster held its key removed %q (err %v)", got, err)
	}
}

// When the removal cannot be made or is refused, the error keeps the cause
// and gives the exact manual removal command for the installed line.
func TestRun_KeyThatCouldNotBeRemovedIsReported(t *testing.T) {
	for name, answer := range map[string]fakeRunResult{
		"refused (not exactly once)": {res: RunResult{ExitCode: sshexec.RemoveKeyExitNotExactlyOne, Stdout: "found 0\n"}},
		"file changed meanwhile":     {res: RunResult{ExitCode: sshexec.RemoveKeyExitChanged, Stdout: "changed\n"}},
		"the session failed":         {err: errors.New("connection reset")},
		"no confirmation printed":    {res: RunResult{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, opts := bareTarget(t)
			opts.HostKeyFingerprint = testHostKey
			session := &fakeSession{byCmd: map[string]fakeRunResult{captureCmdPrefix: {res: RunResult{ExitCode: 1}}}}
			answerRemoval(session, answer)
			tr := &fakeTransport{session: session}
			_, err := Run(context.Background(), opts, tr, &fakeValidator{})
			if !errors.Is(err, ErrTLSCapture) || !strings.Contains(err.Error(), "may still be in root's authorized_keys") ||
				!strings.Contains(err.Error(), sshexec.ManualKeyRemovalCommand(tr.installedKeyLines[0])) {
				t.Fatalf("err = %v; want the cause, the leftover, and the manual command for the installed line", err)
			}
		})
	}
}

// When the key dial itself fails there is no session to remove the key
// over: the error gives the manual command, and nothing was run.
func TestRun_KeyDialFailureReportsTheKey(t *testing.T) {
	_, opts := bareTarget(t)
	opts.HostKeyFingerprint = testHostKey
	session := &fakeSession{}
	tr := &fakeTransport{session: session, dialErr: errors.New("permission denied (publickey)")}
	_, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if err == nil || !strings.Contains(err.Error(), "connect with fresh key") || !strings.Contains(err.Error(), sshexec.ManualKeyRemovalCommand(tr.installedKeyLines[0])) {
		t.Fatalf("err = %v", err)
	}
	if len(session.commands) != 0 {
		t.Fatalf("commands ran without a session: %q", session.commands)
	}
}
