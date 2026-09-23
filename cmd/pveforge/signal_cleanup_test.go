package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// interruptingSession is a scripted pveum session. Like a real SSH session
// it refuses a command whose context has already ended — so a cleanup run
// on the command's cancelled context would never reach it. When the grant
// (pveum acl modify) arrives, it interrupts the root context, as SIGINT
// would mid-mint, and fails that command with the context's error.
type interruptingSession struct {
	interrupt func()

	mu      sync.Mutex
	ran     []string // commands executed, in order
	refused []string // commands refused because their context had ended
}

func (s *interruptingSession) Run(ctx context.Context, cmd string) (bootstrap.RunResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		s.refused = append(s.refused, cmd)
		return bootstrap.RunResult{}, err
	}
	s.ran = append(s.ran, cmd)
	switch {
	case strings.HasPrefix(cmd, "pveum role list"):
		return bootstrap.RunResult{Stdout: `[{"roleid":"PVEAuditor","privs":"Sys.Audit,VM.Audit"}]`}, nil
	case strings.HasPrefix(cmd, "pvesh get /nodes"):
		return bootstrap.RunResult{Stdout: `[{"node":"n"}]`}, nil
	case strings.HasPrefix(cmd, "pveum user token list"):
		return bootstrap.RunResult{Stdout: `[]`}, nil
	case strings.HasPrefix(cmd, "pveum user token add"):
		return bootstrap.RunResult{Stdout: `{"full-tokenid":"root@pam!pveforge","value":"fresh-secret"}`}, nil
	case strings.HasPrefix(cmd, "pveum acl modify"):
		s.interrupt()
		<-ctx.Done()
		return bootstrap.RunResult{}, ctx.Err()
	case strings.HasPrefix(cmd, "pveum user token remove"):
		return bootstrap.RunResult{}, nil
	}
	return bootstrap.RunResult{ExitCode: 127, Stderr: "unexpected command"}, nil
}

func (s *interruptingSession) Close() error { return nil }

func (s *interruptingSession) snapshot() (ran, refused []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ran...), append([]string(nil), s.refused...)
}

// sessionTransport hands out one scripted session over the keyless path.
type sessionTransport struct {
	fakeBootstrapTransport
	session bootstrap.SSHSession
}

func (t *sessionTransport) DialWithPassword(context.Context, string, string, string, string) (bootstrap.SSHSession, string, error) {
	return t.session, "SHA256:fake-host-key", nil
}

// TestInterrupt_BootstrapCleanupRunsAfterTheFirstSignal (RB1): a SIGINT in
// the middle of a mint — after the token was created, while it is being
// granted — does not strand the fresh token. Through the whole CLI (root
// context, runRoot), bootstrap's detached cleanup (removeFresh on its own
// context.WithoutCancel budget) still removes it, and the run exits 130
// with the grant's failure inside the interrupted frame.
func TestInterrupt_BootstrapCleanupRunsAfterTheFirstSignal(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	session := &interruptingSession{interrupt: func() { cancel(interruptError{sig: syscall.SIGINT}) }}
	tr := &sessionTransport{session: session}

	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { return tr }
	newBootstrapValidator = func() bootstrap.APIValidator { return nopValidator{} }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	rosterPath := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(rosterPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVEFORGE_ROSTER", rosterPath)
	t.Setenv("PVEFORGE_ROSTER_PASSPHRASE", "test-roster-pass")
	t.Setenv(pvePasswordEnvVar, "test-pve-pass")

	code, stdout, stderr := runRootInterruptible(ctx, "bootstrap", "qa-test", "--host", "h", "--node", "n",
		"--no-ssh-key", "--grant", "/:PVEAuditor")
	if code != 130 {
		t.Fatalf("exit %d, want 130; stdout %q; stderr %q", code, stdout, stderr)
	}

	ran, refused := session.snapshot()
	const remove = "pveum user token remove 'root@pam' 'pveforge'"
	if len(ran) == 0 || ran[len(ran)-1] != remove {
		t.Fatalf("the fresh token was not removed after the interrupt: ran %q, refused %q", ran, refused)
	}
	if len(refused) != 0 {
		t.Errorf("commands were sent on the cancelled context and refused: %q", refused)
	}
	if !strings.Contains(stdout, "token_outcome=discarded") || strings.Contains(stdout, "leftover_token") {
		t.Errorf("stdout %q: want the token reported discarded, and no leftover", stdout)
	}
	if !errors.Is(context.Cause(ctx), interruptError{sig: syscall.SIGINT}) {
		t.Fatalf("the root context was not interrupted: %v", context.Cause(ctx))
	}
	last := stderr[strings.LastIndex(strings.TrimSuffix(stderr, "\n"), "\n")+1:]
	if !strings.HasPrefix(last, "interrupted (SIGINT): ") || !strings.Contains(last, "grant acl") ||
		!strings.Contains(last, "may or may not have been applied") {
		t.Errorf("final stderr line %q: want the grant's failure inside the interrupted frame", last)
	}
}

// TestInterrupt_NetworkRevertRunsAfterTheFirstSignal (RB1, the network
// variant): a SIGINT that lands after `network bridge create` has staged its
// change and before it commits does not leave the stage pending. Through
// the whole CLI (root context, runRoot) over internal/pvefake's REST and
// SSH fakes, the interrupt arrives during the guard's kernel check; the
// command then fails on its cancelled context, and the revert — on its own
// context.WithoutCancel budget — still discards the stage. Nothing is
// committed, and the run exits 130 inside the interrupted frame.
func TestInterrupt_NetworkRevertRunsAfterTheFirstSignal(t *testing.T) {
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	rest.IfaceResponses = []string{
		pvefake.IfaceAbsent, // Run's Read
		pvefake.IfaceAbsent, // Apply's pre-stage read
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}`, // guard: staged, not active
	}
	rest.CommitUPID = pvefake.NetworkUPID(node, iface)
	srv := rest.Server()
	defer srv.Close()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case pvefake.LinkShowCmd(mgmt):
			return pvefake.LinkJSON(mgmt, true), "", 0
		case pvefake.LinkShowCmd(iface):
			// The guard's kernel check: after the stage, before the commit.
			cancel(interruptError{sig: syscall.SIGINT})
			return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, iface), 1
		}
		return "", "unexpected command", 127
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	code, stdout, stderr := runRootInterruptible(ctx, "network", "bridge", "create", "--roster", rosterPath,
		"--management-bridge", mgmt, "qa-pve-01", iface, "bridge_ports=eth1")
	if code != 130 {
		t.Fatalf("exit %d, want 130; stdout %q; stderr %q", code, stdout, stderr)
	}
	wantWrites := []string{
		"POST /api2/json/nodes/qa-pve-01/network bridge_ports=eth1&iface=vmbr1&type=bridge", // the stage
		"DELETE /api2/json/nodes/qa-pve-01/network",                                         // the revert, after the interrupt
	}
	if got := rest.Writes(); !slices.Equal(got, wantWrites) {
		t.Errorf("writes:\n got:  %q\n want: %q (the stage, then its revert; never a commit)", got, wantWrites)
	}
	if stdout != "" {
		t.Errorf("stdout %q, want nothing: the bridge was not created", stdout)
	}
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "interrupted (SIGINT): ") ||
		!strings.HasSuffix(stderr, "may or may not have been applied\n") {
		t.Errorf("stderr %q, want one interrupted line", stderr)
	}
}
