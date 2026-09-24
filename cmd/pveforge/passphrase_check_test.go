package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The roster passphrase check, through the whole CLI: bootstrap refuses a
// passphrase that does not open what the roster already holds, before it
// asks for anything else or touches anything.

const heldRosterPass = "test-roster-pass"

// rosterHoldingAToken writes a roster whose one target, "held", holds a
// token sealed under heldRosterPass, and points bootstrap's seams at tr and
// a validator that accepts. It returns the roster's path.
func rosterHoldingAToken(t *testing.T, tr bootstrap.SSHTransport) string {
	t.Helper()
	armored, err := fixtureEncrypt([]byte("held-secret"), heldRosterPass)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "roster.toml")
	body := "[[targets]]\nid = \"held\"\nhost = \"h0\"\nnode = \"n0\"\n\n[targets.token]\nid = \"root@pam!pveforge\"\nsecret_enc = '''\n" + armored + "'''\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { return tr }
	newBootstrapValidator = func() bootstrap.APIValidator { return nopValidator{} }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	t.Setenv("PVEFORGE_ROSTER", path)
	return path
}

// TestBootstrap_WrongRosterPassphraseRefusedFirst: a new target's first
// bootstrap with a passphrase that does not open the token the roster
// already holds is refused before the PVE password is asked for (it is not
// set, so reaching that prompt would fail differently), before any dial,
// and with the roster byte-identical. The error names the passphrase and
// where it came from.
func TestBootstrap_WrongRosterPassphraseRefusedFirst(t *testing.T) {
	tr := &fakeBootstrapTransport{}
	path := rosterHoldingAToken(t, tr)
	before, _ := os.ReadFile(path)
	t.Setenv(roster.PassphraseEnvVar, "mistyped-pass")
	t.Setenv(pvePasswordEnvVar, "")

	code, stdout, stderr := runRootArgs("bootstrap", "qa-new", "--host", "h", "--node", "n", "--no-ssh-key", "--grant", "/:PVEAuditor")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, stderr)
	}
	if stdout != "" || strings.Count(stderr, "\n") != 1 ||
		!strings.Contains(stderr, "wrong roster passphrase") ||
		!strings.Contains(stderr, "token secret of target held") ||
		!strings.Contains(stderr, roster.PassphraseEnvVar) {
		t.Errorf("stdout %q, stderr %q: want one line naming the wrong passphrase, the secret it failed on and %s", stdout, stderr, roster.PassphraseEnvVar)
	}
	if tr.calls != 0 {
		t.Errorf("the transport was used %d time(s) after a wrong passphrase", tr.calls)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Errorf("the roster changed:\n%s", after)
	}
}

// okSession is a pveum session on which a keyless mint succeeds.
type okSession struct{ ran []string }

func (s *okSession) Run(_ context.Context, cmd string) (bootstrap.RunResult, error) {
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
		return bootstrap.RunResult{}, nil
	}
	return bootstrap.RunResult{ExitCode: 127, Stderr: "unexpected command"}, nil
}

func (s *okSession) Close() error { return nil }

// TestBootstrap_RosterPassphraseControls: the right passphrase against a
// roster holding a secret, and any passphrase against a roster holding none
// (the first secret sets it), both bootstrap a new target — whose token is
// then sealed under that passphrase.
func TestBootstrap_RosterPassphraseControls(t *testing.T) {
	for name, empty := range map[string]bool{"right passphrase": false, "empty roster": true} {
		t.Run(name, func(t *testing.T) {
			tr := &sessionTransport{session: &okSession{}}
			path := rosterHoldingAToken(t, tr)
			pass := heldRosterPass
			if empty {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				pass = "any-first-pass"
			}
			t.Setenv(roster.PassphraseEnvVar, pass)
			t.Setenv(pvePasswordEnvVar, "test-pve-pass")

			code, _, stderr := runRootArgs("bootstrap", "qa-new", "--host", "h", "--node", "n", "--no-ssh-key", "--grant", "/:PVEAuditor")
			if code != 0 {
				t.Fatalf("exit %d, want 0; stderr %q", code, stderr)
			}
			r, err := roster.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			tg := r.Find("qa-new")
			if tg == nil || tg.Token == nil {
				t.Fatalf("the new target's token was not persisted")
			}
			if got, err := roster.DecryptString(tg.Token.SecretEnc, pass); err != nil || string(got) != "fresh-secret" {
				t.Errorf("the new token does not open under the run's passphrase: %q, %v", got, err)
			}
		})
	}
}

// TestImportToken_WrongRosterPassphraseRefusedFirst: importing a new
// target's token with a passphrase that does not open the token the roster
// already holds for another target is refused before the piped secret is
// read and before the validator's network call; the roster is unchanged.
func TestImportToken_WrongRosterPassphraseRefusedFirst(t *testing.T) {
	c := newImportCase(t)
	armored, err := fixtureEncrypt([]byte("held-secret"), rosterPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	body := "[[targets]]\nid = \"held\"\nhost = \"h0\"\nnode = \"n0\"\n\n[targets.token]\nid = \"root@pam!pveforge\"\nsecret_enc = '''\n" + armored + "'''\n"
	if err := os.WriteFile(c.rosterPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(roster.PassphraseEnvVar, "mistyped-pass")

	code, stdout, stderr := c.run(importSecret+"\n", importArgs...)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, stderr)
	}
	if stdout != "" || strings.Count(stderr, "\n") != 1 ||
		!strings.Contains(stderr, "wrong roster passphrase") || !strings.Contains(stderr, roster.PassphraseEnvVar) {
		t.Errorf("stdout %q, stderr %q: want one line naming the wrong passphrase and %s", stdout, stderr, roster.PassphraseEnvVar)
	}
	if c.stdinReads != 0 || len(c.v.cfgs) != 0 {
		t.Errorf("after a wrong passphrase: %d stdin read(s), %d validation(s); want none", c.stdinReads, len(c.v.cfgs))
	}
	if got := c.rosterBytes(t); string(got) != body {
		t.Errorf("the roster changed:\n%s", got)
	}
	c.requireNoRemovePath(t)
}

// TestBootstrap_UnreadableRosterRefusedFirst (RPC2): a roster whose only
// secret this pveforge cannot read at all (not armored ciphertext it can
// open, and not a wrong-passphrase answer either) cannot check any
// passphrase, so bootstrap refuses it the way it refuses a wrong one:
// before the PVE password is asked for (it is not set, so reaching that
// step would fail differently), before any dial, with the roster
// byte-identical, naming the secret it could not read.
func TestBootstrap_UnreadableRosterRefusedFirst(t *testing.T) {
	tr := &fakeBootstrapTransport{}
	path := rosterHoldingAToken(t, tr)
	body := "[[targets]]\nid = \"held\"\nhost = \"h0\"\nnode = \"n0\"\n\n[targets.token]\nid = \"root@pam!pveforge\"\nsecret_enc = '''\n-----BEGIN AGE ENCRYPTED FILE-----\nnot base64 at all!\n-----END AGE ENCRYPTED FILE-----\n'''\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(roster.PassphraseEnvVar, heldRosterPass)
	t.Setenv(pvePasswordEnvVar, "")

	code, stdout, stderr := runRootArgs("bootstrap", "qa-new", "--host", "h", "--node", "n", "--no-ssh-key", "--grant", "/:PVEAuditor")
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr %q", code, stderr)
	}
	if stdout != "" || strings.Count(stderr, "\n") != 1 ||
		!strings.Contains(stderr, "no secret in the roster can be read") ||
		!strings.Contains(stderr, "token secret of target held") {
		t.Errorf("stdout %q, stderr %q: want one line saying no roster secret can be read, naming the token of target held", stdout, stderr)
	}
	if tr.calls != 0 {
		t.Errorf("the transport was used %d time(s)", tr.calls)
	}
	if after, _ := os.ReadFile(path); string(after) != body {
		t.Errorf("the roster changed:\n%s", after)
	}
}
