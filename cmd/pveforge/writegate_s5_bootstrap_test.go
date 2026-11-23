package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// bootstrap's first write is whichever of the key install, a TLS-pin roster
// write, the SSH-auth persist, or (stored key + equal pin) the token remove or
// mint comes first. The same sentinels are exit 4 in a run whose gate is still
// closed and exit 1 after the first write; nothing below classifies by name:
// each pair runs the SAME refusal at two points of the verb and reads the three
// logs.

// firstRunLeavingStoredKey runs a bootstrap that installs the key, persists the
// SSH auth, and then fails the post-mint validation: the roster is left with a
// stored SSH key and no token, the host with no token. It is the setup for the
// "stored key" modes.
func (e *s5Env) firstRunLeavingStoredKey(extra ...string) {
	e.t.Helper()
	e.val.errs = []error{bootstrap.ErrScopeTooWide}
	o := e.observe(e.bootstrapArgs(extra...)...)
	if o.code != 1 {
		e.t.Fatalf("setup run: exit %d, want 1; stderr %q", o.code, o.stderr)
	}
	tg := e.mustLoad().Find(s5Target)
	if tg == nil || tg.SSH == nil {
		e.t.Fatal("setup run left no stored SSH key")
	}
	e.val.errs, e.val.calls = nil, 0
}

// B1: an option refusal (no --grant) is raised before anything: exit 4, all
// three logs empty and the gate closed. (No post-write twin exists: nothing can
// precede argument validation.)
func TestS5Bootstrap_B1_NoGrantIsRefusedBeforeAnything(t *testing.T) {
	e := newS5Env(t, s5SeedRoster)
	o := e.observe("bootstrap", s5Target, "--host", "h", "--node", s5Node)
	o.wantRefusedBeforeAnyWrite(t)
	if len(e.host.cmds) != 0 || e.host.installs != 0 {
		t.Fatalf("the host was touched: cmds %q installs %d", e.host.cmds, e.host.installs)
	}
}

// B2: ErrTokenNotHeld, in a stored-key run whose gate is still closed (the
// token exists on PVE, the roster does not hold it): exit 4, nothing written.
func TestS5Bootstrap_B2_TokenNotHeldIs4WhileTheGateIsClosed(t *testing.T) {
	e := newS5Env(t, s5SeedRoster)
	e.firstRunLeavingStoredKey()
	e.host.tokens[s5Token] = true
	o := e.observe(e.bootstrapArgs()...)
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, bootstrap.ErrTokenNotHeld.Error()) {
		t.Fatalf("not the not-held refusal: %q", o.stderr)
	}
}

// B2 twin: the SAME sentinel after the key install and the SSH-auth persist
// (a first run): exit 1, with a REST-free SSH write and a roster write behind it.
func TestS5Bootstrap_B2_Twin_TokenNotHeldAfterInstallIs1(t *testing.T) {
	e := newS5Env(t, s5SeedRoster)
	e.host.tokens[s5Token] = true
	o := e.observe(e.bootstrapArgs()...)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || !strings.Contains(o.stderr, bootstrap.ErrTokenNotHeld.Error()) {
		t.Fatalf("exit %d, stderr %q; want the not-held refusal as exit 1", o.code, o.stderr)
	}
	if len(o.ssh) != 1 || len(o.rosterChanged) == 0 {
		t.Fatalf("ssh writes %q, roster changed %q: want the install and the SSH-auth persist", o.ssh, o.rosterChanged)
	}
}

// B3 (the token path): the token add succeeds through session.Run(configWrite),
// then validatePostMint's ErrScopeTooWide / ErrWrongScope: exit 1, NEVER 4. The
// FIRST write of this stored-key run is the token add itself, so it is the
// funnel (sshexec.Client.Run's write branch, here the fake's NoteWrite) that
// opens the gate.
func TestS5Bootstrap_B3_VerdictAfterTheMintIs1NeverFour(t *testing.T) {
	for _, verdict := range []error{bootstrap.ErrScopeTooWide, bootstrap.ErrWrongScope} {
		t.Run(verdict.Error(), func(t *testing.T) {
			e := newS5Env(t, s5SeedRoster)
			e.firstRunLeavingStoredKey()
			e.val.errs = []error{verdict, verdict, verdict}
			o := e.observe(e.bootstrapArgs()...)
			o.wantNotRefusedAfterWrite(t)
			if o.code != 1 {
				t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
			}
			if len(o.ssh) < 2 || !strings.HasPrefix(o.ssh[0], "pveum user token add") {
				t.Fatalf("ssh writes %q: the first write must be the token add", o.ssh)
			}
			if len(o.rosterChanged) != 0 {
				t.Fatalf("a failed validation changed the roster: %q", o.rosterChanged)
			}
			if !strings.Contains(o.stderr, verdict.Error()) {
				t.Fatalf("stderr %q does not carry the verdict", o.stderr)
			}
		})
	}
}

// B4 (stored key + equal pin: the token remove is the first write): the
// pre-write refusal is 4 with nothing written (ErrTokenSecretRejected: a held
// token PVE lists but rejects), and the post-write twin (the remove succeeds,
// the mint then fails the validation) is 1 with the remove as the FIRST write.
func TestS5Bootstrap_B4_StoredKeyEqualPin_TheTokenRemoveIsTheFirstWrite(t *testing.T) {
	setup := func(t *testing.T) *s5Env {
		e := newS5Env(t, s5SeedRosterInsecure)
		// A first, fully successful run: key, pin, token.
		o := e.observe(e.bootstrapArgs("--insecure-tls", "--host-key-fingerprint", s5FP)...)
		if o.code != 0 {
			t.Fatalf("setup run: exit %d, stderr %q", o.code, o.stderr)
		}
		tg := e.mustLoad().Find(s5Target)
		if tg == nil || tg.SSH == nil || tg.TLS == nil || tg.Token == nil {
			t.Fatalf("setup left target %+v without key, pin and token", tg)
		}
		e.val.errs, e.val.calls = nil, 0
		return e
	}
	t.Run("refusal before the first write is 4", func(t *testing.T) {
		e := setup(t)
		e.val.errs = []error{bootstrap.ErrNotAuthorized} // the skip-check: PVE rejects the held secret
		o := e.observe(e.bootstrapArgs("--insecure-tls")...)
		o.wantRefusedBeforeAnyWrite(t)
		if !strings.Contains(o.stderr, bootstrap.ErrTokenSecretRejected.Error()) {
			t.Fatalf("not the secret-rejected refusal: %q", o.stderr)
		}
	})
	t.Run("the remove is the first write, and the same run is then 1", func(t *testing.T) {
		e := setup(t)
		e.val.errs = []error{bootstrap.ErrWrongScope, bootstrap.ErrScopeTooWide} // skip-check verdict, then post-mint verdict
		o := e.observe(e.bootstrapArgs("--insecure-tls")...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
		if len(o.ssh) == 0 || !strings.HasPrefix(o.ssh[0], "pveum user token remove") {
			t.Fatalf("ssh writes %q: the first write of this mode must be the token remove", o.ssh)
		}
		if len(o.rosterChanged) == 0 {
			t.Fatalf("the roster's copy of the dead token was not cleared")
		}
	})
}

// B5 (TLS capture, the key removal after an install): a capture refusal raised
// in a keyless run (no key was installed: the gate is closed) is exit 4 with
// nothing written; the SAME mismatch after a keyful install is exit 1 and the
// run removes the key it installed (dropKeyOver). The removal is a root-SSH
// write that must carry the mark (F-B), and one that times out is exit 3.
func TestS5Bootstrap_B5_TLSCaptureRefusal_ClosedGateIs4_AfterInstallIs1(t *testing.T) {
	mismatch := func(e *s5Env) {
		e.val.served = s5PinOf(e.t, s5CertPEM(e.t, "something-else")) // the address serves another key
	}
	t.Run("keyless, gate closed: 4", func(t *testing.T) {
		e := newS5Env(t, s5SeedRosterInsecure)
		mismatch(e)
		o := e.observe(e.bootstrapArgs("--insecure-tls", "--no-ssh-key", "--ssh-tofu")...)
		o.wantRefusedBeforeAnyWrite(t)
		if !strings.Contains(o.stderr, bootstrap.ErrTLSPinMismatch.Error()) {
			t.Fatalf("not the mismatch refusal: %q", o.stderr)
		}
	})
	t.Run("keyful, after the install: 1, and the key is removed (dropKeyOver)", func(t *testing.T) {
		e := newS5Env(t, s5SeedRosterInsecure)
		mismatch(e)
		o := e.observe(e.bootstrapArgs("--insecure-tls", "--host-key-fingerprint", s5FP)...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, bootstrap.ErrTLSPinMismatch.Error()) {
			t.Fatalf("exit %d, stderr %q; want the same mismatch as exit 1", o.code, o.stderr)
		}
		if len(o.ssh) != 2 || !strings.HasPrefix(o.ssh[0], "install pubkey") || !strings.Contains(o.ssh[1], "authorized_keys") {
			t.Fatalf("ssh writes %q: want the install, then the key removal", o.ssh)
		}
		if len(o.rosterChanged) != 0 {
			t.Fatalf("the roster changed on a refused capture: %q", o.rosterChanged)
		}
	})
	t.Run("F-B twin: the key removal times out: 3", func(t *testing.T) {
		e := newS5Env(t, s5SeedRosterInsecure)
		mismatch(e)
		// The authorized_keys removal script is the one command that is neither
		// a pveum nor an openssl command: match it by what it touches.
		e.host.addRule(s5Rule{prefix: removalScriptPrefix(t), err: s5Timeout})
		o := e.observe(e.bootstrapArgs("--insecure-tls", "--host-key-fingerprint", s5FP)...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3 (an unobserved key removal); stderr %q", o.code, o.stderr)
		}
	})
}

// removalScriptPrefix is the start of the authorized_keys removal script
// bootstrap sends, which the host fake matches to script its timeout.
func removalScriptPrefix(t *testing.T) string {
	t.Helper()
	s, err := sshexec.RemoveAuthorizedKeyScript("ssh-ed25519 AAAA pveforge@x")
	if err != nil {
		t.Fatal(err)
	}
	if len(s) < 20 {
		t.Fatalf("removal script %q is too short to match", s)
	}
	return s[:20]
}

// B6 (exit 3, one fixture per unobserved dispatch): a write that was SENT and
// timed out, marked at the funnel and carried with %w, exits 3 from every
// bootstrap write site. Each fixture also asserts the write really happened.
func TestS5Bootstrap_B6_UnobservedWritesExit3(t *testing.T) {
	t.Run("key install timeout (keyLeftBehind, bootstrap.go:491)", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.host.installErr = s5Timeout
		o := e.observe(e.bootstrapArgs()...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("key install failure that is NOT a timeout stays 1", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.host.installErr = errors.New("remote script exited 1")
		o := e.observe(e.bootstrapArgs()...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("install dial failure (nothing sent) is 4", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.host.installDialErr = errors.Join(errors.New("install pubkey: dial refused"), sshexec.ErrNoCommandSent)
		o := e.observe(e.bootstrapArgs()...)
		o.wantRefusedBeforeAnyWrite(t)
	})
	t.Run("token add timeout (rotation.go add path)", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.firstRunLeavingStoredKey()
		e.host.addRule(s5Rule{prefix: "pveum user token add", err: s5Timeout})
		o := e.observe(e.bootstrapArgs()...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("ACL grant timeout", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.firstRunLeavingStoredKey()
		e.host.addRule(s5Rule{prefix: "pveum acl modify", err: s5Timeout})
		o := e.observe(e.bootstrapArgs()...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("token remove timeout, token still listed (priorUnknown, rotation.go:1040-1046)", func(t *testing.T) {
		e := newS5Env(t, s5SeedRosterInsecure)
		if o := e.observe(e.bootstrapArgs("--insecure-tls", "--host-key-fingerprint", s5FP)...); o.code != 0 {
			t.Fatalf("setup: exit %d %q", o.code, o.stderr)
		}
		e.val.errs, e.val.calls = []error{bootstrap.ErrWrongScope}, 0 // skip-check verdict: replace the token
		e.host.addRule(s5Rule{prefix: "pveum user token remove", err: s5Timeout})
		o := e.observe(e.bootstrapArgs("--insecure-tls")...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3 (an unobserved revoke); stderr %q", o.code, o.stderr)
		}
		if !strings.Contains(o.stderr, "whether it was revoked is unknown") {
			t.Fatalf("stderr %q is not the priorUnknown path", o.stderr)
		}
	})
	t.Run("token remove timeout, follow-up read unreadable (priorUnknown, the second %w)", func(t *testing.T) {
		e := newS5Env(t, s5SeedRosterInsecure)
		if o := e.observe(e.bootstrapArgs("--insecure-tls", "--host-key-fingerprint", s5FP)...); o.code != 0 {
			t.Fatalf("setup: exit %d %q", o.code, o.stderr)
		}
		e.val.errs, e.val.calls = []error{bootstrap.ErrWrongScope}, 0
		e.host.addRule(s5Rule{prefix: "pveum user token remove", err: s5Timeout})
		// the preflight's token list answers; the re-read after the remove does not
		e.host.addRule(s5Rule{prefix: "pveum user token list", skip: 1, err: errors.New("connection reset")})
		o := e.observe(e.bootstrapArgs("--insecure-tls")...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 || !strings.Contains(o.stderr, "could not establish whether the token still exists") {
			t.Fatalf("exit %d, stderr %q; want 3 through the unreadable-follow-up path", o.code, o.stderr)
		}
	})
	t.Run("a root-SSH READ timeout is 1, with nothing written", func(t *testing.T) {
		e := newS5Env(t, s5SeedRoster)
		e.firstRunLeavingStoredKey()
		e.host.addRule(s5Rule{prefix: "pveum role list", err: s5Timeout})
		o := e.observe(e.bootstrapArgs()...)
		if o.code != 1 || o.wrote() {
			t.Fatalf("exit %d, rest=%q ssh=%q roster=%q; want 1 and nothing written (a read timeout is neither 3 nor 4)", o.code, o.rest, o.ssh, o.rosterChanged)
		}
	})
}
