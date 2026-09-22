package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// ---- helpers ----

const heldID = "root@pam!pveforge"

// seeded is a roster whose target already has SSH auth (so Run reconnects)
// and, optionally, a token.
type seeded struct {
	path string
	opts Options
	key  []byte
}

func seedRoster(t *testing.T, tokenID, tokenPassphrase string) seeded {
	t.Helper()
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	if err := roster.AppendTarget(path, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(path, opts.TargetID, roster.SSHWrite{
		User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:abc", PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if tokenID != "" {
		if tokenPassphrase == "" {
			tokenPassphrase = opts.Passphrase
		}
		if err := roster.WriteTokenAuth(path, opts.TargetID, roster.TokenWrite{TokenID: tokenID, SecretPlaintext: []byte("held-secret")}, tokenPassphrase); err != nil {
			t.Fatalf("WriteTokenAuth: %v", err)
		}
	}
	return seeded{path: path, opts: opts, key: kp.PrivateKeyPEM}
}

func rosterBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	return b
}

func rosterToken(t *testing.T, path string) *roster.TokenAuth {
	t.Helper()
	r, err := roster.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r.Find("qa-pve-01").Token
}

func persistedSecret(t *testing.T, s seeded) string {
	t.Helper()
	tok := rosterToken(t, s.path)
	if tok == nil {
		t.Fatal("no token persisted")
	}
	b, err := roster.DecryptString(tok.SecretEnc, s.opts.Passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return string(b)
}

// fastRetries makes the post-mint retry delay zero for this test.
func fastRetries(t *testing.T) {
	t.Helper()
	orig := postMintRetryDelay
	postMintRetryDelay = 0
	t.Cleanup(func() { postMintRetryDelay = orig })
}

func withCleanupTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := cleanupTimeout
	cleanupTimeout = d
	t.Cleanup(func() { cleanupTimeout = orig })
}

// duplicateTargetBlock appends a second qa-pve-01 block: every roster
// splice then refuses the ambiguity (findUniqueTargetBlock).
func duplicateTargetBlock(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"h\"\nnode = \"qa-pve-01\"\n"); err != nil {
		t.Fatal(err)
	}
}

func noToken(t *testing.T, path string) {
	t.Helper()
	if tok := rosterToken(t, path); tok != nil {
		t.Fatalf("the roster still holds a token: %+v", tok)
	}
}

// ---- RL: the run lock ----

// RL1 (+ the author's N5): with the per-target lock held, Run fails on the
// lock and never touches the transport at all.
func TestRun_RL1_LockHeldAbortsBeforeAnyTransportCall(t *testing.T) {
	for _, tokenID := range []string{"pveforge", "a-different-token-id"} { // the second is ML2's kill: the key is per target
		t.Run(tokenID, func(t *testing.T) {
			s := seedRoster(t, "", "")
			unlock, err := lock.Mutation(context.Background(), s.path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"})
			if err != nil {
				t.Fatalf("hold the lock: %v", err)
			}
			defer func() { _ = unlock() }()

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			session := &fakeSession{}
			tr := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
			opts := s.opts
			opts.TokenID = tokenID
			_, err = Run(ctx, opts, tr, &fakeValidator{})
			if err == nil || !strings.Contains(err.Error(), "qa-pve-01/bootstrap/token") {
				t.Fatalf("want a lock error naming the key, got %v", err)
			}
			if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(session.attempted) != 0 {
				t.Fatalf("transport touched: install=%d dial=%d reconnect=%d commands=%v", tr.installCalls, tr.dialCalls, tr.reconnectCalls, session.attempted)
			}
		})
	}
}

// RL2: the lock is per target: another target's lock does not block.
func TestRun_RL2_OtherTargetsLockDoesNotBlock(t *testing.T) {
	path := newTestRoster(t, "")
	unlock, err := lock.Mutation(context.Background(), path, lock.ObjectKey{TargetID: "qa-pve-02", Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Run(ctx, baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}, &fakeValidator{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// R2 addition: the lock is released when Run returns (a second run can take it).
func TestRun_R2_LockReleasedAfterRun(t *testing.T) {
	s := seedRoster(t, heldID, "")
	if _, err := Run(context.Background(), s.opts, &fakeTransport{session: &fakeSession{pve: newFakePVE("pveforge")}}, &fakeValidator{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := lock.Mutation(ctx, s.path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatalf("the run lock was not released: %v", err)
	}
	_ = unlock()
}

// RL3: the lock is held for the WHOLE run, not just its start: at the
// remove, the add and the post-mint validation, another bootstrap of the
// same target cannot take it. RL1 holds the lock before Run starts, so it
// cannot see a release partway through.
func TestRun_RL3_LockHeldThroughTheTokenPhase(t *testing.T) {
	s, session, tr, v := prior(t, nil, nil)
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"}
	free := map[string]bool{}
	probe := func(step string) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		unlock, err := lock.Mutation(ctx, s.path, key)
		if err == nil {
			_ = unlock()
			free[step] = true
			return
		}
		free[step] = false
	}
	session.onRun = func(_ context.Context, cmd string) {
		switch {
		case strings.HasPrefix(cmd, "pveum user token remove"):
			probe("remove")
		case strings.HasPrefix(cmd, "pveum user token add"):
			probe("add")
		}
	}
	v.onCall = func(call int) {
		if call == 1 { // the post-mint validation
			probe("post-mint validation")
		}
	}
	res, err := Run(context.Background(), s.opts, tr, v)
	if err != nil || res.TokenOutcome != OutcomeReplaced {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	for _, step := range []string{"remove", "add", "post-mint validation"} {
		got, ran := free[step]
		if !ran {
			t.Fatalf("the %s step was never probed", step)
		}
		if got {
			t.Errorf("the per-target lock was free during the %s", step)
		}
	}
}

// ---- R3: replacement after a verdict ----

// R3, R4, R4b (+R8b, RC1): a skip-check verdict about the held token, which
// is present on PVE: checked remove, then the roster clear (no token while
// the add runs), then add; replaced, with the verdict as the reason.
func TestRun_R3_VerdictPresent_RemoveClearAdd(t *testing.T) {
	for name, verdict := range map[string]error{
		"ErrNoGrants":      fmt.Errorf("%w", ErrNoGrants),
		"ErrWrongScope":    fmt.Errorf("%w", ErrWrongScope),
		"ErrNotAuthorized": fmt.Errorf("%w", ErrNotAuthorized),
		// R3′: a held token wider than requested is a verdict too.
		"ErrScopeTooWide": fmt.Errorf("%w: at / the token holds VM.Allocate", ErrScopeTooWide),
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, heldID, "")
			var tokenDuringAdd *roster.TokenAuth
			session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{
				"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh")}, onRun: func(context.Context, string) {
					tokenDuringAdd = rosterToken(t, s.path)
				}},
			}}
			v := &fakeValidator{errs: []error{verdict, nil}}
			res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.TokenOutcome != OutcomeReplaced || !res.PriorRevoked || res.RosterToken != RosterTokenCleared {
				t.Fatalf("result = %+v", res)
			}
			if res.ReplacedReason != verdict.Error() || !errors.Is(res.ReplacedErr, verdict) {
				t.Fatalf("reason = %q, want the verdict's own text %q", res.ReplacedReason, verdict.Error())
			}
			if tokenDuringAdd != nil {
				t.Fatalf("RC1: the roster still held a token while the add ran: %+v", tokenDuringAdd)
			}
			m := session.mutating()
			if len(m) < 2 || !strings.HasPrefix(m[0], "pveum user token remove") || !strings.HasPrefix(m[1], "pveum user token add") {
				t.Fatalf("want remove then add, got %v", m)
			}
			if got := persistedSecret(t, s); got != "fresh" {
				t.Fatalf("persisted %q, want fresh", got)
			}
		})
	}
}

// R3b: a verdict, but the token no longer exists on PVE: no remove, the
// roster's dead copy is cleared before the add; replaced, not revoked.
func TestRun_R3b_VerdictNotPresent_NoRemove(t *testing.T) {
	s := seedRoster(t, heldID, "")
	var tokenDuringAdd *roster.TokenAuth
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh")}, onRun: func(context.Context, string) { tokenDuringAdd = rosterToken(t, s.path) }},
	}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNotAuthorized), nil}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeReplaced || res.PriorRevoked || res.RosterToken != RosterTokenCleared {
		t.Fatalf("result = %+v", res)
	}
	if session.ran("pveum user token remove") {
		t.Fatalf("a remove was issued for a token PVE no longer has: %v", session.commands)
	}
	if tokenDuringAdd != nil {
		t.Fatal("the dead copy was not cleared before the add")
	}
}

// R3c: the clear fails in a known-dead-not-present row: abort before the
// add; nothing was revoked by this run, so discarded and stale_absent.
func TestRun_R3c_ClearFailsWhenNotPresent(t *testing.T) {
	s := seedRoster(t, heldID, "")
	session := &fakeSession{}
	v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNotAuthorized)}, onCall: func(call int) {
		if call == 0 { // the skip-check: after the dry run, before the clear
			duplicateTargetBlock(t, s.path)
		}
	}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	if err == nil || res == nil {
		t.Fatalf("want a failure with a partial result, got %+v, %v", res, err)
	}
	if res.TokenOutcome != OutcomeDiscarded || res.RosterToken != RosterTokenStaleAbsent || errors.Is(err, ErrPriorTokenRevoked) {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if session.ran("pveum user token add") || session.ran("pveum user token remove") {
		t.Fatalf("token commands after a failed clear: %v", session.commands)
	}
}

// ---- R5: tokens this roster does not hold, undecryptable, changed id ----

// R5 (first bootstrap) and R5b (reconnect, no token held): a same-named
// token exists on PVE that this roster does not hold. Abort, naming it and
// the manual remove; never remove it.
func TestRun_R5_NotHeldButPresentAborts(t *testing.T) {
	t.Run("first bootstrap", func(t *testing.T) {
		path := newTestRoster(t, "")
		session := &fakeSession{pve: newFakePVE("pveforge")}
		res, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{})
		checkNotHeld(t, res, err, session)
		noToken(t, path)
	})
	t.Run("reconnect", func(t *testing.T) {
		s := seedRoster(t, "", "")
		before := rosterBytes(t, s.path)
		session := &fakeSession{pve: newFakePVE("pveforge")}
		res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
		checkNotHeld(t, res, err, session)
		if !bytes.Equal(before, rosterBytes(t, s.path)) {
			t.Fatal("the roster changed")
		}
	})
}

func checkNotHeld(t *testing.T, res *Result, err error, session *fakeSession) {
	t.Helper()
	if !errors.Is(err, ErrTokenNotHeld) || res != nil {
		t.Fatalf("want ErrTokenNotHeld and no result, got %+v, %v", res, err)
	}
	if !strings.Contains(err.Error(), heldID) || !strings.Contains(err.Error(), "pveum user token remove") {
		t.Fatalf("the error must name the token and the manual remove: %v", err)
	}
	if m := session.mutating(); len(m) != 0 {
		t.Fatalf("token commands issued: %v", m)
	}
}

// R5c: the held token will not decrypt and is still present on PVE: abort,
// never remove. The fixture is the realistic cause, a token written under
// another passphrase: a wrong passphrase is not a verdict about the token.
// Nothing changes, on PVE or in the roster, and the error names the manual
// remove.
func TestRun_R5c_UndecryptablePresentAborts(t *testing.T) {
	s := seedRoster(t, heldID, "another-passphrase")
	before := rosterBytes(t, s.path)
	session := &fakeSession{pve: newFakePVE("pveforge")}
	v := &fakeValidator{}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, ErrTokenUndecryptable) || res != nil {
		t.Fatalf("want ErrTokenUndecryptable and no result, got %+v, %v", res, err)
	}
	if errors.Is(err, ErrPriorTokenRevoked) {
		t.Fatalf("nothing was revoked, but the error says so: %v", err)
	}
	if !strings.Contains(err.Error(), heldID) || !strings.Contains(err.Error(), "pveum user token remove") {
		t.Fatalf("the error must name the token and the manual remove: %v", err)
	}
	if m := session.mutating(); len(m) != 0 {
		t.Fatalf("token commands issued: %v", m)
	}
	if !session.pve.has(heldID) {
		t.Fatal("the token is gone from PVE")
	}
	if v.calls != 0 {
		t.Fatalf("validator calls = %d, want 0", v.calls)
	}
	if !bytes.Equal(before, rosterBytes(t, s.path)) {
		t.Fatal("the roster changed")
	}
}

// R5g: undecryptable and not present: no remove; the dead copy is cleared
// before the add.
func TestRun_R5g_UndecryptableNotPresent(t *testing.T) {
	s := seedRoster(t, heldID, "another-passphrase")
	var tokenDuringAdd *roster.TokenAuth
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh")}, onRun: func(context.Context, string) { tokenDuringAdd = rosterToken(t, s.path) }},
	}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeReplaced || res.PriorRevoked || session.ran("pveum user token remove") || tokenDuringAdd != nil {
		t.Fatalf("result = %+v, commands = %v, token during add = %+v", res, session.commands, tokenDuringAdd)
	}
}

// R5d: a changed --token-id (roster holds A, request B, B absent): mint B;
// A is never removed and is reported orphaned.
func TestRun_R5d_ChangedTokenIDOrphansNeverRemoves(t *testing.T) {
	s := seedRoster(t, heldID, "")
	s.opts.TokenID = "pveforge-2"
	session := &fakeSession{pve: newFakePVE("pveforge")} // A is live on PVE
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeMinted || res.OrphanedToken != heldID {
		t.Fatalf("result = %+v", res)
	}
	if session.ran("pveum user token remove") || !session.pve.has(heldID) {
		t.Fatalf("A was removed: %v", session.commands)
	}
}

// R5e: a changed --token-id, and B already exists on PVE: abort.
func TestRun_R5e_ChangedTokenIDButPresentAborts(t *testing.T) {
	s := seedRoster(t, heldID, "")
	s.opts.TokenID = "pveforge-2"
	session := &fakeSession{pve: newFakePVE("pveforge", "pveforge-2")}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if !errors.Is(err, ErrTokenNotHeld) {
		t.Fatalf("want ErrTokenNotHeld, got %v", err)
	}
	if m := session.mutating(); len(m) != 0 {
		t.Fatalf("token commands issued: %v", m)
	}
}

// R5f: a changed --token-id and the add fails: the roster still holds A,
// byte-identical; no clear; discarded; no orphan reported.
func TestRun_R5f_ChangedTokenIDAddFailsKeepsA(t *testing.T) {
	s := seedRoster(t, heldID, "")
	s.opts.TokenID = "pveforge-2"
	before := rosterBytes(t, s.path)
	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{ExitCode: 1, Stderr: "boom"}},
	}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if err == nil || res == nil || res.TokenOutcome != OutcomeDiscarded || res.OrphanedToken != "" || res.RosterToken != "" {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if !bytes.Equal(before, rosterBytes(t, s.path)) {
		t.Fatal("the roster no longer holds A byte-identically")
	}
}

// ---- R6: preflight ----

// R6, R6b, R6c, R6d (+R8c): the token list must be a real, non-null JSON
// array; anything else aborts before any token command, and the error
// never echoes the output.
func TestRun_R6_TokenListMustParse(t *testing.T) {
	for name, r := range map[string]fakeRunResult{
		"exit non-zero": {res: RunResult{ExitCode: 2, Stderr: "no"}},
		"empty":         {res: RunResult{Stdout: ""}},
		"null":          {res: RunResult{Stdout: "null"}},
		"malformed":     {res: RunResult{Stdout: `[{"tokenid": "s3cr3t-marker"`}},
		"not an array":  {res: RunResult{Stdout: `{"value":"s3cr3t-marker"}`}},
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, heldID, "")
			session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum user token list": r}}
			_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "s3cr3t-marker") {
				t.Fatalf("the error echoes the output: %v", err)
			}
			if m := session.mutating(); len(m) != 0 {
				t.Fatalf("token commands issued: %v", m)
			}
		})
	}
}

// R6e / R6f: an unknown role or node aborts before any token command.
func TestRun_R6e_R6f_UnknownRoleOrNode(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix, out string
		want        error
	}{
		"role": {"pveum role list", `[{"roleid":"PVEAuditor"}]`, ErrUnknownRole},
		"node": {"pvesh get /nodes", `[{"node":"qa-pve-02"}]`, ErrUnknownNode},
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, heldID, "")
			session := &fakeSession{byCmd: map[string]fakeRunResult{tc.prefix: {res: RunResult{Stdout: tc.out}}}}
			_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if session.ran("pveum user token") {
				t.Fatalf("a token command ran: %v", session.commands)
			}
		})
	}
}

// R6f addition to :268's intent: the node the preflight checks is the one
// defaulted from the roster.
func TestRun_R6f_PreflightChecksTheRosterDefaultedNode(t *testing.T) {
	s := seedRoster(t, "", "")
	s.opts.Node = ""
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pvesh get /nodes": {res: RunResult{Stdout: `[{"node":"qa-pve-02"}]`}}}}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if !errors.Is(err, ErrUnknownNode) || !strings.Contains(err.Error(), `"qa-pve-01"`) {
		t.Fatalf("want ErrUnknownNode naming the roster's qa-pve-01, got %v", err)
	}
}

// R6g: a roster path whose parent is a regular file (ENOTDIR, which holds
// for root too): abort before any SSH.
func TestRun_R6g_RosterParentIsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
	if _, err := Run(context.Background(), baseOptions(filepath.Join(file, "roster.toml")), tr, &fakeValidator{}); err == nil {
		t.Fatal("want an error")
	}
	if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(tr.session.attempted) != 0 {
		t.Fatal("the transport was touched")
	}
}

// R6g-b: the dry run failing (as the real one does when the roster
// directory is unwritable) aborts after the three reads and before any
// token command, for every uid.
func TestRun_R6gb_DryRunFailureAbortsBeforeTokenCommands(t *testing.T) {
	orig := dryRunTokenWrite
	dryRunTokenWrite = func(string, string) error { return errors.New("roster dry run: the roster directory is not writable") }
	t.Cleanup(func() { dryRunTokenWrite = orig })
	s := seedRoster(t, heldID, "")
	before := rosterBytes(t, s.path)
	session := &fakeSession{pve: newFakePVE("pveforge")}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if err == nil || !strings.Contains(err.Error(), "dry run") {
		t.Fatalf("want the dry run's error, got %v", err)
	}
	if session.count("pveum user token list") != 1 || len(session.mutating()) != 0 {
		t.Fatalf("want the three reads and no token command, got %v", session.commands)
	}
	if !bytes.Equal(before, rosterBytes(t, s.path)) {
		t.Fatal("the roster changed")
	}
}

// R6g-dup: a layout the real dry run refuses (an inline token table: the
// append would duplicate the key) aborts before any token command.
func TestRun_R6gdup_RealDryRunRefusesAnUnwritableLayout(t *testing.T) {
	s := seedRoster(t, "", "")
	armored, err := roster.EncryptString([]byte("held-secret"), s.opts.Passphrase)
	if err != nil {
		t.Fatal(err)
	}
	b := rosterBytes(t, s.path)
	inline := strings.Replace(string(b), "node = \"qa-pve-01\"\n", fmt.Sprintf("node = \"qa-pve-01\"\ntoken = { id = %q, secret_enc = %q }\n", heldID, armored), 1)
	if err := os.WriteFile(s.path, []byte(inline), 0o600); err != nil {
		t.Fatal(err)
	}
	session := &fakeSession{pve: newFakePVE("pveforge")}
	_, err = Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants)}})
	if err == nil || !strings.Contains(err.Error(), "dry run") {
		t.Fatalf("want the dry run to refuse, got %v", err)
	}
	if len(session.mutating()) != 0 {
		t.Fatalf("token commands issued: %v", session.commands)
	}
}

// R6h-a: a grant's path is normalized like PVE does, and the grant uses the
// normalized path; a path PVE would refuse aborts before any SSH.
func TestRun_R6h_GrantPathNormalizedOrRefused(t *testing.T) {
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	opts.Grants = []Grant{{Path: "pool/p/", Role: "PVEVMAdmin", Propagate: true}}
	session := &fakeSession{}
	if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !session.ran("pveum acl modify '/pool/p' ") {
		t.Fatalf("the grant did not use the normalized path: %v", session.commands)
	}
	for _, bad := range []string{"/foo", "0", "/vms/99"} {
		opts := baseOptions(newTestRoster(t, ""))
		opts.Grants = []Grant{{Path: bad, Role: "PVEVMAdmin", Propagate: true}}
		tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
		if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); !errors.Is(err, ErrInvalidACLPath) {
			t.Fatalf("%q: want ErrInvalidACLPath, got %v", bad, err)
		}
		if tr.installCalls != 0 || len(tr.session.attempted) != 0 {
			t.Fatalf("%q: SSH was touched", bad)
		}
	}
}

func TestACLPathMirror(t *testing.T) {
	for in, want := range map[string]string{
		"/": "/", "pool/p/": "/pool/p", "//pool//p": "/pool/p", "/vms/100": "/vms/100",
		"/sdn/zones/localnetwork/vmbr0": "/sdn/zones/localnetwork/vmbr0", "/storage/local": "/storage/local",
		"/pool/a/b/c": "/pool/a/b/c", "/sdn/zones/z/v/4094": "/sdn/zones/z/v/4094",
	} {
		got, err := checkedACLPath(in)
		if err != nil || got != want {
			t.Errorf("checkedACLPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "/foo", "/vms/99", "/pool/a/b/c/d", "/sdn/zones/z/v/0", "/pool/p\n", "/storage/a b", "/storage/x;y"} {
		if got, err := checkedACLPath(in); err == nil {
			t.Errorf("checkedACLPath(%q) = %q, want an error", in, got)
		}
	}
	// "00" is Perl-true, unlike "0".
	if n, ok := normalizeACLPath("00"); !ok || n != "/00" {
		t.Errorf(`normalizeACLPath("00") = %q, %v; want "/00", true`, n, ok)
	}
}

// ---- R7: non-verdicts and local faults never rotate ----

// R7 (the twin of TestRun_ReplacesOnVerdict), R7b, R7c: a skip-check error
// that is not a verdict aborts; nothing is removed, added, or persisted.
func TestRun_AbortsOnNonVerdict(t *testing.T) {
	for name, e := range map[string]error{
		"plain":        errors.New("token authenticates but appears to have no working grants"),
		"unverifiable": errors.New("unverifiable read"),
		"deadline":     context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, heldID, "")
			before := rosterBytes(t, s.path)
			session := &fakeSession{pve: newFakePVE("pveforge")}
			res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{err: e})
			if err == nil || res != nil {
				t.Fatalf("want an abort with no result, got %+v, %v", res, err)
			}
			if m := session.mutating(); len(m) != 0 {
				t.Fatalf("token commands issued: %v", m)
			}
			if !bytes.Equal(before, rosterBytes(t, s.path)) {
				t.Fatal("the roster changed")
			}
		})
	}
}

// R7d: a roster that stops loading after the dry run aborts; it is a local
// fault, never a reason to mint.
func TestRun_R7d_RosterLoadErrorAborts(t *testing.T) {
	s := seedRoster(t, heldID, "")
	orig := dryRunTokenWrite
	dryRunTokenWrite = func(path, id string) error {
		if err := orig(path, id); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("this is = = not toml"), 0o600)
	}
	t.Cleanup(func() { dryRunTokenWrite = orig })
	session := &fakeSession{pve: newFakePVE("pveforge")}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if err == nil || !strings.Contains(err.Error(), "load roster") {
		t.Fatalf("want a load error, got %v", err)
	}
	if len(session.mutating()) != 0 {
		t.Fatalf("token commands issued: %v", session.commands)
	}
}

// ---- R8: no secret in any report ----

func TestRun_R8_SecretNeverInErrorsOrResult(t *testing.T) {
	fastRetries(t)
	const marker = "s3cr3t-marker"
	add := fakeRunResult{res: RunResult{Stdout: tokenAddJSON(marker)}}
	for name, tc := range map[string]struct {
		byCmd map[string]fakeRunResult
		v     *fakeValidator
		seed  bool
	}{
		"acl error":             {map[string]fakeRunResult{"pveum user token add": add, "pveum acl modify": {res: RunResult{ExitCode: 1, Stderr: "no such role"}}}, &fakeValidator{}, false},
		"post-mint verdict":     {map[string]fakeRunResult{"pveum user token add": add}, &fakeValidator{err: fmt.Errorf("%w", ErrWrongScope)}, false},
		"post-mint non-verdict": {map[string]fakeRunResult{"pveum user token add": add}, &fakeValidator{err: errors.New("dial tcp: refused")}, false},
		"after a remove":        {map[string]fakeRunResult{"pveum user token add": add, "pveum acl modify": {res: RunResult{ExitCode: 1}}}, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants)}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			var s seeded
			var tr *fakeTransport
			session := &fakeSession{byCmd: tc.byCmd}
			if tc.seed {
				s = seedRoster(t, heldID, "")
				session.pve = newFakePVE("pveforge")
				tr = &fakeTransport{session: session}
			} else {
				s = seeded{path: newTestRoster(t, ""), opts: baseOptions("")}
				s.opts.RosterPath = s.path
				tr = &fakeTransport{installFingerprint: "SHA256:abc", session: session}
			}
			res, err := Run(context.Background(), s.opts, tr, tc.v)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(fmt.Sprintf("%+v", res), marker) {
				t.Fatalf("the secret leaked: err=%v res=%+v", err, res)
			}
		})
	}
}

// ---- R9: remove outcomes ----

// R9: the remove exits non-zero: abort with neutral wording; no add; the
// roster is unchanged.
func TestRun_R9_RemoveExitNonZero(t *testing.T) {
	s := seedRoster(t, heldID, "")
	before := rosterBytes(t, s.path)
	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum user token remove": {res: RunResult{ExitCode: 5, Stderr: "busy"}}}}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)})
	if err == nil || !strings.Contains(err.Error(), "remove exited 5; pveforge did not revoke the token") {
		t.Fatalf("got %v", err)
	}
	if session.ran("pveum user token add") || !bytes.Equal(before, rosterBytes(t, s.path)) {
		t.Fatal("an add ran, or the roster changed")
	}
}

// R9b: remove transport error, and the re-read (on a fresh session) shows
// it gone: continue, with the add on the FRESH session.
func TestRun_R9b_RemoveTransportErrorReReadAbsent(t *testing.T) {
	s := seedRoster(t, heldID, "")
	pve := newFakePVE("pveforge")
	orig := &fakeSession{pve: pve, byCmd: map[string]fakeRunResult{"pveum user token remove": {err: errors.New("connection lost"), applies: true}}}
	fresh := &fakeSession{pve: pve}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: orig, reconnectSession: fresh}, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants), nil}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeReplaced || !res.PriorRevoked {
		t.Fatalf("result = %+v", res)
	}
	if orig.ran("pveum user token add") || !fresh.ran("pveum user token add") || !orig.closed {
		t.Fatalf("the add must run on the fresh session, and the dead one be closed: orig=%v fresh=%v", orig.commands, fresh.commands)
	}
}

// R9c: remove transport error, the re-read shows it still present: abort,
// no add.
func TestRun_R9c_RemoveTransportErrorReReadPresent(t *testing.T) {
	s := seedRoster(t, heldID, "")
	pve := newFakePVE("pveforge")
	orig := &fakeSession{pve: pve, byCmd: map[string]fakeRunResult{"pveum user token remove": {err: errors.New("connection lost")}}}
	fresh := &fakeSession{pve: pve}
	_, err := Run(context.Background(), s.opts, &fakeTransport{session: orig, reconnectSession: fresh}, &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)})
	if err == nil || !strings.Contains(err.Error(), "still exists") {
		t.Fatalf("got %v", err)
	}
	if orig.ran("pveum user token add") || fresh.ran("pveum user token add") {
		t.Fatal("an add ran")
	}
	if rosterToken(t, s.path) == nil {
		t.Fatal("the roster lost a token that is still live")
	}
}

// R9d: remove transport error, and the re-read is unreadable: clear the
// roster (it may point at a dead token), stop; prior_token=unknown.
func TestRun_R9d_RemoveTransportErrorReReadUnreadable(t *testing.T) {
	s := seedRoster(t, heldID, "")
	orig := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum user token remove": {err: errors.New("connection lost"), applies: true}}}
	tr := &fakeTransport{session: orig, reconnectErrs: []error{nil, errors.New("no route to host")}}
	res, err := Run(context.Background(), s.opts, tr, &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)})
	if !errors.Is(err, ErrPriorTokenRevoked) || res == nil {
		t.Fatalf("got %+v, %v", res, err)
	}
	if res.TokenOutcome != OutcomeRevokedNotReplaced || res.PriorToken != PriorTokenUnknown || res.RosterToken != RosterTokenCleared {
		t.Fatalf("result = %+v", res)
	}
	noToken(t, s.path)
	if orig.ran("pveum user token add") {
		t.Fatal("an add ran")
	}
}

// RS1: a reconnect after a transport error uses this run's IN-MEMORY
// identity, even if the roster was edited mid-run.
func TestRun_RS1_ReconnectUsesInMemoryIdentity(t *testing.T) {
	s := seedRoster(t, heldID, "")
	pve := newFakePVE("pveforge")
	orig := &fakeSession{pve: pve, byCmd: map[string]fakeRunResult{"pveum user token remove": {err: errors.New("connection lost"), applies: true, onRun: func(context.Context, string) {
		kp, err := sshexec.GenerateEd25519Keypair("attacker")
		if err != nil {
			t.Fatal(err)
		}
		// A hand edit mid-run: a different pinned fingerprint and key.
		if err := roster.WriteSSHAuth(s.path, "qa-pve-01", roster.SSHWrite{User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:edited", PrivateKeyPlaintext: kp.PrivateKeyPEM}, s.opts.Passphrase); err != nil {
			t.Fatal(err)
		}
	}}}}
	tr := &fakeTransport{session: orig, reconnectSession: &fakeSession{pve: pve}}
	if _, err := Run(context.Background(), s.opts, tr, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants), nil}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(tr.reconnectedFingerprints) != 2 {
		t.Fatalf("reconnects = %v, want the initial one and one fresh", tr.reconnectedFingerprints)
	}
	if tr.reconnectedFingerprints[1] != "SHA256:abc" || tr.reconnectedAddrs[1] != "qa-pve-01.example.com:22" || !bytes.Equal(tr.reconnectedKeys[1], s.key) {
		t.Fatalf("the fresh reconnect used fp=%q addr=%q; want this run's original identity", tr.reconnectedFingerprints[1], tr.reconnectedAddrs[1])
	}
}

// ---- R10: failures after the remove ----

// prior sets up the common "held token present, skip-check verdict" run.
func prior(t *testing.T, byCmd map[string]fakeRunResult, errs ...error) (seeded, *fakeSession, *fakeTransport, *fakeValidator) {
	t.Helper()
	s := seedRoster(t, heldID, "")
	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: byCmd}
	tr := &fakeTransport{session: session, reconnectSession: &fakeSession{pve: session.pve}}
	v := &fakeValidator{errs: append([]error{fmt.Errorf("%w", ErrNoGrants)}, errs...)}
	return s, session, tr, v
}

func wantRevoked(t *testing.T, res *Result, err error) {
	t.Helper()
	if !errors.Is(err, ErrPriorTokenRevoked) || res == nil || res.TokenOutcome != OutcomeRevokedNotReplaced {
		t.Fatalf("want revoked_not_replaced with ErrPriorTokenRevoked, got %+v, %v", res, err)
	}
}

// R10: the add exits non-zero after the remove: reported, roster clear.
func TestRun_R10_AddFailsAfterRemove(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {res: RunResult{ExitCode: 1, Stderr: "nope"}}})
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.RosterToken != RosterTokenCleared {
		t.Fatalf("roster_token = %q", res.RosterToken)
	}
	noToken(t, s.path)
	_ = session
}

// R10b / R10d / R10e: the add hits a transport error.
func TestRun_R10b_AddTransportError(t *testing.T) {
	t.Run("re-read present: removed on the fresh session", func(t *testing.T) {
		s, _, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {err: errors.New("connection lost"), applies: true}})
		res, err := Run(context.Background(), s.opts, tr, v)
		wantRevoked(t, res, err)
		if res.LeftoverToken != "" || !tr.reconnectSession.ran("pveum user token remove") || tr.reconnectSession.pve.has(heldID) {
			t.Fatalf("the fresh token was not removed: %+v, %v", res, tr.reconnectSession.commands)
		}
	})
	t.Run("that remove fails: leftover", func(t *testing.T) {
		s, _, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {err: errors.New("connection lost"), applies: true}})
		tr.reconnectSession.byCmd = map[string]fakeRunResult{"pveum user token remove": {res: RunResult{ExitCode: 1}}}
		res, err := Run(context.Background(), s.opts, tr, v)
		wantRevoked(t, res, err)
		if res.LeftoverToken != heldID || res.LeftoverState != LeftoverExists {
			t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
		}
	})
	t.Run("re-read unreadable: may exist", func(t *testing.T) {
		s, _, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {err: errors.New("connection lost"), applies: true}})
		tr.reconnectErrs = []error{nil, errors.New("no route")}
		res, err := Run(context.Background(), s.opts, tr, v)
		wantRevoked(t, res, err)
		// The id alone; the uncertainty is its own field.
		if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
			t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
		}
	})
}

// R10c: the clear fails after the remove: abort before the add;
// stale_revoked.
func TestRun_R10c_ClearFailsAfterRemove(t *testing.T) {
	s, session, tr, v := prior(t, nil)
	session.byCmd = map[string]fakeRunResult{"pveum user token remove": {onRun: func(context.Context, string) { duplicateTargetBlock(t, s.path) }}}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.RosterToken != RosterTokenStaleRevoked || session.ran("pveum user token add") {
		t.Fatalf("result = %+v, commands = %v", res, session.commands)
	}
}

// R11 / R12: parse or grant fails after the remove: the fresh token is
// removed (a second remove).
func TestRun_R11_R12_ParseOrGrantFails(t *testing.T) {
	for name, byCmd := range map[string]map[string]fakeRunResult{
		"parse": {"pveum user token add": {res: RunResult{Stdout: "not json"}}},
		"grant": {"pveum acl modify": {res: RunResult{ExitCode: 1, Stderr: "no such role"}}},
	} {
		t.Run(name, func(t *testing.T) {
			s, session, tr, v := prior(t, byCmd)
			res, err := Run(context.Background(), s.opts, tr, v)
			wantRevoked(t, res, err)
			if session.count("pveum user token remove") != 2 || session.pve.has(heldID) {
				t.Fatalf("want the prior remove and the fresh remove, got %v", session.commands)
			}
		})
	}
}

// ---- R13: post-mint validation ----

// R13 / R13′: a post-mint ErrScopeTooWide is a verdict at once: never
// retried ("too wide" cannot be lag), never persisted, the fresh token
// removed. The retried verdicts are R13i-R13l.
func TestRun_R13_PostMintVerdict(t *testing.T) {
	t.Run("with a prior remove", func(t *testing.T) {
		s, session, tr, v := prior(t, nil, fmt.Errorf("%w", ErrScopeTooWide))
		res, err := Run(context.Background(), s.opts, tr, v)
		wantRevoked(t, res, err)
		if res.Validation != ValidationFailed || v.calls != 2 || session.count("pveum user token remove") != 2 {
			t.Fatalf("result = %+v, calls = %d, commands = %v", res, v.calls, session.commands)
		}
		noToken(t, s.path)
	})
	t.Run("first mint (R13b)", func(t *testing.T) {
		path := newTestRoster(t, "")
		session := &fakeSession{}
		v := &fakeValidator{err: fmt.Errorf("%w", ErrScopeTooWide)}
		res, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
		if err == nil || res.TokenOutcome != OutcomeDiscarded || res.Validation != ValidationFailed || v.calls != 1 {
			t.Fatalf("result = %+v, calls = %d, err = %v", res, v.calls, err)
		}
		noToken(t, path)
	})
}

// R13c-R13g, R14: the bounded retry loop, on a first mint.
func TestRun_R13_PostMintRetryLoop(t *testing.T) {
	fastRetries(t)
	plain := errors.New("dial tcp: connection refused")
	na := fmt.Errorf("%w", ErrNotAuthorized)
	ws := fmt.Errorf("%w", ErrWrongScope)
	ng := fmt.Errorf("%w", ErrNoGrants)
	tw := fmt.Errorf("%w", ErrScopeTooWide)
	for name, tc := range map[string]struct {
		errs       []error
		calls      int
		validation string
		persisted  bool
	}{
		"R13c 401 then OK":              {[]error{na, nil}, 2, ValidationVerified, true},
		"R13d 401 x3 (x4 then nil)":     {[]error{na, na, na, na, nil}, 3, ValidationFailed, false},
		"R13e 401 then plain twice":     {[]error{na, plain, plain}, 3, ValidationFailed, false},
		"R13f 401, plain, OK":           {[]error{na, plain, nil}, 3, ValidationVerified, true},
		"R13g 401 then a non-retryable": {[]error{na, tw}, 2, ValidationFailed, false},
		"R13i WrongScope then OK":       {[]error{ws, nil}, 2, ValidationVerified, true},
		"R13j NoGrants then OK":         {[]error{ng, nil}, 2, ValidationVerified, true},
		"R13k WrongScope x3 (then nil)": {[]error{ws, ws, ws, nil}, 3, ValidationFailed, false},
		"R13l 401 then TooWide stops":   {[]error{na, tw, nil}, 2, ValidationFailed, false},
		"R13m NoGrants, plain, OK":      {[]error{ng, plain, nil}, 3, ValidationVerified, true},
		"R14 plain first: not retried":  {[]error{plain}, 1, ValidationUnverified, true},
	} {
		t.Run(name, func(t *testing.T) {
			path := newTestRoster(t, "")
			v := &fakeValidator{errs: tc.errs}
			res, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}, v)
			if v.calls != tc.calls || res == nil || res.Validation != tc.validation {
				t.Fatalf("calls = %d (want %d), result = %+v, err = %v", v.calls, tc.calls, res, err)
			}
			if tok := rosterToken(t, path); (tok != nil) != tc.persisted {
				t.Fatalf("persisted = %v, want %v", tok != nil, tc.persisted)
			}
			if tc.validation == ValidationUnverified && err == nil {
				t.Fatal("an unverified persist must still exit non-zero")
			}
		})
	}
}

// R13h: the command context is cancelled inside the retry delay, after a
// retryable verdict was seen. The verdict stands: the secret PVE rejected is
// never persisted, and the fresh token is removed.
func TestRun_R13h_CancelInRetryDelayKeepsTheVerdict(t *testing.T) {
	orig := postMintRetryDelay
	postMintRetryDelay = 200 * time.Millisecond
	t.Cleanup(func() { postMintRetryDelay = orig })
	for name, prior := range map[string]bool{"first mint": false, "with a prior remove": true} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var path string
			var opts Options
			var session *fakeSession
			var tr *fakeTransport
			postMint := 0
			errs := []error{fmt.Errorf("%w", ErrNotAuthorized), nil}
			if prior {
				s := seedRoster(t, heldID, "")
				path, opts = s.path, s.opts
				session = &fakeSession{pve: newFakePVE("pveforge")}
				tr = &fakeTransport{session: session}
				postMint = 1
				errs = append([]error{fmt.Errorf("%w", ErrNoGrants)}, errs...)
			} else {
				path = newTestRoster(t, "")
				opts = baseOptions(path)
				session = &fakeSession{pve: newFakePVE()}
				tr = &fakeTransport{installFingerprint: "SHA256:abc", session: session}
			}
			v := &fakeValidator{errs: errs, onCall: func(call int) {
				if call == postMint { // cancel 50ms into the 200ms delay after this 401
					time.AfterFunc(50*time.Millisecond, cancel)
				}
			}}
			res, err := Run(ctx, opts, tr, v)
			if err == nil || res == nil || res.Validation != ValidationFailed {
				t.Fatalf("want a verdict, got %+v, %v", res, err)
			}
			if !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("the error must carry the verdict: %v", err)
			}
			if v.calls != postMint+1 {
				t.Fatalf("validator calls = %d, want %d", v.calls, postMint+1)
			}
			noToken(t, path)
			if session.pve.has(heldID) {
				t.Fatalf("the fresh token was not removed: %v", session.commands)
			}
			if prior {
				wantRevoked(t, res, err)
			} else if res.TokenOutcome != OutcomeDiscarded {
				t.Fatalf("outcome = %q, want discarded", res.TokenOutcome)
			}
		})
	}
}

// R14b: a plain post-mint error after a prior remove: persisted, unverified,
// replaced, and still an error.
func TestRun_R14b_UnverifiedAfterRemove(t *testing.T) {
	s, _, tr, v := prior(t, nil, errors.New("dial tcp: refused"))
	res, err := Run(context.Background(), s.opts, tr, v)
	if err == nil || res.TokenOutcome != OutcomeReplaced || res.Validation != ValidationUnverified || errors.Is(err, ErrPriorTokenRevoked) {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if persistedSecret(t, s) != fakeDefaultSecret {
		t.Fatal("the fresh token was not persisted")
	}
}

// R15: WriteTokenAuth fails: the fresh token is removed.
func TestRun_R15_PersistFails(t *testing.T) {
	s, session, tr, v := prior(t, nil, nil)
	v.onCall = func(call int) {
		if call == 1 { // the post-mint validation, right before the persist
			duplicateTargetBlock(t, s.path)
		}
	}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if session.count("pveum user token remove") != 2 {
		t.Fatalf("the fresh token was not removed: %v", session.commands)
	}
}

// R16: persistTargetMeta fails after the token is persisted: replaced, and
// an error.
func TestRun_R16_MetaPersistFails(t *testing.T) {
	orig := persistTargetMetaFn
	persistTargetMetaFn = func(Options) error { return errors.New("meta write failed") }
	t.Cleanup(func() { persistTargetMetaFn = orig })
	s, _, tr, v := prior(t, nil, nil)
	res, err := Run(context.Background(), s.opts, tr, v)
	if err == nil || res.TokenOutcome != OutcomeReplaced || res.Validation != ValidationVerified {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if persistedSecret(t, s) != fakeDefaultSecret {
		t.Fatal("not persisted")
	}
}

// R17: the cleanup remove of the fresh token fails: leftover_token.
func TestRun_R17_CleanupRemoveFails(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {res: RunResult{ExitCode: 1, Stderr: "busy"}}}}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverExists {
		t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
	}
}

// R17b: the cleanup remove of the fresh token hits a transport error and
// the re-read cannot reach PVE: leftover_token is the bare id, and
// leftover_state says it may exist.
func TestRun_R17b_CleanupRemoveUnknownMayExist(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {err: errors.New("connection lost")}}}
	tr.reconnectErrs = []error{nil, errors.New("no route")}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
		t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
	}
}

// R17c: the cleanup remove exits non-zero and the re-read (on the working
// session) cannot read the token list: may_exist, never a bare "exists".
func TestRun_R17c_CleanupRemoveRefusedReReadUnreadable(t *testing.T) {
	var session *fakeSession
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}, onRun: func(context.Context, string) {
		// After the preflight's read: every later token list fails.
		session.byCmd["pveum user token list"] = fakeRunResult{res: RunResult{ExitCode: 1, Stderr: "timeout"}}
	}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {res: RunResult{ExitCode: 1, Stderr: "busy"}}}}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
		t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
	}
	if tr.reconnectCalls != 1 {
		t.Fatalf("reconnects = %d, want 1 (the run's own): a refused remove leaves the session working", tr.reconnectCalls)
	}
}

// R17d: the cleanup remove exits non-zero but the token is gone (PVE
// reports it missing): the re-read finds it absent, so no leftover is
// reported.
func TestRun_R17d_CleanupRemoveRefusedButGone(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {res: RunResult{ExitCode: 2, Stderr: "no such token"}, applies: true}}}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != "" || res.LeftoverState != "" || session.pve.has(heldID) {
		t.Fatalf("leftover = %q (%q), tokens = %v", res.LeftoverToken, res.LeftoverState, session.pve.tokens)
	}
	if strings.Contains(err.Error(), "left the token behind") {
		t.Fatalf("a gone token reported as left behind: %v", err)
	}
}

// ---- R18: cleanup contexts ----

// R18: the command context is cancelled during the add (whose effect lands
// on PVE): the re-read and the cleanup remove still run and SUCCEED, which
// only a context.WithoutCancel cleanup allows.
func TestRun_R18_CleanupSurvivesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := newTestRoster(t, "")
	pve := newFakePVE()
	session := &fakeSession{pve: pve, byCmd: map[string]fakeRunResult{"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("x")}, onRun: func(context.Context, string) {
		pve.put(heldID) // it ran on the host...
		cancel()        // ...and then the command context died
	}}}}
	fresh := &fakeSession{pve: pve}
	res, err := Run(ctx, baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: session, reconnectSession: fresh}, &fakeValidator{})
	if err == nil || res == nil || res.LeftoverToken != "" {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if !fresh.ran("pveum user token remove") || pve.has(heldID) {
		t.Fatalf("the cleanup remove did not succeed: %v / attempted %v", fresh.commands, fresh.attempted)
	}
}

// R18b: each cleanup step gets a FRESH budget: a slow forward phase cannot
// consume the cleanup's time.
func TestRun_R18b_FreshBudgetPerCleanupStep(t *testing.T) {
	withCleanupTimeout(t, 200*time.Millisecond)
	fastRetries(t)
	slow := func(context.Context, string) { time.Sleep(250 * time.Millisecond) }
	s, session, tr, v := prior(t, map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("x")}, onRun: slow},
		"pveum acl modify":     {onRun: slow},
	}, fmt.Errorf("%w", ErrWrongScope))
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != "" || session.count("pveum user token remove") != 2 {
		t.Fatalf("the cleanup remove did not get its own budget: %+v, %v", res, session.commands)
	}
}

// R18c: a cleanup step slower than its budget is abandoned: leftover, and
// the error names the timeout.
func TestRun_R18c_CleanupStepTimesOut(t *testing.T) {
	withCleanupTimeout(t, 100*time.Millisecond)
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	removes := 0
	block := func(ctx context.Context, cmd string) {
		if !strings.HasPrefix(cmd, "pveum user token remove") {
			return
		}
		removes++
		if removes == 2 { // the cleanup remove of the fresh token
			select {
			case <-time.After(3 * time.Second):
				t.Error("the cleanup step did not time out")
			case <-ctx.Done():
			}
		}
	}
	session.onRun = block
	start := time.Now()
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverExists || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("leftover = %q (%q), err = %v", res.LeftoverToken, res.LeftoverState, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the run waited far beyond the cleanup budget")
	}
}

// ---- RV: the classification tables ----

func TestIsVerdict_RV1(t *testing.T) {
	for e, want := range map[error]bool{
		ErrNoGrants: true, ErrWrongScope: true, ErrNotAuthorized: true, ErrScopeTooWide: true,
		fmt.Errorf("wrapped: %w", ErrNoGrants): true, fmt.Errorf("w: %w", ErrScopeTooWide): true,
		ErrOwnerLacksPrivileges: false, ErrOwnerDisabled: false, ErrRoleHasNoPrivileges: false, ErrInvalidGrant: false,
		errors.New("plain"): false, errors.New("unverifiable read"): false, context.DeadlineExceeded: false,
	} {
		if got := isVerdict(e); got != want {
			t.Errorf("isVerdict(%v) = %v, want %v", e, got, want)
		}
	}
}

func TestPostMintRetryable_RV2(t *testing.T) {
	for e, want := range map[error]bool{
		ErrNotAuthorized: true, fmt.Errorf("w: %w", ErrNotAuthorized): true,
		ErrNoGrants: true, ErrWrongScope: true, fmt.Errorf("w: %w", ErrWrongScope): true,
		ErrScopeTooWide: false, fmt.Errorf("w: %w", ErrScopeTooWide): false, // never: "too wide" cannot be lag
		errors.New("plain"): false, context.DeadlineExceeded: false,
	} {
		if got := postMintRetryable(e); got != want {
			t.Errorf("postMintRetryable(%v) = %v, want %v", e, got, want)
		}
	}
}

// MR1's guard: the verdict sentinels are referenced in this package's
// non-test code only where they are declared (deps.go's aliases) and in the
// two classification slices; the slices only in their declarations and in
// isVerdict/postMintRetryable. A classification that bypasses the tables
// (an inline errors.Is against a sentinel) turns this red.
func TestVerdictSentinelsOnlyReachedThroughTheTables(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	sentinels := map[string]bool{"ErrNoGrants": true, "ErrWrongScope": true, "ErrNotAuthorized": true, "ErrScopeTooWide": true}
	tables := map[string]bool{"verdictSentinels": true, "postMintRetrySentinels": true}
	allowedFuncs := map[string]bool{"isVerdict": true, "postMintRetryable": true}
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					declaring := ""
					for _, n := range vs.Names {
						if sentinels[n.Name] || tables[n.Name] {
							declaring = n.Name
						}
					}
					ast.Inspect(vs, func(n ast.Node) bool {
						id, ok := n.(*ast.Ident)
						if !ok || id.Name == declaring {
							return true
						}
						if sentinels[id.Name] && !tables[declaring] {
							t.Errorf("%s: %s referenced in a declaration other than the classification tables", fset.Position(id.Pos()), id.Name)
						}
						if tables[id.Name] {
							t.Errorf("%s: %s referenced outside isVerdict/postMintRetryable", fset.Position(id.Pos()), id.Name)
						}
						return true
					})
				}
			case *ast.FuncDecl:
				ast.Inspect(d, func(n ast.Node) bool {
					id, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					if sentinels[id.Name] {
						t.Errorf("%s: %s referenced in %s; classify only through isVerdict/postMintRetryable", fset.Position(id.Pos()), id.Name, d.Name.Name)
					}
					if tables[id.Name] && !allowedFuncs[d.Name.Name] {
						t.Errorf("%s: %s referenced in %s", fset.Position(id.Pos()), id.Name, d.Name.Name)
					}
					return true
				})
			}
		}
	}
	if parsed < 3 {
		t.Fatalf("parsed only %d non-test files; the guard would be vacuous", parsed)
	}
}
