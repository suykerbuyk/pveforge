package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// ---- U-B: the token's OWNER is split from the SSH login ----

// aliceOwner is a non-root token owner; the SSH login stays root@pam,
// because pveum refuses to run as anyone else (R20g).
const aliceOwner = "alice@pve"

// ownerRoles answers pveum role list for baseOptions' PVEVMAdmin grant,
// and aliceCovers is an owner holding that role's whole privilege set.
const ownerRoles = `[{"privs":"VM.Allocate","roleid":"PVEVMAdmin","special":1}]`

func aliceCovers() fakeRunResult { return perms(`{"/":{"VM.Allocate":1}}`) }

func ownerSession(byCmd map[string]fakeRunResult, pve *fakePVE) *fakeSession {
	cmds := map[string]fakeRunResult{
		"pveum role list":        {res: RunResult{Stdout: ownerRoles}},
		"pveum user list":        perms(userList(aliceOwner, 1, 0)),
		"pveum user permissions": aliceCovers(),
	}
	for k, r := range byCmd {
		cmds[k] = r
	}
	return &fakeSession{pve: pve, byCmd: cmds}
}

// B-T1: every pveum command that names a principal names the OWNER, while
// the SSH session is the login's (MB1, MB3a, MB4, MB6, MB12, MB14).
func TestRun_BT1_OwnerAndLoginAreSplit(t *testing.T) {
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	opts.TokenOwner = aliceOwner
	session := ownerSession(nil, nil)
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	v := &fakeValidator{}

	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenID != aliceOwner+"!pveforge" || v.lastCfg.TokenID != aliceOwner+"!pveforge" {
		t.Fatalf("token id = %q / %q", res.TokenID, v.lastCfg.TokenID)
	}
	for _, want := range []string{
		"pveum user token list '" + aliceOwner + "' --output-format json",
		"pveum user token add '" + aliceOwner + "' 'pveforge' --privsep 1 --output-format json",
		"pveum user permissions '" + aliceOwner + "' --path '/' --output-format json",
		"pveum acl modify '/' --tokens '" + aliceOwner + "!pveforge' --roles 'PVEVMAdmin' --propagate 1",
	} {
		if !contains(session.commands, want) {
			t.Errorf("missing issued command %q; got %v", want, session.commands)
		}
	}
	// No pveum command may name the login as a principal.
	for _, c := range session.commands {
		if strings.Contains(c, "'root@pam'") {
			t.Errorf("a command addressed the login, not the owner: %q", c)
		}
	}
	// The SSH side is still the login.
	if tr.installCalls != 1 || session.pve.hasName("root@pam", "pveforge") {
		t.Fatalf("installs = %d, tokens = %v", tr.installCalls, session.pve.tokens)
	}
	if !session.pve.hasName(aliceOwner, "pveforge") {
		t.Fatal("the token was not created for the owner")
	}
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tg := r.Find(opts.TargetID)
	if tg.Token == nil || tg.Token.ID != aliceOwner+"!pveforge" || tg.SSH == nil || tg.SSH.User != "root" {
		t.Fatalf("roster token = %+v, ssh user = %+v", tg.Token, tg.SSH)
	}
}

// B-T2b (MB3b): after an ambiguous add, the CLEANUP re-read asks about the
// OWNER's tokens, which is what decides LeftoverToken/LeftoverState.
func TestRun_BT2b_CleanupRereadNamesTheOwner(t *testing.T) {
	s := seedRoster(t, aliceOwner+"!pveforge", "")
	s.opts.TokenOwner = aliceOwner
	pve := newFakePVEFor(aliceOwner, "pveforge")
	session := ownerSession(map[string]fakeRunResult{
		"pveum user token add": {err: errors.New("connection lost"), applies: true},
	}, pve)
	fresh := ownerSession(nil, pve)
	tr := &fakeTransport{session: session, reconnectSession: fresh}
	v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants), nil}}

	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if !contains(fresh.commands, "pveum user token list '"+aliceOwner+"' --output-format json") {
		t.Fatalf("the cleanup re-read did not name the owner: %v", fresh.commands)
	}
	if res.LeftoverToken != "" || pve.hasName(aliceOwner, "pveforge") {
		t.Fatalf("the fresh token was not removed: %+v, %v", res, fresh.commands)
	}
}

// B-T5: a DELIBERATE owner change orphans the held token and never removes
// it (MB7).
func TestRun_BT5_OwnerChangeOrphans(t *testing.T) {
	s := seedRoster(t, heldID, "") // root@pam!pveforge
	s.opts.TokenOwner = aliceOwner
	pve := newFakePVE(heldID)
	session := ownerSession(nil, pve)
	v := &fakeValidator{}

	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeMinted || res.OrphanedToken != heldID || res.TokenID != aliceOwner+"!pveforge" {
		t.Fatalf("result = %+v", res)
	}
	if session.ran("pveum user token remove") {
		t.Fatalf("the previous owner's token was removed: %v", session.commands)
	}
	if !pve.has(heldID) || !pve.hasName(aliceOwner, "pveforge") {
		t.Fatalf("tokens = %v; want both the orphan and the new one", pve.tokens)
	}
	if !contains(session.commands, "pveum user token list '"+aliceOwner+"' --output-format json") {
		t.Fatalf("the token list did not name the new owner: %v", session.commands)
	}
	if tok := rosterToken(t, s.path); tok == nil || tok.ID != aliceOwner+"!pveforge" {
		t.Fatalf("roster token = %+v", tok)
	}
}

// B-T5b (MB9a): the new owner already has a token of that name, which this
// roster does not hold: refused, and the hint names the OWNER.
func TestRun_BT5b_NotHeldHintNamesTheOwner(t *testing.T) {
	s := seedRoster(t, heldID, "")
	s.opts.TokenOwner = aliceOwner
	pve := newFakePVE(heldID, aliceOwner+"!pveforge")
	session := ownerSession(nil, pve)

	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if !errors.Is(err, ErrTokenNotHeld) || !strings.Contains(err.Error(), "pveum user token remove '"+aliceOwner+"' 'pveforge'") {
		t.Fatalf("want ErrTokenNotHeld with an owner-named hint, got %v", err)
	}
	if len(session.mutating()) != 0 {
		t.Fatalf("token commands issued: %v", session.commands)
	}
}

// B-T5e (MB9b): the undecryptable hint names the OWNER too.
func TestRun_BT5e_UndecryptableHintNamesTheOwner(t *testing.T) {
	s := seedRoster(t, aliceOwner+"!pveforge", "another-passphrase")
	s.opts.TokenOwner = aliceOwner
	session := ownerSession(nil, newFakePVEFor(aliceOwner, "pveforge"))

	_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
	if !errors.Is(err, ErrTokenUndecryptable) || !strings.Contains(err.Error(), "pveum user token remove '"+aliceOwner+"' 'pveforge'") {
		t.Fatalf("want ErrTokenUndecryptable with an owner-named hint, got %v", err)
	}
	if len(session.mutating()) != 0 {
		t.Fatalf("token commands issued: %v", session.commands)
	}
}

// bt5cRun runs a target whose roster holds heldTokenID (when non-empty)
// with the owner flag given or omitted, and reports what the transport saw.
func bt5cRun(t *testing.T, held, owner string, passphrase string) (*Result, error, *fakeTransport, []byte, string) {
	t.Helper()
	s := seedRoster(t, held, passphrase)
	s.opts.TokenOwner = owner
	before := rosterBytes(t, s.path)
	tr := &fakeTransport{session: ownerSession(nil, newFakePVE())}
	res, err := Run(context.Background(), s.opts, tr, &fakeValidator{})
	return res, err, tr, before, s.path
}

// assertOrdered requires each want to appear in s, in the given order. An
// empty want list passes trivially, so every caller must supply one.
func assertOrdered(t *testing.T, s string, want ...string) {
	t.Helper()
	at := 0
	for _, w := range want {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Errorf("missing %q (or out of order) in: %s", w, s)
			return
		}
		at += i + len(w)
	}
}

func noSSH(t *testing.T, tr *fakeTransport) {
	t.Helper()
	if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(tr.session.attempted) != 0 {
		t.Fatalf("SSH was touched: install=%d dial=%d reconnect=%d attempted=%v",
			tr.installCalls, tr.dialCalls, tr.reconnectCalls, tr.session.attempted)
	}
}

// B-T5c (MB16, MB18, MB18c, MB19): an ACCIDENTAL owner change — the roster
// holds another principal's token and no owner was given — is refused
// before any SSH, whatever the roster's secret does.
func TestRun_BT5c_AccidentalOwnerChangeRefused(t *testing.T) {
	// CR-B2: the two remedies must stay PAIRED with the right principal.
	// Swapped, the message tells the operator to pass the owner they are
	// drifting TO in order to "keep" the old token, and the held owner to
	// "change it deliberately" — following it would orphan the very token
	// the refusal exists to protect. The assertions are ORDERED substrings,
	// so presence alone cannot satisfy them.
	keepThenChange := []string{
		"--token-owner pveforge-harness@pve to keep addressing that principal",
		"--token-owner root@pam to change it deliberately",
	}
	for name, tc := range map[string]struct {
		held        string
		passphrase  string
		wantOrdered []string
	}{
		"a harness-owned token": {"pveforge-harness@pve!pveforge", "", keepThenChange},
		// MB18c: an undecryptable secret must not let the mismatch slip by;
		// the id alone decides, and it is read without decrypting.
		"and it will not decrypt": {"pveforge-harness@pve!pveforge", "another-passphrase", keepThenChange},
		// FO-B2: a held id with no "!" names no principal to offer back, so
		// the message says so and asks for one explicitly — suggesting
		// "--token-owner pveforge" would only earn a CheckTokenOwner refusal.
		"a hand-edited id with no owner": {"pveforge", "", []string{
			"which names no owner",
			"pass --token-owner explicitly, as name@realm",
		}},
		// FO-B5: an EMPTY owner part is the same shape — it must not take
		// the paired branch and print "--token-owner " with nothing after it.
		"a hand-edited id with an empty owner": {"!pveforge", "", []string{
			"which names no owner",
			"pass --token-owner explicitly, as name@realm",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			res, err, tr, before, path := bt5cRun(t, tc.held, "", tc.passphrase)
			if !errors.Is(err, ErrTokenOwnerMismatch) || res != nil || isVerdict(err) {
				t.Fatalf("want ErrTokenOwnerMismatch and no result, got %+v, %v", res, err)
			}
			if !strings.Contains(err.Error(), tc.held) {
				t.Errorf("the error does not name the held id %q: %v", tc.held, err)
			}
			assertOrdered(t, err.Error(), tc.wantOrdered...)
			// No suggestion may be one CheckTokenOwner would refuse: the
			// whole id (FO-B2), or an empty owner (FO-B5).
			if strings.Contains(err.Error(), "--token-owner pveforge ") || strings.Contains(err.Error(), "--token-owner  ") {
				t.Errorf("the message suggests an owner CheckTokenOwner would refuse: %v", err)
			}
			noSSH(t, tr)
			if !bytes.Equal(before, rosterBytes(t, path)) {
				t.Fatal("the roster changed")
			}
		})
	}
	// BF3: when the token NAME differs too, the message says so.
	t.Run("the token name differs too", func(t *testing.T) {
		s := seedRoster(t, "pveforge-harness@pve!build", "")
		tr := &fakeTransport{session: ownerSession(nil, newFakePVE())}
		_, err := Run(context.Background(), s.opts, tr, &fakeValidator{})
		if !errors.Is(err, ErrTokenOwnerMismatch) || !strings.Contains(err.Error(), `the roster holds "build"`) || !strings.Contains(err.Error(), `asks for "pveforge"`) {
			t.Fatalf("want both differences named, got %v", err)
		}
		noSSH(t, tr)
	})
	// BR3: a first bootstrap holds no token, so it can never refuse —
	// with the flag given or omitted.
	for name, owner := range map[string]string{"flag omitted": "", "flag given": aliceOwner} {
		t.Run("a first bootstrap, "+name, func(t *testing.T) {
			path := newTestRoster(t, "")
			opts := baseOptions(path)
			opts.TokenOwner = owner
			session := ownerSession(nil, nil)
			if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{}); err != nil {
				t.Fatalf("a first bootstrap must proceed: %v", err)
			}
		})
	}
}

// B-T5d (MB17): naming the owner explicitly keeps the deliberate
// behaviour — the held owner is orphaned, the same owner is reused.
func TestRun_BT5d_ExplicitOwnerIsNotRefused(t *testing.T) {
	t.Run("a different owner, explicitly: orphan and mint", func(t *testing.T) {
		s := seedRoster(t, "pveforge-harness@pve!pveforge", "")
		s.opts.TokenOwner = aliceOwner
		session := ownerSession(nil, newFakePVE("pveforge-harness@pve!pveforge"))
		res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
		if err != nil || res.TokenOutcome != OutcomeMinted || res.OrphanedToken != "pveforge-harness@pve!pveforge" {
			t.Fatalf("result = %+v, err = %v", res, err)
		}
		if session.ran("pveum user token remove") {
			t.Fatalf("a remove was issued: %v", session.commands)
		}
	})
	t.Run("the held owner, explicitly: the ordinary reuse path", func(t *testing.T) {
		s := seedRoster(t, aliceOwner+"!pveforge", "")
		s.opts.TokenOwner = aliceOwner
		session := ownerSession(nil, newFakePVEFor(aliceOwner, "pveforge"))
		res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{})
		if err != nil || res.TokenOutcome != OutcomeReused {
			t.Fatalf("result = %+v, err = %v", res, err)
		}
	})
}

// B-T6 (MB5): CheckTokenOwner, directly and through Run.
func TestCheckTokenOwner_BT6(t *testing.T) {
	for _, ok := range []string{"root@pam", aliceOwner, "a.b-c_d@pve", "pveforge-harness@pve", "host$@ad", "first+last@ldap", "user@pve-lab"} {
		if err := CheckTokenOwner(ok); err != nil {
			t.Errorf("CheckTokenOwner(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"alice", "a!b@pve", "a:b@pve", "a/b@pve", "a b@pve", "@pve", "a@", "a@@b", "a@1pve", "a@p", ""} {
		err := CheckTokenOwner(bad)
		if !errors.Is(err, ErrInvalidTokenOwner) || strings.ContainsAny(err.Error(), "\n\r") {
			t.Errorf("CheckTokenOwner(%q) = %v, want ErrInvalidTokenOwner on one line", bad, err)
		}
	}
	// Through Run: refused before any SSH.
	opts := baseOptions(newTestRoster(t, ""))
	opts.TokenOwner = "a!b@pve"
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); !errors.Is(err, ErrInvalidTokenOwner) {
		t.Fatalf("Run: want ErrInvalidTokenOwner, got %v", err)
	}
	noSSH(t, tr)
}

// B-T7 (MB8): the whole-role invariant. A non-root owner narrower than the
// role is refused before anything is removed — even though the validator
// alone would accept the token PVE's intersection would produce (the plan
// review's probe P4).
func TestRun_BT7_OwnerMustHoldTheWholeRole(t *testing.T) {
	const roles = `[{"privs":"A1,A2","roleid":"RoleA","special":0}]`
	grants := []Grant{{Path: "/pool/p", Role: "RoleA"}}
	pinned := []Grant{{Path: "/pool/p", Role: "RoleA", Privs: []string{"A1"}}}
	for name, tc := range map[string]struct {
		grants []Grant
		want   error
		names  string
	}{
		"unpinned: the owner lacks A2":          {grants, ErrOwnerLacksPrivileges, "lacks [A2]"},
		"pinned to the intersection: not equal": {pinned, ErrPinnedPrivsMismatch, "at /pool/p"},
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, aliceOwner+"!pveforge", "")
			s.opts.TokenOwner = aliceOwner
			s.opts.Grants = tc.grants
			before := rosterBytes(t, s.path)
			session := ownerSession(map[string]fakeRunResult{
				"pveum role list":        {res: RunResult{Stdout: roles}},
				"pveum user permissions": perms(`{"/pool/p":{"A1":1}}`),
			}, newFakePVEFor(aliceOwner, "pveforge"))
			v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrWrongScope), nil}}
			_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
			if !errors.Is(err, tc.want) || isVerdict(err) || !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("want %v naming %q (not a verdict), got %v", tc.want, tc.names, err)
			}
			if v.calls != 0 || len(session.mutating()) != 0 || !bytes.Equal(before, rosterBytes(t, s.path)) {
				t.Fatalf("the run got past the pre-remove checks: calls=%d commands=%v", v.calls, session.commands)
			}
		})
	}
}

// B-ACC: the nested harness's four D5 grants, owned by the harness user,
// generated from the pinned D5 r3 fixtures. U-A could assert only the token
// NAME; here every issued command carries the fixture's full ugid.
func TestRun_BACC_D5GrantsUnderTheHarnessOwner(t *testing.T) {
	rows, grants, specs, roleList := d5Fixture(t, "")
	owner, _, _ := strings.Cut(rows[0].UGID, "!")
	if owner != "pveforge-harness@pve" {
		t.Fatalf("fixture owner = %q", owner)
	}
	opts := baseOptions(newTestRoster(t, ""))
	opts.TokenOwner = owner
	opts.TokenID = "build"
	opts.Grants = mustParse(t, specs...)

	// The owner holds each role's whole privilege set at its own path.
	ownerPerms := map[string]fakeRunResult{}
	for _, g := range grants {
		set := make([]string, 0, len(g.Privs))
		for _, p := range g.Privs {
			set = append(set, fmt.Sprintf("%q:1", p))
		}
		ownerPerms["pveum user permissions '"+owner+"' --path '"+g.Path+"'"] = perms(fmt.Sprintf(`{%q:{%s}}`, g.Path, strings.Join(set, ",")))
	}
	byCmd := map[string]fakeRunResult{
		"pveum role list": {res: RunResult{Stdout: roleList}},
		"pveum user list": perms(userList(owner, 1, 0)),
	}
	for k, v := range ownerPerms {
		byCmd[k] = v
	}
	session := &fakeSession{byCmd: byCmd}
	v := &fakeValidator{}

	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var wantCmds []string
	for _, r := range rows {
		wantCmds = append(wantCmds, fmt.Sprintf("pveum acl modify '%s' --tokens '%s' --roles '%s' --propagate %d", r.Path, r.UGID, r.RoleID, r.Propagate))
	}
	if got := aclCommands(session); !reflect.DeepEqual(got, wantCmds) {
		t.Fatalf("acl commands:\n got %q\nwant %q", got, wantCmds)
	}
	if !contains(session.commands, "pveum user token add '"+owner+"' 'build' --privsep 1 --output-format json") {
		t.Fatalf("the token was not added for the harness owner: %v", session.commands)
	}
	if res.TokenID != owner+"!build" || len(v.wants) != 1 || !reflect.DeepEqual(v.wants[0], grants) {
		t.Fatalf("token id = %q, wants = %#v", res.TokenID, v.wants)
	}
	// One owner permission read per distinct grant path, naming the owner.
	if n := session.count("pveum user permissions '" + owner + "'"); n != len(grants) {
		t.Fatalf("owner permission reads = %d, want %d: %v", n, len(grants), session.commands)
	}
}
