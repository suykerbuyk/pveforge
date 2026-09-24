package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// ---- U-C: keyless mode (--no-ssh-key) ----

const keylessFP = "SHA256:keyless-tofu"

// keylessRoster returns a roster holding a target with NO [targets.ssh]
// block — the state a keyless bootstrap leaves — and, when tokenID is not
// empty, that token.
func keylessRoster(t *testing.T, tokenID string) (string, Options) {
	t.Helper()
	path := newTestRoster(t, "")
	opts := baseOptions(path)
	if err := roster.AppendTarget(path, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	if tokenID != "" {
		if err := roster.WriteTokenAuth(path, opts.TargetID, roster.TokenWrite{
			TokenID: tokenID, SecretPlaintext: []byte("held-secret"),
		}, opts.Passphrase); err != nil {
			t.Fatalf("WriteTokenAuth: %v", err)
		}
	}
	return path, opts
}

// dropFingerprint deletes the host_key_fingerprint line from a roster that
// HAS an SSH block: a hand edit that leaves the private key on file while
// loadExistingSSHAuth stops reporting usable auth.
func dropFingerprint(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := regexp.MustCompile(`(?m)^host_key_fingerprint = .*\n`).ReplaceAll(b, nil)
	if bytes.Equal(b, out) {
		t.Fatal("no host_key_fingerprint line to drop")
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reseedSSHUnderAnotherPassphrase rewrites the target's [targets.ssh]
// block encrypted with a DIFFERENT passphrase, so loadExistingSSHAuth
// would fail to decrypt it. The block itself is still plainly there.
func reseedSSHUnderAnotherPassphrase(t *testing.T, path string, opts Options) {
	t.Helper()
	kp, err := sshexec.GenerateEd25519Keypair("test-other")
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteSSHAuth(path, opts.TargetID, roster.SSHWrite{
		User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:abc", PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resealUnder(t, path, r.Find(opts.TargetID).SSH.PrivateKeyEnc, kp.PrivateKeyPEM, "a-different-passphrase")
}

func keylessTransport(session *fakeSession) *fakeTransport {
	return &fakeTransport{session: session, dialPWFingerprint: keylessFP, installFingerprint: "SHA256:abc"}
}

// C-T1: a keyless run installs nothing and persists nothing. The two
// observables are asserted SEPARATELY (FO-C3), so a one-site fix cannot
// pass: (a) no install/dial/reconnect call, (b) no SSH material in the
// roster bytes.
func TestRun_CT1_KeylessInstallsNothingAndPersistsNothing(t *testing.T) {
	path, opts := keylessRoster(t, "")
	opts.NoSSHKey = true
	session := &fakeSession{}
	tr := keylessTransport(session)
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The dial: once, trust-on-first-use, as the LOGIN (MK11), with the
	// run's password.
	if tr.dialPWCalls != 1 || !reflect.DeepEqual(tr.dialPWPins, []string{""}) {
		t.Fatalf("dialPW calls=%d pins=%q", tr.dialPWCalls, tr.dialPWPins)
	}
	if tr.dialPWUsers[0] != "root" || tr.dialPWPasswords[0] != opts.PVEPassword {
		t.Fatalf("dialed as %q with %q", tr.dialPWUsers[0], tr.dialPWPasswords[0])
	}
	// (a) no key path was touched.
	if tr.installCalls != 0 || tr.dialCalls != 0 || tr.reconnectCalls != 0 {
		t.Fatalf("a key path was used: install=%d dial=%d reconnect=%d", tr.installCalls, tr.dialCalls, tr.reconnectCalls)
	}
	// (b) no SSH material in the roster, while the token IS written.
	b := rosterBytes(t, path)
	if bytes.Contains(b, []byte("[targets.ssh]")) || bytes.Contains(b, []byte("private_key_enc")) {
		t.Fatalf("the roster holds SSH auth:\n%s", b)
	}
	if rosterToken(t, path).ID != "root@pam!pveforge" {
		t.Fatalf("the token was not persisted:\n%s", b)
	}
	// The accepted fingerprint is reported (MK9), and the pveum sequence is
	// the ordinary one.
	if res.TokenOutcome != OutcomeMinted || res.HostKeyFingerprint != keylessFP {
		t.Fatalf("result = %+v", res)
	}
	if !session.ran("pveum user token add 'root@pam' 'pveforge'") || !session.ran("pveum acl modify '/' --tokens 'root@pam!pveforge'") {
		t.Fatalf("commands = %v", session.commands)
	}
}

// C-T1b (FO-2): a capture that yields no fingerprint is refused. Accepting
// it would degrade this run's later redial to a SECOND trust-on-first-use
// and drop host_key_fingerprint from the rendered result, so a run could
// not be audited afterwards.
func TestRun_CT1b_KeylessRefusesAnEmptyFingerprint(t *testing.T) {
	path, opts := keylessRoster(t, "")
	opts.NoSSHKey = true
	session := &fakeSession{}
	tr := keylessTransport(session)
	tr.dialPWFingerprint = ""
	before := rosterBytes(t, path)
	res, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if err == nil || res != nil || !strings.Contains(err.Error(), "captured no host key fingerprint") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(session.attempted) != 0 {
		t.Fatalf("commands were attempted: %v", session.attempted)
	}
	if !bytes.Equal(before, rosterBytes(t, path)) {
		t.Fatal("the roster changed")
	}
}

// C-T2 (MK6, MK6b): a redial inside one keyless run is PINNED to the
// fingerprint that run captured, and re-authenticates with the same
// password (which is why Options.PVEPassword must outlive the first dial).
func TestRun_CT2_KeylessRedialIsPinnedToThisRun(t *testing.T) {
	path, opts := keylessRoster(t, "")
	opts.NoSSHKey = true
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {err: errors.New("connection lost")},
	}}
	fresh := &fakeSession{pve: session.state()}
	tr := keylessTransport(session)
	tr.reconnectSession = fresh
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err == nil {
		t.Fatal("want the add's transport error")
	}
	if tr.dialPWCalls != 2 {
		t.Fatalf("dialPW calls = %d, want the first dial and the re-read's redial", tr.dialPWCalls)
	}
	if tr.dialPWPins[1] != keylessFP {
		t.Fatalf("the redial's pin = %q, want this run's captured %q", tr.dialPWPins[1], keylessFP)
	}
	if tr.dialPWPasswords[1] != opts.PVEPassword {
		t.Fatalf("the redial's password = %q", tr.dialPWPasswords[1])
	}
	if !fresh.ran("pveum user token list 'root@pam'") {
		t.Fatalf("the re-read did not run on the fresh session: %v", fresh.commands)
	}
	if tr.reconnectCalls != 0 {
		t.Fatal("a keyless redial used the keyed reconnect")
	}
	_ = path
}

// C-T3 (F6, MK8): an authentication failure on the first dial is never
// redialed — freshSession only runs after a transport error on an
// already-authenticated session.
func TestRun_CT3_KeylessAuthFailureIsNotRedialed(t *testing.T) {
	path, opts := keylessRoster(t, "")
	opts.NoSSHKey = true
	session := &fakeSession{}
	tr := keylessTransport(session)
	tr.dialPWErr = errors.New("ssh: unable to authenticate")
	before := rosterBytes(t, path)
	res, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if err == nil || res != nil || !strings.Contains(err.Error(), "connect with password") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if tr.dialPWCalls != 1 {
		t.Fatalf("dialPW calls = %d, want exactly one attempt", tr.dialPWCalls)
	}
	if len(session.attempted) != 0 {
		t.Fatalf("commands were attempted: %v", session.attempted)
	}
	if !bytes.Equal(before, rosterBytes(t, path)) {
		t.Fatal("the roster changed")
	}
}

// keylessRefused runs opts and asserts the shape every pre-SSH refusal
// shares: no transport call, an unchanged roster, no result, not a verdict.
func keylessRefused(t *testing.T, opts Options, path string, sentinel error) error {
	t.Helper()
	before := rosterBytes(t, path)
	tr := keylessTransport(&fakeSession{})
	res, err := Run(context.Background(), opts, tr, &fakeValidator{})
	if !errors.Is(err, sentinel) || res != nil || isVerdict(err) {
		t.Fatalf("want %v and no result, got %+v, %v", sentinel, res, err)
	}
	if tr.dialPWCalls+tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 {
		t.Fatalf("SSH was touched: %+v", tr)
	}
	if !bytes.Equal(before, rosterBytes(t, path)) {
		t.Fatal("the roster changed")
	}
	return err
}

// C-T4 (MK5, MK10), C-T4b (MK5b), C-T4d (CHC2/FO-3): --no-ssh-key is
// refused for a target whose roster entry holds an SSH block — with or
// without a fingerprint, and whether or not that key can be decrypted,
// because a keypair on file is a credential either way.
//
// C-T4d is what pins the ORDER: the refusal runs before
// loadExistingSSHAuth, which decrypts. Moved below it, a wrong passphrase
// would report a decrypt error instead of this sentinel, so the refusal
// would depend on the passphrase — the opposite of what the plan requires.
func TestRun_CT4_KeylessRefusedWithAPersistedKey(t *testing.T) {
	for name, tc := range map[string]struct{ drop, undecryptable bool }{
		"a block with its fingerprint":        {},
		"C-T4b a block with no fingerprint":   {drop: true},
		"C-T4d a block that will not decrypt": {undecryptable: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, "", "")
			if tc.drop {
				dropFingerprint(t, s.path)
			}
			if tc.undecryptable {
				reseedSSHUnderAnotherPassphrase(t, s.path, s.opts)
			}
			s.opts.NoSSHKey = true
			err := keylessRefused(t, s.opts, s.path, ErrKeylessWithPersistedSSH)
			// R-C2: the remedy is this sentinel's OWN, in order.
			assertOrdered(t, err.Error(),
				"remove that target's [targets.ssh] block by hand to keep it keyless",
				"drop --no-ssh-key to keep using the stored key")
		})
	}
}

// C-T4c (R-C1, MK18a): identity is checked BEFORE transport. A target that
// holds an SSH block AND a token owned by another principal, re-run keyless
// with no --token-owner, reports the OWNER mismatch.
func TestRun_CT4c_OwnerMismatchBeatsTheKeylessRefusal(t *testing.T) {
	s := seedRoster(t, "pveforge-harness@pve!pveforge", "")
	s.opts.NoSSHKey = true
	err := keylessRefused(t, s.opts, s.path, ErrTokenOwnerMismatch)
	if errors.Is(err, ErrKeylessWithPersistedSSH) {
		t.Fatalf("the keyless refusal won over the owner one: %v", err)
	}
}

// C-T5 (MK12), C-T5b/c (MK13, MK14), C-T5d (MK18b), C-T5e (MK12b): the
// symmetric refusal, and everything it must NOT refuse.
func TestRun_CT5_KeylessTargetNeedsTheFlag(t *testing.T) {
	t.Run("a token and no SSH block, without the flag: refused", func(t *testing.T) {
		path, opts := keylessRoster(t, "root@pam!pveforge")
		err := keylessRefused(t, opts, path, ErrKeylessTargetNeedsFlag)
		assertOrdered(t, err.Error(),
			"pass --no-ssh-key to keep this target keyless",
			"remove its [targets.token] block by hand to re-bootstrap it with an SSH key")
	})
	t.Run("C-T5b the same with the flag: proceeds", func(t *testing.T) {
		path, opts := keylessRoster(t, "root@pam!pveforge")
		opts.NoSSHKey = true
		session := &fakeSession{pve: newFakePVE("root@pam!pveforge")}
		tr := keylessTransport(session)
		if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if tr.dialPWCalls != 1 {
			t.Fatalf("dialPW calls = %d", tr.dialPWCalls)
		}
		_ = path
	})
	t.Run("C-T5c a first bootstrap without the flag: proceeds down the key path", func(t *testing.T) {
		path, opts := keylessRoster(t, "")
		session := &fakeSession{}
		tr := keylessTransport(session)
		if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if tr.installCalls != 1 || tr.dialPWCalls != 0 {
			t.Fatalf("install=%d dialPW=%d", tr.installCalls, tr.dialPWCalls)
		}
		if !bytes.Contains(rosterBytes(t, path), []byte("[targets.ssh]")) {
			t.Fatal("the ordinary path did not persist SSH auth")
		}
	})
	t.Run("C-T5d the owner mismatch wins over this refusal too", func(t *testing.T) {
		path, opts := keylessRoster(t, "pveforge-harness@pve!pveforge")
		err := keylessRefused(t, opts, path, ErrTokenOwnerMismatch)
		if errors.Is(err, ErrKeylessTargetNeedsFlag) {
			t.Fatalf("the keyless refusal won over the owner one: %v", err)
		}
	})
	t.Run("C-T5e a fingerprint-less block is NOT a keyless target", func(t *testing.T) {
		s := seedRoster(t, heldID, "")
		dropFingerprint(t, s.path)
		session := &fakeSession{pve: newFakePVE(heldID)}
		tr := keylessTransport(session)
		_, err := Run(context.Background(), s.opts, tr, &fakeValidator{})
		if errors.Is(err, ErrKeylessTargetNeedsFlag) {
			t.Fatalf("a hand-edited fingerprint made a keyed target look keyless: %v", err)
		}
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if tr.installCalls != 1 {
			t.Fatalf("the ordinary re-bootstrap did not run: install=%d", tr.installCalls)
		}
	})
}

// C-T6 (CR-C3, MK7, MK7b): the password reaches none of the six places a
// reader or a machine could pick it up.
func TestRun_CT6_ThePasswordNeverLeaves(t *testing.T) {
	for name, fail := range map[string]bool{"a successful run": false, "a run that fails after the dial": true} {
		t.Run(name, func(t *testing.T) {
			path, opts := keylessRoster(t, "")
			opts.NoSSHKey = true
			opts.PVEPassword = "super-secret-pw"
			byCmd := map[string]fakeRunResult{}
			if fail {
				byCmd["pveum acl modify"] = fakeRunResult{res: RunResult{ExitCode: 1, Stderr: "nope"}}
			}
			session := &fakeSession{byCmd: byCmd}
			res, err := Run(context.Background(), opts, keylessTransport(session), &fakeValidator{})
			if fail == (err == nil) {
				t.Fatalf("err = %v", err)
			}
			pw := opts.PVEPassword
			if res != nil {
				if s := fmt.Sprintf("%+v", res); strings.Contains(s, pw) {
					t.Errorf("the password is in the Result: %s", s)
				}
			}
			if err != nil && strings.Contains(err.Error(), pw) {
				t.Errorf("the password is in the error: %v", err)
			}
			for _, c := range session.commands {
				if strings.Contains(c, pw) {
					t.Errorf("the password is in an issued command: %s", c)
				}
			}
			if bytes.Contains(rosterBytes(t, path), []byte(pw)) {
				t.Error("the password is in the roster")
			}
		})
	}
}

// C-ACC: the nested harness's four D5 grants, keyless, under the harness
// owner — generated from the same pinned fixtures as A-ACC and B-ACC.
func TestRun_CACC_D5GrantsKeylessUnderTheHarnessOwner(t *testing.T) {
	rows, grants, specs, roleList := d5Fixture(t, "")
	path, opts := keylessRoster(t, "")
	opts.TokenOwner = "pveforge-harness@pve"
	opts.TokenID = "build"
	opts.NoSSHKey = true
	opts.Grants = mustParse(t, specs...)
	byCmd := map[string]fakeRunResult{
		"pveum role list": {res: RunResult{Stdout: roleList}},
		"pveum user list": perms(userList("pveforge-harness@pve", 1, 0)),
	}
	// One answer per grant path: the owner holds that grant's whole role
	// there (the U-B invariant), and the reader requires the answer to be
	// keyed by exactly the path it asked for.
	for _, g := range grants {
		key := fmt.Sprintf("pveum user permissions 'pveforge-harness@pve' --path '%s'", g.Path)
		byCmd[key] = perms(d5OwnerPerms(g))
	}
	session := &fakeSession{byCmd: byCmd}
	tr := keylessTransport(session)
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var wantCmds []string
	for _, r := range rows {
		wantCmds = append(wantCmds, fmt.Sprintf("pveum acl modify '%s' --tokens '%s' --roles '%s' --propagate %d", r.Path, r.UGID, r.RoleID, r.Propagate))
	}
	var got []string
	for _, c := range session.commands {
		if strings.HasPrefix(c, "pveum acl modify") {
			got = append(got, c)
		}
	}
	if !reflect.DeepEqual(got, wantCmds) {
		t.Fatalf("acl commands:\n got %q\nwant %q", got, wantCmds)
	}
	if !session.ran("pveum user token add 'pveforge-harness@pve' 'build' --privsep 1") {
		t.Fatalf("commands = %v", session.commands)
	}
	if len(v.wants) != 1 || !reflect.DeepEqual(v.wants[0], grants) {
		t.Fatalf("wants = %#v", v.wants)
	}
	// The harness rule: no root SSH on the outer target.
	if tr.installCalls != 0 || bytes.Contains(rosterBytes(t, path), []byte("[targets.ssh]")) {
		t.Fatalf("install=%d roster:\n%s", tr.installCalls, rosterBytes(t, path))
	}
	if res.HostKeyFingerprint != keylessFP {
		t.Fatalf("the accepted fingerprint was not reported: %+v", res)
	}
}

// d5OwnerPerms answers `pveum user permissions <owner> --path <g.Path>` for
// an owner holding g's whole role there (the U-B invariant), keyed by
// exactly that path as the reader requires.
func d5OwnerPerms(g Grant) string {
	var b strings.Builder
	for _, p := range g.Privs {
		if b.Len() > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:0", p)
	}
	return fmt.Sprintf("{%q:{%s}}", g.Path, b.String())
}
