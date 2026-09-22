package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// fakePVE is the token state a fake PVE host holds, keyed by FULL token id
// ("<userid>!<name>"), the way real PVE holds it: `pveum user token list`
// answers per userid, and two principals may each own a token of the same
// name. It is shared between a run's original session and any session a
// reconnect returns, so a re-read sees what an add or remove did.
//
// Read it through has/hasName ONLY. Indexing tokens directly by a bare name
// silently asks about an id this map never holds, so the clause is false
// whether or not the token exists — an assertion that cannot fail.
type fakePVE struct {
	tokens map[string]bool
}

// fakeDefaultOwner is the owner newFakePVE's shorthand means, and the owner
// baseOptions bootstraps as.
const fakeDefaultOwner = "root@pam"

// newFakePVE seeds tokens. An entry containing "!" is a full id; a bare
// name is shorthand for fakeDefaultOwner's token of that name. Any test
// that involves another owner must pass full ids, or use newFakePVEFor.
func newFakePVE(present ...string) *fakePVE {
	p := &fakePVE{tokens: map[string]bool{}}
	for _, t := range present {
		if !strings.Contains(t, "!") {
			t = fakeDefaultOwner + "!" + t
		}
		p.tokens[t] = true
	}
	return p
}

// newFakePVEFor seeds names as tokens of owner, stating the owner where it
// matters instead of relying on the shorthand.
func newFakePVEFor(owner string, names ...string) *fakePVE {
	p := &fakePVE{tokens: map[string]bool{}}
	for _, n := range names {
		p.tokens[owner+"!"+n] = true
	}
	return p
}

// has reports whether the full token id exists on this fake host.
func (p *fakePVE) has(fullID string) bool { return p.tokens[fullID] }

// hasName reports whether owner holds a token of this name.
func (p *fakePVE) hasName(owner, name string) bool { return p.has(owner + "!" + name) }

// put marks the full token id as existing, for a test that has to seed
// state mid-run (an add whose effect landed on the host).
func (p *fakePVE) put(fullID string) { p.tokens[fullID] = true }

// fakeSession is a scriptable SSHSession. A command is answered by the
// longest byCmd prefix that matches it (deterministic, unlike map order);
// otherwise by the defaults below, which behave like a small PVE host:
// role list and /nodes answer for baseOptions, and token list/add/remove
// read and change pve's token state.
//
// Like sshexec.Client.Run it honours ctx: a command whose ctx is done on
// entry, or becomes done while an onRun hook runs, returns ctx.Err(). Such
// a command is recorded in attempted but not in commands.
type fakeSession struct {
	byCmd map[string]fakeRunResult
	// seq, per prefix, answers successive matching commands in order (the
	// first entry for the first call, ...); once a prefix's sequence is used
	// up, byCmd and the defaults answer. The longest matching prefix wins.
	seq       map[string][]fakeRunResult
	pve       *fakePVE
	onRun     func(ctx context.Context, cmd string) // runs inside every Run, before the answer
	closed    bool
	commands  []string
	attempted []string
}

type fakeRunResult struct {
	res RunResult
	err error
	// applies: the command's effect on pve (an add or a remove) happens
	// even though this result reports a failure (a transport error after
	// the command ran on the host).
	applies bool
	onRun   func(ctx context.Context, cmd string)
}

const fakeDefaultSecret = "fake-default-secret"

func (s *fakeSession) state() *fakePVE {
	if s.pve == nil {
		s.pve = newFakePVE()
	}
	return s.pve
}

// tokenFullID returns the full token id a pveum token command addresses:
// "pveum user token add|remove <userid> <name> ..." (fields 4 and 5),
// joined as real PVE identifies a token.
func tokenFullID(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) < 6 {
		return ""
	}
	return strings.Trim(f[4], "'") + "!" + strings.Trim(f[5], "'")
}

// tokenListUser returns the userid "pveum user token list <userid> ..."
// asks about (field 4).
func tokenListUser(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) < 5 {
		return ""
	}
	return strings.Trim(f[4], "'")
}

func (s *fakeSession) Run(ctx context.Context, cmd string) (RunResult, error) {
	s.attempted = append(s.attempted, cmd)
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	var match *fakeRunResult
	best := -1
	seqKey := ""
	for prefix, rs := range s.seq {
		if len(rs) > 0 && strings.HasPrefix(cmd, prefix) && len(prefix) > best {
			r := rs[0]
			match, best, seqKey = &r, len(prefix), prefix
		}
	}
	if seqKey != "" {
		s.seq[seqKey] = s.seq[seqKey][1:]
	} else {
		for prefix, r := range s.byCmd {
			if strings.HasPrefix(cmd, prefix) && len(prefix) > best {
				r := r
				match, best = &r, len(prefix)
			}
		}
	}
	if s.onRun != nil {
		s.onRun(ctx, cmd)
	}
	if match != nil && match.onRun != nil {
		match.onRun(ctx, cmd)
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	s.commands = append(s.commands, cmd)

	st := s.state()
	apply := func() {
		switch {
		case strings.HasPrefix(cmd, "pveum user token add"):
			st.tokens[tokenFullID(cmd)] = true
		case strings.HasPrefix(cmd, "pveum user token remove"):
			delete(st.tokens, tokenFullID(cmd))
		}
	}
	if match != nil {
		if (match.err == nil && match.res.ExitCode == 0) || match.applies {
			apply()
		}
		return match.res, match.err
	}
	switch {
	case strings.HasPrefix(cmd, "pveum role list"):
		return RunResult{Stdout: `[{"privs":"VM.Allocate","roleid":"PVEVMAdmin","special":1}]`}, nil
	case strings.HasPrefix(cmd, "pvesh get /nodes"):
		return RunResult{Stdout: `[{"node":"qa-pve-01","status":"online"}]`}, nil
	case strings.HasPrefix(cmd, "pveum user token list"):
		// Real pveum lists one userid's tokens, and prints each tokenid as
		// the bare name.
		prefix := tokenListUser(cmd) + "!"
		names := make([]string, 0, len(st.tokens))
		for id := range st.tokens {
			if n, ok := strings.CutPrefix(id, prefix); ok {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		var b strings.Builder
		b.WriteString("[")
		for i, n := range names {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"expire":0,"privsep":1,"tokenid":%q}`, n)
		}
		b.WriteString("]")
		return RunResult{Stdout: b.String()}, nil
	case strings.HasPrefix(cmd, "pveum user token add"):
		apply()
		return RunResult{Stdout: tokenAddJSON(fakeDefaultSecret)}, nil
	case strings.HasPrefix(cmd, "pveum user token remove"):
		apply()
		return RunResult{}, nil
	}
	return RunResult{ExitCode: 0}, nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

// ran reports whether a command with this prefix completed (is in commands).
func (s *fakeSession) ran(prefix string) bool { return s.count(prefix) > 0 }

func (s *fakeSession) count(prefix string) int {
	n := 0
	for _, c := range s.commands {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// mutating returns the token-changing commands the session ran.
func (s *fakeSession) mutating() []string {
	var out []string
	for _, c := range s.commands {
		if strings.HasPrefix(c, "pveum user token add") || strings.HasPrefix(c, "pveum user token remove") || strings.HasPrefix(c, "pveum acl modify") {
			out = append(out, c)
		}
	}
	return out
}

// fakeTransport is a scriptable SSHTransport.
type fakeTransport struct {
	installFingerprint string
	installErr         error
	dialErr            error
	reconnectErr       error
	// reconnectErrs, if set, overrides reconnectErr per call (0-indexed; a
	// call beyond its length reuses reconnectErr).
	reconnectErrs []error
	session       *fakeSession
	// reconnectSession, if set, is what ReconnectWithPinnedKey returns
	// (the fresh session after a transport error); otherwise session.
	reconnectSession *fakeSession

	installCalls            int
	dialCalls               int
	reconnectCalls          int
	installedKeyLines       []string // every authorizedKeyLine InstallPubkeyViaPassword was called with, in order
	reconnectedFingerprints []string // every hostKeyFingerprint ReconnectWithPinnedKey was called with, in order
	reconnectedAddrs        []string
	reconnectedKeys         [][]byte
}

func (t *fakeTransport) InstallPubkeyViaPassword(_ context.Context, addr, user, password, authorizedKeyLine string) (string, error) {
	t.installCalls++
	t.installedKeyLines = append(t.installedKeyLines, authorizedKeyLine)
	if t.installErr != nil {
		return "", t.installErr
	}
	return t.installFingerprint, nil
}

func (t *fakeTransport) DialWithKey(_ context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error) {
	t.dialCalls++
	if t.dialErr != nil {
		return nil, t.dialErr
	}
	return t.session, nil
}

func (t *fakeTransport) ReconnectWithPinnedKey(_ context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error) {
	idx := t.reconnectCalls
	t.reconnectCalls++
	t.reconnectedFingerprints = append(t.reconnectedFingerprints, hostKeyFingerprint)
	t.reconnectedAddrs = append(t.reconnectedAddrs, addr)
	t.reconnectedKeys = append(t.reconnectedKeys, append([]byte(nil), privateKeyPEM...))
	err := t.reconnectErr
	if idx < len(t.reconnectErrs) {
		err = t.reconnectErrs[idx]
	}
	if err != nil {
		return nil, err
	}
	// A reconnect is a FRESH session (after a transport error) when the run
	// already connected: by DialWithKey on a first bootstrap, or by an
	// earlier reconnect.
	if fresh := idx > 0 || t.dialCalls > 0; fresh && t.reconnectSession != nil {
		return t.reconnectSession, nil
	}
	return t.session, nil
}

// fakeValidator is a scriptable APIValidator.
type fakeValidator struct {
	err error
	// errs, if non-empty, overrides err on a per-call basis (0-indexed by
	// call number; a call beyond len(errs) reuses the last entry) — lets a
	// test script "first call fails, second call succeeds" for the
	// skip-recreate-then-fall-through path, without disturbing every
	// existing single-call test that only sets err.
	errs       []error
	calls      int
	lastCfg    APIConfig
	cfgsByCall []APIConfig // every cfg passed, in call order
	wants      [][]Grant   // every want passed, in call order
	// onCall, if set, runs at the start of each call (0-indexed): tests use
	// it to change the roster at an exact point in a run.
	onCall func(call int)
}

func (v *fakeValidator) ValidateTokenGrants(_ context.Context, cfg APIConfig, want []Grant) error {
	if v.onCall != nil {
		v.onCall(v.calls)
	}
	v.lastCfg = cfg
	v.wants = append(v.wants, want)
	v.cfgsByCall = append(v.cfgsByCall, cfg)
	err := v.err
	if len(v.errs) > 0 {
		idx := v.calls
		if idx >= len(v.errs) {
			idx = len(v.errs) - 1
		}
		err = v.errs[idx]
	}
	v.calls++
	return err
}

func newTestRoster(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test roster: %v", err)
	}
	return path
}

func baseOptions(rosterPath string) Options {
	return Options{
		TargetID:    "qa-pve-01",
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		PVEUsername: "root@pam",
		PVEPassword: "hunter2",
		TokenID:     "pveforge",
		// Today's effective grant, stated explicitly: there is no default
		// any more, and every Run test built on baseOptions keeps meaning
		// what it meant before bootstrap failed closed. A fail-closed test
		// clears it explicitly.
		Grants:     []Grant{{Path: "/", Role: "PVEVMAdmin", Propagate: true}},
		RosterPath: rosterPath,
		Passphrase: "roster-pass",
	}
}

func tokenAddJSON(secret string) string {
	return fmt.Sprintf(`{"full-tokenid":"root@pam!pveforge","info":{"privsep":"1"},"value":%q}`, secret)
}

func TestRun_HappyPath(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("tok-secret-123"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	res, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.HostKeyFingerprint != "SHA256:abc" {
		t.Errorf("unexpected host key fingerprint: %q", res.HostKeyFingerprint)
	}
	if res.TokenID != "root@pam!pveforge" {
		t.Errorf("unexpected token id: %q", res.TokenID)
	}
	if transport.installCalls != 1 || transport.dialCalls != 1 {
		t.Errorf("expected exactly one install and one dial, got install=%d dial=%d", transport.installCalls, transport.dialCalls)
	}
	if !session.closed {
		t.Error("expected the ssh session to be closed")
	}
	if validator.calls != 1 {
		t.Errorf("expected exactly one validation call, got %d", validator.calls)
	}
	if validator.lastCfg.TokenSecret != "tok-secret-123" {
		t.Errorf("validator did not receive the fresh token secret: %+v", validator.lastCfg)
	}

	// Roster now has the target with both auth types persisted.
	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load roster: %v", err)
	}
	tg := r.Find("qa-pve-01")
	if tg == nil {
		t.Fatal("target missing from roster")
	}
	if tg.Token == nil || tg.Token.ID != "root@pam!pveforge" {
		t.Fatalf("token auth not persisted correctly: %+v", tg.Token)
	}
	if tg.SSH == nil || tg.SSH.User != "root" || tg.SSH.HostKeyFingerprint != "SHA256:abc" {
		t.Fatalf("ssh auth not persisted correctly: %+v", tg.SSH)
	}
	plaintext, err := roster.DecryptString(tg.Token.SecretEnc, "roster-pass")
	if err != nil {
		t.Fatalf("decrypt persisted token secret: %v", err)
	}
	if string(plaintext) != "tok-secret-123" {
		t.Fatalf("persisted token secret = %q, want %q", plaintext, "tok-secret-123")
	}

	// R1: a first mint issues NO remove (the token list showed it absent):
	// removing blindly would revoke a same-named token another roster uses.
	if session.ran("pveum user token remove") || !session.ran("pveum user token add") {
		t.Errorf("expected an add and no remove, got: %v", session.commands)
	}
	if res.TokenOutcome != OutcomeMinted || res.Validation != ValidationVerified || res.PriorRevoked {
		t.Errorf("outcome = %q/%q prior_revoked=%v, want minted/verified/false", res.TokenOutcome, res.Validation, res.PriorRevoked)
	}
	// Preflight order: role list, nodes, token list, then the add.
	wantOrder := []string{"pveum role list", "pvesh get /nodes", "pveum user token list", "pveum user token add"}
	for i, w := range wantOrder {
		if i >= len(session.commands) || !strings.HasPrefix(session.commands[i], w) {
			t.Fatalf("command %d = %v, want prefix %q (all: %v)", i, session.commands, w, session.commands)
		}
	}
}

func TestRun_AppendsTargetWhenMissingFromRoster(t *testing.T) {
	rosterPath := newTestRoster(t, "") // empty roster: target does not exist yet
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:xyz", session: session}
	validator := &fakeValidator{}

	if _, err := Run(context.Background(), baseOptions(rosterPath), transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Find("qa-pve-01") == nil {
		t.Fatal("expected bootstrap to append a target entry that did not exist yet")
	}
}

func TestRun_ExistingTargetPreserved(t *testing.T) {
	rosterPath := newTestRoster(t, `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"
`)
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:xyz", session: session}
	validator := &fakeValidator{}

	if _, err := Run(context.Background(), baseOptions(rosterPath), transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Targets) != 1 {
		t.Fatalf("expected exactly 1 target (no duplicate append), got %d", len(r.Targets))
	}
}

// TestRun_DefaultsHostNodeFromExistingRosterEntry guards against the
// defect where cmd/pveforge/bootstrap.go's --host/--node flag help
// promised they were "required unless the target already exists in the
// roster," but validateOptions unconditionally required both non-empty —
// there was no code path that ever filled them in from an existing
// roster entry. An operator retrying bootstrap against an
// already-recorded target, without re-passing --host/--node, must
// succeed using the roster's own recorded values.
func TestRun_DefaultsHostNodeFromExistingRosterEntry(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
	}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, "qa-pve-01", roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, "roster-pass"); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{}

	opts := baseOptions(rosterPath)
	opts.Host = ""
	opts.Node = ""

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if validator.lastCfg.Host != "qa-pve-01.example.com" {
		t.Errorf("expected Host to be defaulted from the roster, validator saw Host=%q", validator.lastCfg.Host)
	}
	// The node defaulted from the roster is checked by the preflight
	// (TestRun_R6f_PreflightChecksTheRosterDefaultedNode); the validator no
	// longer takes a node.
}

// TestRun_DefaultsAPIPortInsecureTLSFromExistingRosterEntry is the
// residual finding folded into
// pveforge-bootstrap-skip-token-recreate-when-valid: a target originally
// bootstrapped with a non-default --api-port/--insecure-tls must not have
// those silently drift back to defaults on a retry that leaves the flags
// unset, the same way --host/--node already don't.
func TestRun_DefaultsAPIPortInsecureTLSFromExistingRosterEntry(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{
		ID:          "qa-pve-01",
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		APIPort:     8007,
		InsecureTLS: true,
	}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, "qa-pve-01", roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, "roster-pass"); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	transport := &fakeTransport{session: &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}}
	validator := &fakeValidator{}

	opts := baseOptions(rosterPath)
	opts.APIPort = 0
	opts.InsecureTLS = false

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if validator.lastCfg.APIPort != 8007 {
		t.Errorf("expected APIPort to be defaulted from the roster to 8007, validator saw APIPort=%d", validator.lastCfg.APIPort)
	}
	if !validator.lastCfg.InsecureTLS {
		t.Errorf("expected InsecureTLS to be defaulted from the roster to true, validator saw InsecureTLS=%v", validator.lastCfg.InsecureTLS)
	}
}

// TestRun_StillRequiresHostNodeForTrueFirstBootstrap guards the other
// side of the same fix: a target with NO roster record yet has nothing to
// default Host/Node from, so leaving them blank must still be a clear
// validation error, not a nil-roster-lookup surprise.
func TestRun_StillRequiresHostNodeForTrueFirstBootstrap(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	transport := &fakeTransport{}
	validator := &fakeValidator{}

	opts := baseOptions(rosterPath)
	opts.Host = ""
	opts.Node = ""

	_, err := Run(context.Background(), opts, transport, validator)
	if err == nil {
		t.Fatal("expected an error when host/node are blank and the target has no existing roster entry")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Errorf("expected a clear 'host is required' error, got: %v", err)
	}
}

func TestRun_PubkeyInstallFailure(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	transport := &fakeTransport{installErr: errors.New("connection refused")}
	validator := &fakeValidator{}

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when pubkey install fails")
	}
	if !strings.Contains(err.Error(), "install pubkey") {
		t.Errorf("error should identify the failing step: %v", err)
	}
	if validator.calls != 0 {
		t.Error("validation should not run if pubkey install failed")
	}
}

func TestRun_DialWithKeyFailure(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	transport := &fakeTransport{installFingerprint: "SHA256:abc", dialErr: errors.New("handshake failed")}
	validator := &fakeValidator{}

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when dialing with the fresh key fails")
	}
	if !strings.Contains(err.Error(), "connect with fresh key") {
		t.Errorf("error should identify the failing step: %v", err)
	}
}

func TestRun_TokenCreationFailure(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stderr: "permission denied", ExitCode: 1}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	res, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when token creation fails")
	}
	if !strings.Contains(err.Error(), "pveum user token add exited 1") {
		t.Errorf("error should identify the failing step: %v", err)
	}
	if res == nil || res.TokenOutcome != OutcomeDiscarded || errors.Is(err, ErrPriorTokenRevoked) {
		t.Errorf("want a partial result, outcome discarded, no prior revocation; got %+v, %v", res, err)
	}
	if !session.closed {
		t.Error("session should still be closed on failure")
	}
}

func TestRun_TokenCreationBadJSON(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: "not json at all", ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when pveum output can't be parsed for a secret")
	}
}

func TestRun_ACLGrantFailure(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
		"pveum acl modify":     {res: RunResult{Stderr: "no such role", ExitCode: 1}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when ACL grant fails")
	}
	if !strings.Contains(err.Error(), "grant acl") {
		t.Errorf("error should identify the failing step: %v", err)
	}
	if validator.calls != 0 {
		t.Error("validation should not run if the ACL grant failed")
	}
}

func TestRun_ValidationFailure_NoGrants(t *testing.T) {
	fastRetries(t)
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	// A VERDICT (the ErrNoGrants alias): the fresh token must be removed
	// and never persisted. A plain error is the non-verdict twin (R14).
	// ErrNoGrants may be a fresh ACL's propagation lag, so it is retried
	// the full bounded window first.
	validator := &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)}

	res, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when validation reports no grants")
	}
	if validator.calls != postMintAttempts {
		t.Fatalf("want the post-mint window's %d attempts, got %d", postMintAttempts, validator.calls)
	}
	if res == nil || res.Validation != ValidationFailed || res.TokenOutcome != OutcomeDiscarded {
		t.Fatalf("want validation=failed, outcome=discarded; got %+v", res)
	}
	if session.count("pveum user token remove") != 1 {
		t.Fatalf("the fresh token must be removed once, got: %v", session.commands)
	}

	// Nothing should be persisted to the roster if validation failed —
	// a token reported as bootstrapped must actually work.
	r, loadErr := roster.Load(rosterPath)
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	tg := r.Find("qa-pve-01")
	if tg != nil && tg.Token != nil {
		t.Fatal("token auth should not be persisted when validation failed")
	}
}

func TestRun_RosterWriteFailure_MissingRosterFile(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.toml")
	transport := &fakeTransport{}
	validator := &fakeValidator{}

	opts := baseOptions(missingPath)
	_, err := Run(context.Background(), opts, transport, validator)
	if err == nil {
		t.Fatal("expected error when the roster file doesn't exist yet")
	}
	if !strings.Contains(err.Error(), "roster init") {
		t.Errorf("error should point at `pveforge roster init`: %v", err)
	}
	if transport.installCalls != 0 {
		t.Error("should fail before ever touching the network if the roster is missing")
	}
}

// A non-@pam realm is refused for the LOGIN only. The same realm is
// exactly what a token OWNER is for (TestRun_BT1_OwnerAndLoginAreSplit).
func TestRun_RejectsNonPamRealm(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	opts.PVEUsername = "alice@pve"
	transport := &fakeTransport{}
	validator := &fakeValidator{}

	_, err := Run(context.Background(), opts, transport, validator)
	if err == nil {
		t.Fatal("expected error for a non-pam realm user")
	}
	if !strings.Contains(err.Error(), "@pam") {
		t.Errorf("error should explain the @pam requirement: %v", err)
	}
}

func TestRun_BareUsernameAssumesPam(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	opts.PVEUsername = "root"
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	res, err := Run(context.Background(), opts, transport, validator)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The OWNER defaults from the canonical login, so the token is added
	// for root@pam and its id says so.
	if res.TokenID != "root@pam!pveforge" || !session.ran("pveum user token add 'root@pam' 'pveforge'") {
		t.Fatalf("token id = %q, commands = %v", res.TokenID, session.commands)
	}
}

// TestRun_IdempotentReRun re-runs bootstrap against a target that fully
// succeeded the first time, with a validator that accepts anything
// (fakeValidator{}, err == nil). Per
// pveforge-bootstrap-skip-token-recreate-when-valid, the second run must
// find the first run's token still validates and skip recreating it
// entirely — the roster must still show exactly one target, no "already
// exists" error, and the ORIGINAL secret must survive untouched (proving
// trySkipTokenRecreate actually skipped createToken/grantACL on the
// second run, rather than happening to mint an identical-looking token).
func TestRun_IdempotentReRun(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	newSession := func(secret string) *fakeSession {
		return &fakeSession{byCmd: map[string]fakeRunResult{
			"pveum user token add": {res: RunResult{Stdout: tokenAddJSON(secret), ExitCode: 0}},
		}}
	}
	validator := &fakeValidator{}

	transport1 := &fakeTransport{installFingerprint: "SHA256:abc", session: newSession("first-secret")}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport1, validator); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	// Re-run against the same roster/target: must succeed again, without
	// an "already exists" error — and, since the first run's token still
	// validates, without touching createToken/grantACL at all.
	transport2 := &fakeTransport{installFingerprint: "SHA256:abc", session: newSession("second-secret")}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport2, validator); err != nil {
		t.Fatalf("second (idempotent) Run: %v", err)
	}
	// N2: the preflight's three reads run on every reconnect; nothing may
	// change a token.
	if m := transport2.session.mutating(); len(m) != 0 {
		t.Fatalf("expected the second run to skip token creation/ACL grant entirely, got: %v", m)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Targets) != 1 {
		t.Fatalf("expected exactly 1 target after re-running bootstrap, got %d", len(r.Targets))
	}
	tg := r.Find("qa-pve-01")
	plaintext, err := roster.DecryptString(tg.Token.SecretEnc, "roster-pass")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "first-secret" {
		t.Fatalf("expected the original token to survive untouched (skip-recreate), got %q", plaintext)
	}
}

// TestRun_ReconnectsWithPinnedKeyAfterFullSuccess guards against the
// original defect (Run generated a brand-new SSH keypair on every
// invocation) at its strongest form: after a target has been fully,
// successfully bootstrapped once, a second Run must not touch password
// auth or pubkey install at all — it must reconnect directly with the
// persisted keypair, pinned against the fingerprint the first run
// captured and persisted.
func TestRun_ReconnectsWithPinnedKeyAfterFullSuccess(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	newSession := func(secret string) *fakeSession {
		return &fakeSession{byCmd: map[string]fakeRunResult{
			"pveum user token add": {res: RunResult{Stdout: tokenAddJSON(secret), ExitCode: 0}},
		}}
	}
	validator := &fakeValidator{}

	transport1 := &fakeTransport{installFingerprint: "SHA256:abc", session: newSession("first-secret")}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport1, validator); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if transport1.installCalls != 1 || transport1.reconnectCalls != 0 {
		t.Fatalf("first run should install via password auth, not reconnect: install=%d reconnect=%d", transport1.installCalls, transport1.reconnectCalls)
	}

	// Second run against the now-bootstrapped target: must reconnect with
	// the pinned key, never touch password auth again.
	transport2 := &fakeTransport{session: newSession("second-secret")}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport2, validator); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if transport2.installCalls != 0 {
		t.Fatalf("second run must not touch password auth/pubkey install, got %d install calls", transport2.installCalls)
	}
	if len(transport2.reconnectedFingerprints) != 1 || transport2.reconnectedFingerprints[0] != "SHA256:abc" {
		t.Fatalf("expected the second run to reconnect using the persisted fingerprint SHA256:abc, got %v", transport2.reconnectedFingerprints)
	}
}

// TestRun_RetryAfterPartialFailure_ReconnectsInsteadOfReinstalling is the
// case that actually matters for Finding A: a run that fails somewhere in
// the token/ACL/validate stretch (the likeliest place for a transient
// failure — network drop, an ACL role typo, propagation delay) AFTER the
// SSH key has already been proven to work and persisted must, on retry,
// reconnect with that persisted key rather than generating (and
// orphaning, in a real authorized_keys file) a brand-new one.
func TestRun_RetryAfterPartialFailure_ReconnectsInsteadOfReinstalling(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	validator := &fakeValidator{}

	// First run: pubkey install + key-based dial succeed (so SSH auth is
	// persisted immediately, per the fix), but ACL grant then fails.
	session1 := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s1"), ExitCode: 0}},
		"pveum acl modify":     {res: RunResult{Stderr: "no such role", ExitCode: 1}},
	}}
	transport1 := &fakeTransport{installFingerprint: "SHA256:abc", session: session1}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport1, validator); err == nil {
		t.Fatal("expected the first run to fail at the ACL grant step")
	}

	// SSH auth must already be persisted despite the overall failure.
	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tg := r.Find("qa-pve-01")
	if tg == nil || tg.SSH == nil || tg.SSH.HostKeyFingerprint != "SHA256:abc" {
		t.Fatalf("expected ssh auth to already be persisted after the partial failure, got: %+v", tg)
	}

	// Retry: must reconnect using the already-persisted key, not touch
	// password auth / pubkey install again.
	session2 := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s2"), ExitCode: 0}},
	}}
	transport2 := &fakeTransport{session: session2}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport2, validator); err != nil {
		t.Fatalf("retry Run: %v", err)
	}
	if transport2.installCalls != 0 {
		t.Errorf("retry must not call InstallPubkeyViaPassword, got %d calls", transport2.installCalls)
	}
	if transport2.reconnectCalls != 1 {
		t.Errorf("expected exactly one ReconnectWithPinnedKey call on retry, got %d", transport2.reconnectCalls)
	}
	if len(transport2.reconnectedFingerprints) != 1 || transport2.reconnectedFingerprints[0] != "SHA256:abc" {
		t.Errorf("expected the retry to reconnect using the persisted fingerprint, got %v", transport2.reconnectedFingerprints)
	}
}

// TestRun_ReconnectMismatch_HardStop_NoSilentRePin is Finding B: a target
// that already has a pinned host key fingerprint on file must never fall
// back to password auth + trust-on-first-use just because the pinned
// reconnect failed. A mismatch (simulated here the same way a real
// changed host key would surface — ReconnectWithPinnedKey returning an
// error) must be a hard stop: no InstallPubkeyViaPassword call, and the
// roster's fingerprint must be left exactly as it was — never silently
// re-pinned to whatever a network address now presents.
func TestRun_ReconnectMismatch_HardStop_NoSilentRePin(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)

	existingKP, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           existingKP.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:original-trusted-fingerprint",
		PrivateKeyPlaintext: existingKP.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	transport := &fakeTransport{reconnectErr: errors.New("host key mismatch: got SHA256:attacker-controlled, want SHA256:original-trusted-fingerprint")}
	validator := &fakeValidator{}

	_, err = Run(context.Background(), opts, transport, validator)
	if err == nil {
		t.Fatal("expected Run to fail when the pinned reconnect reports a mismatch")
	}
	if !strings.Contains(err.Error(), "deliberate operator reconciliation") {
		t.Errorf("expected a clear, actionable error explaining this needs manual reconciliation, got: %v", err)
	}
	if transport.installCalls != 0 {
		t.Error("must not fall back to password auth / pubkey install on a pinned-key mismatch")
	}
	if validator.calls != 0 {
		t.Error("validation must not run when the reconnect itself failed")
	}

	r, loadErr := roster.Load(rosterPath)
	if loadErr != nil {
		t.Fatalf("Load: %v", loadErr)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil || tg.SSH == nil || tg.SSH.HostKeyFingerprint != "SHA256:original-trusted-fingerprint" {
		t.Fatalf("roster's pinned fingerprint must be unchanged after a failed reconnect, got: %+v", tg.SSH)
	}
}

// TestRun_SkipsTokenRecreateWhenExistingTokenValid is
// pveforge-bootstrap-skip-token-recreate-when-valid's core case: a
// reconnect against a target whose persisted token still validates must
// not touch createToken/grantACL at all — proven here by asserting the
// SSH session saw zero commands (createToken/grantACL are the only things
// that ever run a remote command in Run), and that the roster is left
// byte-for-byte unchanged (a true no-op writes nothing).
func TestRun_SkipsTokenRecreateWhenExistingTokenValid(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("existing-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read roster before Run: %v", err)
	}

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		// If Run touched these at all, the test's own assertions below
		// would fail regardless of what these returned — scripted only so
		// a defect that DOES call them doesn't panic/hang on an
		// unscripted command.
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("should-never-be-used"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{} // err == nil: existing token "validates"

	res, err := Run(context.Background(), opts, transport, validator)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenID != "root@pam!pveforge" {
		t.Errorf("expected the existing token id to be returned, got %q", res.TokenID)
	}
	if m := session.mutating(); len(m) != 0 {
		t.Fatalf("expected no token-changing command (only the preflight reads), got: %v", m)
	}
	if res.TokenOutcome != OutcomeReused {
		t.Errorf("outcome = %q, want reused", res.TokenOutcome)
	}
	if validator.calls != 1 {
		t.Fatalf("expected exactly one ValidateTokenGrants call (the skip-check), got %d", validator.calls)
	}
	if validator.lastCfg.TokenSecret != "existing-secret" {
		t.Errorf("expected the skip-check to validate using the EXISTING secret, got %q", validator.lastCfg.TokenSecret)
	}

	after, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read roster after Run: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("expected a true no-op: roster file must be byte-for-byte unchanged")
	}
}

// TestRun_FallsThroughWhenRequestedTokenIDDiffersFromPersisted guards
// against the defect a second, independent review found in
// trySkipTokenRecreate: it validated whatever token id was already
// persisted in the roster without ever comparing it to what THIS
// invocation actually requested (opts.TokenOwner+"!"+opts.TokenID). This
// test varies the token NAME with one owner; TestRun_BT5_OwnerChangeOrphans
// varies the OWNER with one name. A
// target bootstrapped once with --token-id pveforge, then retried with
// --token-id pveforge-2 (rotation, or a differently-named admin token),
// must actually create pveforge-2 — the still-healthy OLD token must
// never be silently returned as a stand-in "no-op" for a request that
// asked for a different token by name.
func TestRun_FallsThroughWhenRequestedTokenIDDiffersFromPersisted(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	// A healthy, persisted token under a DIFFERENT token id than this run
	// will request.
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("stale-but-still-healthy-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	opts.TokenID = "pveforge-2" // this run asks for a DIFFERENT token name

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("new-token-2-secret"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{} // would happily validate either token — the id mismatch must short-circuit before this is ever asked to

	res, err := Run(context.Background(), opts, transport, validator)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenID != "root@pam!pveforge-2" {
		t.Fatalf("expected the newly-requested token id to be returned, got %q", res.TokenID)
	}
	if !session.ran("pveum user token add") {
		t.Fatal("expected a mint: a token-id mismatch must never be treated as a skippable no-op")
	}
	if validator.calls != 1 {
		t.Fatalf("expected exactly one ValidateTokenGrants call (post-mint only — the id mismatch must short-circuit before any skip-check validation call), got %d", validator.calls)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tg := r.Find(opts.TargetID)
	if tg.Token.ID != "root@pam!pveforge-2" {
		t.Fatalf("expected the persisted token id to be updated to root@pam!pveforge-2, got %q", tg.Token.ID)
	}
	plaintext, err := roster.DecryptString(tg.Token.SecretEnc, opts.Passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "new-token-2-secret" {
		t.Fatalf("expected the newly minted token's secret to be persisted, got %q", plaintext)
	}
}

// TestRun_ReplacesOnVerdict (S6, formerly
// TestRun_FallsThroughWhenExistingTokenFailsValidation): the skip-check
// returns a VERDICT about the held token (the ErrNoGrants alias), so Run
// removes it (it is present on PVE), clears the roster's copy, mints and
// persists a fresh one. Its twin, TestRun_AbortsOnNonVerdict
// (rotation_test.go, R7), gives a PLAIN error and must change nothing.
func TestRun_ReplacesOnVerdict(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("stale-revoked-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh-secret"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{errs: []error{
		fmt.Errorf("%w", ErrNoGrants), // the skip-check: a verdict
		nil,                           // the post-mint validation
	}}

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if validator.calls != 2 {
		t.Fatalf("expected exactly two ValidateTokenGrants calls (skip-check + post-mint), got %d", validator.calls)
	}
	if !session.ran("pveum user token remove") || !session.ran("pveum user token add") {
		t.Fatalf("expected remove then add after a verdict, got: %v", session.commands)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	plaintext, err := roster.DecryptString(r.Find(opts.TargetID).Token.SecretEnc, opts.Passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "fresh-secret" {
		t.Fatalf("expected the freshly minted token to be persisted, got %q", plaintext)
	}
}

// TestRun_FallsThroughWhenExistingTokenUndecryptable covers the "fails to
// decrypt" branch when the token no longer exists on PVE (the fake host
// lists no tokens): the persisted token's secret was encrypted under a
// different passphrase than the one this Run is using. Gone from PVE, it is
// known dead, so this must fall through to minting a fresh token, not
// surface a hard decrypt error. A token that still exists is never
// replaced on a decrypt failure (TestRun_R5c_UndecryptablePresentAborts).
func TestRun_FallsThroughWhenExistingTokenUndecryptable(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	// Encrypted under a DIFFERENT passphrase than opts.Passphrase.
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("irrelevant"),
	}, "a-completely-different-passphrase"); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh-secret"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{} // always validates; only the skip-check's decrypt fails

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !session.ran("pveum user token add") {
		t.Fatal("expected a mint when the existing token can't be decrypted")
	}
	if validator.calls != 1 {
		t.Fatalf("expected exactly one ValidateTokenGrants call (the skip-check must not even run when decrypt fails), got %d", validator.calls)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	plaintext, err := roster.DecryptString(r.Find(opts.TargetID).Token.SecretEnc, opts.Passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plaintext) != "fresh-secret" {
		t.Fatalf("expected the freshly minted token to be persisted, got %q", plaintext)
	}
}

// TestRun_NoSkipCheckWhenNoExistingTokenPersisted covers the "target has
// SSH auth but no token auth yet" reconnect case (e.g. a prior run that
// died after persisting SSH auth but before ever creating a token) — the
// skip-check must find nothing to check and fall straight through,
// without ever calling ValidateTokenGrants for a skip attempt.
func TestRun_NoSkipCheckWhenNoExistingTokenPersisted(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	// Deliberately no WriteTokenAuth: no token persisted yet.

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("fresh-secret"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{}

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if validator.calls != 1 {
		t.Fatalf("expected exactly one ValidateTokenGrants call (post-mint only, no skip-check), got %d", validator.calls)
	}
	if !session.ran("pveum user token add") {
		t.Fatal("expected a mint when no token was persisted yet")
	}
}

// TestRun_PersistsInsecureTLSAgainstExistingBareTarget is the exact
// pveforge-bootstrap-insecure-tls-not-persisted reproduction: a target
// that already has a bare [[targets]] roster entry (hand-added per the
// roster template's own documented convention — id/host/node only, no
// insecure_tls) never goes through ensureTargetExists's AppendTarget path
// (it only fires for a target with NO roster entry at all), so
// --insecure-tls was silently lost the moment bootstrap finished. After
// this fix, Run must persist it via persistTargetMeta/
// roster.UpdateTargetFields once bootstrap actually succeeds.
func TestRun_PersistsInsecureTLSAgainstExistingBareTarget(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	// Bare entry: exactly what an operator hand-adds per the roster
	// template's own convention — no insecure_tls line at all.
	if err := roster.AppendTarget(rosterPath, roster.Target{
		ID:   opts.TargetID,
		Host: opts.Host,
		Node: opts.Node,
	}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	opts.InsecureTLS = true

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("tok-secret"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{}

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load roster after bootstrap: %v", err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil {
		t.Fatal("target missing from roster")
	}
	if !tg.InsecureTLS {
		t.Fatalf("expected insecure_tls=true to be persisted into the roster after a successful bootstrap, got %+v", tg)
	}
}

// TestRun_RetryWithoutInsecureTLSFlag_DoesNotClearPersistedValue is the
// drift-prevention case defaultHostNodeFromRoster exists for, now
// composed with persistTargetMeta: a target already has insecure_tls=true
// persisted (from a prior bootstrap); this run OMITS --insecure-tls
// (opts.InsecureTLS left at its zero value, false) and reconnects via the
// trySkipTokenRecreate fast path. defaultHostNodeFromRoster must restore
// opts.InsecureTLS to true BEFORE persistTargetMeta ever runs, so the
// write-back must not — and per this test, does not — silently clear the
// roster's persisted value back to false.
func TestRun_RetryWithoutInsecureTLSFlag_DoesNotClearPersistedValue(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{
		ID:          opts.TargetID,
		Host:        opts.Host,
		Node:        opts.Node,
		InsecureTLS: true,
	}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("existing-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	// This run's own opts explicitly omit --insecure-tls (zero value,
	// false) — simulating an operator retry that doesn't re-pass the flag.
	opts.InsecureTLS = false

	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("should-never-be-used"), ExitCode: 0}},
	}}
	transport := &fakeTransport{session: session}
	validator := &fakeValidator{} // existing token "validates" -> skip-recreate fast path

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if m := session.mutating(); len(m) != 0 {
		t.Fatalf("expected the skip-recreate fast path (no token-changing command), got: %v", m)
	}

	r, err := roster.Load(rosterPath)
	if err != nil {
		t.Fatalf("Load roster after retry: %v", err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil || !tg.InsecureTLS {
		t.Fatalf("expected insecure_tls to remain true after a retry that omitted --insecure-tls, got %+v", tg)
	}
}

// TestLoadExistingSSHAuth_NilWhenNoSSHAuthYet exercises
// loadExistingSSHAuth directly: no SSH auth persisted yet -> nil (true
// first bootstrap).
func TestLoadExistingSSHAuth_NilWhenNoSSHAuthYet(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: "qa-pve-01", Host: "h", Node: "n"}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	opts := baseOptions(rosterPath)

	got, err := loadExistingSSHAuth(opts)
	if err != nil {
		t.Fatalf("loadExistingSSHAuth: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil when no SSH auth is persisted yet, got %+v", got)
	}
}

// TestLoadExistingSSHAuth_ReturnsPersistedKeypair exercises the reuse
// path: SSH auth already persisted -> that exact keypair and fingerprint,
// decrypted, not something freshly generated.
func TestLoadExistingSSHAuth_ReturnsPersistedKeypair(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: "qa-pve-01", Host: "h", Node: "n"}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	opts := baseOptions(rosterPath)

	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, "qa-pve-01", roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	got, err := loadExistingSSHAuth(opts)
	if err != nil {
		t.Fatalf("loadExistingSSHAuth: %v", err)
	}
	if got == nil {
		t.Fatal("expected existing SSH auth to be found")
	}
	if got.HostKeyFingerprint != "SHA256:abc" {
		t.Errorf("HostKeyFingerprint = %q, want %q", got.HostKeyFingerprint, "SHA256:abc")
	}
	if string(got.PrivateKeyPEM) != string(kp.PrivateKeyPEM) {
		t.Error("expected the persisted private key to be returned byte-for-byte")
	}
}

// TestLoadExistingSSHAuth_TreatsSSHWithoutFingerprintAsNone is a
// defensive edge case: SSH auth present but with no fingerprint on file
// (this package's own writes never produce this — Run always persists a
// keypair and its fingerprint together — but the roster schema doesn't
// forbid it) is treated the same as "no SSH auth yet": re-bootstrapping is
// the safe default, not reconnecting with an unpinned keypair.
func TestLoadExistingSSHAuth_TreatsSSHWithoutFingerprintAsNone(t *testing.T) {
	armored, err := roster.EncryptString([]byte("some-key-bytes"), "roster-pass")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	rosterPath := newTestRoster(t, `[[targets]]
id = "qa-pve-01"
host = "h"
node = "n"

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA..."
  private_key_enc = '''
`+armored+`'''
`)
	opts := baseOptions(rosterPath)

	got, err := loadExistingSSHAuth(opts)
	if err != nil {
		t.Fatalf("loadExistingSSHAuth: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil when no fingerprint is on file, got %+v", got)
	}
}

func TestLoadExistingSSHAuth_WrongPassphraseErrors(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: "qa-pve-01", Host: "h", Node: "n"}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	opts := baseOptions(rosterPath)

	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, "qa-pve-01", roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	wrongOpts := opts
	wrongOpts.Passphrase = "not-the-right-passphrase"
	if _, err := loadExistingSSHAuth(wrongOpts); err == nil {
		t.Fatal("expected an error decrypting the persisted keypair with the wrong passphrase")
	}
}

// TestLoadExistingSSHAuth_IgnoresUndecryptableTokenData guards against the
// defect where loadExistingSSHAuth called tg.Resolve, which
// unconditionally decrypts BOTH Token.SecretEnc and SSH.PrivateKeyEnc.
// This call only ever needs the SSH key — an unrelated failure decrypting
// a target's token data (corruption, format drift, anything) must not
// block a perfectly good SSH reconnect that doesn't touch that data at
// all. The token secret here is persisted under a deliberately different
// passphrase than the roster's own, so decrypting it with opts.Passphrase
// fails exactly the way real corruption would.
func TestLoadExistingSSHAuth_IgnoresUndecryptableTokenData(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}

	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	// Persist a token whose secret is encrypted under a DIFFERENT
	// passphrase than the roster's own — undecryptable with opts.Passphrase,
	// simulating corrupted/drifted token ciphertext without hand-crafting
	// invalid bytes.
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("irrelevant"),
	}, "a-completely-different-passphrase"); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := loadExistingSSHAuth(opts)
	if err != nil {
		t.Fatalf("loadExistingSSHAuth should succeed using only the SSH data, got error: %v", err)
	}
	if got == nil || got.HostKeyFingerprint != "SHA256:abc" {
		t.Fatalf("expected existing ssh auth to be returned despite undecryptable token data, got %+v", got)
	}
	if string(got.PrivateKeyPEM) != string(kp.PrivateKeyPEM) {
		t.Fatal("expected the persisted private key to be returned byte-for-byte")
	}
}

// TestLoadHeldToken_EmptyWhenNoTokenAuthYet exercises loadHeldToken
// directly: no token auth persisted yet -> an empty ID (nothing held).
func TestLoadHeldToken_EmptyWhenNoTokenAuthYet(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: "qa-pve-01", Host: "h", Node: "n"}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	opts := baseOptions(rosterPath)

	got, err := loadHeldToken(opts)
	if err != nil {
		t.Fatalf("loadHeldToken: %v", err)
	}
	if got.ID != "" || got.DecryptErr != nil {
		t.Fatalf("expected nothing held (no token auth yet), got %+v", got)
	}
}

// TestLoadHeldToken_ReturnsPersistedToken exercises the success path
// directly: an existing, decryptable token returns its full id and
// decrypted secret.
func TestLoadHeldToken_ReturnsPersistedToken(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("a-real-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := loadHeldToken(opts)
	if err != nil {
		t.Fatalf("loadHeldToken: %v", err)
	}
	if got.ID != "root@pam!pveforge" || got.Secret != "a-real-secret" || got.DecryptErr != nil {
		t.Fatalf("expected the persisted token to be returned decrypted, got %+v", got)
	}
}

// TestLoadHeldToken_UndecryptableIsReportedNotAnError exercises the
// decrypt-failure path directly: a token that will not decrypt is still
// HELD (its id is known) and the failure is reported in DecryptErr, not as
// an error. A roster that will not load at all is the error case (R7d).
func TestLoadHeldToken_UndecryptableIsReportedNotAnError(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("a-real-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	wrongOpts := opts
	wrongOpts.Passphrase = "wrong-passphrase"
	got, err := loadHeldToken(wrongOpts)
	if err != nil {
		t.Fatalf("loadHeldToken: a decrypt failure must not be an error, got %v", err)
	}
	if got.ID != "root@pam!pveforge" || got.DecryptErr == nil || got.Secret != "" {
		t.Fatalf("expected a held, undecryptable token, got %+v", got)
	}
}

// TestLoadExistingTokenAuth_IgnoresUndecryptableSSHData is the mirror of
// TestLoadExistingSSHAuth_IgnoresUndecryptableTokenData: an unrelated
// SSH-decrypt failure must not block reading the token data, since this
// call never touches SSH.PrivateKeyEnc at all.
func TestLoadHeldToken_IgnoresUndecryptableSSHData(t *testing.T) {
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{
		TokenID:         "root@pam!pveforge",
		SecretPlaintext: []byte("a-real-secret"),
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	// SSH key encrypted under a DIFFERENT passphrase — undecryptable with
	// opts.Passphrase, simulating corrupted/drifted SSH ciphertext.
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User:                "root",
		PublicKey:           kp.AuthorizedKeyLine,
		HostKeyFingerprint:  "SHA256:abc",
		PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, "a-completely-different-passphrase"); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	got, err := loadHeldToken(opts)
	if err != nil {
		t.Fatalf("loadHeldToken should succeed using only the token data, got error: %v", err)
	}
	if got.ID != "root@pam!pveforge" || got.Secret != "a-real-secret" {
		t.Fatalf("expected the persisted token to be returned despite undecryptable ssh data, got %+v", got)
	}
}

func TestPamLocalUser(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"root@pam", "root", false},
		{"root", "root", false},
		{"alice@pve", "", true},
		{"bob@ldap", "", true},
	}
	for _, c := range cases {
		got, err := pamLocalUser(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("pamLocalUser(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("pamLocalUser(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("pamLocalUser(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseTokenSecret(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"direct shape", `{"value":"abc-123"}`, "abc-123", false},
		{"enveloped shape", `{"data":{"value":"xyz-789"}}`, "xyz-789", false},
		{"missing value", `{"full-tokenid":"root@pam!x"}`, "", true},
		{"not json", `nope`, "", true},
	}
	for _, c := range cases {
		got, err := parseTokenSecret(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestParseTokenSecret_NeverLeaksSecretOnParseFailure guards against the
// defect where the failure branch echoed raw stdout verbatim into the
// returned error — exactly the case most likely to actually be holding the
// real secret, under a response shaped differently than either of the two
// shapes parseTokenSecret knows how to read. A secret must never appear in
// an error string, per this task's own recorded requirement.
func TestParseTokenSecret_NeverLeaksSecretOnParseFailure(t *testing.T) {
	const secret = "tok-secret-abc123-must-not-leak"

	cases := []struct {
		name string
		in   string
	}{
		{"json object, wrong key entirely", `{"unexpected_key":"` + secret + `"}`},
		{"json object, nested under an unexpected shape", `{"result":{"token":"` + secret + `"}}`},
		{"not json at all", "plain text response containing " + secret},
	}
	for _, c := range cases {
		_, err := parseTokenSecret(c.in)
		if err == nil {
			t.Fatalf("%s: expected an error", c.name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: error leaked the secret value: %v", c.name, err)
		}
	}
}

func TestValidateOptions_RequiredFields(t *testing.T) {
	full := Options{
		TargetID:    "t",
		Host:        "h",
		Node:        "n",
		PVEPassword: "p",
		TokenID:     "tok",
		RosterPath:  "r",
		Passphrase:  "pp",
	}
	if err := validateOptions(&full); err != nil {
		t.Fatalf("fully populated options should validate: %v", err)
	}

	fields := []func(*Options){
		func(o *Options) { o.TargetID = "" },
		func(o *Options) { o.Host = "" },
		func(o *Options) { o.Node = "" },
		func(o *Options) { o.PVEPassword = "" },
		func(o *Options) { o.TokenID = "" },
		func(o *Options) { o.RosterPath = "" },
		func(o *Options) { o.Passphrase = "" },
	}
	for i, zero := range fields {
		o := full
		zero(&o)
		if err := validateOptions(&o); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestApplyDefaults(t *testing.T) {
	o := Options{}
	applyDefaults(&o)
	if o.SSHPort != 22 {
		t.Errorf("SSHPort = %d, want 22", o.SSHPort)
	}
	// MG1: no default grant, ever: bootstrap fails closed.
	if o.Grants != nil {
		t.Errorf("Grants = %#v, want nil (no default grant)", o.Grants)
	}
	if o.PVEUsername != "root@pam" {
		t.Errorf("PVEUsername = %q, want root@pam", o.PVEUsername)
	}
	// MB15: the owner defaults to the login, so a caller that names none
	// still addresses a principal.
	if o.TokenOwner != "root@pam" {
		t.Errorf("TokenOwner = %q, want root@pam", o.TokenOwner)
	}

	// MB10: the owner is defaulted from the CANONICAL login, so a bare
	// --pve-user root owns as root@pam, never as the invalid "root".
	bare := Options{PVEUsername: "root"}
	applyDefaults(&bare)
	if bare.TokenOwner != "root@pam" {
		t.Errorf("TokenOwner = %q for a bare login, want root@pam", bare.TokenOwner)
	}

	grants := []Grant{{Path: "/vms", Role: "Custom", Privs: []string{"VM.Audit"}}}
	o2 := Options{SSHPort: 2222, Grants: grants, PVEUsername: "alice@pam", TokenOwner: "harness@pve"}
	applyDefaults(&o2)
	if o2.SSHPort != 2222 || !reflect.DeepEqual(o2.Grants, []Grant{{Path: "/vms", Role: "Custom", Privs: []string{"VM.Audit"}}}) || o2.PVEUsername != "alice@pam" || o2.TokenOwner != "harness@pve" {
		t.Errorf("applyDefaults overwrote explicitly set fields: %+v", o2)
	}
}
