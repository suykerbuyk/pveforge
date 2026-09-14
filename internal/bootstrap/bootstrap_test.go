package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// fakeSession is a scriptable SSHSession: each Run call is answered by
// popping the next entry off responses (in order), or by consulting byCmd
// if set for that exact command string. Close is a no-op that just records
// whether it was called.
type fakeSession struct {
	byCmd    map[string]fakeRunResult
	closed   bool
	commands []string
}

type fakeRunResult struct {
	res RunResult
	err error
}

func (s *fakeSession) Run(_ context.Context, cmd string) (RunResult, error) {
	s.commands = append(s.commands, cmd)
	for prefix, r := range s.byCmd {
		if strings.HasPrefix(cmd, prefix) {
			return r.res, r.err
		}
	}
	return RunResult{ExitCode: 0}, nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

// fakeTransport is a scriptable SSHTransport.
type fakeTransport struct {
	installFingerprint string
	installErr         error
	dialErr            error
	reconnectErr       error
	session            *fakeSession

	installCalls            int
	dialCalls               int
	reconnectCalls          int
	installedKeyLines       []string // every authorizedKeyLine InstallPubkeyViaPassword was called with, in order
	reconnectedFingerprints []string // every hostKeyFingerprint ReconnectWithPinnedKey was called with, in order
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
	t.reconnectCalls++
	t.reconnectedFingerprints = append(t.reconnectedFingerprints, hostKeyFingerprint)
	if t.reconnectErr != nil {
		return nil, t.reconnectErr
	}
	return t.session, nil
}

// fakeValidator is a scriptable APIValidator.
type fakeValidator struct {
	err            error
	calls          int
	lastCfg        APIConfig
	lastExpectNode string
}

func (v *fakeValidator) ValidateTokenGrants(_ context.Context, cfg APIConfig, expectNode string) error {
	v.calls++
	v.lastCfg = cfg
	v.lastExpectNode = expectNode
	return v.err
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
		RosterPath:  rosterPath,
		Passphrase:  "roster-pass",
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

	// createToken must attempt a best-effort delete before the add, so a
	// leftover token from a prior partial run doesn't block a retry.
	foundRemove, foundAdd := false, false
	for _, c := range session.commands {
		if strings.HasPrefix(c, "pveum user token remove") {
			foundRemove = true
		}
		if strings.HasPrefix(c, "pveum user token add") {
			foundAdd = true
		}
	}
	if !foundRemove || !foundAdd {
		t.Errorf("expected both a token remove and a token add command, got: %v", session.commands)
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
	if validator.lastExpectNode != "qa-pve-01" {
		t.Errorf("expected Node to be defaulted from the roster, validator saw expectNode=%q", validator.lastExpectNode)
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

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when token creation fails")
	}
	if !strings.Contains(err.Error(), "create token") {
		t.Errorf("error should identify the failing step: %v", err)
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
	rosterPath := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("s"), ExitCode: 0}},
	}}
	transport := &fakeTransport{installFingerprint: "SHA256:abc", session: session}
	validator := &fakeValidator{err: errors.New("token authenticates but appears to have no working grants")}

	_, err := Run(context.Background(), baseOptions(rosterPath), transport, validator)
	if err == nil {
		t.Fatal("expected error when validation reports no grants")
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

	if _, err := Run(context.Background(), opts, transport, validator); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

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

	// Re-run against the same roster/target: must succeed again and end
	// up with the SECOND run's fresh secret persisted, not an error about
	// "already exists".
	transport2 := &fakeTransport{installFingerprint: "SHA256:abc", session: newSession("second-secret")}
	if _, err := Run(context.Background(), baseOptions(rosterPath), transport2, validator); err != nil {
		t.Fatalf("second (idempotent) Run: %v", err)
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
	if string(plaintext) != "second-secret" {
		t.Fatalf("expected the second run's fresh secret to be persisted, got %q", plaintext)
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
	if o.ACLPath != "/" {
		t.Errorf("ACLPath = %q, want /", o.ACLPath)
	}
	if o.ACLRole != "PVEVMAdmin" {
		t.Errorf("ACLRole = %q, want PVEVMAdmin", o.ACLRole)
	}
	if o.PVEUsername != "root@pam" {
		t.Errorf("PVEUsername = %q, want root@pam", o.PVEUsername)
	}

	o2 := Options{SSHPort: 2222, ACLPath: "/vms", ACLRole: "Custom", PVEUsername: "alice@pam"}
	applyDefaults(&o2)
	if o2.SSHPort != 2222 || o2.ACLPath != "/vms" || o2.ACLRole != "Custom" || o2.PVEUsername != "alice@pam" {
		t.Errorf("applyDefaults overwrote explicitly set fields: %+v", o2)
	}
}
