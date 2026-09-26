package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// newHostKey is the rebuilt node's SSH host key, as the operator read it on
// the console; testHostKey is the old one the roster pins.
const newHostKey = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// rebuiltKeyful is a keyful insecure target pinned to testHostKey and to
// old's TLS key, holding a token; opts ask for a reprovision to newHostKey.
func rebuiltKeyful(t *testing.T, old capturePair) (string, Options) {
	t.Helper()
	rosterPath, opts := sshTarget(t, true, old.pin)
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("old-node-secret")}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	opts.Reprovisioned, opts.HostKeyFingerprint = true, newHostKey
	return rosterPath, opts
}

// rebuiltNode answers like a freshly installed node: the new TLS key (cp),
// no token, and the old token refused (a 401, ErrNotAuthorized).
func rebuiltNode(cp capturePair) (*fakeSession, *fakeValidator) {
	s := &fakeSession{}
	v := &fakeValidator{errs: []error{ErrNotAuthorized, nil}}
	scriptCapture(s, v, cp)
	return s, v
}

func sshBlock(t *testing.T, path, id string) *roster.SSHAuth {
	t.Helper()
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return r.Find(id).SSH
}

func TestReprovision_KeyfulReplacesBothPinsAndTheKeypair(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := rebuiltKeyful(t, old)
	oldSSH := sshBlock(t, rosterPath, opts.TargetID)
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	tr := &fakeTransport{session: session}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ssh := sshBlock(t, rosterPath, opts.TargetID)
	if ssh.HostKeyFingerprint != newHostKey || ssh.HostKeySource != string(tlspin.SourceSSHVerified) {
		t.Fatalf("[targets.ssh] pins %s (%q), want %s (ssh-verified)", ssh.HostKeyFingerprint, ssh.HostKeySource, newHostKey)
	}
	// Compare the DECRYPTED keys: age encryption is randomized, so the
	// ciphertexts differ even for one key.
	oldKey, err1 := opts.Passphrase.Decrypt(oldSSH.PrivateKeyEnc)
	newKey, err2 := opts.Passphrase.Decrypt(ssh.PrivateKeyEnc)
	if err1 != nil || err2 != nil || bytes.Equal(oldKey, newKey) || ssh.PublicKey == oldSSH.PublicKey {
		t.Fatalf("the old keypair was kept (it belongs to the old node): decrypt %v %v", err1, err2)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHVerified) {
		t.Fatalf("[targets.tls] = %+v, want %s (ssh-verified)", got, cp.pin)
	}
	if !res.Reprovisioned || res.PreviousHostKeyFingerprint != testHostKey || res.PreviousTLSPin != old.pin || !res.ReprovisionAsked {
		t.Fatalf("result %+v", res)
	}
	if tr.reconnectCalls != 0 || len(tr.installPins) != 1 || tr.installPins[0] != newHostKey {
		t.Fatalf("reconnects %d (the old pin must never be dialed), install pins %v (want [%s])", tr.reconnectCalls, tr.installPins, newHostKey)
	}
	if res.TokenOutcome != OutcomeReplaced || session.ran("pveum user token remove") {
		t.Fatalf("token outcome %q, remove ran %v; want replaced with no remove (the old token does not exist on the new node)", res.TokenOutcome, session.ran("pveum user token remove"))
	}
	for i, c := range v.cfgsByCall {
		if c.TLSPin != cp.pin {
			t.Errorf("validation %d went through pin %s, want the new node's %s", i, c.TLSPin, cp.pin)
		}
	}
}

func TestReprovision_KeylessReplacesTheTLSPin(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := keylessTarget(t, old.pin)
	opts.NoSSHKey, opts.Reprovisioned, opts.HostKeyFingerprint = true, true, newHostKey
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	tr := &fakeTransport{session: session}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHVerified) {
		t.Fatalf("[targets.tls] = %+v", got)
	}
	if !res.Reprovisioned || res.PreviousTLSPin != old.pin || res.PreviousHostKeyFingerprint != "" {
		t.Fatalf("result %+v; keyless has no previous SSH pin", res)
	}
	// RQ-D: the password session is pinned to the operator's fingerprint,
	// the only trust anchor a keyless target has.
	if len(tr.dialPWPins) != 1 || tr.dialPWPins[0] != newHostKey {
		t.Fatalf("password dial pins %v, want [%s]", tr.dialPWPins, newHostKey)
	}
	if sshBlock(t, rosterPath, opts.TargetID) != nil {
		t.Fatal("a keyless reprovision wrote [targets.ssh]")
	}
}

// Step 1: refused before any connection, the roster untouched.
func TestReprovision_Refusals(t *testing.T) {
	for name, c := range map[string]struct {
		mk   func() (string, Options)
		want error
		text string
	}{
		"no --host-key-fingerprint": {func() (string, Options) {
			p, o := rebuiltKeyful(t, newCapturePair(t))
			o.HostKeyFingerprint = ""
			return p, o
		}, ErrReprovisionNeedsFingerprint, "CONSOLE"},
		"with --ssh-tofu": {func() (string, Options) {
			p, o := rebuiltKeyful(t, newCapturePair(t))
			o.SSHTOFU = true
			return p, o
		}, nil, "never trusted on first use"},
		"a target the roster lacks": {func() (string, Options) {
			p := newTestRoster(t, "")
			o := baseOptions(p)
			o.InsecureTLS, o.Reprovisioned, o.HostKeyFingerprint = true, true, newHostKey
			return p, o
		}, ErrNothingToReprovision, "first bootstrap"},
		"a target holding no pin": {func() (string, Options) {
			p := newTestRoster(t, "")
			o := baseOptions(p)
			if err := roster.AppendTarget(p, roster.Target{ID: o.TargetID, Host: o.Host, Node: o.Node, InsecureTLS: true}); err != nil {
				t.Fatal(err)
			}
			o.Reprovisioned, o.HostKeyFingerprint = true, newHostKey
			return p, o
		}, ErrNothingToReprovision, "nothing to replace"},
		// RQ-B's ordering: the rules hold before the CA-target early return
		// and before the stored-SSH-pin early return.
		"a CA-verified target without a fingerprint": {func() (string, Options) {
			p, o := sshTarget(t, false, newCapturePair(t).pin)
			o.Reprovisioned = true
			return p, o
		}, ErrReprovisionNeedsFingerprint, ""},
		"a stored SSH pin without a fingerprint": {func() (string, Options) {
			p, o := sshTarget(t, true, "")
			o.Reprovisioned = true
			return p, o
		}, ErrReprovisionNeedsFingerprint, ""},
	} {
		path, opts := c.mk()
		before, _ := os.ReadFile(path)
		tr := &fakeTransport{session: &fakeSession{}}
		v := &fakeValidator{}
		_, err := Run(context.Background(), opts, tr, v)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: err = %v, want %v naming %q", name, err, c.want, c.text)
		}
		if tr.installCalls+tr.dialCalls+tr.dialPWCalls+tr.reconnectCalls != 0 || v.servedCalls != 0 {
			t.Errorf("%s: a connection was made", name)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Errorf("%s: the refusal changed the roster", name)
		}
	}
}

// RQ-C: where the stored pins already match the node, --reprovisioned is
// a plain rerun; the crash table's rows as real runs.
func TestReprovision_ConvergesAsAPlainRerun(t *testing.T) {
	cp := newCapturePair(t)

	// Keyful, both pins current (the crash table's last row): the stored
	// SSH pin is dialed as normal, nothing is replaced.
	rosterPath, opts := sshTarget(t, true, cp.pin)
	opts.Reprovisioned, opts.HostKeyFingerprint = true, testHostKey
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, cp)
	tr := &fakeTransport{session: session}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil || res.Reprovisioned || !res.ReprovisionAsked || tr.reconnectCalls != 1 || tr.installCalls != 0 {
		t.Fatalf("keyful, pins current: %+v, %v (reconnects %d, installs %d)", res, err, tr.reconnectCalls, tr.installCalls)
	}

	// Keyless, TLS current: a plain rerun, and no "TLS unchanged" refusal
	// after the password was sent (RQ-D).
	rp2, o2 := keylessTarget(t, cp.pin)
	o2.NoSSHKey, o2.Reprovisioned, o2.HostKeyFingerprint = true, true, newHostKey
	s2 := &fakeSession{}
	v2 := &fakeValidator{}
	scriptCapture(s2, v2, cp)
	res, err = Run(context.Background(), o2, &fakeTransport{session: s2}, v2)
	if err != nil || res.Reprovisioned {
		t.Fatalf("keyless, TLS current: %+v, %v", res, err)
	}
	if got := rosterTLS(t, rp2, o2.TargetID); tlspin.Pin(got.SPKISHA256) != cp.pin {
		t.Fatal("the pin changed")
	}
	_ = rosterPath

	// The middle row: the TLS pin already new, the SSH pin still old (a run
	// stopped between the two writes; the state is built directly). The
	// rerun replaces SSH only, and reports no previous TLS pin (equal).
	rp3, o3 := rebuiltKeyful(t, cp)
	s3, v3 := rebuiltNode(cp)
	res, err = Run(context.Background(), o3, &fakeTransport{session: s3}, v3)
	if err != nil || !res.Reprovisioned || res.PreviousHostKeyFingerprint != testHostKey || res.PreviousTLSPin != "" {
		t.Fatalf("TLS new, SSH old: %+v, %v", res, err)
	}
	if sshBlock(t, rp3, o3.TargetID).HostKeyFingerprint != newHostKey {
		t.Fatal("the SSH pin was not replaced")
	}
}

// RQ-B: a CA-verified target the operator pinned is re-pinned over the
// operator-verified session; one with no pin stays unpinned.
func TestReprovision_CAVerifiedTarget(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := sshTarget(t, false, old.pin)
	opts.Reprovisioned, opts.HostKeyFingerprint = true, newHostKey
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	res, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHVerified) || res.PreviousTLSPin != old.pin {
		t.Fatalf("a pinned CA target: %+v, result %+v", got, res)
	}
	for _, c := range v.cfgsByCall {
		if c.InsecureTLS || c.TLSPin != cp.pin {
			t.Fatalf("the CA target was validated with insecure %v, pin %s: the chain AND the new pin must hold", c.InsecureTLS, c.TLSPin)
		}
	}
	rp2, o2 := sshTarget(t, false, "")
	o2.Reprovisioned, o2.HostKeyFingerprint = true, newHostKey
	s2, v2 := rebuiltNode(cp)
	if _, err := Run(context.Background(), o2, &fakeTransport{session: s2}, v2); err != nil {
		t.Fatalf("an unpinned CA target: %v", err)
	}
	if v2.servedCalls != 0 || rosterTLS(t, rp2, o2.TargetID) != nil {
		t.Fatal("an unpinned CA target was captured")
	}
}

// preflight runs after both pin writes: a failure there says the pins are
// done and what to recreate.
func TestReprovision_PreflightFailureSaysThePinsAreDone(t *testing.T) {
	rosterPath, opts := rebuiltKeyful(t, newCapturePair(t))
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	session.byCmd["pvesh get /nodes"] = fakeRunResult{res: RunResult{Stdout: `[{"node":"another","status":"online"}]`}}
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	// The previous values are in the message: the operator's only record of
	// them, since the rerun that follows is a plain one with nothing to report.
	if err == nil || !strings.Contains(err.Error(), "this run replaced the SSH host key pin (previous "+testHostKey+") and the TLS pin (previous ") ||
		!strings.Contains(err.Error(), "they now match the rebuilt node") || !strings.Contains(err.Error(), "D5 G1-G3") {
		t.Fatalf("err = %v", err)
	}
	if sshBlock(t, rosterPath, opts.TargetID).HostKeyFingerprint != newHostKey || rosterPin(t, rosterPath, opts.TargetID) != cp.pin {
		t.Fatal("the pins are not the new node's, yet the message says they are")
	}
}

// The console command tlspin names (it is pure, so it cannot import
// sshexec) is sshexec's.
func TestConsoleCommand_OneSpelling(t *testing.T) {
	m := (&tlspin.MismatchError{Want: fixedPin(1), Got: fixedPin(2)}).Error()
	if !strings.Contains(m, sshexec.ConsoleHostKeyCommand) {
		t.Fatalf("tlspin's mismatch names another console command than %q: %s", sshexec.ConsoleHostKeyCommand, m)
	}
	// RQ-A for the TLS mismatch: the presented pin never follows the flag.
	if i := strings.Index(m, "--host-key-fingerprint"); i < 0 || strings.Contains(m[i:], string(fixedPin(2))) || !strings.Contains(m, "Do NOT pin the presented key") {
		t.Fatalf("the TLS mismatch text: %s", m)
	}
}

// host_key_source: a first run records how its SSH pin was vouched for.
func TestFirstRun_RecordsTheSSHHostKeySource(t *testing.T) {
	for fp, want := range map[string]tlspin.Source{testHostKey: tlspin.SourceSSHVerified, "": tlspin.SourceSSHTOFU} {
		rosterPath, opts := bareTarget(t)
		opts.HostKeyFingerprint, opts.SSHTOFU = fp, fp == ""
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: testHostKey, session: session}, v); err != nil {
			t.Fatalf("fp %q: %v", fp, err)
		}
		if got := sshBlock(t, rosterPath, opts.TargetID).HostKeySource; got != string(want) {
			t.Fatalf("fp %q: host_key_source %q, want %q", fp, got, want)
		}
	}
}

// The TLS cross-check fails on the rebuilt node: nothing is replaced, the
// SSH pin stays the old one (the TLS pin is written before the SSH auth).
func TestReprovision_FailedCrossCheckKeepsBothOldPins(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := rebuiltKeyful(t, old)
	before, _ := os.ReadFile(rosterPath)
	session, v := rebuiltNode(newCapturePair(t))
	v.served = newCapturePair(t).pin // the address serves another key
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, ErrTLSPinMismatch) {
		t.Fatalf("err = %v, want ErrTLSPinMismatch", err)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) {
		t.Fatal("a reprovision refused at the cross-check changed the roster")
	}
}

// A pin set by the caller that is not the roster's is refused: only a
// reprovision's capture replaces the roster's pin.
func TestRun_CallerPinNotTheRostersIsRefused(t *testing.T) {
	_, opts := sshTarget(t, true, newCapturePair(t).pin)
	opts.TLSPin = newCapturePair(t).pin
	tr := &fakeTransport{session: &fakeSession{}}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err == nil || !strings.Contains(err.Error(), "is not the one the roster holds") {
		t.Fatalf("err = %v", err)
	}
	if tr.reconnectCalls+tr.installCalls != 0 {
		t.Fatal("dialled")
	}
}

// ---- The T2 review's send-back ----

// (4) M4's row: the SSH key is unchanged, the TLS key is new. The TLS pin is
// replaced over the stored-pin session (recorded ssh-stored), SSH is not.
func TestReprovision_SSHMatchesTLSDiffers(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := rebuiltKeyful(t, old)
	opts.HostKeyFingerprint = testHostKey // the console shows the SAME key
	sshBefore := sshBlock(t, rosterPath, opts.TargetID)
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	tr := &fakeTransport{session: session}
	res, err := Run(context.Background(), opts, tr, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHStored) {
		t.Fatalf("[targets.tls] = %+v, want %s recorded ssh-stored", got, cp.pin)
	}
	if *sshBlock(t, rosterPath, opts.TargetID) != *sshBefore || tr.installCalls != 0 || tr.reconnectCalls != 1 {
		t.Fatalf("the SSH auth changed or was not dialed over its stored pin (installs %d, reconnects %d)", tr.installCalls, tr.reconnectCalls)
	}
	if !res.Reprovisioned || res.PreviousTLSPin != old.pin || res.PreviousHostKeyFingerprint != "" {
		t.Fatalf("result %+v", res)
	}
}

// (4) M11: on a keyful reprovision the capture runs on the NEW session
// (the fresh key's), never on one over the old pin.
func TestReprovision_CapturesOnTheNewSession(t *testing.T) {
	_, opts := rebuiltKeyful(t, newCapturePair(t))
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	stale := &fakeSession{}
	tr := &fakeTransport{session: session, reconnectSession: stale}
	if _, err := Run(context.Background(), opts, tr, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !session.ran(captureCmdPrefix) || len(stale.attempted) != 0 || tr.dialCalls != 1 {
		t.Fatalf("capture on the new session %v, commands on a stale session %v, key dials %d", session.ran(captureCmdPrefix), stale.attempted, tr.dialCalls)
	}
}

// (3) A pinned CA-verified target: the chain is verified by the probe,
// BEFORE either pin is written; an untrusted chain writes nothing.
func TestReprovision_CAChainVerifiedBeforeTheWrites(t *testing.T) {
	rosterPath, opts := sshTarget(t, false, newCapturePair(t).pin)
	opts.Reprovisioned, opts.HostKeyFingerprint = true, newHostKey
	before, _ := os.ReadFile(rosterPath)
	session, v := rebuiltNode(newCapturePair(t))
	v.chainErr = errors.New("x509: certificate signed by unknown authority")
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err == nil || !strings.Contains(err.Error(), "unknown authority") || !v.servedVerified {
		t.Fatalf("err = %v, chain verified %v", err, v.servedVerified)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) || v.calls != 0 {
		t.Fatal("an untrusted chain let a pin be written or a token be validated")
	}
	// An insecure_tls target's probe does not verify the chain.
	_, o2 := rebuiltKeyful(t, newCapturePair(t))
	s2, v2 := rebuiltNode(newCapturePair(t))
	v2.chainErr = errors.New("would refuse")
	if _, err := Run(context.Background(), o2, &fakeTransport{session: s2}, v2); err != nil || v2.servedVerified {
		t.Fatalf("insecure_tls: err %v, chain verified %v", err, v2.servedVerified)
	}
}

// (1) The crash between the TLS and the SSH writes: the error carries the
// previous TLS pin and says what is left to do.
func TestReprovision_SSHWriteFailureCarriesThePreviousTLSPin(t *testing.T) {
	old := newCapturePair(t)
	rosterPath, opts := rebuiltKeyful(t, old)
	cp := newCapturePair(t)
	session, v := rebuiltNode(cp)
	// Another writer changes the SSH pin while the run captures: the SSH
	// replace's compare-and-set then refuses, after the TLS write.
	r := session.byCmd[captureCmdPrefix]
	r.onRun = func(context.Context, string) {
		if err := roster.ReplaceSSHAuth(rosterPath, opts.TargetID, testHostKey, roster.SSHWrite{User: "root", HostKeyFingerprint: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", PrivateKeyPlaintext: []byte("k")}, opts.Passphrase); err != nil {
			t.Errorf("the concurrent writer: %v", err)
		}
	}
	session.byCmd[captureCmdPrefix] = r
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, roster.ErrSSHPinChanged) || !strings.Contains(err.Error(), "the TLS pin was already replaced (previous "+string(old.pin)+")") {
		t.Fatalf("err = %v", err)
	}
}

// The keyless preflight message names only the TLS pin.
func TestReprovision_KeylessPreflightNamesOnlyTheTLSPin(t *testing.T) {
	_, opts := keylessTarget(t, newCapturePair(t).pin)
	opts.NoSSHKey, opts.Reprovisioned, opts.HostKeyFingerprint = true, true, newHostKey
	session, v := rebuiltNode(newCapturePair(t))
	session.byCmd["pvesh get /nodes"] = fakeRunResult{res: RunResult{Stdout: `[{"node":"another","status":"online"}]`}}
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err == nil || !strings.Contains(err.Error(), "this run replaced the TLS pin (previous ") || !strings.Contains(err.Error(), "it now matches the rebuilt node") || strings.Contains(err.Error(), "both") || strings.Contains(err.Error(), "SSH host key pin") {
		t.Fatalf("err = %v", err)
	}
}

// The chain verifying does not replace the pin cross-check: a CA-verified
// reprovision whose address serves a DIFFERENT, CA-trusted key (a
// TLS-terminating proxy) is refused, and nothing is written.
func TestReprovision_CATrustedButDifferentKeyIsRefused(t *testing.T) {
	rosterPath, opts := sshTarget(t, false, newCapturePair(t).pin)
	opts.Reprovisioned, opts.HostKeyFingerprint = true, newHostKey
	before, _ := os.ReadFile(rosterPath)
	session, v := rebuiltNode(newCapturePair(t)) // the node serves this key
	v.served = newCapturePair(t).pin             // the address serves another, trusted (chainErr nil)
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, ErrTLSPinMismatch) || !v.servedVerified {
		t.Fatalf("err = %v (chain verified %v), want ErrTLSPinMismatch", err, v.servedVerified)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) || v.calls != 0 {
		t.Fatal("a trusted-but-different key let a pin be written or a token be validated")
	}
}
