package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

const testHostKey = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func fixedPin(n byte) tlspin.Pin {
	return tlspin.Pin(tlspin.Prefix + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)))
}

// sshTarget is baseOptions' target with SSH auth pinned to testHostKey,
// insecure_tls as given, and, when pin is set, a TLS pin (written with
// the writer bootstrap and pin-tls use).
func sshTarget(t *testing.T, insecure bool, pin tlspin.Pin) (string, Options) {
	t.Helper()
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node, InsecureTLS: insecure}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: testHostKey, PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if pin != "" {
		if err := roster.WriteTLSPin(rosterPath, opts.TargetID, "", pin, tlspin.SourceSSHStored, opts.Passphrase); err != nil {
			t.Fatalf("WriteTLSPin: %v", err)
		}
	}
	return rosterPath, opts
}

// bareTarget is a target the roster holds with no auth at all, insecure,
// for a first run.
func bareTarget(t *testing.T) (string, Options) {
	t.Helper()
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	opts.InsecureTLS = true
	return rosterPath, opts
}

func rosterTLS(t *testing.T, path, id string) *roster.TLSPin {
	t.Helper()
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tg := r.Find(id)
	if tg == nil {
		return nil
	}
	return tg.TLS
}

func rosterPin(t *testing.T, path, id string) tlspin.Pin {
	t.Helper()
	if p := rosterTLS(t, path, id); p != nil {
		return tlspin.Pin(p.SPKISHA256)
	}
	return ""
}

func commandIndex(s *fakeSession, prefix string) int {
	for i, c := range s.commands {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// ---- The capture, on each SSH branch ----

// A first keyful run with --host-key-fingerprint: the pin is captured over
// the session, checked against what the address serves, and on disk
// before any token command runs; source ssh-verified.
func TestRun_FirstRunCapturesThePinBeforeAnyToken(t *testing.T) {
	rosterPath, opts := bareTarget(t)
	opts.HostKeyFingerprint = testHostKey
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	pinnedAtFirstValidation := tlspin.Pin("unset")
	v.onCall = func(call int) {
		if call == 0 {
			pinnedAtFirstValidation = rosterPin(t, rosterPath, opts.TargetID)
		}
	}
	res, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(tlspin.SourceSSHVerified) {
		t.Fatalf("roster [targets.tls] = %+v, want %s from ssh-verified", got, cp.pin)
	}
	if res.TLSPin != cp.pin || res.TLSPinSource != tlspin.SourceSSHVerified {
		t.Fatalf("Result TLSPin %q source %q", res.TLSPin, res.TLSPinSource)
	}
	if pinnedAtFirstValidation != cp.pin {
		t.Fatalf("at the first validation the roster pinned %q, want the pin already written", pinnedAtFirstValidation)
	}
	capAt, addAt := commandIndex(session, captureCmdPrefix), commandIndex(session, "pveum user token add")
	if capAt < 0 || addAt < 0 || capAt > addAt {
		t.Fatalf("capture at %d, token add at %d: the capture must come first", capAt, addAt)
	}
	if v.servedCalls != 1 {
		t.Fatalf("ServedPin calls = %d, want 1", v.servedCalls)
	}
	for i, c := range v.cfgsByCall {
		if c.TLSPin != cp.pin {
			t.Errorf("validation %d ran with TLSPin %q, want the captured pin", i, c.TLSPin)
		}
	}
}

func TestRun_KeylessCapturesOverThePasswordSession(t *testing.T) {
	for name, c := range map[string]struct {
		fp     string
		tofu   bool
		source tlspin.Source
	}{
		"verified host key": {testHostKey, false, tlspin.SourceSSHVerified},
		"--ssh-tofu":        {"", true, tlspin.SourceSSHTOFU},
	} {
		rosterPath, opts := bareTarget(t)
		opts.NoSSHKey, opts.HostKeyFingerprint, opts.SSHTOFU = true, c.fp, c.tofu
		session := &fakeSession{}
		v := &fakeValidator{}
		cp := newCapturePair(t)
		scriptCapture(session, v, cp)
		res, err := Run(context.Background(), opts, &fakeTransport{session: session, dialPWFingerprint: testHostKey}, v)
		if err != nil {
			t.Fatalf("%s: Run: %v", name, err)
		}
		if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || tlspin.Pin(got.SPKISHA256) != cp.pin || got.Source != string(c.source) {
			t.Fatalf("%s: roster [targets.tls] = %+v, want %s from %s", name, got, cp.pin, c.source)
		}
		if res.TLSPinSource != c.source {
			t.Fatalf("%s: Result source %q, want %q", name, res.TLSPinSource, c.source)
		}
	}
}

// A target with a stored SSH pin is exempt from B′ and captures over the
// session pinned to it: source ssh-stored.
func TestRun_StoredSSHPinCapturesAsSSHStored(t *testing.T) {
	rosterPath, opts := sshTarget(t, true, "")
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	res, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || got.Source != string(tlspin.SourceSSHStored) || res.TLSPinSource != tlspin.SourceSSHStored {
		t.Fatalf("roster %+v, result %q; want ssh-stored", got, res.TLSPinSource)
	}
}

// N5 with T1b: the reuse path validates through the roster's pin once the
// capture has matched it, and an equal pin rewrites nothing.
func TestRun_ReusedTokenIsValidatedThroughTheRosterPin(t *testing.T) {
	cp := newCapturePair(t)
	rosterPath, opts := sshTarget(t, true, cp.pin)
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("existing-secret")}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	opts.InsecureTLS = false // left unset: the roster's value is used
	before, _ := os.ReadFile(rosterPath)
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, cp)
	res, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeReused || v.calls != 1 || v.lastCfg.TLSPin != cp.pin {
		t.Fatalf("outcome %q, %d validation(s), TLSPin %q", res.TokenOutcome, v.calls, v.lastCfg.TLSPin)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) {
		t.Fatal("a reused-token run with an equal pin rewrote the roster")
	}
}

func TestRun_MintedTokenIsValidatedThroughTheRosterPin(t *testing.T) {
	cp := newCapturePair(t)
	rosterPath, opts := sshTarget(t, true, cp.pin)
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, cp)
	res, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeMinted || len(v.cfgsByCall) == 0 {
		t.Fatalf("outcome %q after %d validation(s)", res.TokenOutcome, len(v.cfgsByCall))
	}
	for i, c := range v.cfgsByCall {
		if c.TLSPin != cp.pin {
			t.Errorf("validation %d: TLSPin %q, want %q", i, c.TLSPin, cp.pin)
		}
	}
	if got := rosterPin(t, rosterPath, opts.TargetID); got != cp.pin {
		t.Fatalf("after the token write the roster's pin is %q", got)
	}
}

// ---- Refusals before any token (RQ1), each by its specific error ----

func TestRun_AddressServingAnotherKeyRefusesBeforeAnyToken(t *testing.T) {
	for name, keyless := range map[string]bool{"keyful first run": false, "keyless": true} {
		rosterPath, opts := bareTarget(t)
		opts.NoSSHKey, opts.HostKeyFingerprint = keyless, testHostKey
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		v.served = newCapturePair(t).pin // the address serves ANOTHER key
		_, err := Run(context.Background(), opts, &fakeTransport{session: session, dialPWFingerprint: testHostKey}, v)
		if !errors.Is(err, ErrTLSPinMismatch) {
			t.Fatalf("%s: err = %v, want ErrTLSPinMismatch", name, err)
		}
		if !strings.Contains(err.Error(), "TLS-terminating proxy") || !strings.Contains(err.Error(), "wrote no TLS pin, SSH auth or token to the roster, and sent no token") {
			t.Errorf("%s: the refusal does not explain itself: %v", name, err)
		}
		if v.servedCalls != 1 || v.calls != 0 || session.ran("pveum user token add") || session.ran("pveum acl modify") {
			t.Fatalf("%s: probes %d, validations %d, token add %v, acl %v; want 1, 0, false, false", name, v.servedCalls, v.calls, session.ran("pveum user token add"), session.ran("pveum acl modify"))
		}
		if tg := rosterTLS(t, rosterPath, opts.TargetID); tg != nil {
			t.Fatalf("%s: a pin was written: %+v", name, tg)
		}
		if data, _ := os.ReadFile(rosterPath); bytes.Contains(data, []byte("[targets.token]")) {
			t.Fatalf("%s: a token was written", name)
		}
	}
}

func TestRun_CaptureFailuresRefuseBeforeAnyToken(t *testing.T) {
	cp := newCapturePair(t)
	for name, c := range map[string]struct {
		answer fakeRunResult
		want   string
	}{
		"nothing printed (openssl missing, or nothing on the port)": {fakeRunResult{res: RunResult{}}, "not exactly one PEM certificate"},
		"the capture exits non-zero":                                {fakeRunResult{res: RunResult{ExitCode: 1}}, "--capture-port"},
		"two certificates":                                          {fakeRunResult{res: RunResult{Stdout: cp.pem + cp.pem}}, "more follows"},
		"the command fails to run":                                  {fakeRunResult{err: errors.New("session reset")}, "run the capture"},
	} {
		_, opts := bareTarget(t)
		opts.HostKeyFingerprint = testHostKey
		session := &fakeSession{byCmd: map[string]fakeRunResult{captureCmdPrefix: c.answer}}
		v := &fakeValidator{served: cp.pin}
		_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
		if !errors.Is(err, ErrTLSCapture) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want ErrTLSCapture naming %q", name, err, c.want)
		}
		if v.servedCalls != 0 || v.calls != 0 || session.ran("pveum user token add") {
			t.Errorf("%s: probes %d, validations %d, token add %v; want none", name, v.servedCalls, v.calls, session.ran("pveum user token add"))
		}
	}
}

func TestRun_ProbeFailureRefusesBeforeAnyToken(t *testing.T) {
	_, opts := bareTarget(t)
	opts.HostKeyFingerprint = testHostKey
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, newCapturePair(t))
	sentinel := errors.New("probe refused")
	v.servedErr = sentinel
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, sentinel) || v.calls != 0 || session.ran("pveum user token add") {
		t.Fatalf("err = %v, validations %d, token add %v", err, v.calls, session.ran("pveum user token add"))
	}
}

// The roster pins another key: refused, nothing written, and the message
// names only what exists in T1b (pin-tls --repin for a keyful target, the
// hand edit otherwise).
func TestRun_StoredPinDiffersIsRefused(t *testing.T) {
	stored := newCapturePair(t)
	rosterPath, opts := sshTarget(t, true, stored.pin)
	before, _ := os.ReadFile(rosterPath)
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, newCapturePair(t))
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, ErrTLSPinDiffers) || !strings.Contains(err.Error(), "pveforge roster pin-tls qa-pve-01 --repin") {
		t.Fatalf("err = %v, want ErrTLSPinDiffers naming roster pin-tls --repin", err)
	}
	// T2: it also names the reprovision, with the console value, never a
	// pin (inverted from T1b, which had no --reprovisioned).
	if !strings.Contains(err.Error(), "pveforge bootstrap qa-pve-01 --reprovisioned --host-key-fingerprint <the console value>") || !strings.Contains(err.Error(), "CONSOLE") {
		t.Errorf("the T2 message does not name the reprovision with the console value: %v", err)
	}
	if after, _ := os.ReadFile(rosterPath); !bytes.Equal(before, after) || v.calls != 0 || session.ran("pveum user token add") {
		t.Fatal("a refused run changed the roster or reached the token phase")
	}
	// Keyless: --repin cannot help it; the keyless reprovision can (T2).
	if e := differsError("k", stored.pin, fixedPin(1), false).Error(); strings.Contains(e, "--repin") || !strings.Contains(e, "pveforge bootstrap k --no-ssh-key --reprovisioned --host-key-fingerprint <the console value>") {
		t.Errorf("the keyless form: %s", e)
	}
}

// The CAS: a pin written by another pveforge between the run's roster read
// and its write is refused, not overwritten.
func TestRun_PinWrittenMeanwhileIsRefusedByTheCAS(t *testing.T) {
	rosterPath, opts := bareTarget(t)
	opts.HostKeyFingerprint = testHostKey
	cp := newCapturePair(t)
	session := &fakeSession{}
	v := &fakeValidator{}
	scriptCapture(session, v, cp)
	r := session.byCmd[captureCmdPrefix]
	r.onRun = func(context.Context, string) {
		if err := roster.WriteTLSPin(rosterPath, opts.TargetID, "", cp.pin, tlspin.SourceExpect, opts.Passphrase); err != nil {
			t.Errorf("the concurrent writer: %v", err)
		}
	}
	session.byCmd[captureCmdPrefix] = r
	_, err := Run(context.Background(), opts, &fakeTransport{session: session}, v)
	if !errors.Is(err, roster.ErrTLSPinChanged) || session.ran("pveum user token add") {
		t.Fatalf("err = %v (token add %v), want ErrTLSPinChanged before any token", err, session.ran("pveum user token add"))
	}
}

// ---- B′ (operator ruling RQ3) ----

func TestRun_BPrimeRequiresAVouchedHostKey(t *testing.T) {
	for name, keyless := range map[string]bool{"first run": false, "keyless": true} {
		rosterPath, opts := bareTarget(t)
		opts.NoSSHKey = keyless
		tr := &fakeTransport{session: &fakeSession{}}
		v := &fakeValidator{}
		_, err := Run(context.Background(), opts, tr, v)
		if !errors.Is(err, ErrHostKeyFingerprintRequired) {
			t.Fatalf("%s: err = %v, want ErrHostKeyFingerprintRequired", name, err)
		}
		if tr.installCalls+tr.dialCalls+tr.dialPWCalls+tr.reconnectCalls != 0 || v.servedCalls != 0 {
			t.Fatalf("%s: a connection was made before the refusal", name)
		}
		if data, _ := os.ReadFile(rosterPath); len(data) != 0 {
			t.Fatalf("%s: the refusal wrote the roster:\n%s", name, data)
		}
	}
}

func TestRun_SSHTOFUOnlyWhereItApplies(t *testing.T) {
	for name, mk := range map[string]func() (Options, string){
		"with --host-key-fingerprint": func() (Options, string) {
			_, o := bareTarget(t)
			o.SSHTOFU, o.HostKeyFingerprint = true, testHostKey
			return o, "contradict"
		},
		"a CA-verified target": func() (Options, string) {
			_, o := sshTarget(t, false, "")
			o.SSHTOFU = true
			return o, "only to an insecure_tls target"
		},
		"a stored SSH pin": func() (Options, string) {
			_, o := sshTarget(t, true, "")
			o.SSHTOFU = true
			return o, "does not apply"
		},
	} {
		opts, want := mk()
		tr := &fakeTransport{session: &fakeSession{}}
		_, err := Run(context.Background(), opts, tr, &fakeValidator{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, want)
		}
		if tr.installCalls+tr.dialCalls+tr.dialPWCalls+tr.reconnectCalls != 0 {
			t.Errorf("%s: a connection was made", name)
		}
	}
}

// N6: a CA-verified target is never pinned implicitly, and nothing is
// probed or captured.
func TestRun_CAVerifiedTargetIsNotCaptured(t *testing.T) {
	rosterPath, opts := sshTarget(t, false, "")
	session := &fakeSession{}
	v := &fakeValidator{}
	if _, err := Run(context.Background(), opts, &fakeTransport{session: session}, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if v.servedCalls != 0 || session.ran(captureCmdPrefix) || rosterTLS(t, rosterPath, opts.TargetID) != nil {
		t.Fatalf("probes %d, capture run %v, pin %+v; want none", v.servedCalls, session.ran(captureCmdPrefix), rosterTLS(t, rosterPath, opts.TargetID))
	}
}

func TestRun_CapturePort(t *testing.T) {
	for port, want := range map[int]string{0: "127.0.0.1:8006 ", 9443: "127.0.0.1:9443 "} {
		_, opts := sshTarget(t, true, "")
		opts.CapturePort = port
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		if _, err := Run(context.Background(), opts, &fakeTransport{session: session}, v); err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		if i := commandIndex(session, captureCmdPrefix); i < 0 || !strings.Contains(session.commands[i], want) {
			t.Fatalf("port %d: capture command %v, want one on %q", port, session.commands, want)
		}
	}
}

// ---- import-token and the real validator (T1a, kept) ----

func TestImport_ValidatesThroughTheRosterPin(t *testing.T) {
	rp := importRoster(t)
	pin := fixedPin(5)
	if err := roster.AppendTarget(rp, roster.Target{ID: "qa-imp", Host: "h.example", Node: "n1", InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteTLSPin(rp, "qa-imp", "", pin, tlspin.SourceExpect, roster.NewPassphrase(importPass)); err != nil {
		t.Fatal(err)
	}
	v := &importValidator{}
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), v); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(v.cfgs) != 1 || v.cfgs[0].TLSPin != pin {
		t.Fatalf("validated with %+v, want TLSPin %q", v.cfgs, pin)
	}
}

func TestDefaultHostNodeFromRoster_TLSPinPrecedence(t *testing.T) {
	rosterPath, opts := sshTarget(t, true, fixedPin(6))
	o := Options{RosterPath: rosterPath, TargetID: opts.TargetID}
	defaultHostNodeFromRoster(&o)
	if o.TLSPin != fixedPin(6) {
		t.Fatalf("unset: TLSPin = %q, want the roster's", o.TLSPin)
	}
	o = Options{RosterPath: rosterPath, TargetID: opts.TargetID, TLSPin: fixedPin(7)}
	defaultHostNodeFromRoster(&o)
	if o.TLSPin != fixedPin(7) {
		t.Fatalf("set: TLSPin = %q, want the caller's", o.TLSPin)
	}
}

func tlsTestServer(t *testing.T) (*httptest.Server, tlspin.Pin, *atomic.Int32, string, int) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return srv, tlspin.FromCertificate(cert), &hits, u.Hostname(), port
}

func TestRealAPIValidator_CarriesThePin(t *testing.T) {
	_, _, hits, host, port := tlsTestServer(t)
	err := NewAPIValidator().ValidateTokenGrants(context.Background(), APIConfig{
		Host: host, APIPort: port, InsecureTLS: true, TLSPin: fixedPin(8), TokenID: "root@pam!pveforge", TokenSecret: "s",
	}, []Grant{{Path: "/", Role: "PVEAuditor"}})
	if err == nil || !strings.Contains(err.Error(), tlspin.ErrPinMismatch.Error()) {
		t.Fatalf("err = %v, want a TLS pin mismatch", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d request(s) reached a peer that failed the pin", hits.Load())
	}
}

// The production validator's ServedPin is pve.ServedPin: the server's own
// pin, with no request made.
func TestRealAPIValidator_ServedPin(t *testing.T) {
	_, pin, hits, host, port := tlsTestServer(t)
	got, cert, err := NewAPIValidator().ServedPin(context.Background(), host, port, false)
	if err != nil || got != pin || cert == nil {
		t.Fatalf("ServedPin = %s, %v, %v; want %s", got, cert != nil, err, pin)
	}
	if hits.Load() != 0 {
		t.Fatalf("ServedPin made %d request(s)", hits.Load())
	}
}

// ---- The Chair's T1b review ----

// requireProbedTheRESTAddress: the cross-check was asked for exactly the
// address REST dials, host and port, the port as REST reads it.
func requireProbedTheRESTAddress(t *testing.T, v *fakeValidator, host string, apiPort int) {
	t.Helper()
	if v.servedHost != host || v.servedPort != pve.EffectiveAPIPort(apiPort) {
		t.Fatalf("the cross-check probed %s:%d; REST dials %s:%d", v.servedHost, v.servedPort, host, pve.EffectiveAPIPort(apiPort))
	}
}

// (1) One rule for the address: the cross-check probes the host and port
// the REST client (APIConfig) dials, never the node-local capture port or
// 127.0.0.1, and port 0 is read as REST reads it, 8006.
func TestRun_CrossCheckProbesTheRESTAddress(t *testing.T) {
	for _, apiPort := range []int{0, 8443} {
		rosterPath := newTestRoster(t, "")
		opts := baseOptions(rosterPath)
		if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node, APIPort: apiPort, InsecureTLS: true}); err != nil {
			t.Fatal(err)
		}
		opts.HostKeyFingerprint = testHostKey
		session := &fakeSession{}
		v := &fakeValidator{}
		scriptCapture(session, v, newCapturePair(t))
		if _, err := Run(context.Background(), opts, &fakeTransport{session: session}, v); err != nil {
			t.Fatalf("api port %d: Run: %v", apiPort, err)
		}
		if v.calls == 0 {
			t.Fatalf("api port %d: no validation ran", apiPort)
		}
		// The REST side of the same run: what its APIConfig dials.
		requireProbedTheRESTAddress(t, v, v.lastCfg.Host, v.lastCfg.APIPort)
		if v.lastCfg.Host != opts.Host || pve.EffectiveAPIPort(v.lastCfg.APIPort) != pve.EffectiveAPIPort(apiPort) {
			t.Fatalf("api port %d: REST dials %s:%d", apiPort, v.lastCfg.Host, v.lastCfg.APIPort)
		}
	}
}

// (2) A first run that fails at the capture or the cross-check persists no
// SSH auth: a rerun is again a first run, needs the host key vouched for
// (or --ssh-tofu) again, and records the pin's real origin.
func TestRun_FailedFirstRunLeavesNoStoredSSHPin(t *testing.T) {
	rosterPath, opts := bareTarget(t)
	opts.SSHTOFU = true
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	v.served = newCapturePair(t).pin // the address serves another key
	tr := &fakeTransport{installFingerprint: testHostKey, session: session}
	_, err := Run(context.Background(), opts, tr, v)
	if !errors.Is(err, ErrTLSPinMismatch) {
		t.Fatalf("err = %v, want ErrTLSPinMismatch", err)
	}
	r, _ := roster.Load(rosterPath)
	if tg := r.Find(opts.TargetID); tg == nil || tg.SSH != nil || tg.TLS != nil || tg.Token != nil {
		t.Fatalf("after the refused first run the roster holds %+v; want the target with no SSH auth, pin or token (the error says so)", tg)
	}
	// The rerun: still a first run, so B′ applies again.
	opts2 := opts
	opts2.SSHTOFU = false
	if _, err := Run(context.Background(), opts2, &fakeTransport{installFingerprint: testHostKey, session: &fakeSession{}}, &fakeValidator{}); !errors.Is(err, ErrHostKeyFingerprintRequired) {
		t.Fatalf("rerun without --ssh-tofu: err = %v, want ErrHostKeyFingerprintRequired", err)
	}
	session3 := &fakeSession{}
	v3 := &fakeValidator{}
	scriptCapture(session3, v3, cp)
	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: testHostKey, session: session3}, v3)
	if err != nil {
		t.Fatalf("rerun with --ssh-tofu: %v", err)
	}
	if got := rosterTLS(t, rosterPath, opts.TargetID); got == nil || got.Source != string(tlspin.SourceSSHTOFU) || res.TLSPinSource != tlspin.SourceSSHTOFU {
		t.Fatalf("roster %+v, result %q; want ssh-tofu", got, res.TLSPinSource)
	}
}

// (2) and (4a): once pinned with ssh-tofu, a later run over the stored SSH
// pin reports the RECORDED source, never ssh-stored.
func TestRun_MatchingStoredPinReportsTheRecordedSource(t *testing.T) {
	rosterPath, opts := bareTarget(t)
	opts.SSHTOFU = true
	session := &fakeSession{}
	v := &fakeValidator{}
	cp := newCapturePair(t)
	scriptCapture(session, v, cp)
	if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: testHostKey, session: session}, v); err != nil {
		t.Fatalf("first run: %v", err)
	}
	later := baseOptions(rosterPath) // dials the stored SSH pin now
	session2 := &fakeSession{}
	v2 := &fakeValidator{}
	scriptCapture(session2, v2, cp)
	res, err := Run(context.Background(), later, &fakeTransport{session: session2}, v2)
	if err != nil {
		t.Fatalf("later run: %v", err)
	}
	if res.TLSPin != cp.pin || res.TLSPinSource != tlspin.SourceSSHTOFU {
		t.Fatalf("later run reports %s from %q; want the recorded ssh-tofu", res.TLSPin, res.TLSPinSource)
	}
	if got := rosterTLS(t, rosterPath, later.TargetID); got.Source != string(tlspin.SourceSSHTOFU) {
		t.Fatalf("the roster's source became %q", got.Source)
	}
}
