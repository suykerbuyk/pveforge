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

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

func fixedPin(n byte) tlspin.Pin {
	return tlspin.Pin(tlspin.Prefix + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)))
}

// pinnedSSHTarget is baseOptions' target with SSH auth and, when pin is
// set, a TLS pin: the state a T1b bootstrap or pin-tls will leave. T1a
// writes no pin itself; the test writes it with the writer T1b will use.
func pinnedSSHTarget(t *testing.T, pin tlspin.Pin) (string, Options) {
	t.Helper()
	rosterPath := newTestRoster(t, "")
	opts := baseOptions(rosterPath)
	if err := roster.AppendTarget(rosterPath, roster.Target{ID: opts.TargetID, Host: opts.Host, Node: opts.Node, InsecureTLS: true}); err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}
	kp, err := sshexec.GenerateEd25519Keypair("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteSSHAuth(rosterPath, opts.TargetID, roster.SSHWrite{
		User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:abc", PrivateKeyPlaintext: kp.PrivateKeyPEM,
	}, opts.Passphrase); err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	if pin != "" {
		if err := roster.WriteTLSPin(rosterPath, opts.TargetID, "", pin, opts.Passphrase); err != nil {
			t.Fatalf("WriteTLSPin: %v", err)
		}
	}
	return rosterPath, opts
}

func rosterPin(t *testing.T, path, id string) tlspin.Pin {
	t.Helper()
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tg := r.Find(id)
	if tg == nil || tg.TLS == nil {
		return ""
	}
	return tlspin.Pin(tg.TLS.SPKISHA256)
}

// N5, the reuse path (rotation.go's held-token validation): the validator
// is handed the roster's pin, and the run writes nothing.
func TestRun_ReusedTokenIsValidatedThroughTheRosterPin(t *testing.T) {
	pin := fixedPin(3)
	rosterPath, opts := pinnedSSHTarget(t, pin)
	if err := roster.WriteTokenAuth(rosterPath, opts.TargetID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("existing-secret")}, opts.Passphrase); err != nil {
		t.Fatal(err)
	}
	opts.InsecureTLS = false // left unset by the caller: the roster's value is used
	before, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{session: &fakeSession{}}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeReused || v.calls != 1 {
		t.Fatalf("outcome %q after %d validation(s), want reused after 1", res.TokenOutcome, v.calls)
	}
	if v.lastCfg.TLSPin != pin || !v.lastCfg.InsecureTLS {
		t.Fatalf("validated with TLSPin %q insecure %v, want %q true", v.lastCfg.TLSPin, v.lastCfg.InsecureTLS, pin)
	}
	after, _ := os.ReadFile(rosterPath)
	if !bytes.Equal(before, after) {
		t.Fatal("a reused-token run rewrote the roster")
	}
}

// N5, the mint path (validatePostMint): the fresh token is validated
// through the roster's pin, and the pin survives the token write.
func TestRun_MintedTokenIsValidatedThroughTheRosterPin(t *testing.T) {
	pin := fixedPin(4)
	rosterPath, opts := pinnedSSHTarget(t, pin)
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{session: &fakeSession{}}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenOutcome != OutcomeMinted || len(v.cfgsByCall) == 0 {
		t.Fatalf("outcome %q after %d validation(s)", res.TokenOutcome, len(v.cfgsByCall))
	}
	for i, c := range v.cfgsByCall {
		if c.TLSPin != pin {
			t.Errorf("validation %d: TLSPin %q, want %q", i, c.TLSPin, pin)
		}
	}
	if got := rosterPin(t, rosterPath, opts.TargetID); got != pin {
		t.Fatalf("after the token write the roster's pin is %q, want %q", got, pin)
	}
}

// R-a and "T1a writes no pin": an unpinned target is validated with no
// pin, and a run leaves it unpinned.
func TestRun_UnpinnedTargetStaysUnpinned(t *testing.T) {
	rosterPath, opts := pinnedSSHTarget(t, "")
	v := &fakeValidator{}
	if _, err := Run(context.Background(), opts, &fakeTransport{session: &fakeSession{}}, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for i, c := range v.cfgsByCall {
		if c.TLSPin != "" {
			t.Errorf("validation %d: TLSPin %q, want none", i, c.TLSPin)
		}
	}
	if data, _ := os.ReadFile(rosterPath); bytes.Contains(data, []byte("[targets.tls]")) || bytes.Contains(data, []byte("spki_sha256")) {
		t.Fatalf("a T1a run wrote a pin:\n%s", data)
	}
}

// N5 for import-token: its validation goes through the pin the roster
// already holds for the target (Import's options carry none).
func TestImport_ValidatesThroughTheRosterPin(t *testing.T) {
	rp := importRoster(t)
	pin := fixedPin(5)
	if err := roster.AppendTarget(rp, roster.Target{ID: "qa-imp", Host: "h.example", Node: "n1", InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteTLSPin(rp, "qa-imp", "", pin, roster.NewPassphrase(importPass)); err != nil {
		t.Fatal(err)
	}
	v := &importValidator{}
	if _, err := Import(context.Background(), importOpts(rp, "ops@pve!ci", "s3cr3t-0001"), v); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(v.cfgs) != 1 || v.cfgs[0].TLSPin != pin {
		t.Fatalf("validated with %+v, want TLSPin %q", v.cfgs, pin)
	}
	if got := rosterPin(t, rp, "qa-imp"); got != pin {
		t.Fatalf("the import changed the pin to %q", got)
	}
}

func TestDefaultHostNodeFromRoster_TLSPinPrecedence(t *testing.T) {
	rosterPath, opts := pinnedSSHTarget(t, fixedPin(6))
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
	unpinned, uo := pinnedSSHTarget(t, "")
	o = Options{RosterPath: unpinned, TargetID: uo.TargetID}
	defaultHostNodeFromRoster(&o)
	if o.TLSPin != "" {
		t.Fatalf("an unpinned target: TLSPin = %q", o.TLSPin)
	}
}

// The production validator (deps.go) builds its client with the pin: a
// server on another key is refused before any request reaches it.
func TestRealAPIValidator_CarriesThePin(t *testing.T) {
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
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	err = NewAPIValidator().ValidateTokenGrants(context.Background(), APIConfig{
		Host: u.Hostname(), APIPort: port, InsecureTLS: true, TLSPin: fixedPin(8), TokenID: "root@pam!pveforge", TokenSecret: "s",
	}, []Grant{{Path: "/", Role: "PVEAuditor"}})
	if err == nil || !strings.Contains(err.Error(), tlspin.ErrPinMismatch.Error()) {
		t.Fatalf("err = %v, want a TLS pin mismatch", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d request(s) reached a peer that failed the pin", hits.Load())
	}
}
