package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// servedValidator answers ServedPin with pin, counting calls, and refuses
// every token validation (pin-tls must never make one).
type servedValidator struct {
	pin    tlspin.Pin
	served int
	tokens int
}

func (v *servedValidator) ServedPin(context.Context, string, int) (tlspin.Pin, *x509.Certificate, error) {
	v.served++
	if v.pin == "" {
		return "", nil, errors.New("servedValidator: no pin scripted")
	}
	return v.pin, nil, nil
}

func (v *servedValidator) ValidateTokenGrants(context.Context, bootstrap.APIConfig, []bootstrap.Grant) error {
	v.tokens++
	return errors.New("servedValidator: a token validation was attempted")
}

// captureSession answers the capture with pem and records every command.
type captureSession struct {
	pem      string
	commands []string
}

func (s *captureSession) Run(_ context.Context, cmd string) (bootstrap.RunResult, error) {
	s.commands = append(s.commands, cmd)
	if strings.HasPrefix(cmd, "openssl s_client") {
		return bootstrap.RunResult{Stdout: s.pem}, nil
	}
	return bootstrap.RunResult{ExitCode: 1, Stderr: "unscripted"}, nil
}
func (s *captureSession) Close() error { return nil }

// captureTransport hands out session on any connection, recording addrs.
type captureTransport struct {
	session *captureSession
	addrs   []string
	calls   int
}

func (c *captureTransport) InstallPubkeyViaPassword(_ context.Context, addr, _, _, _, pin string) (string, error) {
	c.calls++
	c.addrs = append(c.addrs, addr)
	return pin, nil
}
func (c *captureTransport) DialWithKey(_ context.Context, addr, _ string, _ []byte, _ string) (bootstrap.SSHSession, error) {
	c.calls++
	c.addrs = append(c.addrs, addr)
	return c.session, nil
}
func (c *captureTransport) DialWithPassword(_ context.Context, addr, _, _, pin string) (bootstrap.SSHSession, string, error) {
	c.calls++
	c.addrs = append(c.addrs, addr)
	return c.session, pin, nil
}
func (c *captureTransport) ReconnectWithPinnedKey(_ context.Context, addr, _ string, _ []byte, _ string) (bootstrap.SSHSession, error) {
	c.calls++
	c.addrs = append(c.addrs, addr)
	return c.session, nil
}

func freshCert(t *testing.T) (string, tlspin.Pin) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "n"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), tlspin.FromCertificate(c)
}

// pinCase is one pin-tls run's world: a roster holding target "t" and
// the command seams pointed at tr and v.
type pinCase struct {
	rosterPath string
	tr         *captureTransport
	v          *servedValidator
}

func newPinCase(t *testing.T, keyful bool) *pinCase {
	t.Helper()
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	c := &pinCase{rosterPath: filepath.Join(t.TempDir(), "roster.toml"), tr: &captureTransport{session: &captureSession{}}, v: &servedValidator{}}
	if err := os.WriteFile(c.rosterPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := roster.NewPassphrase(rosterPassphrase)
	if err := roster.AppendTarget(c.rosterPath, roster.Target{ID: "t", Host: "h.example", Node: "n1", InsecureTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteTokenAuth(c.rosterPath, "t", roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("s")}, pass); err != nil {
		t.Fatal(err)
	}
	if keyful {
		kp, err := sshexec.GenerateEd25519Keypair("t")
		if err != nil {
			t.Fatal(err)
		}
		if err := roster.WriteSSHAuth(c.rosterPath, "t", roster.SSHWrite{User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PrivateKeyPlaintext: kp.PrivateKeyPEM}, pass); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	origT, origV := newBootstrapTransport, newBootstrapValidator
	newBootstrapTransport = func() bootstrap.SSHTransport { return c.tr }
	newBootstrapValidator = func() bootstrap.APIValidator { return c.v }
	t.Cleanup(func() { newBootstrapTransport, newBootstrapValidator = origT, origV })
	return c
}

func (c *pinCase) run(args ...string) (int, string, string) {
	return runRootArgs(append([]string{"roster", "pin-tls", "t", "--roster", c.rosterPath}, args...)...)
}

func (c *pinCase) tls(t *testing.T) *roster.TLSPin {
	t.Helper()
	r, err := roster.Load(c.rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	return r.Find("t").TLS
}

func TestRosterPinTLS_Expect(t *testing.T) {
	c := newPinCase(t, false)
	_, pin := freshCert(t)
	c.v.pin = pin
	code, out, stderr := c.run("--expect", string(pin), "-o", "json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var view pinTLSView
	if err := json.Unmarshal([]byte(out), &view); err != nil {
		t.Fatalf("stdout %q: %v", out, err)
	}
	if view.TLSPin != string(pin) || view.TLSPinSource != string(tlspin.SourceExpect) || !view.Written || view.Target != "t" {
		t.Fatalf("view %+v", view)
	}
	if got := c.tls(t); got == nil || got.SPKISHA256 != string(pin) || got.Source != string(tlspin.SourceExpect) {
		t.Fatalf("roster %+v", got)
	}
	if c.tr.calls != 0 || c.v.tokens != 0 || c.v.served != 1 {
		t.Fatalf("ssh calls %d, token validations %d, probes %d; want 0, 0, 1", c.tr.calls, c.v.tokens, c.v.served)
	}
}

// --print is wired: it reports and writes nothing.
func TestRosterPinTLS_PrintWritesNothing(t *testing.T) {
	c := newPinCase(t, false)
	_, pin := freshCert(t)
	c.v.pin = pin
	before, _ := os.ReadFile(c.rosterPath)
	code, out, stderr := c.run("--expect", string(pin), "--print")
	if code != 0 || !strings.Contains(out, "written=false") || !strings.Contains(out, string(pin)) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if after, _ := os.ReadFile(c.rosterPath); !bytes.Equal(before, after) {
		t.Fatal("--print changed the roster")
	}
}

func TestRosterPinTLS_Refusals(t *testing.T) {
	c := newPinCase(t, false)
	_, pin := freshCert(t)
	_, other := freshCert(t)
	c.v.pin = other
	before, _ := os.ReadFile(c.rosterPath)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no --expect for a keyless target":       {nil, "--expect"},
		"an empty --expect":                      {[]string{"--expect", ""}, "not a TLS pin"},
		"a malformed --expect":                   {[]string{"--expect", "SHA256:abc"}, "not a TLS pin"},
		"an --expect the address does not serve": {[]string{"--expect", string(pin)}, bootstrap.ErrTLSPinMismatch.Error()},
		"--repin on a keyless target":            {[]string{"--expect", string(other), "--repin"}, "needs SSH auth"},
	} {
		code, _, stderr := c.run(tc.args...)
		if code == 0 || !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: exit %d, stderr %q; want a refusal naming %q", name, code, stderr, tc.want)
		}
	}
	if after, _ := os.ReadFile(c.rosterPath); !bytes.Equal(before, after) {
		t.Fatal("a refused pin-tls changed the roster")
	}
}

// A keyful target: --ssh-port and --capture-port reach the dial and the
// capture command.
func TestRosterPinTLS_KeyfulPortsAreWired(t *testing.T) {
	c := newPinCase(t, true)
	p, pin := freshCert(t)
	c.tr.session.pem, c.v.pin = p, pin
	code, _, stderr := c.run("--ssh-port", "2222", "--capture-port", "9443")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if len(c.tr.addrs) != 1 || c.tr.addrs[0] != "h.example:2222" {
		t.Fatalf("dialled %v, want h.example:2222", c.tr.addrs)
	}
	if len(c.tr.session.commands) != 1 || !strings.Contains(c.tr.session.commands[0], "127.0.0.1:9443 ") {
		t.Fatalf("commands %v, want one capture on 127.0.0.1:9443", c.tr.session.commands)
	}
	if got := c.tls(t); got == nil || got.SPKISHA256 != string(pin) || got.Source != string(tlspin.SourceSSHStored) {
		t.Fatalf("roster %+v", got)
	}
	// A different key served now: refused without --repin, replaced with it.
	p2, pin2 := freshCert(t)
	c.tr.session.pem, c.v.pin = p2, pin2
	if code, _, stderr := c.run(); code == 0 || !strings.Contains(stderr, "pveforge roster pin-tls t --repin") {
		t.Fatalf("a new key without --repin: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := c.run("--repin"); code != 0 || c.tls(t).SPKISHA256 != string(pin2) {
		t.Fatalf("--repin: exit %d, stderr %q, pin %+v", code, stderr, c.tls(t))
	}
}

// ---- bootstrap's T1b flags, through the command layer ----

// B′ through the CLI: an insecure_tls first run without a vouched host key
// is refused before any connection; --ssh-tofu is wired (it lifts exactly
// that refusal); --capture-port reaches the capture.
func TestBootstrap_BPrimeAndCaptureFlagsAreWired(t *testing.T) {
	c := newPinCase(t, false) // reuse its seams and roster; bootstrap a new target "b"
	base := []string{"bootstrap", "b", "--roster", c.rosterPath, "--host", "b.example", "--node", "n1", "--insecure-tls", "--grant", "/vms/100:PVEVMUser"}
	t.Setenv("PVEFORGE_PVE_PASSWORD", "pw")

	code, _, stderr := runRootArgs(base...)
	if code == 0 || !strings.Contains(stderr, "--host-key-fingerprint") || c.tr.calls != 0 {
		t.Fatalf("no fingerprint, no --ssh-tofu: exit %d, stderr %q, ssh calls %d", code, stderr, c.tr.calls)
	}
	code, _, stderr = runRootArgs(append(base, "--ssh-tofu", "--host-key-fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	if code == 0 || !strings.Contains(stderr, "contradict") {
		t.Fatalf("both: exit %d, stderr %q", code, stderr)
	}
	// --ssh-tofu and --capture-port: the run now dials and captures on the
	// named port; the address serves another key, so it stops right there,
	// before any token.
	p, _ := freshCert(t)
	_, other := freshCert(t)
	c.tr.session.pem, c.v.pin = p, other
	code, _, stderr = runRootArgs(append(base, "--ssh-tofu", "--capture-port", "9443")...)
	if code == 0 || !strings.Contains(stderr, bootstrap.ErrTLSPinMismatch.Error()) {
		t.Fatalf("--ssh-tofu: exit %d, stderr %q, want the capture's mismatch", code, stderr)
	}
	var capture string
	for _, cmd := range c.tr.session.commands {
		if strings.HasPrefix(cmd, "openssl s_client") {
			capture = cmd
		}
		if strings.HasPrefix(cmd, "pveum") {
			t.Errorf("a pveum command ran after the mismatch: %q", cmd)
		}
	}
	if !strings.Contains(capture, "127.0.0.1:9443 ") {
		t.Fatalf("capture %q, want it on 127.0.0.1:9443", capture)
	}
	if c.v.tokens != 0 {
		t.Fatalf("%d token validation(s) after a pin mismatch", c.v.tokens)
	}
}

func TestBootstrapView_TLSFields(t *testing.T) {
	var out, errOut bytes.Buffer
	res := &bootstrap.Result{TokenID: "a@pam!b", TokenOutcome: bootstrap.OutcomeMinted, Validation: bootstrap.ValidationVerified,
		TLSPin: "sha256//AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=", TLSPinSource: tlspin.SourceSSHTOFU}
	format, err := kvjson.ParseFormat("json")
	if err != nil {
		t.Fatal(err)
	}
	if err := renderBootstrapResult(&out, &errOut, format, "t", res); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["tls_spki_sha256"] != string(res.TLSPin) || m["tls_pin_source"] != "ssh-tofu" {
		t.Fatalf("view %v", m)
	}
	out.Reset()
	res.TLSPin, res.TLSPinSource = "", ""
	_ = renderBootstrapResult(&out, &errOut, format, "t", res)
	if strings.Contains(out.String(), "tls_") {
		t.Fatalf("no pin captured, yet the view carries tls fields: %s", out.String())
	}
}

// Every flag an error of T1b names exists on the command it names (N7): a
// T1b binary never tells the operator to use a flag it lacks.
func TestT1bErrors_NameOnlyFlagsThatExist(t *testing.T) {
	root := newRootCmd()
	cmds := map[string]*cobra.Command{}
	for _, path := range [][]string{{"bootstrap"}, {"roster", "pin-tls"}} {
		c, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		cmds[strings.Join(path, " ")] = c
	}
	flagRE := regexp.MustCompile(`--[a-z][a-z-]*`)
	check := func(where, msg string) {
		for _, f := range flagRE.FindAllString(msg, -1) {
			if cmds[where].Flags().Lookup(strings.TrimPrefix(f, "--")) == nil && cmds[where].InheritedFlags().Lookup(strings.TrimPrefix(f, "--")) == nil {
				t.Errorf("%s: an error names %s, which `pveforge %s` does not have: %q", where, f, where, msg)
			}
		}
	}
	check("bootstrap", bootstrap.ErrHostKeyFingerprintRequired.Error())
	check("bootstrap", "--capture-port") // the capture's exit-status hint
	check("roster pin-tls", "--repin --expect --print --capture-port --ssh-port --lock-wait")
	for _, f := range []string{"ssh-tofu", "capture-port"} {
		if cmds["bootstrap"].Flags().Lookup(f) == nil {
			t.Errorf("bootstrap has no --%s", f)
		}
	}
}

// Without --ssh-port, pin-tls dials the port RoutedClient dials (the
// roster stores none).
func TestRosterPinTLS_DefaultSSHPortIsRoutedClients(t *testing.T) {
	c := newPinCase(t, true)
	p, pin := freshCert(t)
	c.tr.session.pem, c.v.pin = p, pin
	if code, _, stderr := c.run(); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "h.example:" + strconv.Itoa(pve.RoutedSSHPort()); len(c.tr.addrs) != 1 || c.tr.addrs[0] != want {
		t.Fatalf("dialled %v, want %s", c.tr.addrs, want)
	}
}
