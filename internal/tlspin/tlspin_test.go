package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newCert makes a self-signed certificate on a FRESH ECDSA P-256 key, so
// no two calls share a pin (every httptest server shares Go's one testcert
// key, so a test built on those could not tell one server's pin from
// another's).
func newCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pve.example.test"},
		DNSNames:     []string{"pve.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// independentPin computes a pin the way openssl's documented pipeline
// does, from the public key re-marshalled, not from RawSubjectPublicKeyInfo:
// a separate observer for FromCertificate.
func independentPin(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestFromCertificate_MatchesTheSPKIDigest(t *testing.T) {
	_, c := newCert(t)
	got := FromCertificate(c)
	if want := independentPin(t, c); string(got) != want {
		t.Fatalf("FromCertificate = %s, want %s", got, want)
	}
	if _, err := Parse(string(got)); err != nil {
		t.Fatalf("FromCertificate's own output does not Parse: %v", err)
	}
}

// Two fresh keys have different pins, and neither is the pin of the key
// every httptest.NewTLSServer shares: the anti-vacuity for every test that
// tells two peers apart by pin.
func TestNewCert_PinsDiffer(t *testing.T) {
	_, a := newCert(t)
	_, b := newCert(t)
	if FromCertificate(a) == FromCertificate(b) {
		t.Fatal("two fresh keys share a pin")
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	shared := FromCertificate(srv.Certificate())
	if FromCertificate(a) == shared || FromCertificate(b) == shared {
		t.Fatal("a fresh key has httptest's shared testcert pin")
	}
}

func TestParse(t *testing.T) {
	_, c := newCert(t)
	good := string(FromCertificate(c))
	if p, err := Parse(good); err != nil || string(p) != good {
		t.Fatalf("Parse(%q) = %q, %v", good, p, err)
	}
	body := strings.TrimPrefix(good, Prefix)
	for _, bad := range []string{
		"",
		body,                                   // no prefix
		"SHA256//" + body,                      // prefix case
		"sha256/" + body,                       // one slash
		Prefix + strings.TrimSuffix(body, "="), // unpadded
		" " + good,                             // leading space
		good + "\n",                            // trailing newline
		Prefix + strings.Repeat("A", 44),       // 33 bytes' worth, no padding
		"SHA256:" + strings.TrimSuffix(body, "="),                               // an SSH fingerprint's form
		Prefix + base64.URLEncoding.EncodeToString(make([]byte, 32))[:43] + "-", // URL alphabet
	} {
		if _, err := Parse(bad); !errors.Is(err, ErrMalformedPin) {
			t.Errorf("Parse(%q) = %v, want ErrMalformedPin", bad, err)
		}
	}
}

func TestLeafFromPEM(t *testing.T) {
	_, c := newCert(t)
	_, other := newCert(t)
	one := pemOf(c)
	got, err := LeafFromPEM(append(append([]byte("\n\n"), one...), '\n'))
	if err != nil {
		t.Fatalf("one certificate with whitespace around it: %v", err)
	}
	if FromCertificate(got) != FromCertificate(c) {
		t.Fatal("LeafFromPEM returned another certificate")
	}
	// The marker is what a hostile or confused remote might print; no error
	// may quote it back (instrument #16).
	const marker = "SECRET-MARKER-7f3c"
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(marker)})
	for name, in := range map[string][]byte{
		"empty":             nil,
		"not PEM":           []byte(marker),
		"two certificates":  append(append([]byte{}, one...), pemOf(other)...),
		"not a certificate": keyPEM,
		"trailing garbage":  append(append([]byte{}, one...), []byte(marker)...),
		"leading garbage":   append([]byte(marker+"\n"), one...),
		"garbage DER":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(marker)}),
	} {
		_, err := LeafFromPEM(in)
		if !errors.Is(err, ErrBadCertificatePEM) {
			t.Errorf("%s: err = %v, want ErrBadCertificatePEM", name, err)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error quotes its input: %v", name, err)
		}
	}
}

func TestVerifyConnection_Unit(t *testing.T) {
	_, c := newCert(t)
	_, other := newCert(t)
	want := FromCertificate(c)
	verify, err := VerifyConnection(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}); err != nil {
		t.Fatalf("the pinned certificate: %v", err)
	}
	err = verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{other, c}})
	var me *MismatchError
	if !errors.As(err, &me) || !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("another leaf (the pinned one second in the chain): err = %v, want a MismatchError", err)
	}
	if me.Want != want || me.Got != FromCertificate(other) {
		t.Fatalf("MismatchError = %+v, want Want %s Got %s", me, want, FromCertificate(other))
	}
	if !strings.Contains(err.Error(), string(me.Got)) || !strings.Contains(err.Error(), string(want)) {
		t.Fatalf("the error does not name both pins: %v", err)
	}
	// A pin that differs from the peer's only in its LAST base64 digit is a
	// mismatch: the whole pin is compared, not a prefix of it.
	w := []byte(want)
	last := len(w) - 2 // the digit before the "=" padding
	if w[last] == 'A' {
		w[last] = 'E'
	} else {
		w[last] = 'A'
	}
	near, err := VerifyConnection(Pin(w))
	if err != nil {
		t.Fatal(err)
	}
	if err := near(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("a pin differing only in its last digit: err = %v, want ErrPinMismatch", err)
	}
	if err := verify(tls.ConnectionState{}); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("no peer certificate: err = %v, want ErrPinMismatch", err)
	}
	for _, bad := range []Pin{"", "sha256//x"} {
		if f, err := VerifyConnection(bad); f != nil || !errors.Is(err, ErrMalformedPin) {
			t.Errorf("VerifyConnection(%q) = %v, %v; want nil, ErrMalformedPin", bad, f != nil, err)
		}
	}
}

// Through a real handshake: the right pin connects, a different server's
// key is refused, and the refusal comes before any request reaches the
// server.
func TestVerifyConnection_Handshake(t *testing.T) {
	serve := func() (*httptest.Server, Pin, *int) {
		kp, c := newCert(t)
		hits := new(int)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { *hits++ }))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{kp}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv, FromCertificate(c), hits
	}
	a, pinA, hitsA := serve()
	_, pinB, _ := serve()
	get := func(pin Pin) error {
		verify, err := VerifyConnection(pin)
		if err != nil {
			t.Fatal(err)
		}
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // the pin is the identity under test
			VerifyConnection:   verify,
		}}}
		res, err := cl.Get(a.URL)
		if err == nil {
			res.Body.Close()
		}
		return err
	}
	if err := get(pinA); err != nil {
		t.Fatalf("server A with A's pin: %v", err)
	}
	if *hitsA != 1 {
		t.Fatalf("server A saw %d requests, want 1", *hitsA)
	}
	if err := get(pinB); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("server A with B's pin: err = %v, want ErrPinMismatch", err)
	}
	if *hitsA != 1 {
		t.Fatalf("a refused handshake still reached the handler (%d requests)", *hitsA)
	}
}

func TestCaptureCommand(t *testing.T) {
	cmd := CaptureCommand(8443)
	for _, want := range []string{"openssl s_client -connect 127.0.0.1:8443 ", "</dev/null", "| openssl x509 -outform PEM"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("CaptureCommand(8443) = %q, missing %q", cmd, want)
		}
	}
	if DefaultCapturePort != 8006 {
		t.Errorf("DefaultCapturePort = %d, want pveproxy's 8006", DefaultCapturePort)
	}
}

func TestParseCapture(t *testing.T) {
	_, c := newCert(t)
	pin, cert, err := ParseCapture(pemOf(c))
	if err != nil || pin != FromCertificate(c) || cert == nil {
		t.Fatalf("ParseCapture = %s, %v, %v", pin, cert != nil, err)
	}
	for name, in := range map[string][]byte{"empty (openssl missing, or nothing served)": nil, "not PEM": []byte("unable to load certificate")} {
		_, _, err := ParseCapture(in)
		if !errors.Is(err, ErrCapture) || !errors.Is(err, ErrBadCertificatePEM) {
			t.Errorf("%s: err = %v, want ErrCapture wrapping ErrBadCertificatePEM", name, err)
		}
		if err != nil && len(in) > 0 && strings.Contains(err.Error(), string(in)) {
			t.Errorf("%s: the error quotes the output: %v", name, err)
		}
	}
}

func TestParseSource(t *testing.T) {
	for _, s := range []Source{SourceSSHVerified, SourceSSHStored, SourceSSHTOFU, SourceExpect} {
		if got, err := ParseSource(string(s)); err != nil || got != s {
			t.Errorf("ParseSource(%q) = %q, %v", s, got, err)
		}
	}
	for _, bad := range []string{"", "tofu", "SSH-VERIFIED", "ssh-verified "} {
		if _, err := ParseSource(bad); !errors.Is(err, ErrUnknownSource) {
			t.Errorf("ParseSource(%q) = %v, want ErrUnknownSource", bad, err)
		}
	}
}
