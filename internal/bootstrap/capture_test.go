package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// capturePair is one TLS key as both halves of a capture see it: the PEM
// the node's pveproxy serves (what the capture command prints) and its
// pin (what the address serves, for ServedPin). Each call makes a FRESH
// key, so no two tests, and no two targets in one test, share a pin.
type capturePair struct {
	pem string
	pin tlspin.Pin
}

func newCapturePair(t *testing.T) capturePair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "qa-pve-01"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return capturePair{pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), pin: tlspin.FromCertificate(cert)}
}

// captureCmdPrefix is how every capture command begins.
const captureCmdPrefix = "openssl s_client -connect 127.0.0.1:"

// scriptCapture makes s answer the capture with cp's certificate and v's
// probe report cp's pin: a node whose address serves the key it serves.
func scriptCapture(s *fakeSession, v *fakeValidator, cp capturePair) {
	if s.byCmd == nil {
		s.byCmd = map[string]fakeRunResult{}
	}
	s.byCmd[captureCmdPrefix] = fakeRunResult{res: RunResult{Stdout: cp.pem}}
	v.served = cp.pin
}

func TestCapturePairs_Differ(t *testing.T) {
	a, b := newCapturePair(t), newCapturePair(t)
	if a.pin == b.pin {
		t.Fatal("two capture pairs share a pin")
	}
	if got, _, err := tlspin.ParseCapture([]byte(a.pem)); err != nil || got != a.pin {
		t.Fatalf("a pair's PEM parses to %s (%v), want its own pin %s", got, err, a.pin)
	}
	if tlspin.CaptureCommand(8006)[:len(captureCmdPrefix)] != captureCmdPrefix {
		t.Fatalf("captureCmdPrefix %q is not how CaptureCommand begins: %q", captureCmdPrefix, tlspin.CaptureCommand(8006))
	}
}
