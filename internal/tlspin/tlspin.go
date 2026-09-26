// Package tlspin is the TLS identity of a REST peer: a pin on the SHA-256
// of the leaf certificate's SubjectPublicKeyInfo, the way
// [targets.ssh].host_key_fingerprint is the SSH identity
// (pveforge-rest-tls-certificate-pinning). It is pure: it imports nothing
// of pveforge, so the roster, the REST client and any later library user
// share one definition of a pin.
//
// A pin is written in curl's --pinnedpubkey form, "sha256//<base64>", the
// standard (padded) base64 of the 32-byte digest. An operator can check a
// pin with `curl --pinnedpubkey`, or compute it on a node with
// `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
// openssl dgst -sha256 -binary | base64`.
//
// The SPKI is pinned rather than the whole certificate so that a
// certificate renewed on the same key keeps its pin (operator ruling
// 2026-09-25 (5)).
package tlspin

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
)

// Prefix begins every pin.
const Prefix = "sha256//"

// Pin is one SPKI pin, "sha256//<base64>". The zero value is "no pin".
type Pin string

// pinRE is exactly one pin: the prefix and the padded standard base64 of
// 32 bytes (43 characters and one "=").
var pinRE = regexp.MustCompile(`^sha256//[A-Za-z0-9+/]{43}=$`)

// ErrMalformedPin marks a string that is not one pin.
var ErrMalformedPin = errors.New("not a TLS pin")

// Parse returns s as a Pin, or ErrMalformedPin. Only the exact form is
// accepted, so a typo is named rather than taken for a mismatch. The
// error quotes s: a pin is not secret, and an operator needs to see what
// was refused.
func Parse(s string) (Pin, error) {
	if !pinRE.MatchString(s) {
		return "", fmt.Errorf("%w: %q is not %s<44 base64 characters>, the SHA-256 of a certificate's public key in curl's --pinnedpubkey form", ErrMalformedPin, s, Prefix)
	}
	return Pin(s), nil
}

// FromCertificate returns the pin of cert's public key.
func FromCertificate(cert *x509.Certificate) Pin {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Pin(Prefix + base64.StdEncoding.EncodeToString(sum[:]))
}

// ErrBadCertificatePEM marks input that is not exactly one PEM certificate.
// Its messages are fixed and never quote the input, which may be anything
// a remote command printed.
var ErrBadCertificatePEM = errors.New("not exactly one PEM certificate")

// LeafFromPEM parses data as exactly one PEM CERTIFICATE block, with
// nothing but whitespace around it.
func LeafFromPEM(data []byte) (*x509.Certificate, error) {
	// pem.Decode skips anything before the first BEGIN line, so the
	// "nothing but whitespace around it" rule is checked here for the
	// front, and on rest for the back.
	if !bytes.HasPrefix(trimSpace(data), []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("%w: no PEM block at the start", ErrBadCertificatePEM)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrBadCertificatePEM)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: the PEM block is not a CERTIFICATE", ErrBadCertificatePEM)
	}
	if len(trimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: more follows the certificate", ErrBadCertificatePEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the certificate does not parse", ErrBadCertificatePEM)
	}
	return cert, nil
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// ErrPinMismatch marks a peer whose certificate does not carry the pinned
// key.
var ErrPinMismatch = errors.New("TLS pin mismatch")

// MismatchError is a peer presenting another key: it names the pin wanted
// and the pin got, and nothing else (never a token or a header).
type MismatchError struct {
	Want, Got Pin
}

func (e *MismatchError) Error() string {
	if e.Got == "" {
		return fmt.Sprintf("%s: the peer presented no certificate, want %s", ErrPinMismatch, e.Want)
	}
	return fmt.Sprintf("%s: the peer's public key is %s, want %s (the node was rebuilt or re-keyed, something else answers at this address, a TLS-terminating proxy fronts it, or HTTPS_PROXY names an https:// proxy, which a pinned target does not support (an http:// proxy is fine); pveforge will not re-pin silently)", ErrPinMismatch, e.Got, e.Want)
}

func (e *MismatchError) Is(target error) bool { return target == ErrPinMismatch }

// VerifyConnection returns a tls.Config.VerifyConnection callback that
// accepts a connection only if the peer's leaf certificate carries want's
// key. It runs on every handshake, resumed or not, which
// VerifyPeerCertificate does not. want must not be empty: an empty pin
// would accept nothing, and is refused here so a caller cannot build a
// check that reads as a pin but is not one.
func VerifyConnection(want Pin) (func(tls.ConnectionState) error, error) {
	if _, err := Parse(string(want)); err != nil {
		return nil, err
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return &MismatchError{Want: want}
		}
		if got := FromCertificate(cs.PeerCertificates[0]); got != want {
			return &MismatchError{Want: want, Got: got}
		}
		return nil
	}, nil
}
