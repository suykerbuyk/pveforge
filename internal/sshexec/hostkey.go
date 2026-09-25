package sshexec

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// CapturedHostKey holds the SSH host key presented during a trust-on-
// first-use connection, so its fingerprint can be persisted and pinned for
// every later connection.
type CapturedHostKey struct {
	Key ssh.PublicKey
}

// Fingerprint returns the SHA256 fingerprint of the captured key, in the
// same "SHA256:<base64>" form ssh-keygen -l and PinnedHostKeyCallback use.
// Returns "" if no key was captured (e.g. the connection never got past
// the handshake).
func (c *CapturedHostKey) Fingerprint() string {
	if c == nil || c.Key == nil {
		return ""
	}
	return ssh.FingerprintSHA256(c.Key)
}

// CaptureHostKeyCallback returns an ssh.HostKeyCallback that accepts
// whatever host key the server presents (trust-on-first-use) and records
// it into captured. This must be used ONLY for the one-time bootstrap
// connection (password-authenticated pubkey install) — the caller must
// persist captured.Fingerprint() immediately afterward and use
// PinnedHostKeyCallback for every subsequent connection to this target.
func CaptureHostKeyCallback(captured *CapturedHostKey) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		captured.Key = key
		return nil
	}
}

// fingerprintRE is a SHA256 host key fingerprint exactly as
// `ssh-keygen -l -E sha256` prints it and the roster stores it
// (ssh.FingerprintSHA256): "SHA256:" and the unpadded base64 of 32 bytes.
var fingerprintRE = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// CheckFingerprint refuses anything but one such fingerprint: an MD5 form,
// a whole ssh-keygen line, padding or stray whitespace. A pin is checked
// before anything is dialed, so a typo is named, never taken for a
// mismatching host.
func CheckFingerprint(s string) error {
	if !fingerprintRE.MatchString(s) {
		return fmt.Errorf("host key fingerprint %q is not SHA256:<43 base64 characters>, as ssh-keygen -l -E sha256 prints it", s)
	}
	return nil
}

// PinnedHostKeyCallback returns an ssh.HostKeyCallback that accepts a
// connection only if the presented host key's SHA256 fingerprint matches
// wantFingerprint exactly. A mismatch is treated as a hard failure, not a
// warning — this is the only thing standing between the standing SSH
// vector and a MITM'd connection.
func PinnedHostKeyCallback(wantFingerprint string) (ssh.HostKeyCallback, error) {
	if wantFingerprint == "" {
		return nil, fmt.Errorf("pinned host key callback: fingerprint is required")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if got != wantFingerprint {
			return fmt.Errorf("host key mismatch for %s: got %s %s, want %s; pveforge compares the key type it negotiates (ECDSA when the host serves one), so a pin of another type the host also serves is refused too (possible MITM, or the host was rebuilt/rekeyed, or the pin is of another key type — reconcile deliberately, do not silently re-pin)", hostname, keyTypeName(key.Type()), got, wantFingerprint)
		}
		return nil
	}, nil
}

// keyTypeName is a host key type as ssh-keygen -l names it.
func keyTypeName(t string) string {
	switch {
	case t == ssh.KeyAlgoED25519:
		return "ED25519"
	case strings.HasPrefix(t, "ecdsa-sha2-"):
		return "ECDSA"
	case t == ssh.KeyAlgoRSA:
		return "RSA"
	}
	return t
}
