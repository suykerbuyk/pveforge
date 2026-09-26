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

// ConsoleHostKeyCommand is what an operator runs ON THE NODE'S CONSOLE to
// read the host key pveforge's SSH client negotiates (ECDSA on a stock PVE
// node): the only trustworthy source for a rebuilt node's new pin, never
// the key a mismatching connection presented.
const ConsoleHostKeyCommand = "ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub"

// PinnedHostKeyCallback returns an ssh.HostKeyCallback that accepts a
// connection only if the presented host key's SHA256 fingerprint matches
// wantFingerprint exactly: the pin the ROSTER holds (a stored-pin dial). A
// mismatch is treated as a hard failure, not a warning — this is the only
// thing standing between the standing SSH vector and a MITM'd connection.
// Its error points a rebuilt node's operator at the console and at
// `bootstrap --reprovisioned`, and never offers the presented key.
func PinnedHostKeyCallback(wantFingerprint string) (ssh.HostKeyCallback, error) {
	return hostKeyCallback(wantFingerprint, true)
}

// ExpectedHostKeyCallback is PinnedHostKeyCallback for a password dial,
// whose expected key is the one the operator GAVE (--host-key-fingerprint)
// or a pin the caller supplied: a mismatch there is a wrong value or
// another host, not a rebuild the roster could reconcile, so its error
// says to check the value against the node's console instead.
func ExpectedHostKeyCallback(wantFingerprint string) (ssh.HostKeyCallback, error) {
	return hostKeyCallback(wantFingerprint, false)
}

func hostKeyCallback(wantFingerprint string, stored bool) (ssh.HostKeyCallback, error) {
	if wantFingerprint == "" {
		return nil, fmt.Errorf("pinned host key callback: fingerprint is required")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if got == wantFingerprint {
			return nil
		}
		typeNote := "pveforge compares the key type it negotiates (ECDSA when the host serves one), so a pin of another type the host also serves is refused too"
		if stored {
			return fmt.Errorf("host key mismatch for %s: the host presented %s %s, the roster pins %s. Do NOT pin the presented key: it is what an impostor would show. If the node was rebuilt, read its new key on the node's CONSOLE (%s) and run pveforge bootstrap <target> --reprovisioned --host-key-fingerprint <the console value>; for a disposable roster (a harness nested target), moving the roster aside and bootstrapping afresh also works (hack/harness/README.md). %s", hostname, keyTypeName(key.Type()), got, wantFingerprint, ConsoleHostKeyCommand, typeNote)
		}
		return fmt.Errorf("host key mismatch for %s: the host presented %s %s, expected %s (the value you gave, e.g. --host-key-fingerprint). Do NOT pin the presented key: it is what an impostor would show. Compare the expected value with the key read on the node's CONSOLE (%s): if they differ, correct the value you gave to the console value; if they match, something else answers at this address. %s", hostname, keyTypeName(key.Type()), got, wantFingerprint, ConsoleHostKeyCommand, typeNote)
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
