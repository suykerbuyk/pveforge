package roster

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

// EncryptString encrypts plaintext with a scrypt (passphrase-based) age
// recipient and returns ASCII-armored ciphertext, suitable for embedding
// verbatim as a TOML multi-line literal string value.
func EncryptString(plaintext []byte, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("build scrypt recipient: %w", err)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return "", fmt.Errorf("start age encryption: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalize age stream: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", fmt.Errorf("finalize armor: %w", err)
	}
	return buf.String(), nil
}

// DecryptString reverses EncryptString.
func DecryptString(armored string, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("build scrypt identity: %w", err)
	}
	ar := armor.NewReader(strings.NewReader(armored))
	r, err := age.Decrypt(ar, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted plaintext: %w", err)
	}
	return out, nil
}

// ResolvePassphrase reads the roster's master passphrase from
// PVEFORGE_ROSTER_PASSPHRASE, falling back to an interactive terminal
// prompt. It errors rather than hanging when neither is available, so
// pveforge stays safe to invoke from scripts, cron, and CI.
func ResolvePassphrase() (string, error) {
	if v, ok := os.LookupEnv(PassphraseEnvVar); ok && v != "" {
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no roster passphrase available: set %s or run interactively", PassphraseEnvVar)
	}
	fmt.Fprint(os.Stderr, "Roster passphrase: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty passphrase")
	}
	return string(b), nil
}

// ResolvedTarget is a short-lived, in-memory view of a Target with its
// secrets decrypted. It is never serialized back to disk — only the
// splice-writer (writeback.go) writes to the roster file, and only with
// freshly produced ciphertext.
type ResolvedTarget struct {
	Target
	TokenSecret   []byte
	SSHPrivateKey []byte
}

// Resolve decrypts t's secrets using passphrase.
func (t *Target) Resolve(passphrase string) (*ResolvedTarget, error) {
	rt := &ResolvedTarget{Target: *t}
	if t.Token != nil {
		pt, err := DecryptString(t.Token.SecretEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt token secret for %q: %w", t.ID, err)
		}
		rt.TokenSecret = pt
	}
	if t.SSH != nil {
		pt, err := DecryptString(t.SSH.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt ssh private key for %q: %w", t.ID, err)
		}
		rt.SSHPrivateKey = pt
	}
	return rt, nil
}
