package idempotent

import (
	"bytes"
	"fmt"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// fixtureWorkFactor is the scrypt work factor (log2 N) test fixtures are
// encrypted at. Production's roster.EncryptString never sets one, so it
// writes age's default of 18, which costs ~10-14s per operation under -race;
// 10 costs ~30ms. Decrypt cost follows the factor recorded in the ciphertext,
// so production's unchanged DecryptString path is cheap on these fixtures.
const fixtureWorkFactor = 10

// fixtureEncrypt is roster.EncryptString's exact body plus a low scrypt work
// factor, for test fixtures only. It lives in a _test.go file on purpose: the
// Go toolchain never links a _test.go symbol into a production binary, so
// production cannot pick up the weak parameter (a reference to it from a
// non-test file fails `go build`). internal/roster's
// TestEncryptString_UsesAgeDefaultWorkFactor guards the production side.
func fixtureEncrypt(plaintext []byte, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("build scrypt recipient: %w", err)
	}
	recipient.SetWorkFactor(fixtureWorkFactor)

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
