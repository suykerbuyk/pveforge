package roster

import (
	"bytes"
	"os"
	"testing"
)

// TestEncryptDecryptString_RoundTrip deliberately does NOT lower the work
// factor. It is this package's one end-to-end check that a genuine
// production-parameter header — age's default 18, the factor every roster
// file a user owns is written at — survives armor, age and back again. A
// logN-10 round trip cannot show that.
//
// It is the ONLY test here that keeps production parameters, and one is
// enough: kdf_guard_test.go pins what EncryptString WRITES (exactly 18, over
// a table of inputs), this pins what DecryptString can READ, and nothing else
// in this file adds a third property. The three tests below exercise salt
// freshness, error propagation and Target.Resolve's wiring, none of which
// behaves differently at 10 than at 18, and each of which cost ~12-25s under
// -race to prove something the work factor has no bearing on.
func TestEncryptDecryptString_RoundTrip(t *testing.T) {
	plaintext := []byte("super-secret-token-value")
	passphrase := "correct horse battery staple"

	armored, err := EncryptString(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if !bytes.Contains([]byte(armored), []byte("BEGIN AGE ENCRYPTED FILE")) {
		t.Fatalf("expected armored output, got: %q", armored)
	}

	got, err := DecryptString(armored, passphrase)
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

// TestDecryptString_WrongPassphrase asserts error propagation, which is
// independent of the work factor.
func TestDecryptString_WrongPassphrase(t *testing.T) {
	withTestWorkFactor(t)
	armored, err := EncryptString([]byte("secret"), "right-passphrase")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if _, err := DecryptString(armored, "wrong-passphrase"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase")
	}
}

func TestEncryptString_NondeterministicCiphertext(t *testing.T) {
	// Same plaintext + passphrase must not produce identical ciphertext on
	// repeated calls (fresh salt/nonce each time) — a rotation that writes
	// the "same" secret back still changes the file.
	//
	// The salt is 16 random bytes at every work factor, so this property
	// holds identically at 10.
	withTestWorkFactor(t)
	a, err := EncryptString([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	b, err := EncryptString([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	if a == b {
		t.Fatal("expected different ciphertext across encryptions")
	}
}

func TestResolvePassphrase_EnvVar(t *testing.T) {
	t.Setenv(PassphraseEnvVar, "from-env")
	got, err := ResolvePassphrase()
	if err != nil {
		t.Fatalf("ResolvePassphrase: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("got %q, want %q", got, "from-env")
	}
}

func TestResolvePassphrase_NonInteractiveNoEnv(t *testing.T) {
	t.Setenv(PassphraseEnvVar, "")
	_ = os.Unsetenv(PassphraseEnvVar)
	// In the test environment stdin is not a terminal, so this must error
	// cleanly rather than block waiting for input.
	if _, err := ResolvePassphrase(); err == nil {
		t.Fatal("expected error with no env var and non-interactive stdin")
	}
}

// TestTarget_Resolve asserts that Resolve decrypts the right field into the
// right place. That is wiring, not cryptography.
func TestTarget_Resolve(t *testing.T) {
	withTestWorkFactor(t)
	passphrase := "pw"
	tokenSecret := []byte("tok-secret")
	sshKey := []byte("ssh-priv-key-bytes")

	tokenEnc, err := EncryptString(tokenSecret, passphrase)
	if err != nil {
		t.Fatalf("EncryptString token: %v", err)
	}
	sshEnc, err := EncryptString(sshKey, passphrase)
	if err != nil {
		t.Fatalf("EncryptString ssh: %v", err)
	}

	target := Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
		Token: &TokenAuth{
			ID:        "pveforge@pve!automation",
			SecretEnc: tokenEnc,
		},
		SSH: &SSHAuth{
			User:          "root",
			PublicKey:     "ssh-ed25519 AAAA...",
			PrivateKeyEnc: sshEnc,
		},
	}

	rt, err := target.Resolve(passphrase)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytes.Equal(rt.TokenSecret, tokenSecret) {
		t.Fatalf("token secret mismatch: got %q want %q", rt.TokenSecret, tokenSecret)
	}
	if !bytes.Equal(rt.SSHPrivateKey, sshKey) {
		t.Fatalf("ssh key mismatch: got %q want %q", rt.SSHPrivateKey, sshKey)
	}
}
