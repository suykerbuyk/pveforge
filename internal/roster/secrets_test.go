package roster

import (
	"bytes"
	"os"
	"testing"
)

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

func TestDecryptString_WrongPassphrase(t *testing.T) {
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

func TestTarget_Resolve(t *testing.T) {
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
