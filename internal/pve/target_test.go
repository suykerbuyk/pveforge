package pve

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestNewClientForTarget_MissingToken(t *testing.T) {
	tg := &roster.Target{ID: "qa-pve-01", Host: "qa-pve-01.example.com", Node: "qa-pve-01"}

	_, err := NewClientForTarget(tg, "roster-pass")
	if err == nil {
		t.Fatal("expected an error for a target with no token auth")
	}
}

func TestNewClientForTarget_Success(t *testing.T) {
	armored, err := fixtureEncrypt([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("fixtureEncrypt: %v", err)
	}
	tg := &roster.Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
		Token: &roster.TokenAuth{
			ID:        "root@pam!pveforge",
			SecretEnc: armored,
		},
	}

	c, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget: %v", err)
	}
	if c == nil {
		t.Fatal("expected a non-nil client")
	}
	if c.authHeader != "PVEAPIToken=root@pam!pveforge=tok-secret-value" {
		t.Errorf("unexpected auth header: %q", c.authHeader)
	}
	if c.baseURL != "https://qa-pve-01.example.com:8006/api2/json" {
		t.Errorf("unexpected base URL: %q", c.baseURL)
	}
}

func TestNewClientForTarget_WrongPassphrase(t *testing.T) {
	armored, err := fixtureEncrypt([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("fixtureEncrypt: %v", err)
	}
	tg := &roster.Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
		Token: &roster.TokenAuth{
			ID:        "root@pam!pveforge",
			SecretEnc: armored,
		},
	}

	// The error must be the decrypt failure itself. NewClient also rejects
	// an empty secret, so a bare err != nil would still pass if the decrypt
	// error were swallowed and the empty result used.
	_, err = NewClientForTarget(tg, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected an error decrypting the token with the wrong passphrase")
	}
	if !strings.Contains(err.Error(), `decrypt target "qa-pve-01" token`) {
		t.Errorf("expected the token-decrypt error, got: %v", err)
	}
}

// TestNewClientForTarget_IgnoresUndecryptableSSHData guards the same
// narrow-decrypt principle established for bootstrap.loadExistingSSHAuth:
// this call only needs the token secret, so an unrelated SSH-decrypt
// failure (corruption, format drift) on a target that also has SSH auth
// persisted must not block building the REST client.
func TestNewClientForTarget_IgnoresUndecryptableSSHData(t *testing.T) {
	tokenArmored, err := fixtureEncrypt([]byte("tok-secret-value"), "roster-pass")
	if err != nil {
		t.Fatalf("fixtureEncrypt: %v", err)
	}
	// SSH key encrypted under a DIFFERENT passphrase — undecryptable with
	// "roster-pass", simulating corrupted/drifted ciphertext.
	sshArmored, err := fixtureEncrypt([]byte("ssh-key-bytes"), "a-completely-different-passphrase")
	if err != nil {
		t.Fatalf("fixtureEncrypt: %v", err)
	}
	tg := &roster.Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
		Token: &roster.TokenAuth{
			ID:        "root@pam!pveforge",
			SecretEnc: tokenArmored,
		},
		SSH: &roster.SSHAuth{
			User:               "root",
			PublicKey:          "ssh-ed25519 AAAA...",
			HostKeyFingerprint: "SHA256:abc",
			PrivateKeyEnc:      sshArmored,
		},
	}

	c, err := NewClientForTarget(tg, "roster-pass")
	if err != nil {
		t.Fatalf("NewClientForTarget should succeed using only the token data, got error: %v", err)
	}
	if c.authHeader != "PVEAPIToken=root@pam!pveforge=tok-secret-value" {
		t.Errorf("unexpected auth header: %q", c.authHeader)
	}
}
