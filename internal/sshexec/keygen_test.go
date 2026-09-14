package sshexec

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519Keypair(t *testing.T) {
	kp, err := GenerateEd25519Keypair("pveforge@qa-pve-01")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if !strings.HasPrefix(kp.AuthorizedKeyLine, "ssh-ed25519 ") {
		t.Fatalf("unexpected authorized key line: %q", kp.AuthorizedKeyLine)
	}
	if !strings.HasSuffix(kp.AuthorizedKeyLine, "pveforge@qa-pve-01") {
		t.Fatalf("comment missing from authorized key line: %q", kp.AuthorizedKeyLine)
	}
	if strings.Contains(kp.AuthorizedKeyLine, "\n") {
		t.Fatalf("authorized key line must be a single line: %q", kp.AuthorizedKeyLine)
	}

	signer, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}

	pubFromLine, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.AuthorizedKeyLine))
	if err != nil {
		t.Fatalf("authorized key line does not parse: %v", err)
	}
	if string(pubFromLine.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Fatal("authorized key line's public key does not match the private key's public half")
	}
}

func TestGenerateEd25519Keypair_NoComment(t *testing.T) {
	kp, err := GenerateEd25519Keypair("")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if strings.Contains(kp.AuthorizedKeyLine, " ssh-ed25519 ") {
		t.Fatalf("unexpected content before key type: %q", kp.AuthorizedKeyLine)
	}
	if _, err := ssh.ParsePrivateKey(kp.PrivateKeyPEM); err != nil {
		t.Fatalf("private key does not parse: %v", err)
	}
}

func TestGenerateEd25519Keypair_EachCallIsUnique(t *testing.T) {
	kp1, err := GenerateEd25519Keypair("a")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	kp2, err := GenerateEd25519Keypair("a")
	if err != nil {
		t.Fatalf("GenerateEd25519Keypair: %v", err)
	}
	if kp1.AuthorizedKeyLine == kp2.AuthorizedKeyLine {
		t.Fatal("two independently generated keypairs produced the same public key")
	}
}
