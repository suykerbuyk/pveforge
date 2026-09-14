package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Keypair is a freshly generated ed25519 SSH keypair.
type Keypair struct {
	// AuthorizedKeyLine is a single authorized_keys-format line
	// ("ssh-ed25519 AAAA... comment"), ready to append verbatim.
	AuthorizedKeyLine string
	// PrivateKeyPEM is the OpenSSH-format PEM encoding of the private key,
	// suitable for roster.WriteSSHAuth's PrivateKeyPlaintext and for
	// ssh.ParsePrivateKey when reconnecting.
	PrivateKeyPEM []byte
}

// GenerateEd25519Keypair generates a fresh ed25519 SSH keypair. comment is
// embedded in the authorized_keys line purely for operator readability
// (e.g. "pveforge@<target-id>") — it carries no security meaning.
func GenerateEd25519Keypair(comment string) (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 public key to ssh format: %w", err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		line += " " + comment
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("marshal ed25519 private key: %w", err)
	}

	return &Keypair{
		AuthorizedKeyLine: line,
		PrivateKeyPEM:     pem.EncodeToMemory(block),
	}, nil
}
