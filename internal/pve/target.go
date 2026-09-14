package pve

import (
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// NewClientForTarget builds a token-authenticated Client for t, decrypting
// t.Token.SecretEnc with passphrase. t.Token must already be present — a
// target with only SSH auth (or none yet) has nothing for a REST client to
// authenticate with. Most callers want NewRoutedClient (routed.go) instead,
// which builds this same REST client and also handles the fields that
// can't go over REST regardless of token privilege.
//
// Deliberately decrypts ONLY t.Token.SecretEnc via roster.DecryptString —
// never t.Resolve, which unconditionally also decrypts t.SSH.PrivateKeyEnc
// when SSH auth is present. This call has no use for the SSH key, and an
// unrelated SSH-decrypt failure (corruption, format drift) must not block
// building a REST client that doesn't touch that data at all — the same
// reasoning bootstrap.loadExistingSSHAuth applies in the other direction.
func NewClientForTarget(t *roster.Target, passphrase string) (*Client, error) {
	if t.Token == nil {
		return nil, fmt.Errorf("target %q has no token auth; run `pveforge bootstrap` first", t.ID)
	}
	tokenSecret, err := roster.DecryptString(t.Token.SecretEnc, passphrase)
	if err != nil {
		return nil, fmt.Errorf("decrypt target %q token: %w", t.ID, err)
	}
	return NewClient(ClientConfig{
		Host:        t.Host,
		APIPort:     t.APIPort,
		InsecureTLS: t.InsecureTLS,
		TokenID:     t.Token.ID,
		TokenSecret: string(tokenSecret),
	})
}
