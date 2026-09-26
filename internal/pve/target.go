package pve

import (
	"errors"
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
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
	var pin tlspin.Pin
	if t.TLS != nil {
		pin = tlspin.Pin(t.TLS.SPKISHA256)
	}
	c, err := NewClient(ClientConfig{
		Host:        t.Host,
		APIPort:     t.APIPort,
		InsecureTLS: t.InsecureTLS,
		TLSPin:      pin,
		TokenID:     t.Token.ID,
		TokenSecret: string(tokenSecret),
	})
	if errors.Is(err, ErrTLSPinRequired) {
		return nil, fmt.Errorf("target %q: %w: every REST request to it would trust whatever answers, its token included. Pin it first with pveforge roster pin-tls %s (over its stored SSH pin; --expect sha256//… for a target without SSH auth), or bootstrap it again, which captures one", t.ID, ErrTLSPinRequired, t.ID)
	}
	return c, err
}
