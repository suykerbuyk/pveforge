package bootstrap

import (
	"context"
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// NewSSHTransport returns the production SSHTransport, backed by
// internal/sshexec. This is the only place in the package that talks real
// SSH; Run's own logic never imports sshexec's network-facing types
// directly.
func NewSSHTransport() SSHTransport { return realSSHTransport{} }

type realSSHTransport struct{}

func (realSSHTransport) InstallPubkeyViaPassword(ctx context.Context, addr, user, password, authorizedKeyLine string) (string, error) {
	res, err := sshexec.InstallPubkeyViaPassword(ctx, addr, user, password, authorizedKeyLine)
	if err != nil {
		return "", err
	}
	return res.HostKeyFingerprint, nil
}

func (realSSHTransport) DialWithKey(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error) {
	return dialPinned(ctx, addr, user, privateKeyPEM, hostKeyFingerprint)
}

// ReconnectWithPinnedKey is mechanically identical to DialWithKey — both
// ultimately pin against a fingerprint via sshexec.PinnedHostKeyCallback —
// but is kept as a distinct method (rather than bootstrap.go calling
// DialWithKey directly for both cases) because the two call sites carry
// very different trust implications: DialWithKey is only ever called
// immediately after a fingerprint was just captured via TOFU in this same
// run, where a mismatch can't practically happen; ReconnectWithPinnedKey
// is called with a fingerprint from a PRIOR run, where a mismatch is a
// real "something about this target changed" signal. Keeping them as
// separate interface methods lets bootstrap.go's own logic — and its
// tests — treat "first bootstrap" and "reconnect to an already-trusted
// target" as the distinct operations they are.
func (realSSHTransport) ReconnectWithPinnedKey(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error) {
	return dialPinned(ctx, addr, user, privateKeyPEM, hostKeyFingerprint)
}

func dialPinned(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error) {
	cb, err := sshexec.PinnedHostKeyCallback(hostKeyFingerprint)
	if err != nil {
		return nil, fmt.Errorf("dial with pinned key: %w", err)
	}
	c, err := sshexec.Dial(ctx, addr, user, privateKeyPEM, cb)
	if err != nil {
		return nil, err
	}
	return &realSSHSession{c: c}, nil
}

type realSSHSession struct{ c *sshexec.Client }

func (s *realSSHSession) Run(ctx context.Context, cmd string) (RunResult, error) {
	r, err := s.c.Run(ctx, cmd)
	if err != nil {
		return RunResult{}, err
	}
	return RunResult{Stdout: r.Stdout, Stderr: r.Stderr, ExitCode: r.ExitCode}, nil
}

func (s *realSSHSession) Close() error { return s.c.Close() }

// NewAPIValidator returns the production APIValidator, backed by
// internal/pve.
func NewAPIValidator() APIValidator { return realAPIValidator{} }

type realAPIValidator struct{}

func (realAPIValidator) ValidateTokenGrants(ctx context.Context, cfg APIConfig, expectNode string) error {
	c, err := pve.NewClient(pve.ClientConfig{
		Host:        cfg.Host,
		APIPort:     cfg.APIPort,
		InsecureTLS: cfg.InsecureTLS,
		TokenID:     cfg.TokenID,
		TokenSecret: cfg.TokenSecret,
	})
	if err != nil {
		return fmt.Errorf("build pve client: %w", err)
	}
	return pve.ValidateTokenGrants(ctx, c, expectNode)
}
