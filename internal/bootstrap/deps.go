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

// DialWithPassword is the keyless path's one-shot password session. It is
// dialPinned's password twin: pin == "" captures the presented host key
// (trust-on-first-use, as InstallPubkeyViaPassword does) and returns its
// fingerprint; a non-empty pin is enforced with PinnedHostKeyCallback and
// returned unchanged, so a redial inside one run cannot reach another host.
//
// There is deliberately no pre-dial shape check on pin: "" MEANS
// trust-on-first-use here, and PinnedHostKeyCallback compares strings, so a
// malformed fingerprint fails at the handshake exactly as a mismatch does.
func (realSSHTransport) DialWithPassword(ctx context.Context, addr, user, password, pin string) (SSHSession, string, error) {
	var captured sshexec.CapturedHostKey
	cb := sshexec.CaptureHostKeyCallback(&captured)
	if pin != "" {
		var err error
		if cb, err = sshexec.PinnedHostKeyCallback(pin); err != nil {
			return nil, "", fmt.Errorf("dial with password: %w", err)
		}
	}
	c, err := sshexec.DialWithPassword(ctx, addr, user, password, cb)
	if err != nil {
		return nil, "", err
	}
	if pin != "" {
		return &realSSHSession{c: c}, pin, nil
	}
	return &realSSHSession{c: c}, captured.Fingerprint(), nil
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

func (realAPIValidator) ValidateTokenGrants(ctx context.Context, cfg APIConfig, want []Grant) error {
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
	return pve.ValidateTokenGrants(ctx, c, toPVEGrants(want))
}

// Grant is one requested ACL grant for the bootstrapped token, mirroring
// pve.Grant (deps.go owns the pve import): Role on Path, with Propagate;
// Privs, when non-nil, pins the privileges the grant must confer instead of
// the role's live definition.
type Grant struct {
	Path      string
	Role      string
	Propagate bool
	Privs     []string
}

// Check reports whether g is well formed (pve.Grant.Check); a failure is
// ErrInvalidGrant. Path must already be normalized (checkedACLPath).
func (g Grant) Check() error { return toPVEGrant(g).Check() }

// checkGrants reports whether want is a usable request (pve.CheckGrants).
func checkGrants(want []Grant) error { return pve.CheckGrants(toPVEGrants(want)) }

func toPVEGrant(g Grant) pve.Grant {
	var privs []string
	if g.Privs != nil {
		privs = append([]string{}, g.Privs...)
	}
	return pve.Grant{Path: g.Path, Role: g.Role, Propagate: g.Propagate, Privs: privs}
}

// toPVEGrants translates want, keeping nil (unpinned) and non-nil (pinned)
// Privs apart exactly.
func toPVEGrants(want []Grant) []pve.Grant {
	if want == nil {
		return nil
	}
	out := make([]pve.Grant, len(want))
	for i, g := range want {
		out[i] = toPVEGrant(g)
	}
	return out
}

// ErrInvalidGrant: a requested grant is not well formed. It is refused
// before any SSH and is never a verdict about a token.
var ErrInvalidGrant = pve.ErrInvalidGrant

// The verdict sentinels, aliased from internal/pve (never copied with
// errors.New: a copy would make every verdict look like a non-verdict to
// isVerdict). deps.go owns the pve import; bootstrap.go matches them only
// through isVerdict and postMintRetryable.
var (
	ErrNoGrants      = pve.ErrNoGrants
	ErrWrongScope    = pve.ErrWrongScope
	ErrNotAuthorized = pve.ErrNotAuthorized
	ErrScopeTooWide  = pve.ErrScopeTooWide
)
