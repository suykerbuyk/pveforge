package sshexec

import (
	"context"
	"fmt"
	"strings"
)

// InstallResult reports what InstallPubkeyViaPassword did.
type InstallResult struct {
	// HostKeyFingerprint is the target's SSH host key fingerprint: the
	// pin the connection was checked against, or, with no pin, the one
	// captured trust-on-first-use. The caller must persist this and use
	// PinnedHostKeyCallback for every later connection to this target.
	HostKeyFingerprint string
	// AlreadyPresent reports whether the key was already in
	// authorized_keys (idempotent no-op) rather than newly appended by
	// this call.
	AlreadyPresent bool
}

// InstallPubkeyViaPassword connects to addr as user using password auth,
// and idempotently ensures authorizedKeyLine (a single "ssh-ed25519
// AAAA... comment" line) is present in ~/.ssh/authorized_keys — creating
// ~/.ssh (0700) and the file (0600) if neither exists yet. The host key
// presented during this connection is captured (trust-on-first-use) and
// returned so it can be pinned for every subsequent connection.
//
// With a pin (the operator's `bootstrap --host-key-fingerprint`), the host
// key must match it instead: SSH checks the host key during key exchange,
// before any authentication, so a host presenting another key is refused
// before the password is sent.
func InstallPubkeyViaPassword(ctx context.Context, addr, user, password, authorizedKeyLine, pin string) (*InstallResult, error) {
	var captured CapturedHostKey
	cb := CaptureHostKeyCallback(&captured)
	if pin != "" {
		var err error
		if cb, err = PinnedHostKeyCallback(pin); err != nil {
			return nil, fmt.Errorf("install pubkey: %w", err)
		}
	}
	client, err := DialWithPassword(ctx, addr, user, password, cb)
	if err != nil {
		return nil, fmt.Errorf("install pubkey: %w", err)
	}
	defer func() { _ = client.Close() }()

	line := strings.TrimRight(authorizedKeyLine, "\n")
	res, err := client.Run(ctx, buildIdempotentAppendScript(line))
	if err != nil {
		return nil, fmt.Errorf("install pubkey: run remote script: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("install pubkey: remote script exited %d: %s", res.ExitCode, res.Stderr)
	}

	fp := captured.Fingerprint()
	if pin != "" {
		fp = pin
	}
	return &InstallResult{
		HostKeyFingerprint: fp,
		AlreadyPresent:     strings.TrimSpace(res.Stdout) == "present",
	}, nil
}

// buildIdempotentAppendScript returns a POSIX sh script that ensures
// ~/.ssh/authorized_keys exists with the right permissions and contains
// line exactly once, printing "present" if it was already there or "added"
// if this run appended it.
func buildIdempotentAppendScript(line string) string {
	q := ShellQuote(line)
	return fmt.Sprintf(`set -e
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
if grep -qxF %s ~/.ssh/authorized_keys; then
  echo present
else
  echo %s >> ~/.ssh/authorized_keys
  echo added
fi
`, q, q)
}
