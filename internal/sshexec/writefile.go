package sshexec

import (
	"context"
	"encoding/base64"
	"fmt"
	"path"
)

// WriteFile writes content to remotePath on the remote host, creating any
// missing parent directories and setting mode (an octal permission string
// suitable for chmod, e.g. "0644" or "0755"). Runs over c's existing SSH
// connection, which must be authenticated as a user with sufficient
// privilege to write remotePath — root, in practice, the same standing
// vector SetVMConfigField uses.
//
// content is transferred base64-encoded rather than embedded via a shell
// heredoc: a heredoc's fixed delimiter could collide with arbitrary binary
// or text content, silently truncating or corrupting the write, and
// base64 has no such collision risk. The write itself goes to a temporary
// file in the same directory, then renamed into place — POSIX guarantees
// `mv` within one filesystem is an atomic replace, so a reader can never
// observe a partially-written file.
//
// IMPORTANT: this guarantees atomic REPLACEMENT only, not atomic
// SERIALIZATION — unlike internal/roster's own atomic writeback, which
// additionally holds an flock for the whole write to serialize concurrent
// writers. WriteFile takes no lock of its own, and tmpPath is a fixed name
// derived from remotePath (not randomized), so two concurrent WriteFile
// calls targeting the SAME remotePath can corrupt or clobber each other's
// tmp file — the caller is entirely responsible for ensuring concurrent
// calls never target the same remotePath at the same time. (This is safe
// today for WriteFile's one real caller, RoutedClient.UploadSnippet — see
// that method's own doc comment for how its concurrency is actually
// bounded.)
//
// Sized for pveforge's own use (hookscript content: a few KB at most) —
// the whole base64 payload is embedded as one shell command-line argument,
// which is fine well past that size (Linux's ARG_MAX is generally in the
// hundreds of KB) but this is not intended for large file transfer.
func (c *Client) WriteFile(ctx context.Context, remotePath string, content []byte, mode string) error {
	if remotePath == "" {
		return fmt.Errorf("write file: remote path is required")
	}
	if mode == "" {
		return fmt.Errorf("write file: mode is required")
	}

	dir := path.Dir(remotePath)
	tmpPath := remotePath + ".pveforge-tmp"
	encoded := base64.StdEncoding.EncodeToString(content)

	// printf '%s' <arg>, not echo <arg>: some shells' builtin echo
	// interprets backslash escapes in its argument by default, which could
	// corrupt content that happens to contain a literal backslash sequence
	// once base64-decoded back out — printf with a literal "%s" format
	// string never interprets its argument at all.
	cmd := fmt.Sprintf(
		"set -e\nmkdir -p %s\nprintf '%%s' %s | base64 -d > %s\nchmod %s %s\nmv %s %s\n",
		ShellQuote(dir), ShellQuote(encoded), ShellQuote(tmpPath),
		ShellQuote(mode), ShellQuote(tmpPath),
		ShellQuote(tmpPath), ShellQuote(remotePath),
	)

	res, err := c.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("write file %s: %w", remotePath, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("write file %s: remote script exited %d: %s", remotePath, res.ExitCode, res.Stderr)
	}
	return nil
}
