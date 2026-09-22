package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
)

func TestResolvePVEPassword_FromEnv(t *testing.T) {
	t.Setenv(pvePasswordEnvVar, "env-password")
	got, err := resolvePVEPassword()
	if err != nil {
		t.Fatalf("resolvePVEPassword: %v", err)
	}
	if got != "env-password" {
		t.Fatalf("got %q, want %q", got, "env-password")
	}
}

func TestResolvePVEPassword_NoEnvNonInteractive(t *testing.T) {
	t.Setenv(pvePasswordEnvVar, "")
	// os.Stdin in `go test` is not a terminal, so this should hit the
	// "no PVE password available" error path rather than blocking on a
	// prompt.
	_, err := resolvePVEPassword()
	if err == nil {
		t.Fatal("expected an error when no env var is set and stdin is not a terminal")
	}
}

func TestNewBootstrapCmd_RequiresExactlyOneArg(t *testing.T) {
	cmd := newBootstrapCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Args(cmd, []string{}); err == nil {
		t.Fatal("expected an error for zero positional args")
	}
	if err := cmd.Args(cmd, []string{"a", "b"}); err == nil {
		t.Fatal("expected an error for two positional args")
	}
	if err := cmd.Args(cmd, []string{"only-one"}); err != nil {
		t.Fatalf("expected exactly one positional arg to be accepted: %v", err)
	}
}

// F2: --grant says that a re-run with a different request revokes the held
// token, since the validator's upper bound makes a narrower or different
// request a verdict about it; and that there is no default.
func TestNewBootstrapCmd_GrantFlagWarnsOfRevocation(t *testing.T) {
	cmd := newBootstrapCmd()
	for _, name := range []string{"grant"} {
		u := cmd.Flags().Lookup(name).Usage
		for _, want := range []string{
			"PATH:ROLE[:PRIVS[:PROPAGATE]]",
			"at least one is required, there is no default",
			"PROPAGATE 0 or 1 (default 0)",
			"its privileges, differ from the held token's effective grants",
			"revokes that token on PVE (for every holder)",
			"tries to mint a replacement",
		} {
			if !strings.Contains(u, want) {
				t.Errorf("--%s help does not say %q: %q", name, want, u)
			}
		}
	}
}

// U-B: --token-owner states that it is not the SSH login, that a non-root
// owner must hold the whole role, and what a change does to the held token.
func TestNewBootstrapCmd_TokenOwnerFlagIsExplained(t *testing.T) {
	u := newBootstrapCmd().Flags().Lookup("token-owner").Usage
	for _, want := range []string{
		"name@realm",
		"default: --pve-user",
		"not the SSH login",
		"whole role at each granted path",
		"held by nobody (orphaned_token), never revoked",
		"omitting it when the roster holds another owner's token is refused",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("--token-owner help does not say %q: %q", want, u)
		}
	}
	if pu := newBootstrapCmd().Flags().Lookup("pve-user").Usage; !strings.Contains(pu, "SSH LOGIN") || !strings.Contains(pu, "--token-owner") {
		t.Errorf("--pve-user help does not point at --token-owner: %q", pu)
	}
}

func TestNewBootstrapCmd_FlagDefaults(t *testing.T) {
	cmd := newBootstrapCmd()
	cases := map[string]string{
		"api-port":     "0",
		"ssh-port":     "22",
		"pve-user":     "root@pam",
		"token-id":     "pveforge",
		"grant":        "[]",
		"no-ssh-key":   "false",
		"token-owner":  "",
		"insecure-tls": "false",
		"roster":       "",
	}
	for name, want := range cases {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag %q not registered", name)
		}
		if f.DefValue != want {
			t.Errorf("flag %q default = %q, want %q", name, f.DefValue, want)
		}
	}
	// MG20: the removed flags are gone, not hidden.
	for _, gone := range []string{"acl-path", "acl-role"} {
		if cmd.Flags().Lookup(gone) != nil {
			t.Errorf("flag %q is still registered", gone)
		}
	}
}

// TestNewBootstrapCmd_RunE_FailsFastWithoutLiveHost drives the bootstrap
// command's real RunE body end to end — roster-path/passphrase/password
// resolution, Options construction, and the call into bootstrap.Run — using
// the real (non-faked) SSHTransport/APIValidator. It stops at the first
// network hop (nothing is listening on the target port), so this needs no
// live PVE host, but it does exercise the wiring the fake-based
// internal/bootstrap tests can't reach.
func TestNewBootstrapCmd_RunE_FailsFastWithoutLiveHost(t *testing.T) {
	rosterPath := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(rosterPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty roster: %v", err)
	}

	// Bind a port, then close it immediately: guarantees a fast
	// "connection refused" instead of a multi-second dial timeout against
	// an address nothing ever answers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	t.Setenv("PVEFORGE_ROSTER", rosterPath)
	t.Setenv("PVEFORGE_ROSTER_PASSPHRASE", "test-roster-pass")
	t.Setenv(pvePasswordEnvVar, "test-pve-pass")

	cmd := newBootstrapCmd()
	cmd.SetArgs([]string{"qa-test", "--host", "127.0.0.1", "--node", "qa-test", "--ssh-port", portStr, "--grant", "/:PVEVMAdmin::1"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected an error: nothing is listening on the target port")
	}
	// It must stop at the first network hop, not at the grant check, or it
	// exercises none of the wiring it exists for.
	if errors.Is(err, bootstrap.ErrInvalidGrant) || !strings.Contains(err.Error(), "install pubkey") {
		t.Fatalf("want the first-bootstrap dial failure, got %v", err)
	}
}

func TestResolveRosterPathFromFlagOrEnv_Precedence(t *testing.T) {
	cmd := newBootstrapCmd()

	// Default, no flag/env set.
	got, err := resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		t.Fatalf("resolveRosterPathFromFlagOrEnv: %v", err)
	}
	if got != "pveforge.toml" {
		t.Fatalf("default: got %q, want %q", got, "pveforge.toml")
	}

	// Env var overrides the default.
	t.Setenv("PVEFORGE_ROSTER", "/env/roster.toml")
	got, err = resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		t.Fatalf("resolveRosterPathFromFlagOrEnv: %v", err)
	}
	if got != "/env/roster.toml" {
		t.Fatalf("env: got %q, want %q", got, "/env/roster.toml")
	}

	// --roster flag overrides the env var.
	if err := cmd.Flags().Set("roster", "/flag/roster.toml"); err != nil {
		t.Fatalf("set --roster: %v", err)
	}
	got, err = resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		t.Fatalf("resolveRosterPathFromFlagOrEnv: %v", err)
	}
	if got != "/flag/roster.toml" {
		t.Fatalf("flag: got %q, want %q", got, "/flag/roster.toml")
	}
}

// C-T8: --no-ssh-key's help states what the flag actually does, including
// the two refusals a target can meet later.
func TestNewBootstrapCmd_NoSSHKeyFlagIsExplained(t *testing.T) {
	u := newBootstrapCmd().Flags().Lookup("no-ssh-key").Usage
	for _, want := range []string{
		"no key is installed on the target and none is stored in the roster",
		"trusted on first use on EVERY such run",
		"reported as host_key_fingerprint",
		"needs this flag on every later run",
		"refused against a target whose roster entry holds an SSH keypair",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("--no-ssh-key help does not say %q: %q", want, u)
		}
	}
}
