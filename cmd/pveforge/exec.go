package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/nodump"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// authorizationEnvVar is the one variable `pveforge exec` adds to its
// command's environment: the value of the Authorization header PVE's REST
// API takes, PVEAPIToken=<token id>=<secret>. pveforge never reads it.
const authorizationEnvVar = "PVEFORGE_PVE_AUTHORIZATION"

// execStrippedEnv are removed from the command's environment: the roster
// passphrase would open every secret in the roster, and the PAM password is
// a login, not a token.
var execStrippedEnv = []string{roster.PassphraseEnvVar, pvePasswordEnvVar}

// Seams for the tests that pin their order (harden before decrypt) and
// their arguments without replacing this process.
var (
	execHarden  = nodump.Set
	execDecrypt = (*roster.Target).TokenSecret
	execve      = syscall.Exec
)

func newExecCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec <target> -- <command> [args...]",
		Short: "Run a command with the target's API token in its environment",
		Long: `Run a command with the target's API token in its environment.

pveforge decrypts the target's API token and replaces itself with the
command (execve), whose environment gains exactly one variable:

  ` + authorizationEnvVar + `=PVEAPIToken=<token id>=<secret>

That is the value of the Authorization header PVE's API takes.
` + roster.PassphraseEnvVar + ` and ` + pvePasswordEnvVar + ` are removed from
the command's environment; everything else passes through. The command's
exit status is its own. Nothing is written to disk and no host is contacted.
One line on stderr names the token id, the target and the command, never the
secret.

Only a target the roster marks export = "token" (set by editing the roster
by hand) can have its token handed out. The SSH key never leaves pveforge.
The mark is a guardrail, not a security boundary: anyone holding the
passphrase can copy a target's secret_enc into a roster where it is marked.

On Linux pveforge is non-dumpable while it holds the secret. The command is
dumpable again after the execve, so any process of the same user can read its
environment, secret included.

Keep the secret out of the command's argv, which every user on the host can
read. With curl, pass the header through a config on stdin, written by the
shell's builtin printf, whose arguments are no process's argv. For example,
run pveforge exec qa-pve-01 -- ./pve-version.sh, where pve-version.sh is:

    #!/bin/sh
    printf 'header = "Authorization: %s"' "$` + authorizationEnvVar + `" |
      curl -sS -K - https://qa-pve-01.example.com:8006/api2/json/version

Never curl -H "Authorization: $` + authorizationEnvVar + `": that puts the
secret in curl's argv. Never run a command under exec that prints its
environment (env, printenv, set, a debug log): it prints the secret.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 {
				return fmt.Errorf("usage: pveforge exec <target> -- <command> [args...]: give exactly one target, then --")
			}
			if len(args) < 2 || args[1] == "" {
				return fmt.Errorf("usage: pveforge exec <target> -- <command> [args...]: no command after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			targetID, argv := args[0], args[1:]
			path, err := exec.LookPath(argv[0])
			if err != nil {
				return fmt.Errorf("exec: %w", err)
			}
			if err := execHarden(); err != nil {
				return fmt.Errorf("exec: %w", err)
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			r, err := roster.Load(rosterPath)
			if err != nil {
				return fmt.Errorf("load roster %s: %w", rosterPath, err)
			}
			t := r.Find(targetID)
			if t == nil {
				return fmt.Errorf("target %q not found in roster %s", targetID, rosterPath)
			}
			if t.Export != roster.ExportToken {
				return fmt.Errorf("target %q is not marked export = %q in roster %s: its token stays inside pveforge", targetID, roster.ExportToken, rosterPath)
			}
			if t.Token == nil {
				return fmt.Errorf("target %q holds no API token", targetID)
			}
			pass, err := roster.ResolvePassphraseContext(cmd.Context())
			if err != nil {
				return err
			}
			secret, err := execDecrypt(t, pass)
			if err != nil {
				return err
			}
			auth, err := authorizationValue(t.Token.ID, secret)
			if err != nil {
				return fmt.Errorf("target %q: %w", targetID, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "notice: exec: handing token %s of %s to %s\n",
				kvjson.QuoteValue(t.Token.ID), kvjson.QuoteValue(targetID), kvjson.QuoteValue(filepath.Base(path)))
			if err := execve(path, argv, execEnv(os.Environ(), auth)); err != nil {
				return fmt.Errorf("exec: execve %s failed, so the token was not handed over: %w", path, err)
			}
			return nil // unreachable: a successful execve does not return
		},
	}
	addRosterFlag(cmd)
	// destructive: it hands a credential to an arbitrary program, whose
	// effects pveforge neither sees nor bounds (mutation.go's own example).
	markDestructive(cmd)
	return cmd
}

// authorizationValue is the header value for token id and secret. It refuses
// a byte that would break it where it is documented to go, a curl config's
// quoted string or a header line: a control character, a space, a quote or a
// backslash. The error never quotes the secret.
func authorizationValue(id string, secret []byte) (string, error) {
	bad := func(s string) bool {
		return s == "" || strings.ContainsFunc(s, func(r rune) bool {
			return r <= ' ' || r == 0x7f || r == '"' || r == '\\'
		})
	}
	if bad(id) {
		return "", fmt.Errorf("token id %s cannot be passed as a header", kvjson.QuoteValue(id))
	}
	if bad(string(secret)) {
		return "", fmt.Errorf("the token secret holds a character that cannot be passed as a header")
	}
	return "PVEAPIToken=" + id + "=" + string(secret), nil
}

// execEnv is environ without execStrippedEnv and any earlier
// authorizationEnvVar, plus authorizationEnvVar=auth.
func execEnv(environ []string, auth string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if k == authorizationEnvVar || slices.Contains(execStrippedEnv, k) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, authorizationEnvVar+"="+auth)
}
