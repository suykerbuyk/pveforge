package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Seams, so a test can drive rekey's prompts without a terminal.
var (
	rekeyOldPassphrase = roster.ResolvePassphraseContext
	rekeyNewPassphrase = roster.ReadNewPassphraseContext
)

func newRosterRekeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Change the roster's passphrase: re-encrypt every secret in it under a new one",
		Long: `Change the roster's passphrase: every secret in the roster (each API token
secret and each SSH private key) is decrypted with the current passphrase and
encrypted again under a new one. Nothing is contacted: no node, no token on
PVE. Only the roster file changes.

The current passphrase comes from PVEFORGE_ROSTER_PASSPHRASE or a prompt, and
must open EVERY secret in the roster, or nothing is written. The new one is
read from a terminal only (never an environment variable or a pipe), twice,
and must differ from the current one.

The file is rewritten under the roster lock, and replaced atomically only
after the result decodes with every other field unchanged and every new
secret opens with the new passphrase to its old plaintext. A failure leaves
the file as it was. No copy under the old passphrase is kept, but any copy
made before (a backup, git history) still opens with the old one.

A pveforge command already running against this roster with the old
passphrase fails its next roster write (wrong roster passphrase) rather than
split the roster. For the nested harness's rosters, rekey every one of them,
then seal the new passphrase into hack/harness/secrets.age.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			old, err := rekeyOldPassphrase(cmd.Context())
			if err != nil {
				return err
			}
			// Before the new passphrase is asked for: a roster with nothing
			// to rekey, or a wrong current passphrase, must not cost two
			// more prompts.
			if err := roster.CheckRekey(path, old); err != nil {
				return fmt.Errorf("rekey %s: %w", path, err)
			}
			next, err := rekeyNewPassphrase(cmd.Context())
			if err != nil {
				return fmt.Errorf("rekey %s: %w", path, err)
			}
			res, err := roster.Rekey(path, old, next)
			if err != nil {
				return fmt.Errorf("rekey %s: %w", path, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: rekeyed %d secret(s) of %d target(s)\n", path, res.Secrets, res.Targets)
			if harnessRoster(path) {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: this looks like a nested-harness roster: once every harness roster is rekeyed, seal the new passphrase with hack/harness/unlock.sh seal; until then every harness step fails its passphrase check")
			}
			return nil
		},
	}
	markDestructive(cmd)
	return cmd
}

// harnessRoster reports whether path is named like one of the nested
// harness's rosters (harness-outer.toml, harness-nested.toml), whose
// passphrase is also sealed in hack/harness/secrets.age.
func harnessRoster(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, "harness-") && strings.HasSuffix(base, ".toml")
}
