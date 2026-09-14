package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pvePasswordEnvVar names the environment variable holding the PAM/realm
// password used once, for the pubkey-install step — distinct from
// roster.PassphraseEnvVar (the roster's own encryption passphrase). Per
// the project's standing no-secrets-on-cli rule, neither has a flag.
const pvePasswordEnvVar = "PVEFORGE_PVE_PASSWORD"

func newBootstrapCmd() *cobra.Command {
	var (
		host, node, pveUser, tokenID, aclPath, aclRole string
		apiPort, sshPort                               int
		insecureTLS                                    bool
	)

	cmd := &cobra.Command{
		Use:   "bootstrap <target-id>",
		Short: "Bootstrap a target from PAM/realm username+password to a fully token-authenticated roster entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			passphrase, err := roster.ResolvePassphrase()
			if err != nil {
				return err
			}
			pvePassword, err := resolvePVEPassword()
			if err != nil {
				return err
			}

			opts := bootstrap.Options{
				TargetID:    args[0],
				Host:        host,
				Node:        node,
				APIPort:     apiPort,
				InsecureTLS: insecureTLS,
				SSHPort:     sshPort,
				PVEUsername: pveUser,
				PVEPassword: pvePassword,
				TokenID:     tokenID,
				ACLPath:     aclPath,
				ACLRole:     aclRole,
				RosterPath:  rosterPath,
				Passphrase:  passphrase,
			}

			res, err := bootstrap.Run(cmd.Context(), opts, bootstrap.NewSSHTransport(), bootstrap.NewAPIValidator())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Bootstrapped %s: token %s, host key %s\n", args[0], res.TokenID, res.HostKeyFingerprint)
			return nil
		},
	}

	cmd.Flags().String("roster", "", "path to the roster file (overrides PVEFORGE_ROSTER and the default ./pveforge.toml)")
	cmd.Flags().StringVar(&host, "host", "", "target host/IP (required unless the target already exists in the roster)")
	cmd.Flags().StringVar(&node, "node", "", "PVE node name (required unless the target already exists in the roster)")
	cmd.Flags().IntVar(&apiPort, "api-port", 0, "PVE API port (default 8006)")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "skip TLS certificate verification for the API")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port on the target host")
	cmd.Flags().StringVar(&pveUser, "pve-user", "root@pam", "PAM/realm username to bootstrap with (must be an @pam user)")
	cmd.Flags().StringVar(&tokenID, "token-id", "pveforge", "name of the scoped API token to create")
	cmd.Flags().StringVar(&aclPath, "acl-path", "/", "ACL path to grant the new token")
	cmd.Flags().StringVar(&aclRole, "acl-role", "PVEVMAdmin", "ACL role to grant the new token")

	markMutating(cmd)
	return cmd
}

// resolvePVEPassword reads the PAM/realm login password used once, for
// the pubkey-install step: environment variable first, else an
// interactive terminal prompt, else an error — never a CLI flag. Mirrors
// roster.ResolvePassphrase's own env-var/interactive/error precedence.
func resolvePVEPassword() (string, error) {
	if v, ok := os.LookupEnv(pvePasswordEnvVar); ok && v != "" {
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no PVE password available: set %s or run interactively", pvePasswordEnvVar)
	}
	fmt.Fprint(os.Stderr, "PVE password: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read PVE password: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty PVE password")
	}
	return string(b), nil
}
