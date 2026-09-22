package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pvePasswordEnvVar names the environment variable holding the PAM/realm
// password used once, for the pubkey-install step — distinct from
// roster.PassphraseEnvVar (the roster's own encryption passphrase). Per
// the project's standing no-secrets-on-cli rule, neither has a flag.
const pvePasswordEnvVar = "PVEFORGE_PVE_PASSWORD"

// The bootstrap command's transport and validator constructors, as seams so
// a test can drive the real command (through runRoot) against fakes.
var (
	newBootstrapTransport = bootstrap.NewSSHTransport
	newBootstrapValidator = bootstrap.NewAPIValidator
)

func newBootstrapCmd() *cobra.Command {
	var (
		host, node, pveUser, tokenID, aclPath, aclRole string
		apiPort, sshPort                               int
		insecureTLS                                    bool
		resolveFormat                                  func() (kvjson.Format, error)
	)

	cmd := &cobra.Command{
		Use:   "bootstrap <target-id>",
		Short: "Bootstrap a target from PAM/realm username+password to a fully token-authenticated roster entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// First, before anything can change a token: a bad -o must never
			// let a rotation run and then fail to report it.
			format, err := resolveFormat()
			if err != nil {
				return err
			}
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

			res, err := bootstrap.Run(cmd.Context(), opts, newBootstrapTransport(), newBootstrapValidator())
			return finishBootstrap(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, args[0], res, err)
		},
	}
	resolveFormat = addOutputFlag(cmd)

	cmd.Flags().String("roster", "", "path to the roster file (overrides PVEFORGE_ROSTER and the default ./pveforge.toml)")
	cmd.Flags().StringVar(&host, "host", "", "target host/IP (required unless the target already exists in the roster)")
	cmd.Flags().StringVar(&node, "node", "", "PVE node name (required unless the target already exists in the roster)")
	cmd.Flags().IntVar(&apiPort, "api-port", 0, "PVE API port (default 8006)")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "skip TLS certificate verification for the API")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 22, "SSH port on the target host")
	cmd.Flags().StringVar(&pveUser, "pve-user", "root@pam", "PAM/realm username to bootstrap with (must be an @pam user)")
	cmd.Flags().StringVar(&tokenID, "token-id", "pveforge", "name of the scoped API token to create")
	cmd.Flags().StringVar(&aclPath, "acl-path", "/", "ACL path to grant the new token; if the path, or the role's privileges, differ from the held token's effective grants, re-running bootstrap revokes that token on PVE (for every holder) and then tries to mint a replacement")
	cmd.Flags().StringVar(&aclRole, "acl-role", "PVEVMAdmin", "ACL role to grant the new token; if the path, or the role's privileges, differ from the held token's effective grants, re-running bootstrap revokes that token on PVE (for every holder) and then tries to mint a replacement")

	// destructive, not mutating: a verdict about the held token makes
	// bootstrap remove it on PVE, which revokes its secret for EVERY roster
	// and session that holds it, and cannot be undone (PVE never re-displays
	// a secret). The worst case sets the tier, as for `roster init --force`.
	markDestructive(cmd)
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

// finishBootstrap reports a run: whenever Run returned a result (on success
// AND on a failure after the token phase began) it is rendered, with its
// warnings, BEFORE the error is returned, so a failure is never silent and
// the exit status is still non-zero.
func finishBootstrap(out, errOut io.Writer, f kvjson.Format, target string, res *bootstrap.Result, runErr error) error {
	if res != nil {
		if err := renderBootstrapResult(out, errOut, f, target, res); err != nil && runErr == nil {
			return err
		}
	}
	return runErr
}

// bootstrapView is what `pveforge bootstrap` prints: a dedicated view, never
// bootstrap.Result itself (which carries an error value and Go field names).
type bootstrapView struct {
	Target             string `json:"target"`
	TokenID            string `json:"token_id"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	TokenOutcome       string `json:"token_outcome"`
	Validation         string `json:"validation"`
	ReplacedReason     string `json:"replaced_reason,omitempty"`
	OrphanedToken      string `json:"orphaned_token,omitempty"`
	LeftoverToken      string `json:"leftover_token,omitempty"`
	LeftoverState      string `json:"leftover_state,omitempty"`
	RosterToken        string `json:"roster_token,omitempty"`
	PriorToken         string `json:"prior_token,omitempty"`
}

// renderBootstrapResult writes the view to out and one lowercase warning
// line per credential hazard to errOut. Every interpolated id or reason
// goes through kvjson.QuoteValue: an id read from a hand-edited roster, or
// a reason, can never forge a second line.
func renderBootstrapResult(out, errOut io.Writer, f kvjson.Format, target string, res *bootstrap.Result) error {
	view := bootstrapView{
		Target:             target,
		TokenID:            res.TokenID,
		HostKeyFingerprint: res.HostKeyFingerprint,
		TokenOutcome:       res.TokenOutcome,
		Validation:         res.Validation,
		ReplacedReason:     res.ReplacedReason,
		OrphanedToken:      res.OrphanedToken,
		LeftoverToken:      res.LeftoverToken,
		LeftoverState:      res.LeftoverState,
		RosterToken:        res.RosterToken,
		PriorToken:         res.PriorToken,
	}
	if err := kvjson.Render(out, f, view); err != nil {
		return err
	}
	q := kvjson.QuoteValue
	id := q(res.TokenID)
	switch res.TokenOutcome {
	case bootstrap.OutcomeReplaced:
		if res.PriorRevoked {
			fmt.Fprintf(errOut, "warning: replaced API token %s (%s); its old secret is now revoked for every holder\n", id, q(res.ReplacedReason))
		} else {
			fmt.Fprintf(errOut, "warning: replaced API token %s (%s): it no longer existed on PVE; nothing was revoked by this run\n", id, q(res.ReplacedReason))
		}
	case bootstrap.OutcomeRevokedNotReplaced:
		if res.PriorToken == bootstrap.PriorTokenUnknown {
			fmt.Fprintf(errOut, "warning: API token %s may have been revoked and was NOT replaced: the remove's outcome could not be established; check it with pveum user token list\n", id)
		} else {
			fmt.Fprintf(errOut, "warning: existing API token %s was revoked and NOT replaced; every copy of its secret, including this roster's, is dead\n", id)
		}
	}
	if res.Validation == bootstrap.ValidationUnverified {
		fmt.Fprintf(errOut, "warning: token %s was persisted but its grants could not be verified\n", id)
	}
	if res.OrphanedToken != "" {
		fmt.Fprintf(errOut, "warning: token %s is still live on PVE with its grants but is no longer held by this roster\n", q(res.OrphanedToken))
	}
	if res.LeftoverToken != "" {
		if res.LeftoverState == bootstrap.LeftoverExists {
			fmt.Fprintf(errOut, "warning: token %s created by this run is still live on PVE and its secret was lost; remove it by hand with pveum user token remove\n", q(res.LeftoverToken))
		} else {
			fmt.Fprintf(errOut, "warning: token %s created by this run may still be live on PVE and its secret was lost; check with pveum user token list and remove it by hand with pveum user token remove\n", q(res.LeftoverToken))
		}
	}
	switch res.RosterToken {
	case bootstrap.RosterTokenStaleRevoked, bootstrap.RosterTokenStaleAbsent:
		fmt.Fprintf(errOut, "warning: this roster still holds token %s, which is dead on PVE; remove the target's [targets.token] block by hand\n", id)
	}
	return nil
}
