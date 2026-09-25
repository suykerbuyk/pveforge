package main

import (
	"context"
	"errors"
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
		host, node, pveUser, tokenOwner, tokenID string
		hostKeyFP                                string
		grantSpecs                               []string
		apiPort, sshPort                         int
		insecureTLS, noSSHKey                    bool
		resolveFormat                            func() (kvjson.Format, error)
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
			// Then the grants, before any prompt, roster read or transport:
			// bootstrap fails closed without an explicit grant, and an
			// operator who forgot one is told so before being asked for a
			// secret.
			grants, err := bootstrap.ParseGrants(grantSpecs)
			if err != nil {
				return err
			}
			// And the target id: one the roster would refuse (see
			// roster.ValidateTargetID) must not cost two prompts either.
			if err := roster.ValidateTargetID(args[0]); err != nil {
				return err
			}
			// And the owner, for the same reason: a userid pveforge cannot
			// own a token with must not cost the operator two prompts.
			if tokenOwner != "" {
				if err := bootstrap.CheckTokenOwner(tokenOwner); err != nil {
					return err
				}
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			rawPassphrase, err := roster.ResolvePassphraseContext(cmd.Context())
			if err != nil {
				return err
			}
			// Before the PVE password is asked for: a mistyped roster
			// passphrase must not cost a second prompt, let alone a dial.
			passphrase, err := proveRosterPassphrase(rosterPath, args[0], rawPassphrase)
			if err != nil {
				return err
			}
			pvePassword, err := resolvePVEPassword(cmd.Context())
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
				TokenOwner:  tokenOwner,
				NoSSHKey:    noSSHKey,
				TokenID:     tokenID,
				Grants:      grants,
				RosterPath:  rosterPath,
				Passphrase:  passphrase,
			}
			opts.HostKeyFingerprint = hostKeyFP

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
	cmd.Flags().StringVar(&pveUser, "pve-user", "root@pam", "PAM/realm username to bootstrap with: the SSH LOGIN (must be an @pam user); the token's owner is --token-owner. In keyless mode this login's password is used on every run")
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, "authenticate this run with the PVE password for its own duration only: no key is installed on the target and none is stored in the roster. The host key is trusted on first use on EVERY such run, and the accepted fingerprint is reported as host_key_fingerprint. A target bootstrapped this way needs this flag on every later run, and the flag is refused against a target whose roster entry holds an SSH keypair")
	cmd.Flags().StringVar(&hostKeyFP, "host-key-fingerprint", "", "the target's SSH host key fingerprint as you verified it, SHA256:<base64> exactly as ssh-keygen -l -E sha256 prints it: the password connection (the key install's, or --no-ssh-key's) must present that key, checked before the password is sent, instead of trusting the host key on first use. For a target that already holds a pinned key, a different value is refused before any connection")
	cmd.Flags().StringVar(&tokenOwner, "token-owner", "", "PVE principal that will own the token, as name@realm (default: --pve-user). It is not the SSH login and needs no SSH account. A non-root owner must itself hold the whole role at each granted path, or bootstrap refuses before touching anything. Changing it deliberately leaves the previous token live on PVE, held by nobody (orphaned_token), never revoked; omitting it when the roster holds another owner's token is refused")
	cmd.Flags().StringVar(&tokenID, "token-id", "pveforge", "name of the scoped API token to create")
	cmd.Flags().StringArrayVar(&grantSpecs, "grant", nil, "an ACL grant for the token, PATH:ROLE[:PRIVS[:PROPAGATE]] (repeatable; at least one is required, there is no default): ROLE on PATH, PRIVS an optional comma-separated privilege list pinning exactly the role's privileges, PROPAGATE 0 or 1 (default 0), e.g. /pool/p:PVEVMUser or /:PVEVMAdmin::1; if a grant's path, or its privileges, differ from the held token's effective grants, re-running bootstrap revokes that token on PVE (for every holder) and then tries to mint a replacement")
	addLockWaitFlag(cmd)

	// destructive, not mutating: a verdict about the held token makes
	// bootstrap remove it on PVE, which revokes its secret for EVERY roster
	// and session that holds it, and cannot be undone (PVE never re-displays
	// a secret). The worst case sets the tier, as for `roster init --force`.
	markDestructive(cmd)
	return cmd
}

// proveRosterPassphrase proves pass against the roster at path for a
// command about to encrypt a secret into it (roster.ProvePassphrase), so a
// wrong passphrase is refused before any prompt, lock or network call that
// follows. Only a verdict about the passphrase stops the command here — a
// wrong one, or a roster none of whose secrets can be read to check it
// against. A roster that cannot be loaded at all is left to the command
// itself, which reports it in its own terms, and whose writes prove the
// passphrase again under the roster's lock.
func proveRosterPassphrase(path, targetID, pass string) (roster.Passphrase, error) {
	p, err := roster.ProvePassphrase(path, targetID, pass)
	if errors.Is(err, roster.ErrWrongPassphrase) || errors.Is(err, roster.ErrNoReadableSecret) {
		return roster.Passphrase{}, err
	}
	if err != nil {
		return roster.NewPassphrase(pass), nil
	}
	return p, nil
}

// resolvePVEPassword reads the PAM/realm login password used once, for
// the pubkey-install step: environment variable first, else an
// interactive terminal prompt, else an error — never a CLI flag. Mirrors
// roster.ResolvePassphrase's own env-var/interactive/error precedence.
func resolvePVEPassword(ctx context.Context) (string, error) {
	if v, ok := os.LookupEnv(pvePasswordEnvVar); ok && v != "" {
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no PVE password available: set %s or run interactively", pvePasswordEnvVar)
	}
	fmt.Fprint(os.Stderr, "PVE password: ")
	b, err := roster.ReadSecret(ctx, fd, "PVE password")
	fmt.Fprintln(os.Stderr)
	if err != nil {
		if errors.Is(err, roster.ErrPromptInterrupted) {
			return "", err
		}
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
	// Grants is the scope the surviving token holds (bootstrap.Result.Grants);
	// absent when no token survives the run.
	Grants []grantView `json:"grants,omitempty"`
}

// grantView is one granted scope as printed.
type grantView struct {
	Path      string   `json:"path"`
	Role      string   `json:"role"`
	Propagate bool     `json:"propagate"`
	Privs     []string `json:"privs,omitempty"`
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
	for _, g := range res.Grants {
		view.Grants = append(view.Grants, grantView{Path: g.Path, Role: g.Role, Propagate: g.Propagate, Privs: g.Privs})
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
	if res.Validation == bootstrap.ValidationUnverified && res.TokenOutcome != bootstrap.OutcomeNotImported {
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
