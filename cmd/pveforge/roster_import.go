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

// Seams for the import command's stdin, so tests can pipe a secret and
// stand in for a terminal. Production reads os.Stdin.
var (
	importStdin           = func() io.Reader { return os.Stdin }
	importStdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
)

func newRosterImportTokenCmd() *cobra.Command {
	var (
		host, node, tokenID string
		grantSpecs          []string
		apiPort             int
		insecureTLS         bool
		replace             bool
		resolveFormat       func() (kvjson.Format, error)
	)
	cmd := &cobra.Command{
		Use:   "import-token <target-id>",
		Short: "Put an API token minted outside pveforge into the roster, once PVE proves its grants",
		Long: `Import an API token minted outside pveforge into the roster.

The secret is read from stdin, which must NOT be a terminal: pipe it from
wherever the token was minted. There is no flag or environment variable for
it. The roster passphrase therefore cannot be prompted for either: set
` + roster.PassphraseEnvVar + `.

Before anything is written, PVE is asked, as the token, what it can do, and
that must be exactly the --grant scopes (the validation bootstrap runs). A
token that fails is not written, and nothing on PVE is ever touched: an import
creates nothing there, so it never revokes anything.

A target that already holds a DIFFERENT token is refused unless --replace is
given; the replaced token is not revoked and stays live on PVE. Importing the
token the target already holds is a no-op (already_held).

An imported target holds a token but no SSH key, so a later plain
"pveforge bootstrap" of it is refused: pass --no-ssh-key to keep it keyless.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveFormat()
			if err != nil {
				return err
			}
			grants, err := bootstrap.ParseGrants(grantSpecs)
			if err != nil {
				return err
			}
			if err := roster.ValidateTargetID(args[0]); err != nil {
				return err
			}
			if err := bootstrap.CheckImportTokenID(tokenID); err != nil {
				return err
			}
			if importStdinIsTerminal() {
				return fmt.Errorf("import-token reads the token secret from stdin, which is a terminal: pipe the secret in instead")
			}
			// The passphrase before the secret: with stdin piped it can
			// only come from the environment, and a missing one must not
			// cost the piped secret.
			rawPassphrase, err := roster.ResolvePassphraseContext(cmd.Context())
			if err != nil {
				return err
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			// And proven before the secret is read, for the same reason: a
			// mistyped passphrase must not cost the piped secret either.
			passphrase, err := proveRosterPassphrase(rosterPath, args[0], rawPassphrase)
			if err != nil {
				return err
			}
			secret, err := readImportedSecret(importStdin())
			if err != nil {
				return err
			}
			res, err := bootstrap.Import(cmd.Context(), bootstrap.ImportOptions{
				TargetID: args[0], Host: host, Node: node, APIPort: apiPort, InsecureTLS: insecureTLS,
				TokenID: tokenID, Secret: secret, Grants: grants, Replace: replace,
				RosterPath: rosterPath, Passphrase: passphrase,
			}, newBootstrapValidator())
			return finishBootstrap(cmd.OutOrStdout(), cmd.ErrOrStderr(), format, args[0], res, err)
		},
	}
	cmd.Flags().StringVar(&tokenID, "token-id", "", "the full token id, <user>@<realm>!<token name> (required)")
	cmd.Flags().StringArrayVar(&grantSpecs, "grant", nil, "a scope the token must hold, PATH:ROLE[:PRIVS[:PROPAGATE]] (repeatable, at least one; the token must hold exactly these)")
	cmd.Flags().StringVar(&host, "host", "", "the target's API host (defaults to the roster's, required for a new target)")
	cmd.Flags().StringVar(&node, "node", "", "the target's node name (defaults to the roster's, required for a new target)")
	cmd.Flags().IntVar(&apiPort, "api-port", 0, "the target's API port (default 8006)")
	cmd.Flags().BoolVar(&insecureTLS, "insecure-tls", false, "skip TLS verification for a new target's API")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace a different token the target already holds (the old token is not revoked)")
	resolveFormat = addOutputFlag(cmd)
	addLockWaitFlag(cmd)
	_ = cmd.MarkFlagRequired("token-id")
	return cmd
}

// readImportedSecret reads at most MaxImportedSecretLen+1 bytes from r,
// strips ONE trailing newline ("\n" or "\r\n"), and checks the result
// (bootstrap.CheckTokenSecret). Its errors never include the secret.
func readImportedSecret(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, bootstrap.MaxImportedSecretLen+1+2))
	if err != nil {
		return "", fmt.Errorf("read the token secret from stdin: %w", err)
	}
	s := string(b)
	switch {
	case len(s) >= 2 && s[len(s)-2:] == "\r\n":
		s = s[:len(s)-2]
	case len(s) >= 1 && s[len(s)-1] == '\n':
		s = s[:len(s)-1]
	}
	if err := bootstrap.CheckTokenSecret(s); err != nil {
		return "", err
	}
	return s, nil
}
