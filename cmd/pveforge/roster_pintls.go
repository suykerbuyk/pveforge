package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

func newRosterPinTLSCmd() *cobra.Command {
	var (
		expect           string
		repin, printOnly bool
		sshPort, capPort int
		resolveFormat    func() (kvjson.Format, error)
	)
	cmd := &cobra.Command{
		Use:   "pin-tls <target-id>",
		Short: "Pin a target's TLS key without touching its token",
		Long: `Pin a target's API TLS key ([targets.tls] spki_sha256): the migration path
for a target bootstrapped before TLS pins existed. No token is read, written,
validated or sent.

For a target with SSH auth, the key pveproxy serves on the node itself is
captured over an SSH session pinned to the roster's stored host key, and the
target's address must serve the same key (source ssh-stored). For a target
without SSH auth, give the pin you verified by other means with --expect; the
address must serve exactly it (source expect). There is no trust-on-first-use
path. A CA-verified target (insecure_tls false) is pinned only explicitly,
with --expect: its chain is its identity, and a pin is the operator's choice.

A different stored pin is refused. --repin replaces it, for a target with SSH
auth only, whose pinned session vouches for the new key. --print captures and
checks, and writes nothing. The pin is written with a compare-and-set, under
the target's bootstrap lock.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveFormat()
			if err != nil {
				return err
			}
			if err := roster.ValidateTargetID(args[0]); err != nil {
				return err
			}
			var want tlspin.Pin
			if cmd.Flags().Changed("expect") {
				// A value that was GIVEN must be one: an empty --expect (an
				// unset variable) is refused, never read as "no --expect".
				p, err := tlspin.Parse(expect)
				if err != nil {
					return err
				}
				want = p
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			rawPassphrase, err := roster.ResolvePassphraseContext(cmd.Context())
			if err != nil {
				return err
			}
			passphrase, err := proveRosterPassphrase(rosterPath, args[0], rawPassphrase)
			if err != nil {
				return err
			}
			res, err := bootstrap.PinTLS(cmd.Context(), bootstrap.PinTLSOptions{
				TargetID: args[0], RosterPath: rosterPath, Passphrase: passphrase,
				Expect: want, Repin: repin, Print: printOnly, SSHPort: sshPort, CapturePort: capPort,
			}, newBootstrapTransport(), newBootstrapValidator())
			if res != nil && res.Pin != "" {
				if rerr := kvjson.Render(cmd.OutOrStdout(), format, pinTLSView{
					Target: res.TargetID, TLSPin: string(res.Pin), TLSPinSource: string(res.Source),
					Previous: string(res.Previous), Written: res.Written,
				}); rerr != nil && err == nil {
					return rerr
				}
			}
			return err
		},
	}
	resolveFormat = addOutputFlag(cmd)
	cmd.Flags().StringVar(&expect, "expect", "", "for a target without SSH auth: the pin you verified, sha256//<base64>; the target's address must serve exactly that key")
	cmd.Flags().BoolVar(&repin, "repin", false, "replace a different stored pin (a target with SSH auth only: its pinned session vouches for the new key)")
	cmd.Flags().BoolVar(&printOnly, "print", false, "capture and check the pin, and write nothing")
	cmd.Flags().IntVar(&sshPort, "ssh-port", 0, "SSH port on the target host (default: the port pveforge dials a target's stored SSH pin on, 22; the roster stores none)")
	cmd.Flags().IntVar(&capPort, "capture-port", 0, "pveproxy's port ON THE NODE, where the key is captured over SSH (default 8006)")
	addLockWaitFlag(cmd)
	// mutating: it writes a pin that --repin (or a hand edit) can replace.
	markMutating(cmd)
	return cmd
}

// pinTLSView is what `pveforge roster pin-tls` prints.
type pinTLSView struct {
	Target       string `json:"target"`
	TLSPin       string `json:"tls_spki_sha256"`
	TLSPinSource string `json:"tls_pin_source"`
	Previous     string `json:"previous,omitempty"`
	Written      bool   `json:"written"`
}
