package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

const rosterTemplate = `# pveforge roster — targets and how to reach them.
#
# Add one [[targets]] block per Proxmox host/cluster. Only the id, host,
# and node fields are required by hand; the [targets.token] and
# [targets.ssh] sub-tables are written by ` + "`pveforge bootstrap`" + ` once
# it has generated credentials for a target — do not hand-edit their
# *_enc fields.
#
# [[targets]]
# id   = "qa-pve-01"
# host = "qa-pve-01.example.com"
# node = "qa-pve-01"
`

func newRosterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roster",
		Short: "Inspect and initialize the target roster file",
	}
	cmd.PersistentFlags().String("roster", "", "path to the roster file (overrides PVEFORGE_ROSTER and the default ./pveforge.toml)")
	cmd.AddCommand(newRosterInitCmd())
	cmd.AddCommand(newRosterValidateCmd())
	cmd.AddCommand(newRosterImportTokenCmd())
	return cmd
}

func newRosterInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Create a new, empty roster file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolveRosterPath(cmd, args)
			if err != nil {
				return err
			}
			if !force {
				if _, err := os.Stat(path); err == nil {
					return fmt.Errorf("%s already exists (use --force to overwrite)", path)
				} else if !os.IsNotExist(err) {
					return err
				}
			}
			if err := os.WriteFile(path, []byte(rosterTemplate), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Initialized empty roster at %s\n", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing roster file")
	// destructive, not mutating: without --force this refuses to touch an
	// existing file, but WITH --force it overwrites the roster wholesale —
	// including every target's already-persisted encrypted token/SSH
	// credentials — with the blank rosterTemplate above. That's exactly
	// the "restore-overwrite" case docs/prd.md §3.5 Layer 3 names as
	// destructive: irreversible (no backup, no confirmation prompt) and
	// its blast radius is every target in the file at once, not just one.
	// The command's own worst-case behavior sets its tier; --force being
	// opt-in doesn't change what happens once it's used.
	markDestructive(cmd)
	return cmd
}

func newRosterValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Parse and validate the roster file",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := resolveRosterPath(cmd, args)
			if err != nil {
				return err
			}
			r, err := roster.Load(path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s: valid, %d target(s)\n", path, len(r.Targets))
			for _, t := range r.Targets {
				status := "bootstrap pending"
				switch {
				case t.Token != nil && t.SSH != nil:
					status = "token + ssh configured"
				case t.Token != nil:
					status = "token configured"
				case t.SSH != nil:
					status = "ssh configured"
				}
				fmt.Fprintf(out, "  - %s (%s, node=%s): %s\n", t.ID, t.Host, t.Node, status)
			}
			return nil
		},
	}
	markSafe(cmd)
	return cmd
}

// resolveRosterPath resolves the roster file path shared by every roster
// subcommand, in precedence order: an explicit positional argument (most
// specific to this one invocation) beats --roster (this invocation's
// standing override) beats PVEFORGE_ROSTER (ambient shell state) beats
// roster.DefaultPath.
func resolveRosterPath(cmd *cobra.Command, args []string) (string, error) {
	if len(args) == 1 && args[0] != "" {
		return args[0], nil
	}
	return resolveRosterPathFromFlagOrEnv(cmd)
}

// resolveRosterPathFromFlagOrEnv is resolveRosterPath without the
// positional-argument step, shared with commands (like `bootstrap`) whose
// own positional argument means something else (a target id, not a roster
// path).
func resolveRosterPathFromFlagOrEnv(cmd *cobra.Command) (string, error) {
	flag, err := cmd.Flags().GetString("roster")
	if err != nil {
		return "", fmt.Errorf("read --roster flag: %w", err)
	}
	if flag != "" {
		return flag, nil
	}
	if v := os.Getenv("PVEFORGE_ROSTER"); v != "" {
		return v, nil
	}
	return roster.DefaultPath, nil
}
