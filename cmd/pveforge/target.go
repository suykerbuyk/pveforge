package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// resolveRoutedClient loads the roster, finds targetID, and builds a
// pve.RoutedClient for it — the shared setup every vm/node/storage/network
// command needs before it can call any object-model getter/setter. Callers
// are responsible for calling Close() on the result.
func resolveRoutedClient(cmd *cobra.Command, targetID string) (*pve.RoutedClient, error) {
	rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		return nil, err
	}
	passphrase, err := roster.ResolvePassphrase()
	if err != nil {
		return nil, err
	}
	r, err := roster.Load(rosterPath)
	if err != nil {
		return nil, fmt.Errorf("load roster %s: %w", rosterPath, err)
	}
	t := r.Find(targetID)
	if t == nil {
		return nil, fmt.Errorf("target %q not found in roster %s", targetID, rosterPath)
	}
	return pve.NewRoutedClient(t, passphrase)
}

// addRosterFlag registers the --roster flag shared by every command in
// this file's family, mirroring bootstrap.go's own per-command
// registration (rather than a shared parent persistent flag) — matching
// this project's existing convention.
func addRosterFlag(cmd *cobra.Command) {
	cmd.Flags().String("roster", "", "path to the roster file (overrides PVEFORGE_ROSTER and the default ./pveforge.toml)")
}

// addOutputFlag registers the shared -o/--output flag (kv|json, default
// kv) on a read command. The returned func resolves and validates the
// flag's value at RunE time.
func addOutputFlag(cmd *cobra.Command) func() (kvjson.Format, error) {
	var output string
	cmd.Flags().StringVarP(&output, "output", "o", "kv", `output format: "kv" or "json"`)
	return func() (kvjson.Format, error) {
		return kvjson.ParseFormat(output)
	}
}
