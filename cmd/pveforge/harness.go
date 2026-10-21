package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// pveforge-harness-outer-go-port (U-CORE): `pveforge harness` is the
// operator-driven outer test-harness lifecycle, a Go parallel to
// hack/harness/lib.sh. It reuses pveforge's own snapshot ops and the
// idempotent VMShutdown/VMDestroy posture rather than re-implementing VM
// state logic in bash. The destructive tier is confined to these verbs; the
// public `vm` surface is unchanged.
//
// Every verb enforces the harness VMID bound (690–699) and, for a change or
// destroy, the existing-VM guard (pool/node/tag), exactly as lib.sh does.

func newHarnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harness",
		Short: "Outer test-harness VM lifecycle (operator-driven)",
		Long: `The outer test-harness VM lifecycle, a Go port of hack/harness/lib.sh.

Every verb acts only on a VM in the harness range 690-699 that is a tagged
qemu member of the harness pool on the harness node, and every state decision
is made on PVE's JSON, never on its error text. The destructive tier is
confined to these verbs; the public vm command surface is unchanged.`,
	}
	cmd.AddCommand(newHarnessVMCmd())
	cmd.AddCommand(newHarnessProbeCmd())
	cmd.AddCommand(newHarnessBuildCmd())
	cmd.AddCommand(newHarnessGoldenCmd())
	cmd.AddCommand(newHarnessResetCmd())
	return cmd
}

// addHarnessIdentityFlags registers --pool and --tag (the harness identity
// lib.sh fixes as HARNESS_POOL/HARNESS_TAG); the node is the roster target's
// own node. Defaults match lib.sh:129-130.
func addHarnessIdentityFlags(cmd *cobra.Command) {
	cmd.Flags().String("pool", outer.DefaultPool, "harness pool a VM must be a member of")
	cmd.Flags().String("tag", outer.DefaultTag, "harness tag a VM must carry")
}

// addCreatedFileFlag registers --created-file, the Go harness's own per-run
// created-VM ledger (lib.sh's HARNESS_CREATED_FILE, but independent of the
// shell's — see internal/harness/outer.Ledger). Falls back to the
// HARNESS_CREATED_FILE environment variable.
func addCreatedFileFlag(cmd *cobra.Command) {
	cmd.Flags().String("created-file", "", "path to this run's created-VM ledger (default $HARNESS_CREATED_FILE)")
}

// harnessConfig builds the guard/gone-proof Config from the identity flags
// and the client's own node.
func harnessConfig(cmd *cobra.Command, client *pve.RoutedClient) outer.Config {
	pool, _ := cmd.Flags().GetString("pool")
	tag, _ := cmd.Flags().GetString("tag")
	return outer.Config{Pool: pool, Node: client.Node(), Tag: tag}
}

// harnessLedger opens the created-VM ledger named by --created-file or
// $HARNESS_CREATED_FILE, or returns nil when neither is set (destroy then
// requires --yes).
func harnessLedger(cmd *cobra.Command) *outer.Ledger {
	p, _ := cmd.Flags().GetString("created-file")
	if p == "" {
		p = os.Getenv("HARNESS_CREATED_FILE")
	}
	if p == "" {
		return nil
	}
	return outer.OpenLedger(p)
}
