// Command pveforge is a standalone Go CLI for Proxmox VE cluster lifecycle
// management. See docs/prd.md for the design.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pveforge",
		Short:         "Proxmox VE cluster lifecycle management",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRosterCmd())
	root.AddCommand(newBootstrapCmd())
	root.AddCommand(newVMCmd())
	root.AddCommand(newNodeCmd())
	root.AddCommand(newStorageCmd())
	root.AddCommand(newNetworkCmd())
	root.AddCommand(newDiscoverCmd())
	return root
}
