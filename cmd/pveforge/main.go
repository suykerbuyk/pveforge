// Command pveforge is a standalone Go CLI for Proxmox VE cluster lifecycle
// management. See docs/prd.md for the design.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

func main() {
	os.Exit(runRoot(newRootCmd(), os.Stderr))
}

// runRoot executes root and returns the process exit code. It is the ONE
// place any command's final error is printed, and it prints it as a single
// line: kvjson.QuoteValue writes the text as a JSON string when it could be
// misread (a line break or other control character, edge whitespace, a
// leading quote), so server text embedded in an error (a pveum stderr, a
// 5xx body) can never forge a second line such as "warning: ...". An error
// text that needs no quoting prints exactly as before. Commands' own
// stderr lines (cmd.ErrOrStderr()) go to the same writer.
func runRoot(root *cobra.Command, stderr io.Writer) int {
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(stderr, kvjson.QuoteValue(err.Error()))
		return 1
	}
	return 0
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
	root.AddCommand(newAPICmd())
	root.AddCommand(newSchemaCmd())
	return root
}
