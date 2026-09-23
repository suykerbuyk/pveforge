package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: cmd re-assigned before the call, so cmd.Context() is the root's.
var refuseRoot = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd = cmd.Root()
		_, err := lock.Read(cmd.Context(), "r", lock.ObjectKey{})
		return err
	},
}
