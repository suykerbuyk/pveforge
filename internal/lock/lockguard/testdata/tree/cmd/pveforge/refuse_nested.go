package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: cmd shadowed in a nested block.
var refuseNested = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		{
			cmd := cmd.Root()
			_, err = lock.Read(cmd.Context(), "r", lock.ObjectKey{})
		}
		return err
	},
}
