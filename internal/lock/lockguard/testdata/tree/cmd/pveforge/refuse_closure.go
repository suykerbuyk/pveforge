package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: cmd shadowed by an inner closure's parameter.
var refuseClosure = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		return func(cmd *cobra.Command) error {
			_, err := lock.Read(cmd.Context(), "r", lock.ObjectKey{})
			return err
		}(cmd.Root())
	},
}
