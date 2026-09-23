package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: .Context() of a local that is not the command parameter.
var refuseNotParam = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		root := cmd.Root()
		_, err := lock.Read(root.Context(), "r", lock.ObjectKey{})
		return err
	},
}
