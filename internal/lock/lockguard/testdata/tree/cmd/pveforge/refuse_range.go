package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: cmd bound as a range variable.
var refuseRange = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, cmd := range cmd.Commands() {
			if _, err := lock.Read(cmd.Context(), "r", lock.ObjectKey{}); err != nil {
				return err
			}
		}
		return nil
	},
}
