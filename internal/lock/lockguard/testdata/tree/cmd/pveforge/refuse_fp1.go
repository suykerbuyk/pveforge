package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused by design (the documented false positive): correct code, but the
// context is not cmd.Context() passed directly.
var refuseFP1 = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, err := lock.Read(ctx, "r", lock.ObjectKey{})
		return err
	},
}
