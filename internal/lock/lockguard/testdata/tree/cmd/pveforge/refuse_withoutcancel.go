package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: derived from cmd.Context(), but not it.
var refuseWithoutCancel = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := lock.Read(context.WithoutCancel(cmd.Context()), "r", lock.ObjectKey{})
		return err
	},
}
