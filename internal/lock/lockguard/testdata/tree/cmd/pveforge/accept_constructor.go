package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Accepted: the constructor's own cmd := &cobra.Command{} sits outside the
// RunE that declares the cmd parameter, so it is not a re-binding of it.
func newAcceptConstructorCmd() *cobra.Command {
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := lock.Read(cmd.Context(), "r", lock.ObjectKey{})
			return err
		},
	}
	return cmd
}
