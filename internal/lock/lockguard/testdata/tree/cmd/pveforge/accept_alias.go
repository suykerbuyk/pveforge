package main

import (
	cb "github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Accepted: an aliased cobra import and a parameter not named cmd.
var acceptAlias = &cb.Command{
	RunE: func(c *cb.Command, args []string) error {
		_, err := lock.Mutation(c.Context(), "r", lock.ObjectKey{})
		return err
	},
}
