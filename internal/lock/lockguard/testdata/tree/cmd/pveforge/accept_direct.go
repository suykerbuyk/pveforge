package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Accepted: the RunE's own cmd.Context(), passed directly, to lock.Read and
// to a derived sink (idempotent.Run).
var acceptDirect = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		unlock, err := lock.Read(cmd.Context(), "r", lock.ObjectKey{})
		if err != nil {
			return err
		}
		defer unlock()
		_, err = idempotent.Run(cmd.Context(), "r", lock.ObjectKey{}, nil, false)
		return err
	},
}
