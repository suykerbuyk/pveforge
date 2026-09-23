package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Refused: context.Background(), to lock.Read and to a derived sink.
var refuseBackground = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := lock.Read(context.Background(), "r", lock.ObjectKey{})
		_, err = idempotent.Run(context.Background(), "r", lock.ObjectKey{}, nil, false)
		return err
	},
}
