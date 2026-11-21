package bootstrap

import (
	"context"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// EnableVMDestroy passes its own ctx parameter directly: accepted.
func EnableVMDestroy(ctx context.Context, rosterPath string) error {
	_, err := lock.Mutation(ctx, rosterPath, lock.ObjectKey{})
	return err
}
