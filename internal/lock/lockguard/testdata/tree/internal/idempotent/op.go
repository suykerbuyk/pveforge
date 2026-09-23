package idempotent

import (
	"context"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Run re-assigns its ctx before the lock: refused.
func Run(ctx context.Context, rosterPath string, key lock.ObjectKey, op any, force bool) (any, error) {
	ctx = context.Background()
	_, err := lock.Mutation(ctx, rosterPath, key)
	return nil, err
}

// Shadow's closure takes its own ctx parameter, shadowing Shadow's: refused.
func Shadow(ctx context.Context) error {
	return func(ctx context.Context) error {
		_, err := lock.Read(ctx, "r", lock.ObjectKey{})
		return err
	}(context.Background())
}

// helper takes a lock where no caller can be checked against it: a
// TakerProblem. Its own call is accepted (its ctx parameter, directly).
func helper(ctx context.Context) error {
	_, err := lock.Read(ctx, "r", lock.ObjectKey{})
	return err
}
