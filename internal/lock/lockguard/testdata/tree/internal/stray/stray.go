package stray

import (
	"context"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Take takes a lock outside cmd/pveforge and TakerFiles: a Violation.
func Take(ctx context.Context) error {
	_, err := lock.Read(ctx, "r", lock.ObjectKey{})
	return err
}
