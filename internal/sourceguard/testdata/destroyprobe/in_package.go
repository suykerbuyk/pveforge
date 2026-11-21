package idempotent

// A new file INSIDE package idempotent constructs VMDestroy with no qualifier
// and Applies it.
func applyHere(ctx context.Context, c VMDestroyClient, v int) error {
	op := &VMDestroy{Client: c, VMID: v}
	return op.Apply(ctx)
}
