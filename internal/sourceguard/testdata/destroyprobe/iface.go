package probe

// A new interface a destroy can hide behind (Go cannot satisfy DestroyVM
// under another name, so it must declare DestroyVM).
type destroyer interface {
	DestroyVM(ctx context.Context, vmid int, purge bool) (string, error)
}

func viaInterface(ctx context.Context, d destroyer) {
	_, _ = d.DestroyVM(ctx, 1, true)
}
