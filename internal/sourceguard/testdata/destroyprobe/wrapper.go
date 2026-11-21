package probe

// A wrapper: in an ALLOWED file this is a new (file, func) key, which a
// file-level allow-list cannot see.
func nuke(ctx context.Context, c *pve.RoutedClient, v int) {
	_, _ = c.DestroyVM(ctx, v, true)
}
