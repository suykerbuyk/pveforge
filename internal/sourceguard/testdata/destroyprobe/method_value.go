package probe

// A method value and a method expression: neither is a call, both destroy.
func methodValue(ctx context.Context, client *pve.RoutedClient) {
	f := client.DestroyVM
	_, _ = f(ctx, 1, true)
	g := (*pve.RoutedClient).DestroyVM
	_, _ = g(client, ctx, 1, true)
}
