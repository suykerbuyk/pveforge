package probe

// The raw idiom with the method spelled as a literal.
func rawLiteral(ctx context.Context, client *pve.Client, node string, vmid int) {
	_, _ = client.RawRequest(ctx, "DELETE", fmt.Sprintf("/nodes/%s/qemu/%d", node, vmid), nil)
	_, _ = client.RawRequest(ctx, `DELETE`, fmt.Sprintf("/nodes/%s/qemu/%d", node, vmid), nil)
}
