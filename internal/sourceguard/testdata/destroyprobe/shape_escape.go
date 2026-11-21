package probe

import "net/http"

// Grok FO-1: inside a function ALLOWED to destroy, the DELETE token must be the
// method argument of its request call, DestroyVM must be a call, and the
// request count is pinned. funcShapeProblems must pass okDestroy and okVerb
// and flag the rest.

func okDestroy(ctx context.Context, c *Client, path string) error {
	_, err := c.RawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// G28: the token kept as a discarded identifier; the request carries a
// byte-built "DELETE".
func g28Discarded(ctx context.Context, c *Client, path string) error {
	_ = http.MethodDelete
	method := string([]byte{0x44, 0x45, 0x4c, 0x45, 0x54, 0x45})
	_, err := c.RawRequest(ctx, method, path, nil)
	return err
}

// G22: the real call kept, a second byte-built request beside it.
func g22Second(ctx context.Context, c *Client, path string) error {
	_, err := c.RawRequest(ctx, http.MethodDelete, path, nil)
	_, _ = c.RawRequest(ctx, string([]byte{0x44, 0x45, 0x4c, 0x45, 0x54, 0x45}), path, nil)
	return err
}

// DestroyVM as a method value, not a call.
func methodValue(ctx context.Context, client *pve.RoutedClient) {
	f := client.DestroyVM
	_ = f
}

func okVerb(ctx context.Context, client *pve.RoutedClient, vmid int) {
	_, _ = client.DestroyVM(ctx, vmid, true)
}

// G12: a byte-built request beside the verb's real DestroyVM.
func g12VerbRequest(ctx context.Context, client *pve.RoutedClient, vmid int) {
	_, _ = client.RawRequest(ctx, string([]byte{0x44, 0x45, 0x4c, 0x45, 0x54, 0x45}), "/nodes/n/qemu/1", nil)
	_, _ = client.DestroyVM(ctx, vmid, true)
}
