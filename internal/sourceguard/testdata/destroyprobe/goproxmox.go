package probe

// go-proxmox's own deletes carry NO DELETE token at the call site:
// (*VirtualMachine).Delete → DeleteWithParams(ctx, "/nodes/%s/qemu/%d", …).
func goProxmox(ctx context.Context, vm *proxmox.VirtualMachine, pc *proxmox.Client, path string) {
	_, _ = vm.Delete(ctx, nil)
	_ = pc.DeleteWithParams(ctx, path, nil, nil)
}
