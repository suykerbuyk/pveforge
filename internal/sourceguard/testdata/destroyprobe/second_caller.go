package probe

// The paste of cmd/pveforge/vm_destroy.go runVMDestroy's one DestroyVM call.
func secondCaller(ctx context.Context, client *pve.RoutedClient, vmid int) error {
	upid, err := client.DestroyVM(ctx, vmid, true)
	_ = upid
	return err
}
