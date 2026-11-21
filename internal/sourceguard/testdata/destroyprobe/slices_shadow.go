package probe

import "slices"

// Grok FO-2 (G20b): the file imports slices, so a name-only filter would drop
// this, but a local `slices` holds a go-proxmox VM and .Delete is its destroy.
func shadowDelete(ctx context.Context, vm *proxmox.VirtualMachine) error {
	_ = slices.Delete[[]int]
	slices := vm
	_, err := slices.Delete(ctx, &proxmox.VirtualMachineDeleteOptions{Purge: true})
	return err
}
