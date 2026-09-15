package idempotent

import (
	"fmt"

	proxmox "github.com/luthermonson/go-proxmox"
)

// requireVMConfig returns vm's VirtualMachineConfig, or an error if PVE
// returned none for vmid. Shared by every Op whose Read goes through
// Client.GetVM (VMTagEnsure, BridgeIsolationEnsure) — VMFieldsEnsure reads
// via Client.RawRequest instead (see vmfields.go's own doc comment) and
// never has a VirtualMachineConfig to check here.
//
// A nil VirtualMachineConfig must never be treated as digest="" by a
// CAS-guarding caller: SetVMConfigFieldCAS with an empty expectDigest
// behaves exactly like the unconditional SetVMConfigField, so silently
// defaulting to "" disables the digest-CAS defense-in-depth check instead
// of surfacing that the mutation's target may not exist (pveforge-nil-
// vmconfig-digest-gap, 2026-09-14).
func requireVMConfig(vm *proxmox.VirtualMachine, vmid int, opName string) (*proxmox.VirtualMachineConfig, error) {
	if vm.VirtualMachineConfig == nil {
		return nil, fmt.Errorf("%s: vm %d: no config returned (vm may not exist)", opName, vmid)
	}
	return vm.VirtualMachineConfig, nil
}
