package device

import (
	"context"
	"fmt"
	"strings"
)

// NVMeDrive is one device-semantic intent: an emulated NVMe drive to
// attach to a VM. Proxmox has no first-class NVMe bus type (unlike
// ide/sata/scsi/virtio) — the only way to attach one is the args: raw-QEMU
// escape hatch, which is also this project's standing example of a
// root-only field (verified: HTTP 500, "only root can set 'args'
// config") — so resolving this intent exercises the full routed-write
// stack, not just the args: merge logic.
type NVMeDrive struct {
	// Serial is the drive's emulated serial number, surfaced inside the
	// guest OS. Required. Restricted to a safe character set (see
	// Validate) since it's embedded directly into a comma-delimited QEMU
	// option string.
	Serial string
	// Backing is the QEMU `-drive file=` target: a PVE volid (e.g.
	// "local-lvm:vm-100-disk-1") or a raw host path. Required. Resolving
	// a PVE volid to its actual host filesystem path is out of scope for
	// this resolver — callers supply whatever `-drive file=` already
	// accepts.
	Backing string
	// Format is the QEMU `-drive format=` value (e.g. "raw", "qcow2").
	// Optional — PVE/QEMU infer it when unset, though LVM-backed volumes
	// typically need "raw" set explicitly.
	Format string
}

// Validate reports whether n is well-formed: Serial and Backing are
// required and non-empty, and every set field is restricted to a safe
// character set — none of them may contain ',' or other characters that
// could break out of their slot in the comma-delimited QEMU
// -device/-drive option strings Apply builds them into (the same
// defense-in-depth discipline as sshexec's field-name/shell-quoting
// checks elsewhere in this project).
func (n NVMeDrive) Validate() error {
	if !isSafeToken(n.Serial, "-_") {
		return fmt.Errorf("nvme drive: serial %q is empty or contains unsafe characters", n.Serial)
	}
	if !isSafeToken(n.Backing, "-_./:") {
		return fmt.Errorf("nvme drive: backing %q is empty or contains unsafe characters", n.Backing)
	}
	if n.Format != "" && !isSafeToken(n.Format, "") {
		return fmt.Errorf("nvme drive: format %q contains unsafe characters", n.Format)
	}
	return nil
}

// Apply resolves n into a QEMU args: fragment and applies it to vmid on
// client: it reads the VM's current args: value via client.GetVM, merges
// the new fragment in via AppendArgsFragment (never clobbering existing
// content), and writes the merged value back via
// client.SetVMConfigField(ctx, vmid, "args", merged).
//
// Naive, not idempotent: Apply always appends when called. It does not
// check whether a drive with this serial is already present in args: —
// check-then-act is pveforge-idempotent-mutation-engine's job project-wide
// (PRD §3.4), not this resolver's.
func (n NVMeDrive) Apply(ctx context.Context, client Client, vmid int) error {
	if err := n.Validate(); err != nil {
		return fmt.Errorf("nvme drive for vm %d: %w", vmid, err)
	}

	vm, err := client.GetVM(ctx, client.Node(), vmid)
	if err != nil {
		return fmt.Errorf("nvme drive for vm %d: read current config: %w", vmid, err)
	}

	var existingArgs string
	if vm.VirtualMachineConfig != nil {
		existingArgs = vm.VirtualMachineConfig.Args
	}

	merged := AppendArgsFragment(existingArgs, n.fragment())

	if err := client.SetVMConfigField(ctx, vmid, "args", merged); err != nil {
		return fmt.Errorf("nvme drive for vm %d: %w", vmid, err)
	}
	return nil
}

// fragment builds the QEMU args: fragment for n. Both the -device and
// -drive clauses share one id, derived from Serial (already validated to
// a safe character set, so no further escaping is needed to embed it
// directly).
//
// NOTE: this exact QEMU option syntax (-device nvme,drive=...,serial=...
// -drive file=...,if=none,id=...[,format=...]) is standard, documented
// QEMU device/drive syntax, but has not been independently verified
// against a live PVE host in this implementation session (no live host
// was available) — the same empirical-verification gap flagged for
// pveum's CLI output shape and the sshexec.RootOnlyFields registry
// elsewhere in this project. Confirm against a real host before trusting
// this in production.
func (n NVMeDrive) fragment() string {
	id := "nvme-" + n.Serial
	fragment := fmt.Sprintf("-device nvme,drive=%s,serial=%s -drive file=%s,if=none,id=%s", id, n.Serial, n.Backing, id)
	if n.Format != "" {
		fragment += ",format=" + n.Format
	}
	return fragment
}

// isSafeToken reports whether s is non-empty and every rune is an ASCII
// letter, digit, or one of the runes in extra.
func isSafeToken(s, extra string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune(extra, r):
		default:
			return false
		}
	}
	return true
}
