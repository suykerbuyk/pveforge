package device

import "strings"

// AppendArgsFragment appends fragment to existing (a VM's current args:
// value), space-separated, and returns the merged string — never
// clobbers existing content. Proxmox's args: is a single opaque string of
// raw QEMU command-line tokens; QEMU accepts multiple -device/-drive
// pairs concatenated with whitespace, so appending is safe as long as
// fragment doesn't collide with a device/drive id already present in
// existing — collision detection is the caller's job (see NVMeDrive's own
// id derivation), not this helper's.
func AppendArgsFragment(existing, fragment string) string {
	existing = strings.TrimSpace(existing)
	if existing == "" {
		return fragment
	}
	return existing + " " + fragment
}
