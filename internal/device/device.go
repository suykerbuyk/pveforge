// Package device is pveforge's device-semantic translation layer (PRD
// §3.3): the "own a semantic layer on top of Proxmox's raw, opaque config
// fields" half of this project's stated reason for existing. A device
// intent — "add an emulated NVMe drive with this serial," and whatever
// else a future task adds — resolves internally to the raw config
// field/value pveforge-object-model-get-set's write primitive
// (pve.RoutedClient.SetVMConfigField) already knows how to apply. The
// underlying write primitive stays schema-free; this package builds the
// resolver functions that produce values for it, not a second write
// mechanism.
//
// One resolver per device intent (NVMeDrive today — see nvme.go), each a
// plain Go type implementing Apply against the Client interface below.
// There is deliberately no runtime name→resolver registry: nothing here
// needs to dispatch a resolver by name yet (no CLI flag, no JSON body do
// that), and building one speculatively would be exactly the kind of
// scope creep this task was split out to avoid. A future caller that
// needs name-based dispatch (a CLI command, pveforge-discoverability-schema)
// can add one without touching the resolvers themselves — each already
// stands alone.
package device

import (
	"context"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// Client is the subset of *pve.RoutedClient's capability a resolver
// needs: read the VM's current config (to merge into, not clobber) and
// apply the resolved field back through the routed write primitive.
// Defined here, not as the concrete *pve.RoutedClient, so this package's
// own tests use a lightweight in-package fake instead of pve's
// network/SSH test harness — *pve.RoutedClient satisfies this interface
// structurally, no changes needed on that side beyond its own Node()
// accessor.
type Client interface {
	// GetVM fetches vmid's current status and config on node.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// SetVMConfigField sets one VM config field, routed over REST or the
	// standing SSH vector as sshexec.RootOnlyFields dictates.
	SetVMConfigField(ctx context.Context, vmid int, field, value string) error
}
