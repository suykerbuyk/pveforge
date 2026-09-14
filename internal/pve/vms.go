package pve

import (
	"context"
	"fmt"
	"net/url"

	proxmox "github.com/luthermonson/go-proxmox"
)

// GetVM fetches one VM's current status and full config — mirrors
// go-proxmox's Node.VirtualMachine (status/current, then config, as two
// calls), but via c.pc.Get directly so the returned *proxmox.VirtualMachine's
// client field stays nil — see nodes.go's GetNode doc comment for why.
// Writing a field on the result belongs to RoutedClient.SetVMConfigField /
// Client.SetVMConfigField (vmconfig.go, routed.go), never to this object's
// own (inert) Config/ConfigSync methods.
func (c *Client) GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	if node == "" {
		return nil, fmt.Errorf("get vm %d: node is required", vmid)
	}
	vm := &proxmox.VirtualMachine{Node: node}
	escapedNode := url.PathEscape(node)
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/status/current", escapedNode, vmid), vm); err != nil {
		return nil, fmt.Errorf("get vm %d status: %w", vmid, err)
	}
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/config", escapedNode, vmid), &vm.VirtualMachineConfig); err != nil {
		return nil, fmt.Errorf("get vm %d config: %w", vmid, err)
	}
	return vm, nil
}

// GetVMs lists every VM on node with summary status fields —
// GET /nodes/{node}/qemu. Matches go-proxmox's own Node.VirtualMachines:
// no per-VM config fetch here (that's what GetVM is for) — this is the
// summary/listing endpoint only.
func (c *Client) GetVMs(ctx context.Context, node string) (proxmox.VirtualMachines, error) {
	if node == "" {
		return nil, fmt.Errorf("get vms: node is required")
	}
	var vms proxmox.VirtualMachines
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/qemu", url.PathEscape(node)), &vms); err != nil {
		return nil, fmt.Errorf("get vms on %q: %w", node, err)
	}
	for _, v := range vms {
		v.Node = node
	}
	return vms, nil
}
