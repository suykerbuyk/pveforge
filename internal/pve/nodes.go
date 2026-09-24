package pve

import (
	"context"
	"fmt"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// GetNode fetches one node's detailed status (kernel version, load,
// uptime, CPU/memory/swap breakdowns, root filesystem usage) —
// GET /nodes/{node}/status.
//
// Deliberately calls c.pc.Get directly rather than go-proxmox's own
// Client.Node/Node.Status wrapper methods: those set the returned
// *proxmox.Node's unexported client field, which is what lets its own
// write-side methods (NewVirtualMachine, NewNetwork, etc.) talk to PVE
// directly — bypassing RoutedClient's REST/SSH root-only-field routing
// and vmconfig.go's error-surfacing fix entirely. Skipping that wrapper
// means the returned value's client field stays nil (JSON unmarshal never
// touches unexported fields), so any accidental call to one of those
// write methods panics immediately instead of silently doing the wrong
// thing. See vms.go/storage.go/networks.go for the same pattern.
//
// Unlike GetStorage, GetVM and GetNetworkInterface, this read carries no
// ErrUnverifiableRead guard: /nodes/{node}/status has no field confirmed to
// be present on every healthy answer, and its only consumer (`node get`)
// is display-only, so a {"data":null} answer prints zeros rather than
// feeding a decision.
func (c *Client) GetNode(ctx context.Context, node string) (*proxmox.Node, error) {
	if node == "" {
		return nil, fmt.Errorf("get node: node is required")
	}
	result := &proxmox.Node{Name: node}
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/status", url.PathEscape(node)), result); err != nil {
		return nil, fmt.Errorf("get node %q: %w", node, err)
	}
	return result, nil
}

// GetNodes lists every node in the cluster with its summary status —
// GET /nodes. proxmox.NodeStatus carries no client field at all (a plain
// data struct), so this is safe with no special handling; it's the same
// call ListNodes makes, just returning the full typed result instead of
// narrowing to node names.
func (c *Client) GetNodes(ctx context.Context) (proxmox.NodeStatuses, error) {
	ns, err := c.pc.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("get nodes: %w", err)
	}
	if ns == nil {
		return nil, fmt.Errorf("get nodes: %w: list payload was null", ErrUnverifiableRead)
	}
	if i := nullEntry(ns); i >= 0 {
		return nil, fmt.Errorf("get nodes: %w: entry %d is null", ErrUnverifiableRead, i)
	}
	return ns, nil
}
