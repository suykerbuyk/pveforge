package pve

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// GetNetworkInterface fetches one node-level network interface's config
// (bridge/bond/vlan settings) — GET /nodes/{node}/network/{iface}. Mirrors
// go-proxmox's Node.Network but via c.pc.Get directly so the returned
// *proxmox.NodeNetwork's client/NodeAPI fields stay nil (never set) — see
// nodes.go's GetNode doc comment for why (its embedded Update/Delete
// methods would otherwise bypass RoutedClient's routing entirely).
func (c *Client) GetNetworkInterface(ctx context.Context, node, iface string) (*proxmox.NodeNetwork, error) {
	if node == "" || iface == "" {
		return nil, fmt.Errorf("get network interface: node and iface are required")
	}
	nw := &proxmox.NodeNetwork{}
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/network/%s", url.PathEscape(node), url.PathEscape(iface)), nw); err != nil {
		return nil, fmt.Errorf("get network interface %q on %q: %w", iface, node, err)
	}
	nw.Node = node
	nw.Iface = iface
	return nw, nil
}

// GetNetworkInterfaces lists node's network interfaces —
// GET /nodes/{node}/network, optionally filtered to one interface type
// (e.g. "bridge", "bond") — PVE accepts at most one type filter.
func (c *Client) GetNetworkInterfaces(ctx context.Context, node string, ifaceType ...string) (proxmox.NodeNetworks, error) {
	if node == "" {
		return nil, fmt.Errorf("get network interfaces: node is required")
	}
	if len(ifaceType) > 1 {
		return nil, errors.New("get network interfaces: only one interface type filter is allowed")
	}

	path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(node))
	if len(ifaceType) == 1 {
		path += "?" + url.Values{"type": ifaceType}.Encode()
	}

	var networks proxmox.NodeNetworks
	if err := c.pc.Get(ctx, path, &networks); err != nil {
		return nil, fmt.Errorf("get network interfaces on %q: %w", node, err)
	}
	for _, nw := range networks {
		nw.Node = node
	}
	return networks, nil
}
