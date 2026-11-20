package pve

import (
	"context"
	"fmt"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// Placement is where the cluster-wide resource list says a vmid lives. It is
// DETAIL ONLY: it is read through a principal-filtered endpoint, so a short
// answer proves nothing, and it is never an input to a gone-proof verdict class
// — it can only name the node a refusal is about.
type Placement struct {
	Node   string
	Seen   bool
	Read   string
	Detail string
}

// PlacementOf reads GET /cluster/resources and filters client-side to the
// qemu resource with this vmid (FindByTag's idiom; a vmid is looked up, no tag
// is accepted).
//
// GET /cluster/resources drops every VM the caller lacks VM.Audit on, so
// Seen=false means "this token does not see one", not "none exists". Note also
// that Cluster.Resources collapses a 403 into a bare, body-less ErrNotAuthorized
// (a 401 reads the same): the detail cannot quote PVE's privilege sentence.
func (c *Client) PlacementOf(ctx context.Context, vmid int) Placement {
	const read = "GET /cluster/resources"
	cluster := (&proxmox.Cluster{}).New(c.pc)
	resources, err := cluster.Resources(ctx, "vm")
	if err != nil {
		return Placement{Read: read, Detail: oneLine(err.Error())}
	}
	if resources == nil {
		return Placement{Read: read, Detail: "the resource list payload was null"}
	}
	if i := nullEntry(resources); i >= 0 {
		return Placement{Read: read, Detail: fmt.Sprintf("resource list entry %d is null", i)}
	}
	for _, r := range resources {
		if r.Type == "qemu" && r.VMID == uint64(vmid) {
			return Placement{Node: r.Node, Seen: true, Read: read}
		}
	}
	return Placement{Read: read, Detail: "this token's resource list does not show the vmid (the list is filtered by VM.Audit)"}
}
