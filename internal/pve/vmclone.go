package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// CloneVM issues PVE's clone call — POST /nodes/{node}/qemu/{sourceVMID}/clone
// — copying sourceVMID into a new VM at newVMID on node. params carries
// every OTHER raw PVE clone parameter the caller wants set (full, storage,
// target, name, pool, snapname — proxmox.VirtualMachineCloneOptions's own
// field names 1:1, types.go:1486, but as raw url.Values for the same
// schema-free reason CreateVM takes them that way).
//
// Returns the UPID of the PVE task the clone kicks off — cloning is always
// asynchronous on PVE's side — so the caller hands this straight to
// WaitForTask.
//
// Deliberately NOT built on go-proxmox's own VirtualMachine.Clone
// (virtual_machine.go:572), for two independent reasons:
//
//  1. It routes through v.client.Post. Through v0.8.2-pveforge.0
//     go-proxmox's handleResponse discarded the response body on HTTP
//     500/501, the statuses PVE uses for a clone-time rejection (a newid
//     collision, an incompatible storage target, a missing snapshot
//     name); since .1 it keeps it in a *proxmox.StatusError, but that
//     error's text is still only the status line, whose reason phrase
//     HTTP/2 erases, while RawRequest's error carries PVE's own text. And
//     Post JSON-encodes the parameters, where RawRequest form-encodes them
//     like every other write path here (RawRequest's doc comment).
//  2. Whenever params.NewID == 0 it calls v.client.Cluster(ctx) +
//     cluster.NextID(ctx) internally — an incidental extra /cluster/status
//     round trip. This project always pre-resolves the target VMID (via
//     NextVMID, before the Op is ever constructed), so that path must
//     never be reachable; stamping newid here unconditionally is what
//     guarantees it.
//
// newVMID is authoritative: it is stamped onto the form even if the caller
// already put a "newid" key in params. That is deliberate rather than
// incidental — VMClone's Read/Satisfied check for an existing VM at ITS
// NewVMID, so a params-supplied newid that disagreed would mean the
// existence check and the wire were talking about two different VMs.
//
// Cloned, never mutated in place, for the same reason CreateVM clones:
// params is the caller's own map (VMClone.Apply passes op.Params directly),
// and stamping "newid" onto it destructively would leave the caller looking
// at a map with a key it never put there.
func (c *Client) CloneVM(ctx context.Context, node string, sourceVMID, newVMID int, params url.Values) (string, error) {
	if node == "" {
		return "", fmt.Errorf("clone vm %d: node is required", sourceVMID)
	}

	form := params.Clone()
	if form == nil {
		form = url.Values{}
	}
	form.Set("newid", strconv.Itoa(newVMID))

	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/clone", url.PathEscape(node), sourceVMID), form)
	if err != nil {
		return "", fmt.Errorf("clone vm %d to %d: %w", sourceVMID, newVMID, err)
	}

	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return "", fmt.Errorf("clone vm %d to %d: %w", sourceVMID, newVMID, err)
	}
	return upid, nil
}

// StorageType resolves storageID's backend type string on node (e.g.
// "lvmthin", "zfspool", "dir") — a thin wrapper over GetStorage returning
// only its .Type.
//
// EXPORTED deliberately, and that is not a style choice: VMClone.Apply's
// linked-clone storage pre-check lives in internal/idempotent and holds
// only its VMCloneClient interface, never a concrete *pve.Client. An
// unexported helper here would be unreachable from the one caller the
// check exists for (Chair review, 2026-09-14). The matching
// RoutedClient.StorageType pass-through in routed.go is the other half of
// the same requirement.
func (c *Client) StorageType(ctx context.Context, node, storageID string) (string, error) {
	storage, err := c.GetStorage(ctx, node, storageID)
	if err != nil {
		return "", fmt.Errorf("storage type: %w", err)
	}
	return storage.Type, nil
}
