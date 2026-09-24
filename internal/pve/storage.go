package pve

import (
	"context"
	"fmt"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// GetStorage fetches one storage's per-node status —
// GET /nodes/{node}/storage/{name}/status. Mirrors go-proxmox's
// Node.Storage but via c.pc.Get directly so the returned *proxmox.Storage's
// client field stays nil (never set) — see nodes.go's GetNode doc comment
// for why that matters (its embedded Upload/Delete-style methods would
// otherwise bypass RoutedClient's routing entirely).
func (c *Client) GetStorage(ctx context.Context, node, name string) (*proxmox.Storage, error) {
	if node == "" || name == "" {
		return nil, fmt.Errorf("get storage: node and name are required")
	}
	storage := &proxmox.Storage{}
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/storage/%s/status", url.PathEscape(node), url.PathEscape(name)), storage); err != nil {
		return nil, fmt.Errorf("get storage %q on %q: %w", name, node, err)
	}
	// PVE's status payload always names the storage's type; a payload
	// without one is a zero value decoded from {"data":null}, and reading
	// it as real would report Shared == 0 for a storage never confirmed
	// unshared (the orphan scan's refusal keys on exactly that).
	if storage.Type == "" {
		return nil, fmt.Errorf("get storage %q on %q: %w: status payload carries no storage type", name, node, ErrUnverifiableRead)
	}
	storage.Node = node
	storage.Name = name
	return storage, nil
}

// GetStorages lists every storage backend visible on node —
// GET /nodes/{node}/storage.
func (c *Client) GetStorages(ctx context.Context, node string) (proxmox.Storages, error) {
	if node == "" {
		return nil, fmt.Errorf("get storages: node is required")
	}
	var storages proxmox.Storages
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/storage", url.PathEscape(node)), &storages); err != nil {
		return nil, fmt.Errorf("get storages on %q: %w", node, err)
	}
	if storages == nil {
		return nil, fmt.Errorf("get storages on %q: %w: list payload was null", node, ErrUnverifiableRead)
	}
	if i := nullEntry(storages); i >= 0 {
		return nil, fmt.Errorf("get storages on %q: %w: entry %d is null", node, ErrUnverifiableRead, i)
	}
	for _, s := range storages {
		s.Node = node
	}
	return storages, nil
}

// GetStorageConfigPath resolves storageID's configured filesystem base
// path (e.g. "/var/lib/vz") via the cluster-wide storage CONFIG endpoint —
// GET /storage/{storageID} — as opposed to GetStorage's per-node runtime
// STATUS endpoint, which carries no path field at all. Needed by
// RoutedClient.UploadSnippet to compute where PVE's "snippets" storage
// content type actually lives on disk, since Proxmox has no REST upload
// endpoint for that content type (see UploadSnippet's own doc comment).
//
// Deliberately calls c.pc.Get directly rather than go-proxmox's own
// Client.ClusterStorage wrapper, for the same reason as GetNode/GetStorage
// (see their own doc comments): keeps the returned struct's unexported
// client field nil.
func (c *Client) GetStorageConfigPath(ctx context.Context, storageID string) (string, error) {
	if storageID == "" {
		return "", fmt.Errorf("get storage config path: storage id is required")
	}
	result := &proxmox.ClusterStorage{}
	if err := c.pc.Get(ctx, fmt.Sprintf("/storage/%s", url.PathEscape(storageID)), result); err != nil {
		return "", fmt.Errorf("get storage config for %q: %w", storageID, err)
	}
	if result.Path == "" {
		return "", fmt.Errorf("storage %q has no configured filesystem path (not a directory-backed storage type?)", storageID)
	}
	return result.Path, nil
}

// GetStorageVolumes lists the content (volumes: disks, ISOs, backups,
// templates) on one storage — GET /nodes/{node}/storage/{storage}/content.
// proxmox.StorageContent is a plain data struct with no client field at
// all, so this needs none of GetStorage's nil-client care.
func (c *Client) GetStorageVolumes(ctx context.Context, node, storage string) ([]*proxmox.StorageContent, error) {
	if node == "" || storage == "" {
		return nil, fmt.Errorf("get storage volumes: node and storage are required")
	}
	var content []*proxmox.StorageContent
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/storage/%s/content", url.PathEscape(node), url.PathEscape(storage)), &content); err != nil {
		return nil, fmt.Errorf("get volumes on storage %q on %q: %w", storage, node, err)
	}
	if content == nil {
		return nil, fmt.Errorf("get volumes on storage %q on %q: %w: list payload was null", storage, node, ErrUnverifiableRead)
	}
	if i := nullEntry(content); i >= 0 {
		return nil, fmt.Errorf("get volumes on storage %q on %q: %w: entry %d is null", storage, node, ErrUnverifiableRead, i)
	}
	return content, nil
}
