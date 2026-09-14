package pve

import (
	"context"
	"fmt"
	"net/url"

	proxmox "github.com/luthermonson/go-proxmox"
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
	for _, s := range storages {
		s.Node = node
	}
	return storages, nil
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
	return content, nil
}
