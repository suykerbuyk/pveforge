package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	// unshared (the orphan scan's refusal keys on exactly that). Verified
	// live: an nfs storage's status carries type (nested pvh 2026-10-23,
	// evidence ~/.config/pveforge/harness-evidence/batch-a/).
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

// CreateStorage issues PVE's create-storage call — POST /storage — and
// returns PVE's raw (envelope-unwrapped) response for the caller to decode.
//
// Unlike CreateVM, this is a DATACENTER/cluster-level write, not node-scoped:
// there is no POST /nodes/{node}/storage; a storage definition lives in the
// cluster-wide storage.cfg and applies to the whole cluster however one node
// is addressed. This method's only job on top of params is stamping
// storage=<name> onto a clone and dispatching the call — no structured
// create-options type, mirroring CreateVM's own raw/schema-free precedent
// (PVE owns the per-type parameter surface and validates it).
//
// Goes through RawRequest for the same reasons CreateVM does (see its doc
// comment): PVE's own verbatim error text reaches the caller — a duplicate id
// comes back as a *StatusError carrying "storage ID already defined", and a
// 403 satisfies errors.Is(err, ErrNotAuthorized) — rather than HTTP/2 erasing
// the reason phrase, and the form-encoded body PVE expects.
//
// POST /storage is SYNCHRONOUS on PVE's side: it writes storage.cfg and
// answers with the created storage's config object as data, NOT a bare UPID
// task-id — so unlike CreateVM this returns the response for the caller to
// decode and normally needs no WaitForTask. NOT live-verified (owed to
// pveforge-nested-pve-test-harness): the one caller (idempotent.StorageCreate)
// decodes defensively and waits on a bare UPID if PVE ever returns one, so the
// design is correct either way.
func (c *Client) CreateStorage(ctx context.Context, name string, params url.Values) (json.RawMessage, error) {
	if name == "" {
		return nil, fmt.Errorf("create storage: a storage name is required")
	}

	// Cloned, never mutated in place: params is the caller's own map (the Op
	// passes op.Params directly), so stamping "storage" onto it destructively
	// would leave the caller's map holding a key it never set.
	form := params.Clone()
	if form == nil {
		form = url.Values{}
	}
	form.Set("storage", name)

	raw, err := c.RawRequest(ctx, http.MethodPost, "/storage", form)
	if err != nil {
		return nil, fmt.Errorf("create storage %q: %w", name, err)
	}
	return raw, nil
}

// GetStorageConfig resolves storageID's cluster-wide CONFIG object —
// GET /storage/{storageID} — carrying type, content, nodes, digest and the
// rest of the definition PVE holds in storage.cfg. This is the right read-back
// for a create: it exists cluster-wide the instant the config is written,
// unlike GetStorage's per-node runtime STATUS endpoint. Unlike
// GetStorageConfigPath (which returns only the filesystem path and rejects a
// storage type that has none), this returns the whole object, so it works for
// a zfspool/lvm storage that has no on-disk path.
//
// A not-found id is left for the caller to classify (IsStorageNotFoundError):
// PVE answers a missing storage with its own 400 "No such storage.", which
// this wraps with %w so errors.As still finds the typed answer.
//
// Deliberately calls c.pc.Get directly rather than go-proxmox's own
// Client.ClusterStorage wrapper, for the same reason as GetStorage/GetNode
// (see their own doc comments): keeps the returned struct's unexported client
// field nil.
func (c *Client) GetStorageConfig(ctx context.Context, storageID string) (*proxmox.ClusterStorage, error) {
	if storageID == "" {
		return nil, fmt.Errorf("get storage config: storage id is required")
	}
	result := &proxmox.ClusterStorage{}
	if err := c.pc.Get(ctx, fmt.Sprintf("/storage/%s", url.PathEscape(storageID)), result); err != nil {
		return nil, fmt.Errorf("get storage config for %q: %w", storageID, err)
	}
	return result, nil
}

// GetStorageConfigRaw reads storageID's cluster-wide CONFIG object —
// GET /storage/{storageID} — as the RAW PVE object, decoded into a map of its
// own PVE-named keys (type, pool, content, nodes, sparse, shared, digest, ...),
// NOT the typed proxmox.ClusterStorage. That struct models only a subset
// (Content, Digest, Storage, Type, Shared, Nodes, Thinpool, Path, VgName) and
// encoding/json silently DROPS every other key on decode — notably `pool` (the
// field a zfspool is defined by), `sparse`, and an omitempty `shared=0`. A
// drift check that must compare every parameter the operator asked for needs
// those keys, so StorageCreate reads through this; GetStorageConfig and
// GetStorageConfigPath keep the typed struct for callers that only need the
// modeled fields. This mirrors storageorphans.go's storageContentEntry, which
// adds back the one field proxmox.StorageContent drops for the same reason.
//
// A not-found id is left for the caller to classify (IsStorageNotFoundError),
// exactly as GetStorageConfig: the error is wrapped with %w so errors.As still
// finds the typed PVE answer.
func (c *Client) GetStorageConfigRaw(ctx context.Context, storageID string) (map[string]json.RawMessage, error) {
	if storageID == "" {
		return nil, fmt.Errorf("get storage config: storage id is required")
	}
	raw := map[string]json.RawMessage{}
	if err := c.pc.Get(ctx, fmt.Sprintf("/storage/%s", url.PathEscape(storageID)), &raw); err != nil {
		return nil, fmt.Errorf("get storage config for %q: %w", storageID, err)
	}
	return raw, nil
}

// IsStorageNotFoundError reports whether err is PVE's own answer that a
// storage id does not exist. PVE answers a missing storage with a 400
// parameter-verification body whose errors.storage entry is exactly
// "No such storage." — NOT the "does not exist" phrase pve.NotFound keys on —
// so storage needs its own classifier. The missing-storage wording was
// observed live for the per-node STATUS endpoint
// (GET /nodes/{node}/storage/{name}/status; nested pvh 2026-10-23, evidence
// ~/.config/pveforge/harness-evidence/batch-a/, item storage-missing); the
// config endpoint GET /storage/{id} that GetStorageConfigRaw calls shares that
// wording by PVE convention, but its 400 body is NOT yet captured on a live
// host, so this is not a claim that the config route was live-verified.
//
// Anchored, not a whole-answer substring: it is true ONLY when a typed PVE
// answer (a *StatusError or *proxmox.StatusError anywhere in err's chain)
// carries a parameter-verification map whose `storage` entry equals
// "No such storage." (case-insensitive, optional trailing period), via the
// same parameterErrors decode notfound.go uses. Fails CLOSED both ways: an
// untyped error, a transport failure, a duplicate-id 500, or a privilege 403
// whose prose merely contains the phrase "no such storage pool" is NOT read as
// absent — only PVE's exact absence answer is, so a read that failed for some
// other reason is never mistaken for "the storage isn't there".
func IsStorageNotFoundError(err error) bool {
	answer, ok := pveAnswer(err)
	if !ok {
		return false
	}
	entries, structured := parameterErrors(answer)
	if !structured {
		return false
	}
	entry := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(entries["storage"])), ".")
	return entry == "no such storage"
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
