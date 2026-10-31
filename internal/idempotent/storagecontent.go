package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// StorageContentClient is the subset of *pve.RoutedClient a storage
// content-toggle Op needs — a narrow interface per Op, modeled on
// StorageCreateClient: the RAW cluster-config read-back (for the current
// content list and the CAS digest), the digest-guarded config write, Node (for
// the defensive WaitForTask only), and WaitForTask. Defined here, not as the
// concrete *pve.RoutedClient, so this package's tests use a lightweight
// in-package fake; *pve.RoutedClient satisfies it structurally (compat_test.go
// pins that).
type StorageContentClient interface {
	// GetStorageConfigRaw reads storageID's cluster-wide config object as the
	// RAW PVE object — every key PVE holds, including `content` and `digest`.
	GetStorageConfigRaw(ctx context.Context, storageID string) (map[string]json.RawMessage, error)
	// UpdateStorageConfig writes params (content=<list>&digest=<d>) to storageID
	// via PUT /storage/{id}, returning PVE's raw (envelope-unwrapped) response.
	UpdateStorageConfig(ctx context.Context, storageID string, params url.Values) (json.RawMessage, error)
	// Node returns the PVE node this client is scoped to — only for the
	// defensive WaitForTask below, never to scope the write (storage.cfg is
	// cluster-wide, not node-scoped).
	Node() string
	// WaitForTask polls a PVE task by UPID — reached only on the defensive path
	// where PUT /storage/{id} returned a bare UPID scalar.
	WaitForTask(ctx context.Context, node, upid string) error
}

// StorageContentEnsure is the idempotent-mutation-engine's Op for
// `storage set-content` (pveforge-storage-content-toggle): ensure Storage's
// cluster-level `content` list INCLUDES ContentType — an ADD-ONLY toggle
// (existing set ∪ ContentType), never a removal. It is a digest-CAS
// read-modify-write of the single `content` field, mirroring vmfields.go's
// re-read-before-every-write discipline applied to /storage/{id}, and the
// StorageCreate sibling's synchronous-write / defensive-UPID posture.
//
// Unlike StorageCreate it never creates a storage: a storage that does not
// exist is a HARD error from Read (you cannot toggle content on a storage that
// isn't there), not an "absent -> create" signal. Removing a content type is
// out of scope by design — removing e.g. `images` from a storage holding VM
// disks would strand them, which is a destructive operation, not this one.
type StorageContentEnsure struct {
	Client      StorageContentClient
	Storage     string
	ContentType string // the one content type to ensure present, e.g. "snippets"

	// snapshot is what Read observed — the content-type set, the CAS digest,
	// and the full raw field map — captured so Satisfied can answer without a
	// second read. Refreshed on every attempt, including a Run-driven retry
	// after ErrConflict. Apply does NOT reuse its digest (it re-reads a fresh
	// one of its own; see Apply).
	snapshot storageContentSnapshot
}

// storageContentSnapshot is one parsed GET /storage/{id}: the content-type set,
// the digest (the CAS token), and the full raw field map rendered to plain
// scalars (for Apply's post-write diff-guard).
type storageContentSnapshot struct {
	content map[string]bool
	digest  string
	fields  map[string]string // every PVE key (lowercased) -> jsonScalar value
}

// validStorageContentTypes is PVE's canonical set of storage `content` field
// values — distinct from storageorphans.go's claimableContentTypes (which is
// the SUBSET that can be claimed as a VM volume, images+iso; do NOT conflate
// them). This is the full set a storage.cfg `content` list may legitimately
// hold, so set-content fails closed on anything else rather than writing an
// unvalidated token into the cluster-wide config.
//
// Tracks PVE 9.x's known content types (images, rootdir, iso, vztmpl, backup,
// snippets, import). NOT verified against a live host beyond PVE 9.2 (the
// project's standing unverified-against-live convention): a future PVE release
// that adds a content type will need this set extended.
var validStorageContentTypes = map[string]bool{
	"images":   true,
	"rootdir":  true,
	"iso":      true,
	"vztmpl":   true,
	"backup":   true,
	"snippets": true,
	"import":   true,
}

// Validate reports whether the Op is well-formed: a storage name is required,
// and the content type must be one of PVE's canonical content types
// (validStorageContentTypes) — a command that writes the cluster-wide
// storage.cfg fails closed on an input it cannot trust rather than passing an
// arbitrary string to PVE.
func (op *StorageContentEnsure) Validate() error {
	if op.Storage == "" {
		return fmt.Errorf("storage set-content: a storage name is required")
	}
	if op.ContentType == "" {
		return fmt.Errorf("storage set-content: a content type is required")
	}
	if !validStorageContentTypes[op.ContentType] {
		return fmt.Errorf("storage set-content: storage %q: unknown content type %q; valid types are backup, images, import, iso, rootdir, snippets, vztmpl", op.Storage, op.ContentType)
	}
	return nil
}

// Read reports Storage's current content-type list as a comparable string (the
// sorted types, comma-joined). A storage that does not exist is a HARD error
// (pve.IsStorageNotFoundError), never "absent"; a config carrying no `digest`
// is refused loudly (StorageCreate/vmfields discipline — the digest is the CAS
// token Apply needs, and its absence means an untrustworthy read).
func (op *StorageContentEnsure) Read(ctx context.Context) (string, error) {
	raw, err := op.Client.GetStorageConfigRaw(ctx, op.Storage)
	if err != nil {
		if pve.IsStorageNotFoundError(err) {
			return "", fmt.Errorf("storage set-content: storage %q does not exist (create it first; set-content does not create a storage): %w", op.Storage, err)
		}
		return "", fmt.Errorf("storage set-content: storage %q: read current config: %w", op.Storage, err)
	}
	snap, err := parseStorageContentSnapshot(op.Storage, raw)
	if err != nil {
		return "", err
	}
	op.snapshot = snap
	return contentListString(snap.content), nil
}

// Satisfied reports whether ContentType is already present in the storage's
// content set (the add-only toggle is a no-op when it is). Keyed on what Read
// observed, which Run guarantees ran first on this same Op value.
func (op *StorageContentEnsure) Satisfied(_ string) bool {
	return op.snapshot.content[op.ContentType]
}

// Apply ensures ContentType is in Storage's content list. It re-reads a FRESH
// digest immediately before the CAS write — never Read's snapshot digest
// (vmfields.go discipline): a stale digest would spuriously conflict. The whole
// cycle runs under one lock.Mutation hold, so a conflict on this fresh digest
// can only mean genuine external interference (a different machine/roster, the
// PVE GUI), exactly what digest-CAS exists to catch as defense-in-depth.
//
// The new content list is the existing set UNIONED with ContentType, sorted,
// comma-joined — add-only, so no existing type is ever lost. On a digest
// mismatch the error wraps ErrConflict so idempotent.Run retries the whole
// cycle. PUT /storage/{id} is SYNCHRONOUS; the task is waited on only
// defensively if PVE ever answers with a bare UPID scalar (mirror
// StorageCreate.Apply). Finally the diff-guard re-reads and asserts the ONLY
// fields that changed are `content` and `digest`.
func (op *StorageContentEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	raw, err := op.Client.GetStorageConfigRaw(ctx, op.Storage)
	if err != nil {
		return fmt.Errorf("storage set-content: storage %q: re-read before write: %w", op.Storage, err)
	}
	pre, err := parseStorageContentSnapshot(op.Storage, raw)
	if err != nil {
		return err
	}

	// Add-only merge: existing set ∪ ContentType, sorted, rejoined with ','.
	merged := map[string]bool{op.ContentType: true}
	for t := range pre.content {
		merged[t] = true
	}
	newList := contentListString(merged)

	form := url.Values{}
	form.Set("content", newList)
	form.Set("digest", pre.digest)

	resp, err := op.Client.UpdateStorageConfig(ctx, op.Storage, form)
	if err != nil {
		if pve.IsDigestConflictError(err) {
			return fmt.Errorf("storage set-content: storage %q: %w: %w", op.Storage, ErrConflict, err)
		}
		return fmt.Errorf("storage set-content: storage %q: write content: %w", op.Storage, err)
	}

	// Synchronous storage.cfg write; wait only defensively on a bare UPID.
	if upid, ok := upidIfScalar(resp); ok {
		if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
			return fmt.Errorf("storage set-content: storage %q: %w", op.Storage, err)
		}
	}

	return op.diffGuard(ctx, pre)
}

// diffGuard re-reads the config after the write and asserts the ONLY fields
// that differ from the pre-write snapshot are `content` and `digest`. This is
// defense-in-depth against PVE's own config-reload touching a field this Op
// never asked for; a mismatch (including a field that appeared or disappeared —
// an absent key reads as "") is a HARD error naming the field(s), never
// silently accepted.
func (op *StorageContentEnsure) diffGuard(ctx context.Context, pre storageContentSnapshot) error {
	raw, err := op.Client.GetStorageConfigRaw(ctx, op.Storage)
	if err != nil {
		return fmt.Errorf("storage set-content: storage %q: diff-guard re-read: %w", op.Storage, err)
	}
	post, err := parseStorageContentSnapshot(op.Storage, raw)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	for k := range pre.fields {
		seen[k] = true
	}
	for k := range post.fields {
		seen[k] = true
	}
	var unexpected []string
	for k := range seen {
		if k == "content" || k == "digest" {
			continue
		}
		if pre.fields[k] != post.fields[k] {
			unexpected = append(unexpected, k)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return fmt.Errorf("storage set-content: storage %q: the write changed unexpected field(s) %s (only content and digest were meant to change) — refusing to report success", op.Storage, strings.Join(unexpected, ", "))
	}

	// Positive assertion: the INTENDED change actually landed. idempotent.Run
	// does not re-check Satisfied after Apply (op.go only re-reads for
	// Result.After), so a PUT that returns 2xx while the re-read still shows the
	// old list would otherwise make Apply return nil and Run report a success
	// that did not happen. Confirm ContentType is now present, or fail closed.
	if !post.content[op.ContentType] {
		return fmt.Errorf("storage set-content: storage %q: the write reported success but content type %q is not present on re-read — refusing to report success", op.Storage, op.ContentType)
	}
	return nil
}

// parseStorageContentSnapshot parses one raw GET /storage/{id} into the
// content-type set, the CAS digest, and the full scalar field map. A config
// with no `digest` key, or an empty one, is refused: Apply's CAS write needs a
// real digest, and its absence signals an untrustworthy read.
func parseStorageContentSnapshot(storage string, raw map[string]json.RawMessage) (storageContentSnapshot, error) {
	digestRaw, ok := raw["digest"]
	if !ok {
		return storageContentSnapshot{}, fmt.Errorf("storage set-content: storage %q: config carries no digest (cannot compare-and-swap safely)", storage)
	}
	digest := jsonScalar(digestRaw)
	if digest == "" {
		return storageContentSnapshot{}, fmt.Errorf("storage set-content: storage %q: config digest is empty", storage)
	}

	fields := make(map[string]string, len(raw))
	for k, v := range raw {
		fields[strings.ToLower(k)] = jsonScalar(v)
	}

	content := map[string]bool{}
	if c, ok := fields["content"]; ok {
		for _, t := range strings.Split(c, ",") {
			if t = strings.TrimSpace(t); t != "" {
				content[t] = true
			}
		}
	}
	return storageContentSnapshot{content: content, digest: digest, fields: fields}, nil
}

// contentListString renders a content-type set as PVE's `content` field value:
// the types sorted and comma-joined, so the written list is deterministic.
func contentListString(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
