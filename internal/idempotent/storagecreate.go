package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// StorageCreateClient is the subset of *pve.RoutedClient a storage-create Op
// needs: the cluster-wide config read-back (to detect existence and compare
// the definition), the create call itself, Node (for the defensive
// WaitForTask), and WaitForTask. Defined here, not as the concrete
// *pve.RoutedClient, so this package's own tests use a lightweight in-package
// fake — *pve.RoutedClient satisfies it structurally (compat_test.go pins
// that), the same "narrow interface per Op" shape VMCreateClient uses.
type StorageCreateClient interface {
	// GetStorageConfig reads storageID's cluster-wide config object. Read
	// uses it to detect existence and, with Satisfied, to compare the
	// definition; a not-found id is classified with pve.IsStorageNotFoundError.
	GetStorageConfig(ctx context.Context, storageID string) (*proxmox.ClusterStorage, error)
	// CreateStorage issues PVE's POST /storage with storage=name stamped on,
	// returning PVE's raw (envelope-unwrapped) response.
	CreateStorage(ctx context.Context, name string, params url.Values) (json.RawMessage, error)
	// Node returns the PVE node name this client is scoped to — only for the
	// defensive WaitForTask below, never to scope the create (storage is
	// cluster-wide, not node-scoped).
	Node() string
	// WaitForTask polls a PVE task (by UPID) to completion — reached only on
	// the defensive path where POST /storage returned a bare UPID scalar.
	WaitForTask(ctx context.Context, node, upid string) error
}

// requiredKeysByType is the per-type "these keys must be present" guard — a
// tiny, data-driven table, deliberately NOT a schema: PVE validates everything
// else and its verbatim error reaches the caller. A type belongs here only
// when an omitted key is a SILENT misconfiguration trap, not merely invalid.
//
// v1: zfspool needs `pool`. A zfspool storage created with no pool= points at
// no zpool and comes up guaranteed-inactive rather than failing loudly, so the
// one footgun the harness dogfood would hit is caught client-side before any
// POST. Everything else is left to PVE.
var requiredKeysByType = map[string][]string{
	"zfspool": {"pool"},
}

// StorageCreate is the idempotent-mutation-engine's Op for `storage create`
// (pveforge-storage-create-command): ensure a storage named Name exists with
// the definition in Params, creating it if absent, no-op if it already matches,
// and REFUSING (never silently converging) if it exists with a differing
// definition.
//
// Params is the caller-validated, already form-shaped set of raw PVE create
// parameters (type, pool, content, nodes, ...) INCLUDING type — mirroring
// VMCreate.Params' raw/schema-free precedent (PRD §3.3). The storage name is
// held separately and stamped as storage=<name> by CreateStorage, exactly as
// CreateVM stamps vmid.
//
// Stricter than VMCreate two ways, by design:
//   - Read maps ONLY an authoritative not-found to "absent"; any other read
//     error propagates, because the differ-refusal below depends on a
//     trustworthy read (VMCreate can be laxer — its create call is its own
//     authoritative existence check).
//   - Satisfied requires the definition to MATCH, not merely exist: a storage
//     of the same name but a different type/content is a real misconfiguration
//     to surface, not a silent no-op.
//
// Drift: absent -> create; present+matching -> no-op; present+differing ->
// StorageDiffersError (refuse-and-report, NO POST). --force (idempotent.Run's
// force) bypasses the no-op check only — it re-POSTs a present+matching storage
// (PVE then refuses the duplicate, fail-closed) but STILL refuses a differing
// one rather than converging; convergence is a future `storage set` on
// PUT /storage/{id} with its own digest-CAS.
//
// Cluster-wide caveat (not a v1 blocker): storage.cfg is cluster-wide, but
// idempotent.Run's lock (keyed on this target id) serializes only pveforge
// processes sharing one roster file against the same key. Two runs against two
// nodes of the SAME cluster use different target ids and are not serialized
// against each other; the TOCTOU between Read and Apply fails CLOSED anyway —
// POST /storage refuses a duplicate id with PVE's "storage ID already defined"
// verbatim, never a silent overwrite.
//
// v1 drift-detection limitation (documented, honest): the read-back
// (proxmox.ClusterStorage) does not model every PVE storage key — notably
// `pool` for a zfspool — so a desired key the read-back does not carry is not
// drift-checked (Satisfied skips it). The required-keys guard still forces
// `pool` to be PRESENT on create; a FUTURE raw read-back (or a go-proxmox
// field) is owed to drift-check it. The modeled fields (type, content, nodes,
// shared, thinpool, vgname, path) ARE drift-checked today.
type StorageCreate struct {
	Client StorageCreateClient
	Name   string
	Params url.Values

	// current is what Read observed, captured so Apply can tell absent from
	// present+differing without a second read (Run calls Read then Apply on
	// the same Op value).
	current string
}

// StorageDiffersError is Apply's refusal when the storage already exists with a
// definition that differs from what was asked. It names the desired and actual
// definitions so the operator sees the diff and the next step, and NO POST is
// made. --force does not override it (see StorageCreate's doc comment).
type StorageDiffersError struct {
	Name    string
	Desired url.Values
	Actual  string
}

func (e *StorageDiffersError) Error() string {
	return fmt.Sprintf("storage create: storage %q already exists with a differing definition; refusing to change it (a future `storage set` converges one deliberately). desired {%s}; actual %s", e.Name, encodeDesired(e.Desired), e.Actual)
}

// encodeDesired renders the desired params in a stable, storage=-free order
// for the diff message (storage is the name, not part of the definition).
func encodeDesired(params url.Values) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "storage" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+params.Get(k))
	}
	return strings.Join(parts, " ")
}

// Validate reports whether the Op is well-formed BEFORE any POST: a name and a
// type are required, and every required key for that type (requiredKeysByType)
// must be present. Exported and standalone — NOT inlined into Apply — for the
// same reason VMCreate.Validate is: idempotent.Run calls Satisfied before Apply
// and skips Apply entirely on the already-satisfied path, so a caller that
// wants the guard enforced even then (cmd/pveforge's `storage create` does)
// calls Validate itself ahead of the Read/Satisfied/Apply cycle.
func (op *StorageCreate) Validate() error {
	if op.Name == "" {
		return fmt.Errorf("storage create: a storage name is required")
	}
	typ := op.Params.Get("type")
	if typ == "" {
		return fmt.Errorf("storage create: storage %q: a storage type is required (--type)", op.Name)
	}
	for _, key := range requiredKeysByType[typ] {
		if op.Params.Get(key) == "" {
			return fmt.Errorf("storage create: storage %q: type %q requires %s to be set (e.g. --data %s=<value>)", op.Name, typ, key, key)
		}
	}
	return nil
}

// Read reports the storage's current cluster-wide config as a comparable
// string, or "" if it does not exist. Unlike VMCreate.Read (which maps ANY
// read error to absent), this maps ONLY PVE's authoritative "No such storage."
// to "" (pve.IsStorageNotFoundError) and propagates every other error: the
// differ-refusal in Apply/Satisfied must not fire against a read it could not
// trust.
func (op *StorageCreate) Read(ctx context.Context) (string, error) {
	cfg, err := op.Client.GetStorageConfig(ctx, op.Name)
	if err != nil {
		if pve.IsStorageNotFoundError(err) {
			op.current = ""
			return "", nil
		}
		return "", fmt.Errorf("storage create: storage %q: read current config: %w", op.Name, err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("storage create: storage %q: encode current state: %w", op.Name, err)
	}
	op.current = string(b)
	return op.current, nil
}

// Satisfied reports whether the storage already exists AND every desired param
// the read-back models matches it — the stricter contract this Op owns (a
// same-name storage of a different definition is NOT satisfied). An absent
// storage, or an unreadable current, is not satisfied.
func (op *StorageCreate) Satisfied(current string) bool {
	if current == "" {
		return false
	}
	return op.matches(current)
}

// matches reports whether every desired param (bar the name and digest)
// equals the read-back's value for that key, compared case-insensitively on
// the key (the read-back marshals Go-cased field names: Type, Content, ...).
// A desired key the read-back does not carry is NOT compared — it cannot be
// confirmed, so it is neither a match nor a mismatch (the documented v1
// limitation; `pool` is the case). Fails closed on an unparseable current.
func (op *StorageCreate) matches(current string) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(current), &raw); err != nil {
		return false
	}
	actual := make(map[string]string, len(raw))
	for k, v := range raw {
		actual[strings.ToLower(k)] = jsonScalar(v)
	}
	for key := range op.Params {
		lk := strings.ToLower(key)
		if lk == "storage" || lk == "digest" {
			continue
		}
		got, present := actual[lk]
		if !present {
			continue // not modeled by the read-back; cannot confirm drift (v1)
		}
		if got != op.Params.Get(key) {
			return false
		}
	}
	return true
}

// jsonScalar renders a scalar JSON value as the plain string to compare
// against a desired param value: a JSON string unquoted, anything else (a
// number like Shared's 0/1) as its raw text.
func jsonScalar(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// Apply creates the storage — but first validates (see Validate) and refuses a
// present+differing definition with StorageDiffersError and NO POST. Reached
// when the storage is absent, present+differing, or (via force) present. The
// present vs absent decision reuses what Read captured, so Apply makes no extra
// read.
//
// POST /storage is synchronous: PVE returns the created config object, so there
// is normally no task to wait on. Decoded defensively — if PVE ever answers
// with a bare UPID scalar instead, the task is waited on (NOT live-verified;
// correct either way).
func (op *StorageCreate) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	if op.current != "" && !op.matches(op.current) {
		return &StorageDiffersError{Name: op.Name, Desired: op.Params, Actual: op.current}
	}

	raw, err := op.Client.CreateStorage(ctx, op.Name, op.Params)
	if err != nil {
		return fmt.Errorf("storage create: storage %q: %w", op.Name, err)
	}

	if upid, ok := upidIfScalar(raw); ok {
		if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
			return fmt.Errorf("storage create: storage %q: %w", op.Name, err)
		}
	}
	return nil
}

// upidIfScalar reports whether raw — CreateStorage's already-unwrapped
// response — is a bare PVE task-id scalar ("UPID:..."). POST /storage is
// synchronous and answers with the created config OBJECT, so this is normally
// false and no wait is needed; an object, number, or null is not a UPID. The
// defensive path for a PVE version that ever answers with a bare UPID.
func upidIfScalar(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	if !strings.HasPrefix(s, "UPID:") {
		return "", false
	}
	return s, true
}
