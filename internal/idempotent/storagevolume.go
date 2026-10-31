package idempotent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// StorageVolumeClient is the subset of *pve.RoutedClient both storage-volume
// Ops need: a raw REST call, the storage content listing (alloc's read-back and
// existence check), the task poller (the free's async DELETE), and the node
// name. *pve.RoutedClient satisfies it structurally (see compat_test.go) — no
// new RoutedClient method, so no routedClientSeam entry. EffectivePermissions/
// PathPermissions are DELIBERATELY ABSENT: the superseded C3 token gate;
// completeness now comes from the root VM list injected into VolumeFreeOrphans.
type StorageVolumeClient interface {
	Node() string
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	GetStorageVolumes(ctx context.Context, node, storage string) ([]*proxmox.StorageContent, error)
	// GetStorage is read by VolumeFreeOrphans.Read's defense-in-depth selector
	// guard (F1): a node-scoped CompleteVMIDs free must refuse a shared storage
	// in the Op itself, not rely on a downstream refuseIfShared or on the CLI.
	GetStorage(ctx context.Context, node, name string) (*proxmox.Storage, error)
	WaitForTask(ctx context.Context, node, upid string) error
}

// StorageOrphanScanner is the destructive-safe orphan determination the free
// consumes. *pve.RoutedClient satisfies it structurally. It has TWO methods so
// the free can scan either a single node's claimed set OR the cluster-wide one,
// and the cluster-wide method is DELIBERATELY NOT satisfiable by the node-
// scoped one (U-CWCV §3):
//   - OrphanVolumesForVMIDWithVMList: node-scoped, from a complete root VMID
//     list for THIS node (landed as Unit 2). Refuses shared storage.
//   - OrphanVolumesClusterForVMID: cluster-wide, from a node-carrying pair list
//     (pve.ClusterQemuPairs). The ONLY path that may free on shared storage,
//     because only a cross-node claimed set can see a disk a VM on another node
//     claims. VolumeFreeOrphans picks it when ClusterGuests is set.
type StorageOrphanScanner interface {
	OrphanVolumesForVMIDWithVMList(ctx context.Context, node, storage string, vmid int, completeVMIDs []int) ([]*proxmox.StorageContent, error)
	OrphanVolumesClusterForVMID(ctx context.Context, node, storage string, vmid int, clusterGuests []pve.NodeVMID) ([]*proxmox.StorageContent, error)
}

// decodeScalarString decodes a PVE response that must be a non-empty JSON
// string — a volid (alloc) or a UPID (free). It copies pve.decodeUPIDScalar's
// discipline (that function is unexported and in package pve, so it is copied,
// not called) and ADDS an empty-"" refusal, so the alloc and free siblings
// share one discipline and cannot diverge: both reject null, a non-string, and
// "". (WaitForTask also refuses an empty UPID; this is the primary check, that
// a defense-in-depth backstop.) `what` words the error ("volid" / "upid").
func decodeScalarString(raw json.RawMessage, what string) (string, error) {
	if string(bytes.TrimSpace(raw)) == "null" {
		return "", fmt.Errorf("decode %s: unexpected response %s: expected a %s string, got null", what, raw, what)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("decode %s: unexpected response %s: %w", what, raw, err)
	}
	if s == "" {
		return "", fmt.Errorf("decode %s: unexpected response %s: expected a non-empty %s string, got \"\"", what, raw, what)
	}
	return s, nil
}

// volidBasename is the volume's name without its storage prefix and without
// any directory component: the part after the last '/', else after the first
// ':'. It makes the alloc existence check form-aware (see VolumeAllocEnsure.Read).
func volidBasename(volid string) string {
	rest := volid
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}

// VolumeAllocEnsure ensures a convention-named raw volume exists on Storage —
// the create half of "pvesm alloc for volumes outside qm's own disk schema"
// (quantum-ng's raw NVMe boot volumes). Idempotent by construction: Filename is
// a caller-supplied deterministic name, so Read recognizes an already-allocated
// volume with NO persisted pveforge-side state.
type VolumeAllocEnsure struct {
	Client   StorageVolumeClient
	Storage  string
	Filename string // required, deterministic — e.g. "vm-105-disk-0"
	Size     string // e.g. "32G" — PVE's size grammar, unvalidated here
	VMID     int
	Format   string // optional; PVE infers from storage type when empty

	// volid is set by Read/Apply to the EXACT volid PVE holds for this volume
	// ("<storage>:vm-105-disk-0" on lvmthin/ZFS, "<storage>:105/vm-105-disk-0"
	// on directory storage), else "".
	volid string
}

// Validate rejects a malformed request before any network call.
func (op *VolumeAllocEnsure) Validate() error {
	switch {
	case op.Storage == "":
		return fmt.Errorf("storage alloc: storage is required")
	case op.Filename == "":
		return fmt.Errorf("storage alloc: filename is required")
	case op.Size == "":
		return fmt.Errorf("storage alloc: size is required")
	case op.VMID < 1:
		return fmt.Errorf("storage alloc: vmid must be a positive integer, got %d", op.VMID)
	}
	return nil
}

// Read recognizes an already-allocated volume by matching Filename against the
// volid BASENAME together with VMID — the accepted v3-N2 binding. It is
// deliberately NOT a "<storage>:<filename>" PREFIX match: that would MISS the
// directory-storage form, whose volid is "<storage>:<vmid>/<name>" (e.g.
// local:106/vm-105-disk-0.raw binds to VM 105 by its <vmid>/ + basename). A
// later edit must not "fix" this into a prefix match.
func (op *VolumeAllocEnsure) Read(ctx context.Context) (string, error) {
	node := op.Client.Node()
	vols, err := op.Client.GetStorageVolumes(ctx, node, op.Storage)
	if err != nil {
		return "", fmt.Errorf("storage alloc: read volumes on %q/%q: %w", node, op.Storage, err)
	}
	op.volid = ""
	for _, v := range vols {
		if v == nil {
			continue
		}
		if v.VMID == uint64(op.VMID) && volidBasename(v.Volid) == op.Filename {
			op.volid = v.Volid
			break
		}
	}
	return op.volid, nil
}

// Satisfied: the volume already exists (Read found its volid).
func (op *VolumeAllocEnsure) Satisfied(current string) bool { return current != "" }

// Apply POSTs the alloc (synchronous — no WaitForTask) and verifies with a
// DUAL signal: a strict decode of the volid the POST RETURNED (reject
// null/non-string/empty), then that EXACT returned volid must be listed by
// GetStorageVolumes. It compares the RETURNED volid, never a predicted
// "<storage>:<filename>" (wrong for directory storage).
func (op *VolumeAllocEnsure) Apply(ctx context.Context) error {
	node := op.Client.Node()
	params := url.Values{}
	params.Set("filename", op.Filename)
	params.Set("size", op.Size)
	params.Set("vmid", strconv.Itoa(op.VMID))
	if op.Format != "" {
		params.Set("format", op.Format)
	}
	raw, err := op.Client.RawRequest(ctx, http.MethodPost,
		fmt.Sprintf("/nodes/%s/storage/%s/content", url.PathEscape(node), url.PathEscape(op.Storage)), params)
	if err != nil {
		return fmt.Errorf("storage alloc: allocate %q on %q/%q: %w", op.Filename, node, op.Storage, err)
	}
	returned, err := decodeScalarString(raw, "volid")
	if err != nil {
		return fmt.Errorf("storage alloc: allocate %q on %q/%q: %w", op.Filename, node, op.Storage, err)
	}
	// Second signal: the volid the POST returned must now be listed.
	vols, err := op.Client.GetStorageVolumes(ctx, node, op.Storage)
	if err != nil {
		return fmt.Errorf("storage alloc: read-back %q on %q/%q: %w", returned, node, op.Storage, err)
	}
	for _, v := range vols {
		if v != nil && v.Volid == returned {
			op.volid = returned
			return nil
		}
	}
	return fmt.Errorf("storage alloc: the POST for %q returned volid %q but GetStorageVolumes does not list it (second signal failed)", op.Filename, returned)
}

// Volid is the volid Read/Apply settled on, for the CLI to report. "" before a
// successful Read/Apply.
func (op *VolumeAllocEnsure) Volid() string { return op.volid }

// freeDeleteTimeout bounds the per-volume DELETE call, DELIBERATELY TIGHTER
// than pve.TaskWaitCeiling (10m), so a stuck DELETE that never returns a UPID
// cannot hold the storage lock for the full task ceiling. It bounds ONLY the
// DELETE, not the WaitForTask: the module-wide TestTaskWaitsUseTheCallersContext
// guard requires WaitForTask be given the caller's OWN ctx directly (that is how
// the command's task-warnings reporter reaches it), so the wait leg cannot take
// a tighter child context and self-bounds at pve.TaskWaitCeiling (10m) instead.
// The per-volume worst case is therefore freeDeleteTimeout + up to 10m, and the
// N-orphan lock-hold is N × that. A var so tests can shorten it.
var freeDeleteTimeout = 3 * time.Minute

// VolumeFreeOrphans frees every volume on Storage matching VMID's naming
// convention that the destructive-safe orphan determination reports unclaimed —
// the destroy-time reconciliation half. Sequential, stop-at-first-failure.
//
// PRECONDITION on CompleteVMIDs (this field is EXPORTED — a caller building the
// Op directly must honor it): CompleteVMIDs MUST be a QUORUM-VERIFIED, root-
// sourced NodeVMIDs list for THIS node. The Op does NOT re-check quorum and
// does NOT re-verify completeness — the CLI (`storage free-orphans`) establishes
// both (bootstrap.RootAccess.NodeVMIDs + ClusterStatusQuorate) BEFORE building
// the Op. quorum is NECESSARY, NOT SUFFICIENT: a node that just regained quorum
// or is receiving a migration may still serve a stale list for a replication
// window no API read closes, so EVERY caller of this Op (the standalone CLI
// AND any future vm-destroy reconciliation that builds it) inherits the
// replication-lag precondition + warning. Building this Op with a token GetVMs
// list, an unverified list, or a list from a non-quorate node frees live VMs'
// disks.
type VolumeFreeOrphans struct {
	Client        StorageVolumeClient
	Scanner       StorageOrphanScanner
	Storage       string
	VMID          int
	CompleteVMIDs []int

	// ClusterPairs, when non-nil, routes Read onto the CLUSTER-WIDE scanner
	// (OrphanVolumesClusterForVMID) instead of the node-scoped
	// OrphanVolumesForVMIDWithVMList — the ONLY safe path on SHARED storage
	// (U-CWCV §3/§5). It carries node (pve.NodeVMID) because the cluster claimed
	// set is a union over (node, vmid) PAIRS, which a nodeless CompleteVMIDs
	// cannot express. The CLI builds it with pve.ClusterQemuPairs under the same
	// quorum gate + warning as CompleteVMIDs, and only after the §2 proxy proof.
	// A nil slice keeps the node-scoped path; set exactly one of ClusterPairs /
	// CompleteVMIDs for a given free. (Named ClusterPairs, not ClusterGuests, so
	// it does not collide with bootstrap.RootAccess.ClusterGuests in the
	// root-writer source guard.)
	ClusterPairs []pve.NodeVMID

	// Applied is the volids actually freed, in order, each appended ONLY after
	// its WaitForTask returned nil — never reconstructed from a before/after
	// diff, the VMFieldsEnsure.Applied discipline. This Op never returns
	// ErrConflict (nothing here is digest-CAS), so Run never retries Apply and
	// Applied cannot double-report.
	Applied []string

	orphans []*proxmox.StorageContent // Read's snapshot, in U2's sorted-by-volid order
}

// Read takes a snapshot of the orphans to free. It PROPAGATES any scanner error
// (a token config-refusal wrapped as ErrNotAuthorized, an ErrUnverifiableRead,
// a shared-storage refusal) — it NEVER maps a failed/short listing to "[]",
// which would let Satisfied short-circuit a determination that should refuse.
func (op *VolumeFreeOrphans) Read(ctx context.Context) (string, error) {
	node := op.Client.Node()

	// F1 defense-in-depth: the destructive selector is enforced in the Op, not
	// only in cmd/pveforge/storage.go, so a FUTURE caller that builds the Op
	// directly cannot free cross-node disks.
	//
	// (a) EXACTLY ONE of ClusterPairs / CompleteVMIDs must be set. Both-set is
	// ambiguous; neither-set would scan a nil node-scoped list. Fail closed.
	clusterSel := op.ClusterPairs != nil
	nodeSel := op.CompleteVMIDs != nil
	if clusterSel == nodeSel {
		return "", fmt.Errorf("storage free-orphans: vmid %d on %q/%q: %w: exactly one of ClusterPairs (shared, cluster-wide) or CompleteVMIDs (node-scoped) must be set, not both and not neither", op.VMID, node, op.Storage, pve.ErrUnverifiableRead)
	}
	// (b) A node-scoped CompleteVMIDs free must refuse a SHARED storage in the
	// Op itself: a node-scoped claimed set cannot see a disk a VM on another
	// node claims, so it must error here rather than scan (even though the
	// node-scoped scanner also refuses shared downstream — two guards).
	if nodeSel {
		stg, gerr := op.Client.GetStorage(ctx, node, op.Storage)
		if gerr != nil {
			return "", fmt.Errorf("storage free-orphans: vmid %d on %q/%q: read storage for the shared-selector guard: %w", op.VMID, node, op.Storage, gerr)
		}
		if stg.Shared != 0 {
			return "", fmt.Errorf("storage free-orphans: vmid %d on %q/%q: %w: storage is shared but the free was built with a node-scoped CompleteVMIDs; a cluster-wide ClusterPairs is required to free shared storage safely", op.VMID, node, op.Storage, pve.ErrUnverifiableRead)
		}
	}

	// Cluster-wide claimed set when ClusterPairs is set (shared storage, §3);
	// otherwise the node-scoped list. The cluster method is NOT satisfiable by
	// the node-scoped one — reverting this to the node-scoped scanner on shared
	// storage would free a disk a VM on another node claims.
	var orphans []*proxmox.StorageContent
	var err error
	if op.ClusterPairs != nil {
		orphans, err = op.Scanner.OrphanVolumesClusterForVMID(ctx, node, op.Storage, op.VMID, op.ClusterPairs)
	} else {
		orphans, err = op.Scanner.OrphanVolumesForVMIDWithVMList(ctx, node, op.Storage, op.VMID, op.CompleteVMIDs)
	}
	if err != nil {
		return "", fmt.Errorf("storage free-orphans: determine orphans for vmid %d on %q/%q: %w", op.VMID, node, op.Storage, err)
	}
	op.orphans = orphans
	volids := make([]string, 0, len(orphans))
	for _, o := range orphans {
		if o != nil {
			volids = append(volids, o.Volid)
		}
	}
	b, err := json.Marshal(volids)
	if err != nil {
		return "", fmt.Errorf("storage free-orphans: render orphan list: %w", err)
	}
	return string(b), nil
}

// Satisfied: nothing to free.
func (op *VolumeFreeOrphans) Satisfied(current string) bool { return current == "[]" }

// Apply frees each orphan in Read's snapshot, in sorted order, sequentially:
// DELETE (no `delay`) -> strict UPID decode -> WaitForTask -> record Applied ->
// next. Each per-volume op runs under its own bounded child context
// (the DELETE under freeDeleteTimeout; the wait self-bounds at 10m). Stop at
// first failure: a DELETE or WaitForTask error
// aborts Apply, leaves the remaining volumes untouched, and Applied reports
// exactly what was freed. Never returns ErrConflict.
func (op *VolumeFreeOrphans) Apply(ctx context.Context) error {
	node := op.Client.Node()
	for _, o := range op.orphans {
		if o == nil {
			continue
		}
		if err := op.freeOne(ctx, node, o.Volid); err != nil {
			return fmt.Errorf("storage free-orphans: free %q: %w", o.Volid, err)
		}
		op.Applied = appendOnce(op.Applied, o.Volid)
	}
	return nil
}

func (op *VolumeFreeOrphans) freeOne(ctx context.Context, node, volid string) error {
	// Bound the DELETE with a child context tighter than WaitForTask's 10m
	// ceiling, so a stuck DELETE that never returns a UPID cannot hold the
	// storage lock. No `delay`: PVE returns the UPID when delay is absent, so a
	// null body is a refusal (decodeScalarString rejects it), never a delayed
	// success.
	delCtx, cancel := context.WithTimeout(ctx, freeDeleteTimeout)
	raw, err := op.Client.RawRequest(delCtx, http.MethodDelete,
		fmt.Sprintf("/nodes/%s/storage/%s/content/%s", url.PathEscape(node), url.PathEscape(op.Storage), url.PathEscape(volid)), nil)
	cancel()
	if err != nil {
		return err
	}
	upid, err := decodeScalarString(raw, "upid")
	if err != nil {
		return err
	}
	// WaitForTask gets the caller's OWN ctx directly (the
	// TestTaskWaitsUseTheCallersContext guard: the command's task-warnings
	// reporter rides it); it self-bounds at pve.TaskWaitCeiling (10m).
	return op.Client.WaitForTask(ctx, node, upid)
}
