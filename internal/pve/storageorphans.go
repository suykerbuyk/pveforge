package pve

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// claimableContentTypes are the PVE storage "content" classifications that
// can ever legitimately appear as a volid claimed by a live qemu VM's
// config slot: real disk images, and ISO images (referenceable as cdrom
// media, e.g. "local:iso/x.iso,media=cdrom"). Backups, container templates,
// LXC rootdirs, and snippets are structurally never claimed this way — a
// vzdump backup or a vztmpl template never appears in any qm config disk
// slot, by design, not by leak — so OrphanVolumes excludes them from its
// actual-side candidates entirely rather than flagging every one of them
// as an orphan on every run. See storageContentEntry's doc comment for why
// this classification has to be recovered by hand.
var claimableContentTypes = map[string]bool{
	"images": true,
	"iso":    true,
}

// storageContentEntry augments go-proxmox's own proxmox.StorageContent with
// the one field its struct definition drops on the floor: PVE's per-entry
// "content" classification (images/iso/vztmpl/backup/rootdir/snippets).
// proxmox.StorageContent (go-proxmox@v0.8.1/types.go) has no field for it
// at all — confirmed by grepping the whole vendored source for a `content`
// JSON tag on that struct; there is none — so encoding/json silently drops
// it on decode (unknown-field decoding is a no-op, not an error). The
// anonymous embed lets one JSON decode populate both the existing
// StorageContent fields (Volid, VMID, ...) and this added one:
// encoding/json promotes fields from an embedded pointer, allocating it
// lazily the first time a promoted field needs to be set.
type storageContentEntry struct {
	*proxmox.StorageContent
	Content string `json:"content,omitempty"`
}

// storageContentWithType fetches node/storage's content listing — the same
// GET /nodes/{node}/storage/{storage}/content endpoint GetStorageVolumes
// uses — but decoded into storageContentEntry so the per-entry content
// classification survives the round trip. GetStorageVolumes itself is left
// untouched (its existing callers don't need this field); this is a
// separate, package-private read used only by OrphanVolumes.
func (c *Client) storageContentWithType(ctx context.Context, node, storage string) ([]*storageContentEntry, error) {
	var raw []*storageContentEntry
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/storage/%s/content", url.PathEscape(node), url.PathEscape(storage)), &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("storage %q on %q: %w: content list payload was null", storage, node, ErrUnverifiableRead)
	}
	return raw, nil
}

// ClaimedVolumes returns the set of PVE volids vmid's OWN config
// currently references — every indexed disk-shaped slot (ide*, scsi*,
// sata*, virtio*, unused*) plus efidisk0/tpmstate0 — parsed from
// VirtualMachineConfig via GetVM. A slot holding "none" or a non-storage
// device (e.g. a physical-passthrough spec with no leading volid) is
// simply absent from the returned set; this function does no PVE-side
// existence checking of its own.
//
// Locking: the caller must hold lock.Read or lock.Mutation on this
// storage's ObjectKey for the duration of this call; ClaimedVolumes does
// not lock anything itself.
//
// Trust precondition: the result is only as complete as the target's PVE
// API token's own view permissions. A token scoped to see fewer VMs than
// actually exist yields an INCOMPLETE claimed set with NO error and NO
// signal that anything was scoped down — PVE returns a plain 200 with a
// shorter list, and nothing in this function (or its caller) can detect
// that after the fact. The target's token needs full node-scoped audit
// rights (VM.Audit at minimum) for the result to be trustworthy.
//
// Unverified against a real host: whether a linked clone's own disk-slot
// volid, taken verbatim from qm config, is byte-identical to the Volid
// PVE's /content listing reports for the same underlying storage object,
// on every storage backend PVE supports — proxmox.StorageContent.Parent
// exists specifically to carry a linked clone's base-volume relationship,
// and this function does not consult it at all. See vault task
// pveforge-storage-orphan-scan's "Unverified assumptions" section before
// trusting this for destroy-time reconciliation in any environment using
// linked clones.
func (c *Client) ClaimedVolumes(ctx context.Context, node string, vmid int) (map[string]bool, error) {
	if node == "" {
		return nil, fmt.Errorf("claimed volumes for vmid %d: node is required", vmid)
	}

	vm, err := c.GetVM(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("claimed volumes for vmid %d: %w", vmid, err)
	}

	claimed := make(map[string]bool)
	// GetVM already refuses a nil config; kept as a second line of defence,
	// because an empty claimed set here would report every one of this VM's
	// disks as an orphan.
	cfg := vm.VirtualMachineConfig
	if cfg == nil {
		return nil, fmt.Errorf("claimed volumes for vmid %d: %w: config payload was null", vmid, ErrUnverifiableRead)
	}

	add := func(slotValue string) {
		volid := slotValue
		if idx := strings.IndexByte(slotValue, ','); idx >= 0 {
			volid = slotValue[:idx]
		}
		// A genuine PVE volid is always "<storage>:<name>". A slot holding
		// "none" (empty removable media), a bare scalar, or a raw device
		// path for physical passthrough (e.g. "/dev/sdb") has no colon and
		// is not a storage-resident volume this scan tracks.
		//
		// UNVERIFIED against a real host: whether a linked clone's own
		// disk-slot volid, taken verbatim from qm config, is byte-identical
		// to the Volid PVE's /content listing reports for that same
		// underlying storage object, on every storage backend PVE
		// supports — proxmox.StorageContent.Parent exists specifically to
		// carry a linked clone's base-volume relationship, and this parser
		// does not consult it at all. See vault task
		// pveforge-storage-orphan-scan's "Unverified assumptions" section.
		// Must be checked against a real PVE host running an actual linked
		// qm clone before this function's output is trusted for
		// destroy-time reconciliation in any environment using linked
		// clones.
		if !strings.Contains(volid, ":") {
			return
		}
		claimed[volid] = true
	}

	// Volume-bearing config keys come from TWO different shapes on
	// VirtualMachineConfig, both handled below: the indexed device maps
	// (this loop) AND the two plain scalar fields after it (EFIDisk0,
	// TPMState0 — a UEFI VM's NVRAM store and a vTPM's state volume,
	// neither part of any indexed map). Reason about both when extending
	// this function; the indexed-map frame below is not the whole claimed
	// surface on its own.
	//
	// This list is exactly the 5 of go-proxmox's 12 indexed device
	// maps (types.go:1088-1099) that ever carry a volid — confirmed by
	// direct source inspection: Nets, Numas, HostPCIs, Serials, USBs,
	// Parallels, and IPConfigs are all real indexed maps too, but none of
	// their values are ever a storage-resident volume. This is a MANUAL
	// enumeration, not derived from go-proxmox's own routing table
	// (indexedDeviceMaps(), types.go:1128) — that method is unexported and
	// unreachable from this package. It is NOT automatically kept in sync
	// with a future go-proxmox release: if a vendored upgrade ever adds a
	// new disk-bearing indexed map, this list must be updated by hand or a
	// claimed volume in that new slot silently reads as unclaimed here —
	// which the downstream OrphanVolumes/VolumeFreeOrphans consumer would
	// then free. TestClaimedVolumes_OnlyDiskBearingIndexedMapsContribute
	// pins this exact 5-map set (and the 7-map exclusion) as a named,
	// walkable list — re-verify it against go-proxmox's own
	// indexedDeviceMaps() on every vendored version bump.
	for _, slots := range []map[string]string{cfg.IDEs, cfg.SCSIs, cfg.SATAs, cfg.VirtIOs, cfg.Unuseds} {
		for _, v := range slots {
			add(v)
		}
	}
	// Both scalars are pinned by TestClaimedVolumes_ParsesEveryDiskShapedSlotAndScalar
	// (deleting either add() call here fails that test) — dropping either
	// would report a live VM's EFI or TPM volume as an orphan, and
	// OrphanVolumes/VolumeFreeOrphans would free it, leaving a VM that no
	// longer boots.
	add(cfg.EFIDisk0)
	add(cfg.TPMState0)

	return claimed, nil
}

// OrphanVolumes returns every volume node/storage's own content listing
// reports that is NOT claimed by any VM's config on that node — GetVMs +
// ClaimedVolumes per vmid, unioned, then set-differenced against the
// storage's content (restricted to claimableContentTypes). Sorted by Volid
// for deterministic output — this function's OWN output ordering, not
// reliance on PVE's, is what closes the epic's cited /storage
// field-ordering non-determinism.
//
// Locking: the caller must hold lock.Read or lock.Mutation on this
// storage's ObjectKey for the duration of this call; OrphanVolumes does
// not lock anything itself.
//
// Trust precondition: see ClaimedVolumes — this function inherits GetVMs'
// and ClaimedVolumes' exposure to permission-scoped short lists. A token
// missing view rights on even one VM makes every volume that VM
// legitimately owns look orphaned, silently, with no error anywhere in
// this call. Requires a full node-scoped audit-rights token; do not call
// this with a narrowly-scoped token and trust the result for a
// destructive follow-up action.
//
// Shared-storage refusal: a shared storage's content listing reflects
// volumes claimed by VMs on OTHER cluster nodes too, invisible to this
// function's node-scoped claimed set (GetVMs/ClaimedVolumes only ever see
// node's own VMs — RoutedClient is bound to a single roster.Target.Node).
// Unlike the permission-scoping hazard above, shared-ness IS cheaply
// detectable — proxmox.Storage.Shared is a real, already-fetchable field —
// so this function fails closed instead of documenting around it: it
// refuses outright rather than return a diff it knows may be wrong.
// Cluster-wide claimed-set support (Cluster.Resources for cross-node
// VMIDs, plus per-node config reads) is a real, achievable follow-on, not
// attempted in this function — it needs RoutedClient to route across
// nodes, which is a routing change, not a few lines here.
//
// Unverified against a real host: this function's diff quality inherits
// ClaimedVolumes' linked-clone caveat unchanged — see that function's own
// doc comment and vault task pveforge-storage-orphan-scan's "Unverified
// assumptions" section.
func (c *Client) OrphanVolumes(ctx context.Context, node, storage string) ([]*proxmox.StorageContent, error) {
	if node == "" || storage == "" {
		return nil, fmt.Errorf("orphan volumes: node and storage are required")
	}

	stg, err := c.GetStorage(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: get storage %q on %q: %w", storage, node, err)
	}
	if stg.Shared != 0 {
		return nil, fmt.Errorf("orphan volumes: storage %q on %q is shared (shared=1): the claimed set this function builds is scoped to node %q alone and cannot see volumes claimed by VMs on other cluster nodes — refusing rather than returning a diff that may falsely report volumes in active use elsewhere as orphaned", storage, node, node)
	}

	actual, err := c.storageContentWithType(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: get storage content on %q/%q: %w", node, storage, err)
	}

	vms, err := c.GetVMs(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: list vms on %q: %w", node, err)
	}

	claimed := make(map[string]bool)
	for _, vm := range vms {
		vmClaimed, err := c.ClaimedVolumes(ctx, node, int(vm.VMID))
		if err != nil {
			return nil, fmt.Errorf("orphan volumes: %w", err)
		}
		for volid := range vmClaimed {
			claimed[volid] = true
		}
	}

	var orphans []*proxmox.StorageContent
	for _, entry := range actual {
		if entry.StorageContent == nil || !claimableContentTypes[entry.Content] {
			continue
		}
		if claimed[entry.Volid] {
			continue
		}
		orphans = append(orphans, entry.StorageContent)
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Volid < orphans[j].Volid })

	return orphans, nil
}

// OrphanVolumesForVMID narrows OrphanVolumes to volids matching vmid's own
// naming convention ("<storage>:vm-<vmid>-*") — pveforge-storage-volume-
// tracking's VolumeFreeOrphans calls this directly. In the destroy-time
// case the owning VM's config no longer exists at all, so every matching
// volume is unclaimed by construction (GetVMs simply won't list a
// destroyed vmid — ClaimedVolumes for it is never consulted).
//
// Locking: the caller must hold lock.Read or lock.Mutation on this
// storage's ObjectKey for the duration of this call; OrphanVolumesForVMID
// does not lock anything itself.
//
// Trust precondition: inherited unchanged from OrphanVolumes, which this
// function delegates to entirely (including its shared-storage refusal
// and permission-scoping exposure). This matters more here than anywhere
// else in this file: pveforge-storage-volume-tracking's VolumeFreeOrphans
// calls this to decide what to DELETE. A permission-scoped short claimed
// set does not just mis-report — it frees a volume that is still in
// active use. See vault task pveforge-storage-orphan-scan's "Unverified
// assumptions" section.
//
// Unverified against a real host, and the MORE DANGEROUS direction of
// the two flagged on this file: this function also inherits
// ClaimedVolumes' unverified linked-clone volid-identity assumption. If a
// linked clone's own disk-slot volid does not match the Volid its base
// image reports on some storage backend, a base image still backing a
// live clone could be misread as unclaimed and handed to
// VolumeFreeOrphans for deletion. Do not trust this function's output for
// destroy-time reconciliation in any environment using linked clones
// until that assumption is checked against a real PVE host.
func (c *Client) OrphanVolumesForVMID(ctx context.Context, node, storage string, vmid int) ([]*proxmox.StorageContent, error) {
	orphans, err := c.OrphanVolumes(ctx, node, storage)
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("%s:vm-%d-", storage, vmid)
	var matched []*proxmox.StorageContent
	for _, o := range orphans {
		if strings.HasPrefix(o.Volid, prefix) {
			matched = append(matched, o)
		}
	}
	return matched, nil
}
