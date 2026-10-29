package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// firstCommaVolid parses a config slot value to the volid the claimed-set
// scan keeps: everything up to the first comma. A value with no colon is not
// a storage-resident volid and is returned as "" so a caller never treats
// "none"/"/dev/sdb" as one. Lifted (with allDigits/isDiskShapedKey and the
// configVolids reader) from the former harness-only snapshotSectionVolids so
// one reader and one parser serve both the production claimed-set path and
// the item-75 capture (pveforge-claimed-volumes-snapshot-vmstate, B2).
func firstCommaVolid(slotValue string) string {
	v := slotValue
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	if !strings.Contains(v, ":") {
		return ""
	}
	return v
}

// allDigits reports whether s is non-empty and all ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isDiskShapedKey reports whether a config/snapshot-section key is one the
// claimed-set scan walks: an indexed disk map (ide/scsi/sata/virtio/unused +
// N) or one of the two disk scalars. The reader restricts to these + "vmstate"
// so a freeform field (e.g. a "description" carrying a ':') never becomes a
// bogus volid.
//
// This recognizer is the SOLE decider of which config keys count as disks on
// the destroy path: if a future PVE/go-proxmox release adds a new disk-bearing
// key family this does not match, a volume in that new slot silently reads as
// UNCLAIMED and the destroy-time free deletes it. TestIsDiskShapedKey pins the
// current families and exclusions; re-verify it on every vendored bump.
func isDiskShapedKey(key string) bool {
	switch key {
	case "efidisk0", "tpmstate0":
		return true
	}
	for _, p := range []string{"ide", "scsi", "sata", "virtio", "unused"} {
		if rest, ok := strings.CutPrefix(key, p); ok && allDigits(rest) {
			return true
		}
	}
	return false
}

// configRead is the parsed result of one raw /config read — the live config
// or a frozen snapshot section. A NAMED STRUCT, not adjacent (vmstate, lock)
// strings: two same-type positional returns would let a swap compile and
// silently make the vmstate oracle never fire (finding 3.1). Fields are
// addressed by name at the call site.
type configRead struct {
	volids  []string // disk-shaped slot volids (and the vmstate volid when it is one)
	vmstate string   // the raw "vmstate" key value, or "" — the call-site oracle runs firstCommaVolid on it
	lock    string   // the "lock" key, or "" — present on a live config and possibly on a frozen snapshot section
}

// configVolids issues a RAW GET of a VM config endpoint (the live config, or a
// snapshot section when snapshot != "") and parses every disk-shaped value and
// any "vmstate" value with firstCommaVolid. It applies the two per-read
// fail-closed shape guards; the vmstate ORACLE (live lock, snapshot list
// Vmstate) is applied by the caller, which alone can see those signals:
//
//   - snapshot == "" (LIVE): require a "digest" key — a real config always
//     carries one (vms.go:35-41), so a 200 {"data":{}}/null read is refused.
//   - snapshot != "" (SNAPSHOT): require a non-empty decode — a frozen snapshot
//     config has no digest on PVE 9.x, so len(cfg)==0 is the empty-read signal.
//
// strict=true (the claimed-set/destroy path): a present disk-shaped-or-"vmstate"
// key whose value is not a JSON string is refused (ErrUnverifiableRead), never
// silently dropped — a dropped claim is a freed live volume. strict=false (the
// item-75 capture) keeps the lenient skip. No node parameter: RawRequest uses
// baseURL+path.
func (c *Client) configVolids(ctx context.Context, vmid int, snapshot, path string, params url.Values, strict bool) (configRead, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, path, params)
	if err != nil {
		return configRead{}, err
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cfg); err != nil {
		if snapshot == "" {
			return configRead{}, fmt.Errorf("config for vmid %d: %w: %w", vmid, ErrUnverifiableRead, err)
		}
		return configRead{}, fmt.Errorf("snapshot %q config for vmid %d: %w: %w", snapshot, vmid, ErrUnverifiableRead, err)
	}
	if snapshot == "" {
		if _, ok := cfg["digest"]; !ok {
			return configRead{}, fmt.Errorf("config for vmid %d: %w: config carries no digest", vmid, ErrUnverifiableRead)
		}
	} else if len(cfg) == 0 {
		return configRead{}, fmt.Errorf("snapshot %q config for vmid %d: %w: empty config decode", snapshot, vmid, ErrUnverifiableRead)
	}

	var out configRead
	for key, rawVal := range cfg {
		if key == "lock" {
			var s string
			if json.Unmarshal(rawVal, &s) != nil {
				// A present-but-non-string lock is unverifiable: the suspend
				// backstop reads lock, so silently dropping it would fail OPEN
				// (F2). Refuse on the strict/claimed path, same posture as a
				// non-string disk/vmstate value.
				if strict {
					if snapshot == "" {
						return configRead{}, fmt.Errorf("config for vmid %d: %w: key \"lock\" is present with a non-string value", vmid, ErrUnverifiableRead)
					}
					return configRead{}, fmt.Errorf("snapshot %q config for vmid %d: %w: key \"lock\" is present with a non-string value", snapshot, vmid, ErrUnverifiableRead)
				}
			} else {
				out.lock = s
			}
			continue
		}
		if !isDiskShapedKey(key) && key != "vmstate" {
			continue
		}
		var s string
		if json.Unmarshal(rawVal, &s) != nil {
			if strict {
				if snapshot == "" {
					return configRead{}, fmt.Errorf("config for vmid %d: %w: key %q is present with a non-string value", vmid, ErrUnverifiableRead, key)
				}
				return configRead{}, fmt.Errorf("snapshot %q config for vmid %d: %w: key %q is present with a non-string value", snapshot, vmid, ErrUnverifiableRead, key)
			}
			continue // non-string value (e.g. a nested object) — not a volid slot
		}
		if key == "vmstate" {
			out.vmstate = s
		}
		if v := firstCommaVolid(s); v != "" {
			out.volids = append(out.volids, v)
		}
	}
	sort.Strings(out.volids)
	return out, nil
}

// ClaimedVolumes returns the set of PVE volids vmid's config references across
// its LIVE config (pending ∪ current=1) and EVERY real snapshot section —
// every indexed disk-shaped slot (ide*, scsi*, sata*, virtio*, unused*),
// efidisk0/tpmstate0, and the vmstate volid of a hibernated VM or a vmstate=1
// snapshot. A slot holding "none" or a non-storage device (a physical-
// passthrough path with no leading volid) is simply absent from the returned
// set; this function does no PVE-side existence checking of its own.
//
// Snapshot and hibernated vmstate inclusion (pveforge-claimed-volumes-snapshot-
// vmstate): a vmstate=1 snapshot creates local-lvm:vm-<vmid>-state-<snap>,
// referenced ONLY from that snapshot's section — absent from the current
// config, present in /content, and matching the vm-<vmid>- destroy-time prefix.
// Reading only the current config (the former behaviour, live-verified to miss
// it: nested pvh 2026-10-23, Batch C item 75) let the destroy-time free
// (OrphanVolumesForVMID -> VolumeFreeOrphans) select and delete a live VM's
// snapshot RAM state. Both vmstate legs are now backed by PVE's own oracle and
// fail closed: a live config whose lock reports a suspend-family state but
// carries no vmstate volid, and a snapshot whose list entry reports vmstate!=0
// but whose section carries no vmstate volid, are each refused
// (ErrUnverifiableRead) rather than returned as a short set.
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
// rights (VM.Audit at minimum) for the result to be trustworthy. This
// permission-scoped short-list hazard is LIVE-VERIFIED (nested pvh
// 2026-10-25, PVE 9.2, Batch C item 76/C3, VMID 690, capture exit 0): a
// token holding Datastore.Allocate but NO VM.Audit got a plain 200 with the
// owning VM absent from the list, and that VM's live disk then read as a
// false orphan under it but not under a full VM.Audit token. See
// OrphanVolumes for the exact dangerous vs too-weak token shapes. The
// DESTRUCTIVE consumer enumerates VMs from a COMPLETE root-sourced list (Unit 1
// NodeVMIDs) via OrphanVolumesForVMIDWithVMList, where a VM whose config the
// token cannot read is a HARD refusal, not a silent omission; this
// token-enumeration hazard remains only on the advisory OrphanVolumes path.
//
// Linked-clone volid identity — live on nested lvmthin (pvh 2026-10-23,
// Batch C item 74); UNVERIFIED on ZFS (deferred item 79). Live-verified facts:
// (a) a `qm clone --full 0` disk is a plain local-lvm:vm-<clone>-disk-0 whose
// qm-config volid is BYTE-IDENTICAL to the Volid /content reports (so a clone's
// OWN disk is self-claimed by its own config); (b) /content exposes NO
// linked-clone parent (proxmox.StorageContent.Parent came back empty), so the
// clone→base link is invisible to /content; (c) the template base appears as a
// separate local-lvm:base-<tpl>-disk-N, which is OUTSIDE the vm-<vmid>- destroy-time
// selector. The safety conclusion — the base-reads-unclaimed/freed hazard does NOT
// reproduce on lvmthin — rests on (c) alone. (That the base is also in the
// template's own config is true BY CONSTRUCTION, not a fact C1 measured: the
// capture bailed at fact (b)'s empty parent and never evaluated base-claimed-by-
// template.) On other backends (the operator's production ZFS) this is still
// unverified — see vault task pveforge-storage-orphan-scan's "Unverified
// assumptions" section before trusting destroy-time reconciliation there.
func (c *Client) ClaimedVolumes(ctx context.Context, node string, vmid int) (map[string]bool, error) {
	if node == "" {
		return nil, fmt.Errorf("claimed volumes for vmid %d: node is required", vmid)
	}

	claimed := make(map[string]bool)

	// Live config, pending ∪ current=1 (B4). A volid present only in the
	// pending view is a pending ADD (already allocated); one present only in
	// current=1 is a pending DELETE (still allocated and in use until the
	// guest's next cold boot) — both must be claimed, so neither view alone is
	// sufficient. Read the live config FIRST and refuse on its guard before
	// listing snapshots.
	livePath := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(node), vmid)
	for _, params := range []url.Values{nil, {"current": {"1"}}} {
		cr, err := c.configVolids(ctx, vmid, "", livePath, params, true)
		if err != nil {
			return nil, fmt.Errorf("claimed volumes for vmid %d: %w", vmid, err)
		}
		// Live vmstate backstop (3.2): PVE's lock is its own witness that a
		// hibernated VM has a resume-state volume. suspended (at rest) and
		// suspending (mid suspend-to-disk) both prefix "suspend"; every other
		// lock legitimately has no live vmstate (a rollback's state is the
		// snapshot's). So refuse ONLY when the lock asserts a suspend-family
		// state and the config reported no vmstate volid — fail closed, a
		// refusal never a deletion, and never for a correctly-reporting VM.
		if strings.HasPrefix(cr.lock, "suspend") && firstCommaVolid(cr.vmstate) == "" {
			return nil, fmt.Errorf("claimed volumes for vmid %d: %w: lock %q asserts a suspend-family state volume but the config carries no vmstate volid", vmid, ErrUnverifiableRead, cr.lock)
		}
		for _, v := range cr.volids {
			claimed[v] = true
		}
	}

	// Every real snapshot's frozen section: its disk slots, efidisk0/tpmstate0,
	// and vmstate volid. Covers a disk referenced ONLY by an older (since-
	// detached) snapshot. listSnapshotsVerifiable fails closed on a swallowed
	// or current-less list; a VM with no snapshots yields only the "current"
	// pseudo-entry, which realSnapshots drops.
	snaps, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("claimed volumes for vmid %d: %w", vmid, err)
	}
	for _, s := range realSnapshots(snaps) {
		cr, err := c.configVolids(ctx, vmid, s.Name,
			fmt.Sprintf("/nodes/%s/qemu/%d/snapshot/%s/config", url.PathEscape(node), vmid, url.PathEscape(s.Name)), nil, true)
		if err != nil {
			return nil, fmt.Errorf("claimed volumes for vmid %d: %w", vmid, err)
		}
		// Snapshot vmstate backstop (NEW-13): the snapshot LIST entry's
		// Vmstate flag is PVE's own witness (the same oracle CreateSnapshot
		// gates on, snapshot.go) that a vm-<vmid>-state-<snap> volume exists.
		// Refuse when it asserts one and the section carries no vmstate volid.
		if s.Vmstate != 0 && firstCommaVolid(cr.vmstate) == "" {
			return nil, fmt.Errorf("claimed volumes for vmid %d: %w: snapshot %q list reports vmstate=%d but its section carries no vmstate volid", vmid, ErrUnverifiableRead, s.Name, s.Vmstate)
		}
		for _, v := range cr.volids {
			claimed[v] = true
		}
	}

	return claimed, nil
}

// refuseIfShared fails closed on a shared storage, single-sourcing the refusal
// text the token OrphanVolumes and the destructive OrphanVolumesWithVMList both
// use. A shared storage's content listing reflects volumes claimed by VMs on
// OTHER cluster nodes too, invisible to a node-scoped claimed set; refuse rather
// than return a diff that may be wrong. Also surfaces a GetStorage read error.
func (c *Client) refuseIfShared(ctx context.Context, node, storage string) error {
	stg, err := c.GetStorage(ctx, node, storage)
	if err != nil {
		return fmt.Errorf("orphan volumes: get storage %q on %q: %w", storage, node, err)
	}
	if stg.Shared != 0 {
		return fmt.Errorf("orphan volumes: storage %q on %q is shared (shared=1): the claimed set this function builds is scoped to node %q alone and cannot see volumes claimed by VMs on other cluster nodes — refusing rather than returning a diff that may falsely report volumes in active use elsewhere as orphaned", storage, node, node)
	}
	return nil
}

// orphanVolumesForVMIDs is the claim-loop + set-difference ONLY: it unions
// ClaimedVolumes over vmids and diffs the ALREADY-FETCHED content listing. Its
// caller has already refused shared storage and fetched content; this function
// never enumerates VMs and never sees a GetVMs error, so a refused qemu list
// (vms.go's null-list ErrUnverifiableRead) can never degrade into an empty
// claimed set here. A ClaimedVolumes error — a token 401/403 wrapped as
// ErrNotAuthorized, or an ErrUnverifiableRead — ABORTS the whole determination;
// it is never skipped, which would leave a live VM's disk reading as a false
// orphan on the destructive path.
func (c *Client) orphanVolumesForVMIDs(ctx context.Context, node string, content []*storageContentEntry, vmids []int) ([]*proxmox.StorageContent, error) {
	claimed := make(map[string]bool)
	for _, vmid := range vmids {
		vmClaimed, err := c.ClaimedVolumes(ctx, node, vmid)
		if err != nil {
			return nil, fmt.Errorf("orphan volumes: %w", err)
		}
		for volid := range vmClaimed {
			claimed[volid] = true
		}
	}

	var orphans []*proxmox.StorageContent
	for _, entry := range content {
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

// narrowToVMIDPrefix keeps only the orphans whose volid matches vmid's
// "<storage>:vm-<vmid>-" naming convention — the selector both ForVMID
// entrypoints share.
func narrowToVMIDPrefix(orphans []*proxmox.StorageContent, storage string, vmid int) []*proxmox.StorageContent {
	prefix := fmt.Sprintf("%s:vm-%d-", storage, vmid)
	var matched []*proxmox.StorageContent
	for _, o := range orphans {
		if strings.HasPrefix(o.Volid, prefix) {
			matched = append(matched, o)
		}
	}
	return matched
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
// Trust precondition (LIVE-VERIFIED, nested pvh 2026-10-25, PVE 9.2, Batch
// C item 76/C3): see ClaimedVolumes — this function inherits GetVMs' and
// ClaimedVolumes' exposure to permission-scoped short lists. A token
// missing view rights on even one VM makes every volume that VM
// legitimately owns look orphaned, silently, with no error anywhere in
// this call. The dangerous token shape is precise: /content reveals a
// VM-owned image to a token holding Datastore.Allocate (on the storage) OR
// VM.Config.Disk (on the VM) — NEITHER grants VM.Audit, so the owning VM
// stays out of GET /nodes/{node}/qemu. The Allocate shape was then run
// through this function and the live disk read as a false orphan; the
// VM.Config.Disk shape was measured only as that visibility split (disk
// present, VM absent), not as an OrphanVolumes result. A Datastore.Audit-only
// token is too weak to see the disk in /content at all (safe by accident,
// not by design). Adding Datastore.AllocateSpace on top of Datastore.Audit
// was also measured and still hid the disk; AllocateSpace alone was not
// isolated. So /content visibility is NOT a subset of VM-list
// visibility. Requires a full node-scoped VM.Audit token (every VM on
// the node); do not call this with a storage-operator token and trust
// the result for a destructive follow-up action. This is the ADVISORY,
// token-sourced path; the destructive-safe variant is OrphanVolumesWithVMList,
// which enumerates VMs from a complete root-sourced list (pveforge-orphan-scan-
// vmlist-completeness-root-read, Unit 1) instead of this token GetVMs, and whose
// closure is conditional (see that function's doc comment).
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
// Linked-clone caveat — live on nested lvmthin (pvh 2026-10-23, Batch C
// item 74); UNVERIFIED on ZFS (item 79). Inherits ClaimedVolumes' result
// unchanged: on lvmthin the clone's own disk is self-claimed and the base
// (base-<tpl>-disk-N) is outside the vm-<vmid>- selector, and /content
// exposes no parent link. See that function's own doc comment and vault
// task pveforge-storage-orphan-scan's "Unverified assumptions" section.
func (c *Client) OrphanVolumes(ctx context.Context, node, storage string) ([]*proxmox.StorageContent, error) {
	if node == "" || storage == "" {
		return nil, fmt.Errorf("orphan volumes: node and storage are required")
	}

	if err := c.refuseIfShared(ctx, node, storage); err != nil {
		return nil, err
	}

	actual, err := c.storageContentWithType(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: get storage content on %q/%q: %w", node, storage, err)
	}

	// Token-sourced enumeration. A GetVMs error — including the null-list
	// ErrUnverifiableRead (vms.go) — is returned HERE, before the claim-loop,
	// so the advisory path never degrades a refused list into an empty claimed
	// set.
	vms, err := c.GetVMs(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: list vms on %q: %w", node, err)
	}
	vmids := make([]int, 0, len(vms))
	for _, vm := range vms {
		vmids = append(vmids, int(vm.VMID))
	}

	return c.orphanVolumesForVMIDs(ctx, node, actual, vmids)
}

// OrphanVolumesWithVMList is OrphanVolumes' DESTRUCTIVE-safe twin: the caller
// supplies a COMPLETE, root-sourced VMID set (bootstrap.RootAccess.NodeVMIDs,
// pveforge-orphan-scan-vmlist-completeness-root-read Unit 1) so the claimed set
// is not built from the token's silently-short GetVMs. It does its OWN
// node/storage check, shared-storage refusal and content fetch (it does not call
// OrphanVolumes), then unions ClaimedVolumes over completeVMIDs and diffs.
//
// Closure is CONDITIONAL — this closes the token-ENUMERATION short-list hazard
// ONLY given: (a) the per-VM-config fail-closed (a token that cannot read a
// root-listed VM's config aborts the whole call, never a short claimed set —
// PVE gates the whole vm_config on VM.Audit, so there is no non-error
// disk-redacted config); (b) a COMPLETE, non-stale injected list — the pmxcfs
// quorum-short / not-yet-replicated residual is the CALLER's gate (Unit 3), not
// closed here; (c) the ZFS linked-clone identity caveat (item 79; see
// OrphanVolumesForVMID) still unverified. It is NOT "C3 closed" unconditionally.
//
// completeVMIDs: a nil slice is REFUSED (it is a dropped NodeVMIDs error); a
// non-nil EMPTY slice is accepted and means a genuinely zero-QEMU node — NO VM
// claims anything, so every prefix-matching images volume is reported an orphan.
// A caller that cannot PROVE the node is truly empty (vs a quorum-short list)
// MUST refuse: that proof is Unit 3's quorum gate, not this function's.
func (c *Client) OrphanVolumesWithVMList(ctx context.Context, node, storage string, completeVMIDs []int) ([]*proxmox.StorageContent, error) {
	if node == "" || storage == "" {
		return nil, fmt.Errorf("orphan volumes: node and storage are required")
	}
	if completeVMIDs == nil {
		return nil, fmt.Errorf("orphan volumes: a nil VM list is refused (a non-nil empty slice is a genuinely zero-QEMU node; nil is a dropped NodeVMIDs error)")
	}

	if err := c.refuseIfShared(ctx, node, storage); err != nil {
		return nil, err
	}

	actual, err := c.storageContentWithType(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes: get storage content on %q/%q: %w", node, storage, err)
	}

	return c.orphanVolumesForVMIDs(ctx, node, actual, completeVMIDs)
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
// active use, and this is LIVE-VERIFIED (nested pvh 2026-10-25, PVE 9.2,
// Batch C item 76/C3, VMID 690): under a storage-operator token
// (Datastore.Allocate + Datastore.Audit on the storage, no VM.Audit) a
// live VM's disk read as a false orphan here and would have been freed.
// VolumeFreeOrphans MUST refuse a destructive free unless its token
// holds VM.Audit on every VM that can own a volume in that content
// listing (measured: node-scoped GET /nodes/{node}/qemu; a VM.Audit
// grant on /vms/690 was enough to un-hide that one VM). A cluster-wide
// grant is sufficient if it implies that, and was not itself measured.
// See vault task pveforge-storage-orphan-scan's "Unverified
// assumptions" section.
//
// Linked-clone caveat — live on nested lvmthin (pvh 2026-10-23, Batch C
// item 74); UNVERIFIED on ZFS (the operator's production backend — item
// 79). On lvmthin a `--full 0` clone's own disk volid is byte-identical to
// its /content Volid, and the template base is local-lvm:base-<tpl>-disk-N —
// OUTSIDE this function's "<storage>:vm-<vmid>-" prefix — so the base is
// never selected for deletion here and the base-reads-unclaimed/freed hazard
// does NOT reproduce on lvmthin. /content exposes no linked-clone parent, so
// the clone→base link is invisible to /content (an LVM-level check would be
// needed if a future free ever had to reason about it — not required for
// today's prefix-based free). On ZFS this is still unverified: do not trust
// destroy-time reconciliation for linked clones there until item 79 checks
// it on a real ZFS host.
//
// This is the ADVISORY, token-sourced variant and keeps the short-list hazard
// above; the destructive free (pveforge-storage-volume-tracking's
// VolumeFreeOrphans) must call OrphanVolumesForVMIDWithVMList, which takes a
// complete root-sourced VM list. Its base/shared-storage error is returned BARE
// here, unchanged.
func (c *Client) OrphanVolumesForVMID(ctx context.Context, node, storage string, vmid int) ([]*proxmox.StorageContent, error) {
	orphans, err := c.OrphanVolumes(ctx, node, storage)
	if err != nil {
		return nil, err
	}
	return narrowToVMIDPrefix(orphans, storage, vmid), nil
}

// OrphanVolumesForVMIDWithVMList narrows OrphanVolumesWithVMList to vmid's
// "<storage>:vm-<vmid>-" naming convention — the entrypoint Unit 3's destructive
// VolumeFreeOrphans calls. The completeVMIDs contract (nil refused, non-nil
// empty = zero-QEMU node), the CONDITIONAL closure (per-VM fail-closed + a
// complete non-stale list which is the caller's quorum gate), and the ZFS
// linked-clone caveat (item 79) are all as documented on OrphanVolumesWithVMList
// and OrphanVolumesForVMID above. Unlike the token variant, this one wraps the
// base error with its own vmid context.
func (c *Client) OrphanVolumesForVMIDWithVMList(ctx context.Context, node, storage string, vmid int, completeVMIDs []int) ([]*proxmox.StorageContent, error) {
	orphans, err := c.OrphanVolumesWithVMList(ctx, node, storage, completeVMIDs)
	if err != nil {
		return nil, fmt.Errorf("orphan volumes for vmid %d: %w", vmid, err)
	}
	return narrowToVMIDPrefix(orphans, storage, vmid), nil
}
