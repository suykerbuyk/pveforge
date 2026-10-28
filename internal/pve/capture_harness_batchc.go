//go:build harness

// Batch C storage-free-safety captures (pveforge-nested-pve-test-harness items
// 74/75/76/77 — the "storage-free safety" set that gates
// pveforge-storage-volume-tracking's free path). Same rules as
// capture_harness_amut.go: built only under the `harness` tag, in package pve so
// it can reach the production client, the orphan-scan inputs
// (ClaimedVolumes/OrphanVolumes/OrphanVolumesForVMID), the storage content
// decode (storageContentWithType), and the nextid classifier (vmidFree /
// isVMIDTakenError). It adds no production behaviour.
//
// The ASSERTIONS here — each capture's Failures(), appended to the report's
// errors in cmd/pveforge-harness-capture — are the non-vacuity gate, never
// `pveforge api`'s exit status. Each decision is factored into a small pure
// function (evalCloneVolid, evalSnapshotSection, evalShortList,
// evalCrossNodeCreate) so the invariant has a single line to mutation-test,
// exactly as classifyVMList / isAgentOff / classifyAbsence do for Batch A.
//
// Scope: C1/C2 settle volid identity and the claimed-surface gap on nested
// `local-lvm` (lvmthin) ONLY; the operator's production ZFS backend is unproven
// by this unit (item 79). C4 is create/oracle-side, not a free gate.

package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// firstCommaVolid, allDigits and isDiskShapedKey were lifted into production
// storageorphans.go (pveforge-claimed-volumes-snapshot-vmstate, B2) so one
// reader and one parser serve both the claimed-set path and this capture; this
// file still uses them (same package pve).

// freePrefix, SnapshotSectionCapture, snapshotSectionInputs, evalSnapshotSection
// and Failures were relocated to the untagged snapshotsectiongate.go (F6) so CI
// runs the item-75 gate test; this harness file still references them.

// diskSlotVolids returns the parsed volids of every disk-shaped slot of cfg, in
// the SAME surface ClaimedVolumes walks (ide/scsi/sata/virtio/unused +
// efidisk0/tpmstate0, storageorphans.go:161-172), keyed by slot name so a caller
// can pick "the clone's disk slot" without matching on the volid under test.
func diskSlotVolids(cfg *proxmox.VirtualMachineConfig) map[string]string {
	out := map[string]string{}
	add := func(slot, val string) {
		if v := firstCommaVolid(val); v != "" {
			out[slot] = v
		}
	}
	for slot, v := range cfg.IDEs {
		add(slot, v)
	}
	for slot, v := range cfg.SCSIs {
		add(slot, v)
	}
	for slot, v := range cfg.SATAs {
		add(slot, v)
	}
	for slot, v := range cfg.VirtIOs {
		add(slot, v)
	}
	for slot, v := range cfg.Unuseds {
		add(slot, v)
	}
	add("efidisk0", cfg.EFIDisk0)
	add("tpmstate0", cfg.TPMState0)
	return out
}

// ---- C1 (74): linked-clone disk volid identity --------------------------

// CloneVolidCapture records the three gated facts of item 74 on the nested
// local-lvm backend. Each boolean is an assertion; Failures() turns the false
// ones into report errors. StorageContent.Parent is the field the orphan scan's
// parser never reads (storageorphans.go add()), which is the whole hazard.
type CloneVolidCapture struct {
	Storage           string `json:"storage"`
	TemplateVMID      int    `json:"template_vmid"`
	CloneVMID         int    `json:"clone_vmid"`
	CloneSlot         string `json:"clone_slot"`
	CloneSlotVolid    string `json:"clone_slot_volid"`    // from clone config (first-comma)
	CloneContentVolid string `json:"clone_content_volid"` // /content Volid of the clone's disk row
	CloneParent       string `json:"clone_parent"`        // StorageContent.Parent on that row
	BaseContentVolid  string `json:"base_content_volid"`  // the separate /content base row Parent names

	IdentityHolds         bool `json:"identity_holds"`           // fact 1: CloneSlotVolid == CloneContentVolid
	ParentLinked          bool `json:"parent_linked"`            // fact 2: Parent non-empty AND a separate base row exists
	BaseClaimedByTemplate bool `json:"base_claimed_by_template"` // fact 3a: base volid in template's current ClaimedVolumes
	BaseMatchesFreePrefix bool `json:"base_matches_free_prefix"` // fact 3b: base volid has prefix <storage>:vm-<tpl>- (expected FALSE)
}

// cloneVolidInputs are the already-read values evalCloneVolid decides on, so the
// decision is testable without a live clone.
type cloneVolidInputs struct {
	storage        string
	templateVMID   int
	cloneVMID      int
	cloneSlot      string
	cloneSlotVolid string
	content        []*storageContentEntry // the storage's /content listing
	templateClaim  map[string]bool        // ClaimedVolumes(template) current config
}

// rowByVolid finds the /content row whose Volid equals volid (used to resolve
// Parent → a separate base row).
func rowByVolid(content []*storageContentEntry, volid string) *storageContentEntry {
	for _, e := range content {
		if e != nil && e.StorageContent != nil && e.Volid == volid {
			return e
		}
	}
	return nil
}

// volidDiskName is a volid's trailing disk name: the segment after the last '/'
// (a linked clone's compound "base-X-disk-N/vm-Y-disk-M"), then after the last
// ':' (the storage prefix). So both "local-lvm:vm-905-disk-0" and
// "local-lvm:base-900-disk-0/vm-905-disk-0" yield "vm-905-disk-0".
func volidDiskName(volid string) string {
	s := volid
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// imagesDiskRowForSlot resolves the /content images row for the clone's chosen
// disk SLOT, not VMID alone (NB3): a multi-disk template would otherwise let the
// VMID-only match compare two different disks. It keys on VMID AND the slot
// volid's disk-name suffix, so the row compared is the one the slot names.
func imagesDiskRowForSlot(content []*storageContentEntry, vmid int, slotVolid string) *storageContentEntry {
	want := volidDiskName(slotVolid)
	for _, e := range content {
		if e == nil || e.StorageContent == nil {
			continue
		}
		if e.Content != "images" || int(e.VMID) != vmid {
			continue
		}
		if volidDiskName(e.Volid) == want {
			return e
		}
	}
	return nil
}

// evalCloneVolid is item 74's decision and the mutation target. It gates the
// DANGEROUS direction (the base image), not the clone's own trivially
// round-tripping slot.
func evalCloneVolid(in cloneVolidInputs) *CloneVolidCapture {
	cap := &CloneVolidCapture{
		Storage:        in.storage,
		TemplateVMID:   in.templateVMID,
		CloneVMID:      in.cloneVMID,
		CloneSlot:      in.cloneSlot,
		CloneSlotVolid: in.cloneSlotVolid,
	}
	cloneRow := imagesDiskRowForSlot(in.content, in.cloneVMID, in.cloneSlotVolid)
	if cloneRow == nil {
		// B absent from a non-null content listing: the clone disk was
		// silently dropped (truncation/403) — identity cannot read as "equal
		// to nothing". Leave IdentityHolds false.
		return cap
	}
	cap.CloneContentVolid = cloneRow.Volid
	cap.CloneParent = cloneRow.Parent
	cap.IdentityHolds = in.cloneSlotVolid == cloneRow.Volid // fact 1 — byte-identical

	if cloneRow.Parent != "" {
		// Parent may be the bare base volid or carry the storage prefix. Fact 2
		// is honest only when Parent resolves to an actual /content row — the
		// whole point of C1 is to discover whether lvmthin's `parent` field
		// matches a real volid. NO template-VMID fallback (S1): guessing the
		// template's disk when Parent does not resolve would paper over a
		// non-match and let a full clone pass fact 2.
		base := rowByVolid(in.content, cloneRow.Parent)
		if base == nil {
			base = rowByVolid(in.content, in.storage+":"+cloneRow.Parent)
		}
		// fact 2 — true ONLY when Parent resolves to a separate /content row.
		parentResolves := base != nil && base.Volid != cloneRow.Volid
		if parentResolves {
			cap.ParentLinked = true
			if base != nil {
				cap.BaseContentVolid = base.Volid
				cap.BaseClaimedByTemplate = in.templateClaim[base.Volid] // fact 3a
				cap.BaseMatchesFreePrefix = strings.HasPrefix(base.Volid, freePrefix(in.storage, in.templateVMID))
			}
		}
	}
	return cap
}

// Failures lists the gate failures. Empty Parent / a full clone is a FAILURE
// (OQ-5 REJECTED — no degrade-to-full-clone), as is a missing clone content row
// or a base the template does not claim.
func (c *CloneVolidCapture) Failures() []string {
	var f []string
	if c.CloneContentVolid == "" {
		f = append(f, fmt.Sprintf("item-74: clone vm %d has no images disk row in /content on %q (silent truncation/403 — cannot read as identity)", c.CloneVMID, c.Storage))
		return f // nothing else is meaningful without the clone row
	}
	if !c.IdentityHolds {
		f = append(f, fmt.Sprintf("item-74: clone slot volid %q != /content Volid %q (byte-identity FAILS)", c.CloneSlotVolid, c.CloneContentVolid))
	}
	if !c.ParentLinked {
		f = append(f, fmt.Sprintf("item-74: clone row Parent=%q did not resolve to a separate /content base row — not a linked clone (FAIL; a full-clone compare does not satisfy item 74)", c.CloneParent))
		return f
	}
	if !c.BaseClaimedByTemplate {
		f = append(f, fmt.Sprintf("item-74: base volid %q is NOT in the template's ClaimedVolumes(current) — the base-reads-unclaimed input could not be established", c.BaseContentVolid))
	}
	return f
}

// ---- C3 (76): token-view-rights short list ------------------------------

// TokenShortListCapture records item 76: a view-restricted token returns a
// strictly shorter VM list with HTTP 200 and no error, and a volume a hidden VM
// owns reads as an orphan under the restricted client but not the full one.
type TokenShortListCapture struct {
	Node              string `json:"node"`
	Storage           string `json:"storage"`
	GroundTruthToken  string `json:"ground_truth_token"` // which token was N (nested Administrator — nested.sh:144)
	RestrictedToken   string `json:"restricted_token"`
	FullLen           int    `json:"full_len"`         // N
	RestrictedLen     int    `json:"restricted_len"`   // M
	RestrictedTyped   bool   `json:"restricted_typed"` // the restricted read returned a typed error (e.g. 403) — a FAIL, not a short list
	RestrictedErr     string `json:"restricted_err,omitempty"`
	HiddenOrphanVolid string `json:"hidden_orphan_volid"`  // the disk-owning hidden VM's volume
	HiddenVMID        int    `json:"hidden_vmid"`          // the VMID the restricted token cannot see
	ScanError         string `json:"scan_error,omitempty"` // a non-nil OrphanVolumesForVMID error (either client) — an UNREAD scan, a FAIL

	OrphanUnderRestricted bool `json:"orphan_under_restricted"` // in OrphanVolumesForVMID(restricted)
	OrphanUnderFull       bool `json:"orphan_under_full"`       // in OrphanVolumesForVMID(full) — must be FALSE
}

type shortListInputs struct {
	fullLen               int
	restrictedLen         int
	restrictedTyped       bool
	hiddenOrphanVolid     string
	orphanUnderRestricted bool
	orphanUnderFull       bool
}

// evalShortList is item 76's decision and mutation target. It keys on the length
// DELTA, never the status code; M==N is a vacuous FAIL; a typed (403) restricted
// read is a FAIL, never a "short list".
func evalShortList(in shortListInputs) (shorter bool, orphanShown bool) {
	shorter = !in.restrictedTyped && in.fullLen > 0 && in.restrictedLen < in.fullLen
	orphanShown = in.hiddenOrphanVolid != "" && in.orphanUnderRestricted && !in.orphanUnderFull
	return
}

// Failures delegates to evalShortList so the length AND orphan gates are the
// SAME decider the tests exercise (no second hand-rolled copy — the dead-code
// gap that let the orphan gate go unmeasured).
func (c *TokenShortListCapture) Failures() []string {
	var f []string
	if c.RestrictedTyped {
		f = append(f, fmt.Sprintf("item-76: restricted read returned a typed error (%s) — a 403 is NOT a silent short list; capture FAILS", c.RestrictedErr))
		return f
	}
	if c.ScanError != "" {
		f = append(f, "item-76: OrphanVolumesForVMID error (an UNREAD scan — never read as 'not an orphan'): "+c.ScanError)
		return f
	}
	shorter, orphanShown := evalShortList(shortListInputs{
		fullLen:               c.FullLen,
		restrictedLen:         c.RestrictedLen,
		restrictedTyped:       c.RestrictedTyped,
		hiddenOrphanVolid:     c.HiddenOrphanVolid,
		orphanUnderRestricted: c.OrphanUnderRestricted,
		orphanUnderFull:       c.OrphanUnderFull,
	})
	if !shorter {
		f = append(f, fmt.Sprintf("item-76: restricted len M=%d is not < ground-truth N=%d (M==N or N<=0 ⇒ truncation NOT reproduced)", c.RestrictedLen, c.FullLen))
	}
	if !orphanShown {
		f = append(f, fmt.Sprintf("item-76: hidden VM %d's volume %q is not orphan-only-under-restricted via OrphanVolumesForVMID (restricted=%v full=%v) — the destroy-time data-loss path was not shown", c.HiddenVMID, c.HiddenOrphanVolid, c.OrphanUnderRestricted, c.OrphanUnderFull))
	}
	return f
}

// ---- C4 (77): cross-node VMID collision ---------------------------------

// CrossNodeCreateCapture records item 77: a create at a VMID taken on ANOTHER
// node is rejected, and PVE's /cluster/nextid oracle agrees in both directions.
type CrossNodeCreateCapture struct {
	TakenVMID           int    `json:"taken_vmid"`
	OtherNode           string `json:"other_node"`    // where the VMID already exists
	CreateNode          string `json:"create_node"`   // where the colliding create was attempted
	PostRejected        bool   `json:"post_rejected"` // the create's OWN error was a *pve.StatusError
	CreateCode          int    `json:"create_code,omitempty"`
	CreateBody          string `json:"create_body,omitempty"`
	TaskExit            string `json:"task_exit,omitempty"` // if the POST was 2xx: the create task exitstatus
	XAbsentOnCreateNode bool   `json:"x_absent_on_create_node"`
	XPresentOnOtherNode bool   `json:"x_present_on_other_node"`

	NextidTakenSaysTaken bool `json:"nextid_taken_says_taken"` // vmidFree(taken) == (false,nil) via isVMIDTakenError
	NextidFreeSaysFree   bool `json:"nextid_free_says_free"`   // vmidFree(free) == (true,nil)
	FreeProbeVMID        int  `json:"free_probe_vmid"`
}

type crossNodeInputs struct {
	postRejected         bool
	taskExit             string // "" when the POST was rejected (no task)
	xAbsentOnCreateNode  bool
	xPresentOnOtherNode  bool
	nextidTakenSaysTaken bool
	nextidFreeSaysFree   bool
}

// evalCrossNodeCreate is item 77's decision and mutation target. A create is a
// genuine rejection iff the POST itself errored as a StatusError, OR the POST
// was accepted but the task did not finish OK and no VM X exists on the create
// node. A 2xx whose task exits OK is a FAIL (a duplicate was created).
func evalCrossNodeCreate(in crossNodeInputs) (createRejected bool) {
	if in.postRejected {
		return true
	}
	// An empty/unread taskExit (CaptureTaskExitStatus failed) is NOT a
	// rejection — it is unproven, and the capture must FAIL rather than count it
	// as one.
	if in.taskExit == "" {
		return false
	}
	// Judge the task by PVE's OWN rule (taskExitSucceeded, task.go:131): "OK" or
	// "WARNINGS: n" are BOTH successes, so a success is never a rejection. A
	// rejection is a non-success task AND no VM X on the create node.
	return !taskExitSucceeded(in.taskExit) && in.xAbsentOnCreateNode
}

func (c *CrossNodeCreateCapture) Failures() []string {
	var f []string
	if !evalCrossNodeCreate(crossNodeInputs{
		postRejected:        c.PostRejected,
		taskExit:            c.TaskExit,
		xAbsentOnCreateNode: c.XAbsentOnCreateNode,
	}) {
		f = append(f, fmt.Sprintf("item-77: create of taken VMID %d on %q was NOT rejected (post_rejected=%v task_exit=%q x_absent=%v) — a duplicate cluster-wide VMID was created", c.TakenVMID, c.CreateNode, c.PostRejected, c.TaskExit, c.XAbsentOnCreateNode))
	}
	if !c.XPresentOnOtherNode {
		f = append(f, fmt.Sprintf("item-77: VMID %d is not present on %q — the collision precondition did not hold", c.TakenVMID, c.OtherNode))
	}
	if !c.NextidTakenSaysTaken {
		f = append(f, fmt.Sprintf("item-77: /cluster/nextid did not classify taken VMID %d as taken (isVMIDTakenError FALSE)", c.TakenVMID))
	}
	if !c.NextidFreeSaysFree {
		f = append(f, fmt.Sprintf("item-77: /cluster/nextid did not classify free VMID %d as free", c.FreeProbeVMID))
	}
	return f
}

// ---- Shared live helpers ------------------------------------------------

// startAndConfirmRunning posts the status/start leaf (reset.go:396) and confirms
// the guest reports `running`, BEFORE a vmstate snapshot. A start failure is a
// capture error, never swallowed.
func (c *Client) startAndConfirmRunning(ctx context.Context, node string, vmid int) error {
	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/status/start", url.PathEscape(node), vmid), nil)
	if err != nil {
		return fmt.Errorf("start vm %d: %w", vmid, err)
	}
	// A 2xx start MUST return a UPID; without one the start task cannot be
	// confirmed, so FAIL rather than judge by an immediate status read (N2).
	upid, derr := decodeUPIDScalar(raw)
	if derr != nil || upid == "" {
		return fmt.Errorf("start vm %d: start did not return a UPID (cannot confirm the start task): %v", vmid, derr)
	}
	if werr := c.WaitForTask(ctx, node, upid); werr != nil {
		return fmt.Errorf("start vm %d: start task did not finish OK: %w", vmid, werr)
	}
	var st struct {
		Status string `json:"status"`
	}
	sraw, err := c.RawRequest(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/qemu/%d/status/current", url.PathEscape(node), vmid), nil)
	if err != nil {
		return fmt.Errorf("start vm %d: read status: %w", vmid, err)
	}
	if err := json.Unmarshal(sraw, &st); err != nil {
		return fmt.Errorf("start vm %d: status shape: %w", vmid, err)
	}
	if st.Status != "running" {
		return fmt.Errorf("start vm %d: status is %q, want running", vmid, st.Status)
	}
	return nil
}

// snapshotSectionVolids issues a RAW GET of the snapshot SECTION config (never
// the nil-client library VirtualMachineSnapshot.Config) and parses every
// disk-shaped value and any `vmstate` value with the same first-comma rule as
// the claimed-set scan. It is a strict=false wrapper over the production
// configVolids reader (pveforge-claimed-volumes-snapshot-vmstate, B2/NEW-2): the
// capture is a measurement that never DELETEs, so its output under-reporting a
// skipped key is caught by Failures()/ContentMissed — the lenient skip is safe
// here. Returns the parsed volids and the raw vmstate value (if any) for the
// hibernate best-effort leg.
func (c *Client) snapshotSectionVolids(ctx context.Context, node string, vmid int, snap string) (volids []string, vmstate string, err error) {
	cr, err := c.configVolids(ctx, vmid, snap,
		fmt.Sprintf("/nodes/%s/qemu/%d/snapshot/%s/config", url.PathEscape(node), vmid, url.PathEscape(snap)), nil, false)
	if err != nil {
		return nil, "", fmt.Errorf("snapshot %q config on vm %d: %w", snap, vmid, err)
	}
	return cr.volids, cr.vmstate, nil
}

// volidSet collapses a /content listing to the set of its Volids.
func volidSet(content []*storageContentEntry) map[string]bool {
	m := map[string]bool{}
	for _, e := range content {
		if e != nil && e.StorageContent != nil {
			m[e.Volid] = true
		}
	}
	return m
}

// destroyAndConfirmGone is the cleanup oracle: DestroyVM, confirm the destroy
// task finished OK (WaitForTask), and confirm gone two more ways — nextid says
// the VMID is free AND GetVMs on the node no longer lists it. The nested cluster
// creates no pool, so there is no pool leg. A read ERROR is never read as
// absence.
func (c *Client) destroyAndConfirmGone(ctx context.Context, node string, vmid int) error {
	upid, err := c.DestroyVM(ctx, node, vmid, true)
	if err != nil {
		return fmt.Errorf("destroy vm %d: %w", vmid, err)
	}
	if err := c.WaitForTask(ctx, node, upid); err != nil {
		return fmt.Errorf("destroy vm %d: task did not finish OK: %w", vmid, err)
	}
	free, err := c.vmidFree(ctx, vmid)
	if err != nil {
		return fmt.Errorf("destroy vm %d: nextid read error (not read as gone): %w", vmid, err)
	}
	if !free {
		return fmt.Errorf("destroy vm %d: /cluster/nextid still reports it taken", vmid)
	}
	vms, err := c.GetVMs(ctx, node)
	if err != nil {
		return fmt.Errorf("destroy vm %d: GetVMs error (not read as gone): %w", vmid, err)
	}
	for _, v := range vms {
		if int(v.VMID) == vmid {
			return fmt.Errorf("destroy vm %d: still listed by GetVMs on %q", vmid, node)
		}
	}
	return nil
}

// ---- Live captures (compose reads/mutations + the deciders) --------------

// CaptureCloneVolidIdentity performs item 74 against a live nested cluster: it
// reads the (already-created) clone's config and the storage /content listing
// plus the template's current ClaimedVolumes, and evaluates the three gated
// facts. The caller is responsible for the clone/template lifecycle (create,
// template-convert, clone full=0, WaitForTask) and cleanup via
// destroyAndConfirmGone — see the instrument wiring.
func (c *Client) CaptureCloneVolidIdentity(ctx context.Context, node, storage string, templateVMID, cloneVMID int) (*CloneVolidCapture, error) {
	vm, err := c.GetVM(ctx, node, cloneVMID)
	if err != nil {
		return nil, fmt.Errorf("item-74: read clone %d config: %w", cloneVMID, err)
	}
	if vm.VirtualMachineConfig == nil {
		return nil, fmt.Errorf("item-74: clone %d config was null", cloneVMID)
	}
	slots := diskSlotVolids(vm.VirtualMachineConfig)
	cloneSlot, cloneSlotVolid := pickDiskSlot(slots)
	if cloneSlot == "" {
		return nil, fmt.Errorf("item-74: clone %d has no storage-resident disk slot", cloneVMID)
	}
	content, err := c.storageContentWithType(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("item-74: read %q content: %w", storage, err)
	}
	templateClaim, err := c.ClaimedVolumes(ctx, node, templateVMID)
	if err != nil {
		return nil, fmt.Errorf("item-74: ClaimedVolumes(template %d): %w", templateVMID, err)
	}
	return evalCloneVolid(cloneVolidInputs{
		storage:        storage,
		templateVMID:   templateVMID,
		cloneVMID:      cloneVMID,
		cloneSlot:      cloneSlot,
		cloneSlotVolid: cloneSlotVolid,
		content:        content,
		templateClaim:  templateClaim,
	}), nil
}

// pickDiskSlot returns a deterministic disk slot (lowest slot name) and its
// parsed volid, so the clone's disk is identified by SLOT, not by the volid
// under test.
func pickDiskSlot(slots map[string]string) (string, string) {
	names := make([]string, 0, len(slots))
	for s := range slots {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		if slots[s] != "" {
			return s, slots[s]
		}
	}
	return "", ""
}

// CaptureVmstateSection performs item 75 against a live nested cluster on an
// already-started, already-snapshotted guest: it reads the snapshot SECTION, the
// current ClaimedVolumes, and the storage /content listing, and evaluates the
// claimed-surface gap. The caller owns start+snapshot (start via
// startAndConfirmRunning, snapshot via CreateSnapshot) and cleanup.
func (c *Client) CaptureVmstateSection(ctx context.Context, node, storage string, vmid int, snap, hibernateKey string) (*SnapshotSectionCapture, error) {
	sectionVolids, _, err := c.snapshotSectionVolids(ctx, node, vmid, snap)
	if err != nil {
		return nil, err
	}
	// The pre-fix surface: the LIVE config only (pending ∪ current, no
	// snapshots). Built from the production reader directly so a raw gap is
	// defined against exactly what ClaimedVolumes read before snapshots existed.
	currentConfigOnlyClaim := map[string]bool{}
	livePath := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(node), vmid)
	for _, params := range []url.Values{nil, {"current": {"1"}}} {
		cr, err := c.configVolids(ctx, vmid, "", livePath, params, true)
		if err != nil {
			return nil, fmt.Errorf("item-75: live config claim(%d): %w", vmid, err)
		}
		for _, v := range cr.volids {
			currentConfigOnlyClaim[v] = true
		}
	}
	fullClaim, err := c.ClaimedVolumes(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("item-75: ClaimedVolumes(full %d): %w", vmid, err)
	}
	// Live-disk witness for leg (c), by SLOT, from an independent typed read —
	// NOT from either claim set. A real GetVM failure must PROPAGATE (else the
	// gate's live-leg check silently skips and lies green, F1); only a
	// legitimately diskless VM — a valid read whose config has no disk slot —
	// yields an empty witness and skips leg (c) by design (NEW-18).
	vm, err := c.GetVM(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("item-75: live-disk witness read for vm %d: %w", vmid, err)
	}
	var liveWitnessVolid string
	if vm.VirtualMachineConfig != nil {
		if _, wv := pickDiskSlot(diskSlotVolids(vm.VirtualMachineConfig)); wv != "" {
			liveWitnessVolid = wv
		}
	}
	content, err := c.storageContentWithType(ctx, node, storage)
	if err != nil {
		return nil, fmt.Errorf("item-75: read %q content: %w", storage, err)
	}
	return evalSnapshotSection(snapshotSectionInputs{
		storage:                storage,
		vmid:                   vmid,
		snapshot:               snap,
		sectionVolids:          sectionVolids,
		currentConfigOnlyClaim: currentConfigOnlyClaim,
		fullClaim:              fullClaim,
		contentVolids:          volidSet(content),
		hibernateKey:           hibernateKey,
		liveWitnessVolid:       liveWitnessVolid,
	}), nil
}

// CaptureTokenShortList performs item 76 with two clients: this client (the
// ground-truth nested Administrator) and restricted (operator-provided, OQ-3).
// hiddenOrphanVolid is a volume owned by a VM the restricted token cannot see;
// the capture confirms it reads as an orphan under restricted and NOT under full.
func (c *Client) CaptureTokenShortList(ctx context.Context, restricted *Client, node, storage, groundTruthToken, restrictedToken, hiddenOrphanVolid string, hiddenVMID int) (*TokenShortListCapture, error) {
	cap := &TokenShortListCapture{
		Node:              node,
		Storage:           storage,
		GroundTruthToken:  groundTruthToken,
		RestrictedToken:   restrictedToken,
		HiddenOrphanVolid: hiddenOrphanVolid,
		HiddenVMID:        hiddenVMID,
	}
	full, err := c.GetVMs(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("item-76: ground-truth GetVMs on %q: %w", node, err)
	}
	cap.FullLen = len(full)

	rvms, rerr := restricted.GetVMs(ctx, node)
	if rerr != nil {
		cap.RestrictedTyped = true
		cap.RestrictedErr = rerr.Error()
		return cap, nil // a typed error (e.g. 403) is a FAIL via Failures(), not a short list
	}
	cap.RestrictedLen = len(rvms)

	// orphan-set fact, via OrphanVolumesForVMID — the free's ACTUAL DELETE
	// selector (prefix vm-<vmid>-, storageorphans.go:298), not the general scan.
	// The hidden VM's volume is an orphan under restricted (its owner is
	// invisible, so its volume is unclaimed) and NOT under full. A non-nil scan
	// error on either client is an UNREAD scan — recorded as ScanError and
	// failed by Failures(), never silently left as "not an orphan".
	if rows, err := c.OrphanVolumesForVMID(ctx, node, storage, hiddenVMID); err != nil {
		cap.ScanError = fmt.Sprintf("full OrphanVolumesForVMID(%d): %v", hiddenVMID, err)
	} else {
		cap.OrphanUnderFull = containsVolid(rows, hiddenOrphanVolid)
	}
	if rows, err := restricted.OrphanVolumesForVMID(ctx, node, storage, hiddenVMID); err != nil {
		if cap.ScanError == "" {
			cap.ScanError = fmt.Sprintf("restricted OrphanVolumesForVMID(%d): %v", hiddenVMID, err)
		}
	} else {
		cap.OrphanUnderRestricted = containsVolid(rows, hiddenOrphanVolid)
	}
	return cap, nil
}

func containsVolid(rows []*proxmox.StorageContent, volid string) bool {
	for _, r := range rows {
		if r != nil && r.Volid == volid {
			return true
		}
	}
	return false
}

// CaptureCrossNodeCreate performs item 77's nextid legs through the production
// vmidFree path, both directions. The create leg is driven by the caller (it
// attempts a create at the taken VMID and supplies the outcome), because the
// create itself is the mutation; this method records the nextid oracle and
// assembles the capture.
func (c *Client) CaptureCrossNodeCreate(ctx context.Context, takenVMID, freeProbeVMID int, otherNode, createNode string, createPost crossNodeCreateOutcome) (*CrossNodeCreateCapture, error) {
	cap := &CrossNodeCreateCapture{
		TakenVMID:           takenVMID,
		OtherNode:           otherNode,
		CreateNode:          createNode,
		PostRejected:        createPost.postRejected,
		CreateCode:          createPost.code,
		CreateBody:          createPost.body,
		TaskExit:            createPost.taskExit,
		XAbsentOnCreateNode: createPost.xAbsentOnCreateNode,
		XPresentOnOtherNode: createPost.xPresentOnOtherNode,
		FreeProbeVMID:       freeProbeVMID,
	}
	// nextid taken direction: through the production classifier.
	takenFree, terr := c.vmidFree(ctx, takenVMID)
	if terr == nil {
		cap.NextidTakenSaysTaken = !takenFree // free==false means isVMIDTakenError matched
	}
	// nextid free direction.
	freeFree, ferr := c.vmidFree(ctx, freeProbeVMID)
	if ferr == nil {
		cap.NextidFreeSaysFree = freeFree
	}
	return cap, nil
}

// crossNodeCreateOutcome is the caller-supplied result of the real colliding
// create attempt (the mutation the instrument performs).
type crossNodeCreateOutcome struct {
	postRejected        bool
	code                int
	body                string
	taskExit            string
	xAbsentOnCreateNode bool
	xPresentOnOtherNode bool
}

// ---- Exported live orchestrators (own the mutation lifecycle + cleanup) ---
//
// These are what the instrument (cmd/pveforge-harness-capture) calls per flag.
// Each performs the real mutations the capture needs, evaluates the gated facts
// via the capture method above, and cleans up the guests it created (DestroyVM +
// the gone oracle) before returning. They run live only; the tested invariant is
// the pure decider each one wraps.

// RunCloneVolidCapture does item 74 end to end: linked clone (full=0) of an
// existing template into cloneVMID, WaitForTask, capture, then destroy the clone
// and confirm it gone. The template is an execution precondition (OQ-5 — no
// `qm template` primitive exists in this package; the clone of a non-template is
// a PVE rejection, which surfaces here as the clone error, never a silent pass).
func (c *Client) RunCloneVolidCapture(ctx context.Context, node, storage string, templateVMID, cloneVMID int) (*CloneVolidCapture, error) {
	// full=0 is the linked clone; no `storage` override, so the clone lands on
	// the template's own storage (a linked clone cannot cross storage).
	upid, err := c.CloneVM(ctx, node, templateVMID, cloneVMID, url.Values{"full": {"0"}})
	if err != nil {
		return nil, fmt.Errorf("item-74: linked clone of template %d: %w", templateVMID, err)
	}
	if err := c.WaitForTask(ctx, node, upid); err != nil {
		return nil, fmt.Errorf("item-74: clone task did not finish OK: %w", err)
	}
	capt, cerr := c.CaptureCloneVolidIdentity(ctx, node, storage, templateVMID, cloneVMID)
	// Always surface a cleanup failure (N1): a failed capture must not silently
	// leave the clone behind to fail the next A-RO golden gate.
	if derr := c.destroyAndConfirmGone(ctx, node, cloneVMID); derr != nil {
		cerr = errors.Join(cerr, fmt.Errorf("item-74: clone cleanup: %w", derr))
	}
	return capt, cerr
}

// RunVmstateCapture does item 75 end to end on an existing stopped guest: start
// it (confirm running), take a vmstate=1 snapshot, capture the section, then
// delete the snapshot it created. The guest itself is the operator's and is NOT
// destroyed here.
func (c *Client) RunVmstateCapture(ctx context.Context, node, storage string, vmid int, snap string) (*SnapshotSectionCapture, error) {
	if err := c.startAndConfirmRunning(ctx, node, vmid); err != nil {
		return nil, err
	}
	if err := c.CreateSnapshot(ctx, node, vmid, snap, "batch-c item-75 vmstate capture"); err != nil {
		return nil, fmt.Errorf("item-75: create vmstate snapshot: %w", err)
	}
	capt, cerr := c.CaptureVmstateSection(ctx, node, storage, vmid, snap, "")
	// Always surface a cleanup failure (N1): a failed capture must not silently
	// leave the snapshot behind.
	if _, derr := c.CascadeDeleteSnapshots(ctx, node, vmid, []string{snap}); derr != nil {
		cerr = errors.Join(cerr, fmt.Errorf("item-75: snapshot cleanup: %w", derr))
	}
	return capt, cerr
}

// RunCrossNodeCapture does item 77 end to end: confirm the VMID is present on
// otherNode, attempt a colliding create on createNode, classify the outcome
// (POST StatusError, or task-exit + GetVM absence), run both nextid directions
// through the production vmidFree path, and destroy any accidental duplicate.
func (c *Client) RunCrossNodeCapture(ctx context.Context, takenVMID, freeVMID int, otherNode, createNode string) (*CrossNodeCreateCapture, error) {
	outcome := crossNodeCreateOutcome{}
	if vms, err := c.GetVMs(ctx, otherNode); err == nil {
		for _, v := range vms {
			if int(v.VMID) == takenVMID {
				outcome.xPresentOnOtherNode = true
			}
		}
	}

	upid, cerr := c.CreateVM(ctx, createNode, takenVMID, url.Values{"name": {fmt.Sprintf("c4-collide-%d", takenVMID)}})
	if cerr != nil {
		var se *StatusError
		if errors.As(cerr, &se) {
			outcome.postRejected = true
			outcome.code = se.Code
			outcome.body = string(se.Body)
		} else {
			outcome.body = cerr.Error() // e.g. a non-StatusError wrapping; recorded, not read as a rejection
		}
		outcome.xAbsentOnCreateNode = true // the POST failed, so no VM was created on createNode
	} else {
		// 2xx: wait for the create task, record its exitstatus, and check whether
		// a VM X actually materialised on createNode.
		_ = c.WaitForTask(ctx, createNode, upid) // its error is folded into the exitstatus read below
		if es, err := c.CaptureTaskExitStatus(ctx, createNode, upid); err == nil {
			outcome.taskExit = es.ExitStatus
		}
		// Absence counts ONLY when GetVM fails with the missing-VM subject
		// (NotFound) — not on a 403/transport/null-config error, which would
		// otherwise let a non-absence read as a rejection.
		if _, err := c.GetVM(ctx, createNode, takenVMID); err != nil && NotFound(err, VMConfigMissingSubject(takenVMID)) {
			outcome.xAbsentOnCreateNode = true
		}
	}

	capt, err := c.CaptureCrossNodeCreate(ctx, takenVMID, freeVMID, otherNode, createNode, outcome)
	// Cleanup: if a duplicate VM X was created on createNode, destroy it.
	if cerr == nil && !outcome.xAbsentOnCreateNode {
		_ = c.destroyAndConfirmGone(ctx, createNode, takenVMID)
	}
	return capt, err
}
