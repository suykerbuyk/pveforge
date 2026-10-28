package pve

import (
	"fmt"
	"sort"
	"strings"
)

// This file holds the item-75 (snapshot-section claimed-surface) gate as a pure
// decision over already-read values, in the PRODUCTION build (no harness tag) so
// CI's untagged `go test ./...` runs TestEvalSnapshotSection (F6). The live
// orchestration that feeds it — CaptureVmstateSection — stays harness-only. The
// capture structs and freePrefix live here too, since both the gate and the
// harness captures (item 74/75) reference them (same package pve).

// freePrefix is the exact prefix OrphanVolumesForVMID selects on
// (storageorphans.go): "<storage>:vm-<vmid>-". The captures record whether a
// volid matches it so the write-back can state the hazard→free linkage precisely.
func freePrefix(storage string, vmid int) string {
	return fmt.Sprintf("%s:vm-%d-", storage, vmid)
}

// SnapshotSectionCapture records item 75: the snapshot-section volids a running
// guest's vmstate snapshot creates, and whether the fix now CLAIMS each one that
// reproduces the free-path gap (absent from the live-config-only claim ∧ present
// in /content ∧ prefixed vm-<vmid>-).
type SnapshotSectionCapture struct {
	Storage       string   `json:"storage"`
	VMID          int      `json:"vmid"`
	Snapshot      string   `json:"snapshot"`
	SectionVolids []string `json:"section_volids"` // ALL disk+vmstate volids parsed from the snapshot section
	GapVolids     []string `json:"gap_volids"`     // raw-gap volids: absent-from-current-config-only ∧ in-/content ∧ prefixed
	Unclosed      []string `json:"unclosed"`       // raw-gap volids still ABSENT from the FULL claimed set (the fix regressed) — FAIL
	HibernateKey  string   `json:"hibernate_key"`  // best-effort current-config vmstate: value (may be empty)
	ContentMissed []string `json:"content_missed"` // absent-from-current section volids with NO /content row (FAIL)

	// LiveWitnessVolid / WitnessClaimed drive leg (c); exported and serialized so
	// the capture record shows whether the live-leg sanity check actually ran (F1).
	LiveWitnessVolid string `json:"live_witness_volid"`
	WitnessClaimed   bool   `json:"witness_claimed"`
}

// snapshotSectionInputs are the read values evalSnapshotSection decides on.
// Gap-CLOSED semantics (pveforge-claimed-volumes-snapshot-vmstate, B3/NEW-14):
// the capture proves the fix CLOSED the gap, not that the gap reproduces.
type snapshotSectionInputs struct {
	storage       string
	vmid          int
	snapshot      string
	sectionVolids []string
	// currentConfigOnlyClaim is the claimed set from the LIVE config only
	// (pending ∪ current, NO snapshots) — the pre-fix surface, against which a
	// raw gap is defined.
	currentConfigOnlyClaim map[string]bool
	// fullClaim is the new ClaimedVolumes (live + snapshots): every raw-gap
	// volid must now be present in it.
	fullClaim     map[string]bool
	contentVolids map[string]bool // set of /content Volids on the storage
	hibernateKey  string
	// liveWitnessVolid is a disk volid known-live BY CONSTRUCTION, identified by
	// slot from an INDEPENDENT typed read (diskSlotVolids/pickDiskSlot), not from
	// currentConfigOnlyClaim. "" when the VM has no live disk, which SKIPS leg (c).
	liveWitnessVolid string
}

// evalSnapshotSection is item 75's gap-CLOSED decision and mutation target. A
// raw gap is a section volid absent from the current-config-only claim AND
// present as a /content Volid AND carrying the free prefix — the shape the fix
// must now claim. Failures() gates on: (a) at least one raw gap exists
// (non-vacuity); (b) every raw gap is now in the full claimed set (closure);
// (c) a live-disk witness, when present, is in the current-config-only claim
// (the live leg did not silently go empty).
func evalSnapshotSection(in snapshotSectionInputs) *SnapshotSectionCapture {
	cap := &SnapshotSectionCapture{
		Storage:       in.storage,
		VMID:          in.vmid,
		Snapshot:      in.snapshot,
		SectionVolids: append([]string(nil), in.sectionVolids...),
		HibernateKey:  in.hibernateKey,
	}
	sort.Strings(cap.SectionVolids)
	prefix := freePrefix(in.storage, in.vmid)
	for _, v := range in.sectionVolids {
		if in.currentConfigOnlyClaim[v] {
			continue // claimed by the live config — not a gap the snapshot leg must close
		}
		if !in.contentVolids[v] {
			cap.ContentMissed = append(cap.ContentMissed, v)
			continue
		}
		if strings.HasPrefix(v, prefix) {
			cap.GapVolids = append(cap.GapVolids, v)
			if !in.fullClaim[v] {
				cap.Unclosed = append(cap.Unclosed, v)
			}
		}
	}
	sort.Strings(cap.GapVolids)
	sort.Strings(cap.Unclosed)
	sort.Strings(cap.ContentMissed)
	// Leg (c) is evaluated in Failures from the inputs it needs; stash them.
	cap.LiveWitnessVolid = in.liveWitnessVolid
	cap.WitnessClaimed = in.currentConfigOnlyClaim[in.liveWitnessVolid]
	return cap
}

// Failures gates item 75 under gap-CLOSED semantics. (a) No raw gap ⇒ the
// fixture never exercised the snapshot leg (vacuous) ⇒ FAIL. (b) A raw-gap volid
// still absent from the full claimed set ⇒ the fix regressed ⇒ FAIL. (c) A
// non-empty live witness absent from the current-config-only claim ⇒ the live
// leg silently went empty ⇒ FAIL. A content row missing for an absent volid ⇒
// FAIL. Hibernate key stays best-effort and never gates.
func (c *SnapshotSectionCapture) Failures() []string {
	var f []string
	for _, v := range c.ContentMissed {
		f = append(f, fmt.Sprintf("item-75: snapshot-section volid %q is absent from current config but has NO /content row (FAIL)", v))
	}
	if len(c.GapVolids) == 0 {
		f = append(f, fmt.Sprintf("item-75: no snapshot-section volid exercised the claimed-surface gap (absent-from-current-config ∧ in-/content ∧ prefixed %q) — fixture is vacuous", freePrefix(c.Storage, c.VMID)))
	}
	for _, v := range c.Unclosed {
		f = append(f, fmt.Sprintf("item-75: raw-gap volid %q is STILL absent from the full claimed set — the snapshot/vmstate claim regressed (FAIL)", v))
	}
	if c.LiveWitnessVolid != "" && !c.WitnessClaimed {
		f = append(f, fmt.Sprintf("item-75: live-disk witness %q is absent from the current-config-only claim — the live-config leg returned empty (FAIL)", c.LiveWitnessVolid))
	}
	return f
}
