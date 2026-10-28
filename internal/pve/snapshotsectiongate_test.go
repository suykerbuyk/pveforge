package pve

import "testing"

// TestEvalSnapshotSection is UNTAGGED (F6) so CI's `go test ./...` runs the
// item-75 gate decision; it previously sat behind //go:build harness and CI
// never executed it. The gate function moved to the untagged
// snapshotsectiongate.go for the same reason.
func TestEvalSnapshotSection(t *testing.T) {
	const storage = "local-lvm"
	const vmid = 905
	stateVolid := "local-lvm:vm-905-state-snap1"
	diskVolid := "local-lvm:vm-905-disk-0"

	// Gap-CLOSED base: stateVolid is the raw gap (absent from the live-config-
	// only claim, present in /content, prefixed) and the FULL claim now contains
	// it — the fix closed it. diskVolid is the live-disk witness, present in the
	// current-config-only claim.
	base := func() snapshotSectionInputs {
		return snapshotSectionInputs{
			storage:                storage,
			vmid:                   vmid,
			snapshot:               "snap1",
			sectionVolids:          []string{diskVolid, stateVolid},
			currentConfigOnlyClaim: map[string]bool{diskVolid: true}, // disk is in live config; state is NOT
			fullClaim:              map[string]bool{diskVolid: true, stateVolid: true},
			contentVolids:          map[string]bool{diskVolid: true, stateVolid: true},
			liveWitnessVolid:       diskVolid,
		}
	}

	t.Run("good: the raw gap is closed by the full claim", func(t *testing.T) {
		cap := evalSnapshotSection(base())
		if len(cap.GapVolids) != 1 || cap.GapVolids[0] != stateVolid {
			t.Fatalf("GapVolids = %v, want [%s]", cap.GapVolids, stateVolid)
		}
		if len(cap.SectionVolids) != 2 {
			t.Errorf("must record ALL section volids, got %v", cap.SectionVolids)
		}
		if f := cap.Failures(); len(f) != 0 {
			t.Errorf("want no failures, got %v", f)
		}
	})

	// REGRESSION: the raw-gap volid is NOT in the full claim ⇒ the fix regressed ⇒ FAIL.
	t.Run("mutant: raw gap not in full claim ⇒ FAIL", func(t *testing.T) {
		in := base()
		in.fullClaim = map[string]bool{diskVolid: true} // stateVolid dropped — snapshot/vmstate claim regressed
		cap := evalSnapshotSection(in)
		if len(cap.Unclosed) != 1 || cap.Unclosed[0] != stateVolid {
			t.Fatalf("Unclosed = %v, want [%s]", cap.Unclosed, stateVolid)
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when a raw-gap volid is absent from the full claim")
		}
	})

	// ANTI-VACUITY: if the state volid is ALSO in the live config, there is no raw
	// gap to prove closure on ⇒ FAIL.
	t.Run("mutant: section volid in live config ⇒ vacuous fixture, FAIL", func(t *testing.T) {
		in := base()
		in.currentConfigOnlyClaim = map[string]bool{diskVolid: true, stateVolid: true}
		in.fullClaim = map[string]bool{diskVolid: true, stateVolid: true}
		cap := evalSnapshotSection(in)
		if len(cap.GapVolids) != 0 {
			t.Fatalf("GapVolids = %v, want empty (both volids in live config)", cap.GapVolids)
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when no section volid is a raw gap")
		}
	})

	// ANTI-VACUITY: an absent-from-live section volid with NO /content row ⇒ FAIL.
	t.Run("mutant: content row missing ⇒ FAIL", func(t *testing.T) {
		in := base()
		in.contentVolids = map[string]bool{diskVolid: true} // state volid NOT in content
		cap := evalSnapshotSection(in)
		if len(cap.ContentMissed) != 1 || cap.ContentMissed[0] != stateVolid {
			t.Fatalf("ContentMissed = %v, want [%s]", cap.ContentMissed, stateVolid)
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when the content row is missing")
		}
	})

	// LEG (c) present: a live witness absent from the current-config-only claim ⇒
	// the live-config leg silently went empty ⇒ FAIL.
	t.Run("leg c: live witness absent from current-only claim ⇒ FAIL", func(t *testing.T) {
		in := base()
		in.currentConfigOnlyClaim = map[string]bool{} // live leg returned empty
		cap := evalSnapshotSection(in)
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when the live witness is absent from the current-only claim")
		}
	})

	// LEG (c) skip: a diskless/detached fixture (no witness) must not false-FAIL.
	t.Run("leg c: empty witness is skipped, detached-disk-only passes", func(t *testing.T) {
		in := base()
		in.liveWitnessVolid = ""                      // no live disk to witness
		in.currentConfigOnlyClaim = map[string]bool{} // disk detached from live config
		in.sectionVolids = []string{stateVolid}       // only the raw gap remains
		in.contentVolids = map[string]bool{stateVolid: true}
		in.fullClaim = map[string]bool{stateVolid: true} // closed
		cap := evalSnapshotSection(in)
		if f := cap.Failures(); len(f) != 0 {
			t.Errorf("want no failures for a witness-skipped closed gap, got %v", f)
		}
	})
}
