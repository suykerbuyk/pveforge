//go:build harness

package pve

import (
	"context"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// row is a /content listing entry constructor for the fixtures.
func row(volid, parent string, vmid int, content string) *storageContentEntry {
	return &storageContentEntry{
		StorageContent: &proxmox.StorageContent{Volid: volid, Parent: parent, VMID: uint64(vmid)},
		Content:        content,
	}
}

// ---- C1 (74) ------------------------------------------------------------

func TestEvalCloneVolid(t *testing.T) {
	const storage = "local-lvm"
	const tpl, clone = 900, 905
	baseVolid := "local-lvm:base-900-disk-0"
	cloneVolid := "local-lvm:base-900-disk-0/vm-905-disk-0"

	base := func() cloneVolidInputs {
		return cloneVolidInputs{
			storage:        storage,
			templateVMID:   tpl,
			cloneVMID:      clone,
			cloneSlot:      "scsi0",
			cloneSlotVolid: cloneVolid,
			content: []*storageContentEntry{
				row(cloneVolid, baseVolid, clone, "images"),
				row(baseVolid, "", tpl, "images"),
			},
			templateClaim: map[string]bool{baseVolid: true},
		}
	}

	t.Run("good: all three facts hold, no failures", func(t *testing.T) {
		cap := evalCloneVolid(base())
		if !cap.IdentityHolds || !cap.ParentLinked || !cap.BaseClaimedByTemplate {
			t.Fatalf("facts = %+v", cap)
		}
		if cap.BaseMatchesFreePrefix {
			t.Errorf("base volid %q must NOT match the free prefix %q", cap.BaseContentVolid, freePrefix(storage, tpl))
		}
		if f := cap.Failures(); len(f) != 0 {
			t.Errorf("want no failures, got %v", f)
		}
	})

	// ANTI-VACUITY: a one-byte mismatch between the clone's config volid and its
	// /content Volid must drive IdentityHolds false and produce a failure. The
	// content row keeps the SAME disk name (vm-905-disk-0) so slot-resolution
	// still FINDS it — only the full volid differs (base-900 → base-901).
	t.Run("mutant: one-byte volid mismatch ⇒ IdentityHolds false, FAIL", func(t *testing.T) {
		in := base()
		in.content = []*storageContentEntry{
			row("local-lvm:base-901-disk-0/vm-905-disk-0", baseVolid, clone, "images"), // base-901, not base-900
			row(baseVolid, "", tpl, "images"),
		}
		cap := evalCloneVolid(in)
		if cap.IdentityHolds {
			t.Fatal("IdentityHolds must be false on a one-byte mismatch")
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure on identity mismatch")
		}
	})

	// ANTI-VACUITY (S1): Parent is a string that resolves to NO /content row,
	// while the template still has an images row. ParentLinked must be false —
	// there is NO template-VMID fallback that papers over the non-match.
	t.Run("mutant S1: Parent does not resolve ⇒ ParentLinked false, FAIL (no template fallback)", func(t *testing.T) {
		in := base()
		in.content = []*storageContentEntry{
			row(cloneVolid, "not-a-volid", clone, "images"), // Parent names no /content row
			row(baseVolid, "", tpl, "images"),               // the fallback would have grabbed this
		}
		cap := evalCloneVolid(in)
		if !cap.IdentityHolds {
			t.Fatalf("identity should still hold here (clone volid == its content volid): %+v", cap)
		}
		if cap.ParentLinked {
			t.Fatal("ParentLinked must be false when Parent resolves to no /content row")
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when Parent does not resolve")
		}
	})

	// ANTI-VACUITY (S2/B3): facts 1&2 met but the base is NOT in the template's
	// ClaimedVolumes ⇒ fact 3a FAILs.
	t.Run("mutant S2: base not claimed by template ⇒ FAIL", func(t *testing.T) {
		in := base()
		in.templateClaim = map[string]bool{} // base NOT claimed
		cap := evalCloneVolid(in)
		if !cap.IdentityHolds || !cap.ParentLinked {
			t.Fatalf("facts 1&2 should hold: %+v", cap)
		}
		if cap.BaseClaimedByTemplate {
			t.Fatal("BaseClaimedByTemplate must be false when templateClaim is empty")
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when the base is not claimed by the template")
		}
	})

	// ANTI-VACUITY: an empty Parent (a full clone) must FAIL — no degrade.
	t.Run("mutant: empty Parent ⇒ ParentLinked false, FAIL (no degrade)", func(t *testing.T) {
		in := base()
		in.content = []*storageContentEntry{
			row(cloneVolid, "", clone, "images"), // Parent empty
			row(baseVolid, "", tpl, "images"),
		}
		cap := evalCloneVolid(in)
		if cap.ParentLinked {
			t.Fatal("ParentLinked must be false when Parent is empty")
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when Parent is empty (OQ-5: no degrade-to-full-clone)")
		}
	})

	// A clone disk silently dropped from /content must FAIL, not read as identity.
	t.Run("clone content row absent ⇒ FAIL", func(t *testing.T) {
		in := base()
		in.content = []*storageContentEntry{row(baseVolid, "", tpl, "images")} // no clone row
		cap := evalCloneVolid(in)
		if cap.IdentityHolds || cap.CloneContentVolid != "" {
			t.Fatalf("absent clone row must not read as identity: %+v", cap)
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when the clone's content row is absent")
		}
	})
}

// ---- C2 (75) ------------------------------------------------------------

func TestEvalSnapshotSection(t *testing.T) {
	const storage = "local-lvm"
	const vmid = 905
	stateVolid := "local-lvm:vm-905-state-snap1"
	diskVolid := "local-lvm:vm-905-disk-0"

	base := func() snapshotSectionInputs {
		return snapshotSectionInputs{
			storage:       storage,
			vmid:          vmid,
			snapshot:      "snap1",
			sectionVolids: []string{diskVolid, stateVolid},
			currentClaim:  map[string]bool{diskVolid: true}, // disk is in current config; state is NOT
			contentVolids: map[string]bool{diskVolid: true, stateVolid: true},
		}
	}

	t.Run("good: the state volid reproduces the gap", func(t *testing.T) {
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

	// ANTI-VACUITY: if the state volid is ALSO in current config, the gap is not
	// reproduced ⇒ FAIL. (A decider that ignored current-config membership would
	// wrongly pass here.)
	t.Run("mutant: section volid in current config ⇒ gap NOT reproduced, FAIL", func(t *testing.T) {
		in := base()
		in.currentClaim = map[string]bool{diskVolid: true, stateVolid: true}
		cap := evalSnapshotSection(in)
		if len(cap.GapVolids) != 0 {
			t.Fatalf("GapVolids = %v, want empty (both volids claimed)", cap.GapVolids)
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when no section volid is absent-from-current")
		}
	})

	// ANTI-VACUITY: an absent-from-current section volid with NO /content row ⇒ FAIL.
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
}

// snapshotSectionVolids parses disk+vmstate values with the first-comma rule.
func TestSnapshotSectionParse_FirstComma(t *testing.T) {
	// Not a network test: exercise firstCommaVolid on the shapes the parser feeds.
	for _, tc := range []struct{ in, want string }{
		{"local-lvm:vm-905-disk-0,size=32G", "local-lvm:vm-905-disk-0"},
		{"local-lvm:vm-905-state-snap1", "local-lvm:vm-905-state-snap1"},
		{"none", ""},
		{"/dev/sdb", ""},
	} {
		if got := firstCommaVolid(tc.in); got != tc.want {
			t.Errorf("firstCommaVolid(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- C3 (76) ------------------------------------------------------------

func TestEvalShortList(t *testing.T) {
	t.Run("good: M<N and hidden volume orphan-only-under-restricted", func(t *testing.T) {
		cap := &TokenShortListCapture{
			FullLen: 2, RestrictedLen: 1,
			HiddenOrphanVolid:     "local-lvm:vm-777-disk-0",
			OrphanUnderRestricted: true, OrphanUnderFull: false,
		}
		shorter, orphan := evalShortList(shortListInputs{
			fullLen: 2, restrictedLen: 1,
			hiddenOrphanVolid: "local-lvm:vm-777-disk-0", orphanUnderRestricted: true, orphanUnderFull: false,
		})
		if !shorter || !orphan {
			t.Fatalf("shorter=%v orphan=%v, want both true", shorter, orphan)
		}
		if f := cap.Failures(); len(f) != 0 {
			t.Errorf("want no failures, got %v", f)
		}
	})

	// ANTI-VACUITY (B1): a valid short list (M<N, not typed) with the orphan fact
	// UNMET — the volume is ALSO an orphan under the full client, so it is not a
	// data-loss-only-under-restricted volume ⇒ Failures non-empty, with the
	// orphan gate as the SOLE failing condition (length is fine).
	t.Run("mutant B1: orphan fact unmet ⇒ FAIL (orphan gate is the sole failure)", func(t *testing.T) {
		in := shortListInputs{fullLen: 2, restrictedLen: 1,
			hiddenOrphanVolid: "local-lvm:vm-777-disk-0", orphanUnderRestricted: true, orphanUnderFull: true}
		if shorter, orphan := evalShortList(in); !shorter || orphan {
			t.Fatalf("want shorter=true, orphan=false; got shorter=%v orphan=%v", shorter, orphan)
		}
		cap := &TokenShortListCapture{
			FullLen: 2, RestrictedLen: 1, HiddenVMID: 777,
			HiddenOrphanVolid:     "local-lvm:vm-777-disk-0",
			OrphanUnderRestricted: true, OrphanUnderFull: true,
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when the orphan fact is unmet, even with M<N")
		}
	})

	// S4: a non-nil OrphanVolumesForVMID error (ScanError) is an UNREAD scan ⇒
	// FAIL, never silently read as "not an orphan".
	t.Run("S4: scan error ⇒ FAIL (unread scan)", func(t *testing.T) {
		cap := &TokenShortListCapture{
			FullLen: 2, RestrictedLen: 1, HiddenVMID: 777,
			HiddenOrphanVolid:     "local-lvm:vm-777-disk-0",
			OrphanUnderRestricted: true, OrphanUnderFull: false,
			ScanError: "restricted OrphanVolumesForVMID(777): boom",
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("a scan error must fail the capture")
		}
	})

	// ANTI-VACUITY: M==N ⇒ truncation NOT reproduced ⇒ FAIL.
	t.Run("mutant: M==N ⇒ FAIL", func(t *testing.T) {
		if shorter, _ := evalShortList(shortListInputs{fullLen: 2, restrictedLen: 2}); shorter {
			t.Fatal("M==N must not read as shorter")
		}
		cap := &TokenShortListCapture{FullLen: 2, RestrictedLen: 2,
			HiddenOrphanVolid: "x", OrphanUnderRestricted: true}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure on M==N")
		}
	})

	// A typed (403) restricted read is a FAIL, never a short list.
	t.Run("mutant: restricted typed error (403) ⇒ FAIL, not short list", func(t *testing.T) {
		if shorter, _ := evalShortList(shortListInputs{fullLen: 2, restrictedLen: 0, restrictedTyped: true}); shorter {
			t.Fatal("a typed error must not read as a short list")
		}
		cap := &TokenShortListCapture{RestrictedTyped: true, RestrictedErr: "403"}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure on a typed restricted error")
		}
	})
}

// The live two-client method returns early (RestrictedTyped) when the restricted
// token 403s — proving a 403 is a FAIL, not a short list — without touching the
// orphan plumbing.
func TestCaptureTokenShortList_403IsFail(t *testing.T) {
	ctx := context.Background()
	full := amutClient(t, "200 OK", `{"data":[{"vmid":100},{"vmid":101}]}`)
	restricted := amutClient(t, "403 Permission check failed", `{"data":null}`)
	cap, err := full.CaptureTokenShortList(ctx, restricted, "pvh-n1", "local-lvm", "root@pam!pvh-n1", "restricted@pve!ro", "local-lvm:vm-101-disk-0", 101)
	if err != nil {
		t.Fatalf("CaptureTokenShortList: %v", err)
	}
	if !cap.RestrictedTyped {
		t.Fatalf("want RestrictedTyped on a 403, got %+v", cap)
	}
	if len(cap.Failures()) == 0 {
		t.Fatal("a 403 must be a capture failure")
	}
}

// ---- C4 (77) ------------------------------------------------------------

func TestEvalCrossNodeCreate(t *testing.T) {
	t.Run("good: POST rejected ⇒ createRejected", func(t *testing.T) {
		if !evalCrossNodeCreate(crossNodeInputs{postRejected: true}) {
			t.Fatal("a POST StatusError is a rejection")
		}
	})
	t.Run("good: 2xx but task not OK and X absent ⇒ createRejected", func(t *testing.T) {
		if !evalCrossNodeCreate(crossNodeInputs{taskExit: "ERROR", xAbsentOnCreateNode: true}) {
			t.Fatal("a failed task + absent VM is a rejection")
		}
	})
	// ANTI-VACUITY: a 2xx whose task exits OK is a FAIL (a duplicate was created).
	t.Run("mutant: 2xx + task OK ⇒ NOT rejected, FAIL", func(t *testing.T) {
		if evalCrossNodeCreate(crossNodeInputs{taskExit: "OK", xAbsentOnCreateNode: false}) {
			t.Fatal("a 2xx whose task exits OK must NOT read as rejected")
		}
		cap := &CrossNodeCreateCapture{
			TakenVMID: 905, OtherNode: "pvh-n2", CreateNode: "pvh-n1",
			PostRejected: false, TaskExit: "OK", XAbsentOnCreateNode: false,
			XPresentOnOtherNode: true, NextidTakenSaysTaken: true, NextidFreeSaysFree: true,
		}
		if len(cap.Failures()) == 0 {
			t.Fatal("want a failure when a duplicate create succeeded")
		}
	})

	okCap := func(taskExit string, xAbsent bool) *CrossNodeCreateCapture {
		return &CrossNodeCreateCapture{
			TakenVMID: 905, OtherNode: "pvh-n2", CreateNode: "pvh-n1",
			PostRejected: false, TaskExit: taskExit, XAbsentOnCreateNode: xAbsent,
			XPresentOnOtherNode: true, NextidTakenSaysTaken: true, NextidFreeSaysFree: true,
		}
	}

	// ANTI-VACUITY (B2/S3): task not-OK but X still PRESENT ⇒ NOT a rejection
	// (kills dropping the `&& xAbsent` conjunct, and `&&`→`||`).
	t.Run("mutant B2/S3: task ERROR but X present (xAbsent=false) ⇒ NOT rejected, FAIL", func(t *testing.T) {
		if evalCrossNodeCreate(crossNodeInputs{taskExit: "ERROR", xAbsentOnCreateNode: false}) {
			t.Fatal("task not-OK but X still present must NOT read as rejected")
		}
		if len(okCap("ERROR", false).Failures()) == 0 {
			t.Fatal("want a failure when X is still present after a non-OK task")
		}
	})

	// ANTI-VACUITY (S3): an empty/unread taskExit must NOT count as a rejection.
	t.Run("mutant S3: empty taskExit ⇒ NOT rejected, FAIL", func(t *testing.T) {
		if evalCrossNodeCreate(crossNodeInputs{taskExit: "", xAbsentOnCreateNode: true}) {
			t.Fatal("an empty/unread taskExit must NOT read as rejected")
		}
		if len(okCap("", true).Failures()) == 0 {
			t.Fatal("want a failure when taskExit is empty/unread")
		}
	})

	// ANTI-VACUITY (S3): WARNINGS: n is a SUCCESS (taskExitSucceeded), so a create
	// that "succeeded with warnings" is a duplicate ⇒ NOT a rejection ⇒ FAIL.
	t.Run("WARNINGS: n is a success ⇒ NOT rejected, FAIL", func(t *testing.T) {
		if evalCrossNodeCreate(crossNodeInputs{taskExit: "WARNINGS: 1", xAbsentOnCreateNode: false}) {
			t.Fatal("a WARNINGS: n task is a SUCCESS, not a rejection")
		}
		if len(okCap("WARNINGS: 1", false).Failures()) == 0 {
			t.Fatal("want a failure when the create succeeded with warnings (a duplicate)")
		}
	})
}

// The nextid legs go through the production vmidFree/isVMIDTakenError path.
func TestCaptureCrossNodeCreate_NextidBothDirections(t *testing.T) {
	ctx := context.Background()
	// taken: /cluster/nextid?vmid=905 → 400 whose reason phrase carries the
	// classifier's text (over HTTP/1.1, as the production code relies on).
	taken := amutClient(t, "400 VM 905 already exists", `{"data":null}`)
	gotTaken, err := taken.vmidFree(ctx, 905)
	if err != nil {
		t.Fatalf("vmidFree(taken): unexpected error %v", err)
	}
	if gotTaken {
		t.Fatal("taken VMID must classify as NOT free (isVMIDTakenError)")
	}
	// free: /cluster/nextid?vmid=906 → the id itself.
	free := amutClient(t, "200 OK", `{"data":"906"}`)
	gotFree, err := free.vmidFree(ctx, 906)
	if err != nil {
		t.Fatalf("vmidFree(free): %v", err)
	}
	if !gotFree {
		t.Fatal("free VMID must classify as free")
	}
}
