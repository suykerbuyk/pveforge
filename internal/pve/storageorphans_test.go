package pve

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// --- ClaimedVolumes ---------------------------------------------------

func TestClaimedVolumes_ParsesEveryDiskShapedSlotAndScalar(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/qemu/105/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/105/config":
			_, _ = w.Write([]byte(`{"data":{
				"digest": "abc123",
				"scsi0": "local-lvm:vm-105-disk-0,size=32G",
				"sata0": "local-lvm:vm-105-disk-5,size=16G",
				"virtio1": "local-lvm:vm-105-disk-1,size=8G",
				"unused0": "local-lvm:vm-105-disk-2",
				"unused1": "/dev/sdb",
				"efidisk0": "local-lvm:vm-105-disk-3,size=4M",
				"tpmstate0": "local-lvm:vm-105-disk-4,size=4M",
				"ide2": "none,media=cdrom",
				"scsihw": "virtio-scsi-pci"
			}}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	claimed, err := c.ClaimedVolumes(context.Background(), "qa-pve-01", 105)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}

	want := []string{
		"local-lvm:vm-105-disk-0",
		"local-lvm:vm-105-disk-1",
		"local-lvm:vm-105-disk-2",
		"local-lvm:vm-105-disk-3",
		"local-lvm:vm-105-disk-4",
		"local-lvm:vm-105-disk-5",
	}
	if len(claimed) != len(want) {
		t.Fatalf("claimed = %v, want exactly %v", claimed, want)
	}
	for _, volid := range want {
		if !claimed[volid] {
			t.Errorf("expected claimed[%q] to be true", volid)
		}
	}
	// scsihw's value must never be mistaken for a SCSIs entry (it isn't
	// one of go-proxmox's indexed maps at all), ide2's "none" must
	// contribute nothing, and unused1's colon-less physical-passthrough
	// path must be excluded.
	for _, bad := range []string{"virtio-scsi-pci", "none", "/dev/sdb"} {
		if claimed[bad] {
			t.Errorf("claimed set must not contain %q", bad)
		}
	}
}

// TestClaimedVolumes_OnlyDiskBearingIndexedMapsContribute pins, as a
// named, walkable list, exactly which of go-proxmox@v0.8.1's 12 indexed
// device-map key families ClaimedVolumes consults: ide*/scsi*/sata*/
// virtio*/unused* (5), and NOT net*/numa*/hostpci*/serial*/usb*/
// parallel*/ipconfig* (7) — confirmed by direct source inspection that
// only the first five ever carry a volid. Every family here is given a
// colon-bearing value, so this assertion is entirely about WHICH MAPS
// ClaimedVolumes iterates, not about the separate ":" heuristic that
// excludes non-storage scalar values. Mutation-test target: dropping any
// of the 5 included maps from the iteration (e.g. cfg.SATAs) makes this
// test fail; accidentally adding one of the 7 excluded maps also makes
// it fail.
func TestClaimedVolumes_OnlyDiskBearingIndexedMapsContribute(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/qemu/110/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/110/config":
			_, _ = w.Write([]byte(`{"data":{
				"ide0":      "fake:disk-ide",
				"scsi0":     "fake:disk-scsi",
				"sata0":     "fake:disk-sata",
				"virtio0":   "fake:disk-virtio",
				"unused0":   "fake:disk-unused",
				"net0":      "fake:not-a-disk-net",
				"numa0":     "fake:not-a-disk-numa",
				"hostpci0":  "fake:not-a-disk-hostpci",
				"serial0":   "fake:not-a-disk-serial",
				"usb0":      "fake:not-a-disk-usb",
				"parallel0": "fake:not-a-disk-parallel",
				"ipconfig0": "fake:not-a-disk-ipconfig"
			}}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	claimed, err := c.ClaimedVolumes(context.Background(), "qa-pve-01", 110)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}

	wantIncluded := []string{
		"fake:disk-ide", "fake:disk-scsi", "fake:disk-sata", "fake:disk-virtio", "fake:disk-unused",
	}
	if len(claimed) != len(wantIncluded) {
		t.Fatalf("claimed = %v, want exactly the 5 disk-bearing entries %v", claimed, wantIncluded)
	}
	for _, v := range wantIncluded {
		if !claimed[v] {
			t.Errorf("expected claimed[%q] = true (disk-bearing indexed map)", v)
		}
	}

	wantExcluded := []string{
		"fake:not-a-disk-net", "fake:not-a-disk-numa", "fake:not-a-disk-hostpci",
		"fake:not-a-disk-serial", "fake:not-a-disk-usb", "fake:not-a-disk-parallel",
		"fake:not-a-disk-ipconfig",
	}
	for _, v := range wantExcluded {
		if claimed[v] {
			t.Errorf("claimed set must not contain %q — its indexed map never carries a volid", v)
		}
	}
}

func TestClaimedVolumes_PropagatesConfigFetchError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/qemu/999/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/999/config":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("config fetch exploded"))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	claimed, err := c.ClaimedVolumes(context.Background(), "qa-pve-01", 999)
	if err == nil {
		t.Fatal("expected an error when the config fetch fails")
	}
	if claimed != nil {
		t.Errorf("expected a nil map alongside the error, got %v", claimed)
	}
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("expected the vmid to appear in the error, got: %v", err)
	}
}

// --- storageContentEntry decode proof ----------------------------------

// TestStorageContentEntry_DecodePopulatesContentField is the reviewer-
// required regression guard for the content-type fix itself: an
// embedded-pointer JSON decode can silently leave the added field zero
// depending on how the embedding is wired, which would quietly
// reintroduce the exact false-positive-orphan bug the fix exists to
// remove. This asserts on the DECODED VALUES, not just that decoding
// succeeds without error — reverting storageContentEntry to a plain,
// non-embedded copy of proxmox.StorageContent (dropping Content) makes
// this test fail.
func TestStorageContentEntry_DecodePopulatesContentField(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"volid":"local-lvm:vm-100-disk-0","vmid":100,"content":"images","size":34359738368},
			{"volid":"local-lvm:iso/debian.iso","content":"iso","size":1073741824},
			{"volid":"local-lvm:backup/vzdump-qemu-999-2026_01_01.vma.zst","vmid":999,"content":"backup"},
			{"volid":"local-lvm:vztmpl/debian-12-standard.tar.zst","content":"vztmpl"}
		]}`))
	})
	c := testClient(t, srv)

	entries, err := c.storageContentWithType(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("storageContentWithType: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}

	wantContent := []string{"images", "iso", "backup", "vztmpl"}
	wantVolid := []string{
		"local-lvm:vm-100-disk-0",
		"local-lvm:iso/debian.iso",
		"local-lvm:backup/vzdump-qemu-999-2026_01_01.vma.zst",
		"local-lvm:vztmpl/debian-12-standard.tar.zst",
	}
	for i, e := range entries {
		if e.StorageContent == nil {
			t.Fatalf("entry %d: embedded *proxmox.StorageContent is nil — the promoted fields never got allocated", i)
		}
		if e.Content != wantContent[i] {
			t.Errorf("entry %d: Content = %q, want %q", i, e.Content, wantContent[i])
		}
		if e.Volid != wantVolid[i] {
			t.Errorf("entry %d: Volid = %q, want %q", i, e.Volid, wantVolid[i])
		}
	}
	if entries[0].VMID != 100 {
		t.Errorf("entry 0: VMID = %d, want 100", entries[0].VMID)
	}
}

// --- OrphanVolumes ------------------------------------------------------

// orphanScenarioHandler builds the fake server for the main OrphanVolumes
// scenario shared by several tests below: storage "local-lvm" on node
// "qa-pve-01", not shared; two live VMs (100 claims its own disk and an
// attached ISO, 101 claims nothing); four content entries covering all
// four relevant content-type buckets. contentOrder lets a caller request
// the content array in a different element order without changing what
// it contains, to prove OrphanVolumes' own output ordering doesn't depend
// on the server's.
func orphanScenarioHandler(t *testing.T, contentReversed bool) http.HandlerFunc {
	t.Helper()
	forward := `[
		{"volid":"local-lvm:vm-100-disk-0","vmid":100,"content":"images"},
		{"volid":"local-lvm:iso/debian.iso","content":"iso"},
		{"volid":"local-lvm:vm-102-disk-0","vmid":102,"content":"images"},
		{"volid":"local-lvm:backup/vzdump-qemu-999-2026_01_01.vma.zst","vmid":999,"content":"backup"},
		{"volid":"local-lvm:vztmpl/debian-12-standard.tar.zst","content":"vztmpl"}
	]`
	reversed := `[
		{"volid":"local-lvm:vztmpl/debian-12-standard.tar.zst","content":"vztmpl"},
		{"volid":"local-lvm:backup/vzdump-qemu-999-2026_01_01.vma.zst","vmid":999,"content":"backup"},
		{"volid":"local-lvm:vm-102-disk-0","vmid":102,"content":"images"},
		{"volid":"local-lvm:iso/debian.iso","content":"iso"},
		{"volid":"local-lvm:vm-100-disk-0","vmid":100,"content":"images"}
	]`
	content := forward
	if contentReversed {
		content = reversed
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":` + content + `}`))
		case "/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[{"vmid":100},{"vmid":101}]}`))
		case "/nodes/qa-pve-01/qemu/100/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"scsi0":"local-lvm:vm-100-disk-0,size=32G"}}`))
		case "/nodes/qa-pve-01/qemu/101/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/101/config":
			_, _ = w.Write([]byte(`{"data":{"ide2":"local-lvm:iso/debian.iso,media=cdrom"}}`))
		default:
			http.NotFound(w, r)
		}
	}
}

func TestOrphanVolumes_ExcludesClaimedBackupAndVztmplIncludesRealOrphan(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, orphanScenarioHandler(t, false)))

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("OrphanVolumes: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("got %d orphans, want exactly 1: %+v", len(orphans), orphans)
	}
	if orphans[0].Volid != "local-lvm:vm-102-disk-0" {
		t.Errorf("orphan = %q, want local-lvm:vm-102-disk-0", orphans[0].Volid)
	}
}

// TestOrphanVolumes_DeterministicDespiteContentReordering is the direct
// regression test for the epic's own cited hazard: PVE's /storage
// content listing has no stable element order between two calls against
// an unchanged target. Reverting OrphanVolumes' own sort-before-return
// would make this test flaky/fail whenever the two orderings above
// happen to produce different orphan slice ordering.
func TestOrphanVolumes_DeterministicDespiteContentReordering(t *testing.T) {
	c1 := testClient(t, newFakeAPIServer(t, orphanScenarioHandler(t, false)))
	c2 := testClient(t, newFakeAPIServer(t, orphanScenarioHandler(t, true)))

	orphans1, err := c1.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("OrphanVolumes (forward order): %v", err)
	}
	orphans2, err := c2.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("OrphanVolumes (reversed order): %v", err)
	}

	if len(orphans1) != len(orphans2) {
		t.Fatalf("result length differs: %d vs %d", len(orphans1), len(orphans2))
	}
	for i := range orphans1 {
		if orphans1[i].Volid != orphans2[i].Volid {
			t.Errorf("result[%d] differs by input order: %q vs %q", i, orphans1[i].Volid, orphans2[i].Volid)
		}
	}
}

func TestOrphanVolumes_PropagatesContentFetchError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("content listing exploded"))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err == nil {
		t.Fatal("expected an error when the content fetch fails")
	}
	if orphans != nil {
		t.Errorf("expected a nil result alongside the error, got %+v", orphans)
	}
}

func TestOrphanVolumes_PropagatesGetVMsError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/nodes/qa-pve-01/qemu":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("vm list exploded"))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err == nil {
		t.Fatal("expected an error when GetVMs fails")
	}
	if orphans != nil {
		t.Errorf("expected a nil result alongside the error, got %+v", orphans)
	}
}

// TestOrphanVolumes_AbortsWholeCallWhenAnySingleClaimedSetFails is the
// Chair's core fail-closed requirement: a single unreachable VM must
// never make its own disks (or anyone else's) look orphaned by silently
// contributing an empty claimed-set for itself while the rest of the
// diff proceeds. Mutation-test target: reverting the abort-on-first-
// claimed-error path to "log and continue with an empty set for that
// vmid" must make this test fail.
func TestOrphanVolumes_AbortsWholeCallWhenAnySingleClaimedSetFails(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`))
		case "/nodes/qa-pve-01/storage/local-lvm/content":
			// This volume genuinely belongs to VM 101, whose claimed set
			// we are about to fail to read. A buggy "continue on error"
			// implementation would report this as an orphan; the correct
			// implementation must abort before ever computing a diff.
			_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-101-disk-0","vmid":101,"content":"images"}]}`))
		case "/nodes/qa-pve-01/qemu":
			_, _ = w.Write([]byte(`{"data":[{"vmid":100},{"vmid":101}]}`))
		case "/nodes/qa-pve-01/qemu/100/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
		case "/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{}}`))
		case "/nodes/qa-pve-01/qemu/101/status/current":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("vm 101 status fetch exploded"))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err == nil {
		t.Fatalf("expected the whole call to error, got a result: %+v", orphans)
	}
	if !strings.Contains(err.Error(), "101") {
		t.Errorf("expected the failing vmid (101) to appear in the error, got: %v", err)
	}
	if orphans != nil {
		t.Errorf("expected a nil result alongside the error, got %+v", orphans)
	}
}

// TestOrphanVolumes_RefusesSharedStorage is the Chair's required
// fail-closed shared-storage gate: a shared storage's content listing
// reflects volumes claimed by VMs on OTHER cluster nodes, invisible to
// this function's node-scoped claimed set. Mutation-test target: removing
// the Shared check must make this test fail (it would instead see the
// content/qemu endpoints called and likely misreport an orphan).
func TestOrphanVolumes_RefusesSharedStorage(t *testing.T) {
	var contentHits, qemuHits int32
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/nfs-shared/status":
			_, _ = w.Write([]byte(`{"data":{"storage":"nfs-shared","type":"nfs","shared":1}}`))
		case "/nodes/qa-pve-01/storage/nfs-shared/content":
			atomic.AddInt32(&contentHits, 1)
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/nodes/qa-pve-01/qemu":
			atomic.AddInt32(&qemuHits, 1)
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	orphans, err := c.OrphanVolumes(context.Background(), "qa-pve-01", "nfs-shared")
	if err == nil {
		t.Fatalf("expected a refusal error for a shared storage, got a result: %+v", orphans)
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("expected the error to name shared storage as the reason, got: %v", err)
	}
	if orphans != nil {
		t.Errorf("expected a nil result alongside the refusal, got %+v", orphans)
	}
	if got := atomic.LoadInt32(&contentHits); got != 0 {
		t.Errorf("expected the content endpoint to never be called for a shared storage, got %d hits", got)
	}
	if got := atomic.LoadInt32(&qemuHits); got != 0 {
		t.Errorf("expected the qemu list endpoint to never be called for a shared storage, got %d hits", got)
	}
}

func TestOrphanVolumes_RequiresNodeAndStorage(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network for a missing node/storage")
	}))
	if _, err := c.OrphanVolumes(context.Background(), "", "local-lvm"); err == nil {
		t.Fatal("expected an error for an empty node")
	}
	if _, err := c.OrphanVolumes(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected an error for an empty storage")
	}
}

// --- OrphanVolumesForVMID -----------------------------------------------

func TestOrphanVolumesForVMID_NarrowsToNamingConvention(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, orphanScenarioHandler(t, false)))

	matched, err := c.OrphanVolumesForVMID(context.Background(), "qa-pve-01", "local-lvm", 102)
	if err != nil {
		t.Fatalf("OrphanVolumesForVMID: %v", err)
	}
	if len(matched) != 1 || matched[0].Volid != "local-lvm:vm-102-disk-0" {
		t.Fatalf("unexpected result: %+v", matched)
	}

	// A vmid with no matching orphan (e.g. 999, which only appears as a
	// backup, never as a vm-<vmid>- prefixed disk) must report none.
	matched, err = c.OrphanVolumesForVMID(context.Background(), "qa-pve-01", "local-lvm", 999)
	if err != nil {
		t.Fatalf("OrphanVolumesForVMID: %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("expected no matches for vmid 999, got %+v", matched)
	}
}

func TestOrphanVolumesForVMID_PropagatesOrphanVolumesError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/nodes/qa-pve-01/storage/nfs-shared/status" {
			_, _ = w.Write([]byte(`{"data":{"storage":"nfs-shared","type":"nfs","shared":1}}`))
			return
		}
		t.Error("should not reach any endpoint beyond the storage status check")
	})
	c := testClient(t, srv)

	matched, err := c.OrphanVolumesForVMID(context.Background(), "qa-pve-01", "nfs-shared", 102)
	if err == nil {
		t.Fatalf("expected the shared-storage refusal to propagate, got a result: %+v", matched)
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("expected the propagated error to still name shared storage, got: %v", err)
	}
}
