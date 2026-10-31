package idempotent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// TestVolumeFreeOrphans_Read_SelectorGuards is F1: VolumeFreeOrphans.Read is
// fail-closed in the Op itself. (a) exactly one of ClusterPairs / CompleteVMIDs
// must be set — both or neither refuse; (b) a node-scoped CompleteVMIDs free on
// SHARED storage refuses in the Op (not only via a downstream refuseIfShared or
// the CLI). A node-scoped free on UNSHARED storage is allowed and proceeds.
//
// Mutation target: removing the XOR guard lets "both set" scan (ambiguous
// selector); removing the shared guard lets a node-scoped CompleteVMIDs free a
// shared storage. Each case below goes RED under its guard's removal.
func TestVolumeFreeOrphans_Read_SelectorGuards(t *testing.T) {
	base := func() *fakeStorageClient { return &fakeStorageClient{node: "A"} }

	t.Run("both selectors set refuses", func(t *testing.T) {
		op := &VolumeFreeOrphans{Client: base(), Scanner: base(), Storage: "s", VMID: 700,
			ClusterPairs: []pve.NodeVMID{{Node: "A", VMID: 105}}, CompleteVMIDs: []int{105}}
		if _, err := op.Read(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) {
			t.Fatalf("both-set: err=%v; want ErrUnverifiableRead", err)
		}
	})
	t.Run("neither selector set refuses", func(t *testing.T) {
		op := &VolumeFreeOrphans{Client: base(), Scanner: base(), Storage: "s", VMID: 700}
		if _, err := op.Read(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) {
			t.Fatalf("neither-set: err=%v; want ErrUnverifiableRead", err)
		}
	})
	t.Run("node-scoped on shared storage refuses", func(t *testing.T) {
		f := &fakeStorageClient{node: "A", storageShared: 1}
		op := &VolumeFreeOrphans{Client: f, Scanner: f, Storage: "s", VMID: 700, CompleteVMIDs: []int{105}}
		if _, err := op.Read(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) {
			t.Fatalf("node-scoped on shared: err=%v; want ErrUnverifiableRead", err)
		}
	})
	t.Run("node-scoped on unshared storage proceeds", func(t *testing.T) {
		f := &fakeStorageClient{node: "A", storageShared: 0} // scanner returns no orphans
		op := &VolumeFreeOrphans{Client: f, Scanner: f, Storage: "s", VMID: 700, CompleteVMIDs: []int{105}}
		cur, err := op.Read(context.Background())
		if err != nil || cur != "[]" {
			t.Fatalf("node-scoped on unshared: cur=%q err=%v; want \"[]\" and no error", cur, err)
		}
	})
}

// clusterFreeHandler serves a NODE-KEYED fake PVE API for the cross-node free
// test: the shared storage's content, and each (node, vmid)'s config + snapshot
// list keyed on the EXACT node in the path. A config read for the wrong node
// 404s (default), so a node-scoped scan cannot accidentally satisfy a cross-
// node claim. The owning VM of vm-700-disk-0 lives on node B, not the bound
// node A.
func clusterFreeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	// Shared storage, on the bound node's view. shared=1 so the node-scoped
	// scanner (the planted mutant's path) hits refuseIfShared.
	case "/nodes/A/storage/shared-lvm/status":
		_, _ = w.Write([]byte(`{"data":{"storage":"shared-lvm","type":"lvmthin","shared":1}}`))
	case "/nodes/A/storage/shared-lvm/content":
		_, _ = w.Write([]byte(`{"data":[` +
			`{"volid":"shared-lvm:vm-700-disk-0","vmid":700,"content":"images"},` +
			`{"volid":"shared-lvm:vm-800-disk-0","vmid":800,"content":"images"}]}`))
	// VM 105 on node A.
	case "/nodes/A/qemu/105/config":
		_, _ = w.Write([]byte(`{"data":{"digest":"dA","scsi0":"shared-lvm:vm-105-disk-0,size=8G"}}`))
	case "/nodes/A/qemu/105/snapshot":
		_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
	// VM 700 on node B — its config claims vm-700-disk-0, invisible to a
	// node-A-only scan.
	case "/nodes/B/qemu/700/config":
		_, _ = w.Write([]byte(`{"data":{"digest":"dB","scsi0":"shared-lvm:vm-700-disk-0,size=32G"}}`))
	case "/nodes/B/qemu/700/snapshot":
		_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
	default:
		http.NotFound(w, r)
	}
}

// TestVolumeFreeOrphans_ClusterScanner_DoesNotFreeCrossNodeDisk is U-CWCV
// invariant #1 on the DESTRUCTIVE path: VolumeFreeOrphans.Read, routed onto the
// cluster scanner (ClusterGuests != nil), must NOT report vm-700-disk-0 — a
// live disk claimed by VM 700 on node B — as an orphan to free, even though the
// bound node is A and the storage is shared. The claimed set is built through
// the REAL ParseClusterGuests -> ClusterQemuPairs enumeration and a real
// *pve.Client that reads each node's config keyed on the node in the path.
//
// Mutation target: reverting Read to the node-scoped
// OrphanVolumesForVMIDWithVMList (ignoring ClusterGuests) makes the scan run
// node-A-only; on this shared storage that path hits refuseIfShared and Read
// errors instead of returning the empty set — RED. (With refuseIfShared kept on
// the node-scoped path per §5, the mutant surfaces as that refusal rather than
// a silent free; either way the clean empty result below turns red.)
func TestVolumeFreeOrphans_ClusterScanner_DoesNotFreeCrossNodeDisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(clusterFreeHandler))
	t.Cleanup(srv.Close)

	scanner, err := pve.NewClient(pve.ClientConfig{
		BaseURLOverride: srv.URL,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Real enumeration: /cluster/resources rows -> QEMU pairs, both nodes online.
	guests, err := pve.ParseClusterGuests([]byte(
		`[{"type":"qemu","vmid":105,"node":"A"},{"type":"qemu","vmid":700,"node":"B"}]`))
	if err != nil {
		t.Fatalf("ParseClusterGuests: %v", err)
	}
	pairs, err := pve.ClusterQemuPairs(guests, map[string]bool{"A": true, "B": true})
	if err != nil {
		t.Fatalf("ClusterQemuPairs: %v", err)
	}

	// Only ClusterPairs is set (F1 XOR guard forbids setting CompleteVMIDs too).
	op := &VolumeFreeOrphans{
		Client:       &fakeStorageClient{node: "A"}, // Node() only
		Scanner:      scanner,
		Storage:      "shared-lvm",
		VMID:         700,
		ClusterPairs: pairs,
	}

	cur, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read via the cluster scanner errored: %v", err)
	}
	if cur != "[]" {
		t.Fatalf("Read reported orphans %q for vm-700-* on shared storage; VM 700 on node B claims vm-700-disk-0, so the cluster scanner must report nothing to free", cur)
	}
	if !op.Satisfied(cur) {
		t.Fatalf("Satisfied(%q) = false; want nothing-to-free", cur)
	}
}

// TestVolumeFreeOrphans_ClusterScanner_TruncatedClaimedSetReportsCrossNodeDisk
// is F2 (grok N1): it observes the FREED-VOLID behavior through the Op's Read on
// the CLUSTER path, not just a refusal string. With a TRUNCATED pair list (only
// node A's VM, node B's 700 omitted), the cluster claimed set misses
// vm-700-disk-0, so Read must REPORT shared-lvm:vm-700-disk-0 as an orphan to
// free — the exact disk a complete enumeration protects. Asserting the volid (not
// an error string) means a future node-scoped claim path can no longer go green
// on a wrong-reason refusal: the DoesNotFree test above pins "[]" for the full
// set, this pins the specific volid for the truncated set.
//
// Mutation target: reverting Read to the node-scoped scanner (ignoring
// ClusterPairs) makes Read error (nil node-scoped list refusal) instead of
// reporting the volid — the volid assertion then fails RED.
func TestVolumeFreeOrphans_ClusterScanner_TruncatedClaimedSetReportsCrossNodeDisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(clusterFreeHandler))
	t.Cleanup(srv.Close)

	scanner, err := pve.NewClient(pve.ClientConfig{
		BaseURLOverride: srv.URL,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Truncated enumeration: node A only, node B's VM 700 dropped. Through the
	// REAL ClusterQemuPairs path, not hand-fed, so the truncation is the input a
	// short/incomplete cluster list would produce.
	guests, err := pve.ParseClusterGuests([]byte(`[{"type":"qemu","vmid":105,"node":"A"}]`))
	if err != nil {
		t.Fatalf("ParseClusterGuests: %v", err)
	}
	pairs, err := pve.ClusterQemuPairs(guests, map[string]bool{"A": true, "B": true})
	if err != nil {
		t.Fatalf("ClusterQemuPairs: %v", err)
	}

	op := &VolumeFreeOrphans{
		Client:       &fakeStorageClient{node: "A"},
		Scanner:      scanner,
		Storage:      "shared-lvm",
		VMID:         700,
		ClusterPairs: pairs,
	}

	cur, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read via the cluster scanner errored: %v", err)
	}
	if cur != `["shared-lvm:vm-700-disk-0"]` {
		t.Fatalf("Read reported %q; a truncated cluster claimed set (node B omitted) must surface shared-lvm:vm-700-disk-0 as a reported orphan — the freed-volid behavior, observed through the Op", cur)
	}
}
