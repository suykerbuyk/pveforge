package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// clusterClaimHandler serves a node-keyed fake for the cluster-wide claimed-set
// tests: VM 105 on node A, VM 700 on node B, each config keyed on its own node.
func clusterClaimHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/nodes/A/qemu/105/config":
		_, _ = w.Write([]byte(`{"data":{"digest":"dA","scsi0":"shared-lvm:vm-105-disk-0,size=8G"}}`))
	case "/nodes/A/qemu/105/snapshot":
		_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
	case "/nodes/B/qemu/700/config":
		_, _ = w.Write([]byte(`{"data":{"digest":"dB","scsi0":"shared-lvm:vm-700-disk-0,size=32G"}}`))
	case "/nodes/B/qemu/700/snapshot":
		_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
	default:
		http.NotFound(w, r)
	}
}

// TestClusterClaimedVolumes_UnionsAcrossNodes: the union reaches each pair's
// OWN node (keyed config reads) and claims both VMs' disks.
func TestClusterClaimedVolumes_UnionsAcrossNodes(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, clusterClaimHandler))
	claimed, err := c.ClusterClaimedVolumes(context.Background(),
		[]NodeVMID{{Node: "A", VMID: 105}, {Node: "B", VMID: 700}})
	if err != nil {
		t.Fatalf("ClusterClaimedVolumes: %v", err)
	}
	for _, v := range []string{"shared-lvm:vm-105-disk-0", "shared-lvm:vm-700-disk-0"} {
		if !claimed[v] {
			t.Errorf("expected %q in the cluster claimed set, got %v", v, claimed)
		}
	}
}

// TestClusterClaimedVolumes_NilRefused: a nil pair list is a dropped
// enumeration, refused; a non-nil empty slice is a zero-QEMU cluster, accepted.
func TestClusterClaimedVolumes_NilRefused(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("nil/empty must not reach the network")
	}))
	if _, err := c.ClusterClaimedVolumes(context.Background(), nil); err == nil {
		t.Fatal("expected a nil pair list to be refused")
	}
	claimed, err := c.ClusterClaimedVolumes(context.Background(), []NodeVMID{})
	if err != nil || len(claimed) != 0 {
		t.Fatalf("empty slice: claimed=%v err=%v; want an empty set and no error", claimed, err)
	}
}

// TestClusterClaimedVolumes_AbortsOnFirstError is invariant #3: one pair's
// config read failing ABORTS the whole union — the returned map is NIL, the
// error names the failing node+vmid, and no later pair is consulted. Mirrors
// TestOrphanVolumes_AbortsWholeCallWhenAnySingleClaimedSetFails. Mutation
// target: a "continue on error" in ClusterClaimedVolumes returns a short set
// (node B's disk missing), which on the free path is a freed live disk.
func TestClusterClaimedVolumes_AbortsOnFirstError(t *testing.T) {
	var cHits int32
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/A/qemu/105/config":
			atomic.AddInt32(&cHits, 1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("vm 105 config exploded"))
		default:
			http.NotFound(w, r)
		}
	}))
	claimed, err := c.ClusterClaimedVolumes(context.Background(),
		[]NodeVMID{{Node: "A", VMID: 105}, {Node: "B", VMID: 700}})
	if err == nil {
		t.Fatalf("expected the whole union to abort, got claimed=%v", claimed)
	}
	if claimed != nil {
		t.Errorf("expected a NIL map alongside the error, got %v", claimed)
	}
	if !strings.Contains(err.Error(), "105") || !strings.Contains(err.Error(), `"A"`) {
		t.Errorf("expected the failing node+vmid (A/105) in the error, got: %v", err)
	}
}

// TestOrphanVolumesClusterForVMID_CrossNodeDiskNotOrphaned: on SHARED storage,
// vm-700-disk-0 (claimed by VM 700 on node B) is NOT reported as an orphan for
// VMID 700, while a genuinely unclaimed vm-700-disk-9 IS. No refuseIfShared is
// consulted (no /status endpoint is served).
func TestOrphanVolumesClusterForVMID_CrossNodeDiskNotOrphaned(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes/A/storage/shared-lvm/content" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[` +
				`{"volid":"shared-lvm:vm-700-disk-0","vmid":700,"content":"images"},` +
				`{"volid":"shared-lvm:vm-700-disk-9","vmid":700,"content":"images"}]}`))
			return
		}
		clusterClaimHandler(w, r)
	}))
	pairs := []NodeVMID{{Node: "A", VMID: 105}, {Node: "B", VMID: 700}}
	orphans, err := c.OrphanVolumesClusterForVMID(context.Background(), "A", "shared-lvm", 700, pairs)
	if err != nil {
		t.Fatalf("OrphanVolumesClusterForVMID: %v", err)
	}
	var got []string
	for _, o := range orphans {
		got = append(got, o.Volid)
	}
	if len(got) != 1 || got[0] != "shared-lvm:vm-700-disk-9" {
		t.Fatalf("orphans = %v; want only the genuinely unclaimed shared-lvm:vm-700-disk-9 (vm-700-disk-0 is claimed cross-node)", got)
	}
}

// TestOrphanVolumesClusterForVMID_FailsClosedOnBadArgs is imp2 N1: the
// entrypoint's OWN fail-closed guards — an empty node and a nil cluster guest
// list — must refuse before any read, mirroring ClusterClaimedVolumes' nil
// refusal. (These are defense-in-depth echoes the CLI never triggers, but a
// future direct caller might.)
func TestOrphanVolumesClusterForVMID_FailsClosedOnBadArgs(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("a bad-arg refusal must not reach the network")
	}))
	if _, err := c.OrphanVolumesClusterForVMID(context.Background(), "", "shared-lvm", 700, []NodeVMID{{Node: "A", VMID: 1}}); err == nil {
		t.Fatal("expected an empty node to be refused")
	}
	if _, err := c.OrphanVolumesClusterForVMID(context.Background(), "A", "", 700, []NodeVMID{{Node: "A", VMID: 1}}); err == nil {
		t.Fatal("expected an empty storage to be refused")
	}
	if _, err := c.OrphanVolumesClusterForVMID(context.Background(), "A", "shared-lvm", 700, nil); err == nil {
		t.Fatal("expected a nil cluster guest list to be refused")
	}
}

// TestStorageContentWithType_RefusesNullEntry is invariant #5: a null content
// ENTRY (not a null list) must refuse as ErrUnverifiableRead before any diff,
// not be skipped. Driven through OrphanVolumesClusterForVMID, whose content
// fetch is storageContentWithType. Mutation target: dropping the per-entry
// nullEntry guard lets the scan return a short orphan set from a payload no
// healthy PVE emits.
func TestStorageContentWithType_RefusesNullEntry(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nodes/A/storage/shared-lvm/content" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[null,{"volid":"shared-lvm:vm-700-disk-0","vmid":700,"content":"images"}]}`))
			return
		}
		clusterClaimHandler(w, r)
	}))
	orphans, err := c.OrphanVolumesClusterForVMID(context.Background(), "A", "shared-lvm", 700,
		[]NodeVMID{{Node: "B", VMID: 700}})
	if err == nil {
		t.Fatalf("expected a null content entry to refuse, got orphans=%v", orphans)
	}
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Errorf("expected ErrUnverifiableRead for a null content entry, got: %v", err)
	}
	if orphans != nil {
		t.Errorf("expected a nil result alongside the refusal, got %v", orphans)
	}
}

// TestClusterQemuPairs is invariant #4 (the sound-but-weaker membership check)
// plus the QEMU-only filter: a guest naming a node NOT in the online set
// refuses; LXC is excluded; an online node with zero guests does NOT refuse.
func TestClusterQemuPairs(t *testing.T) {
	online := map[string]bool{"A": true, "B": true}

	// QEMU-only, both nodes known-online: two pairs, LXC dropped.
	pairs, err := ClusterQemuPairs([]Guest{
		{Type: "qemu", VMID: 105, Node: "A"},
		{Type: "lxc", VMID: 200, Node: "A"},
		{Type: "qemu", VMID: 700, Node: "B"},
	}, online)
	if err != nil {
		t.Fatalf("ClusterQemuPairs: %v", err)
	}
	if len(pairs) != 2 || pairs[0] != (NodeVMID{"A", 105}) || pairs[1] != (NodeVMID{"B", 700}) {
		t.Fatalf("pairs = %v; want [{A 105} {B 700}] (LXC excluded)", pairs)
	}

	// A guest on a node the cluster does NOT report online → refuse.
	if p, err := ClusterQemuPairs([]Guest{{Type: "qemu", VMID: 9, Node: "C"}}, online); !errors.Is(err, ErrUnverifiableRead) || p != nil {
		t.Fatalf("guest on offline/unknown node C: pairs=%v err=%v; want ErrUnverifiableRead", p, err)
	}

	// An online node (B) with zero guests must NOT false-refuse.
	pairs, err = ClusterQemuPairs([]Guest{{Type: "qemu", VMID: 105, Node: "A"}}, online)
	if err != nil {
		t.Fatalf("empty-but-online node B must not refuse: %v", err)
	}
	if len(pairs) != 1 || pairs[0] != (NodeVMID{"A", 105}) {
		t.Fatalf("pairs = %v; want just {A 105}", pairs)
	}

	// A genuinely zero-QEMU cluster is a non-nil empty slice (not nil, not an
	// error), so ClusterClaimedVolumes does not mistake it for a dropped list.
	pairs, err = ClusterQemuPairs(nil, online)
	if err != nil || pairs == nil || len(pairs) != 0 {
		t.Fatalf("no guests: pairs=%v err=%v; want a non-nil empty slice", pairs, err)
	}
}

// TestParseClusterStatusOnlineNodes is invariant #6: it reads the "name" key
// (not "node") and a strict 0/1 "online" on the type=="node" rows, returns the
// online set, and fails closed on an empty name, an absent/bad online, or no
// node entry.
func TestParseClusterStatusOnlineNodes(t *testing.T) {
	good := `[{"type":"cluster","name":"pvh","quorate":1},` +
		`{"type":"node","name":"A","online":1},` +
		`{"type":"node","name":"B","online":0}]`
	online, err := ParseClusterStatusOnlineNodes([]byte(good))
	if err != nil {
		t.Fatalf("ParseClusterStatusOnlineNodes(good): %v", err)
	}
	if !online["A"] || online["B"] || len(online) != 1 {
		t.Fatalf("online = %v; want only A", online)
	}
	// A standalone node reports itself online.
	if o, err := ParseClusterStatusOnlineNodes([]byte(`[{"type":"node","name":"solo","online":1}]`)); err != nil || !o["solo"] {
		t.Fatalf("standalone: %v, %v", o, err)
	}

	for name, bad := range map[string]string{
		"null":              `null`,
		"not json":          `pvesh: denied`,
		"data envelope":     `{"data":[{"type":"node","name":"A","online":1}]}`,
		"trailing data":     `[{"type":"node","name":"A","online":1}] []`,
		"a null entry":      `[null]`,
		"no node entry":     `[{"type":"cluster","name":"pvh","quorate":1}]`,
		"empty name":        `[{"type":"node","name":"","online":1}]`,
		"name absent":       `[{"type":"node","online":1}]`,
		"name not a string": `[{"type":"node","name":123,"online":1}]`,
		"online absent":     `[{"type":"node","name":"A"}]`,
		"online not 0/1":    `[{"type":"node","name":"A","online":2}]`,
		"online a string":   `[{"type":"node","name":"A","online":"1"}]`,
	} {
		if o, err := ParseClusterStatusOnlineNodes([]byte(bad)); !errors.Is(err, ErrUnverifiableRead) || o != nil {
			t.Errorf("%s: %v, %v; want ErrUnverifiableRead and no set", name, o, err)
		}
	}
}
