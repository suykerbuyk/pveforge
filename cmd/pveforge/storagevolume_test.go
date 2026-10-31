package main

import (
	"strings"
	"testing"
)

// TestStorageFreeOrphans_RefusesNonQuorate_AtCLI is the central RULING-2 test:
// the quorum gate lives only in the CLI RunE (the Op is quorum-blind), so this
// drives the whole `storage free-orphans` command. A non-quorate node (whose
// pmxcfs VM list may be stale) must be REFUSED before any DELETE.
//
// The root reads are faked over SSH: NodeVMIDs returns an empty (stale/short)
// list and /cluster/status reports quorate:0. /content lists a vm-690-disk-0
// that an empty VM list would make a FALSE orphan. Correct code refuses with
// ZERO DELETEs. Mutation target: dropping the CLI quorum gate (or treating
// quorate:0 as quorate) lets the free proceed and issue a DELETE for
// local-lvm:vm-690-disk-0 — this test's "no DELETE" assertion then goes RED.
func TestStorageFreeOrphans_RefusesNonQuorate_AtCLI(t *testing.T) {
	routes := map[string]string{
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status":  `{"data":{"storage":"local-lvm","type":"lvmthin","shared":0}}`,
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/content": `{"data":[{"volid":"local-lvm:vm-690-disk-0","vmid":690,"content":"images"}]}`,
		// A DELETE response is seeded so a gate-dropping mutant's DELETE is
		// answered (and recorded) rather than erroring before it is observed.
		"DELETE /api2/json/nodes/qa-pve-01/storage/local-lvm/content/local-lvm:vm-690-disk-0": `{"data":"UPID:qa-pve-01:0:0:0:imgdel:690:root@pam:"}`,
	}
	// NodeQemuCommand shell-quotes the node (/nodes/'qa-pve-01'/qemu), so match
	// on substrings rather than an exact prefix.
	exec := func(cmd string) (string, string, int) {
		switch {
		case strings.HasPrefix(cmd, "readlink /etc/pve/local"):
			return "nodes/qa-pve-01\n", "", 0
		case strings.Contains(cmd, "/cluster/status"):
			return `[{"type":"cluster","name":"c","nodes":2,"quorate":0}]`, "", 0 // NOT quorate
		case strings.Contains(cmd, "/qemu"):
			return "[]", "", 0 // an empty (stale/short) list — non-nil, no error
		}
		return "", "", 0
	}

	rp, _, rf := accessSetupExec(t, routes, exec)
	code, _, stderr := runRootArgs("storage", "free-orphans", "qa-pve-01", "local-lvm", "690", "--roster", rp)

	if code == 0 {
		t.Fatalf("expected a non-zero exit (refusal) for a non-quorate node; stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "not quorate") {
		t.Fatalf("expected the refusal to name quorum as the reason; stderr=%q", stderr)
	}
	for _, req := range rf.got() {
		if strings.HasPrefix(req, "DELETE ") {
			t.Fatalf("a DELETE was issued despite a non-quorate node: %q — the free must refuse with ZERO DELETEs", req)
		}
	}
}

// TestStorageFreeOrphans_SharedStorage_RoutesClusterPath_AtCLI pins the ENABLED
// behavior after the U-CWCV §2 merge gate (clusterSharedFreeProxyProven) was
// removed: a SHARED-storage free no longer refuses with "not yet enabled" — it
// PROCEEDS through the cluster path (ClusterGuests + ClusterStatusOnlineNodes +
// ClusterQemuPairs -> the Op's cluster scanner) behind the quorum gate + stale-
// residual warning, and it does NOT free a disk a VM on ANOTHER node claims.
//
// Scenario: storage local-lvm is shared; its content lists vm-700-disk-0, which
// VM 700 — living on node qa-pve-02 (node B), not the bound node qa-pve-01 —
// claims in its config. The cross-node claimed set must therefore report NOTHING
// to free. The fake REST server stands in for node A's API proxying node B's
// config read (the live behavior proven on the nested pvh harness 2026-10-30).
// Before the gate removal this run refused; now it must proceed with ZERO
// DELETEs and read node B's config through the cluster scanner.
func TestStorageFreeOrphans_SharedStorage_RoutesClusterPath_AtCLI(t *testing.T) {
	routes := map[string]string{
		// shared=1 -> storage.go routes the free through the cluster path.
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/status": `{"data":{"storage":"local-lvm","type":"nfs","shared":1}}`,
		// The cluster scanner's content fetch (bound node's view).
		"GET /api2/json/nodes/qa-pve-01/storage/local-lvm/content": `{"data":[{"volid":"local-lvm:vm-700-disk-0","vmid":700,"content":"images"}]}`,
		// The cross-node claim read: VM 700 on node B, served through node A's API
		// (one route answers both the plain and the ?current=1 config read — the
		// route key strips the query). Claiming vm-700-disk-0 makes it NOT an orphan.
		"GET /api2/json/nodes/qa-pve-02/qemu/700/config":   `{"data":{"digest":"d700","scsi0":"local-lvm:vm-700-disk-0,size=8G"}}`,
		"GET /api2/json/nodes/qa-pve-02/qemu/700/snapshot": `{"data":[{"name":"current"}]}`,
		// Seeded so a (buggy) DELETE would be answered and recorded, not error first.
		"DELETE /api2/json/nodes/qa-pve-02/storage/local-lvm/content/local-lvm:vm-700-disk-0": `{"data":"UPID:qa-pve-02:0:0:0:imgdel:700:root@pam:"}`,
		"DELETE /api2/json/nodes/qa-pve-01/storage/local-lvm/content/local-lvm:vm-700-disk-0": `{"data":"UPID:qa-pve-01:0:0:0:imgdel:700:root@pam:"}`,
	}
	exec := func(cmd string) (string, string, int) {
		switch {
		case strings.HasPrefix(cmd, "readlink /etc/pve/local"):
			return "nodes/qa-pve-01\n", "", 0
		case strings.Contains(cmd, "/cluster/resources"):
			// VM 700 lives on node B (qa-pve-02) — the cross-node guest.
			return `[{"type":"qemu","vmid":700,"node":"qa-pve-02"}]`, "", 0
		case strings.Contains(cmd, "/cluster/status"):
			// One body satisfies BOTH ClusterStatusOnlineNodes (node rows with
			// name+online) and ClusterStatusQuorate (the cluster entry).
			return `[{"type":"cluster","name":"pvh","nodes":2,"quorate":1},{"type":"node","name":"qa-pve-01","online":1},{"type":"node","name":"qa-pve-02","online":1}]`, "", 0
		}
		return "", "", 0
	}

	rp, _, rf := accessSetupExec(t, routes, exec)
	code, stdout, stderr := runRootArgs("storage", "free-orphans", "qa-pve-01", "local-lvm", "700", "--roster", rp)

	// Proceeds (not the removed gated refusal), nothing to free.
	if code != 0 {
		t.Fatalf("expected exit 0 (shared free proceeds through the cluster path); code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, "not yet enabled") || strings.Contains(stderr, "MERGE GATE") {
		t.Fatalf("the removed gate still refused a shared free; stderr=%q", stderr)
	}
	if !strings.Contains(stdout, "nothing freed") {
		t.Fatalf("expected the cross-node disk NOT to be freed (\"nothing freed\"); stdout=%q", stdout)
	}
	// The quorum gate + stale-residual warning still ride the enabled shared path.
	if !strings.Contains(stderr, "necessary but NOT sufficient") {
		t.Fatalf("expected the stale-residual warning on the enabled shared free; stderr=%q", stderr)
	}
	// Reached the cluster scanner: node B's config was read cross-node through
	// the bound node's API (this is the path the gate used to block).
	var sawCrossNodeClaimRead bool
	for _, req := range rf.got() {
		if req == "GET /api2/json/nodes/qa-pve-02/qemu/700/config" {
			sawCrossNodeClaimRead = true
		}
		if strings.HasPrefix(req, "DELETE ") {
			t.Fatalf("a DELETE was issued for a cross-node-claimed disk: %q — the cluster claimed set must protect it", req)
		}
	}
	if !sawCrossNodeClaimRead {
		t.Fatalf("expected a cross-node claim read of node B's config (cluster path reached); got %v", rf.got())
	}
}
