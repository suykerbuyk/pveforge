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
