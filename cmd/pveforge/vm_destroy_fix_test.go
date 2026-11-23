package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// AC11: a B10 refusal names `pveforge acl enable-vm-destroy <t>` exactly where
// doctor does (a Sys.Audit PVE refused with a 403), with doctor's own format
// string, and nowhere else.

func TestVMDestroyFix_B10NamesTheFixOnlyOnA403(t *testing.T) {
	big := make([]pvefake.TaskRow, 2000)
	for i := range big {
		big[i] = pvefake.TaskRow{UPID: dUPID("qmconfig", 100+i), Type: "qmconfig", ID: strconv.Itoa(dVMID), StartTime: int64(100 + i), Status: "OK", EndTime: int64(101 + i), Saved: true, Node: dNode, User: "root@pam"}
	}
	wantFix := "pveforge acl enable-vm-destroy " + dTarget
	for _, tc := range []struct {
		name string
		mut  func(*pvefake.VMREST)
		fix  bool
	}{
		{"node status 403", func(s *pvefake.VMREST) { s.NodeStatus = 403 }, true},
		{"node status 500", func(s *pvefake.VMREST) { s.NodeStatus = 500 }, false},
		{"task list 500", func(s *pvefake.VMREST) { s.TasksStatus = 500 }, false},
		{"a full page", func(s *pvefake.VMREST) { s.Tasks = big }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDEnv(t, tc.mut)
			r := e.runYes()
			want(t, r, 4, "refused", "B10")
			if tc.fix {
				if r.str("fix") != wantFix || !strings.Contains(r.stderr, "run: "+wantFix) {
					t.Fatalf("fix %q, stderr %q", r.str("fix"), r.stderr)
				}
				if e.deletes() != 0 || e.stops() != 0 {
					t.Fatalf("dispatched")
				}
				return
			}
			if r.has("fix") || strings.Contains(r.stderr, "enable-vm-destroy") || strings.Contains(r.stdout, "enable-vm-destroy") {
				t.Fatalf("a fix beside a refusal that is not a 403: %s / %s", r.stdout, r.stderr)
			}
		})
	}
}

// The retry's member-list 403 (Sys.Audit on /) names it too.
func TestVMDestroyFix_RetryMemberList403(t *testing.T) {
	e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) { s.ClusterNodesStatus = 403 })
	r := e.runYes()
	want(t, r, 4, "refused", "B10")
	if r.str("fix") != "pveforge acl enable-vm-destroy "+dTarget {
		t.Fatalf("fix %q: %s", r.str("fix"), r.stdout)
	}
}

// The decision, called directly (the mutants' target): both directions.
func TestVMDestroyFix_FixFor(t *testing.T) {
	for _, p := range []string{"Sys.Audit on /nodes/n1", "Sys.Audit on /", "Sys.Audit"} {
		if got := fixFor(p, "t1", "n1"); got != "pveforge acl enable-vm-destroy t1" {
			t.Errorf("fixFor(%q) = %q", p, got)
		}
	}
	for _, p := range []string{"", "VM.Allocate on /vms/1", "VM.PowerMgmt", "sys.audit", " Sys.Audit"} {
		if got := fixFor(p, "t1", "n1"); got != "" {
			t.Errorf("fixFor(%q) = %q, want none", p, got)
		}
	}
	// one spelling: doctor's constant, the same text
	if got, want := fixFor("Sys.Audit on /", "tx", "n1"), strings.Replace(doctorFixFmt, "%s", "tx", 1); got != want {
		t.Errorf("fixFor %q is not doctor's %q", got, want)
	}
	// the roster node's own row: exactly doctor's remedy; another member's:
	// the remedy plus the way out of the loop, naming THAT node.
	if got := fixFor("Sys.Audit on /nodes/n1", "t1", "n1"); got != "pveforge acl enable-vm-destroy t1" {
		t.Errorf("roster node: %q", got)
	}
	peer := fixFor("Sys.Audit on /nodes/n2", "t1", "n1")
	if !strings.HasPrefix(peer, "pveforge acl enable-vm-destroy t1; if it reports already enabled, check") || !strings.Contains(peer, "/nodes/n2") || strings.Contains(peer, "/nodes/n1") {
		t.Errorf("peer node: %q", peer)
	}
}

// A refusal on ANOTHER member's node must not send the operator in a loop:
// the fix says to check that node's override row if the token already holds
// the role. (The roster node's own 403 keeps doctor's exact text, above.)
func TestVMDestroyFix_PeerNode403PointsAtTheOverrideRow(t *testing.T) {
	e := retryEnv(t, []pvefake.TaskRow{dRow("qmdestroy", 3, "OK")}, func(s *pvefake.VMREST) {
		s.Peers = map[string]*pvefake.PeerNode{"n2": {NodeStatus: 403}}
	})
	r := e.runYes()
	want(t, r, 4, "refused", "B10")
	if r.str("privilege") != "Sys.Audit on /nodes/n2" {
		t.Fatalf("privilege %q: %s", r.str("privilege"), r.stdout)
	}
	fix := r.str("fix")
	if !strings.HasPrefix(fix, "pveforge acl enable-vm-destroy "+dTarget+"; if it reports already enabled, check") || !strings.Contains(fix, "/nodes/n2") {
		t.Fatalf("fix %q", fix)
	}
	if !strings.Contains(r.stderr, "/nodes/n2") {
		t.Errorf("stderr lacks the node: %q", r.stderr)
	}
}
