package pve

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// ClusterNodes is called DIRECTLY. The set is Complete only when BOTH reads
// succeeded and the authoritative list is non-empty and names the roster.

func memberFixture(t *testing.T, mut func(s *pvefake.VMREST)) NodeSet {
	t.Helper()
	s := pvefake.NewVMREST(t, "n1")
	s.Peers = map[string]*pvefake.PeerNode{"n2": {}, "n3": {}}
	if mut != nil {
		mut(s)
	}
	srv := s.Server()
	t.Cleanup(srv.Close)
	return detClient(t, srv.URL+"/api2/json").ClusterNodes(context.Background(), "n1")
}

func mustComplete(t *testing.T, ns NodeSet, want ...string) {
	t.Helper()
	if !ns.Complete {
		t.Fatalf("not complete: %+v", ns)
	}
	if !slices.Equal(ns.Names, want) {
		t.Fatalf("names = %v, want %v", ns.Names, want)
	}
}

func mustIncomplete(t *testing.T, ns NodeSet, detail string) {
	t.Helper()
	if ns.Complete || len(ns.Names) != 0 {
		t.Fatalf("COMPLETE with %v — an unestablished member set must carry no names", ns.Names)
	}
	if ns.Read == "" || !strings.Contains(ns.Detail, detail) {
		t.Fatalf("read %q detail %q, want a detail containing %q", ns.Read, ns.Detail, detail)
	}
}

func TestClusterNodes_Healthy(t *testing.T) {
	mustComplete(t, memberFixture(t, nil), "n1", "n2", "n3")
}

func TestClusterNodes_UnionOfBothLists(t *testing.T) {
	// a node only in the authority is read.
	mustComplete(t, memberFixture(t, func(s *pvefake.VMREST) {
		s.NodesIndex = `[{"node":"n1"},{"node":"n2"}]`
	}), "n1", "n2", "n3")
	// a node only in /nodes is read.
	mustComplete(t, memberFixture(t, func(s *pvefake.VMREST) {
		s.ClusterNodes = `[{"node":"n1"},{"node":"n2"}]`
	}), "n1", "n2", "n3")
	// the roster is always in the set, whatever /nodes says, and duplicates collapse.
	mustComplete(t, memberFixture(t, func(s *pvefake.VMREST) {
		s.NodesIndex = `[{"node":"n3"},{"node":"n3"}]`
		s.ClusterNodes = `[{"node":"n1"},{"node":"n3"},{"node":"n1"}]`
	}), "n1", "n3")
}

// G21 / U5-D2: an EMPTY authoritative list is membership-unknown whatever
// /nodes says — no standalone inference.
func TestClusterNodes_EmptyAuthorityIsNotStandalone(t *testing.T) {
	for _, nodes := range []string{`[{"node":"n1"}]`, `[]`, `[{"node":"n1"},{"node":"n2"},{"node":"n3"}]`} {
		ns := memberFixture(t, func(s *pvefake.VMREST) {
			s.ClusterNodes = `[]`
			s.NodesIndex = nodes
		})
		mustIncomplete(t, ns, "membership unknown")
		if !strings.Contains(ns.Read, "/cluster/config/nodes") {
			t.Errorf("read %q", ns.Read)
		}
	}
}

func TestClusterNodes_AuthorityWithoutTheRosterIsUnknown(t *testing.T) {
	ns := memberFixture(t, func(s *pvefake.VMREST) { s.ClusterNodes = `[{"node":"n2"},{"node":"n3"}]` })
	mustIncomplete(t, ns, `does not name the roster node "n1"`)
}

// The roster match is exact: node names are case-sensitive, and "N1" is not "n1".
func TestClusterNodes_RosterMatchIsCaseSensitive(t *testing.T) {
	ns := memberFixture(t, func(s *pvefake.VMREST) { s.ClusterNodes = `[{"node":"N1"},{"node":"n2"}]` })
	mustIncomplete(t, ns, `does not name the roster node "n1"`)
}

// grok F1 / codex F-01: a /nodes entry with no node name is membership-UNKNOWN,
// never dropped.
func TestClusterNodes_NodesEntryWithNoNameIsUnknown(t *testing.T) {
	ns := memberFixture(t, func(s *pvefake.VMREST) {
		s.ClusterNodes = `[{"node":"n1"}]`
		s.NodesIndex = `[{"node":"n1"},{"node":""}]`
	})
	mustIncomplete(t, ns, "an entry with no node name")
	if ns.Read != "GET /nodes" {
		t.Errorf("read %q", ns.Read)
	}
	// the control: the same lists without the empty entry are complete.
	mustComplete(t, memberFixture(t, func(s *pvefake.VMREST) {
		s.ClusterNodes = `[{"node":"n1"}]`
		s.NodesIndex = `[{"node":"n1"}]`
	}), "n1")
}

func TestClusterNodes_AuthorityRefusals(t *testing.T) {
	ns := memberFixture(t, func(s *pvefake.VMREST) { s.ClusterNodesStatus = 403 })
	mustIncomplete(t, ns, "Sys.Audit on /")
	if ns.Privilege != "Sys.Audit on /" {
		t.Errorf("privilege %q", ns.Privilege)
	}
	// /nodes answering fine does NOT rescue a refused authority.
	if ns.Complete {
		t.Fatal("complete on a 403 authority")
	}
	// a 401 is a bad credential, not a missing privilege: no privilege is named.
	ns = NodeSet{}
	c := rawClient(t, "401 Unauthorized", `{"data":null}`)
	ns = c.ClusterNodes(context.Background(), "n1")
	if ns.Complete || ns.Privilege != "" {
		t.Errorf("401: %+v, want incomplete with no privilege named", ns)
	}
	// a 500 / a stall-free failure.
	ns = memberFixture(t, func(s *pvefake.VMREST) { s.ClusterNodesStatus = 500 })
	if ns.Complete || ns.Privilege != "" {
		t.Errorf("500: %+v", ns)
	}
}

func TestClusterNodes_NodesIndexFailureIsNotRescuedByTheAuthority(t *testing.T) {
	for _, code := range []int{403, 500, 595} {
		ns := memberFixture(t, func(s *pvefake.VMREST) { s.NodesIndexStatus = code })
		if ns.Complete {
			t.Fatalf("HTTP %d on /nodes: complete — either read failing must make the set unreadable", code)
		}
		if ns.Read != "GET /nodes" && !strings.Contains(ns.Read, "nodes") {
			t.Errorf("read %q", ns.Read)
		}
	}
}

func TestDecodeCorosyncNodes(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		ok   bool
		want []string
	}{
		{`[{"node":"n1"},{"node":"n2","nodeid":"2","ring0_addr":"x"}]`, true, []string{"n1", "n2"}},
		{`[]`, true, nil},
		{`null`, false, nil},
		{`{}`, false, nil},
		{`[null]`, false, nil},
		{`[{"name":"n1"}]`, false, nil},
		{`[{"node":""}]`, false, nil},
		{`[{"node":7}]`, false, nil},
		{`[{"node":"n1"}] [{"node":"n2"}]`, false, nil},
		{`[{"node":"n1"}] x`, false, nil},
		{`"n1"`, false, nil},
	} {
		got, why := decodeCorosyncNodes(json.RawMessage(tc.raw))
		if (why == "") != tc.ok || (tc.ok && !slices.Equal(got, tc.want)) {
			t.Errorf("decodeCorosyncNodes(%s) = %v, %q; want ok=%v %v", tc.raw, got, why, tc.ok, tc.want)
		}
	}
}

func TestClusterNodes_EmptyRosterNameIsRefusedWithoutARequest(t *testing.T) {
	s := pvefake.NewVMREST(t, "n1")
	srv := s.Server()
	defer srv.Close()
	ns := detClient(t, srv.URL+"/api2/json").ClusterNodes(context.Background(), "")
	if ns.Complete || len(s.Requests()) != 0 {
		t.Fatalf("%+v requests %v", ns, s.Requests())
	}
}

func TestNodeSet_ZeroValueIsNotComplete(t *testing.T) {
	var z NodeSet
	if z.Complete {
		t.Fatal("the zero NodeSet must not be complete")
	}
}
