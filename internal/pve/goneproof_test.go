package pve

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// These tests call JudgeGone / judge DIRECTLY and assert the VERDICT. The
// central invariant: never GONE unless proven; never block permanently on a
// healthy cluster. Every table row is paired so the instrument is shown to move
// (a reachable GONE next to every refusal).

const gNode = "n1"
const gVMID = 690

func gRow(node, upid string, start int64, status string, end int64) pvefake.TaskRow {
	return pvefake.TaskRow{UPID: upid, Type: "qmdestroy", ID: strconv.Itoa(gVMID), StartTime: start, Status: status, EndTime: end, Saved: true, Node: node, User: "root@pam"}
}

// gOK / gWarn: a terminal destroy on node ending OK / WARNINGS at start.
func gOK(node string, start int64) pvefake.TaskRow {
	return gRow(node, fmt.Sprintf("UPID:%s:OK%d", node, start), start, "OK", start+2)
}
func gWarn(node string, start int64) pvefake.TaskRow {
	return gRow(node, fmt.Sprintf("UPID:%s:WARN%d", node, start), start, "WARNINGS: 1", start+2)
}

// goneFixture is a healthy three-node cluster {n1 roster, n2, n3}: the vmid is
// free, every member's index is served, and rows script each node's task log.
func goneFixture(t *testing.T, roster []pvefake.TaskRow, peers map[string][]pvefake.TaskRow, mut func(s *pvefake.VMREST)) (*pvefake.VMREST, *Client) {
	t.Helper()
	s := pvefake.NewVMREST(t, gNode)
	s.NextIDFree = true
	s.Tasks = roster
	s.Peers = map[string]*pvefake.PeerNode{}
	for _, n := range []string{"n2", "n3"} {
		s.Peers[n] = &pvefake.PeerNode{Tasks: peers[n]}
	}
	if mut != nil {
		mut(s)
	}
	srv := s.Server()
	t.Cleanup(srv.Close)
	return s, detClient(t, srv.URL+"/api2/json")
}

func retry(presence Presence) GoneEvidence { return GoneEvidence{Presence: presence} }

func judgeOn(c *Client, ev GoneEvidence) *GoneVerdict {
	return c.JudgeGone(context.Background(), gNode, gVMID, ev)
}

func wantSituation(t *testing.T, v *GoneVerdict, want GoneSituation) {
	t.Helper()
	if v == nil {
		t.Fatal("nil verdict")
	}
	if v.Situation != want {
		t.Fatalf("situation %q, want %q (gone=%v): %+v", v.Situation, want, v.Gone, v)
	}
	if v.Gone != (want == GoneProven) {
		t.Fatalf("Gone=%v with situation %q", v.Gone, v.Situation)
	}
}

// requestsMatching counts recorded requests whose rendering contains sub.
func requestsMatching(s *pvefake.VMREST, sub string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.Contains(r, sub) {
			n++
		}
	}
	return n
}

func indexOfRequest(s *pvefake.VMREST, sub string, from int) int {
	for i, r := range s.Requests() {
		if i >= from && strings.Contains(r, sub) {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------- T-judge

type destroyAxis int

const (
	dNone destroyAxis = iota
	dOK
	dWarn
	dErr
	dReadFailed
	dInFlight // a retry-only cell: a non-terminal hazardous task on a member
)

func (d destroyAxis) String() string {
	return [...]string{"none", "OK", "WARNINGS", "error", "readFailed", "inFlight"}[d]
}

// expect is the ORACLE, written out from the plan's §4 rules and not derived
// from the production switch: the check and the thing checked must not be the
// same object.
func expect(dispatched bool, presence Presence, free VMIDState, d destroyAxis) GoneSituation {
	if presence == PresenceHere {
		if dispatched {
			return GoneUnproven
		}
		return GoneUnreadable
	}
	switch free {
	case VMIDUnverified:
		if dispatched {
			return GoneUnproven
		}
		return GoneUnreadable
	case VMIDInUse:
		if dispatched {
			return GoneUnproven // never Elsewhere after our own dispatch
		}
		return GoneElsewhere
	}
	// free
	if dispatched {
		switch d {
		case dOK:
			return GoneProven
		case dWarn, dErr:
			return GoneUnclean
		}
		return GoneUnproven
	}
	switch d {
	case dNone:
		return GoneAbsentNoTask
	case dOK:
		return GoneProven
	case dWarn, dErr:
		return GoneUnclean
	case dInFlight:
		return GoneInFlightElsewhere
	}
	return GoneUnreadable
}

func TestJudge_Table(t *testing.T) {
	produced := map[GoneSituation]int{}
	cells := 0
	for _, dispatched := range []bool{false, true} {
		for _, presence := range []Presence{PresenceUnreadable, PresenceHere, PresenceAbsent, PresenceForbidden} {
			for _, free := range []VMIDState{VMIDFree, VMIDInUse, VMIDUnverified} {
				for _, d := range []destroyAxis{dNone, dOK, dWarn, dErr, dReadFailed, dInFlight} {
					if dispatched && d == dInFlight {
						continue // a dispatching invocation never scans
					}
					name := fmt.Sprintf("dispatched=%v/presence=%d/free=%d/%s", dispatched, presence, free, d)
					ev := GoneEvidence{Presence: presence, Dispatched: dispatched}
					sr := scanResult{}
					switch d {
					case dOK:
						row := gOK(gNode, 100)
						ev.Destroy = &DestroyEnd{UPID: row.UPID, ExitStatus: "OK"}
						r := TaskRow{UPID: row.UPID, Status: "OK", StartTime: 100, EndTime: 102}
						sr.Newest, sr.NewestNode = &r, gNode
					case dWarn, dErr:
						st := "WARNINGS: 1"
						if d == dErr {
							st = "unable to remove volume"
						}
						ev.Destroy = &DestroyEnd{UPID: "UPID:x", ExitStatus: st}
						r := TaskRow{UPID: "UPID:x", Status: st, StartTime: 100, EndTime: 102}
						sr.Newest, sr.NewestNode = &r, gNode
					case dReadFailed:
						ev.DestroyReadErr = "read failed"
						sr.Refusal = unreadableRefusal("n2", gVMID, "task list for node n2", "boom")
					case dInFlight:
						sr.Refusal = inFlightRefusal(SituationDestroy, "n2", gVMID, TaskRow{UPID: "UPID:n2:run", Type: "qmdestroy"})
					}
					fr := FreeResult{State: free, Read: "GET /cluster/nextid", Detail: "d"}
					if free == VMIDFree {
						fr.Detail = ""
					}
					placed := 0
					v := judge(gNode, gVMID, fr, ev, func() scanResult { return sr }, func() Placement { placed++; return Placement{Node: "n9", Seen: true, Read: "GET /cluster/resources"} })
					want := expect(dispatched, presence, free, d)
					cells++
					if v.Situation != want {
						t.Errorf("%s: %q, want %q", name, v.Situation, want)
						continue
					}
					if v.Gone != (want == GoneProven) {
						t.Errorf("%s: Gone=%v for %q", name, v.Gone, want)
					}
					produced[v.Situation]++
					if v.Gone {
						continue
					}
					// I5: the vmid, an observation, and the change-condition.
					text := v.Observed + "\n" + v.Condition
					if !strings.Contains(text, strconv.Itoa(gVMID)) || v.Observed == "" || v.Condition == "" {
						t.Errorf("%s: a %q verdict does not name vmid + observation + condition: %+v", name, v.Situation, v)
					}
					if want == GoneElsewhere && placed != 1 {
						t.Errorf("%s: the placement read ran %d times, want exactly 1 (detail only)", name, placed)
					}
					if want != GoneElsewhere && placed != 0 {
						t.Errorf("%s: the placement read ran for a %q verdict", name, want)
					}
				}
			}
		}
	}
	if cells < 120 {
		t.Fatalf("only %d cells: the table shrank", cells)
	}
	// anti-vacuity: every one of the seven verdicts was PRODUCED by some cell.
	for _, s := range []GoneSituation{GoneProven, GoneUnclean, GoneElsewhere, GoneAbsentNoTask, GoneUnproven, GoneUnreadable, GoneInFlightElsewhere} {
		if produced[s] == 0 {
			t.Errorf("no cell produced %q: the table cannot see it", s)
		}
	}
}

// grok F2 and the InUse pair, spelled out: the SAME input differs only in the
// Dispatched bit.
func TestJudge_DispatchedBitSplitsTheSameInput(t *testing.T) {
	scan := func() scanResult { t.Fatal("scan ran"); return scanResult{} }
	place := func() Placement { return Placement{} }
	for _, tc := range []struct {
		name string
		free VMIDState
		post GoneSituation
		ret  GoneSituation
	}{
		{"free-proof unverified", VMIDUnverified, GoneUnproven, GoneUnreadable},
		{"vmid in use", VMIDInUse, GoneUnproven, GoneElsewhere},
	} {
		fr := FreeResult{State: tc.free, Read: "GET /cluster/nextid", Detail: "d"}
		post := judge(gNode, gVMID, fr, GoneEvidence{Dispatched: true, Destroy: &DestroyEnd{UPID: "u", ExitStatus: "OK"}}, scan, place)
		if post.Situation != tc.post {
			t.Errorf("%s, dispatched: %q, want %q (a refusal here would hide an UNKNOWN)", tc.name, post.Situation, tc.post)
		}
		ret := judge(gNode, gVMID, fr, GoneEvidence{}, scan, place)
		if ret.Situation != tc.ret {
			t.Errorf("%s, retry: %q, want %q", tc.name, ret.Situation, tc.ret)
		}
	}
}

func TestJudge_ZeroValuesNeverMeanGone(t *testing.T) {
	scan := func() scanResult { return scanResult{} }
	place := func() Placement { return Placement{} }
	if v := judge(gNode, gVMID, FreeResult{}, GoneEvidence{}, scan, place); v.Gone {
		t.Fatal("zero FreeResult read as gone")
	}
	if v := judge(gNode, gVMID, FreeResult{State: VMIDFree}, GoneEvidence{Dispatched: true}, scan, place); v.Gone {
		t.Fatal("a dispatched invocation with no destroy evidence read as gone")
	}
	if v := judge(gNode, gVMID, FreeResult{State: VMIDFree}, GoneEvidence{}, func() scanResult { return scanResult{} }, place); v.Gone {
		t.Fatal("a retry with no destroy row read as gone")
	}
}

// ---------------------------------------------------------------- T-nodes

// OD-1 / G15: the newest destroy ACROSS ALL members decides.
func TestJudgeGone_NewestAcrossAllMembers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		roster []pvefake.TaskRow
		peers  map[string][]pvefake.TaskRow
		want   GoneSituation
		on     string
	}{
		{"old OK on the roster, newer WARNINGS on a peer (codex U5-1)", []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 500)}}, GoneUnclean, "n2"},
		{"the inverse: old WARNINGS on a peer, newer OK on the roster", []pvefake.TaskRow{gOK("n1", 500)}, map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 100)}}, GoneProven, "n1"},
		{"newer OK on a peer over an older roster OK", []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n3": {gOK("n3", 500)}}, GoneProven, "n3"},
		{"tie: roster OK, peer WARNINGS", []pvefake.TaskRow{gOK("n1", 300)}, map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 300)}}, GoneUnclean, "n2"},
		{"tie: roster WARNINGS, peer OK", []pvefake.TaskRow{gWarn("n1", 300)}, map[string][]pvefake.TaskRow{"n2": {gOK("n2", 300)}}, GoneUnclean, "n1"},
		{"only the roster has a row", []pvefake.TaskRow{gOK("n1", 100)}, nil, GoneProven, "n1"},
		{"only a peer has a row", nil, map[string][]pvefake.TaskRow{"n3": {gOK("n3", 100)}}, GoneProven, "n3"},
		{"no row on any member", nil, nil, GoneAbsentNoTask, ""},
		{"three nodes, newest WARNINGS is on the LAST peer", []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {gOK("n2", 200)}, "n3": {gWarn("n3", 900)}}, GoneUnclean, "n3"},
		{"three nodes, newest WARNINGS is on the FIRST peer", []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 900)}, "n3": {gOK("n3", 200)}}, GoneUnclean, "n2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := goneFixture(t, tc.roster, tc.peers, nil)
			v := judgeOn(c, retry(PresenceAbsent))
			wantSituation(t, v, tc.want)
			if tc.on != "" && v.DecidedOn != tc.on {
				t.Errorf("decided on %q, want %q", v.DecidedOn, tc.on)
			}
		})
	}
}

// G16: ANY member unreadable ⇒ not GONE, naming THAT node; the same fixture made
// readable reaches GONE (the instrument moves).
func TestJudgeGone_AnyMemberUnreadableIsNeverGone(t *testing.T) {
	good := []pvefake.TaskRow{gOK("n1", 100)}
	_, c := goneFixture(t, good, nil, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven) // control

	full := make([]pvefake.TaskRow, destroyTaskListLimit)
	for i := range full {
		full[i] = gOK("n2", int64(10+i))
	}
	for _, tc := range []struct {
		name string
		mut  func(s *pvefake.VMREST)
		priv string
	}{
		{"offline member", func(s *pvefake.VMREST) { s.Peers["n2"].Offline = true }, ""},
		{"probe 403", func(s *pvefake.VMREST) { s.Peers["n2"].NodeStatus = 403 }, "Sys.Audit on /nodes/n2"},
		{"task list 500", func(s *pvefake.VMREST) { s.Peers["n2"].TasksStatus = 500 }, ""},
		{"full page", func(s *pvefake.VMREST) { s.Peers["n2"].Tasks = full }, ""},
		{"undecodable body", func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /nodes/n2/tasks": {{Body: `[{"endtime":"soon","id":"690","type":"qmdestroy"}]`}}}
		}, ""},
		{"last member offline", func(s *pvefake.VMREST) { s.Peers["n3"].Offline = true }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := goneFixture(t, good, nil, tc.mut)
			v := judgeOn(c, retry(PresenceAbsent))
			wantSituation(t, v, GoneUnreadable)
			if v.OtherNode != "n2" && v.OtherNode != "n3" {
				t.Errorf("the verdict names node %q", v.OtherNode)
			}
			if tc.priv != "" && v.Privilege != tc.priv {
				t.Errorf("privilege %q, want %q", v.Privilege, tc.priv)
			}
		})
	}
	// a stalled member is bounded by the caller's context and the deadline fired.
	_, c = goneFixture(t, good, nil, func(s *pvefake.VMREST) { s.Peers["n2"].StallTasks = 30 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	v := c.JudgeGone(ctx, gNode, gVMID, retry(PresenceAbsent))
	if ctx.Err() == nil {
		t.Fatal("the deadline never fired: the stall measured nothing")
	}
	wantSituation(t, v, GoneUnreadable)

	// an EMPTY peer page is not a failure (B14).
	_, c = goneFixture(t, good, map[string][]pvefake.TaskRow{"n2": {}}, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
}

// G20: a non-terminal hazardous task on ANY member refuses, for each of the seven
// types; an allowed type does not.
func TestJudgeGone_HazardousTaskOnAMemberRefuses(t *testing.T) {
	for typ := range wantHazard {
		for _, onNode := range []string{"n1", "n2"} {
			t.Run(typ+"@"+onNode, func(t *testing.T) {
				row := pvefake.TaskRow{UPID: "UPID:" + onNode + ":run:" + typ, Type: typ, ID: "690", StartTime: 700, Status: "RUNNING", Node: onNode}
				roster := []pvefake.TaskRow{gOK("n1", 100)}
				peers := map[string][]pvefake.TaskRow{}
				if onNode == "n1" {
					roster = append(roster, row)
				} else {
					peers["n2"] = []pvefake.TaskRow{row}
				}
				_, c := goneFixture(t, roster, peers, nil)
				v := judgeOn(c, retry(PresenceAbsent))
				wantSituation(t, v, GoneInFlightElsewhere)
				if v.OtherNode != onNode || v.UPID != row.UPID || !strings.Contains(v.Observed, typ) {
					t.Errorf("%+v", v)
				}
			})
		}
	}
	allowed := pvefake.TaskRow{UPID: "UPID:n2:run:reset", Type: "qmreset", ID: "690", StartTime: 700, Status: "RUNNING", Node: "n2"}
	_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {allowed}}, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
}

// G19: the free-proof comes first. A vmid in use costs no member read.
func TestJudgeGone_InUseCostsNoScan(t *testing.T) {
	s, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {gOK("n2", 200)}}, func(s *pvefake.VMREST) {
		s.NextID = map[string]pvefake.NextIDAnswer{"690": {Code: 400, Body: pvefake.NextIDInUseBody("690")}}
		s.Resources = `[{"type":"qemu","vmid":690,"node":"n2"}]`
	})
	v := judgeOn(c, retry(PresenceAbsent))
	wantSituation(t, v, GoneElsewhere)
	if v.OtherNode != "n2" || !strings.Contains(v.Observed, "n2") {
		t.Errorf("placement naming: %+v", v)
	}
	for _, sub := range []string{"/nodes/", "/cluster/config/nodes", "GET /api2/json/nodes ?"} {
		if n := requestsMatching(s, sub); n != 0 {
			t.Errorf("%d requests matching %q on an in-use vmid: %v", n, sub, s.Requests())
		}
	}
	if requestsMatching(s, "/cluster/nextid") != 1 || requestsMatching(s, "/cluster/resources") != 1 {
		t.Errorf("requests = %v, want one nextid and one placement read", s.Requests())
	}
}

// G18: the post-dispatch path holds its own UPID and does not scan: an offline
// member, or a broken member list, must not block a clean ok.
func TestJudgeGone_PostDispatchDoesNotScan(t *testing.T) {
	s, c := goneFixture(t, nil, nil, func(s *pvefake.VMREST) {
		s.Peers["n2"].Offline = true
		s.ClusterNodesStatus = 403
		s.NodesIndexStatus = 500
	})
	ev := GoneEvidence{Presence: PresenceAbsent, Dispatched: true, Destroy: &DestroyEnd{UPID: "UPID:n1:own", ExitStatus: "OK"}}
	v := judgeOn(c, ev)
	wantSituation(t, v, GoneProven)
	if v.UPID != "UPID:n1:own" {
		t.Errorf("decided on %q, not our own destroy", v.UPID)
	}
	if got := s.Requests(); len(got) != 1 || !strings.Contains(got[0], "/cluster/nextid") {
		t.Errorf("requests = %v, want exactly the one nextid read", got)
	}
	// ... and our own non-OK end is UNCLEAN, our own unreadable end UNPROVEN.
	ev.Destroy = &DestroyEnd{UPID: "UPID:n1:own", ExitStatus: "WARNINGS: 2"}
	wantSituation(t, judgeOn(c, ev), GoneUnclean)
	ev.Destroy, ev.DestroyReadErr = nil, "status poll failed"
	wantSituation(t, judgeOn(c, ev), GoneUnproven)
}

// G11/G13 end to end: the SAME fixtures, only the bit differs.
func TestJudgeGone_FreeProofFailuresByDispatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(s *pvefake.VMREST)
		post GoneSituation
		ret  GoneSituation
	}{
		{"in use", func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{"690": {Code: 400, Body: pvefake.NextIDInUseBody("690")}}
		}, GoneUnproven, GoneElsewhere},
		{"nextid 500", func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{"690": {Code: 500, Body: `{"message":"boom"}`}}
		}, GoneUnproven, GoneUnreadable},
		{"nextid echoes another vmid", func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{"690": {Body: `"691"`}}
		}, GoneUnproven, GoneUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, tc.mut)
			post := GoneEvidence{Presence: PresenceAbsent, Dispatched: true, Destroy: &DestroyEnd{UPID: "u", ExitStatus: "OK"}}
			wantSituation(t, judgeOn(c, post), tc.post)
			wantSituation(t, judgeOn(c, retry(PresenceAbsent)), tc.ret)
		})
	}
}

// G8 (grok F7): a token that cannot see the VM is not blocked, and the pool leg is
// never read. The fixture SERVES the pool path, so a consumer that reads it is
// observed rather than failing as "unscripted".
func TestJudgeGone_ForbiddenIsNotBlockedAndPoolIsNeverRead(t *testing.T) {
	roster := []pvefake.TaskRow{gOK("n1", 100)}
	for _, presence := range []Presence{PresenceAbsent, PresenceForbidden, PresenceUnreadable} {
		s, c := goneFixture(t, roster, nil, func(s *pvefake.VMREST) {
			s.PoolStatus = 403
			s.ResourcesStatus = 403
			s.ConfigStatus = 403
		})
		wantSituation(t, judgeOn(c, retry(presence)), GoneProven)
		for _, sub := range []string{"/pools/", "/cluster/resources", "/qemu/"} {
			if n := requestsMatching(s, sub); n != 0 {
				t.Errorf("presence %d: %d requests matching %q on the free path", presence, n, sub)
			}
		}
	}
	// Forbidden and Absent give the SAME class for every free-proof/destroy input
	// (the free-proof is the discriminator), differing only in wording.
	for _, mut := range []func(s *pvefake.VMREST){
		nil,
		func(s *pvefake.VMREST) { s.Tasks = []pvefake.TaskRow{gWarn("n1", 100)} },
		func(s *pvefake.VMREST) { s.Tasks = nil },
		func(s *pvefake.VMREST) {
			s.NextID = map[string]pvefake.NextIDAnswer{"690": {Code: 400, Body: pvefake.NextIDInUseBody("690")}}
		},
	} {
		_, c := goneFixture(t, roster, nil, mut)
		a, f := judgeOn(c, retry(PresenceAbsent)), judgeOn(c, retry(PresenceForbidden))
		if a.Situation != f.Situation {
			t.Errorf("absent %q vs forbidden %q: the node-local read decided the class", a.Situation, f.Situation)
		}
	}
}

// E2: the zombie — config left with the destroyed lock, task terminal non-OK,
// vmid in use, token reads 403: a refusal that says the VM is invisible.
func TestJudgeGone_ZombieIsElsewhereInvisible(t *testing.T) {
	_, c := goneFixture(t, []pvefake.TaskRow{gWarn("n1", 100)}, nil, func(s *pvefake.VMREST) {
		s.ConfigStatus = 403
		s.NextID = map[string]pvefake.NextIDAnswer{"690": {Code: 400, Body: pvefake.NextIDInUseBody("690")}}
	})
	v := judgeOn(c, retry(PresenceForbidden))
	wantSituation(t, v, GoneElsewhere)
	if !v.Invisible || !strings.Contains(v.Observed, "cannot see") {
		t.Errorf("%+v", v)
	}
	v = judgeOn(c, retry(PresenceAbsent))
	if v.Invisible {
		t.Error("an absent config is not 'invisible'")
	}
}

// G9: the principal-filtered placement read is never decisive.
func TestJudgeGone_PlacementShapesOnlyTheDetail(t *testing.T) {
	inUse := map[string]pvefake.NextIDAnswer{"690": {Code: 400, Body: pvefake.NextIDInUseBody("690")}}
	for name, mut := range map[string]func(s *pvefake.VMREST){
		"empty":    func(s *pvefake.VMREST) { s.Resources = `[]` },
		"a row":    func(s *pvefake.VMREST) { s.Resources = `[{"type":"qemu","vmid":690,"node":"n3"}]` },
		"403":      func(s *pvefake.VMREST) { s.ResourcesStatus = 403 },
		"500":      func(s *pvefake.VMREST) { s.ResourcesStatus = 500 },
		"garbage":  func(s *pvefake.VMREST) { s.Resources = `{"nope":1}` },
		"null row": func(s *pvefake.VMREST) { s.Resources = `[null]` },
	} {
		t.Run(name, func(t *testing.T) {
			_, c := goneFixture(t, nil, nil, func(s *pvefake.VMREST) { s.NextID = inUse; mut(s) })
			wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneElsewhere)
		})
	}
}

// E11: a caller that passes Here is refused, never GONE, for either bit.
func TestJudgeGone_PresentIsNeverGone(t *testing.T) {
	_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, nil)
	wantSituation(t, judgeOn(c, retry(PresenceHere)), GoneUnreadable)
	wantSituation(t, judgeOn(c, GoneEvidence{Presence: PresenceHere, Dispatched: true, Destroy: &DestroyEnd{UPID: "u", ExitStatus: "OK"}}), GoneUnproven)
}

// ---------------------------------------------------------------- T-snapshots

// U5-D1 (G22/E16): U4 reads the roster node and sees OK; the retry reads it
// AGAIN, fresh, and a newer WARNINGS row has appeared. Healthy cluster, no
// fault.
func TestJudgeGone_RetryRereadsTheRosterNode(t *testing.T) {
	okOld := gOK("n1", 100)
	warnNew := gWarn("n1", 500)
	s, c := goneFixture(t, nil, nil, func(s *pvefake.VMREST) {
		s.TaskSnapshots = map[string][][]pvefake.TaskRow{"n1": {{okOld}, {okOld, warnNew}}}
	})
	d := c.DetermineDestroyInFlight(context.Background(), gNode, gVMID)
	if !d.Proceed || d.LastDestroy == nil || !d.LastDestroyEndedOK {
		t.Fatalf("U4's snapshot did not see the old OK: %+v", d)
	}
	v := judgeOn(c, retry(PresenceAbsent))
	wantSituation(t, v, GoneUnclean)
	if v.UPID != warnNew.UPID || v.DecidedOn != "n1" {
		t.Errorf("decided on %s@%s", v.UPID, v.DecidedOn)
	}
	// the second scripted answer was actually SERVED, and the roster read came
	// AFTER the free-proof.
	if n := s.Count("GET", "/api2/json/nodes/n1/tasks"); n != 2 {
		t.Errorf("roster task reads = %d, want 2 (U4's, then the retry's fresh one)", n)
	}
	nid := indexOfRequest(s, "/cluster/nextid", 0)
	second := indexOfRequest(s, "/nodes/n1/tasks", indexOfRequest(s, "/nodes/n1/tasks", 0)+1)
	if nid < 0 || second < nid {
		t.Errorf("order: nextid at %d, the retry's roster task read at %d: %v", nid, second, s.Requests())
	}
	if requestsMatching(s, "/nodes/n1/status") != 2 {
		t.Errorf("the roster was not probed afresh: %v", s.Requests())
	}
}

func TestJudgeGone_RetryRereadsTheRosterNode_Inverse(t *testing.T) {
	warnOld := gWarn("n1", 100)
	okNew := gOK("n1", 500)
	_, c := goneFixture(t, nil, nil, func(s *pvefake.VMREST) {
		s.TaskSnapshots = map[string][][]pvefake.TaskRow{"n1": {{warnOld}, {warnOld, okNew}}}
	})
	if d := c.DetermineDestroyInFlight(context.Background(), gNode, gVMID); d.LastDestroyEndedOK {
		t.Fatalf("U4's snapshot should see the old WARNINGS: %+v", d)
	}
	v := judgeOn(c, retry(PresenceAbsent))
	wantSituation(t, v, GoneProven)
	if v.UPID != okNew.UPID {
		t.Errorf("decided on %s, want the newer OK row", v.UPID)
	}
}

func TestJudgeGone_RetryRereadsTheRosterNode_PeerUnderRoster(t *testing.T) {
	// U4 sees roster OK@400; the roster then shows OK@900; a peer holds WARNINGS@600.
	// Fresh fold: the roster's newer OK is the newest ⇒ GONE. A stale roster row
	// (OK@400) would lose to the peer and say UNCLEAN.
	ok1, ok2 := gOK("n1", 400), gOK("n1", 900)
	_, c := goneFixture(t, nil, map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 600)}}, func(s *pvefake.VMREST) {
		s.TaskSnapshots = map[string][][]pvefake.TaskRow{"n1": {{ok1}, {ok1, ok2}}}
	})
	_ = c.DetermineDestroyInFlight(context.Background(), gNode, gVMID)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
}

// ---------------------------------------------------------------- T-collapse

// U5-D2 (G23/E15): the client sends nextid BEFORE the member reads, and each is a
// separate API request that refreshes the cluster state anew. The fixture scripts
// the member reads by per-endpoint call count, so nextid answers Free and the
// member endpoints answer empty / local-only; a hidden peer holds a newer
// WARNINGS row. It must NOT be GONE.
func TestJudgeGone_CollapsedMemberViewIsNeverGone(t *testing.T) {
	roster := []pvefake.TaskRow{gOK("n1", 100)}
	hidden := map[string][]pvefake.TaskRow{"n2": {gWarn("n2", 900)}}
	for name, mut := range map[string]func(s *pvefake.VMREST){
		"both empty": func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /cluster/config/nodes": {{Body: `[]`}}, "GET /nodes": {{Body: `[]`}}}
		},
		"empty authority, local-only /nodes": func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /cluster/config/nodes": {{Body: `[]`}}, "GET /nodes": {{Body: `[{"node":"n1"}]`}}}
		},
		"authority without the roster": func(s *pvefake.VMREST) {
			s.Script = map[string][]pvefake.Reply{"GET /cluster/config/nodes": {{Body: `[{"node":"n2"}]`}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, c := goneFixture(t, roster, hidden, mut)
			v := judgeOn(c, retry(PresenceAbsent))
			wantSituation(t, v, GoneUnreadable)
			if !strings.Contains(v.ReadErr, "membership unknown") {
				t.Errorf("detail %q", v.ReadErr)
			}
			if requestsMatching(s, "/nodes/n2/") != 0 {
				t.Error("a peer was read although the membership was unknown")
			}
		})
	}
	// the control: the same fixture with the real member list reaches the fold, and
	// the hidden peer's newer WARNINGS row decides.
	_, c := goneFixture(t, roster, hidden, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneUnclean)

	// a sequence: healthy, then collapsed.
	_, c = goneFixture(t, roster, nil, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{"GET /cluster/config/nodes": {{Body: `[{"node":"n1"},{"node":"n2"},{"node":"n3"}]`}, {Body: `[]`}}}
	})
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneUnreadable)
}

// R-STANDALONE, pinned: on a standalone host (empty corosync list) a retry refuses;
// the post-dispatch path (own UPID, no scan) is unaffected; and a genuine ONE-node
// cluster whose corosync list names it is not refused for being small.
func TestJudgeGone_StandaloneIsTheAcceptedCost(t *testing.T) {
	standalone := func(s *pvefake.VMREST) {
		s.Peers = map[string]*pvefake.PeerNode{}
		s.ClusterNodes = `[]`
	}
	_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, standalone)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneUnreadable)
	ev := GoneEvidence{Presence: PresenceAbsent, Dispatched: true, Destroy: &DestroyEnd{UPID: "u", ExitStatus: "OK"}}
	wantSituation(t, judgeOn(c, ev), GoneProven)

	_, c = goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, func(s *pvefake.VMREST) {
		s.Peers = map[string]*pvefake.PeerNode{}
		s.ClusterNodes = `[{"node":"n1"}]`
	})
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
}

// ---------------------------------------------------------------- forwarding

func TestRoutedForwarding_GoneProofMethods(t *testing.T) {
	for _, c := range []struct {
		node string
		vmid int
	}{{fwdTargetNode, fwdVMID}, {fwdTargetNode2, fwdVMID2}} {
		t.Run(c.node, func(t *testing.T) {
			upid := fmt.Sprintf("UPID:%s:0000ABCD:0000ABCD:66AC0000:qmdestroy:%d:root@pam:", c.node, c.vmid)
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/cluster/nextid"):
					writeData(w, fmt.Sprintf(`"%s"`, r.URL.Query().Get("vmid")))
				case strings.HasSuffix(r.URL.Path, "/status"):
					if strings.Contains(r.URL.Path, "/tasks/") {
						writeData(w, fmt.Sprintf(`{"upid":%q,"type":"qmdestroy","id":"%d","node":%q,"status":"stopped","exitstatus":"OK"}`, upid, c.vmid, c.node))
						return
					}
					writeData(w, `{"uptime":1}`)
				case strings.HasSuffix(r.URL.Path, "/cluster/config/nodes"):
					writeData(w, fmt.Sprintf(`[{"node":%q}]`, c.node))
				case strings.HasSuffix(r.URL.Path, "/nodes"):
					writeData(w, fmt.Sprintf(`[{"node":%q}]`, c.node))
				case strings.HasSuffix(r.URL.Path, "/cluster/resources"):
					writeData(w, fmt.Sprintf(`[{"type":"qemu","vmid":%d,"node":"elsewhere"}]`, c.vmid))
				default:
					writeData(w, `[]`)
				}
			})
			rc := fwdClientOn(t, srv, c.node)
			ctx := context.Background()

			if r := rc.FreeProof(ctx, c.vmid); r.State != VMIDFree {
				t.Fatalf("FreeProof: %+v", r)
			}
			end, err := rc.DestroyEnd(ctx, c.vmid, upid)
			if err != nil || !end.EndedOK() {
				t.Fatalf("DestroyEnd: %+v, %v", end, err)
			}
			if p := rc.PlacementOf(ctx, c.vmid); !p.Seen || p.Node != "elsewhere" {
				t.Fatalf("PlacementOf: %+v", p)
			}
			if ns := rc.ClusterNodes(ctx); !ns.Complete || !slices.Equal(ns.Names, []string{c.node}) {
				t.Fatalf("ClusterNodes: %+v (the target's node is the roster)", ns)
			}
			v := rc.JudgeGone(ctx, c.vmid, GoneEvidence{Presence: PresenceAbsent})
			wantSituation(t, v, GoneAbsentNoTask)
			if v.Node != c.node || v.VMID != c.vmid {
				t.Errorf("verdict about %s/%d, want %s/%d", v.Node, v.VMID, c.node, c.vmid)
			}
			var lines []string
			for _, r := range rec.got() {
				lines = append(lines, r.String())
			}
			got := strings.Join(lines, "\n")
			for _, want := range []string{
				fmt.Sprintf("GET /nodes/%s/tasks/", c.node),
				fmt.Sprintf("GET /cluster/nextid?vmid=%d", c.vmid),
				fmt.Sprintf("GET /nodes/%s/status", c.node),
				fmt.Sprintf("GET /nodes/%s/tasks?limit=%d&source=all&vmid=%d", c.node, destroyTaskListLimit, c.vmid),
			} {
				if !strings.Contains(got, want) {
					t.Errorf("no request %q in:\n%s", want, got)
				}
			}
		})
	}
}

// A /nodes entry with no name, end to end (codex F-01): the authority names only
// the roster, /nodes adds an unnamed entry, nextid is Free and the roster holds an
// OK row ⇒ UNREADABLE, never GONE.
func TestJudgeGone_UnnamedNodesEntryIsNeverGone(t *testing.T) {
	_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, func(s *pvefake.VMREST) {
		s.Peers = map[string]*pvefake.PeerNode{}
		s.ClusterNodes = `[{"node":"n1"}]`
		s.NodesIndex = `[{"node":"n1"},{"node":""}]`
	})
	v := judgeOn(c, retry(PresenceAbsent))
	wantSituation(t, v, GoneUnreadable)
	if !strings.Contains(v.ReadErr, "no node name") {
		t.Errorf("detail %q", v.ReadErr)
	}
	// the control: without the unnamed entry the same fixture is GONE.
	_, c = goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, nil, func(s *pvefake.VMREST) {
		s.Peers = map[string]*pvefake.PeerNode{}
		s.ClusterNodes = `[{"node":"n1"}]`
		s.NodesIndex = `[{"node":"n1"}]`
	})
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)
}

// B9: the newest DESTROY decides, not the newest row of any type. A newer
// terminal non-destroy task for the same vmid (a qmstart shares the id) with a
// failing status must not shadow an exactly-OK destroy, nor an OK one hide a
// newer failed destroy.
func TestJudgeGone_NewestDestroyNotNewestRow(t *testing.T) {
	later := pvefake.TaskRow{UPID: "UPID:n2:start", Type: "qmstart", ID: "690", StartTime: 900, Status: "WARNINGS: 1", EndTime: 901, Saved: true, Node: "n2"}
	_, c := goneFixture(t, []pvefake.TaskRow{gOK("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {later}}, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneProven)

	okLater := pvefake.TaskRow{UPID: "UPID:n2:start", Type: "qmstart", ID: "690", StartTime: 900, Status: "OK", EndTime: 901, Saved: true, Node: "n2"}
	_, c = goneFixture(t, []pvefake.TaskRow{gWarn("n1", 100)}, map[string][]pvefake.TaskRow{"n2": {okLater}}, nil)
	wantSituation(t, judgeOn(c, retry(PresenceAbsent)), GoneUnclean)
}
