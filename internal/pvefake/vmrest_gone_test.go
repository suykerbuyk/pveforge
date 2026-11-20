package pvefake

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The U5 additions to the VMREST fixture, each pinned by its own fidelity test
// so a mutation of the FIXTURE (reverting a shape to the one U3/U4 shipped) is
// observed red here rather than silently greening a consumer.

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func dataObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	return env.Data
}

// G1: the per-task endpoint answers in read_task_status's shape, not the list's.
func TestVMREST_G1_PerTaskStatusIsNotTheListShape(t *testing.T) {
	s := NewVMREST(t, "n1")
	s.Tasks = []TaskRow{
		{UPID: "UPID:n1:1:1:1:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 5, Status: "OK", EndTime: 6, Saved: true, Node: "n1", User: "root@pam"},
		{UPID: "UPID:n1:2:2:2:qmdestroy:691:root@pam:", Type: "qmdestroy", ID: "691", StartTime: 5, Status: "WARNINGS: 1", EndTime: 6, Saved: true, Node: "n1", User: "root@pam"},
		{UPID: "UPID:n1:3:3:3:qmdestroy:692:root@pam:", Type: "qmdestroy", ID: "692", StartTime: 5, Status: "RUNNING", Node: "n1", User: "root@pam"},
	}
	srv := s.Server()
	defer srv.Close()
	for _, tc := range []struct {
		upid, status, exit string
		hasExit            bool
	}{
		{s.Tasks[0].UPID, "stopped", "OK", true},
		{s.Tasks[1].UPID, "stopped", "WARNINGS: 1", true},
		{s.Tasks[2].UPID, "running", "", false},
	} {
		code, body := get(t, srv.URL+"/api2/json/nodes/n1/tasks/"+tc.upid+"/status")
		d := dataObject(t, body)
		if code != 200 || d["status"] != tc.status {
			t.Errorf("%s: HTTP %d status=%v, want %q (the list spells a running row RUNNING; the per-task endpoint says running)", tc.upid, code, d["status"], tc.status)
		}
		ex, has := d["exitstatus"]
		if has != tc.hasExit || (has && ex != tc.exit) {
			t.Errorf("%s: exitstatus=%v present=%v, want %q present=%v", tc.upid, ex, has, tc.exit, tc.hasExit)
		}
		if d["type"] != "qmdestroy" || d["upid"] != tc.upid {
			t.Errorf("%s: identity fields %v / %v", tc.upid, d["type"], d["upid"])
		}
	}
}

// G2: a missing config is PVE's 500 naming the config path (a classifier
// anchors on it); a 403 is what an invisible VM reads; neither is a 404.
func TestVMREST_G2_ConfigModes(t *testing.T) {
	s := NewVMREST(t, "n1")
	srv := s.Server()
	defer srv.Close()
	u := srv.URL + "/api2/json/nodes/n1/qemu/690/config"

	code, body := get(t, u)
	if code != 500 || !strings.Contains(body, "Configuration file 'nodes/n1/qemu-server/690.conf' does not exist") {
		t.Errorf("absent: HTTP %d %s, want 500 naming nodes/n1/qemu-server/690.conf", code, body)
	}
	s.ConfigStatus = 403
	code, body = get(t, u)
	if code != 403 || !strings.Contains(body, "Permission check failed (/vms/690, VM.Audit)") {
		t.Errorf("forbidden: HTTP %d %s", code, body)
	}
	s.ConfigStatus = 0
	s.VMConfig = `{"digest":"d"}`
	if code, _ := get(t, u); code != 200 {
		t.Errorf("present: HTTP %d, want 200", code)
	}
	s.StatusCurrentStatus = 403
	if code, body := get(t, srv.URL+"/api2/json/nodes/n1/qemu/690/status/current"); code != 403 || !strings.Contains(body, "VM.Audit") {
		t.Errorf("status/current forbidden: HTTP %d %s", code, body)
	}
}

// G3: nextid answers PER VMID with arbitrary bodies, so one vmid can be free
// while another is in use and a client that forgot to send the vmid is seen.
func TestVMREST_G3_NextIDPerVMID(t *testing.T) {
	s := NewVMREST(t, "n1")
	s.NextID = map[string]NextIDAnswer{
		"690": {Body: `"690"`},
		"691": {Code: 400, Body: NextIDInUseBody("691")},
		"692": {Body: `692`},
		"693": {Body: `"694"`},
		"694": {Code: 400, Body: NextIDInUseMasterBody("694")},
	}
	srv := s.Server()
	defer srv.Close()
	for vmid, want := range map[string]struct {
		code int
		sub  string
	}{
		"690": {200, `"data":"690"`},
		"691": {400, `"errors":{"vmid":"VM 691 already exists"}`},
		"692": {200, `"data":692`},
		"693": {200, `"data":"694"`},
		"694": {400, `guest ID 694 is already in use`},
	} {
		code, body := get(t, srv.URL+"/api2/json/cluster/nextid?vmid="+vmid)
		if code != want.code || !strings.Contains(body, want.sub) {
			t.Errorf("vmid %s: HTTP %d %s, want %d containing %s", vmid, code, body, want.code, want.sub)
		}
	}
	// the default for an unlisted vmid is still the bool.
	if code, _ := get(t, srv.URL+"/api2/json/cluster/nextid?vmid=999"); code != 400 {
		t.Errorf("unlisted vmid with NextIDFree=false: HTTP %d, want 400", code)
	}
}

// G4: peers are served through the one server, each with its own node-local
// index; an offline peer is a proxy failure; member lists default to a healthy
// cluster and are scriptable.
func TestVMREST_G4_PeersAndMemberLists(t *testing.T) {
	s := NewVMREST(t, "n1")
	s.Tasks = []TaskRow{{UPID: "UPID:n1:1:1:1:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 1, Status: "OK", EndTime: 2, Saved: true}}
	s.Peers = map[string]*PeerNode{
		"n2": {Tasks: []TaskRow{{UPID: "UPID:n2:1:1:1:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 9, Status: "WARNINGS: 1", EndTime: 10, Saved: true}}},
		"n3": {Offline: true},
		"n4": {NodeStatus: 403},
	}
	srv := s.Server()
	defer srv.Close()
	api := srv.URL + "/api2/json"

	if _, rows := getRows(t, api+"/nodes/n1/tasks?source=all&vmid=690&limit=9"); len(rows) != 1 || rows[0]["status"] != "OK" {
		t.Errorf("roster rows: %v", rows)
	}
	if _, rows := getRows(t, api+"/nodes/n2/tasks?source=all&vmid=690&limit=9"); len(rows) != 1 || rows[0]["status"] != "WARNINGS: 1" {
		t.Errorf("peer n2 rows (its OWN index, not the roster's): %v", rows)
	}
	if code, _ := get(t, api+"/nodes/n3/status"); code != 595 {
		t.Errorf("offline peer status: HTTP %d, want 595", code)
	}
	if code, _ := get(t, api+"/nodes/n3/tasks?source=all&limit=9"); code != 595 {
		t.Errorf("offline peer tasks: HTTP %d, want 595", code)
	}
	if code, body := get(t, api+"/nodes/n4/status"); code != 403 || !strings.Contains(body, "Sys.Audit") {
		t.Errorf("peer n4 status: HTTP %d %s, want 403 naming Sys.Audit", code, body)
	}
	// default member lists: roster + every peer, in both endpoints.
	for _, p := range []string{"/cluster/config/nodes", "/nodes"} {
		code, body := get(t, api+p)
		for _, n := range []string{"n1", "n2", "n3", "n4"} {
			if code != 200 || !strings.Contains(body, `"node":"`+n+`"`) {
				t.Errorf("%s default list %s (HTTP %d) lacks %s", p, body, code, n)
			}
		}
	}
	// scripted, and a 403 on the authority names the privilege on /.
	s.ClusterNodes = `[]`
	if _, body := get(t, api+"/cluster/config/nodes"); !strings.Contains(body, `"data":[]`) {
		t.Errorf("scripted empty list: %s", body)
	}
	s.ClusterNodesStatus = 403
	if code, body := get(t, api+"/cluster/config/nodes"); code != 403 || !strings.Contains(body, "(/, Sys.Audit)") {
		t.Errorf("authority 403: HTTP %d %s", code, body)
	}
}

// G5: sequenced scripts. The second answer is actually SERVED (Count proves it).
func TestVMREST_G5_SequencedScripts(t *testing.T) {
	s := NewVMREST(t, "n1")
	old := TaskRow{UPID: "UPID:n1:1:1:1:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 1, Status: "OK", EndTime: 2, Saved: true}
	newer := TaskRow{UPID: "UPID:n1:2:2:2:qmdestroy:690:root@pam:", Type: "qmdestroy", ID: "690", StartTime: 8, Status: "WARNINGS: 1", EndTime: 9, Saved: true}
	s.TaskSnapshots = map[string][][]TaskRow{"n1": {{old}, {old, newer}}}
	s.Script = map[string][]Reply{
		"GET /cluster/config/nodes": {{Body: `[{"node":"n1"},{"node":"n2"}]`}, {Body: `[]`}},
		"GET /nodes":                {{Body: `[{"node":"n1"}]`, Code: 0}},
	}
	s.Peers = map[string]*PeerNode{"n2": {}}
	srv := s.Server()
	defer srv.Close()
	api := srv.URL + "/api2/json"

	q := api + "/nodes/n1/tasks?source=all&vmid=690&limit=9"
	_, r1 := getRows(t, q)
	_, r2 := getRows(t, q)
	_, r3 := getRows(t, q)
	if len(r1) != 1 || len(r2) != 2 || len(r3) != 2 {
		t.Errorf("snapshot sequence: %d, %d, %d rows, want 1, 2, 2 (the last repeats)", len(r1), len(r2), len(r3))
	}
	if n := s.Count("GET", "/api2/json/nodes/n1/tasks"); n != 3 {
		t.Errorf("Count = %d, want 3", n)
	}
	_, b1 := get(t, api+"/cluster/config/nodes")
	_, b2 := get(t, api+"/cluster/config/nodes")
	_, b3 := get(t, api+"/cluster/config/nodes")
	if !strings.Contains(b1, "n2") || strings.Contains(b2, "n1") || strings.Contains(b3, "n1") {
		t.Errorf("member-list script: %s | %s | %s, want the full list once then [] repeating", b1, b2, b3)
	}
	if s.Count("GET", "/api2/json/cluster/config/nodes") != 3 {
		t.Error("the scripted endpoint's request count is wrong")
	}
}

// G6: the pool path is SERVED, so a consumer that reads it is observed.
func TestVMREST_G6_PoolIsServed(t *testing.T) {
	s := NewVMREST(t, "n1")
	srv := s.Server()
	defer srv.Close()
	if code, _ := get(t, srv.URL+"/api2/json/pools/p1"); code != 200 {
		t.Errorf("pool: HTTP %d, want 200", code)
	}
	s.PoolStatus = 403
	if code, body := get(t, srv.URL+"/api2/json/pools/p1"); code != 403 || !strings.Contains(body, "Permission check failed") {
		t.Errorf("pool 403: HTTP %d %s", code, body)
	}
	s.ResourcesStatus = 403
	if code, _ := get(t, srv.URL+"/api2/json/cluster/resources?type=vm"); code != 403 {
		t.Errorf("resources 403: HTTP %d", code)
	}
}
