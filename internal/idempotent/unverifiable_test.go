package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Regression tests for pveforge-read-guards-unverifiable (P1 of
// pveforge-read-status-swallow), at the Op layer. Each drives a REAL
// *pve.Client against a scripted HTTP server — the guards live in
// internal/pve, and an in-package fake of the pve interface would never
// exercise them — except the network tests, whose reads go through
// RawRequest and are driven through this package's own raw fakes.
//
// Every guard fixture serves 200 {"data":null}; see internal/pve's
// unverifiable_test.go for why a 595 fixture would stop killing its
// mutation after the pin bump.

const (
	uvNode   = "qa-pve-01"
	uvNull   = `{"data":null}`
	uvVMID   = 4242
	uvSource = 9137
)

type uvReply struct {
	status int
	body   string
}

// uvServer scripts replies by "METHOD /path"; a trailing "*" matches a
// prefix. A route may hold a sequence (the last reply repeats). Unrouted
// requests fail the test.
type uvServer struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string][]uvReply
	hits   map[string]int
}

func newUVServer(t *testing.T) *uvServer {
	t.Helper()
	return &uvServer{t: t, routes: map[string][]uvReply{}, hits: map[string]int{}}
}

func (s *uvServer) on(method, path string, replies ...uvReply) {
	s.routes[method+" "+path] = replies
}

func (s *uvServer) count(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[method+" "+path]
}

func (s *uvServer) client() *pve.Client {
	s.t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		s.mu.Lock()
		seq, ok := s.routes[key]
		if !ok {
			for k, v := range s.routes {
				if strings.HasSuffix(k, "*") && strings.HasPrefix(key, strings.TrimSuffix(k, "*")) {
					seq, ok, key = v, true, k
					break
				}
			}
		}
		idx := s.hits[key]
		s.hits[key]++
		s.mu.Unlock()
		if !ok {
			s.t.Errorf("unrouted request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unrouted", http.StatusTeapot)
			return
		}
		if idx >= len(seq) {
			idx = len(seq) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(seq[idx].status)
		_, _ = w.Write([]byte(seq[idx].body))
	}))
	s.t.Cleanup(srv.Close)
	c, err := pve.NewClient(pve.ClientConfig{BaseURLOverride: srv.URL, TokenID: "root@pam!pveforge", TokenSecret: "test-secret"})
	if err != nil {
		s.t.Fatalf("pve.NewClient: %v", err)
	}
	return c
}

func uvUPID(kind string, id int) string {
	return fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:%s:%d:root@pam:", uvNode, kind, id)
}

// uvTaskOK answers every task-status poll with success, echoing the UPID
// and node PVE always sends (go-proxmox copies them onto the Task).
func uvTaskOK(s *uvServer, upid string) {
	s.on("GET", "/nodes/"+uvNode+"/tasks/*", uvReply{200,
		fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, upid, uvNode)})
}

func uvKey(id int) lock.ObjectKey {
	return lock.ObjectKey{TargetID: uvNode, Kind: "vm", ID: fmt.Sprintf("%d", id)}
}

// --- P1-6: vm create -------------------------------------------------------

// A null GetVM must read as "cannot tell", which VMCreate.Read maps to
// absent by its documented design — so the create is issued, exactly once.
// Today the zero VM marshals to a non-empty string, Satisfied reports the
// VM already present, and no create is sent.
func TestVMCreate_EndToEnd_NullGetVMIsAbsentAndCreates(t *testing.T) {
	upid := uvUPID("qmcreate", uvVMID)
	s := newUVServer(t)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), uvReply{200, uvNull})
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID), uvReply{200, uvNull})
	s.on("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode), uvReply{200, fmt.Sprintf(`{"data":%q}`, upid)})
	uvTaskOK(s, upid)

	op := &VMCreate{Client: &realPVEClientAdapter{Client: s.client(), node: uvNode}, VMID: uvVMID,
		Params: url.Values{"cores": {"2"}}}
	res, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if posts := s.count("POST", fmt.Sprintf("/nodes/%s/qemu", uvNode)); posts != 1 {
		t.Fatalf("expected exactly 1 create POST, got %d (Changed=%v)", posts, res.Changed)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	// P3: after the create, the same null is a re-read that could not be
	// verified — AfterErr, never "absent", never a created-not-found.
	if !errors.Is(res.AfterErr, pve.ErrUnverifiableRead) || res.PostApplyErr != nil {
		t.Errorf("AfterErr %v, PostApplyErr %v; want ErrUnverifiableRead only", res.AfterErr, res.PostApplyErr)
	}
}

// --- P1-7: linked-clone storage-family pre-check ---------------------------

type uvCloneAdapter struct {
	*pve.Client
	node string
}

func (a *uvCloneAdapter) Node() string { return a.node }
func (a *uvCloneAdapter) CloneVM(ctx context.Context, src, dst int, params url.Values) (string, error) {
	return a.Client.CloneVM(ctx, a.node, src, dst, params)
}

// Both storage-status reads null leave both types "", which today compares
// equal and lets a linked clone proceed across storage families.
func TestVMClone_LinkedClone_NullStorageStatusRefuses(t *testing.T) {
	upid := uvUPID("qmclone", uvVMID)
	clonePath := fmt.Sprintf("/nodes/%s/qemu/%d/clone", uvNode, uvSource)
	s := newUVServer(t)
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID),
		uvReply{500, `{"data":null}`}) // new vmid absent: already an error today
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvSource),
		uvReply{200, fmt.Sprintf(`{"data":{"digest":"d","scsi0":"nfs-store:%d/base-%d-disk-0.qcow2,size=8G"}}`, uvSource, uvSource)})
	s.on("GET", fmt.Sprintf("/nodes/%s/storage/lvm-thin/status", uvNode), uvReply{200, uvNull})
	s.on("GET", fmt.Sprintf("/nodes/%s/storage/nfs-store/status", uvNode), uvReply{200, uvNull})
	s.on("POST", clonePath, uvReply{200, fmt.Sprintf(`{"data":%q}`, upid)})
	uvTaskOK(s, upid)

	op := &VMClone{Client: &uvCloneAdapter{Client: s.client(), node: uvNode}, SourceVMID: uvSource, NewVMID: uvVMID,
		Params: url.Values{"storage": {"lvm-thin"}}}
	_, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false)
	if posts := s.count("POST", clonePath); posts != 0 {
		t.Errorf("linked clone POST issued %d time(s) although neither storage type was verified", posts)
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected the clone to refuse with ErrUnverifiableRead, got %v", err)
	}
}

// --- P1-8: bridge isolation -------------------------------------------------

type uvBridgeAdapter struct {
	*pve.Client
	node         string
	isolateCalls int
}

func (a *uvBridgeAdapter) Node() string { return a.node }
func (a *uvBridgeAdapter) SetVMConfigFieldCAS(context.Context, int, string, string, string) error {
	return nil
}
func (a *uvBridgeAdapter) SetVMConfigField(context.Context, int, string, string) error { return nil }
func (a *uvBridgeAdapter) DeleteVMConfigFieldCAS(context.Context, int, string, string) error {
	return nil
}
func (a *uvBridgeAdapter) DeleteVMConfigField(context.Context, int, string) error { return nil }
func (a *uvBridgeAdapter) SetVMConfigFieldOverSSH(context.Context, int, string, string) error {
	return nil
}
func (a *uvBridgeAdapter) DeleteVMConfigFieldOverSSH(context.Context, int, string) error { return nil }
func (a *uvBridgeAdapter) UploadSnippet(context.Context, string, string, []byte) error {
	return nil
}
func (a *uvBridgeAdapter) TapLinkState(context.Context, string) (sshexec.TapLinkState, error) {
	return sshexec.TapLinkState{Exists: true, Isolated: false}, nil // live tap NOT isolated
}
func (a *uvBridgeAdapter) SetBridgePortIsolated(context.Context, string, bool) error {
	a.isolateCalls++
	return nil
}

// A null status/current reads as "not running" today, so an Op whose
// hookscript already matches reports itself satisfied and never isolates
// the live tap of a VM that is in fact running.
func TestBridgeIsolation_NullStatusRefuses(t *testing.T) {
	s := newUVServer(t)
	a := &uvBridgeAdapter{node: uvNode}
	op := &BridgeIsolationEnsure{Client: a, VMID: uvVMID, NetIndices: []int{0}, StorageID: "local"}
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/status/current", uvNode, uvVMID), uvReply{200, uvNull})
	s.on("GET", fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID),
		uvReply{200, fmt.Sprintf(`{"data":{"digest":"abc","hookscript":%q}}`, op.wantedHookscript())})
	a.Client = s.client()

	_, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false)
	if a.isolateCalls != 0 {
		t.Errorf("SetBridgePortIsolated called %d time(s) on an unverified read", a.isolateCalls)
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected Run to refuse with ErrUnverifiableRead, got %v", err)
	}
}

// --- P1-9: vm destroy's tag recheck ----------------------------------------

type uvDestroyAdapter struct {
	*pve.Client
	node string
}

func (a *uvDestroyAdapter) Node() string { return a.node }
func (a *uvDestroyAdapter) StopVM(ctx context.Context, vmid int) (string, error) {
	return a.Client.StopVM(ctx, a.node, vmid)
}
func (a *uvDestroyAdapter) DestroyVM(ctx context.Context, vmid int, purge bool) (string, error) {
	return a.Client.DestroyVM(ctx, a.node, vmid, purge)
}

// A null /cluster/resources is not "the recheck ran and found nothing":
// TagRecheckErr must carry the refusal.
func TestVMDestroy_NullResourcesIsTagRecheckError(t *testing.T) {
	stopU, delU := uvUPID("qmstop", uvVMID), uvUPID("qmdestroy", uvVMID)
	cfgPath := fmt.Sprintf("/nodes/%s/qemu/%d/config", uvNode, uvVMID)
	s := newUVServer(t)
	s.on("GET", cfgPath,
		uvReply{200, `{"data":{"digest":"d","tags":"web"}}`},
		uvReply{500, fmt.Sprintf(`Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist`, uvNode, uvVMID)})
	s.on("POST", fmt.Sprintf("/nodes/%s/qemu/%d/status/stop", uvNode, uvVMID), uvReply{200, fmt.Sprintf(`{"data":%q}`, stopU)})
	s.on("DELETE", fmt.Sprintf("/nodes/%s/qemu/%d", uvNode, uvVMID), uvReply{200, fmt.Sprintf(`{"data":%q}`, delU)})
	uvTaskOK(s, stopU)
	s.on("GET", "/cluster/resources", uvReply{200, uvNull})

	op := &VMDestroy{Client: &uvDestroyAdapter{Client: s.client(), node: uvNode}, VMID: uvVMID, Tag: "web"}
	if _, err := Run(context.Background(), testRosterPath(t), uvKey(uvVMID), op, false); err != nil {
		t.Fatalf("Run: %v (the destroy itself must still succeed; only the recheck is unverifiable)", err)
	}
	if !errors.Is(op.TagRecheckErr, pve.ErrUnverifiableRead) {
		t.Fatalf("expected TagRecheckErr to wrap ErrUnverifiableRead, got %v", op.TagRecheckErr)
	}
}

// --- P1-10: network fields' "every other interface" guard ------------------

// A null interface list makes both snapshots empty, so the comparison is
// vacuous and the commit proceeds without having checked anything.
func TestNetworkFieldsEnsure_NullOtherInterfacesListRefuses(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: nil}} // marshals to JSON null
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5",
		Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if client.commitCalls != 0 || client.stageCalls != 0 {
		t.Errorf("stage=%d commit=%d on an unverified interface list", client.stageCalls, client.commitCalls)
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead, got %v", err)
	}
}

// A node always lists at least the interface being edited, so an EMPTY list
// is as unverifiable as a null one.
func TestNetworkFieldsEnsure_EmptyOtherInterfacesListRefuses(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{}}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5",
		Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if client.commitCalls != 0 || client.stageCalls != 0 {
		t.Errorf("stage=%d commit=%d on an empty interface list", client.stageCalls, client.commitCalls)
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead, got %v", err)
	}
}

// --- Network bridge: null body and the missing-interface classifier -------

func uvNetOp(client *fakeNetworkBridgeClient, iface string) *NetworkBridgeEnsure {
	// Wanted empty = destroy: the direction in which "absent" satisfies the
	// Op and a misread silently no-ops while reporting success.
	return &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: iface, ManagementBridge: "vmbr0"}
}

func TestNetworkBridgeEnsure_Destroy_NullBodyIsUnverifiableNotAbsent(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr1"] = []getResponse{{fields: nil}} // marshals to JSON null
	op := uvNetOp(client, "vmbr1")
	cur, err := op.Read(context.Background())
	if err == nil && op.Satisfied(cur) {
		t.Fatal("destroy reported satisfied (a silent no-op) on a null interface read")
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead, got %v", err)
	}
}

// Near misses: an error that says "does not exist" about something OTHER
// than the interface being read must never make it read as absent.
func TestNetworkBridgeEnsure_Destroy_UnrelatedDoesNotExistIsNotAbsent(t *testing.T) {
	cases := []struct{ name, text string }{
		{"a different object", `raw request: pve returned 500 Internal Server Error: user 'svc@pve' does not exist`},
		{"a longer interface name", `raw request: pve returned 500 Internal Server Error: iface 'vmbr10' does not exist`},
		{"a different parameter", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"storage":"storage 'local' does not exist"},"data":null}`},
		{"a different parameter (vmid)", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"vmid":"VM 4242 does not exist"},"data":null}`},
		{"the iface parameter, but not missing", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"iface":"invalid format - value does not look like a valid interface name"},"data":null}`},
		{"the iface parameter, while another parameter is missing", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"iface":"invalid format","storage":"storage 'local' does not exist"},"data":null}`},
		{"a transport error quoting the request URL", `raw request: Get "https://pve1:8006/api2/json/nodes/pve1/network/vmbr1": proxy target does not exist`},
		// The four fail-open shapes the P1 cross-review found, driven the
		// way it drove them: end to end through Read and Satisfied.
		{"(b) the name and the phrase, not adjacent", `raw request: pve returned 500 Internal Server Error: bridge 'vmbr1': port 'eno9' does not exist`},
		{"(c) the iface entry names a different interface", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"iface":"interface 'vmbr10' does not exist"},"data":null}`},
		{"(d) another parameter's entry names the interface", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"storage":"storage 'vmbr1' does not exist"},"data":null}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := newFakeNetworkBridgeClient("pve1")
			client.getResponses["vmbr1"] = []getResponse{{err: fixtureErr(c.text)}}
			op := uvNetOp(client, "vmbr1")
			cur, err := op.Read(context.Background())
			if err == nil {
				t.Fatalf("read as absent (satisfied=%v) from an unrelated error: %s", op.Satisfied(cur), c.text)
			}
		})
	}
}

// (a) from the cross-review: an alias interface on the target's parent.
// PVE's pve-iface format allows a [:.]<digits> suffix, so "eth0:1" is a
// different interface from "eth0".
func TestNetworkBridgeEnsure_Destroy_AliasInterfaceIsNotTheParent(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["eth0"] = []getResponse{{err: pveAnswer(`raw request: pve returned 500 Internal Server Error: iface 'eth0:1' does not exist`)}}
	op := uvNetOp(client, "eth0")
	if cur, err := op.Read(context.Background()); err == nil {
		t.Fatalf("eth0 read as absent (satisfied=%v) from an error about eth0:1", op.Satisfied(cur))
	}
}

// TestIsMissingNetworkInterfaceError pins the classifier directly: every
// near miss must NOT classify as the target missing (a false "absent" turns
// a destroy into a silent no-op), and every accepted genuine shape must.
func TestIsMissingNetworkInterfaceError(t *testing.T) {
	const pve500 = "raw request: pve returned 500 Internal Server Error: "
	const pve400 = "raw request: pve returned 400 Parameter verification failed.: "
	param := func(entries string) string { return pve400 + `{"errors":{` + entries + `},"data":null}` }
	notMissing := []struct{ name, iface, text string }{
		{"alias of the target", "eth0", pve500 + "iface 'eth0:1' does not exist"},
		{"VLAN child of the target", "vmbr1", pve500 + "iface 'vmbr1.100' does not exist"},
		{"target is a suffix of the named interface", "br0", pve500 + "iface 'vmbr0' does not exist"},
		{"target is a suffix, veth", "eth0", pve500 + "iface 'veth0' does not exist"},
		{"target is a prefix, underscore", "vmbr1", pve500 + "iface 'vmbr1_x' does not exist"},
		{"target is a prefix, dash", "vmbr1", pve500 + "iface 'vmbr1-x' does not exist"},
		{"target is a prefix, digit", "vmbr1", pve500 + "iface 'vmbr10' does not exist"},
		{"same name, different case", "vmbr1", pve500 + "iface 'VMBR1' does not exist"},
		{"name and phrase, not adjacent", "vmbr1", pve500 + "bridge 'vmbr1': port 'eno9' does not exist"},
		{"name adjacent but phrase further on", "vmbr1", pve500 + "iface 'vmbr1' has port 'eno9' that does not exist"},
		{"unstructured, wrong noun", "vmbr1", pve500 + "storage 'vmbr1' does not exist"},
		{"unstructured, unquoted name", "vmbr1", pve500 + "iface vmbr1 does not exist"},
		{"names the target, no phrase", "vmbr1", pve500 + "iface 'vmbr1' is not a bridge"},
		{"unrelated object", "vmbr1", pve500 + "user 'svc@pve' does not exist"},
		{"not an answer from PVE", "vmbr1", `raw request: Get "https://pve1:8006/api2/json/nodes/pve1/network/vmbr1": iface 'vmbr1' does not exist`},
		{"iface entry names a different interface", "vmbr1", param(`"iface":"interface 'vmbr10' does not exist"`)},
		{"iface entry names another, other style", "vmbr1", param(`"iface":"iface 'eth3' does not exist"`)},
		{"iface entry names the target in another case", "vmbr1", param(`"iface":"interface 'VMBR1' does not exist"`)},
		{"iface entry names two interfaces", "vmbr1", param(`"iface":"interface 'vmbr1' does not exist; did you mean 'vmbr10'?"`)},
		{"iface entry, unquoted different name", "vmbr1", param(`"iface":"interface vmbr10 does not exist"`)},
		{"iface entry names the target, no phrase", "vmbr1", param(`"iface":"interface 'vmbr1' is not a bridge"`)},
		{"another parameter names the target", "vmbr1", param(`"storage":"storage 'vmbr1' does not exist"`)},
		{"another parameter says it, iface says otherwise", "vmbr1", param(`"iface":"invalid format","storage":"storage 'local' does not exist"`)},
		{"structured body present: unstructured text not consulted", "vmbr1", pve500 + `iface 'vmbr1' does not exist {"errors":{"storage":"bad"},"data":null}`},
		{"empty target", "", param(`"iface":"interface does not exist"`)},
		{"malformed structured body: unstructured text not consulted", "vmbr1", pve500 + `iface 'vmbr1' does not exist {"errors":{"storage": }`},
		{"noun is part of a longer word", "vmbr1", pve500 + "subinterface 'vmbr1' does not exist"},
	}
	for _, c := range notMissing {
		t.Run("not/"+c.name, func(t *testing.T) {
			if isMissingNetworkInterfaceError(fixtureErr(c.text), c.iface) {
				t.Fatalf("classified %q as missing from: %s", c.iface, c.text)
			}
		})
	}
	missing := []struct{ name, iface, text string }{
		{"unstructured, iface noun, single quotes", "vmbr1", pve500 + "iface 'vmbr1' does not exist"},
		{"unstructured, interface noun, double quotes", "vmbr1", pve500 + `interface "vmbr1" does not exist`},
		{"unstructured, noun and phrase in another case", "vmbr1", pve500 + "Interface 'vmbr1' DOES NOT EXIST"},
		{"unstructured, alias target", "eth0:1", pve500 + "iface 'eth0:1' does not exist"},
		{"iface entry, generic", "vmbr1", param(`"iface":"interface does not exist"`)},
		{"iface entry names the target", "vmbr1", param(`"iface":"interface 'vmbr1' does not exist"`)},
		{"iface entry names the target in double quotes", "vmbr1", param(`"iface":"interface \"vmbr1\" does not exist"`)},
		{"iface entry names a VLAN target", "vmbr1.100", param(`"iface":"interface 'vmbr1.100' does not exist"`)},
		{"iface entry names a mixed-case target", "vmbrA", param(`"iface":"interface 'vmbrA' does not exist"`)},
	}
	for _, c := range missing {
		t.Run("missing/"+c.name, func(t *testing.T) {
			if !isMissingNetworkInterfaceError(fixtureErr(c.text), c.iface) {
				t.Fatalf("did not classify %q as missing from: %s", c.iface, c.text)
			}
		})
	}
}

// Controls: both plausible shapes of a genuine missing-interface answer
// must still read as absent, so anchoring cannot over-narrow into a hard
// error. PVE's exact text is unverified against a live host; the second
// shape is PVE's parameter-verification form for the iface parameter.
func TestNetworkBridgeEnsure_Destroy_GenuineMissingInterfaceIsAbsent(t *testing.T) {
	cases := []struct{ name, text string }{
		{"names the interface", `raw request: pve returned 500 Internal Server Error: iface 'vmbr1' does not exist`},
		{"iface parameter error", `raw request: pve returned 400 Parameter verification failed.: {"errors":{"iface":"interface does not exist"},"data":null}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := newFakeNetworkBridgeClient("pve1")
			client.getResponses["vmbr1"] = []getResponse{{err: fixtureErr(c.text)}}
			op := uvNetOp(client, "vmbr1")
			cur, err := op.Read(context.Background())
			if err != nil {
				t.Fatalf("a genuine missing interface must read as absent, got %v", err)
			}
			if !op.Satisfied(cur) {
				t.Fatal("destroy of an absent interface must be satisfied")
			}
		})
	}
}

// The management-bridge guard already refuses on a null read, but with the
// misleading reason "does not exist"; it must say the read was unverifiable.
func TestNetworkBridgeEnsure_NullManagementBridgeIsUnverifiable(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: nil}}
	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr9", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"}}
	err := op.Apply(context.Background())
	if client.stageCalls != 0 {
		t.Errorf("stage issued %d time(s) with an unverified management bridge", client.stageCalls)
	}
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead, got %v", err)
	}
}
