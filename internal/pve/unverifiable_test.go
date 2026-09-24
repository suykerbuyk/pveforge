package pve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Regression tests for pveforge-read-guards-unverifiable (P1 of
// pveforge-read-status-swallow). go-proxmox's handleResponse decodes a
// {"data":null} body into the target's zero value with a nil error — for a
// 200, and before pveforge-status-error-pin-bump also for
// 404/502/503/504/595-599 — so a read that PVE never actually answered
// looks like a real, empty answer. Every guard under test turns such a
// payload into ErrUnverifiableRead.
//
// Fixtures deliberately serve 200 {"data":null} rather than a 595: since
// pveforge-status-error-pin-bump, a non-2xx is a *proxmox.StatusError
// before any of these guards runs, and a guard test built on one would
// stay green with its guard deleted. The single exception is the cause-agnostic
// headline replay of the measured incident,
// TestOrphanVolumes_Swallowed595SharedStatusRefuses.

const nullData = `{"data":null}`

// routeReply is one scripted answer; routes are keyed "METHOD /path" (query
// string excluded) and a request with no route fails the test, so a fixture
// that silently misses a read cannot pass by accident.
type routeReply struct {
	status int
	body   string
}

type routeServer struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]routeReply
	hits   map[string]int
}

func newRouteServer(t *testing.T) *routeServer {
	t.Helper()
	return &routeServer{t: t, routes: map[string]routeReply{}, hits: map[string]int{}}
}

func (s *routeServer) on(method, path string, status int, body string) {
	s.routes[method+" "+path] = routeReply{status: status, body: body}
}

func (s *routeServer) count(method, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[method+" "+path]
}

func (s *routeServer) client() *Client {
	s.t.Helper()
	srv := newFakeAPIServer(s.t, func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		s.mu.Lock()
		reply, ok := s.routes[key]
		if !ok {
			for k, v := range s.routes {
				if strings.HasSuffix(k, "*") && strings.HasPrefix(key, strings.TrimSuffix(k, "*")) {
					reply, ok, key = v, true, k
					break
				}
			}
		}
		s.hits[key]++
		s.mu.Unlock()
		if !ok {
			s.t.Errorf("unrouted request %s %s", r.Method, r.URL.Path)
			http.Error(w, "unrouted", http.StatusTeapot)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.status)
		_, _ = w.Write([]byte(reply.body))
	})
	return testClient(s.t, srv)
}

func requireUnverifiable(t *testing.T, err error, mustName string) {
	t.Helper()
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("expected an error wrapping ErrUnverifiableRead, got %v", err)
	}
	if mustName != "" && !strings.Contains(err.Error(), mustName) {
		t.Errorf("error %q does not name the object %q it was reading", err, mustName)
	}
}

// --- The measured incident, replayed -------------------------------------

// TestOrphanVolumes_Swallowed595SharedStatusRefuses replays the defect
// measured on main: storage "nfs-shared" is shared, but its status read
// answers 595 {"data":null} (pveproxy cannot reach the node), which today
// decodes to Shared == 0, bypasses the shared-storage refusal, and returns
// VM 200's volume as an orphan. Cause-agnostic on purpose: it asserts only
// that the scan refuses and reports nothing, so it compiles and stays
// meaningful on both pins — whichever layer catches the swallow.
func TestOrphanVolumes_Swallowed595SharedStatusRefuses(t *testing.T) {
	for _, status := range []int{595, 404, 503, 599} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			s := newRouteServer(t)
			s.on("GET", "/nodes/n1/storage/nfs-shared/status", status, nullData)
			s.on("GET", "/nodes/n1/storage/nfs-shared/content", 200,
				`{"data":[{"volid":"nfs-shared:200/vm-200-disk-0.qcow2","vmid":200,"content":"images","format":"qcow2","size":1}]}`)
			s.on("GET", "/nodes/n1/qemu", 200, `{"data":[]}`)

			orphans, err := s.client().OrphanVolumes(context.Background(), "n1", "nfs-shared")
			if err == nil {
				t.Fatalf("scan did not refuse a storage whose status read was swallowed (%d); returned %d orphan(s)", status, len(orphans))
			}
			if len(orphans) != 0 {
				t.Fatalf("scan refused but still returned %d orphan(s)", len(orphans))
			}
		})
	}
}

// TestOrphanVolumes_Status595IsReportedAsTheStatus is the same incident,
// discriminating the CAUSE: on v0.8.2-pveforge.0 the 595 was swallowed and
// the scan refused only because P1's GetStorage guard saw a null payload,
// so the error said "unverifiable read" and nothing about the node being
// unreachable. With the typed status error the refusal names the 595.
// Compiles on both pins (see statusLine in statuserror_test.go).
func TestOrphanVolumes_Status595IsReportedAsTheStatus(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/storage/nfs-shared/status", 595, nullData)
	s.on("GET", "/nodes/n1/storage/nfs-shared/content", 200,
		`{"data":[{"volid":"nfs-shared:200/vm-200-disk-0.qcow2","vmid":200,"content":"images","format":"qcow2","size":1}]}`)
	s.on("GET", "/nodes/n1/qemu", 200, `{"data":[]}`)

	orphans, err := s.client().OrphanVolumes(context.Background(), "n1", "nfs-shared")
	if len(orphans) != 0 {
		t.Fatalf("scan returned %d orphan(s) from a storage whose status read failed", len(orphans))
	}
	requireStatusCause(t, err, 595)
}

// --- P1-1 .. P1-5: the orphan scan and its reads -------------------------

func TestOrphanVolumes_NullSharedStatusIsUnverifiable(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/storage/nfs-shared/status", 200, nullData)
	s.on("GET", "/nodes/n1/storage/nfs-shared/content", 200,
		`{"data":[{"volid":"nfs-shared:200/vm-200-disk-0.qcow2","vmid":200,"content":"images","format":"qcow2","size":1}]}`)
	s.on("GET", "/nodes/n1/qemu", 200, `{"data":[]}`)

	orphans, err := s.client().OrphanVolumes(context.Background(), "n1", "nfs-shared")
	requireUnverifiable(t, err, "nfs-shared")
	if len(orphans) != 0 {
		t.Fatalf("expected no orphans alongside the refusal, got %d", len(orphans))
	}
}

// On UNSHARED storage the scan is allowed to run, which makes a swallowed
// VM list the most dangerous case: no VMs means nothing is claimed, so a
// disk in active use by VM 4242 would be reported as an orphan.
func TestOrphanVolumes_NullVMListDoesNotOrphanInUseDisk(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/storage/local-lvm/status", 200, `{"data":{"type":"lvmthin","shared":0,"active":1}}`)
	s.on("GET", "/nodes/n1/storage/local-lvm/content", 200,
		`{"data":[{"volid":"local-lvm:vm-4242-disk-0","vmid":4242,"content":"images","format":"raw","size":1}]}`)
	s.on("GET", "/nodes/n1/qemu", 200, nullData)

	orphans, err := s.client().OrphanVolumes(context.Background(), "n1", "local-lvm")
	for _, o := range orphans {
		if o.Volid == "local-lvm:vm-4242-disk-0" {
			t.Errorf("in-use disk %s reported as an orphan", o.Volid)
		}
	}
	requireUnverifiable(t, err, "n1")
}

// The null guard must not forbid a legitimately empty answer: a node with
// no VMs answers {"data":[]}, which decodes to an empty non-nil slice.
func TestGetVMs_EmptyListIsAnAnswerNotUnverifiable(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/qemu", 200, `{"data":[]}`)

	vms, err := s.client().GetVMs(context.Background(), "n1")
	if err != nil {
		t.Fatalf("an empty VM list is a valid answer, got error %v", err)
	}
	if len(vms) != 0 {
		t.Fatalf("expected 0 VMs, got %d", len(vms))
	}
}

func TestClaimedVolumes_NullConfigIsUnverifiable(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/qemu/4242/status/current", 200, `{"data":{"vmid":4242,"status":"running","name":"web"}}`)
	s.on("GET", "/nodes/n1/qemu/4242/config", 200, nullData)

	claimed, err := s.client().ClaimedVolumes(context.Background(), "n1", 4242)
	requireUnverifiable(t, err, "4242")
	if claimed != nil {
		t.Fatalf("expected no claimed set alongside the refusal, got %v", claimed)
	}
}

// vmidFree treats any nil error as "free". A null answer is not PVE saying
// the id is free; it is PVE saying nothing.
func TestVMIDFree_NullAnswerIsUnverifiable(t *testing.T) {
	s := newRouteServer(t)
	s.on("GET", "/cluster/nextid", 200, nullData)
	c := s.client()

	free, err := c.vmidFree(context.Background(), 4242)
	if free {
		t.Error("vmidFree reported a vmid free on a null answer")
	}
	requireUnverifiable(t, err, "4242")

	got, err := c.NextVMID(context.Background(), 4242)
	if err == nil {
		t.Fatalf("NextVMID(pin 4242) accepted a null nextid answer and returned %d", got)
	}
	requireUnverifiable(t, err, "")
}

// --- P1-11: a snapshot create must not skip its collision check ----------

func TestCreateSnapshot_NullListRefusesBeforePost(t *testing.T) {
	const upid = "UPID:n1:00001234:00005678:12345678:qmsnapshot:4242:root@pam:"
	s := newRouteServer(t)
	s.on("GET", "/nodes/n1/qemu/4242/snapshot", 200, nullData)
	s.on("POST", "/nodes/n1/qemu/4242/snapshot", 200, fmt.Sprintf(`{"data":%q}`, upid))
	s.on("GET", "/nodes/n1/tasks/*", 200,
		fmt.Sprintf(`{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":"n1"}}`, upid))

	err := s.client().CreateSnapshot(context.Background(), "n1", 4242, "pre-upgrade", "")
	if posts := s.count("POST", "/nodes/n1/qemu/4242/snapshot"); posts != 0 {
		t.Errorf("snapshot create POST issued %d time(s) although the collision check never saw a real list", posts)
	}
	requireUnverifiable(t, err, "4242")
}

// --- P1-12: every guarded LIST read --------------------------------------

// Each list read must refuse {"data":null} as unverifiable and must still
// accept {"data":[]} as the legitimate answer it is. The null-vs-empty
// distinction is real: encoding/json leaves a nil slice for null and makes
// an empty non-nil slice for [].
func TestListReads_NullIsUnverifiable_EmptyIsAnswer(t *testing.T) {
	ctx := context.Background()
	type result struct {
		n   int
		err error
	}
	cases := []struct {
		name       string
		path       string
		read       func(c *Client) result
		emptyCheck func(t *testing.T, r result) // behaviour on {"data":[]}
	}{
		{"GetVMs", "/nodes/n1/qemu", func(c *Client) result { v, err := c.GetVMs(ctx, "n1"); return result{len(v), err} }, nil},
		{"GetStorages", "/nodes/n1/storage", func(c *Client) result { v, err := c.GetStorages(ctx, "n1"); return result{len(v), err} }, nil},
		{"GetStorageVolumes", "/nodes/n1/storage/local/content", func(c *Client) result {
			v, err := c.GetStorageVolumes(ctx, "n1", "local")
			return result{len(v), err}
		}, nil},
		{"storageContentWithType", "/nodes/n1/storage/local/content", func(c *Client) result {
			v, err := c.storageContentWithType(ctx, "n1", "local")
			return result{len(v), err}
		}, nil},
		{"ListSnapshots", "/nodes/n1/qemu/4242/snapshot", func(c *Client) result {
			v, err := c.ListSnapshots(ctx, "n1", 4242)
			return result{len(v), err}
		}, nil},
		{"GetNetworkInterfaces", "/nodes/n1/network", func(c *Client) result {
			v, err := c.GetNetworkInterfaces(ctx, "n1")
			return result{len(v), err}
		}, nil},
		{"ListNodes", "/nodes", func(c *Client) result { v, err := c.ListNodes(ctx); return result{len(v), err} }, nil},
		{"GetNodes", "/nodes", func(c *Client) result { v, err := c.GetNodes(ctx); return result{len(v), err} }, nil},
		{"FindByTag", "/cluster/resources", func(c *Client) result {
			r, err := c.FindByTag(ctx, "web")
			n := 0
			if r != nil {
				n = 1
			}
			return result{n, err}
		}, func(t *testing.T, r result) {
			// An empty cluster has no match for any tag: that is a real
			// not-found, not an unverifiable read.
			if !errors.Is(r.err, ErrNotFound) || errors.Is(r.err, ErrUnverifiableRead) {
				t.Fatalf("empty resource list: want ErrNotFound only, got %v", r.err)
			}
		}},
		{"TagStillClaimed", "/cluster/resources", func(c *Client) result {
			claimed, err := c.TagStillClaimed(ctx, "web", 4242)
			n := 0
			if claimed {
				n = 1
			}
			return result{n, err}
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/null", func(t *testing.T) {
			s := newRouteServer(t)
			s.on("GET", tc.path, 200, nullData)
			r := tc.read(s.client())
			requireUnverifiable(t, r.err, "")
			if r.n != 0 {
				t.Fatalf("returned %d item(s) alongside the refusal", r.n)
			}
		})
		t.Run(tc.name+"/empty", func(t *testing.T) {
			s := newRouteServer(t)
			s.on("GET", tc.path, 200, `{"data":[]}`)
			r := tc.read(s.client())
			if tc.emptyCheck != nil {
				tc.emptyCheck(t, r)
				return
			}
			if r.err != nil || r.n != 0 {
				t.Fatalf("an empty list is a valid answer: got n=%d err=%v", r.n, r.err)
			}
		})
	}
}

// --- P1-13 and the object reads: a missing identity field -----------------

func TestObjectReads_NullIsUnverifiable_HealthyIsAccepted(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		routes  map[string]string // path -> body, all 200
		read    func(c *Client) error
		objName string
	}{
		{"GetStorage/null", map[string]string{"/nodes/n1/storage/nfs-shared/status": nullData},
			func(c *Client) error { _, err := c.GetStorage(ctx, "n1", "nfs-shared"); return err }, "nfs-shared"},
		{"GetNetworkInterface/null", map[string]string{"/nodes/n1/network/vmbr7": nullData},
			func(c *Client) error { _, err := c.GetNetworkInterface(ctx, "n1", "vmbr7"); return err }, "vmbr7"},
		{"GetVM/status-null", map[string]string{
			"/nodes/n1/qemu/4242/status/current": nullData,
			"/nodes/n1/qemu/4242/config":         `{"data":{"digest":"d","name":"web"}}`,
		}, func(c *Client) error { _, err := c.GetVM(ctx, "n1", 4242); return err }, "4242"},
		{"GetVM/config-null", map[string]string{
			"/nodes/n1/qemu/4242/status/current": `{"data":{"vmid":4242,"status":"running"}}`,
			"/nodes/n1/qemu/4242/config":         nullData,
		}, func(c *Client) error { _, err := c.GetVM(ctx, "n1", 4242); return err }, "4242"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newRouteServer(t)
			for p, b := range tc.routes {
				s.on("GET", p, 200, b)
			}
			requireUnverifiable(t, tc.read(s.client()), tc.objName)
		})
	}

	// Controls: a PVE-shaped healthy payload must still be accepted, so the
	// guards cannot pass by refusing everything.
	healthy := []struct {
		name   string
		routes map[string]string
		read   func(c *Client) error
	}{
		{"GetStorage/healthy", map[string]string{"/nodes/n1/storage/nfs-shared/status": `{"data":{"type":"nfs","shared":1,"active":1}}`},
			func(c *Client) error { _, err := c.GetStorage(ctx, "n1", "nfs-shared"); return err }},
		{"GetNetworkInterface/healthy", map[string]string{"/nodes/n1/network/vmbr7": `{"data":{"type":"bridge","active":1}}`},
			func(c *Client) error { _, err := c.GetNetworkInterface(ctx, "n1", "vmbr7"); return err }},
		{"GetVM/healthy", map[string]string{
			"/nodes/n1/qemu/4242/status/current": `{"data":{"vmid":4242,"status":"stopped"}}`,
			"/nodes/n1/qemu/4242/config":         `{"data":{"digest":"d"}}`,
		}, func(c *Client) error { _, err := c.GetVM(ctx, "n1", 4242); return err }},
	}
	for _, tc := range healthy {
		t.Run(tc.name, func(t *testing.T) {
			s := newRouteServer(t)
			for p, b := range tc.routes {
				s.on("GET", p, 200, b)
			}
			if err := tc.read(s.client()); err != nil {
				t.Fatalf("healthy payload refused: %v", err)
			}
		})
	}
}
