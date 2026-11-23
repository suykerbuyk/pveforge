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
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// Contract plan unit U-A, family S1: the two wait sites of internal/idempotent
// that NO CLI verb reaches (`vm create --clone` does not exist; `vm destroy`
// has its own destroy sequence in cmd/pveforge/vm_destroy.go and reaches only
// VMDestroy's stop wait), observed at the library boundary with a REAL
// *pve.Client (so the REAL write gate and the REAL WaitForTask error), over a
// loopback fake. The CLI-visible wait sites have their fixtures in
// cmd/pveforge/ua_s1_test.go.

const uaNode = "qa-pve-01"

// uaServer answers the few paths the two ops touch and counts POST/DELETE
// (the writes) and task polls. pollCode is the status every poll answers.
type uaServer struct {
	srv      *httptest.Server
	writes   atomic.Int32
	polls    atomic.Int32
	pollCode int
	postCode int // when non-zero, every write answers this status instead of a UPID
	vmStatus string
}

func newUAServer(t *testing.T) *uaServer {
	t.Helper()
	s := &uaServer{pollCode: http.StatusServiceUnavailable, vmStatus: "running"} // vmStatus "" = the VM is absent
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case r.Method != http.MethodGet:
			s.writes.Add(1)
			if s.postCode != 0 {
				w.WriteHeader(s.postCode)
				_, _ = w.Write([]byte(`{"data":null}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":%q}`, fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:qmtest:100:root@pam:", uaNode))
		case strings.Contains(p, "/tasks/") && strings.HasSuffix(p, "/status"):
			s.polls.Add(1)
			w.WriteHeader(s.pollCode)
			_, _ = w.Write([]byte(`{"data":null}`))
		case strings.HasSuffix(p, "/status/current"):
			if s.vmStatus == "" { // the VM is absent (a clone's new vmid)
				http.Error(w, "no such vm", http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"status":%q,"vmid":100}}`, s.vmStatus)
		case strings.HasSuffix(p, "/config"):
			_, _ = w.Write([]byte(`{"data":{"name":"x"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *uaServer) client(t *testing.T) *pve.Client {
	t.Helper()
	c, err := pve.NewClient(pve.ClientConfig{BaseURLOverride: s.srv.URL, TokenID: "root@pam!pveforge", TokenSecret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// uaCloneClient is a REAL pve.Client for GetVM and WaitForTask and CloneVM's
// REST call; only the node-scoped signatures and the storage lookup are shaped.
type uaCloneClient struct {
	*pve.Client
	types map[string]string
}

func (c *uaCloneClient) Node() string { return uaNode }
func (c *uaCloneClient) CloneVM(ctx context.Context, src, dst int, p url.Values) (string, error) {
	return c.Client.CloneVM(ctx, uaNode, src, dst, p)
}
func (c *uaCloneClient) StorageType(_ context.Context, _, id string) (string, error) {
	return c.types[id], nil
}
func (c *uaCloneClient) RawRequest(ctx context.Context, method, path string, p url.Values) (json.RawMessage, error) {
	if method == http.MethodGet && strings.HasSuffix(path, "/config") {
		return json.RawMessage(`{"scsi0":"srcstore:vm-100-disk-0,size=1G"}`), nil
	}
	return c.Client.RawRequest(ctx, method, path, p)
}

func uaKey() lock.ObjectKey { return lock.ObjectKey{TargetID: uaNode, Kind: "vm", ID: "101"} }

// vmclone.go:187 — the clone wait. A task whose poll keeps failing: the error
// out of Run is an unobserved dispatch (never a refusal), the clone POST was
// sent exactly once, the poll gave up on its fourth try.
func TestUAS1_VMClone_WaitSiteIsUnobserved(t *testing.T) {
	t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 2*time.Second))
	s := newUAServer(t)
	s.vmStatus = ""
	ctx, _ := dispatch.With(context.Background())
	op := &VMClone{Client: &uaCloneClient{Client: s.client(t), types: map[string]string{"srcstore": "lvmthin"}}, SourceVMID: 100, NewVMID: 101, Params: url.Values{"full": {"1"}}}
	_, err := Run(ctx, testRosterPath(t), uaKey(), op, false)
	if err == nil {
		t.Fatal("Run: nil error from a wait whose polls all fail")
	}
	if !dispatch.IsUnobserved(err) || dispatch.IsRefused(err) {
		t.Fatalf("unobserved=%v refused=%v, want true/false: %v", dispatch.IsUnobserved(err), dispatch.IsRefused(err), err)
	}
	if s.writes.Load() != 1 || s.polls.Load() != 4 || !dispatch.Opened(ctx) {
		t.Fatalf("writes %d polls %d opened %v, want 1, 4, true", s.writes.Load(), s.polls.Load(), dispatch.Opened(ctx))
	}
	if !strings.Contains(err.Error(), "UPID:") {
		t.Errorf("the UPID is not in the error: %v", err)
	}
}

// VMClone's two documented refusals (a duplicated "full", the linked-clone
// storage-type mismatch) are raised from Preflight, before the gate opens and
// before the clone POST: exit 4. The twin: the SAME clone, past the POST, that
// fails is not a refusal.
func TestUAS1_VMClone_RefusalsAreBeforeTheGate_AndTheTwinIsNot(t *testing.T) {
	for _, c := range []struct {
		name   string
		params url.Values
		types  map[string]string
	}{
		{"linked clone across storage types", url.Values{"storage": {"dst"}}, map[string]string{"srcstore": "lvmthin", "dst": "dir"}},
		{"duplicated full", url.Values{"full": {"1", "0"}}, map[string]string{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newUAServer(t)
			s.vmStatus = ""
			ctx, _ := dispatch.With(context.Background())
			op := &VMClone{Client: &uaCloneClient{Client: s.client(t), types: c.types}, SourceVMID: 100, NewVMID: 101, Params: c.params}
			_, err := Run(ctx, testRosterPath(t), uaKey(), op, false)
			if err == nil || !dispatch.IsRefused(err) || dispatch.IsUnobserved(err) {
				t.Fatalf("want a refusal, got %v", err)
			}
			if s.writes.Load() != 0 || dispatch.Opened(ctx) {
				t.Fatalf("a refusal after a write: writes %d opened %v", s.writes.Load(), dispatch.Opened(ctx))
			}
		})
	}
	t.Run("twin: the same clone, past the POST, is rejected -> not a refusal", func(t *testing.T) {
		s := newUAServer(t)
		s.vmStatus = ""
		s.postCode = http.StatusInternalServerError
		ctx, _ := dispatch.With(context.Background())
		op := &VMClone{Client: &uaCloneClient{Client: s.client(t), types: map[string]string{"srcstore": "lvmthin", "dst": "lvmthin"}}, SourceVMID: 100, NewVMID: 101, Params: url.Values{"storage": {"dst"}}}
		_, err := Run(ctx, testRosterPath(t), uaKey(), op, false)
		if err == nil || dispatch.IsRefused(err) || dispatch.IsUnobserved(err) {
			t.Fatalf("want a plain failure, got refused=%v unobserved=%v: %v", dispatch.IsRefused(err), dispatch.IsUnobserved(err), err)
		}
		if s.writes.Load() != 1 || !dispatch.Opened(ctx) {
			t.Fatalf("writes %d opened %v, want 1 and true", s.writes.Load(), dispatch.Opened(ctx))
		}
	})
}

// uaDestroyClient is a real pve.Client with VMDestroyClient's node-less shapes.
type uaDestroyClient struct{ *pve.Client }

func (c *uaDestroyClient) Node() string { return uaNode }
func (c *uaDestroyClient) StopVM(ctx context.Context, vmid int) (string, error) {
	return c.Client.StopVM(ctx, uaNode, vmid)
}
func (c *uaDestroyClient) DestroyVM(ctx context.Context, vmid int, purge bool) (string, error) {
	return c.Client.DestroyVM(ctx, uaNode, vmid, purge)
}

// vmdestroy.go:279 (the stop wait) and :299 (the destroy wait): the library Op
// (which the harness destroy leaf and library callers use; the `vm destroy`
// verb has its own destroy sequence and reaches only the stop wait through
// StatusGatedStop). Each: a sent POST/DELETE, polls that keep failing, an
// unobserved dispatch, the second request never sent when the first wait fails.
func TestUAS1_VMDestroyOp_WaitSitesAreUnobserved(t *testing.T) {
	for _, c := range []struct {
		name       string
		status     string
		wantWrites int32
	}{
		{"stop wait (vmdestroy.go:279): a running VM's stop task cannot be observed", "running", 1}, // the destroy is never sent
		{"destroy wait (vmdestroy.go:299): a stopped VM's destroy task cannot be observed", "stopped", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Cleanup(pve.SetTaskTimingsForTests(5*time.Millisecond, 2*time.Second))
			s := newUAServer(t)
			s.vmStatus = c.status
			ctx, _ := dispatch.With(context.Background())
			op := &VMDestroy{Client: &uaDestroyClient{Client: s.client(t)}, VMID: 100}
			err := op.Apply(ctx)
			if err == nil || !dispatch.IsUnobserved(err) || dispatch.IsRefused(err) {
				t.Fatalf("want an unobserved dispatch, got %v", err)
			}
			if s.writes.Load() != c.wantWrites || s.polls.Load() != 4 || !dispatch.Opened(ctx) {
				t.Fatalf("writes %d polls %d opened %v, want %d, 4, true", s.writes.Load(), s.polls.Load(), dispatch.Opened(ctx), c.wantWrites)
			}
		})
	}
}

// VMCreate's Validate (an orphan ipconfigN) is a Preflight: through Run it is a
// refusal raised before the gate opens, and no create is sent. (The verb also
// validates before Run, so this pins the Op's own contract for library callers.)
// The twin: a well-formed create whose POST is rejected is not a refusal.
func TestUAS1_VMCreate_ValidateIsAPreflight_AndTheTwinIsNot(t *testing.T) {
	s := newUAServer(t)
	s.vmStatus = ""
	ctx, _ := dispatch.With(context.Background())
	op := &VMCreate{Client: &realPVEClientAdapter{Client: s.client(t), node: uaNode}, VMID: 101, Params: url.Values{"ipconfig0": {"ip=dhcp"}}}
	_, err := Run(ctx, testRosterPath(t), uaKey(), op, false)
	if err == nil || !dispatch.IsRefused(err) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if s.writes.Load() != 0 || dispatch.Opened(ctx) {
		t.Fatalf("a refusal after a write: writes %d opened %v", s.writes.Load(), dispatch.Opened(ctx))
	}

	s2 := newUAServer(t)
	s2.vmStatus = ""
	s2.postCode = http.StatusInternalServerError
	ctx2, _ := dispatch.With(context.Background())
	op2 := &VMCreate{Client: &realPVEClientAdapter{Client: s2.client(t), node: uaNode}, VMID: 101, Params: url.Values{"net0": {"virtio"}, "ipconfig0": {"ip=dhcp"}}}
	_, err = Run(ctx2, testRosterPath(t), uaKey(), op2, false)
	if err == nil || dispatch.IsRefused(err) || s2.writes.Load() != 1 || !dispatch.Opened(ctx2) {
		t.Fatalf("twin: err %v writes %d opened %v, want a plain failure after one write", err, s2.writes.Load(), dispatch.Opened(ctx2))
	}
}

// VMFieldsEnsure's Validate is a Preflight too: through Run a malformed batch
// is refused before the gate opens and before any write (the verb also
// validates before Run; this pins the Op's own contract). The twin: a
// well-formed batch whose write fails is a plain error after the gate opened.
func TestUAS1_VMFieldsEnsure_ValidateIsAPreflight_AndTheTwinIsNot(t *testing.T) {
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","cores":2}`)}}
	ctx, _ := dispatch.With(context.Background())
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "cores", "8")}
	_, err := Run(ctx, testRosterPath(t), key, op, false)
	if err == nil || !dispatch.IsRefused(err) {
		t.Fatalf("want a refusal, got %v", err)
	}
	if client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 || dispatch.Opened(ctx) {
		t.Fatalf("a refusal after a write: writes %d/%d opened %v", client.setFieldCalls, client.setFieldPlainCalls, dispatch.Opened(ctx))
	}

	client2 := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","cores":2}`)}, setFieldErrs: []error{errors.New("pve says no")}}
	ctx2, _ := dispatch.With(context.Background())
	op2 := &VMFieldsEnsure{Client: client2, VMID: 100, Pairs: pairs("cores", "4")}
	_, err = Run(ctx2, testRosterPath(t), key, op2, false)
	if err == nil || dispatch.IsRefused(err) || client2.setFieldCalls != 1 || !dispatch.Opened(ctx2) {
		t.Fatalf("twin: err %v writes %d opened %v, want a plain failure after one write attempt", err, client2.setFieldCalls, dispatch.Opened(ctx2))
	}
}
