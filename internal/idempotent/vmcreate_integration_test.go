package idempotent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// realPVEClientAdapter is the smallest possible shim letting a REAL
// *pve.Client — not a fake — satisfy VMCreateClient, so
// TestVMCreate_EndToEnd_AgainstRealPVEClient below crosses the
// pve/idempotent package boundary for real, rather than through an
// in-package fake (internal/idempotent's own unit tests above already
// cover the Op's logic against fakeVMCreateClient; this is a distinct
// requirement — see this task's own scope notes). *pve.Client's GetVM and
// WaitForTask already match VMCreateClient's method signatures exactly
// (both take node explicitly) and are promoted unchanged by embedding;
// the only gap is Node() — pve.Client is node-agnostic by design, unlike
// *pve.RoutedClient, which is scoped to one target — and CreateVM, whose
// pve.Client signature takes node as an explicit parameter that
// VMCreateClient's narrower signature doesn't have room for.
type realPVEClientAdapter struct {
	*pve.Client
	node string
}

func (a *realPVEClientAdapter) Node() string { return a.node }

func (a *realPVEClientAdapter) CreateVM(ctx context.Context, vmid int, params url.Values) (string, error) {
	return a.Client.CreateVM(ctx, a.node, vmid, params)
}

// TestVMCreate_EndToEnd_AgainstRealPVEClient wires a real *pve.Client
// (via realPVEClientAdapter) pointed at a fake PVE HTTP server into a
// VMCreate Op and runs a full Read -> Satisfied -> Apply cycle through
// idempotent.Run — proving internal/pve.CreateVM/WaitForTask and
// internal/idempotent.VMCreate actually work together, not just against
// each other's fakes.
//
// The fake server's task-status handler is the same shape
// internal/pve/task_test.go's own taskStatusHandler already uses
// (echoing "upid"/"node" back — required so go-proxmox's own
// UnmarshalJSON, which copies every response field onto the Task via
// reflection, doesn't zero them and panic inside Ping on a later poll;
// see WaitForTask's own doc comment) — reimplemented here rather than
// imported, since it's an unexported test helper in a different package.
// Answering "stopped"/"OK" on the very first poll (respondRunning: 0)
// means WaitForTask returns without ever needing to sleep between polls,
// so this test needs no access to pve's own unexported poll-interval
// override (defaultTaskPollInterval) to run quickly.
func TestVMCreate_EndToEnd_AgainstRealPVEClient(t *testing.T) {
	const node = "qa-pve-01"
	const vmid = 100
	upid := fmt.Sprintf("UPID:%s:00001234:0000ABCD:5F000000:qmcreate:%d:root@pam:", node, vmid)

	var createCalls int32
	var gotForm url.Values
	var taskStatusCalls int32

	mux := http.NewServeMux()

	// The VM never actually "exists" in this fake — every GetVM call sees a
	// 404 that is not PVE's "no such VM" answer. The initial Read treats it
	// as "doesn't exist yet" per its own documented contract; the re-read
	// after the create is VMCreate.ReRead (P3), which does not, so the
	// result is reported unverified (AfterErr) rather than absent. This
	// keeps the fake server simple while still exercising the real create
	// + wait path end to end.
	mux.HandleFunc(fmt.Sprintf("/nodes/%s/qemu/%d/status/current", node, vmid), func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such vm", http.StatusNotFound)
	})

	mux.HandleFunc(fmt.Sprintf("/nodes/%s/qemu", node), func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&createCalls, 1)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":%q}`, upid)
	})

	mux.HandleFunc(fmt.Sprintf("/nodes/%s/tasks/", node), func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&taskStatusCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"status":"stopped","exitstatus":"OK","upid":%q,"node":%q}}`, upid, node)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	rest, err := pve.NewClient(pve.ClientConfig{
		BaseURLOverride: srv.URL,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("pve.NewClient: %v", err)
	}
	client := &realPVEClientAdapter{Client: rest, node: node}

	op := &VMCreate{Client: client, VMID: vmid, Params: url.Values{"cores": {"4"}, "memory": {"2048"}}}
	key := lock.ObjectKey{TargetID: node, Kind: "vm", ID: fmt.Sprintf("%d", vmid)}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true: the vmid did not exist yet")
	}
	// P3: the post-create 404 is a re-read that failed, not an absence.
	if res.AfterErr == nil || res.PostApplyErr != nil {
		t.Errorf("AfterErr %v, PostApplyErr %v; want the re-read's failure and no created-not-found", res.AfterErr, res.PostApplyErr)
	}
	if got := atomic.LoadInt32(&createCalls); got != 1 {
		t.Fatalf("expected exactly 1 POST to /nodes/%s/qemu, got %d", node, got)
	}
	if gotForm.Get("vmid") != "100" {
		t.Errorf("form vmid = %q, want 100", gotForm.Get("vmid"))
	}
	if gotForm.Get("cores") != "4" || gotForm.Get("memory") != "2048" {
		t.Errorf("form cores/memory = %q/%q, want 4/2048", gotForm.Get("cores"), gotForm.Get("memory"))
	}
	if got := atomic.LoadInt32(&taskStatusCalls); got < 1 {
		t.Fatal("expected WaitForTask to poll the fake task-status endpoint at least once")
	}
}
