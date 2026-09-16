package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestStopVM_PostsToStatusStop(t *testing.T) {
	var gotMethod, gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstop:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	upid, err := c.StopVM(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/status/stop" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100/status/stop", gotPath)
	}
	if upid != "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmstop:100:root@pam:" {
		t.Errorf("unexpected upid: %q", upid)
	}
}

func TestStopVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network without a node")
	}))
	if _, err := c.StopVM(context.Background(), "", 100); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

func TestStopVM_PropagatesPVEErrorText(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("VM 100 is locked (backup)"))
	})
	c := testClient(t, srv)

	_, err := c.StopVM(context.Background(), "qa-pve-01", 100)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "VM 100 is locked (backup)") {
		t.Errorf("expected PVE's verbatim error text to survive, got: %v", err)
	}
}

func TestDestroyVM_DeletesWithPurgeParam(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:00001235:0000ABCE:5F000001:qmdestroy:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	upid, err := c.DestroyVM(context.Background(), "qa-pve-01", 100, true)
	if err != nil {
		t.Fatalf("DestroyVM: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100", gotPath)
	}
	if gotQuery != "purge=1" {
		t.Errorf("query = %q, want purge=1", gotQuery)
	}
	if upid != "UPID:qa-pve-01:00001235:0000ABCE:5F000001:qmdestroy:100:root@pam:" {
		t.Errorf("unexpected upid: %q", upid)
	}
}

func TestDestroyVM_NoPurgeParamWhenFalse(t *testing.T) {
	var gotQuery string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmdestroy:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	if _, err := c.DestroyVM(context.Background(), "qa-pve-01", 100, false); err != nil {
		t.Fatalf("DestroyVM: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want empty (no purge param)", gotQuery)
	}
}

func TestDestroyVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network without a node")
	}))
	if _, err := c.DestroyVM(context.Background(), "", 100, true); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

func TestDestroyVM_PropagatesPVEErrorText(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Configuration file '/etc/pve/nodes/qa-pve-01/qemu-server/100.conf' does not exist"))
	})
	c := testClient(t, srv)

	_, err := c.DestroyVM(context.Background(), "qa-pve-01", 100, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected PVE's verbatim error text to survive, got: %v", err)
	}
}

// tagStillClaimedFixture mirrors clusterResourcesFixture (findbytag_test.go)
// but is scoped to this file so TagStillClaimed's tests don't depend on
// FindByTag's own fixture staying byte-for-byte stable.
const tagStillClaimedFixture = `{"data":[
	{"id":"qemu/100","type":"qemu","vmid":100,"node":"qa-pve-01","tags":"qng"},
	{"id":"qemu/101","type":"qemu","vmid":101,"node":"qa-pve-01","tags":"qng-template;other"},
	{"id":"lxc/200","type":"lxc","vmid":200,"node":"qa-pve-01","tags":"qng"}
]}`

// TestTagStillClaimed_ExcludesGivenVMID is the exact stale-cache regression
// the epic calls out: a fixture where the ONLY match is the excluded vmid
// itself must report false, not true.
func TestTagStillClaimed_ExcludesGivenVMID(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"tags":"qng"}]}`))
	})
	c := testClient(t, srv)

	claimed, err := c.TagStillClaimed(context.Background(), "qng", 100)
	if err != nil {
		t.Fatalf("TagStillClaimed: %v", err)
	}
	if claimed {
		t.Error("expected false: the only match is the excluded vmid itself")
	}
}

func TestTagStillClaimed_TrueWhenAnotherVMHasTag(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tagStillClaimedFixture))
	})
	c := testClient(t, srv)

	claimed, err := c.TagStillClaimed(context.Background(), "qng", 999)
	if err != nil {
		t.Fatalf("TagStillClaimed: %v", err)
	}
	if !claimed {
		t.Error("expected true: vmid 100 still carries the tag and wasn't excluded")
	}
}

func TestTagStillClaimed_ExactElementMatch_NotSubstring(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"qemu/101","type":"qemu","vmid":101,"tags":"qng-template;other"}]}`))
	})
	c := testClient(t, srv)

	claimed, err := c.TagStillClaimed(context.Background(), "qng", 999)
	if err != nil {
		t.Fatalf("TagStillClaimed: %v", err)
	}
	if claimed {
		t.Error("expected false: \"qng-template\" must not substring-match \"qng\"")
	}
}

func TestTagStillClaimed_ExcludesLXC(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"lxc/200","type":"lxc","vmid":200,"tags":"qng"}]}`))
	})
	c := testClient(t, srv)

	claimed, err := c.TagStillClaimed(context.Background(), "qng", 999)
	if err != nil {
		t.Fatalf("TagStillClaimed: %v", err)
	}
	if claimed {
		t.Error("expected false: an lxc-type resource must never count toward a match")
	}
}

func TestTagStillClaimed_RequiresTag(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network for an empty tag")
	}))
	if _, err := c.TagStillClaimed(context.Background(), "", 100); err == nil {
		t.Fatal("expected an error for an empty tag")
	}
}

func TestTagStillClaimed_NeverCallsClusterStatus(t *testing.T) {
	var seenPaths []string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.Path)
		if r.URL.Path == "/cluster/status" {
			t.Error("must never call GET /cluster/status")
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(tagStillClaimedFixture))
	})
	c := testClient(t, srv)

	if _, err := c.TagStillClaimed(context.Background(), "qng", 999); err != nil {
		t.Fatalf("TagStillClaimed: %v", err)
	}
	if len(seenPaths) != 1 || seenPaths[0] != "/cluster/resources" {
		t.Fatalf("expected exactly one request to /cluster/resources, got: %v", seenPaths)
	}
}

func TestTagStillClaimed_PropagatesTransportError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := testClient(t, srv)

	_, err := c.TagStillClaimed(context.Background(), "qng", 999)
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got: %v", err)
	}
}
