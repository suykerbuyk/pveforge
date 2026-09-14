package pve

import (
	"context"
	"net/http"
	"testing"
)

func TestGetNode_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"uptime":12345,"pveversion":"pve-manager/9.2.11","cpu":0.05}}`))
	})
	c := testClient(t, srv)

	node, err := c.GetNode(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.Name != "qa-pve-01" {
		t.Errorf("Name = %q, want qa-pve-01", node.Name)
	}
	if node.Uptime != 12345 {
		t.Errorf("Uptime = %d, want 12345", node.Uptime)
	}
	if node.PVEVersion != "pve-manager/9.2.11" {
		t.Errorf("PVEVersion = %q", node.PVEVersion)
	}
}

// TestGetNode_EscapesNodeInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL: node is roster-config/PVE-listing
// controlled, not external input, but an unescaped value containing '/'
// would otherwise silently corrupt the request path rather than failing
// loudly.
func TestGetNode_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetNode(context.Background(), "weird node/name"); err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/status"
	if gotEscapedPath != want {
		t.Fatalf("expected the node name to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

func TestGetNode_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.GetNode(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty node")
	}
}

// TestGetNode_ReturnedObjectHasNoLiveClient is the safety-property
// regression guard: GetNode must never populate the returned
// *proxmox.Node's client field, since that's what would let a caller's
// accidental use of one of its embedded write methods (Version, Report,
// NewVirtualMachine, ...) talk to PVE directly — bypassing
// RoutedClient's REST/SSH routing and vmconfig.go's error-surfacing fix
// entirely. A nil client makes that fail loudly (panic) instead of
// silently doing the wrong thing.
func TestGetNode_ReturnedObjectHasNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"uptime":1}}`))
	})
	c := testClient(t, srv)

	node, err := c.GetNode(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling a write-capable method on the returned node to panic (nil client)")
		}
	}()
	_, _ = node.Version(context.Background())
	t.Fatal("unreachable: Version should have panicked before returning")
}

func TestGetNodes_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"node":"qa-pve-01","status":"online"},{"node":"qa-pve-02","status":"online"}]}`))
	})
	c := testClient(t, srv)

	nodes, err := c.GetNodes(context.Background())
	if err != nil {
		t.Fatalf("GetNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Node != "qa-pve-01" || nodes[1].Node != "qa-pve-02" {
		t.Errorf("unexpected node names: %+v", nodes)
	}
}
