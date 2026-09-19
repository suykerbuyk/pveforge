package pve

import (
	"context"
	"net/http"
	"testing"
)

func TestGetNetworkInterface_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/network/vmbr0" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"bridge","cidr":"10.0.0.5/24","gateway":"10.0.0.1","bridge_ports":"eno1"}}`))
	})
	c := testClient(t, srv)

	nw, err := c.GetNetworkInterface(context.Background(), "qa-pve-01", "vmbr0")
	if err != nil {
		t.Fatalf("GetNetworkInterface: %v", err)
	}
	if nw.Node != "qa-pve-01" || nw.Iface != "vmbr0" {
		t.Errorf("unexpected node/iface: %+v", nw)
	}
	if nw.CIDR != "10.0.0.5/24" {
		t.Errorf("CIDR = %q", nw.CIDR)
	}
	if nw.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %q", nw.Gateway)
	}
	if nw.BridgePorts != "eno1" {
		t.Errorf("BridgePorts = %q", nw.BridgePorts)
	}
}

// TestGetNetworkInterface_EscapesNodeAndIfaceInURL mirrors
// vmconfig_test.go's TestSetVMConfigField_EscapesNodeInURL — node and
// iface are roster-config/PVE-listing controlled, not external input, but
// an unescaped value containing '/' would otherwise silently corrupt the
// request path rather than failing loudly.
func TestGetNetworkInterface_EscapesNodeAndIfaceInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"bridge"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetNetworkInterface(context.Background(), "weird node/name", "weird iface/name"); err != nil {
		t.Fatalf("GetNetworkInterface: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/network/weird%20iface%2Fname"
	if gotEscapedPath != want {
		t.Fatalf("expected node and iface to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

func TestGetNetworkInterface_RequiresNodeAndIface(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node/iface validation fails locally")
	}))
	if _, err := c.GetNetworkInterface(context.Background(), "", "vmbr0"); err == nil {
		t.Fatal("expected error for empty node")
	}
	if _, err := c.GetNetworkInterface(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected error for empty iface")
	}
}

// TestGetNetworkInterface_ReturnedObjectHasNoLiveClient is the
// safety-property regression guard: GetNetworkInterface must never
// populate the returned *proxmox.NodeNetwork's client/NodeAPI fields —
// its embedded Update/Delete methods talk to PVE directly and would
// bypass RoutedClient's routing entirely. A nil client makes an
// accidental call to one of them panic instead of silently doing the
// wrong thing.
func TestGetNetworkInterface_ReturnedObjectHasNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"bridge","cidr":"10.0.0.5/24"}}`))
	})
	c := testClient(t, srv)

	nw, err := c.GetNetworkInterface(context.Background(), "qa-pve-01", "vmbr0")
	if err != nil {
		t.Fatalf("GetNetworkInterface: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling Update on the returned interface to panic (nil client)")
		}
	}()
	_ = nw.Update(context.Background())
	t.Fatal("unreachable: Update should have panicked before returning")
}

func TestGetNetworkInterfaces_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/network" {
			http.NotFound(w, r)
			return
		}
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query string when no type filter is given, got: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0","cidr":"10.0.0.5/24"},{"iface":"eno1","cidr":""}]}`))
	})
	c := testClient(t, srv)

	networks, err := c.GetNetworkInterfaces(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetNetworkInterfaces: %v", err)
	}
	if len(networks) != 2 {
		t.Fatalf("want 2 interfaces, got %d", len(networks))
	}
	for _, nw := range networks {
		if nw.Node != "qa-pve-01" {
			t.Errorf("interface %q: Node = %q, want qa-pve-01", nw.Iface, nw.Node)
		}
	}
}

// TestGetNetworkInterfaces_EscapesNodeInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL.
func TestGetNetworkInterfaces_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetNetworkInterfaces(context.Background(), "weird node/name"); err != nil {
		t.Fatalf("GetNetworkInterfaces: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/network"
	if gotEscapedPath != want {
		t.Fatalf("expected the node name to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

// TestGetNetworkInterfaces_ReturnedObjectsHaveNoLiveClient is the
// list-getter twin of
// TestGetNetworkInterface_ReturnedObjectHasNoLiveClient: every
// *proxmox.NodeNetwork in the returned slice carries the identical
// embedded-write-method hazard as the singular getter's result, and
// nothing else in this suite would catch a future regression (e.g.
// GetNetworkInterfaces "simplified" to call a go-proxmox wrapper
// convenience method instead of c.pc.Get directly, which would set the
// client/NodeAPI fields on every list element).
func TestGetNetworkInterfaces_ReturnedObjectsHaveNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Iface must come through in the fixture: NodeNetwork.Update
		// no-ops (returns nil, no panic) when Iface is empty, and the
		// list endpoint's own response is what populates it here (unlike
		// the singular GetNetworkInterface, whose single-object response
		// doesn't include "iface" and needs it set manually).
		_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0","cidr":"10.0.0.5/24"}]}`))
	})
	c := testClient(t, srv)

	networks, err := c.GetNetworkInterfaces(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetNetworkInterfaces: %v", err)
	}
	if len(networks) == 0 {
		t.Fatal("expected at least one network interface")
	}
	if networks[0].Iface == "" {
		t.Fatal("test fixture invalid: Iface must be non-empty for Update to reach the client")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling Update on a returned interface to panic (nil client)")
		}
	}()
	_ = networks[0].Update(context.Background())
	t.Fatal("unreachable: Update should have panicked before returning")
}

func TestGetNetworkInterfaces_TypeFilter(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "bridge" {
			t.Errorf("expected type=bridge in the query string, got: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"iface":"vmbr0"}]}`))
	})
	c := testClient(t, srv)

	networks, err := c.GetNetworkInterfaces(context.Background(), "qa-pve-01", "bridge")
	if err != nil {
		t.Fatalf("GetNetworkInterfaces: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("want 1 interface, got %d", len(networks))
	}
}

func TestGetNetworkInterfaces_RejectsMultipleTypeFilters(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when the multi-filter validation fails locally")
	}))
	if _, err := c.GetNetworkInterfaces(context.Background(), "qa-pve-01", "bridge", "bond"); err == nil {
		t.Fatal("expected error for more than one type filter")
	}
}

func TestGetNetworkInterfaces_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.GetNetworkInterfaces(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty node")
	}
}
