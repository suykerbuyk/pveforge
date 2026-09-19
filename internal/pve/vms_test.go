package pve

import (
	"context"
	"net/http"
	"testing"
)

func TestGetVM_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/qemu/100/status/current":
			_, _ = w.Write([]byte(`{"data":{"status":"running","vmid":100,"cpus":2,"maxmem":4294967296}}`))
		case "/nodes/qa-pve-01/qemu/100/config":
			_, _ = w.Write([]byte(`{"data":{"name":"web-01","args":"-device foo","cores":2}}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	vm, err := c.GetVM(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.Node != "qa-pve-01" {
		t.Errorf("Node = %q, want qa-pve-01", vm.Node)
	}
	if vm.Status != "running" {
		t.Errorf("Status = %q, want running", vm.Status)
	}
	if vm.CPUs != 2 {
		t.Errorf("CPUs = %d, want 2", vm.CPUs)
	}
	if vm.VirtualMachineConfig == nil {
		t.Fatal("expected VirtualMachineConfig to be populated")
	}
	if vm.VirtualMachineConfig.Name != "web-01" {
		t.Errorf("config Name = %q, want web-01", vm.VirtualMachineConfig.Name)
	}
	if vm.VirtualMachineConfig.Args != "-device foo" {
		t.Errorf("config Args = %q, want '-device foo'", vm.VirtualMachineConfig.Args)
	}
}

// TestGetVM_EscapesNodeInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL, covering both requests GetVM
// makes (status/current and config) — node is roster-config/PVE-listing
// controlled, not external input, but an unescaped value containing '/'
// would otherwise silently corrupt the request path rather than failing
// loudly.
func TestGetVM_EscapesNodeInURL(t *testing.T) {
	var gotPaths []string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"stopped"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetVM(context.Background(), "weird node/name", 100); err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	want := []string{
		"/nodes/weird%20node%2Fname/qemu/100/status/current",
		"/nodes/weird%20node%2Fname/qemu/100/config",
	}
	if len(gotPaths) != len(want) || gotPaths[0] != want[0] || gotPaths[1] != want[1] {
		t.Fatalf("expected the node name to be escaped on the wire for both requests, got %v, want %v", gotPaths, want)
	}
}

func TestGetVM_StatusFetchFailure(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := testClient(t, srv)

	if _, err := c.GetVM(context.Background(), "qa-pve-01", 100); err == nil {
		t.Fatal("expected an error when the status fetch fails")
	}
}

func TestGetVM_ConfigFetchFailure(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/nodes/qa-pve-01/qemu/100/status/current" {
			_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	c := testClient(t, srv)

	if _, err := c.GetVM(context.Background(), "qa-pve-01", 100); err == nil {
		t.Fatal("expected an error when the config fetch fails")
	}
}

func TestGetVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.GetVM(context.Background(), "", 100); err == nil {
		t.Fatal("expected error for empty node")
	}
}

// TestGetVM_ReturnedObjectHasNoLiveClient is the safety-property
// regression guard: GetVM must never populate the returned
// *proxmox.VirtualMachine's client field — its embedded Config/ConfigSync
// methods talk to PVE directly and would bypass RoutedClient's REST/SSH
// root-only-field routing and vmconfig.go's error-surfacing fix entirely.
// A nil client makes any accidental call to them panic instead of
// silently doing the wrong thing.
func TestGetVM_ReturnedObjectHasNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"status":"running"}}`))
	})
	c := testClient(t, srv)

	vm, err := c.GetVM(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling Config on the returned vm to panic (nil client)")
		}
	}()
	_, _ = vm.Config(context.Background())
	t.Fatal("unreachable: Config should have panicked before returning")
}

func TestGetVMs_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/qemu" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"vmid":100,"name":"web-01","status":"running"},{"vmid":101,"name":"web-02","status":"stopped"}]}`))
	})
	c := testClient(t, srv)

	vms, err := c.GetVMs(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetVMs: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("want 2 vms, got %d", len(vms))
	}
	for _, v := range vms {
		if v.Node != "qa-pve-01" {
			t.Errorf("vm %v: Node = %q, want qa-pve-01", v.VMID, v.Node)
		}
	}
	if vms[0].Name != "web-01" || vms[1].Name != "web-02" {
		t.Errorf("unexpected vm names: %+v", vms)
	}
}

// TestGetVMs_EscapesNodeInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL.
func TestGetVMs_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetVMs(context.Background(), "weird node/name"); err != nil {
		t.Fatalf("GetVMs: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/qemu"
	if gotEscapedPath != want {
		t.Fatalf("expected the node name to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

// TestGetVMs_ReturnedObjectsHaveNoLiveClient is the list-getter twin of
// TestGetVM_ReturnedObjectHasNoLiveClient: every *proxmox.VirtualMachine in
// the returned slice carries the identical embedded-write-method hazard as
// the singular getter's result, and nothing else in this suite would catch
// a future regression (e.g. GetVMs "simplified" to call a go-proxmox
// wrapper convenience method instead of c.pc.Get directly, which would set
// the client field on every list element).
func TestGetVMs_ReturnedObjectsHaveNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"vmid":100,"name":"web-01","status":"running"}]}`))
	})
	c := testClient(t, srv)

	vms, err := c.GetVMs(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetVMs: %v", err)
	}
	if len(vms) == 0 {
		t.Fatal("expected at least one vm")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling Config on a returned vm to panic (nil client)")
		}
	}()
	_, _ = vms[0].Config(context.Background())
	t.Fatal("unreachable: Config should have panicked before returning")
}

func TestGetVMs_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.GetVMs(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty node")
	}
}
