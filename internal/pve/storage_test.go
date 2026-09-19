package pve

import (
	"context"
	"net/http"
	"testing"
)

func TestGetStorage_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/storage/local-lvm/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"lvmthin","content":"images,rootdir","total":1000000,"used":250000,"avail":750000}}`))
	})
	c := testClient(t, srv)

	storage, err := c.GetStorage(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("GetStorage: %v", err)
	}
	if storage.Node != "qa-pve-01" || storage.Name != "local-lvm" {
		t.Errorf("unexpected node/name: %+v", storage)
	}
	if storage.Type != "lvmthin" {
		t.Errorf("Type = %q, want lvmthin", storage.Type)
	}
	if storage.Total != 1000000 || storage.Used != 250000 || storage.Avail != 750000 {
		t.Errorf("unexpected usage fields: %+v", storage)
	}
}

// TestGetStorage_EscapesNodeAndNameInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL — node and name are
// roster-config/PVE-listing controlled, not external input, but an
// unescaped value containing '/' would otherwise silently corrupt the
// request path rather than failing loudly.
func TestGetStorage_EscapesNodeAndNameInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"dir"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetStorage(context.Background(), "weird node/name", "weird storage/name"); err != nil {
		t.Fatalf("GetStorage: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/storage/weird%20storage%2Fname/status"
	if gotEscapedPath != want {
		t.Fatalf("expected node and name to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

func TestGetStorage_RequiresNodeAndName(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node/name validation fails locally")
	}))
	if _, err := c.GetStorage(context.Background(), "", "local-lvm"); err == nil {
		t.Fatal("expected error for empty node")
	}
	if _, err := c.GetStorage(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected error for empty name")
	}
}

// TestGetStorage_ReturnedObjectHasNoLiveClient is the safety-property
// regression guard: GetStorage must never populate the returned
// *proxmox.Storage's client field — its embedded write methods
// (Upload, DeleteContent, ...) talk to PVE directly and would bypass
// RoutedClient's routing entirely. A nil client makes an accidental call
// to one of them panic instead of silently doing the wrong thing.
func TestGetStorage_ReturnedObjectHasNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"dir"}}`))
	})
	c := testClient(t, srv)

	storage, err := c.GetStorage(context.Background(), "qa-pve-01", "local")
	if err != nil {
		t.Fatalf("GetStorage: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling DeleteContent on the returned storage to panic (nil client)")
		}
	}()
	_, _ = storage.DeleteContent(context.Background(), "local:iso/whatever.iso")
	t.Fatal("unreachable: DeleteContent should have panicked before returning")
}

func TestGetStorages_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/storage" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"storage":"local","type":"dir"},{"storage":"local-lvm","type":"lvmthin"}]}`))
	})
	c := testClient(t, srv)

	storages, err := c.GetStorages(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetStorages: %v", err)
	}
	if len(storages) != 2 {
		t.Fatalf("want 2 storages, got %d", len(storages))
	}
	for _, s := range storages {
		if s.Node != "qa-pve-01" {
			t.Errorf("storage %q: Node = %q, want qa-pve-01", s.Name, s.Node)
		}
	}
}

// TestGetStorages_EscapesNodeInURL mirrors vmconfig_test.go's
// TestSetVMConfigField_EscapesNodeInURL.
func TestGetStorages_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetStorages(context.Background(), "weird node/name"); err != nil {
		t.Fatalf("GetStorages: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/storage"
	if gotEscapedPath != want {
		t.Fatalf("expected the node name to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

// TestGetStorages_ReturnedObjectsHaveNoLiveClient is the list-getter twin
// of TestGetStorage_ReturnedObjectHasNoLiveClient: every *proxmox.Storage
// in the returned slice carries the identical embedded-write-method hazard
// as the singular getter's result, and nothing else in this suite would
// catch a future regression (e.g. GetStorages "simplified" to call a
// go-proxmox wrapper convenience method instead of c.pc.Get directly,
// which would set the client field on every list element).
func TestGetStorages_ReturnedObjectsHaveNoLiveClient(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"storage":"local","type":"dir"}]}`))
	})
	c := testClient(t, srv)

	storages, err := c.GetStorages(context.Background(), "qa-pve-01")
	if err != nil {
		t.Fatalf("GetStorages: %v", err)
	}
	if len(storages) == 0 {
		t.Fatal("expected at least one storage")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected calling DeleteContent on a returned storage to panic (nil client)")
		}
	}()
	_, _ = storages[0].DeleteContent(context.Background(), "local:iso/whatever.iso")
	t.Fatal("unreachable: DeleteContent should have panicked before returning")
}

func TestGetStorages_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.GetStorages(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty node")
	}
}

func TestGetStorageConfigPath_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/storage/local" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"storage":"local","type":"dir","path":"/var/lib/vz"}}`))
	})
	c := testClient(t, srv)

	path, err := c.GetStorageConfigPath(context.Background(), "local")
	if err != nil {
		t.Fatalf("GetStorageConfigPath: %v", err)
	}
	if path != "/var/lib/vz" {
		t.Errorf("path = %q, want /var/lib/vz", path)
	}
}

// TestGetStorageConfigPath_NoPath covers a storage type with no
// filesystem-path concept at all (e.g. LVM/ZFS-backed storage, which
// cannot host the "snippets" content type in the first place) — PVE
// returns no "path" field for these, and GetStorageConfigPath must fail
// loudly rather than silently returning an empty path a caller might
// path.Join onto and write into an unintended location.
func TestGetStorageConfigPath_NoPath(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"storage":"local-lvm","type":"lvmthin"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetStorageConfigPath(context.Background(), "local-lvm"); err == nil {
		t.Fatal("expected an error for a storage with no configured path")
	}
}

func TestGetStorageConfigPath_RequiresStorageID(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when storage id validation fails locally")
	}))
	if _, err := c.GetStorageConfigPath(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty storage id")
	}
}

// TestGetStorageConfigPath_EscapesStorageIDInURL mirrors
// vmconfig_test.go's TestSetVMConfigField_EscapesNodeInURL.
func TestGetStorageConfigPath_EscapesStorageIDInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"path":"/var/lib/vz"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetStorageConfigPath(context.Background(), "weird storage/name"); err != nil {
		t.Fatalf("GetStorageConfigPath: %v", err)
	}
	want := "/storage/weird%20storage%2Fname"
	if gotEscapedPath != want {
		t.Fatalf("expected the storage id to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

func TestGetStorageVolumes_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes/qa-pve-01/storage/local-lvm/content" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"volid":"local-lvm:vm-100-disk-0","size":34359738368,"format":"raw","vmid":100}]}`))
	})
	c := testClient(t, srv)

	vols, err := c.GetStorageVolumes(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("GetStorageVolumes: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("want 1 volume, got %d", len(vols))
	}
	if vols[0].Volid != "local-lvm:vm-100-disk-0" {
		t.Errorf("Volid = %q", vols[0].Volid)
	}
	if vols[0].Size != 34359738368 {
		t.Errorf("Size = %d", vols[0].Size)
	}
}

// TestGetStorageVolumes_EscapesNodeAndStorageInURL mirrors
// vmconfig_test.go's TestSetVMConfigField_EscapesNodeInURL.
func TestGetStorageVolumes_EscapesNodeAndStorageInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	if _, err := c.GetStorageVolumes(context.Background(), "weird node/name", "weird storage/name"); err != nil {
		t.Fatalf("GetStorageVolumes: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/storage/weird%20storage%2Fname/content"
	if gotEscapedPath != want {
		t.Fatalf("expected node and storage to be escaped on the wire, got %q, want %q", gotEscapedPath, want)
	}
}

func TestGetStorageVolumes_RequiresNodeAndStorage(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node/storage validation fails locally")
	}))
	if _, err := c.GetStorageVolumes(context.Background(), "", "local-lvm"); err == nil {
		t.Fatal("expected error for empty node")
	}
	if _, err := c.GetStorageVolumes(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected error for empty storage")
	}
}
