package pve

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestCloneVM_PostsSourceInPathAndNewIDInForm is the wire-level assertion
// that matters most for this call: BOTH vmids must land where PVE expects
// them — the SOURCE in the URL path, the TARGET as the "newid" form key —
// and the node must be the one the caller named. A clone that got either
// vmid wrong would happily succeed against the wrong VM entirely.
func TestCloneVM_PostsSourceInPathAndNewIDInForm(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	var gotForm url.Values
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmclone:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	params := url.Values{"full": {"0"}, "storage": {"local-lvm"}, "name": {"clone-of-100"}}
	upid, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, params)
	if err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/clone" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100/clone", gotPath)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if gotForm.Get("newid") != "201" {
		t.Errorf("form newid = %q, want 201", gotForm.Get("newid"))
	}
	if gotForm.Get("full") != "0" || gotForm.Get("storage") != "local-lvm" || gotForm.Get("name") != "clone-of-100" {
		t.Errorf("form full/storage/name = %q/%q/%q, want 0/local-lvm/clone-of-100",
			gotForm.Get("full"), gotForm.Get("storage"), gotForm.Get("name"))
	}
	const wantUPID = "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmclone:100:root@pam:"
	if upid != wantUPID {
		t.Errorf("upid = %q, want %q", upid, wantUPID)
	}
}

// TestCloneVM_NewVMIDOverridesParamsNewID proves the newVMID ARGUMENT is
// authoritative over any "newid" the caller happened to leave in params.
// This is a real safety property, not pedantry: VMClone's Read/Satisfied
// check for an existing VM at its NewVMID, so a params-supplied newid that
// silently won would mean the existence check and the wire were talking
// about two different VMs — the clone would land somewhere the Op never
// looked.
func TestCloneVM_NewVMIDOverridesParamsNewID(t *testing.T) {
	var gotForm url.Values
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	params := url.Values{"newid": {"999"}}
	if _, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, params); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if got := gotForm["newid"]; len(got) != 1 || got[0] != "201" {
		t.Errorf("form newid = %v, want exactly [201] — the argument must win outright, not be appended alongside", got)
	}
}

func TestCloneVM_NilParamsDoesNotPanic(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("newid") != "201" {
			t.Errorf("form newid = %q, want 201", r.PostForm.Get("newid"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	if _, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, nil); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
}

// TestCloneVM_DoesNotMutateCallerParams mirrors CreateVM's own equivalent:
// the caller's map (VMClone.Apply passes op.Params directly) must come
// back with no "newid" key it never put there.
func TestCloneVM_DoesNotMutateCallerParams(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	params := url.Values{"full": {"1"}}
	if _, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, params); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if _, ok := params["newid"]; ok {
		t.Errorf("caller's params was mutated: got newid key %v, want untouched", params["newid"])
	}
	if len(params) != 1 {
		t.Errorf("caller's params gained keys: %v, want only full", params)
	}
}

func TestCloneVM_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotEscapedPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:x:1:2:3:qmclone:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	if _, err := c.CloneVM(context.Background(), "weird node/name", 100, 201, nil); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	want := "/nodes/weird%20node%2Fname/qemu/100/clone"
	if gotEscapedPath != want {
		t.Fatalf("escaped path = %q, want %q", gotEscapedPath, want)
	}
}

func TestCloneVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.CloneVM(context.Background(), "", 100, 201, url.Values{}); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

// TestCloneVM_ServerErrorBodyIsVisible is the regression test for hazard D
// — go-proxmox's handleResponse (proxmox.go:446-449) discards the response
// body entirely on HTTP 500/501, which is the whole reason CloneVM goes
// through RawRequest rather than VirtualMachine.Clone. Checks the BODY
// text reaches the caller, not just the status.
func TestCloneVM_ServerErrorBodyIsVisible(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  can't clone VM 100 to 201: storage 'nfs-a' does not support linked clones  \n"))
	})
	c := testClient(t, srv)

	_, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, url.Values{})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if got := err.Error(); !strings.Contains(got, "storage 'nfs-a' does not support linked clones") {
		t.Errorf("expected PVE's verbatim error body in %q", got)
	}
}

func TestCloneVM_MalformedUPIDResponseErrors(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"upid":"UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:"}}`))
	})
	c := testClient(t, srv)

	if _, err := c.CloneVM(context.Background(), "qa-pve-01", 100, 201, url.Values{}); err == nil {
		t.Fatal("expected an error for a non-string upid response")
	}
}

// TestStorageType_ReadsGetStorageType proves StorageType returns
// GetStorage's .Type field specifically — not its name, not its content
// string, not a hardcoded value. The whole linked-clone pre-check compares
// these two strings, so reading the wrong field would make the guard
// compare something that always matches (or never does).
func TestStorageType_ReadsGetStorageType(t *testing.T) {
	var gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"type":"zfspool","content":"images,rootdir","total":1000000}}`))
	})
	c := testClient(t, srv)

	got, err := c.StorageType(context.Background(), "qa-pve-01", "tank")
	if err != nil {
		t.Fatalf("StorageType: %v", err)
	}
	if got != "zfspool" {
		t.Errorf("StorageType = %q, want zfspool", got)
	}
	if gotPath != "/nodes/qa-pve-01/storage/tank/status" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/storage/tank/status", gotPath)
	}
}

// TestStorageType_DistinguishesTwoStorages guards the specific mutation a
// single-storage test cannot catch: a StorageType that ignored its
// storageID argument entirely (or returned a constant) would still pass
// the test above. Two different storages must resolve to two different
// types, each fetched from its OWN path.
func TestStorageType_DistinguishesTwoStorages(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/qa-pve-01/storage/local-lvm/status":
			_, _ = w.Write([]byte(`{"data":{"type":"lvmthin"}}`))
		case "/nodes/qa-pve-01/storage/tank/status":
			_, _ = w.Write([]byte(`{"data":{"type":"zfspool"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	lvm, err := c.StorageType(context.Background(), "qa-pve-01", "local-lvm")
	if err != nil {
		t.Fatalf("StorageType(local-lvm): %v", err)
	}
	zfs, err := c.StorageType(context.Background(), "qa-pve-01", "tank")
	if err != nil {
		t.Fatalf("StorageType(tank): %v", err)
	}
	if lvm != "lvmthin" {
		t.Errorf("local-lvm type = %q, want lvmthin", lvm)
	}
	if zfs != "zfspool" {
		t.Errorf("tank type = %q, want zfspool", zfs)
	}
}

func TestStorageType_PropagatesGetStorageError(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when storage id validation fails locally")
	}))
	if _, err := c.StorageType(context.Background(), "qa-pve-01", ""); err == nil {
		t.Fatal("expected an error for an empty storage id")
	}
}
