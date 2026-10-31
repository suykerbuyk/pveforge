package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// fakeStorageClient satisfies StorageVolumeClient and StorageOrphanScanner,
// recording a call trace so order (DELETE-then-WAIT, per volume) is pinnable.
type fakeStorageClient struct {
	node string

	vols          []*proxmox.StorageContent // GetStorageVolumes before a POST
	volsAfterPost []*proxmox.StorageContent // GetStorageVolumes after a POST
	posted        bool
	postResp      json.RawMessage // alloc POST response body

	deleteResp map[string]json.RawMessage // volid -> DELETE response body (a UPID)
	waitErr    map[string]error           // upid -> WaitForTask error

	scannerOrphans []*proxmox.StorageContent
	scannerErr     error

	clusterOrphans []*proxmox.StorageContent
	clusterErr     error

	storageShared int   // GetStorage's Shared flag (0 = unshared)
	getStorageErr error // when set, GetStorage returns it

	posts   int
	trace   []string // "DELETE <volid>" / "WAIT <upid>" in call order
	deletes []string
	waits   []string
}

func (f *fakeStorageClient) Node() string { return f.node }

func (f *fakeStorageClient) GetStorage(_ context.Context, _, name string) (*proxmox.Storage, error) {
	if f.getStorageErr != nil {
		return nil, f.getStorageErr
	}
	return &proxmox.Storage{Storage: name, Shared: f.storageShared}, nil
}

func (f *fakeStorageClient) GetStorageVolumes(_ context.Context, _, _ string) ([]*proxmox.StorageContent, error) {
	if f.posted {
		return f.volsAfterPost, nil
	}
	return f.vols, nil
}

func (f *fakeStorageClient) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	switch method {
	case http.MethodPost:
		f.posts++
		f.posted = true
		return f.postResp, nil
	case http.MethodDelete:
		seg := path[strings.LastIndex(path, "/content/")+len("/content/"):]
		volid, _ := url.PathUnescape(seg)
		f.trace = append(f.trace, "DELETE "+volid)
		f.deletes = append(f.deletes, volid)
		resp, ok := f.deleteResp[volid]
		if !ok {
			return nil, fmt.Errorf("fake: no DELETE response for %q", volid)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("fake: unexpected %s %s", method, path)
}

func (f *fakeStorageClient) WaitForTask(_ context.Context, _, upid string) error {
	f.trace = append(f.trace, "WAIT "+upid)
	f.waits = append(f.waits, upid)
	return f.waitErr[upid]
}

func (f *fakeStorageClient) OrphanVolumesForVMIDWithVMList(_ context.Context, _, _ string, _ int, _ []int) ([]*proxmox.StorageContent, error) {
	return f.scannerOrphans, f.scannerErr
}

func (f *fakeStorageClient) OrphanVolumesClusterForVMID(_ context.Context, _, _ string, _ int, _ []pve.NodeVMID) ([]*proxmox.StorageContent, error) {
	return f.clusterOrphans, f.clusterErr
}

// --- alloc: the returned-volid second signal (central) -------------------

// The read-back compares the volid the POST RETURNED, which for directory
// storage is "<storage>:<vmid>/<name>" — a mutant that read back a predicted
// "<storage>:<filename>" would not find it here and false-fail.
func TestVolumeAllocEnsure_ReturnedVolidSignal_DirectoryForm(t *testing.T) {
	f := &fakeStorageClient{
		node:          "n1",
		vols:          nil, // Read: absent
		volsAfterPost: []*proxmox.StorageContent{{Volid: "local:105/vm-105-disk-0", VMID: 105}},
		postResp:      json.RawMessage(`"local:105/vm-105-disk-0"`),
	}
	op := &VolumeAllocEnsure{Client: f, Storage: "local", Filename: "vm-105-disk-0", Size: "32G", VMID: 105}
	cur, err := op.Read(context.Background())
	if err != nil || op.Satisfied(cur) {
		t.Fatalf("Read before alloc: cur=%q satisfied=%v err=%v; want absent", cur, op.Satisfied(cur), err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if op.Volid() != "local:105/vm-105-disk-0" {
		t.Fatalf("Volid() = %q, want the directory-form volid the POST returned", op.Volid())
	}
	if len(f.waits) != 0 {
		t.Fatalf("WaitForTask called %d time(s) on a synchronous alloc; want 0", len(f.waits))
	}
}

func TestVolumeAllocEnsure_RejectsBadPostResponse(t *testing.T) {
	for name, resp := range map[string]json.RawMessage{
		"null":       json.RawMessage(`null`),
		"empty":      json.RawMessage(`""`),
		"non-string": json.RawMessage(`123`),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeStorageClient{node: "n1", postResp: resp}
			op := &VolumeAllocEnsure{Client: f, Storage: "local", Filename: "vm-105-disk-0", Size: "32G", VMID: 105}
			if _, err := op.Read(context.Background()); err != nil {
				t.Fatalf("Read: %v", err)
			}
			if err := op.Apply(context.Background()); err == nil {
				t.Fatalf("Apply accepted a %s alloc response; want a refusal", name)
			}
		})
	}
}

func TestVolumeAllocEnsure_ReturnedVolidNotListed(t *testing.T) {
	f := &fakeStorageClient{node: "n1", postResp: json.RawMessage(`"local:105/vm-105-disk-0"`), volsAfterPost: nil}
	op := &VolumeAllocEnsure{Client: f, Storage: "local", Filename: "vm-105-disk-0", Size: "32G", VMID: 105}
	_, _ = op.Read(context.Background())
	if err := op.Apply(context.Background()); err == nil {
		t.Fatalf("Apply returned nil when the read-back did not list the returned volid; want the second signal to fail")
	}
}

// A pre-existing same-name volume (directory form) is recognized by Read via
// basename+VMID, so Satisfied is true and no POST is made — not a false change.
func TestVolumeAllocEnsure_PreExisting_Satisfied(t *testing.T) {
	f := &fakeStorageClient{node: "n1", vols: []*proxmox.StorageContent{{Volid: "local:105/vm-105-disk-0", VMID: 105}}}
	op := &VolumeAllocEnsure{Client: f, Storage: "local", Filename: "vm-105-disk-0", Size: "32G", VMID: 105}
	cur, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !op.Satisfied(cur) {
		t.Fatalf("Satisfied(%q) = false; want true for a pre-existing directory-form volume", cur)
	}
	if f.posts != 0 {
		t.Fatalf("a POST was made for a volume that already exists")
	}
}

// --- free: sorted/sequential, stop-at-first-failure, Applied (central) ----

func freeFake(waitErr map[string]error) (*fakeStorageClient, *VolumeFreeOrphans) {
	f := &fakeStorageClient{
		node: "n1",
		scannerOrphans: []*proxmox.StorageContent{
			{Volid: "local-lvm:vm-690-disk-0"},
			{Volid: "local-lvm:vm-690-disk-1"},
		},
		deleteResp: map[string]json.RawMessage{
			"local-lvm:vm-690-disk-0": json.RawMessage(`"UPID:0"`),
			"local-lvm:vm-690-disk-1": json.RawMessage(`"UPID:1"`),
		},
		waitErr: waitErr,
	}
	return f, &VolumeFreeOrphans{Client: f, Scanner: f, Storage: "local-lvm", VMID: 690, CompleteVMIDs: []int{}}
}

func TestVolumeFreeOrphans_SortedSequentialApplied(t *testing.T) {
	f, op := freeFake(nil)
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantTrace := []string{"DELETE local-lvm:vm-690-disk-0", "WAIT UPID:0", "DELETE local-lvm:vm-690-disk-1", "WAIT UPID:1"}
	if strings.Join(f.trace, "|") != strings.Join(wantTrace, "|") {
		t.Fatalf("trace = %v, want DELETE-then-WAIT per volume, in sorted order: %v", f.trace, wantTrace)
	}
	if strings.Join(op.Applied, ",") != "local-lvm:vm-690-disk-0,local-lvm:vm-690-disk-1" {
		t.Fatalf("Applied = %v, want both in order", op.Applied)
	}
}

func TestVolumeFreeOrphans_StopsAtFirstFailure(t *testing.T) {
	f, op := freeFake(map[string]error{"UPID:0": errors.New("task failed")})
	_, _ = op.Read(context.Background())
	if err := op.Apply(context.Background()); err == nil {
		t.Fatalf("Apply returned nil when the first WaitForTask failed")
	}
	if len(f.deletes) != 1 || f.deletes[0] != "local-lvm:vm-690-disk-0" {
		t.Fatalf("DELETEs = %v; the second volume must NOT be attempted after the first fails", f.deletes)
	}
	if len(op.Applied) != 0 {
		t.Fatalf("Applied = %v, want empty — nothing freed when WaitForTask failed on #0", op.Applied)
	}
}

func TestVolumeFreeOrphans_SecondFailsAppliedHasFirst(t *testing.T) {
	f, op := freeFake(map[string]error{"UPID:1": errors.New("task failed")})
	_, _ = op.Read(context.Background())
	if err := op.Apply(context.Background()); err == nil {
		t.Fatalf("Apply returned nil when the second WaitForTask failed")
	}
	if strings.Join(op.Applied, ",") != "local-lvm:vm-690-disk-0" {
		t.Fatalf("Applied = %v, want exactly [disk-0] after #1 failed", op.Applied)
	}
	_ = f
}

func TestVolumeFreeOrphans_NullDeleteBodyRefused(t *testing.T) {
	f, op := freeFake(nil)
	f.deleteResp["local-lvm:vm-690-disk-0"] = json.RawMessage(`null`)
	_, _ = op.Read(context.Background())
	if err := op.Apply(context.Background()); err == nil {
		t.Fatalf("Apply accepted a null DELETE body; want a refusal (no delay was requested)")
	}
	if len(op.Applied) != 0 {
		t.Fatalf("Applied = %v, want empty", op.Applied)
	}
}

// RULING 4: Read must PROPAGATE a scanner error, never surface the orphan list
// it came with. A mutant that returned the orphans despite the error would free
// a live disk; a mutant that mapped it to "[]" would silently no-op. Both are
// bugs — this pins the dangerous direction (orphans must not leak past an error)
// and that Read reports the error rather than "[]".
func TestVolumeFreeOrphans_ReadPropagatesScannerError(t *testing.T) {
	f := &fakeStorageClient{
		node:           "n1",
		scannerOrphans: []*proxmox.StorageContent{{Volid: "local-lvm:vm-690-disk-0"}}, // a buggy scanner returning BOTH
		scannerErr:     errors.New("the token cannot read VM 690 that root's list includes"),
	}
	op := &VolumeFreeOrphans{Client: f, Scanner: f, Storage: "local-lvm", VMID: 690, CompleteVMIDs: []int{690}}
	cur, err := op.Read(context.Background())
	if err == nil {
		t.Fatalf("Read returned nil error for a scanner failure; it must propagate (never free on an unverified determination)")
	}
	if cur != "" {
		t.Fatalf("Read returned current=%q alongside the error; it must not surface the orphan list (would be freed)", cur)
	}
}
