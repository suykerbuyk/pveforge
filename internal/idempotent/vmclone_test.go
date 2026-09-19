package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// fakeVMCloneClient is a scriptable VMCloneClient, local to this test file
// — VMClone's interface (RawRequest + StorageType + CloneVM) matches
// neither fakeClient nor fakeVMCreateClient, so it gets its own fake,
// matching this package's existing "one fake per interface shape"
// discipline.
type fakeVMCloneClient struct {
	node string

	getVMResult *proxmox.VirtualMachine
	getVMErr    error
	getVMCalls  int
	lastGetVMID int

	// rawConfig is the source VM's config, returned by RawRequest.
	rawConfig     map[string]any
	rawErr        error
	rawCalls      int
	lastRawPath   string
	lastRawMethod string

	// storageTypes maps a storage id to the type StorageType reports.
	// An id absent from the map is an error, mirroring a storage PVE
	// doesn't know.
	storageTypes     map[string]string
	storageTypeCalls []string
	lastStorageNode  string

	cloneUPID      string
	cloneErr       error
	cloneCalls     int
	lastSourceVMID int
	lastNewVMID    int
	lastParams     url.Values

	waitForTaskErr   error
	waitForTaskCalls int
	lastWaitNode     string
	lastWaitUPID     string
}

func (f *fakeVMCloneClient) Node() string { return f.node }

func (f *fakeVMCloneClient) GetVM(_ context.Context, _ string, vmid int) (*proxmox.VirtualMachine, error) {
	f.getVMCalls++
	f.lastGetVMID = vmid
	if f.getVMErr != nil {
		return nil, f.getVMErr
	}
	return f.getVMResult, nil
}

func (f *fakeVMCloneClient) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	f.rawCalls++
	f.lastRawMethod = method
	f.lastRawPath = path
	if f.rawErr != nil {
		return nil, f.rawErr
	}
	b, err := json.Marshal(f.rawConfig)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (f *fakeVMCloneClient) StorageType(_ context.Context, node, storageID string) (string, error) {
	f.lastStorageNode = node
	f.storageTypeCalls = append(f.storageTypeCalls, storageID)
	t, ok := f.storageTypes[storageID]
	if !ok {
		return "", fmt.Errorf("no such storage %q", storageID)
	}
	return t, nil
}

func (f *fakeVMCloneClient) CloneVM(_ context.Context, sourceVMID, newVMID int, params url.Values) (string, error) {
	f.cloneCalls++
	f.lastSourceVMID = sourceVMID
	f.lastNewVMID = newVMID
	f.lastParams = params
	if f.cloneErr != nil {
		return "", f.cloneErr
	}
	return f.cloneUPID, nil
}

func (f *fakeVMCloneClient) WaitForTask(_ context.Context, node, upid string) error {
	f.waitForTaskCalls++
	f.lastWaitNode = node
	f.lastWaitUPID = upid
	return f.waitForTaskErr
}

// linkedCloneFake builds a fake whose source VM's scsi0 lives on
// sourceStorage, with the two storages typed as given.
func linkedCloneFake(sourceStorage, sourceType, targetStorage, targetType string) *fakeVMCloneClient {
	return &fakeVMCloneClient{
		node:     "qa-pve-01",
		getVMErr: errors.New("not found"),
		rawConfig: map[string]any{
			"scsi0":  sourceStorage + ":vm-100-disk-0,size=32G",
			"digest": "abc123",
			// Decoys, present on purpose: "scsihw" shares the "scsi"
			// prefix but has no numeric suffix, and net0 is an indexed
			// key that is not a disk. A classifier matching on prefix
			// alone, or on "value contains a colon", would read these as
			// disks and refuse ordinary VMs.
			"scsihw": "virtio-scsi-pci",
			"net0":   "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
			"boot":   "order=scsi0",
		},
		storageTypes: map[string]string{
			sourceStorage: sourceType,
			targetStorage: targetType,
		},
		cloneUPID: "UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:",
	}
}

// TestVMClone_LinkedCloneMismatchedStorageTypesRefusedBeforeClone is THE
// test this Op exists for. A linked clone whose source storage
// (lvmthin) and target storage (zfspool) have different Type strings must
// be refused, and — the part that actually matters — refused BEFORE
// CloneVM is ever called. A refusal that arrived after the clone call
// would be worthless: the mismatched clone would already be running on
// PVE's side. Asserts the clone call count is exactly ZERO.
func TestVMClone_LinkedCloneMismatchedStorageTypesRefusedBeforeClone(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"tank"}},
	}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected a refusal for a linked clone across mismatched storage types")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s); the pre-check must refuse BEFORE the clone call", f.cloneCalls)
	}
	if f.waitForTaskCalls != 0 {
		t.Errorf("WaitForTask was called %d time(s), want 0", f.waitForTaskCalls)
	}
	for _, want := range []string{"lvmthin", "zfspool", "local-lvm", "tank"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q — the message must say which types and storages disagreed", err, want)
		}
	}
}

// TestVMClone_LinkedCloneMatchingStorageTypesProceeds is the positive half
// of the guard, and carries this Op's wire assertions: the NODE and BOTH
// vmids must reach CloneVM/WaitForTask exactly as configured. (A sibling
// unit shipped a destroy whose tests never asserted the vmid passed, so
// destroying VMID+1 passed every test — this is that class of hole, closed
// deliberately.)
func TestVMClone_LinkedCloneMatchingStorageTypesProceeds(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "other-lvm", "lvmthin")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"other-lvm"}},
	}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Fatalf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	if f.lastSourceVMID != 100 {
		t.Errorf("CloneVM source vmid = %d, want 100", f.lastSourceVMID)
	}
	if f.lastNewVMID != 201 {
		t.Errorf("CloneVM new vmid = %d, want 201", f.lastNewVMID)
	}
	if f.lastParams.Get("storage") != "other-lvm" {
		t.Errorf("CloneVM params storage = %q, want other-lvm", f.lastParams.Get("storage"))
	}
	if f.waitForTaskCalls != 1 {
		t.Fatalf("WaitForTask calls = %d, want 1", f.waitForTaskCalls)
	}
	if f.lastWaitNode != "qa-pve-01" {
		t.Errorf("WaitForTask node = %q, want qa-pve-01", f.lastWaitNode)
	}
	if f.lastWaitUPID != "UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:" {
		t.Errorf("WaitForTask upid = %q, want the UPID CloneVM returned", f.lastWaitUPID)
	}
	// The source config read must target the SOURCE vmid on this node —
	// reading 201's config (or another node's) would resolve the wrong
	// VM's storage and make the whole comparison meaningless.
	if f.lastRawPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("source config read path = %q, want /nodes/qa-pve-01/qemu/100/config", f.lastRawPath)
	}
	if f.lastStorageNode != "qa-pve-01" {
		t.Errorf("StorageType node = %q, want qa-pve-01", f.lastStorageNode)
	}
	// Both sides of the comparison must actually have been resolved —
	// source storage first, then target.
	if got := strings.Join(f.storageTypeCalls, ","); got != "other-lvm,local-lvm" {
		t.Errorf("StorageType called for %q, want other-lvm,local-lvm (target once, then each disk)", got)
	}
}

// TestVMClone_FullCloneSkipsStorageCheck proves full=1 bypasses the
// pre-check entirely, even with storage types that would refuse a linked
// clone: a full clone copies the disk outright and has no linked-clone
// storage-family constraint. Asserts StorageType was never consulted at
// all, not merely that the clone succeeded.
func TestVMClone_FullCloneSkipsStorageCheck(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"full": {"1"}, "storage": {"tank"}},
	}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Fatalf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	if f.lastSourceVMID != 100 || f.lastNewVMID != 201 {
		t.Errorf("CloneVM vmids = %d -> %d, want 100 -> 201", f.lastSourceVMID, f.lastNewVMID)
	}
	if len(f.storageTypeCalls) != 0 {
		t.Errorf("StorageType was consulted %v on the full-clone path; full=1 must skip the check entirely", f.storageTypeCalls)
	}
	if f.rawCalls != 0 {
		t.Errorf("the source config was read %d time(s) on the full-clone path, want 0", f.rawCalls)
	}
}

// TestVMClone_UnsetFullIsTreatedAsLinked pins the default that makes the
// guard meaningful at all: PVE's own default when "full" is unset is a
// LINKED clone, so an unset "full" must run the pre-check, not skip it. A
// version that only checked on an explicit full=0 would let the most
// common invocation of all straight through unguarded.
func TestVMClone_UnsetFullIsTreatedAsLinked(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"tank"}}, // no "full" key at all
	}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a refusal: an unset full means a LINKED clone on PVE's side")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s) with full unset; the check must run", f.cloneCalls)
	}
}

// TestVMClone_FullZeroIsTreatedAsLinked covers the explicit full=0 form
// alongside the unset one above.
func TestVMClone_FullZeroIsTreatedAsLinked(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"full": {"0"}, "storage": {"tank"}},
	}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a refusal for an explicit full=0 across mismatched storage types")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s), want 0", f.cloneCalls)
	}
}

// TestVMClone_NoTargetStorageSkipsComparison covers the one case where
// the linked-clone path legitimately has nothing to compare: with no
// "storage" key, PVE clones onto the source's own storage, so source and
// target are the same storage by construction. The clone must proceed —
// refusing here would reject the most common linked-clone invocation
// there is.
func TestVMClone_NoTargetStorageSkipsComparison(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"name": {"clone-of-100"}},
	}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Fatalf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	if len(f.storageTypeCalls) != 0 {
		t.Errorf("StorageType was consulted %v with no target storage requested, want none", f.storageTypeCalls)
	}
}

// TestVMClone_ExistingNewVMIDShortCircuits proves the Read/Satisfied pair
// short-circuits an already-populated NewVMID without ever cloning —
// Apply is simply never reached (idempotent.Run's own documented no-op
// path), which this test models by asserting Satisfied on Read's output
// and that no clone call happened.
func TestVMClone_ExistingNewVMIDShortCircuits(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	f.getVMErr = nil
	f.getVMResult = &proxmox.VirtualMachine{VMID: 201, Name: "already-there"}
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"tank"}},
	}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !op.Satisfied(current) {
		t.Fatalf("Satisfied(%q) = false, want true for an already-existing new vmid", current)
	}
	// Read must have looked at the NEW vmid, not the source — checking
	// the source's existence would report satisfied for every clone of a
	// VM that exists, i.e. always.
	if f.lastGetVMID != 201 {
		t.Errorf("Read checked vmid %d, want 201 (the NEW vmid)", f.lastGetVMID)
	}
	if f.cloneCalls != 0 {
		t.Errorf("CloneVM calls = %d, want 0 on the satisfied path", f.cloneCalls)
	}
}

// TestVMClone_ReadTreatsGetVMErrorAsAbsent mirrors VMCreate.Read's
// contract: any GetVM failure reads as "does not exist yet", never an
// error, because Apply's own clone call is the authoritative check.
func TestVMClone_ReadTreatsGetVMErrorAsAbsent(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	f.getVMErr = errors.New("transient network blip")
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read must not propagate a GetVM error, got %v", err)
	}
	if op.Satisfied(current) {
		t.Fatal("Satisfied = true after a failed GetVM, want false")
	}
}

// TestVMClone_UnparseableDiskRefuses is the load-bearing rule of the
// all-disks design: any disk-shaped entry the check cannot parse must
// REFUSE, never be skipped. Skipping the unintelligible would reintroduce
// exactly the false negative that widening the check to every disk exists
// to close, while making the guard look more thorough than before — weaker
// in fact, stronger in appearance.
//
// The third row is the one that matters most: a first disk that parses
// cleanly must not let a later unparseable one through on its coat-tails.
func TestVMClone_UnparseableDiskRefuses(t *testing.T) {
	cases := []struct {
		name   string
		config map[string]any
	}{
		{"value has no storage prefix at all", map[string]any{"scsi0": "garbage-with-no-colon"}},
		{"value is not a string", map[string]any{"scsi0": 42}},
		{"a LATER disk is unparseable while the first is fine", map[string]any{
			"scsi0": "local-lvm:vm-100-disk-0,size=32G",
			"scsi1": "no-colon-here,size=8G",
		}},
		{"bare 'none' without media=cdrom is not self-evidently a drive", map[string]any{"ide2": "none"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := linkedCloneFake("local-lvm", "lvmthin", "tank", "lvmthin")
			f.rawConfig = c.config
			op := &VMClone{
				Client:     f,
				SourceVMID: 100,
				NewVMID:    201,
				Params:     url.Values{"storage": {"tank"}},
			}
			err := op.Apply(context.Background())
			if err == nil {
				t.Fatal("expected a refusal: an unparseable disk must never be skipped")
			}
			if f.cloneCalls != 0 {
				t.Fatalf("CloneVM was called %d time(s) despite an unparseable disk", f.cloneCalls)
			}
		})
	}
}

// TestVMClone_SourceConfigReadFailureRefuses proves a failed source-config
// read refuses rather than falling through to an unchecked clone.
func TestVMClone_SourceConfigReadFailureRefuses(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "lvmthin")
	f.rawErr = errors.New("pve said no")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"tank"}},
	}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a refusal when the source config cannot be read")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s) after a failed source config read", f.cloneCalls)
	}
	if f.lastRawMethod != "GET" {
		t.Errorf("source config read method = %q, want GET", f.lastRawMethod)
	}
}

// TestVMClone_StorageTypeFailureRefuses proves an unresolvable storage
// (either side) refuses rather than proceeding.
func TestVMClone_StorageTypeFailureRefuses(t *testing.T) {
	for _, unknown := range []string{"local-lvm", "tank"} {
		t.Run("unknown "+unknown, func(t *testing.T) {
			f := linkedCloneFake("local-lvm", "lvmthin", "tank", "lvmthin")
			delete(f.storageTypes, unknown)
			op := &VMClone{
				Client:     f,
				SourceVMID: 100,
				NewVMID:    201,
				Params:     url.Values{"storage": {"tank"}},
			}
			if err := op.Apply(context.Background()); err == nil {
				t.Fatalf("expected a refusal when storage %q cannot be resolved", unknown)
			}
			if f.cloneCalls != 0 {
				t.Fatalf("CloneVM was called %d time(s), want 0", f.cloneCalls)
			}
		})
	}
}

// TestVMClone_CloneFailureSkipsWait proves a failed CloneVM is not
// followed by a WaitForTask on a UPID that was never issued.
func TestVMClone_CloneFailureSkipsWait(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "other-lvm", "lvmthin")
	f.cloneErr = errors.New("vmid 201 already exists")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"other-lvm"}},
	}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected CloneVM's error to propagate")
	}
	if !strings.Contains(err.Error(), "vmid 201 already exists") {
		t.Errorf("error %q does not carry PVE's own text", err)
	}
	if f.waitForTaskCalls != 0 {
		t.Errorf("WaitForTask calls = %d, want 0 after a failed clone", f.waitForTaskCalls)
	}
}

// TestVMClone_WaitForTaskFailurePropagates proves a clone task that fails
// server-side surfaces as an Apply error rather than a silent success.
func TestVMClone_WaitForTaskFailurePropagates(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "other-lvm", "lvmthin")
	f.waitForTaskErr = errors.New("clone task failed: out of space")
	op := &VMClone{
		Client:     f,
		SourceVMID: 100,
		NewVMID:    201,
		Params:     url.Values{"storage": {"other-lvm"}},
	}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected WaitForTask's error to propagate")
	}
	if !strings.Contains(err.Error(), "out of space") {
		t.Errorf("error %q does not carry the task failure text", err)
	}
}

// multiDiskFake builds a source VM whose disks are given as key -> volid,
// with each named storage typed via types.
func multiDiskFake(disks map[string]string, types map[string]string) *fakeVMCloneClient {
	cfg := map[string]any{"digest": "abc123", "scsihw": "virtio-scsi-pci"}
	for k, v := range disks {
		cfg[k] = v
	}
	return &fakeVMCloneClient{
		node:         "qa-pve-01",
		getVMErr:     errors.New("not found"),
		rawConfig:    cfg,
		storageTypes: types,
		cloneUPID:    "UPID:qa-pve-01:1:2:3:qmclone:100:root@pam:",
	}
}

// TestVMClone_SecondDiskMismatchRefuses is the case that motivated widening
// this check to every disk, and it is the regression test for the gap an
// independent review executed against the single-disk revision: scsi0 on
// lvmthin passed the check while scsi1 on nfs was never consulted at all,
// and PVE — which clones ALL of a VM's disks — silently full-cloned the nfs
// disk. The guard looked one disk away from the hazard it exists to catch.
//
// Asserts zero CloneVM calls: the refusal must come before the clone, not
// after, exactly as for the first disk.
func TestVMClone_SecondDiskMismatchRefuses(t *testing.T) {
	f := multiDiskFake(
		map[string]string{
			"scsi0": "local-lvm:vm-100-disk-0,size=32G",
			"scsi1": "nfs-a:100/vm-100-disk-1.qcow2,size=500G",
		},
		map[string]string{"local-lvm": "lvmthin", "nfs-a": "nfs", "tank": "lvmthin"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected a refusal: scsi1 is on an nfs storage, the target is lvmthin")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s); the refusal must precede the clone", f.cloneCalls)
	}
	// The message must identify WHICH disk. With one disk that was
	// self-evident; with several it is the difference between an
	// actionable refusal and a puzzle.
	for _, want := range []string{"scsi1", "nfs", "nfs-a", "lvmthin", "tank"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "scsi0") {
		t.Errorf("error %q names scsi0, which matched fine — it should name the offending disk", err)
	}
}

// TestVMClone_AllDiskShapedPrefixesAreChecked walks every prefix the
// classifier recognises and proves each one, alone, is enough to refuse a
// mismatch. A prefix silently missing from the list would let every VM
// whose only disk sits on that controller through unchecked.
func TestVMClone_AllDiskShapedPrefixesAreChecked(t *testing.T) {
	for _, key := range []string{"scsi0", "scsi30", "virtio0", "virtio15", "sata0", "ide0", "efidisk0", "tpmstate0", "unused0", "unused7"} {
		t.Run(key, func(t *testing.T) {
			f := multiDiskFake(
				map[string]string{key: "nfs-a:100/vm-100-disk-0.qcow2,size=8G"},
				map[string]string{"nfs-a": "nfs", "tank": "lvmthin"},
			)
			op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

			err := op.Apply(context.Background())
			if err == nil {
				t.Fatalf("expected a refusal: %s is on nfs, the target is lvmthin", key)
			}
			if f.cloneCalls != 0 {
				t.Fatalf("CloneVM was called %d time(s) for a mismatched %s", f.cloneCalls, key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name the offending disk %s", err, key)
			}
		})
	}
}

// TestVMClone_UnusedDisksAreChecked pins the deliberate inclusion of
// unusedN — a disk detached from the VM but still in its config.
//
// Whether PVE copies such a disk on a clone is NOT verified against a live
// host, and this is not a guess about it: including them is safe under
// either answer. If PVE does copy them, checking is necessary; if it does
// not, checking can only produce the false-positive refusal this Op
// explicitly prefers — and only when the detached disk's storage family
// actually mismatches, never merely because one exists, which the second
// half of this test pins. Ignoring them would be the one unsafe option.
func TestVMClone_UnusedDisksAreChecked(t *testing.T) {
	// A mismatched unused disk refuses...
	f := multiDiskFake(
		map[string]string{
			"scsi0":   "local-lvm:vm-100-disk-0,size=32G",
			"unused0": "nfs-a:100/vm-100-disk-9.qcow2",
		},
		map[string]string{"local-lvm": "lvmthin", "nfs-a": "nfs", "tank": "lvmthin"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}
	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a refusal for a detached disk on a mismatched storage family")
	} else if !strings.Contains(err.Error(), "unused0") {
		t.Errorf("error %q does not name unused0", err)
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s), want 0", f.cloneCalls)
	}

	// ...but merely HAVING one, on a matching family, must not.
	f2 := multiDiskFake(
		map[string]string{
			"scsi0":   "local-lvm:vm-100-disk-0,size=32G",
			"unused0": "other-lvm:vm-100-disk-9",
		},
		map[string]string{"local-lvm": "lvmthin", "other-lvm": "lvmthin", "tank": "lvmthin"},
	)
	op2 := &VMClone{Client: f2, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}
	if err := op2.Apply(context.Background()); err != nil {
		t.Fatalf("a detached disk on a MATCHING family must not refuse: %v", err)
	}
	if f2.cloneCalls != 1 {
		t.Errorf("CloneVM calls = %d, want 1", f2.cloneCalls)
	}
}

// TestVMClone_CDROMsAreSkipped proves a media=cdrom entry never triggers a
// refusal even when its ISO sits on a storage family that would refuse a
// real disk. An ISO in a drive is not a disk being copied, and PVE
// regenerates a cloud-init drive on the target rather than cloning it.
// Refusing on these would reject perfectly ordinary VMs — and a guard that
// cries wolf is a guard people switch off, which is strictly worse than no
// guard at all.
func TestVMClone_CDROMsAreSkipped(t *testing.T) {
	f := multiDiskFake(
		map[string]string{
			"scsi0": "local-lvm:vm-100-disk-0,size=32G",
			"ide2":  "isos:iso/debian-12.iso,media=cdrom,size=600M",
			"ide0":  "local-lvm:vm-100-cloudinit,media=cdrom",
			"ide3":  "none,media=cdrom",
		},
		map[string]string{"local-lvm": "lvmthin", "isos": "nfs", "tank": "lvmthin"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("a CD-ROM on an incompatible storage must not refuse: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Fatalf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	// "isos" is nfs and would refuse if it were read as a disk; it must
	// never even be resolved.
	for _, s := range f.storageTypeCalls {
		if s == "isos" {
			t.Errorf("StorageType resolved %q — a CD-ROM's storage must never be consulted", s)
		}
	}
}

// TestVMClone_CDROMMatchIsExactNotSubstring pins isCDROM's PRECISION, which
// matters more than it looks: isCDROM gates the only `continue` in the whole
// disk walk — the single place this design permits skipping an entry at all.
//
// A real disk whose option list merely CONTAINS the text "media=cdrom" inside
// another option's value is a genuine disk and must be checked. Loosening the
// comparison from `strings.TrimSpace(opt) == "media=cdrom"` to
// `strings.Contains(opt, "media=cdrom")` is a natural-looking simplification
// for a future contributor, it survived the full suite when an independent
// review mutated it, and it silently reopens the skip path this design
// forbids. Asserts the disk's storage IS resolved — not merely that Apply
// returned an error, which it would for several unrelated reasons.
func TestVMClone_CDROMMatchIsExactNotSubstring(t *testing.T) {
	cases := []struct{ name, value string }{
		{"media=cdrom inside another option's value", "nfs-a:vm-100-disk-0,size=32G,serial=media=cdrom"},
		{"an option merely prefixed with it", "nfs-a:vm-100-disk-0,size=32G,media=cdromx"},
		{"an option merely suffixed with it", "nfs-a:vm-100-disk-0,size=32G,xmedia=cdrom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := multiDiskFake(
				map[string]string{"scsi0": c.value},
				map[string]string{"nfs-a": "nfs", "tank": "lvmthin"},
			)
			op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

			err := op.Apply(context.Background())
			if len(f.storageTypeCalls) == 0 {
				t.Fatalf("scsi0 was SKIPPED as a cd-rom: %q is a real disk — only an option exactly equal to media=cdrom marks a drive", c.value)
			}
			if err == nil {
				t.Errorf("expected a refusal: scsi0 is on nfs, the target is lvmthin")
			}
			if f.cloneCalls != 0 {
				t.Errorf("CloneVM calls = %d, want 0", f.cloneCalls)
			}
		})
	}
}

// TestVMClone_NonDiskKeysAreNotTreatedAsDisks guards the classifier from
// the other direction. Every key here would refuse if misread as a disk:
// net0 carries colons, scsihw shares the "scsi" prefix, ide (bare, no
// index) shares "ide". None is a disk.
func TestVMClone_NonDiskKeysAreNotTreatedAsDisks(t *testing.T) {
	f := multiDiskFake(
		map[string]string{"scsi0": "local-lvm:vm-100-disk-0,size=32G"},
		map[string]string{"local-lvm": "lvmthin", "tank": "lvmthin"},
	)
	f.rawConfig["net0"] = "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"
	f.rawConfig["scsihw"] = "virtio-scsi-pci"
	f.rawConfig["ide"] = "nfs-a:whatever"
	f.rawConfig["ipconfig0"] = "ip=10.0.0.5/24,gw=10.0.0.1"
	f.rawConfig["serial0"] = "socket"
	f.rawConfig["hostpci0"] = "0000:01:00,pcie=1"
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("non-disk keys must not be read as disks: %v", err)
	}
	if got := strings.Join(f.storageTypeCalls, ","); got != "tank,local-lvm" {
		t.Errorf("StorageType called for %q, want tank,local-lvm only", got)
	}
}

// TestVMClone_MultipleDisksOnOneStorageResolveItOnce pins the memoisation:
// several disks sharing a storage must not each trigger a REST call.
func TestVMClone_MultipleDisksOnOneStorageResolveItOnce(t *testing.T) {
	f := multiDiskFake(
		map[string]string{
			"scsi0":   "local-lvm:vm-100-disk-0,size=32G",
			"scsi1":   "local-lvm:vm-100-disk-1,size=64G",
			"virtio0": "local-lvm:vm-100-disk-2,size=8G",
		},
		map[string]string{"local-lvm": "lvmthin", "tank": "lvmthin"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := strings.Join(f.storageTypeCalls, ","); got != "tank,local-lvm" {
		t.Errorf("StorageType called for %q, want tank,local-lvm — one call per distinct storage", got)
	}
}

// TestVMClone_FullCloneSkipsCheckWithMultipleMismatchedDisks re-pins the
// full=1 bypass against the widened check: with several disks on several
// incompatible families, full=1 must still consult nothing at all.
func TestVMClone_FullCloneSkipsCheckWithMultipleMismatchedDisks(t *testing.T) {
	f := multiDiskFake(
		map[string]string{
			"scsi0": "local-lvm:vm-100-disk-0,size=32G",
			"scsi1": "nfs-a:100/vm-100-disk-1.qcow2,size=500G",
			"sata0": "cephpool:vm-100-disk-2",
		},
		map[string]string{"local-lvm": "lvmthin", "nfs-a": "nfs", "cephpool": "rbd", "tank": "lvmthin"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201,
		Params: url.Values{"full": {"1"}, "storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("full=1 must skip the check entirely: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Fatalf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	if len(f.storageTypeCalls) != 0 || f.rawCalls != 0 {
		t.Errorf("full=1 consulted storages %v and read config %d time(s); it must skip the check entirely",
			f.storageTypeCalls, f.rawCalls)
	}
}

// TestVMClone_DisklessSourceProceeds covers a source with no disk-shaped
// keys at all. Returning nil here is not a skipped verdict: an unparseable
// disk refuses rather than being dropped, so an empty disk set genuinely
// means there are no disks, and a diskless clone has no storage-family
// constraint to enforce.
func TestVMClone_DisklessSourceProceeds(t *testing.T) {
	f := multiDiskFake(map[string]string{}, map[string]string{"tank": "lvmthin"})
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("a diskless source must clone: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Errorf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
	if len(f.storageTypeCalls) != 0 {
		t.Errorf("StorageType consulted %v for a diskless source, want none", f.storageTypeCalls)
	}
}

// TestVMClone_EmptyStoragePrefixRefusesLocally covers the ":vm-100-disk-0"
// shape — a value where strings.Cut DOES find a colon but the storage id
// before it is empty — separately from the unparseable table, and asserts
// the refusal is LOCAL.
//
// The separation is the point. As a plain table row asserting only that an
// error came back, this case could not distinguish the guard's
// `storage == ""` half from its absence: with that half removed, the empty
// storage id simply flows on to StorageType, which fails, and the Op still
// refuses. Independent review confirmed by mutation that deleting that half
// left the whole package passing. Pinning zero StorageType calls is what
// makes the guard observable — the second instance of a masked-guard shape
// this Op has now had to fix twice.
func TestVMClone_EmptyStoragePrefixRefusesLocally(t *testing.T) {
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "lvmthin")
	f.rawConfig = map[string]any{"scsi0": ":vm-100-disk-0,size=32G"}
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected a refusal for a disk value whose storage prefix is empty")
	}
	if len(f.storageTypeCalls) != 0 {
		t.Errorf("StorageType was consulted %v for an empty storage id; the refusal must be local", f.storageTypeCalls)
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM was called %d time(s), want 0", f.cloneCalls)
	}
}

// TestVMClone_DuplicateFullKeyRefused covers the multi-valued-Params
// bypass: url.Values is a map to a SLICE, and Params.Get returns only the
// first value, so Add("full","1") then Add("full","0") read as a full clone
// and skipped the storage pre-check entirely while the wire carried
// "full=1&full=0". Independent review executed this: the clone reached
// CloneVM with mismatched storage and StorageType was never consulted.
//
// Which duplicate PVE's own parser honours is not verified against a live
// host, so the input is treated as unverifiable and refused — the same
// conservative bias the storage-family check itself rests on. Asserts the
// refusal is LOCAL (no config read, no StorageType, no clone), since an
// error alone could also have come from some later step.
func TestVMClone_DuplicateFullKeyRefused(t *testing.T) {
	for _, vals := range [][]string{{"1", "0"}, {"0", "1"}, {"1", "1"}} {
		t.Run(strings.Join(vals, "+"), func(t *testing.T) {
			f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
			params := url.Values{"storage": {"tank"}}
			for _, v := range vals {
				params.Add("full", v)
			}
			op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: params}

			err := op.Apply(context.Background())
			if err == nil {
				t.Fatal(`expected a refusal for a duplicated "full" key`)
			}
			if !strings.Contains(err.Error(), "full") {
				t.Errorf("error %q should name the duplicated key", err)
			}
			if f.cloneCalls != 0 {
				t.Fatalf("CloneVM was called %d time(s) with a duplicated full key, want 0", f.cloneCalls)
			}
			if len(f.storageTypeCalls) != 0 {
				t.Errorf("StorageType was consulted %v; the refusal must be local", f.storageTypeCalls)
			}
			if f.rawCalls != 0 {
				t.Errorf("the source config was read %d time(s); the refusal must be local", f.rawCalls)
			}
		})
	}
}

// TestVMClone_SingleFullKeyStillWorks is the negative case for the refusal
// above: exactly one "full" value must still take both paths normally, so
// the duplicate guard cannot be satisfied by simply refusing everything.
func TestVMClone_SingleFullKeyStillWorks(t *testing.T) {
	// full=1 once: skips the check, clones.
	f := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201,
		Params: url.Values{"full": {"1"}, "storage": {"tank"}}}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("single full=1 must still clone: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Errorf("CloneVM calls = %d, want 1", f.cloneCalls)
	}

	// full=0 once: runs the check, refuses on the mismatch (not on duplication).
	f2 := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
	op2 := &VMClone{Client: f2, SourceVMID: 100, NewVMID: 201,
		Params: url.Values{"full": {"0"}, "storage": {"tank"}}}
	err := op2.Apply(context.Background())
	if err == nil {
		t.Fatal("single full=0 across mismatched storage must still refuse")
	}
	if !strings.Contains(err.Error(), "matching storage types") {
		t.Errorf("error %q should be the storage-type refusal, not the duplicate-key one", err)
	}
	if len(f2.storageTypeCalls) != 2 {
		t.Errorf("StorageType calls = %v, want both target and disk resolved", f2.storageTypeCalls)
	}
}

// rawBodyCloneClient returns a caller-chosen raw config body verbatim, so a
// test can drive the exact bytes RawRequest would hand back — which is the
// only way to reach the shapes that unmarshal into an EMPTY map with no
// error at all.
type rawBodyCloneClient struct {
	*fakeVMCloneClient
	body string
}

func (c *rawBodyCloneClient) RawRequest(_ context.Context, _, _ string, _ url.Values) (json.RawMessage, error) {
	c.rawCalls++
	return json.RawMessage(c.body), nil
}

// TestVMClone_UnusableConfigBodyRefuses is the regression test for a defect
// this Op INTRODUCED when the storage check was widened from one named disk
// field to every disk, found by independent review.
//
// The old code looked up a single field and refused when the lookup missed,
// which a nil map does. The widened code iterates instead — and iterating
// nothing is indistinguishable from iterating a VM that genuinely has no
// disks, so an unusable config body read as "diskless, nothing to enforce"
// and the ENTIRE check was skipped: a linked clone across incompatible
// storage families proceeded, which is the precise hazard the expansion was
// commissioned to close.
//
// Both bodies below unmarshal into an empty map with NO error:
//
//   - "null" is what pve.RawRequest's unwrapDataEnvelope returns for an
//     ENTIRELY EMPTY HTTP body (and for {"data":null}), so this is reachable
//     from a plain PVE 200 with nothing in it — a proxy hiccup, a truncated
//     response — not only from a malformed payload.
//   - "{}" is a truncated or partial config object.
//
// Asserts zero CloneVM calls, since "it returned an error" is not the
// property at risk — proceeding is.
func TestVMClone_UnusableConfigBodyRefuses(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"json null (what RawRequest returns for an empty http body)", `null`},
		{"empty object (a truncated or partial config)", `{}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := linkedCloneFake("local-lvm", "lvmthin", "tank", "zfspool")
			op := &VMClone{
				Client:     &rawBodyCloneClient{fakeVMCloneClient: base, body: c.body},
				SourceVMID: 100,
				NewVMID:    201,
				Params:     url.Values{"storage": {"tank"}},
			}

			err := op.Apply(context.Background())
			if base.cloneCalls != 0 {
				t.Fatalf("CloneVM was called %d time(s): an unusable config body must never read as a disk-free vm", base.cloneCalls)
			}
			if err == nil {
				t.Fatal("expected a refusal for an unusable source config body")
			}
			if len(base.storageTypeCalls) != 0 {
				t.Errorf("StorageType was consulted %v; the refusal must come before any storage resolution", base.storageTypeCalls)
			}
		})
	}
}

// TestVMClone_PopulatedConfigWithNoDisksStillProceeds is the other half of
// the fix above, and the reason it is scoped to the config map rather than
// the disk set: a config that was genuinely READ and POPULATED but names no
// disk-shaped key must still clone. That covers a diskless VM and a VM whose
// only drive is a CD-ROM. Refusing on an empty DISK set instead would break
// both.
func TestVMClone_PopulatedConfigWithNoDisksStillProceeds(t *testing.T) {
	f := multiDiskFake(map[string]string{}, map[string]string{"tank": "lvmthin"})
	f.rawConfig = map[string]any{
		"digest":  "abc123",
		"boot":    "order=net0",
		"smbios1": "uuid=5b6c...",
		"ide2":    "isos:iso/debian-12.iso,media=cdrom",
	}
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("a populated config naming no disks must still clone: %v", err)
	}
	if f.cloneCalls != 1 {
		t.Errorf("CloneVM calls = %d, want 1", f.cloneCalls)
	}
}

// TestVMClone_DetachedDiskRefusalIsActionable pins the wording of the one
// refusal most likely to baffle. A VM whose LIVE disks all match the clone
// target can still be refused over a leftover unusedN, and that is expected
// to happen on ordinary VMs: PVE's "Move disk" creates the unusedN entry and
// leaves it on the OLD storage family whenever "Delete source" is unchecked
// (the GUI default), so the leftover and the mismatch are correlated by
// construction rather than independent.
//
// The message must therefore say the offending entry is DETACHED, not a disk
// in use, and name the remedy that actually applies. It must NOT offer only
// "pass full=1", which is a different operation — copying every disk outright
// — and points the wrong way for someone who just wants a leftover ignored.
func TestVMClone_DetachedDiskRefusalIsActionable(t *testing.T) {
	f := multiDiskFake(
		map[string]string{
			"scsi0":   "tank:vm-100-disk-0,size=32G", // live disk, MATCHES the target family
			"unused0": "local-lvm:vm-100-disk-0",     // leftover from an earlier Move disk
		},
		map[string]string{"tank": "zfspool", "local-lvm": "lvmthin", "tank2": "zfspool"},
	)
	op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank2"}}}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected a refusal over the detached disk's storage family")
	}
	if f.cloneCalls != 0 {
		t.Fatalf("CloneVM calls = %d, want 0", f.cloneCalls)
	}
	msg := err.Error()
	for _, want := range []string{"unused0", "DETACHED", "not a disk in use", "Remove"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not contain %q — it must be actionable, not baffling", msg, want)
		}
	}
	// A LIVE disk's refusal must keep the generic wording, so the detached
	// phrasing cannot be satisfied by applying it to everything.
	f2 := multiDiskFake(
		map[string]string{"scsi0": "local-lvm:vm-100-disk-0,size=32G"},
		map[string]string{"local-lvm": "lvmthin", "tank": "zfspool"},
	)
	op2 := &VMClone{Client: f2, SourceVMID: 100, NewVMID: 201, Params: url.Values{"storage": {"tank"}}}
	err2 := op2.Apply(context.Background())
	if err2 == nil {
		t.Fatal("expected a refusal for the live disk")
	}
	if strings.Contains(err2.Error(), "DETACHED") {
		t.Errorf("a LIVE disk's refusal %q uses the detached-disk wording", err2)
	}
}

// TestVMClone_RefusalNamesTheLowestSortedMismatchingDiskDeterministically
// pins the determinism sourceDisks promises in its own doc comment —
// "ordered by key so a refusal names the same disk run after run" — which
// nothing else holds it to.
//
// The promise matters because Go randomises map iteration order
// deliberately, and sourceDisks builds its key list by ranging over the raw
// config map. Drop the sort and a multi-disk VM with more than one
// mismatching disk gets an error naming a DIFFERENT disk on each run: the
// operator sees a different culprit every time they retry, and the message
// stops being evidence about their VM. No behaviour changes, so nothing
// else in this suite would notice.
//
// Asserting "the message names ide0" ONCE would be a coin flip: with six
// mismatching disks an unsorted implementation still names the right one
// about one run in six, so such a test would pass by luck often enough to
// be worthless. This runs the refusal many times in one process — each
// Apply re-ranges the map and gets a fresh random order — and requires
// EVERY run to agree. An unsorted implementation would have to win the same
// coin flip `runs` times consecutively.
//
// The expected disk is the lowest-sorted MISMATCHING key, not the
// lowest-sorted key outright: efidisk0 sorts first but matches the target,
// so the loop passes over it and ide0 is the first disk that can refuse.
// That distinguishes real sorted iteration from "whatever key came first".
func TestVMClone_RefusalNamesTheLowestSortedMismatchingDiskDeterministically(t *testing.T) {
	const runs = 60
	// Sorted: efidisk0 < ide0 < sata0 < scsi0 < scsi1 < unused0 < virtio0.
	disks := map[string]string{
		"efidisk0": "zfs-a:vm-100-disk-9,size=528K", // matches the target family
		"ide0":     "lvm-a:vm-100-disk-1,size=8G",   // <- first MISMATCHING in sorted order
		"sata0":    "lvm-b:vm-100-disk-2,size=8G",
		"scsi0":    "lvm-c:vm-100-disk-3,size=32G",
		"scsi1":    "lvm-d:vm-100-disk-4,size=64G",
		"unused0":  "lvm-e:vm-100-disk-5",
		"virtio0":  "lvm-f:vm-100-disk-6,size=8G",
	}
	types := map[string]string{
		"zfs-a": "zfspool", "target-zfs": "zfspool",
		"lvm-a": "lvmthin", "lvm-b": "lvmthin", "lvm-c": "lvmthin",
		"lvm-d": "lvmthin", "lvm-e": "lvmthin", "lvm-f": "lvmthin",
	}
	allKeys := []string{"efidisk0", "ide0", "sata0", "scsi0", "scsi1", "unused0", "virtio0"}

	named := map[string]int{}
	for i := 0; i < runs; i++ {
		f := multiDiskFake(disks, types)
		op := &VMClone{Client: f, SourceVMID: 100, NewVMID: 201,
			Params: url.Values{"storage": {"target-zfs"}}}

		err := op.Apply(context.Background())
		if err == nil {
			t.Fatalf("run %d: expected a refusal", i)
		}
		if f.cloneCalls != 0 {
			t.Fatalf("run %d: CloneVM calls = %d, want 0", i, f.cloneCalls)
		}

		var hits []string
		for _, k := range allKeys {
			if strings.Contains(err.Error(), k) {
				hits = append(hits, k)
			}
		}
		if len(hits) != 1 {
			t.Fatalf("run %d: refusal %q names %v — a refusal must identify exactly one disk", i, err, hits)
		}
		named[hits[0]]++
	}

	if len(named) != 1 {
		t.Fatalf("across %d runs the refusal named %v — sourceDisks promises the same disk run after run, "+
			"but map iteration order is randomised and the sort is what makes that promise true", runs, named)
	}
	if named["ide0"] != runs {
		t.Errorf("refusal named %v, want ide0 every time — the lowest-sorted MISMATCHING disk "+
			"(efidisk0 sorts first but matches the target, so it is passed over)", named)
	}
}
