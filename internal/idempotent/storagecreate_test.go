package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// fakeStorageCreateClient is a scriptable StorageCreateClient, local to this
// test file — the Op's interface is narrower than the shared fakeClient, so it
// gets its own small fake, matching this package's one-fake-per-interface
// discipline (see fakeVMCreateClient).
type fakeStorageCreateClient struct {
	node string

	getConfigResult *proxmox.ClusterStorage
	getConfigErr    error
	getConfigCalls  int
	// createdConfig, when set, is what GetStorageConfig answers once
	// CreateStorage has run: a fake that reflects its own create, so Run's
	// re-read after a create is clean.
	createdConfig *proxmox.ClusterStorage

	createResult json.RawMessage
	createErr    error
	createCalls  int
	lastName     string
	lastParams   url.Values

	waitCalls    int
	lastWaitNode string
	lastWaitUPID string
	waitErr      error
}

func (f *fakeStorageCreateClient) Node() string { return f.node }

func (f *fakeStorageCreateClient) GetStorageConfig(_ context.Context, _ string) (*proxmox.ClusterStorage, error) {
	f.getConfigCalls++
	if f.createdConfig != nil && f.createCalls > 0 {
		return f.createdConfig, nil
	}
	if f.getConfigErr != nil {
		return nil, f.getConfigErr
	}
	return f.getConfigResult, nil
}

func (f *fakeStorageCreateClient) CreateStorage(_ context.Context, name string, params url.Values) (json.RawMessage, error) {
	f.createCalls++
	f.lastName = name
	f.lastParams = params
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResult, nil
}

func (f *fakeStorageCreateClient) WaitForTask(_ context.Context, node, upid string) error {
	f.waitCalls++
	f.lastWaitNode = node
	f.lastWaitUPID = upid
	return f.waitErr
}

// storageNotFoundErr is the typed PVE answer GET /storage/{id} gives for a
// missing id — 400 "No such storage." in errors.storage (verified live, nested
// pvh 2026-10-23, batch-a) — built the way RawRequest/go-proxmox build it, so
// pve.IsStorageNotFoundError classifies it as absent.
func storageNotFoundErr() error {
	return pve.NewStatusError("get storage config", 400, "400 Parameter verification failed.", []byte(`{"errors":{"storage":"No such storage."}}`))
}

func zfspoolParams() url.Values {
	return url.Values{"type": {"zfspool"}, "pool": {"tank"}, "content": {"images"}}
}

// --- Invariant 1: absent -> create ------------------------------------------

// TestStorageCreate_Absent_Creates proves a storage nothing answers to drives a
// full Run cycle: Read is not-found -> Satisfied(false) -> Apply POSTs
// /storage with the name stamped on and the type in params, and Changed is true.
func TestStorageCreate_Absent_Creates(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:          "qa-pve-07",
		getConfigErr:  storageNotFoundErr(),
		createdConfig: &proxmox.ClusterStorage{Storage: "pveforge-harness", Type: "zfspool", Content: "images"},
		createResult:  json.RawMessage(`{"storage":"pveforge-harness","type":"zfspool"}`), // an object, not a UPID
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true for an absent storage")
	}
	if client.createCalls != 1 {
		t.Fatalf("expected 1 CreateStorage call, got %d", client.createCalls)
	}
	if client.lastName != "pveforge-harness" {
		t.Errorf("CreateStorage name = %q, want pveforge-harness (the POST stamps storage=<name>)", client.lastName)
	}
	if client.lastParams.Get("type") != "zfspool" {
		t.Errorf("POST params type = %q, want zfspool", client.lastParams.Get("type"))
	}
	if client.lastParams.Get("pool") != "tank" {
		t.Errorf("POST params pool = %q, want tank", client.lastParams.Get("pool"))
	}
	if client.waitCalls != 0 {
		t.Errorf("expected 0 WaitForTask calls for a synchronous object response, got %d", client.waitCalls)
	}
	// Anti-vacuity for the clean path: the created config was re-read.
	if res.AfterErr != nil || res.After == "" || res.Before != "" {
		t.Errorf("Before %q, After %q, AfterErr %v; want a clean re-read of the created storage", res.Before, res.After, res.AfterErr)
	}
}

// --- Invariant 2: present + matching -> no-op -------------------------------

// TestStorageCreate_PresentMatching_NoOp proves a storage that already exists
// with the requested definition is Satisfied: Apply is never called and
// Changed is false.
func TestStorageCreate_PresentMatching_NoOp(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: &proxmox.ClusterStorage{Storage: "pveforge-harness", Type: "zfspool", Content: "images"},
	}
	// pool is not modeled by the read-back, so it is not drift-checked (v1);
	// the modeled type+content match.
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: the storage already matches")
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must not be called on a matching storage, got %d calls", client.createCalls)
	}
}

// --- Invariant 3: present + differing -> refuse-and-report (NO POST) ---------

// TestStorageCreate_PresentDiffering_Refuses proves a storage that exists with
// a DIFFERING definition is refused with a StorageDiffersError and NO POST is
// made.
func TestStorageCreate_PresentDiffering_Refuses(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: &proxmox.ClusterStorage{Storage: "pveforge-harness", Type: "dir", Content: "images"}, // type differs
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	_, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err == nil {
		t.Fatal("expected a refusal for a differing storage")
	}
	var differs *StorageDiffersError
	if !errors.As(err, &differs) {
		t.Fatalf("error = %v, want a *StorageDiffersError", err)
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must NOT be called when the definition differs, got %d calls", client.createCalls)
	}
}

// TestStorageCreate_PresentDiffering_ForceStillRefuses proves --force
// (Run's force) does NOT converge a differing definition: it is still refused,
// with no POST.
func TestStorageCreate_PresentDiffering_ForceStillRefuses(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: &proxmox.ClusterStorage{Storage: "pveforge-harness", Type: "dir", Content: "images"},
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	_, err := Run(context.Background(), testRosterPath(t), key, op, true) // force = true
	if err == nil {
		t.Fatal("expected --force to STILL refuse a differing storage")
	}
	var differs *StorageDiffersError
	if !errors.As(err, &differs) {
		t.Fatalf("error = %v, want a *StorageDiffersError even with force", err)
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must NOT be called for a differing storage even with force, got %d calls", client.createCalls)
	}
}

// --- Invariant 4: required-keys guard (client-side, before any POST) --------

// TestStorageCreate_RequiredKeysGuard proves a --type with a required key
// missing (zfspool without pool) is refused by Validate, BEFORE any Read or
// POST, and that supplying the key passes. Mutating requiredKeysByType away
// from {"zfspool":{"pool"}} turns the first assertion green-when-it-should-be-
// red: that is the planted-mutant check in the findings.
func TestStorageCreate_RequiredKeysGuard(t *testing.T) {
	missing := &StorageCreate{
		Name:   "pveforge-harness",
		Params: url.Values{"type": {"zfspool"}, "content": {"images"}}, // no pool
	}
	if err := missing.Validate(); err == nil {
		t.Error("expected --type zfspool with no pool to be refused by the required-keys guard")
	}
	// Anti-vacuity: a client-touch would mean the guard ran too late.
	client := &fakeStorageCreateClient{node: "qa-pve-07"}
	missing.Client = client
	_ = missing.Validate()
	if client.createCalls != 0 || client.getConfigCalls != 0 {
		t.Error("the required-keys guard must refuse BEFORE touching the client (no POST, no read)")
	}

	ok := &StorageCreate{Name: "pveforge-harness", Params: zfspoolParams()} // pool present
	if err := ok.Validate(); err != nil {
		t.Errorf("a zfspool WITH pool must pass the guard: %v", err)
	}
}

// TestStorageCreate_Validate_RequiresTypeAndName covers the other two guard
// branches: a missing type and a missing name are both refused.
func TestStorageCreate_Validate_RequiresTypeAndName(t *testing.T) {
	if err := (&StorageCreate{Name: "s", Params: url.Values{}}).Validate(); err == nil {
		t.Error("expected a missing type to be refused")
	}
	if err := (&StorageCreate{Name: "", Params: url.Values{"type": {"dir"}}}).Validate(); err == nil {
		t.Error("expected a missing name to be refused")
	}
}

// --- Invariant 5: privilege 403 -> verbatim AND errors.Is(ErrNotAuthorized) -

// TestStorageCreate_Apply_PrivilegeDenied proves a 403 from the create is
// propagated verbatim AND satisfies errors.Is(pve.ErrNotAuthorized).
func TestStorageCreate_Apply_PrivilegeDenied(t *testing.T) {
	denied := pve.NewStatusError("create storage", 403, "403 Forbidden", []byte(`Permission check failed (/storage, Datastore.Allocate)`))
	client := &fakeStorageCreateClient{node: "qa-pve-07", createErr: denied}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 403 from the create")
	}
	if !errors.Is(err, pve.ErrNotAuthorized) {
		t.Errorf("error does not satisfy errors.Is(pve.ErrNotAuthorized): %v", err)
	}
	if !strings.Contains(err.Error(), "Datastore.Allocate") {
		t.Errorf("PVE's verbatim text was not propagated: %v", err)
	}
}

// --- Invariant 6: duplicate 500 -> verbatim, no silent success --------------

// TestStorageCreate_Apply_DuplicateRefused proves PVE's "storage ID already
// defined" (the TOCTOU/duplicate case) is propagated verbatim and is a real
// error, never a silent success.
func TestStorageCreate_Apply_DuplicateRefused(t *testing.T) {
	dup := pve.NewStatusError("create storage", 500, "500 Internal Server Error", []byte(`storage ID 'pveforge-harness' already defined`))
	client := &fakeStorageCreateClient{node: "qa-pve-07", createErr: dup}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when PVE refuses a duplicate id")
	}
	if !strings.Contains(err.Error(), "already defined") {
		t.Errorf("PVE's verbatim duplicate text was not propagated: %v", err)
	}
}

// --- Invariant 7: defensive UPID row -> WaitForTask path runs ---------------

// TestStorageCreate_Apply_DefensiveUPIDWaits proves that IF POST /storage ever
// answers with a bare UPID scalar (it is documented synchronous, but this is
// not live-verified), Apply waits on that task.
func TestStorageCreate_Apply_DefensiveUPIDWaits(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:         "qa-pve-07",
		createResult: json.RawMessage(`"UPID:qa-pve-07:0001:0002:0003:storagecreate:pveforge-harness:root@pam:"`),
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.waitCalls != 1 {
		t.Fatalf("expected 1 WaitForTask call for a UPID response, got %d", client.waitCalls)
	}
	if client.lastWaitUPID != "UPID:qa-pve-07:0001:0002:0003:storagecreate:pveforge-harness:root@pam:" {
		t.Errorf("WaitForTask upid = %q, want the UPID the create returned", client.lastWaitUPID)
	}
	if client.lastWaitNode != "qa-pve-07" {
		t.Errorf("WaitForTask node = %q, want qa-pve-07", client.lastWaitNode)
	}
}

// TestStorageCreate_Apply_SyncObjectDoesNotWait is the anti-vacuity partner of
// the UPID test: the normal synchronous object response waits on nothing.
func TestStorageCreate_Apply_SyncObjectDoesNotWait(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:         "qa-pve-07",
		createResult: json.RawMessage(`{"storage":"pveforge-harness","type":"zfspool"}`),
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.waitCalls != 0 {
		t.Errorf("a synchronous object response must not wait on a task, got %d WaitForTask calls", client.waitCalls)
	}
}

// --- Read's strict not-found contract ---------------------------------------

// TestStorageCreate_Read_PropagatesNonNotFoundError proves Read is stricter
// than VMCreate.Read: a read error that is NOT an authoritative not-found is
// propagated, never swallowed as "absent".
func TestStorageCreate_Read_PropagatesNonNotFoundError(t *testing.T) {
	client := &fakeStorageCreateClient{node: "qa-pve-07", getConfigErr: errors.New("connection refused")}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	if _, err := op.Read(context.Background()); err == nil {
		t.Error("expected a non-not-found read error to propagate, not be read as absent")
	}
}
