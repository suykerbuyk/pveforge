package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// fakeStorageCreateClient is a scriptable StorageCreateClient, local to this
// test file — the Op's interface is narrower than the shared fakeClient, so it
// gets its own small fake, matching this package's one-fake-per-interface
// discipline (see fakeVMCreateClient).
type fakeStorageCreateClient struct {
	node string

	getConfigResult map[string]json.RawMessage
	getConfigErr    error
	getConfigCalls  int
	// createdConfig, when set, is what GetStorageConfigRaw answers once
	// CreateStorage has run: a fake that reflects its own create, so Run's
	// re-read after a create is clean.
	createdConfig map[string]json.RawMessage

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

func (f *fakeStorageCreateClient) GetStorageConfigRaw(_ context.Context, _ string) (map[string]json.RawMessage, error) {
	f.getConfigCalls++
	if f.createdConfig != nil && f.createCalls > 0 {
		return f.createdConfig, nil
	}
	if f.getConfigErr != nil {
		return nil, f.getConfigErr
	}
	return f.getConfigResult, nil
}

// rawCfg builds a raw PVE storage config object (string-valued keys) from
// key,value pairs, the shape GetStorageConfigRaw returns.
func rawCfg(kv ...string) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	for i := 0; i+1 < len(kv); i += 2 {
		b, _ := json.Marshal(kv[i+1])
		m[kv[i]] = b
	}
	return m
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
		createdConfig: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank"),
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
	// Truly matching, pool included: the raw read-back carries every desired
	// key (type, pool, content), so matching means truly-matching — this no
	// longer bakes in the old pool blind spot.
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank"),
	}
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
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images"), // type differs
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
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images"), // type differs
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

// --- H1: drift must see EVERY desired key, not just modeled ones ------------

// TestStorageCreate_PresentDifferingPool_Refuses is the headline H1 fix: a
// present zfspool on a DIFFERENT pool (same type and content) is refused, not a
// silent no-op. `pool` is dropped by the typed proxmox.ClusterStorage, so this
// only passes because Read uses the raw read-back.
func TestStorageCreate_PresentDifferingPool_Refuses(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "otherpool"),
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()} // pool=tank
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	_, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err == nil {
		t.Fatal("expected a differing-pool storage to be refused, not a silent no-op")
	}
	var differs *StorageDiffersError
	if !errors.As(err, &differs) {
		t.Fatalf("error = %v, want a *StorageDiffersError for a differing pool", err)
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must NOT be called for a differing pool, got %d", client.createCalls)
	}
}

// TestStorageCreate_DesiredNodesVsNoneRefuses: a desired nodes= against a
// read-back that omits nodes (cluster-wide) is drift, not a no-op.
func TestStorageCreate_DesiredNodesVsNoneRefuses(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank"), // no nodes
	}
	params := zfspoolParams()
	params.Set("nodes", "qa-pve-07")
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: params}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	_, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err == nil {
		t.Fatal("expected a desired nodes= against an unscoped storage to be refused")
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must NOT be called, got %d", client.createCalls)
	}
}

// TestStorageCreate_DesiredShared0VsOmittedRefuses: the omitempty hole — a
// desired shared=0 against a read-back that omits shared is drift, not a no-op.
func TestStorageCreate_DesiredShared0VsOmittedRefuses(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank"), // no shared
	}
	params := zfspoolParams()
	params.Set("shared", "0")
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: params}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	_, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err == nil {
		t.Fatal("expected a desired shared=0 against a storage omitting shared to be refused")
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must NOT be called, got %d", client.createCalls)
	}
}

// TestStorageCreate_DigestIsNotDrift (M3): once the raw read-back carries
// `digest`, a desired `digest=` (and `storage=`) must NOT count as drift — they
// are skipped. A matching definition whose read-back digest differs from a
// desired digest is still a no-op.
func TestStorageCreate_DigestIsNotDrift(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank", "digest", "actual-digest"),
	}
	params := zfspoolParams()
	params.Set("digest", "a-different-digest")
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: params}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("a differing digest must NOT count as drift (digest is skipped): expected a no-op")
	}
	if client.createCalls != 0 {
		t.Errorf("CreateStorage must not be called, got %d", client.createCalls)
	}
}

// TestStorageCreate_ForceMatchingRePosts (L4): --force on a present+matching
// storage bypasses the no-op and re-POSTs (createCalls==1); PVE would then
// refuse the duplicate — force never silently converges.
func TestStorageCreate_ForceMatchingRePosts(t *testing.T) {
	client := &fakeStorageCreateClient{
		node:            "qa-pve-07",
		getConfigResult: rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank"),
		createResult:    json.RawMessage(`{"storage":"pveforge-harness","type":"zfspool"}`),
	}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, true) // force
	if err != nil {
		t.Fatalf("Run(force): %v", err)
	}
	if !res.Changed {
		t.Error("expected --force to re-POST a matching storage (Changed=true)")
	}
	if client.createCalls != 1 {
		t.Errorf("expected exactly 1 CreateStorage call on force+matching, got %d", client.createCalls)
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

// TestStorageCreate_Apply_ForcePathDuplicateNotSwallowed (M2) proves the
// "no silent success" property on the FORCE path, not just the absent path:
// with op.current a MATCHING snapshot (what --force on a present+matching
// storage produces), a 500 "already defined" from CreateStorage must still be
// an error, never nil.
func TestStorageCreate_Apply_ForcePathDuplicateNotSwallowed(t *testing.T) {
	dup := pve.NewStatusError("create storage", 500, "500 Internal Server Error", []byte(`storage ID 'pveforge-harness' already defined`))
	client := &fakeStorageCreateClient{node: "qa-pve-07", createErr: dup}
	op := &StorageCreate{Client: client, Name: "pveforge-harness", Params: zfspoolParams()}
	// The force path: Read already ran and found a matching storage, so
	// op.current is a matching snapshot and Apply falls through to the POST.
	op.current = string(mustJSON(rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images", "pool", "tank")))
	if !op.matches(op.current) {
		t.Fatal("test setup: op.current must be a matching snapshot for the force path")
	}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected the duplicate 500 to be an error on the force path, not silently swallowed")
	}
	if !strings.Contains(err.Error(), "already defined") {
		t.Errorf("PVE's verbatim duplicate text was not propagated on the force path: %v", err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
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
