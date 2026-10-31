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

// fakeStorageContentClient is a scriptable StorageContentClient, local to this
// test file (one fake per interface, like fakeStorageCreateClient). It serves
// cfgBefore until a write SUCCEEDS, then cfgAfter — so a Run cycle's re-read
// after a successful Apply sees the new state, while a conflicted/ failed write
// leaves the read unchanged.
type fakeStorageContentClient struct {
	node string

	cfgBefore map[string]json.RawMessage
	cfgAfter  map[string]json.RawMessage // served once a write has succeeded
	getErr    error
	getCalls  int
	updatedOK bool

	updateErrs   []error // consumed one per call (for a retry sequence); then:
	updateErr    error   // a sticky error, or
	updateResult json.RawMessage
	updateCalls  int
	lastParams   url.Values

	waitCalls    int
	lastWaitNode string
	lastWaitUPID string
	waitErr      error
}

func (f *fakeStorageContentClient) Node() string { return f.node }

func (f *fakeStorageContentClient) GetStorageConfigRaw(_ context.Context, _ string) (map[string]json.RawMessage, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.updatedOK && f.cfgAfter != nil {
		return f.cfgAfter, nil
	}
	return f.cfgBefore, nil
}

func (f *fakeStorageContentClient) UpdateStorageConfig(_ context.Context, _ string, params url.Values) (json.RawMessage, error) {
	f.updateCalls++
	f.lastParams = params
	if len(f.updateErrs) > 0 {
		e := f.updateErrs[0]
		f.updateErrs = f.updateErrs[1:]
		if e != nil {
			return nil, e
		}
	} else if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.updatedOK = true
	return f.updateResult, nil
}

func (f *fakeStorageContentClient) WaitForTask(_ context.Context, node, upid string) error {
	f.waitCalls++
	f.lastWaitNode = node
	f.lastWaitUPID = upid
	return f.waitErr
}

// digestConflictErr is the shape PVE's config-digest mismatch takes: a 500
// whose body contains "digest", which pve.IsDigestConflictError matches.
func digestConflictErr() error {
	return pve.NewStatusError("update storage config", 500, "500 Internal Server Error", []byte("digest mismatch - config changed"))
}

const okObject = `{"storage":"pveforge-harness","type":"dir"}`

// --- present -> no-op (also pins the Satisfied precheck, mutant 2) ----------

// TestStorageContent_Present_NoOp proves a content type already in the set is
// Satisfied: Apply never runs, so no PUT and Changed is false. If Satisfied is
// mutated to always-false, Run calls Apply and updateCalls becomes 1 — RED.
func TestStorageContent_Present_NoOp(t *testing.T) {
	client := &fakeStorageContentClient{
		node:      "qa-pve-07",
		cfgBefore: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images,snippets", "digest", "d1"),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: the content type is already present")
	}
	if client.updateCalls != 0 {
		t.Errorf("UpdateStorageConfig must not be called when the type is present, got %d", client.updateCalls)
	}
}

// --- absent -> add-only, sorted (pins the add-only merge, mutant 1) ---------

// TestStorageContent_Absent_AddsSortedPreservingExisting proves an absent
// content type drives a full cycle: Apply PUTs the existing set UNIONED with
// the new type, SORTED, with the fresh digest; the synchronous object response
// waits on nothing. If Apply drops the union (writes just the new type), the
// content assertion fails — RED.
func TestStorageContent_Absent_AddsSortedPreservingExisting(t *testing.T) {
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    rawCfg("storage", "pveforge-harness", "type", "dir", "content", "iso,images", "digest", "d1"),
		cfgAfter:     rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images,iso,snippets", "digest", "d2"),
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true for a newly-added content type")
	}
	if client.updateCalls != 1 {
		t.Fatalf("expected exactly 1 UpdateStorageConfig call, got %d", client.updateCalls)
	}
	if got := client.lastParams.Get("content"); got != "images,iso,snippets" {
		t.Errorf("PUT content = %q, want \"images,iso,snippets\" (existing types preserved, sorted, new type added)", got)
	}
	if got := client.lastParams.Get("digest"); got != "d1" {
		t.Errorf("PUT digest = %q, want the fresh pre-write digest d1", got)
	}
	if client.waitCalls != 0 {
		t.Errorf("a synchronous object response must not wait on a task, got %d WaitForTask calls", client.waitCalls)
	}
}

// TestStorageContent_Absent_EmptyContentField proves a storage whose content
// field is empty (or absent) still gets the new type written as the sole,
// sorted member.
func TestStorageContent_Absent_EmptyContentField(t *testing.T) {
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    rawCfg("storage", "pveforge-harness", "type", "dir", "content", "", "digest", "d1"),
		cfgAfter:     rawCfg("storage", "pveforge-harness", "type", "dir", "content", "snippets", "digest", "d2"),
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	if _, err := Run(context.Background(), testRosterPath(t), key, op, false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := client.lastParams.Get("content"); got != "snippets" {
		t.Errorf("PUT content = %q, want \"snippets\"", got)
	}
}

// --- defensive UPID wait ----------------------------------------------------

// TestStorageContent_Apply_DefensiveUPIDWaits proves that IF PUT /storage ever
// answers with a bare UPID scalar, Apply waits on that task — the defensive
// branch. Its anti-vacuity partner is the object-response no-wait assertion in
// TestStorageContent_Absent_AddsSortedPreservingExisting.
func TestStorageContent_Apply_DefensiveUPIDWaits(t *testing.T) {
	const upid = "UPID:qa-pve-07:0001:0002:0003:setcontent:pveforge-harness:root@pam:"
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1"),
		cfgAfter:     rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images,snippets", "digest", "d2"),
		updateResult: json.RawMessage(`"` + upid + `"`),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.waitCalls != 1 {
		t.Fatalf("expected 1 WaitForTask call for a UPID response, got %d", client.waitCalls)
	}
	if client.lastWaitUPID != upid {
		t.Errorf("WaitForTask upid = %q, want the UPID the write returned", client.lastWaitUPID)
	}
	if client.lastWaitNode != "qa-pve-07" {
		t.Errorf("WaitForTask node = %q, want qa-pve-07", client.lastWaitNode)
	}
}

// --- digest conflict wraps ErrConflict (pins mutant 3, Apply level) ---------

// TestStorageContent_Apply_DigestConflictWrapsErrConflict proves a digest
// mismatch from the PUT is wrapped as ErrConflict (so idempotent.Run retries),
// and no task is waited on. If Apply stops wrapping, errors.Is fails — RED.
func TestStorageContent_Apply_DigestConflictWrapsErrConflict(t *testing.T) {
	client := &fakeStorageContentClient{
		node:      "qa-pve-07",
		cfgBefore: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1"),
		updateErr: digestConflictErr(),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error for a digest conflict")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("a digest conflict must wrap ErrConflict so Run retries; got %v", err)
	}
	if client.waitCalls != 0 {
		t.Errorf("a failed write must not wait on a task, got %d WaitForTask calls", client.waitCalls)
	}
}

// TestStorageContent_Run_RetriesOnDigestConflict proves the Run-level effect of
// the ErrConflict wrapping: a transient conflict (write 1) is retried and
// succeeds (write 2). If Apply fails to wrap the conflict, Run returns a
// terminal error instead of retrying — updateCalls stays 1 and Run errors — RED.
func TestStorageContent_Run_RetriesOnDigestConflict(t *testing.T) {
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1"),
		cfgAfter:     rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images,snippets", "digest", "d2"),
		updateErrs:   []error{digestConflictErr()}, // conflict once, then succeed
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run should retry past a transient digest conflict: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true after the retried write succeeded")
	}
	if client.updateCalls != 2 {
		t.Errorf("expected a retry (2 UpdateStorageConfig calls), got %d", client.updateCalls)
	}
}

// --- diff-guard rejects an unexpected field change (pins mutant 4) ----------

// TestStorageContent_Apply_DiffGuardRejectsUnexpectedField rigs the post-write
// read to also change `type` (a field this Op never touches). The diff-guard
// must fail hard and name it. If Apply skips the diff-guard, the write looks
// clean — RED.
func TestStorageContent_Apply_DiffGuardRejectsUnexpectedField(t *testing.T) {
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1"),
		cfgAfter:     rawCfg("storage", "pveforge-harness", "type", "zfspool", "content", "images,snippets", "digest", "d2"), // type changed!
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected the diff-guard to reject an unexpected field change")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Errorf("the diff-guard error must name the changed field (type): %v", err)
	}
}

// --- missing storage is a hard error ----------------------------------------

// TestStorageContent_Read_MissingStorageIsHardError proves a storage that does
// not exist is a hard error from Read (never "absent"): you cannot toggle
// content on a storage that isn't there.
func TestStorageContent_Read_MissingStorageIsHardError(t *testing.T) {
	client := &fakeStorageContentClient{node: "qa-pve-07", getErr: storageNotFoundErr()}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}

	_, err := op.Read(context.Background())
	if err == nil {
		t.Fatal("expected a hard error for a missing storage")
	}
	if !pve.IsStorageNotFoundError(err) {
		t.Errorf("the error should still carry the typed not-found answer: %v", err)
	}
}

// --- no-digest read is refused ----------------------------------------------

// TestStorageContent_Read_NoDigestRefused proves a config carrying no digest is
// refused loudly (the digest is the CAS token Apply needs).
func TestStorageContent_Read_NoDigestRefused(t *testing.T) {
	client := &fakeStorageContentClient{
		node:      "qa-pve-07",
		cfgBefore: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images"), // no digest
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	if _, err := op.Read(context.Background()); err == nil {
		t.Error("expected a config with no digest to be refused")
	}
}

// --- Validate ---------------------------------------------------------------

func TestStorageContent_Validate(t *testing.T) {
	if err := (&StorageContentEnsure{Storage: "", ContentType: "snippets"}).Validate(); err == nil {
		t.Error("expected a missing storage name to be refused")
	}
	if err := (&StorageContentEnsure{Storage: "s", ContentType: ""}).Validate(); err == nil {
		t.Error("expected a missing content type to be refused")
	}
	if err := (&StorageContentEnsure{Storage: "s", ContentType: "snippets"}).Validate(); err != nil {
		t.Errorf("a well-formed Op must pass Validate: %v", err)
	}
}

// --- Fix A (DEFECT 5): the diff-guard must confirm the intended change landed -

// TestStorageContent_Apply_DiffGuardRejectsMissingIntendedType rigs the
// post-write GET to return a 2xx but the OLD content list (no ContentType),
// simulating a PUT that reported success without landing. The diff-guard's
// positive assertion must fail hard — otherwise Run reports a success that did
// not happen (idempotent.Run never re-checks Satisfied after Apply). Reverting
// that assertion turns this RED.
func TestStorageContent_Apply_DiffGuardRejectsMissingIntendedType(t *testing.T) {
	before := rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1")
	after := rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d2") // digest moved, but snippets still absent
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    before,
		cfgAfter:     after,
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected a hard error: the PUT reported success but the re-read does not show the new type")
	}
	if !strings.Contains(err.Error(), "not present on re-read") {
		t.Errorf("the error must say the intended type is not present on re-read: %v", err)
	}
}

// TestStorageContent_Run_FailsWhenWriteDidNotLand is the Run-level consequence:
// a write that does not land must make Run return an error, never report
// success for a change that did not happen.
func TestStorageContent_Run_FailsWhenWriteDidNotLand(t *testing.T) {
	before := rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1")
	after := rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d2")
	client := &fakeStorageContentClient{
		node:         "qa-pve-07",
		cfgBefore:    before,
		cfgAfter:     after,
		updateResult: json.RawMessage(okObject),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "snippets"}
	key := lock.ObjectKey{TargetID: "qa-pve-07", Kind: "storage", ID: "pveforge-harness"}

	if _, err := Run(context.Background(), testRosterPath(t), key, op, false); err == nil {
		t.Fatal("Run must not report success when the intended content type did not land")
	}
}

// --- Fix B (DEFECT 3): fail closed on an unknown content type ----------------

// TestStorageContent_Validate_RejectsUnknownContentType proves a bogus content
// type is refused by Validate, and every one of PVE's 7 canonical types passes.
// Reverting the validation turns the rejection RED.
func TestStorageContent_Validate_RejectsUnknownContentType(t *testing.T) {
	if err := (&StorageContentEnsure{Storage: "pveforge-harness", ContentType: "garbage"}).Validate(); err == nil {
		t.Error("expected an unknown content type to be refused (a cluster-config write must fail closed)")
	}
	for _, ct := range []string{"images", "rootdir", "iso", "vztmpl", "backup", "snippets", "import"} {
		if err := (&StorageContentEnsure{Storage: "pveforge-harness", ContentType: ct}).Validate(); err != nil {
			t.Errorf("canonical content type %q must pass Validate: %v", ct, err)
		}
	}
}

// TestStorageContent_Apply_UnknownTypeIssuesNoPUT proves the fail-closed
// property reaches the write path: Apply validates first, so a garbage type is
// refused BEFORE any PUT (updateCalls stays 0).
func TestStorageContent_Apply_UnknownTypeIssuesNoPUT(t *testing.T) {
	client := &fakeStorageContentClient{
		node:      "qa-pve-07",
		cfgBefore: rawCfg("storage", "pveforge-harness", "type", "dir", "content", "images", "digest", "d1"),
	}
	op := &StorageContentEnsure{Client: client, Storage: "pveforge-harness", ContentType: "garbage"}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a garbage content type to be refused by Apply")
	}
	if client.updateCalls != 0 {
		t.Errorf("no PUT may be issued for an invalid content type, got %d", client.updateCalls)
	}
}
