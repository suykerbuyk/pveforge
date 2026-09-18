package idempotent

import (
	"context"
	"errors"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

func vmWithTags(tags, digest string) *proxmox.VirtualMachine {
	return &proxmox.VirtualMachine{
		VirtualMachineConfig: &proxmox.VirtualMachineConfig{Tags: tags, Digest: digest},
	}
}

func TestVMTagEnsure_Read_PopulatesTagsAndDigest(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", getVMResults: []*proxmox.VirtualMachine{vmWithTags("prod;web", "d1")}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current != "prod;web" {
		t.Errorf("Read returned %q, want %q", current, "prod;web")
	}
	if op.digest != "d1" {
		t.Errorf("op.digest = %q, want d1", op.digest)
	}
	if len(op.tags) != 2 || op.tags[0] != "prod" || op.tags[1] != "web" {
		t.Errorf("op.tags = %v, want [prod web]", op.tags)
	}
}

// TestVMTagEnsure_Read_NilVirtualMachineConfig proves a VM with no
// VirtualMachineConfig (e.g. it doesn't exist) is surfaced as an error
// rather than silently treated as digest="" — the latter would disable
// SetVMConfigFieldCAS's compare-and-swap guard entirely (pveforge-nil-
// vmconfig-digest-gap).
func TestVMTagEnsure_Read_NilVirtualMachineConfig(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", getVMResults: []*proxmox.VirtualMachine{{}}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when VirtualMachineConfig is nil")
	}
	if op.tags != nil {
		t.Errorf("op.tags = %v, want nil", op.tags)
	}
	if op.digest != "" {
		t.Errorf("op.digest = %q, want empty", op.digest)
	}
}

func TestVMTagEnsure_Read_PropagatesGetVMError(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", getVMErr: errors.New("network down")}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when GetVM fails")
	}
}

func TestVMTagEnsure_Satisfied(t *testing.T) {
	op := &VMTagEnsure{Tag: "canary"}
	if op.Satisfied("") {
		t.Error("empty tags should not satisfy")
	}
	if op.Satisfied("prod;web") {
		t.Error("unrelated tags should not satisfy")
	}
	if !op.Satisfied("prod;canary;web") {
		t.Error("expected canary to be found among existing tags")
	}
}

// TestVMTagEnsure_Validate covers the gap an independent review found:
// VMTagEnsure had no input validation on Tag at all. A Tag containing the
// tag separator (';') would silently fragment into two separate tags on
// the next read/write round-trip — Satisfied's exact-string match against
// the whole original Tag could then never match again, causing a
// non-idempotent re-append on every invocation — and an empty Tag would
// produce a dangling trailing separator in the merged list.
func TestVMTagEnsure_Validate(t *testing.T) {
	cases := []struct {
		name    string
		tag     string
		wantErr bool
	}{
		{"valid tag", "canary", false},
		{"empty tag", "", true},
		{"tag containing the separator", "foo;bar", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op := &VMTagEnsure{VMID: 100, Tag: c.tag}
			err := op.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestVMTagEnsure_Apply_RejectsInvalidTagBeforeTouchingClient proves Apply
// actually calls Validate before doing anything else — an invalid Tag
// must never reach SetVMConfigFieldCAS at all (matching NVMeDrive.Apply's
// own "validate first" contract in internal/device/nvme.go).
func TestVMTagEnsure_Apply_RejectsInvalidTagBeforeTouchingClient(t *testing.T) {
	cases := []struct {
		name string
		tag  string
	}{
		{"empty tag", ""},
		{"tag containing the separator", "foo;bar"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &fakeClient{node: "qa-pve-01"}
			op := &VMTagEnsure{Client: client, VMID: 100, Tag: c.tag}
			op.tags = []string{"prod"}
			op.digest = "d1"

			err := op.Apply(context.Background())
			if err == nil {
				t.Fatal("expected an error for an invalid tag")
			}
			if client.setFieldCalls != 0 {
				t.Error("SetVMConfigFieldCAS must not be called when validation fails")
			}
		})
	}
}

func TestVMTagEnsure_Apply_MergesAndSendsDigest(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}
	op.tags = []string{"prod", "web"}
	op.digest = "d1"

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.lastVMID != 100 || client.lastField != "tags" {
		t.Errorf("SetVMConfigFieldCAS called with vmid=%d field=%q, want 100/tags", client.lastVMID, client.lastField)
	}
	if client.lastValue != "prod;web;canary" {
		t.Errorf("merged tags = %q, want prod;web;canary", client.lastValue)
	}
	if client.lastDigest != "d1" {
		t.Errorf("expected digest d1 sent as the CAS guard, got %q", client.lastDigest)
	}
}

func TestVMTagEnsure_Apply_NoExistingTags(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}
	// op.tags left nil (no prior Read), matching a VM with no tags yet.

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.lastValue != "canary" {
		t.Errorf("merged tags = %q, want just canary", client.lastValue)
	}
}

func TestVMTagEnsure_Apply_PropagatesNonConflictError(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", setFieldErrs: []error{errors.New("permission denied")}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error when SetVMConfigFieldCAS fails")
	}
	if errors.Is(err, ErrConflict) {
		t.Error("an unrelated failure must not be wrapped as ErrConflict")
	}
}

// TestVMTagEnsure_Apply_WrapsDigestConflictAsErrConflict proves the
// bridge between pve.IsDigestConflictError and idempotent.ErrConflict:
// Apply must recognize a genuine digest-mismatch-shaped rejection and
// wrap it so Run knows to retry.
func TestVMTagEnsure_Apply_WrapsDigestConflictAsErrConflict(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", setFieldErrs: []error{errors.New("update rejected: digest mismatch")}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected a digest-conflict-shaped error to be wrapped as ErrConflict, got: %v", err)
	}
}

// TestVMTagEnsure_Apply_RootOnlyRefusal_NotMisclassifiedAsConflict is the
// asymmetry regression test called for in this task's own recorded
// decision: RoutedClient.SetVMConfigFieldCAS refuses outright (a
// permanent, purely local error — never reaches PVE at all) for any field
// routed over the standing SSH vector, since that vector has no
// compare-and-swap mechanism. That refusal text must never be
// misclassified as a retryable digest conflict — it's the exact bug this
// implementation caught and fixed in internal/pve/routed.go before this
// test was written (the refusal originally contained the word "digest").
// Uses the real pve.RoutedClient refusal string verbatim so this test
// would catch a regression in either package.
func TestVMTagEnsure_Apply_RootOnlyRefusal_NotMisclassifiedAsConflict(t *testing.T) {
	refusal := errors.New(`set vm 100 field "args": root-only fields routed over the standing SSH vector have no compare-and-swap mechanism to honor an expected prior value with`)
	if pve.IsDigestConflictError(refusal) {
		t.Fatal("sanity check failed: the root-only refusal text is already misclassified by pve.IsDigestConflictError")
	}

	client := &fakeClient{node: "qa-pve-01", setFieldErrs: []error{refusal}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrConflict) {
		t.Fatal("a root-only-field refusal must never be wrapped as ErrConflict")
	}
}

// TestVMTagEnsure_ViaRun_EndToEnd_NoOp exercises the full stack this
// package provides — internal/lock's per-object serialization plus the
// read-compare-mutate contract — against the concrete proof case, not
// just Run's generic logic (op_test.go) or VMTagEnsure's methods in
// isolation (above).
func TestVMTagEnsure_ViaRun_EndToEnd_NoOp(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", getVMResults: []*proxmox.VirtualMachine{vmWithTags("prod;canary", "d1")}}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: canary is already present")
	}
	if client.setFieldCalls != 0 {
		t.Error("SetVMConfigFieldCAS must not be called on a no-op")
	}
}

// TestVMTagEnsure_ViaRun_EndToEnd_ConflictThenSuccess is the full-stack
// proof of the digest-CAS retry path: the first write attempt is rejected
// as a digest conflict (someone else changed the VM's tags between our
// Read and our Apply), Run re-reads (observing the concurrent change) and
// retries, and the second attempt succeeds — merging onto the
// concurrently-added tag rather than clobbering it.
func TestVMTagEnsure_ViaRun_EndToEnd_ConflictThenSuccess(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		getVMResults: []*proxmox.VirtualMachine{
			vmWithTags("prod", "d1"),                  // first Read: no concurrent change yet
			vmWithTags("prod;other-tag", "d2"),        // retry's Read: someone else added other-tag concurrently
			vmWithTags("prod;other-tag;canary", "d3"), // Run's final re-read for Result.After
		},
		setFieldErrs: []error{
			errors.New("digest mismatch: config changed since read"), // first Apply: conflict
			nil, // second Apply: succeeds
		},
	}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if client.setFieldCalls != 2 {
		t.Fatalf("expected 2 SetVMConfigFieldCAS calls (1 conflict + 1 success), got %d", client.setFieldCalls)
	}
	if client.lastValue != "prod;other-tag;canary" {
		t.Errorf("expected the retry to merge onto the concurrently-added tag, got %q", client.lastValue)
	}
	if client.lastDigest != "d2" {
		t.Errorf("expected the retry to CAS-guard against the re-read digest d2, got %q", client.lastDigest)
	}
}

// TestVMTagEnsure_ViaRun_RootOnlyFieldAsymmetry_NotRetried is the
// full-stack version of the asymmetry test above: run the engine end to
// end against a refusal shaped exactly like
// RoutedClient.SetVMConfigFieldCAS's real root-only-field response, and
// confirm Run still serializes correctly via internal/lock (it acquires
// and releases the lock, and returns cleanly) while making exactly one
// Apply attempt — never retrying a permanent, non-conflict refusal.
func TestVMTagEnsure_ViaRun_RootOnlyFieldAsymmetry_NotRetried(t *testing.T) {
	refusal := errors.New(`set vm 100 field "args": root-only fields routed over the standing SSH vector have no compare-and-swap mechanism to honor an expected prior value with`)
	client := &fakeClient{
		node:         "qa-pve-01",
		getVMResults: []*proxmox.VirtualMachine{vmWithTags("prod", "d1")},
		setFieldErrs: []error{refusal},
	}
	op := &VMTagEnsure{Client: client, VMID: 100, Tag: "canary"}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	roster := testRosterPath(t) // reused below: same lock domain for both Run calls

	_, err := Run(context.Background(), roster, key, op, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if client.setFieldCalls != 1 {
		t.Errorf("expected exactly 1 Apply attempt (no retry for a non-conflict refusal), got %d", client.setFieldCalls)
	}

	// The lock must have been released despite the failure: a second Run
	// for the SAME key AND roster must be able to proceed immediately, not
	// hang.
	client2 := &fakeClient{node: "qa-pve-01", getVMResults: []*proxmox.VirtualMachine{vmWithTags("prod;canary", "d1")}}
	op2 := &VMTagEnsure{Client: client2, VMID: 100, Tag: "canary"}
	res2, err2 := Run(context.Background(), roster, key, op2, false)
	if err2 != nil {
		t.Fatalf("second Run after a failed first Run: %v", err2)
	}
	if res2.Changed {
		t.Error("expected the second Run to be a clean no-op")
	}
}
