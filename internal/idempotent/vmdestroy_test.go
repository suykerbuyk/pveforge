package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// rawRequestStep scripts one fetchVMConfig-relevant RawRequest call.
type rawRequestStep struct {
	result json.RawMessage
	err    error
}

// fakeVMDestroyClient is a scriptable VMDestroyClient, local to this test
// file — VMDestroy's Client interface (RawRequest/StopVM/DestroyVM/
// WaitForTask/TagStillClaimed) doesn't match fakeClient's or
// fakeVMCreateClient's shape, so it gets its own small fake, matching this
// package's existing "one fake per interface shape" discipline.
type fakeVMDestroyClient struct {
	node string

	rawRequestSteps []rawRequestStep
	rawRequestCalls int
	lastRawMethod   string
	lastRawPath     string

	stopVMUPID   string
	stopVMErr    error
	stopVMCalls  int
	lastStopVMID int

	destroyVMUPID   string
	destroyVMErr    error
	destroyVMCalls  int
	lastDestroyVMID int
	lastPurge       bool

	waitForTaskErrs  []error
	waitForTaskCalls int
	lastWaitNode     string
	lastWaitUPIDs    []string

	tagStillClaimedResult bool
	tagStillClaimedErr    error
	tagStillClaimedCalls  int
	lastTagArg            string
	lastExcludeVMID       int
}

func (f *fakeVMDestroyClient) Node() string { return f.node }

func (f *fakeVMDestroyClient) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	f.lastRawMethod = method
	f.lastRawPath = path
	idx := f.rawRequestCalls
	f.rawRequestCalls++
	if len(f.rawRequestSteps) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if idx >= len(f.rawRequestSteps) {
		idx = len(f.rawRequestSteps) - 1
	}
	step := f.rawRequestSteps[idx]
	return step.result, step.err
}

func (f *fakeVMDestroyClient) StopVM(_ context.Context, vmid int) (string, error) {
	f.stopVMCalls++
	f.lastStopVMID = vmid
	if f.stopVMErr != nil {
		return "", f.stopVMErr
	}
	return f.stopVMUPID, nil
}

func (f *fakeVMDestroyClient) DestroyVM(_ context.Context, vmid int, purge bool) (string, error) {
	f.destroyVMCalls++
	f.lastDestroyVMID = vmid
	f.lastPurge = purge
	if f.destroyVMErr != nil {
		return "", f.destroyVMErr
	}
	return f.destroyVMUPID, nil
}

func (f *fakeVMDestroyClient) WaitForTask(_ context.Context, node, upid string) error {
	idx := f.waitForTaskCalls
	f.waitForTaskCalls++
	f.lastWaitNode = node
	f.lastWaitUPIDs = append(f.lastWaitUPIDs, upid)
	if idx < len(f.waitForTaskErrs) {
		return f.waitForTaskErrs[idx]
	}
	return nil
}

func (f *fakeVMDestroyClient) TagStillClaimed(_ context.Context, tag string, excludeVMID int) (bool, error) {
	f.tagStillClaimedCalls++
	f.lastTagArg = tag
	f.lastExcludeVMID = excludeVMID
	if f.tagStillClaimedErr != nil {
		return false, f.tagStillClaimedErr
	}
	return f.tagStillClaimedResult, nil
}

// missingVMErrorText is the realistic PVE "no such VM" message this
// project's isMissingVMError is built to recognize.
func missingVMErrorText(vmid int) string {
	return "raw request: pve returned 500 Internal Server Error: Configuration file '/etc/pve/nodes/qa-pve-01/qemu-server/" +
		strconv.Itoa(vmid) + ".conf' does not exist"
}

// --- isMissingVMError -------------------------------------------------

func TestIsMissingVMError_MatchesRealMissingVMText(t *testing.T) {
	err := errors.New(missingVMErrorText(100))
	if !isMissingVMError(err, 100) {
		t.Error("expected a match for the vmid's own missing-config text")
	}
}

// TestIsMissingVMError_RejectsAuthFailureNearMiss is the regression this
// classifier exists for: PVE's unrelated "user '<name>@pve' does not
// exist" auth-failure text also contains "does not exist" but must NOT be
// classified as "VM gone" — a bare substring match would silently no-op a
// real destroy exactly the way GetVM's opaque errors did in the rejected
// first draft of this Op.
func TestIsMissingVMError_RejectsAuthFailureNearMiss(t *testing.T) {
	err := errors.New("raw request: pve returned 500 Internal Server Error: user 'root@pve' does not exist")
	if isMissingVMError(err, 100) {
		t.Error("expected the auth-failure near-miss to be rejected, not classified as \"VM gone\"")
	}
}

// TestIsMissingVMError_RejectsWrongVMID proves the match is vmid-specific:
// a missing-config message for a DIFFERENT vmid must not satisfy this
// vmid's check.
func TestIsMissingVMError_RejectsWrongVMID(t *testing.T) {
	err := errors.New(missingVMErrorText(101))
	if isMissingVMError(err, 100) {
		t.Error("expected vmid 101's missing-config text to not match vmid 100's check")
	}
}

func TestIsMissingVMError_RejectsUnrelatedError(t *testing.T) {
	err := errors.New("raw request: dial tcp 10.0.0.1:8006: connect: connection refused")
	if isMissingVMError(err, 100) {
		t.Error("expected an unrelated transport error to not be classified as \"VM gone\"")
	}
}

func TestIsMissingVMError_NilErrorIsFalse(t *testing.T) {
	if isMissingVMError(nil, 100) {
		t.Error("expected a nil error to never be classified as \"VM gone\"")
	}
}

// --- Read / Satisfied ---------------------------------------------------

// TestVMDestroy_Read_ClassifiedMissing_ReportsGone proves the happy path:
// a classified not-found error reads as "" (gone), Satisfied is true.
func TestVMDestroy_Read_ClassifiedMissing_ReportsGone(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:            "qa-pve-01",
		rawRequestSteps: []rawRequestStep{{err: errors.New(missingVMErrorText(100))}},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current != "" {
		t.Errorf("current = %q, want empty for an already-gone vmid", current)
	}
	if !op.Satisfied(current) {
		t.Error("expected Satisfied(current) to be true when the vm is already gone")
	}
}

// TestVMDestroy_Read_UnrelatedError_Propagates is the critical regression
// this Op was rejected twice over: a transient/unclassified RawRequest
// error must surface as a real Read error, NOT be folded into "gone" the
// way VMCreate.Read treats any GetVM failure. Getting this backwards makes
// idempotent.Run's Satisfied-skip path (op.go) silently no-op a real
// destroy.
func TestVMDestroy_Read_UnrelatedError_Propagates(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:            "qa-pve-01",
		rawRequestSteps: []rawRequestStep{{err: errors.New("dial tcp: connection refused")}},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	_, err := op.Read(context.Background())
	if err == nil {
		t.Fatal("expected an unclassified RawRequest error to propagate from Read")
	}
}

// TestVMDestroy_Read_NearMissAuthError_Propagates is the same regression,
// specifically for the auth-failure near-miss the tightened classifier was
// built to reject.
func TestVMDestroy_Read_NearMissAuthError_Propagates(t *testing.T) {
	client := &fakeVMDestroyClient{
		node: "qa-pve-01",
		rawRequestSteps: []rawRequestStep{
			{err: errors.New("raw request: pve returned 500 Internal Server Error: user 'root@pve' does not exist")},
		},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	_, err := op.Read(context.Background())
	if err == nil {
		t.Fatal("expected the auth-failure near-miss to propagate as a real error, not read as \"gone\"")
	}
}

func TestVMDestroy_Read_VMExists_ReportsNonEmpty(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:            "qa-pve-01",
		rawRequestSteps: []rawRequestStep{{result: json.RawMessage(`{"name":"test-vm","cores":"4"}`)}},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current == "" {
		t.Fatal("expected a non-empty current state for an existing vm")
	}
	if op.Satisfied(current) {
		t.Error("expected Satisfied(current) to be false for an existing vm")
	}
}

// --- Apply ---------------------------------------------------------------

// baseDestroyClient returns a fakeVMDestroyClient scripted for a full
// happy-path Apply: stop succeeds, destroy succeeds, reverify confirms
// gone (classified missing), no tag recheck.
func baseDestroyClient() *fakeVMDestroyClient {
	return &fakeVMDestroyClient{
		node:          "qa-pve-01",
		stopVMUPID:    "UPID:qa-pve-01:1:1:1:qmstop:100:root@pam:",
		destroyVMUPID: "UPID:qa-pve-01:2:2:2:qmdestroy:100:root@pam:",
		rawRequestSteps: []rawRequestStep{
			{err: errors.New(missingVMErrorText(100))},
		},
	}
}

func TestVMDestroy_Apply_HappyPath(t *testing.T) {
	client := baseDestroyClient()
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if op.StopWarning != nil {
		t.Errorf("expected no StopWarning, got: %v", op.StopWarning)
	}
	if client.stopVMCalls != 1 || client.destroyVMCalls != 1 {
		t.Errorf("expected exactly one StopVM and one DestroyVM call, got stop=%d destroy=%d", client.stopVMCalls, client.destroyVMCalls)
	}
	if client.lastStopVMID != op.VMID {
		t.Errorf("StopVM called with vmid=%d, want %d", client.lastStopVMID, op.VMID)
	}
	if client.lastDestroyVMID != op.VMID {
		t.Errorf("DestroyVM called with vmid=%d, want %d", client.lastDestroyVMID, op.VMID)
	}
	if client.waitForTaskCalls != 2 {
		t.Errorf("expected 2 WaitForTask calls (stop + destroy), got %d", client.waitForTaskCalls)
	}
	if !client.lastPurge {
		t.Error("expected DestroyVM to be called with purge=true")
	}
}

// TestVMDestroy_Apply_StopFailure_RecordedAsWarning_DestroyStillRuns proves
// the stop/destroy asymmetry: a failing stop never blocks the hard destroy.
func TestVMDestroy_Apply_StopFailure_RecordedAsWarning_DestroyStillRuns(t *testing.T) {
	client := baseDestroyClient()
	client.stopVMErr = errors.New("vm 100 is locked")
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if op.StopWarning == nil {
		t.Error("expected StopWarning to be set")
	}
	if client.destroyVMCalls != 1 {
		t.Error("expected DestroyVM to still run despite the stop failure")
	}
	if client.lastStopVMID != op.VMID {
		t.Errorf("StopVM called with vmid=%d, want %d", client.lastStopVMID, op.VMID)
	}
	if client.lastDestroyVMID != op.VMID {
		t.Errorf("DestroyVM called with vmid=%d, want %d", client.lastDestroyVMID, op.VMID)
	}
}

// TestVMDestroy_Apply_StopWaitForTaskFailure_RecordedAsWarning covers the
// other stop-step failure point: StopVM itself succeeds but its
// WaitForTask fails.
func TestVMDestroy_Apply_StopWaitForTaskFailure_RecordedAsWarning(t *testing.T) {
	client := baseDestroyClient()
	client.waitForTaskErrs = []error{errors.New("stop task failed")}
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if op.StopWarning == nil {
		t.Error("expected StopWarning to be set when the stop's own WaitForTask fails")
	}
	if client.destroyVMCalls != 1 {
		t.Error("expected DestroyVM to still run despite the stop-wait failure")
	}
}

func TestVMDestroy_Apply_DestroyVMError_HardFails(t *testing.T) {
	client := baseDestroyClient()
	client.destroyVMErr = errors.New("VM 100 already exists")
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected an error when DestroyVM fails")
	}
	if client.rawRequestCalls != 0 {
		t.Error("reverify must not run when the destroy call itself failed")
	}
	if client.lastDestroyVMID != op.VMID {
		t.Errorf("DestroyVM called with vmid=%d, want %d", client.lastDestroyVMID, op.VMID)
	}
}

func TestVMDestroy_Apply_DestroyWaitForTaskError_HardFails(t *testing.T) {
	client := baseDestroyClient()
	// First WaitForTask call is the stop step (succeeds); second is the
	// destroy step (fails).
	client.waitForTaskErrs = []error{nil, errors.New("task failed: unable to allocate storage")}
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected an error when the destroy step's WaitForTask fails")
	}
	if client.rawRequestCalls != 0 {
		t.Error("reverify must not run when the destroy task itself failed")
	}
}

// TestVMDestroy_Apply_ReverifyStillExists_HardFails is finding 2's own
// regression: destroy and its WaitForTask both report success, but the
// node-local reverify still finds the VM — this must be a hard Apply
// error, not silently accepted.
func TestVMDestroy_Apply_ReverifyStillExists_HardFails(t *testing.T) {
	client := baseDestroyClient()
	client.rawRequestSteps = []rawRequestStep{{result: json.RawMessage(`{"name":"still-here"}`)}}
	op := &VMDestroy{Client: client, VMID: 100}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error: destroy reported success but the vm still exists")
	}
}

// TestVMDestroy_Apply_ReverifyUnclassifiedError_HardFails is the mirror of
// TestVMDestroy_Read_UnrelatedError_Propagates, for the reverify step: an
// unclassified fetchVMConfig error must be a hard Apply failure, never
// silently accepted as "proven removed."
func TestVMDestroy_Apply_ReverifyUnclassifiedError_HardFails(t *testing.T) {
	client := baseDestroyClient()
	client.rawRequestSteps = []rawRequestStep{{err: errors.New("dial tcp: connection refused")}}
	op := &VMDestroy{Client: client, VMID: 100}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an unclassified reverify error to be a hard Apply failure")
	}
}

func TestVMDestroy_Apply_TagRecheck_SkippedWhenTagEmpty(t *testing.T) {
	client := baseDestroyClient()
	op := &VMDestroy{Client: client, VMID: 100}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.tagStillClaimedCalls != 0 {
		t.Error("expected TagStillClaimed to never be called when Tag is empty")
	}
}

func TestVMDestroy_Apply_TagRecheck_SetsWarningWhenStillClaimed(t *testing.T) {
	client := baseDestroyClient()
	client.tagStillClaimedResult = true
	op := &VMDestroy{Client: client, VMID: 100, Tag: "qng"}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !op.TagStillClaimedWarning {
		t.Error("expected TagStillClaimedWarning to be set")
	}
	if op.TagRecheckErr != nil {
		t.Errorf("expected no TagRecheckErr when the recheck itself succeeded, got: %v", op.TagRecheckErr)
	}
	if client.lastTagArg != "qng" || client.lastExcludeVMID != 100 {
		t.Errorf("expected TagStillClaimed(qng, exclude 100), got (%q, %d)", client.lastTagArg, client.lastExcludeVMID)
	}
}

// TestVMDestroy_Apply_TagRecheck_ErrorIsNonFatal_ButDistinguishable proves
// a TagStillClaimed failure never fails Apply (informational check only)
// AND is distinguishable from a clean "no stale claim found" result: a
// caller must be able to tell "the recheck ran and found nothing" apart
// from "the recheck itself never ran" instead of both silently reporting
// as the same clean, warning-free outcome.
func TestVMDestroy_Apply_TagRecheck_ErrorIsNonFatal_ButDistinguishable(t *testing.T) {
	client := baseDestroyClient()
	client.tagStillClaimedErr = errors.New("cluster resources unavailable")
	op := &VMDestroy{Client: client, VMID: 100, Tag: "qng"}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v (tag recheck failure must never fail Apply)", err)
	}
	if op.TagStillClaimedWarning {
		t.Error("expected no stale-claim warning when TagStillClaimed itself errored")
	}
	if op.TagRecheckErr == nil {
		t.Error("expected TagRecheckErr to be set when TagStillClaimed itself errored, so the recheck's unknown outcome isn't reported as a clean result")
	}
}

// --- via Run --------------------------------------------------------------

func destroyKey() lock.ObjectKey {
	return lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
}

// TestVMDestroy_ViaRun_AlreadyGone_SkipsApply proves the Satisfied no-op
// path: a vmid that's already gone never touches StopVM/DestroyVM at all.
func TestVMDestroy_ViaRun_AlreadyGone_SkipsApply(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:            "qa-pve-01",
		rawRequestSteps: []rawRequestStep{{err: errors.New(missingVMErrorText(100))}},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	res, err := Run(context.Background(), testRosterPath(t), destroyKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: the vm is already gone")
	}
	if client.stopVMCalls != 0 || client.destroyVMCalls != 0 {
		t.Error("StopVM/DestroyVM must not be called when the vm is already gone")
	}
}

// TestVMDestroy_ViaRun_UnrelatedReadError_FailsRun is the full-stack
// regression for finding 1: Run must surface a failed cycle, not a silent
// no-op, when Read hits an unclassified error.
func TestVMDestroy_ViaRun_UnrelatedReadError_FailsRun(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:            "qa-pve-01",
		rawRequestSteps: []rawRequestStep{{err: errors.New("dial tcp: connection refused")}},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	_, err := Run(context.Background(), testRosterPath(t), destroyKey(), op, false)
	if err == nil {
		t.Fatal("expected Run to fail on an unclassified Read error, not silently no-op")
	}
	if client.stopVMCalls != 0 || client.destroyVMCalls != 0 {
		t.Error("StopVM/DestroyVM must not be called when Read itself failed")
	}
}

// TestVMDestroy_ViaRun_FullCycle_AppliesAndConfirmsGone drives a full
// Read -> Satisfied(false) -> Apply -> best-effort Read cycle: the vm
// exists at first Read, Apply destroys it, and both the reverify and Run's
// own final Read see it as gone afterward.
func TestVMDestroy_ViaRun_FullCycle_AppliesAndConfirmsGone(t *testing.T) {
	client := &fakeVMDestroyClient{
		node:          "qa-pve-01",
		stopVMUPID:    "UPID:qa-pve-01:1:1:1:qmstop:100:root@pam:",
		destroyVMUPID: "UPID:qa-pve-01:2:2:2:qmdestroy:100:root@pam:",
		rawRequestSteps: []rawRequestStep{
			{result: json.RawMessage(`{"name":"test-vm"}`)}, // Read: exists
			{err: errors.New(missingVMErrorText(100))},      // Apply's reverify: gone
		},
	}
	op := &VMDestroy{Client: client, VMID: 100}

	res, err := Run(context.Background(), testRosterPath(t), destroyKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true: the vm existed and was destroyed")
	}
	if res.After != "" {
		t.Errorf("Result.After = %q, want empty (vm confirmed gone)", res.After)
	}
	if client.stopVMCalls != 1 || client.destroyVMCalls != 1 {
		t.Errorf("expected exactly one stop and one destroy, got stop=%d destroy=%d", client.stopVMCalls, client.destroyVMCalls)
	}
}
