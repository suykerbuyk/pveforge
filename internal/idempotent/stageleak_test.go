package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Tests for pveforge-network-stage-leak-on-error: every failure after a
// successful stage must discard the staged change (the whole-node DELETE
// /nodes/{node}/network) before returning, or the pending interfaces.new is
// left on the node for whatever applies next to commit. Each test injects a
// sentinel at one post-stage failure path and asserts the revert was issued,
// nothing was committed, and the original error survives errors.Is.

var errStageLeakProbe = errors.New("stage-leak probe failure")

func newStageLeakBridgeOp(client *fakeNetworkBridgeClient) *NetworkBridgeEnsure {
	return &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
}

func requireRevertedNotCommitted(t *testing.T, revertCalls, commitCalls int) {
	t.Helper()
	if revertCalls != 1 {
		t.Errorf("expected the staged change to be reverted exactly once, got %d revert(s)", revertCalls)
	}
	if commitCalls != 0 {
		t.Errorf("expected no commit after a post-stage failure, got %d", commitCalls)
	}
}

// --- NetworkBridgeEnsure --------------------------------------------------

func TestNetworkBridgeEnsure_Apply_PostStageManagementReadError_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {err: errStageLeakProbe}}

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the post-stage read error to be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "post-stage snapshot of management bridge vmbr0") {
		t.Errorf("expected the existing error text, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_PostStageManagementNullRead_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {fields: nil}}

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead to survive the revert, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_ManagementBridgeVanishedDuringStage_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {missing: true}}

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if err == nil || !strings.Contains(err.Error(), "vanished") {
		t.Fatalf("expected the vanished-management-bridge error, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_GuardSelfCheckReadError_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.getResponses["vmbr99"] = []getResponse{{missing: true}, {err: errStageLeakProbe}} // pre-stage: absent; guard read fails

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the guard self-check read error to be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "guard self-check: read iface state") {
		t.Errorf("expected the existing error text, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_GuardSelfCheckLinkStateError_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.linkErrs["vmbr99"] = []error{errStageLeakProbe}

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the guard self-check link-state error to be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "guard self-check: read kernel link state") {
		t.Errorf("expected the existing error text, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_CommitError_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.commitErr = errStageLeakProbe

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	if client.revertCalls != 1 {
		t.Errorf("expected the staged change to be reverted after a failed commit, got %d revert(s)", client.revertCalls)
	}
	if client.waitForTaskCalls != 0 {
		t.Errorf("expected WaitForTask never called after a failed commit, got %d", client.waitForTaskCalls)
	}
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the commit error to be preserved, got %v", err)
	}
	// Exact text: the message may say only what is known. It must never
	// claim the change was "reverted" or "not applied" — a revert racing the
	// apply worker can land after the change is already live.
	const want = "network bridge ensure: vmbr99: commit failed, outcome unknown (the change may or may not have been applied): stage-leak probe failure"
	if err.Error() != want {
		t.Errorf("step-6 error text:\n got: %s\nwant: %s", err, want)
	}
}

func TestNetworkBridgeEnsure_Apply_CommitEmptyUPID_Reverts(t *testing.T) {
	client := newHappyPathClient()
	client.commitUPID = ""

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	if client.revertCalls != 1 {
		t.Errorf("expected the staged change to be reverted after a UPID-less commit, got %d revert(s)", client.revertCalls)
	}
	if client.waitForTaskCalls != 0 {
		t.Errorf("expected WaitForTask never called without a UPID, got %d", client.waitForTaskCalls)
	}
	if err == nil || !strings.Contains(err.Error(), "commit returned no upid") {
		t.Fatalf("expected the missing-UPID error, got %v", err)
	}
}

// When the revert itself also fails, the error must still carry the original
// cause (errors.Is) AND report that the staged change may still be pending.
func TestNetworkBridgeEnsure_Apply_PostStageErrorAndRevertBothFail_KeepsBoth(t *testing.T) {
	client := newHappyPathClient()
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {err: errStageLeakProbe}}
	client.revertErr = errors.New("revert refused")

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	if client.revertCalls != 1 {
		t.Errorf("expected one revert attempt, got %d", client.revertCalls)
	}
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the original cause to survive a failed revert, got %v", err)
	}
	if !strings.Contains(err.Error(), "reverting staged changes also failed: revert refused") {
		t.Fatalf("expected the revert failure to be reported, got %v", err)
	}
}

// --- NetworkFieldsEnsure --------------------------------------------------

func newStageLeakFieldsOp(client *fakeNetworkFieldsClient) *NetworkFieldsEnsure {
	return &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5",
		Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
}

func stageLeakHealthyList() listResponse {
	return listResponse{entries: []map[string]json.RawMessage{
		ifaceEntry("vmbr5", map[string]json.RawMessage{"mtu": rawField("1500")}),
		ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")}),
	}}
}

func TestNetworkFieldsEnsure_Apply_PostStageListError_Reverts(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList(), {err: errStageLeakProbe}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the post-stage list error to be preserved, got %v", err)
	}
	if !strings.Contains(err.Error(), "post-stage snapshot of other interfaces") {
		t.Errorf("expected the existing error text, got %v", err)
	}
}

func TestNetworkFieldsEnsure_Apply_PostStageNullList_Reverts(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList(), {entries: nil}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	requireRevertedNotCommitted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, pve.ErrUnverifiableRead) {
		t.Fatalf("expected ErrUnverifiableRead to survive the revert, got %v", err)
	}
}

func TestNetworkFieldsEnsure_Apply_CommitError_Reverts(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList()}
	client.commitErr = errStageLeakProbe

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	if client.revertCalls != 1 {
		t.Errorf("expected the staged change to be reverted after a failed commit, got %d revert(s)", client.revertCalls)
	}
	if client.waitForTaskCalls != 0 {
		t.Errorf("expected WaitForTask never called after a failed commit, got %d", client.waitForTaskCalls)
	}
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the commit error to be preserved, got %v", err)
	}
	const want = "network fields ensure: vmbr5: commit failed, outcome unknown (the change may or may not have been applied): stage-leak probe failure"
	if err.Error() != want {
		t.Errorf("step-6 error text:\n got: %s\nwant: %s", err, want)
	}
}

func TestNetworkFieldsEnsure_Apply_CommitEmptyUPID_Reverts(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList()}
	client.commitUPID = ""

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	if client.revertCalls != 1 {
		t.Errorf("expected the staged change to be reverted after a UPID-less commit, got %d revert(s)", client.revertCalls)
	}
	if err == nil || !strings.Contains(err.Error(), "commit returned no upid") {
		t.Fatalf("expected the missing-UPID error, got %v", err)
	}
}

// --- The paths that must NOT revert (pinned rulings) ----------------------

// A failed stage must not revert. The revert discards every staged change on
// the node, and when our own stage failed, what is pending most likely
// belongs to someone else. Without this pin, "helpfully" adding a revert
// here would pass every other test in the package.
func TestNetworkBridgeEnsure_Apply_StageError_DoesNotRevert(t *testing.T) {
	client := newHappyPathClient()
	client.stageErr = errStageLeakProbe

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	if client.revertCalls != 0 {
		t.Errorf("a failed stage must not trigger the whole-node revert, got %d", client.revertCalls)
	}
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the stage error, got %v", err)
	}
}

func TestNetworkFieldsEnsure_Apply_StageError_DoesNotRevert(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList()}
	client.stageErr = errStageLeakProbe

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	if client.revertCalls != 0 {
		t.Errorf("a failed stage must not trigger the whole-node revert, got %d", client.revertCalls)
	}
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the stage error, got %v", err)
	}
}

// After the commit has consumed our stage, anything still pending on the node
// belongs to someone else, and the revert is a whole-node discard. So no
// post-commit failure may revert. These pin the four post-commit returns the
// WaitForTask tests do not cover.

func requireCommittedNotReverted(t *testing.T, revertCalls, commitCalls int) {
	t.Helper()
	if commitCalls != 1 {
		t.Errorf("expected the commit to have run, got %d", commitCalls)
	}
	if revertCalls != 0 {
		t.Errorf("a post-commit failure must not revert (it would discard someone else's staged work), got %d", revertCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_PostCommitManagementLinkStateError_DoesNotRevert(t *testing.T) {
	client := newHappyPathClient()
	client.linkErrs["vmbr0"] = []error{nil, errStageLeakProbe} // call 0: pre-stage; call 1: step 7

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireCommittedNotReverted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the step-7 link-state error, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_PostCommitIfaceLinkStateError_DoesNotRevert(t *testing.T) {
	client := newHappyPathClient()
	client.linkErrs["vmbr99"] = []error{nil, errStageLeakProbe} // call 0: guard self-check; call 1: step 8

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireCommittedNotReverted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the step-8 link-state error, got %v", err)
	}
}

func TestNetworkBridgeEnsure_Apply_PostCommitIfaceExistsMismatch_DoesNotRevert(t *testing.T) {
	client := newHappyPathClient()
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: false}} // create, but never appears

	err := newStageLeakBridgeOp(client).Apply(context.Background())
	requireCommittedNotReverted(t, client.revertCalls, client.commitCalls)
	if err == nil || !strings.Contains(err.Error(), "post-apply kernel state mismatch") {
		t.Fatalf("expected the step-8 mismatch, got %v", err)
	}
}

func TestNetworkFieldsEnsure_Apply_PostCommitLinkStateError_DoesNotRevert(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{stageLeakHealthyList()}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"
	client.linkErrs = []error{errStageLeakProbe} // the only LinkState call: post-apply

	err := newStageLeakFieldsOp(client).Apply(context.Background())
	requireCommittedNotReverted(t, client.revertCalls, client.commitCalls)
	if !errors.Is(err, errStageLeakProbe) {
		t.Fatalf("expected the post-apply link-state error, got %v", err)
	}
}

// cancellingBridgeClient behaves as a real HTTP client does: a request made
// on a context that is already done fails without ever reaching PVE. It
// cancels the Op's context during the post-stage read of the management
// bridge, the moment a caller's deadline or signal would.
type cancellingBridgeClient struct {
	*fakeNetworkBridgeClient
	cancel   context.CancelFunc
	mgmtGets int
}

func (c *cancellingBridgeClient) RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if method == http.MethodGet && strings.HasSuffix(path, "/network/vmbr0") {
		c.mgmtGets++
		if c.mgmtGets == 2 {
			c.cancel()
			return nil, context.Canceled
		}
	}
	return c.fakeNetworkBridgeClient.RawRequest(ctx, method, path, params)
}

// A cancelled caller context is exactly when a half-done Apply most needs to
// clean up. The revert must still reach PVE, or the stage is left pending.
func TestNetworkBridgeEnsure_Apply_CancelledContext_RevertStillReachesPVE(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newHappyPathClient()
	op := newStageLeakBridgeOp(fake)
	op.Client = &cancellingBridgeClient{fakeNetworkBridgeClient: fake, cancel: cancel}

	err := op.Apply(ctx)
	if fake.revertCalls != 1 {
		t.Errorf("the revert must reach PVE even though the caller's context was cancelled, got %d", fake.revertCalls)
	}
	if fake.commitCalls != 0 {
		t.Errorf("expected no commit, got %d", fake.commitCalls)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the cancellation to be the reported cause, got %v", err)
	}
}

// revertCtxCapturingClient records the context the revert DELETE is issued
// on, so the test can inspect what the revert actually runs under.
type revertCtxCapturingClient struct {
	*fakeNetworkBridgeClient
	revertCtx context.Context
}

func (c *revertCtxCapturingClient) RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	if method == http.MethodDelete && strings.HasSuffix(path, "/network") {
		c.revertCtx = ctx
	}
	return c.fakeNetworkBridgeClient.RawRequest(ctx, method, path, params)
}

type revertCtxKey struct{}

// The revert runs detached from the caller's cancellation, but it must stay
// bounded (a hung PVE must not hold the caller forever) and must keep the
// caller's context values. The bound is asserted against a literal 30s, not
// against revertTimeout, so that raising the constant cannot pass unnoticed.
func TestNetworkBridgeEnsure_Apply_RevertContextIsBoundedAndKeepsCallerValues(t *testing.T) {
	fake := newHappyPathClient()
	fake.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {err: errStageLeakProbe}}
	capture := &revertCtxCapturingClient{fakeNetworkBridgeClient: fake}
	op := newStageLeakBridgeOp(fake)
	op.Client = capture
	ctx := context.WithValue(context.Background(), revertCtxKey{}, "caller-marker")

	before := time.Now()
	_ = op.Apply(ctx)
	after := time.Now()
	if capture.revertCtx == nil {
		t.Fatal("expected a revert DELETE to be issued")
	}
	deadline, ok := capture.revertCtx.Deadline()
	if !ok {
		t.Fatal("the revert must run under a deadline, or a hung PVE holds the caller forever")
	}
	// The revert ran somewhere between before and after, so its deadline
	// must fall after before and no later than 30s past after.
	if !deadline.After(before) || deadline.After(after.Add(30*time.Second)) {
		t.Errorf("revert deadline must be at most 30s after the revert, got %v past the call", deadline.Sub(before))
	}
	if got := capture.revertCtx.Value(revertCtxKey{}); got != "caller-marker" {
		t.Errorf("the revert must keep the caller's context values, got %v", got)
	}
}
