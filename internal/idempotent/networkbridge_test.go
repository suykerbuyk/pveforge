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

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// getResponse is one scripted response to a GET on one interface path, used
// by fakeNetworkBridgeClient.getResponses.
type getResponse struct {
	missing bool
	fields  map[string]json.RawMessage
	err     error
}

// fakeNetworkBridgeClient is a scriptable NetworkBridgeClient, mirroring
// fakeBridgeClient's own "indexed by call number" shape (see
// bridgeisolation_fake_test.go) but keyed by interface name for the GET/
// LinkState calls (NetworkBridgeEnsure addresses those by iface, not call
// order) and by call-kind for the node-level stage/commit/revert calls.
//
// events records every call in order, across all methods, so tests can
// assert relative ORDERING (e.g. "WaitForTask strictly before the
// post-apply LinkState call") rather than merely "both were called".
type fakeNetworkBridgeClient struct {
	node string

	getResponses map[string][]getResponse
	getCalls     map[string]int

	stageErr        error
	stageCalls      int
	lastStageMethod string
	lastStageParams url.Values

	commitUPID  string
	commitErr   error
	commitCalls int

	revertErr   error
	revertCalls int

	waitForTaskErr   error
	waitForTaskCalls int

	linkStates map[string][]sshexec.LinkState
	linkErrs   map[string][]error
	linkCalls  map[string]int

	events []string
}

func newFakeNetworkBridgeClient(node string) *fakeNetworkBridgeClient {
	return &fakeNetworkBridgeClient{
		node:         node,
		getResponses: map[string][]getResponse{},
		getCalls:     map[string]int{},
		linkStates:   map[string][]sshexec.LinkState{},
		linkErrs:     map[string][]error{},
		linkCalls:    map[string]int{},
	}
}

func (f *fakeNetworkBridgeClient) Node() string { return f.node }

func (f *fakeNetworkBridgeClient) RawRequest(_ context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	f.events = append(f.events, fmt.Sprintf("rawrequest:%s:%s", method, path))
	base := fmt.Sprintf("/nodes/%s/network", f.node)

	switch {
	case method == http.MethodGet && strings.HasPrefix(path, base+"/"):
		iface := strings.TrimPrefix(path, base+"/")
		return f.handleGet(iface)

	case method == http.MethodDelete && path == base:
		// revert: whole-node, no iface.
		f.revertCalls++
		if f.revertErr != nil {
			return nil, f.revertErr
		}
		return json.RawMessage("null"), nil

	case method == http.MethodDelete && strings.HasPrefix(path, base+"/"):
		// stage: destroy targets iface specifically.
		f.stageCalls++
		f.lastStageMethod = method
		if f.stageErr != nil {
			return nil, f.stageErr
		}
		return json.RawMessage("null"), nil

	case method == http.MethodPost && path == base:
		// stage: create.
		f.stageCalls++
		f.lastStageMethod = method
		f.lastStageParams = params
		if f.stageErr != nil {
			return nil, f.stageErr
		}
		return json.RawMessage("null"), nil

	case method == http.MethodPut && path == base:
		// commit.
		f.commitCalls++
		if f.commitErr != nil {
			return nil, f.commitErr
		}
		b, err := json.Marshal(f.commitUPID)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(b), nil

	default:
		return nil, fmt.Errorf("fakeNetworkBridgeClient: unexpected RawRequest %s %s", method, path)
	}
}

func (f *fakeNetworkBridgeClient) handleGet(iface string) (json.RawMessage, error) {
	idx := f.getCalls[iface]
	f.getCalls[iface]++

	seq := f.getResponses[iface]
	var resp getResponse
	switch {
	case len(seq) == 0:
		resp = getResponse{missing: true}
	case idx < len(seq):
		resp = seq[idx]
	default:
		resp = seq[len(seq)-1]
	}

	if resp.err != nil {
		return nil, resp.err
	}
	if resp.missing {
		return nil, fmt.Errorf("raw request: pve returned 500 Internal Server Error: iface '%s' does not exist", iface)
	}
	b, err := json.Marshal(resp.fields)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func (f *fakeNetworkBridgeClient) LinkState(_ context.Context, iface string) (sshexec.LinkState, error) {
	f.events = append(f.events, "linkstate:"+iface)
	idx := f.linkCalls[iface]
	f.linkCalls[iface]++

	if errs, ok := f.linkErrs[iface]; ok {
		var e error
		switch {
		case idx < len(errs):
			e = errs[idx]
		case len(errs) > 0:
			e = errs[len(errs)-1]
		}
		if e != nil {
			return sshexec.LinkState{}, e
		}
	}

	states := f.linkStates[iface]
	if len(states) == 0 {
		return sshexec.LinkState{}, nil
	}
	if idx >= len(states) {
		idx = len(states) - 1
	}
	return states[idx], nil
}

func (f *fakeNetworkBridgeClient) WaitForTask(_ context.Context, _, _ string) error {
	f.events = append(f.events, "waitfortask")
	f.waitForTaskCalls++
	return f.waitForTaskErr
}

// eventIndex returns the index of the n-th (0-based) occurrence of event in
// f.events, or -1 if there aren't that many.
func (f *fakeNetworkBridgeClient) eventIndex(event string, n int) int {
	seen := 0
	for i, e := range f.events {
		if e == event {
			if seen == n {
				return i
			}
			seen++
		}
	}
	return -1
}

func rawField(v string) json.RawMessage {
	b, _ := json.Marshal(v)
	return json.RawMessage(b)
}

// --- Validate ---------------------------------------------------------

func TestNetworkBridgeEnsure_Validate(t *testing.T) {
	base := func() NetworkBridgeEnsure {
		return NetworkBridgeEnsure{Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
	}

	t.Run("missing node", func(t *testing.T) {
		op := base()
		op.Node = ""
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "node") {
			t.Fatalf("expected error naming node, got %v", err)
		}
	})

	t.Run("missing iface", func(t *testing.T) {
		op := base()
		op.Iface = ""
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "iface") {
			t.Fatalf("expected error naming iface, got %v", err)
		}
	})

	t.Run("missing management bridge", func(t *testing.T) {
		op := base()
		op.ManagementBridge = ""
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "management bridge") {
			t.Fatalf("expected error naming management bridge, got %v", err)
		}
	})

	t.Run("wanted contains iface key", func(t *testing.T) {
		op := base()
		op.Wanted = map[string]string{"iface": "vmbr99"}
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "iface") {
			t.Fatalf("expected error about Wanted containing iface key, got %v", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		op := base()
		if err := op.Validate(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

// --- Read / Satisfied ---------------------------------------------------

func TestNetworkBridgeEnsure_Read(t *testing.T) {
	t.Run("interface does not exist", func(t *testing.T) {
		client := newFakeNetworkBridgeClient("pve1")
		op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
		current, err := op.Read(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if current != "" {
			t.Fatalf("expected empty comparable state for missing iface, got %q", current)
		}
	})

	t.Run("interface exists", func(t *testing.T) {
		client := newFakeNetworkBridgeClient("pve1")
		client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"bridge_ports": rawField("eth0")}}}
		op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
		current, err := op.Read(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if current == "" {
			t.Fatalf("expected non-empty comparable state for existing iface")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(current), &fields); err != nil {
			t.Fatalf("expected valid json, got %q: %v", current, err)
		}
		if s, _ := fields["bridge_ports"]; string(s) != `"eth0"` {
			t.Fatalf("expected bridge_ports eth0, got %v", fields)
		}
	})
}

func TestNetworkBridgeEnsure_Satisfied(t *testing.T) {
	t.Run("does not exist, create wanted -> not satisfied", func(t *testing.T) {
		op := &NetworkBridgeEnsure{Wanted: map[string]string{"bridge_ports": "eth0"}}
		if op.Satisfied("") {
			t.Fatalf("expected not satisfied")
		}
	})

	t.Run("exists with matching fields, create wanted -> satisfied", func(t *testing.T) {
		op := &NetworkBridgeEnsure{Wanted: map[string]string{"bridge_ports": "eth0"}}
		current := `{"bridge_ports":"eth0","active":"1"}`
		if !op.Satisfied(current) {
			t.Fatalf("expected satisfied")
		}
	})

	t.Run("exists with mismatching field, create wanted -> not satisfied", func(t *testing.T) {
		op := &NetworkBridgeEnsure{Wanted: map[string]string{"bridge_ports": "eth0"}}
		current := `{"bridge_ports":"eth1"}`
		if op.Satisfied(current) {
			t.Fatalf("expected not satisfied")
		}
	})

	t.Run("exists, destroy wanted -> not satisfied", func(t *testing.T) {
		op := &NetworkBridgeEnsure{}
		current := `{"bridge_ports":"eth0"}`
		if op.Satisfied(current) {
			t.Fatalf("expected not satisfied")
		}
	})

	t.Run("does not exist, destroy wanted -> satisfied", func(t *testing.T) {
		op := &NetworkBridgeEnsure{}
		if !op.Satisfied("") {
			t.Fatalf("expected satisfied")
		}
	})
}

// --- Apply: helpers to build common scenario fields ---------------------

func mgmtFields(v string) map[string]json.RawMessage {
	return map[string]json.RawMessage{"bridge_ports": rawField(v), "digest": rawField("deadbeef")}
}

// --- (a) matching pre/pending management-bridge fields -> commit called, success.

func TestNetworkBridgeEnsure_Apply_CreateSucceeds(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}} // same both reads (index clamps to last)
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}             // guard: not yet live
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}} // same both reads
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: true}}
	client.commitUPID = "UPID:pve1:00000001:00000002:00000003:00000004:test:root@pam:"

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.commitCalls != 1 {
		t.Fatalf("expected commit called once, got %d", client.commitCalls)
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert, got %d", client.revertCalls)
	}
	if client.lastStageParams.Get("iface") != "vmbr99" {
		t.Fatalf("expected stage params to set iface=vmbr99, got %v", client.lastStageParams)
	}
	if client.lastStageParams.Get("bridge_ports") != "eth1" {
		t.Fatalf("expected stage params to carry bridge_ports=eth1, got %v", client.lastStageParams)
	}
}

// --- (b) a DIFFERENT pending management-bridge field -> commit never
// called, revert called, hard error naming the differing field.

func TestNetworkBridgeEnsure_Apply_StanzaChangedDuringStage_AbortsAndReverts(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{
		{fields: mgmtFields("eth0")},
		{fields: mgmtFields("eth9")}, // changed during the stage window
	}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "bridge_ports") {
		t.Fatalf("expected error naming the differing field bridge_ports, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert called once, got %d", client.revertCalls)
	}
}

// --- (c) kernel LinkState mismatch post-apply (step 7) -> hard error, no
// remediation attempted.

func TestNetworkBridgeEnsure_Apply_PostApplyManagementBridgeKernelMismatch(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}, {Exists: true, Up: false}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "vmbr0") || !strings.Contains(err.Error(), "no automatic remediation") {
		t.Fatalf("expected error naming vmbr0 and no-remediation, got %v", err)
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert attempted for a step-7 failure, got %d", client.revertCalls)
	}
	// step 8's LinkState(vmbr99) must never run once step 7 fails.
	if client.linkCalls["vmbr99"] != 1 {
		t.Fatalf("expected exactly one LinkState(vmbr99) call (guard only), got %d", client.linkCalls["vmbr99"])
	}
}

// --- (d) pre/pending reads byte-identical even across a real stage ->
// refuses to auto-commit via step 4's self-check, not step 5's hash
// compare.

func TestNetworkBridgeEnsure_Apply_ByteIdenticalStanzaStillGuardChecked(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}} // identical every read
	client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"active": rawField("1")}}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "active=true") {
		t.Fatalf("expected error naming the active=true guard signal (not a hash-mismatch message), got %v", err)
	}
	if strings.Contains(err.Error(), "staged config changed") {
		t.Fatalf("expected step 4 to catch this, not step 5's hash-compare message; got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert called once, got %d", client.revertCalls)
	}
}

// --- (e)-(g): WaitForTask ordering vs. the post-apply LinkState call.

func newHappyPathClient() *fakeNetworkBridgeClient {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: true}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"
	return client
}

func TestNetworkBridgeEnsure_Apply_WaitForTaskSucceeds_ThenRunsPostApplyCheck(t *testing.T) {
	client := newHappyPathClient()
	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	waitIdx := client.eventIndex("waitfortask", 0)
	postApplyMgmtLinkIdx := client.eventIndex("linkstate:vmbr0", 1) // 0 = preKernelState, 1 = post-apply
	if waitIdx == -1 || postApplyMgmtLinkIdx == -1 {
		t.Fatalf("expected both waitfortask and a second linkstate:vmbr0 call, got events: %v", client.events)
	}
	if !(waitIdx < postApplyMgmtLinkIdx) {
		t.Fatalf("expected WaitForTask (idx %d) strictly before the post-apply LinkState call (idx %d); events: %v", waitIdx, postApplyMgmtLinkIdx, client.events)
	}
}

func TestNetworkBridgeEnsure_Apply_WaitForTaskFails_TaskFailedError(t *testing.T) {
	client := newHappyPathClient()
	client.waitForTaskErr = &pve.TaskFailedError{UPID: client.commitUPID, ExitStatus: "ERROR"}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	var tfe *pve.TaskFailedError
	if !errors.As(err, &tfe) {
		t.Fatalf("expected error to wrap *pve.TaskFailedError, got %v", err)
	}
	if client.linkCalls["vmbr0"] != 1 {
		t.Fatalf("expected the post-apply LinkState(vmbr0) call to NEVER happen after a WaitForTask failure, got %d calls", client.linkCalls["vmbr0"])
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert attempted after commit's task already ran, got %d", client.revertCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_WaitForTaskFails_Timeout(t *testing.T) {
	client := newHappyPathClient()
	client.waitForTaskErr = fmt.Errorf("wait for task %s: %w", client.commitUPID, errors.New("timed out waiting for task to complete"))

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected underlying timeout error surfaced, got %v", err)
	}
	if client.linkCalls["vmbr0"] != 1 {
		t.Fatalf("expected the post-apply LinkState(vmbr0) call to NEVER happen after a WaitForTask timeout, got %d calls", client.linkCalls["vmbr0"])
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert attempted after commit's task already ran, got %d", client.revertCalls)
	}
}

// --- (h) create, both step-4 signals correctly show op.Iface not yet
// live -> proceeds to step 5 normally.

func TestNetworkBridgeEnsure_Apply_Create_GuardPasses_ProceedsNormally(t *testing.T) {
	client := newHappyPathClient()
	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.commitCalls != 1 || client.revertCalls != 0 {
		t.Fatalf("expected the guard to pass and apply to proceed to commit; commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
}

// --- (i) create, `active` already true post-stage -> commit never called,
// revert called, hard error naming the active signal, step 5 never runs.

func TestNetworkBridgeEnsure_Apply_Create_GuardActiveAlreadyTrue_Aborts(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{
		{fields: mgmtFields("eth0")},
		{fields: mgmtFields("eth9")}, // ALSO differs, to prove step 4 catches this before step 5 ever runs
	}
	client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"active": rawField("1")}}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "active=true") {
		t.Fatalf("expected error naming the active signal, got %v", err)
	}
	if strings.Contains(err.Error(), "staged config changed") {
		t.Fatalf("expected step 5's compare to never run; got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert called once, got %d", client.revertCalls)
	}
}

// --- (j) create, `LinkState.Exists` already true post-stage -> same abort
// behavior, error naming the kernel signal instead.

func TestNetworkBridgeEnsure_Apply_Create_GuardLinkExists_Aborts(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}} // active signal passes (absent -> falsy)
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}} // but kernel already shows it live

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "LinkState") || !strings.Contains(err.Error(), "Exists=true") {
		t.Fatalf("expected error naming the LinkState/Exists=true signal, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert called once, got %d", client.revertCalls)
	}
}

// --- (k) destroy, both step-4 signals correctly show op.Iface still live
// -> proceeds normally.

func TestNetworkBridgeEnsure_Apply_Destroy_GuardPasses_ProceedsNormally(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"active": rawField("1")}}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}, {Exists: false}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		// Wanted nil/empty means destroy.
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.commitCalls != 1 || client.revertCalls != 0 {
		t.Fatalf("expected the guard to pass and apply to proceed to commit; commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
}

// --- (l) destroy, either step-4 signal already shows op.Iface gone
// post-stage -> same abort behavior as (i)/(j).

func TestNetworkBridgeEnsure_Apply_Destroy_GuardActiveAlreadyFalse_Aborts(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}} // active reads as false
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}}

	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "active=false") {
		t.Fatalf("expected error naming the active=false signal, got %v", err)
	}
	if client.commitCalls != 0 || client.revertCalls != 1 {
		t.Fatalf("expected abort with revert; commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_Destroy_GuardLinkGone_Aborts(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"active": rawField("1")}}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}} // kernel already shows it gone

	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "LinkState") || !strings.Contains(err.Error(), "Exists=false") {
		t.Fatalf("expected error naming the LinkState/Exists=false signal, got %v", err)
	}
	if client.commitCalls != 0 || client.revertCalls != 1 {
		t.Fatalf("expected abort with revert; commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
}

// --- additional coverage: hard-error branches not covered by the named
// (a)-(l)/(e)-(g) scenarios above.

func TestNetworkBridgeEnsure_Apply_ManagementBridgeMissing_HardError(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{missing: true}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected hard error naming missing management bridge, got %v", err)
	}
	if client.stageCalls != 0 {
		t.Fatalf("expected stage never attempted, got %d", client.stageCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_ManagementBridgeVanishedDuringStage(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}, {missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "vanished") {
		t.Fatalf("expected hard error naming vanished management bridge, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_StageError_Propagates(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.stageErr = errors.New("pve rejected the staged create")

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pve rejected the staged create") {
		t.Fatalf("expected stage error to propagate, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_CommitError_Propagates(t *testing.T) {
	client := newHappyPathClient()
	client.commitErr = errors.New("pve rejected the commit")

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pve rejected the commit") {
		t.Fatalf("expected commit error to propagate, got %v", err)
	}
	if client.waitForTaskCalls != 0 {
		t.Fatalf("expected WaitForTask never called after a commit failure, got %d", client.waitForTaskCalls)
	}
}

func TestNetworkBridgeEnsure_Apply_Step8Mismatch_HardError(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	// Guard (call 0) shows not-yet-live, but post-apply (call 1) still
	// reports not existing, contradicting the intended create.
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: false}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "post-apply kernel state mismatch") {
		t.Fatalf("expected step 8 hard error, got %v", err)
	}
}

// TestNetworkBridgeEnsure_Apply_CommitReturnsEmptyUPID_HardError guards the
// extract-method refactor that turns commit into the free function
// commitNetworkStage (see networkfields.go's own doc comment on why that
// refactor happened): no other test in this file ever drives commit to
// return an empty UPID, so without this test the "commit returned no upid"
// guard could be deleted entirely and every other test here would still
// pass.
func TestNetworkBridgeEnsure_Apply_CommitReturnsEmptyUPID_HardError(t *testing.T) {
	client := newHappyPathClient()
	client.commitUPID = "" // explicit: this is the case under test, not relying on the zero value

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "commit returned no upid") {
		t.Fatalf("expected hard error naming the missing upid, got %v", err)
	}
	if client.waitForTaskCalls != 0 {
		t.Fatalf("expected WaitForTask never called after a commit-parse failure, got %d", client.waitForTaskCalls)
	}
}

// TestNetworkBridgeEnsure_Apply_GuardTripAndRevertBothFail_CombinedError
// guards the extract-method refactor that turns abortAndRevert into the
// free function revertNetworkStage: no other test in this file ever makes
// the revert call itself fail, so without this test the combined-error
// branch (which reports the revert failure instead of silently swallowing
// it) could be dropped entirely and every other test here would still
// pass.
func TestNetworkBridgeEnsure_Apply_GuardTripAndRevertBothFail_CombinedError(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{
		{fields: mgmtFields("eth0")},
		{fields: mgmtFields("eth9")}, // changed during the stage window -> guard trip
	}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}
	client.revertErr = errors.New("pve rejected the revert")

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "bridge_ports") {
		t.Fatalf("expected error to still name the original guard-trip reason (bridge_ports), got %v", err)
	}
	if !strings.Contains(err.Error(), "pve rejected the revert") {
		t.Fatalf("expected error to also name the revert failure, not silently swallow it, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert attempted once, got %d", client.revertCalls)
	}
}

func TestNetworkBridgeEnsure_Read_PropagatesHardError(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr99"] = []getResponse{{err: errors.New("connection reset")}}
	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0"}
	_, err := op.Read(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("expected hard error to propagate, got %v", err)
	}
}

// --- misc coverage: canonicalHash digest exclusion, networkLockKey.

func TestCanonicalHash_ExcludesDigest(t *testing.T) {
	withDigest := map[string]json.RawMessage{"bridge_ports": rawField("eth0"), "digest": rawField("aaa")}
	withDifferentDigest := map[string]json.RawMessage{"bridge_ports": rawField("eth0"), "digest": rawField("bbb")}

	h1, err := canonicalHash(withDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := canonicalHash(withDifferentDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected hash to ignore digest field, got %s vs %s", h1, h2)
	}

	withDifferentField := map[string]json.RawMessage{"bridge_ports": rawField("eth1"), "digest": rawField("aaa")}
	h3, err := canonicalHash(withDifferentField)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h3 {
		t.Fatalf("expected hash to change when a non-digest field changes")
	}
}

func TestNetworkLockKey_IsPerNodeNotPerIface(t *testing.T) {
	k := NetworkLockKey("qa-pve-01", "pve1")
	if k.Kind != "network" {
		t.Fatalf("expected kind %q, got %q", "network", k.Kind)
	}
	if k.ID != "pve1" {
		t.Fatalf("expected key id to be the node (not an iface name), got %q", k.ID)
	}
	if k.TargetID != "qa-pve-01" {
		t.Fatalf("expected target id passthrough, got %q", k.TargetID)
	}
}
