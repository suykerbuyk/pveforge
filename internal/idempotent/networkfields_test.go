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

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// listResponse is one scripted response to the raw LIST GET
// (/nodes/{node}/network, no iface segment), used by
// fakeNetworkFieldsClient.listResponses — sequential across calls (index 0
// = pre-stage snapshot, index 1 = post-stage snapshot), clamping to the
// last entry once exhausted, same "indexed by call number" convention
// fakeNetworkBridgeClient uses for its own per-iface sequences.
type listResponse struct {
	entries []map[string]json.RawMessage
	err     error
}

// fakeNetworkFieldsClient is a scriptable NetworkFieldsClient. Reuses
// getResponse and rawField from networkbridge_test.go (same package) for
// op.Iface's own single-interface GET (fetchInterface), and adds
// listResponses for the "every other interface" guard's raw LIST GET
// (fetchAllInterfaces) that NetworkBridgeEnsure never needed.
type fakeNetworkFieldsClient struct {
	node string

	getResponses map[string][]getResponse
	getCalls     map[string]int

	listResponses []listResponse
	listCalls     int

	stageErr        error
	stageCalls      int
	lastStageParams url.Values

	commitUPID  string
	commitErr   error
	commitCalls int

	revertErr   error
	revertCalls int

	waitForTaskErr   error
	waitForTaskCalls int

	linkStates []sshexec.LinkState
	linkErrs   []error
	linkCalls  int
}

func newFakeNetworkFieldsClient(node string) *fakeNetworkFieldsClient {
	return &fakeNetworkFieldsClient{
		node:         node,
		getResponses: map[string][]getResponse{},
		getCalls:     map[string]int{},
	}
}

func (f *fakeNetworkFieldsClient) Node() string { return f.node }

func (f *fakeNetworkFieldsClient) RawRequest(_ context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	base := fmt.Sprintf("/nodes/%s/network", f.node)

	switch {
	case method == http.MethodGet && path == base:
		return f.handleList()

	case method == http.MethodGet && strings.HasPrefix(path, base+"/"):
		iface := strings.TrimPrefix(path, base+"/")
		return f.handleGet(iface)

	case method == http.MethodPut && strings.HasPrefix(path, base+"/"):
		// stage
		f.stageCalls++
		f.lastStageParams = params
		if f.stageErr != nil {
			return nil, f.stageErr
		}
		return json.RawMessage("null"), nil

	case method == http.MethodPut && path == base:
		// commit
		f.commitCalls++
		if f.commitErr != nil {
			return nil, f.commitErr
		}
		b, err := json.Marshal(f.commitUPID)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(b), nil

	case method == http.MethodDelete && path == base:
		// revert
		f.revertCalls++
		if f.revertErr != nil {
			return nil, f.revertErr
		}
		return json.RawMessage("null"), nil

	default:
		return nil, fmt.Errorf("fakeNetworkFieldsClient: unexpected RawRequest %s %s", method, path)
	}
}

func (f *fakeNetworkFieldsClient) handleList() (json.RawMessage, error) {
	idx := f.listCalls
	f.listCalls++

	var resp listResponse
	switch {
	case len(f.listResponses) == 0:
		resp = listResponse{entries: []map[string]json.RawMessage{}}
	case idx < len(f.listResponses):
		resp = f.listResponses[idx]
	default:
		resp = f.listResponses[len(f.listResponses)-1]
	}

	if resp.err != nil {
		return nil, resp.err
	}
	b, err := json.Marshal(resp.entries)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func (f *fakeNetworkFieldsClient) handleGet(iface string) (json.RawMessage, error) {
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
		return nil, pveAnswer(fmt.Sprintf("raw request: pve returned 500 Internal Server Error: iface '%s' does not exist", iface))
	}
	b, err := json.Marshal(resp.fields)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func (f *fakeNetworkFieldsClient) LinkState(_ context.Context, _ string) (sshexec.LinkState, error) {
	idx := f.linkCalls
	f.linkCalls++
	if idx < len(f.linkErrs) && f.linkErrs[idx] != nil {
		return sshexec.LinkState{}, f.linkErrs[idx]
	}
	if len(f.linkStates) == 0 {
		return sshexec.LinkState{}, nil
	}
	if idx >= len(f.linkStates) {
		idx = len(f.linkStates) - 1
	}
	return f.linkStates[idx], nil
}

func (f *fakeNetworkFieldsClient) WaitForTask(_ context.Context, _, _ string) error {
	f.waitForTaskCalls++
	return f.waitForTaskErr
}

// ifaceEntry builds one raw LIST-endpoint entry, injecting iface's own name
// under the "iface" key the way fetchAllInterfaces expects to index by.
func ifaceEntry(iface string, fields map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(fields)+1)
	for k, v := range fields {
		out[k] = v
	}
	out["iface"] = rawField(iface)
	// Every interface in PVE's list carries its type; NetworkFieldsEnsure's
	// stage sends the target's, so a fixture without one is unrealistic.
	if _, ok := out["type"]; !ok {
		out["type"] = rawField("bridge")
	}
	return out
}

func rawBool(b bool) json.RawMessage {
	if b {
		return json.RawMessage("true")
	}
	return json.RawMessage("false")
}

// --- Validate -------------------------------------------------------------

func TestNetworkFieldsEnsure_Validate(t *testing.T) {
	base := func() NetworkFieldsEnsure {
		return NetworkFieldsEnsure{Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	}

	t.Run("missing node", func(t *testing.T) {
		op := base()
		op.Node = ""
		if err := op.Validate(); err == nil || !strings.Contains(err.Error(), "node") {
			t.Fatalf("expected error naming node, got %v", err)
		}
	})

	t.Run("missing iface", func(t *testing.T) {
		op := base()
		op.Iface = ""
		if err := op.Validate(); err == nil || !strings.Contains(err.Error(), "iface") {
			t.Fatalf("expected error naming iface, got %v", err)
		}
	})

	t.Run("no pairs", func(t *testing.T) {
		op := base()
		op.Pairs = nil
		if err := op.Validate(); err == nil || !strings.Contains(err.Error(), "at least one field") {
			t.Fatalf("expected error requiring at least one field, got %v", err)
		}
	})

	t.Run("duplicate field", func(t *testing.T) {
		op := base()
		op.Pairs = []kvjson.Pair{{Field: "mtu", Value: "9000"}, {Field: "mtu", Value: "1500"}}
		if err := op.Validate(); err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("expected error naming the duplicate field, got %v", err)
		}
	})

	t.Run("valid", func(t *testing.T) {
		op := base()
		if err := op.Validate(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}

// --- Read -------------------------------------------------------------

func TestNetworkFieldsEnsure_Read(t *testing.T) {
	t.Run("interface does not exist -> hard error", func(t *testing.T) {
		client := newFakeNetworkFieldsClient("pve1")
		op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		_, err := op.Read(context.Background())
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected hard error naming missing interface, got %v", err)
		}
	})

	t.Run("interface exists, field present", func(t *testing.T) {
		client := newFakeNetworkFieldsClient("pve1")
		client.getResponses["vmbr5"] = []getResponse{{fields: map[string]json.RawMessage{"mtu": rawField("1500")}}}
		op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		current, err := op.Read(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var state networkFieldsState
		if err := json.Unmarshal([]byte(current), &state); err != nil {
			t.Fatalf("expected valid json, got %q: %v", current, err)
		}
		if state.Current["mtu"] != "1500" {
			t.Fatalf("expected current mtu=1500, got %v", state.Current)
		}
	})

	t.Run("interface exists, requested field absent from config", func(t *testing.T) {
		client := newFakeNetworkFieldsClient("pve1")
		client.getResponses["vmbr5"] = []getResponse{{fields: map[string]json.RawMessage{"bridge_ports": rawField("eth0")}}}
		op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		current, err := op.Read(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var state networkFieldsState
		if err := json.Unmarshal([]byte(current), &state); err != nil {
			t.Fatalf("expected valid json, got %q: %v", current, err)
		}
		if _, ok := state.Current["mtu"]; ok {
			t.Fatalf("expected mtu absent from current, got %v", state.Current)
		}
	})
}

// --- Satisfied --------------------------------------------------------

func TestNetworkFieldsEnsure_Satisfied(t *testing.T) {
	t.Run("exact match -> satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		if !op.Satisfied(`{"current":{"mtu":"9000"}}`) {
			t.Fatalf("expected satisfied")
		}
	})

	t.Run("mismatch -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		if op.Satisfied(`{"current":{"mtu":"1500"}}`) {
			t.Fatalf("expected not satisfied")
		}
	})

	t.Run("field absent from current -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		if op.Satisfied(`{"current":{}}`) {
			t.Fatalf("expected not satisfied")
		}
	})

	t.Run("corrupted input -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
		if op.Satisfied("not json") {
			t.Fatalf("expected not satisfied for corrupted input")
		}
	})

	t.Run("vlan_filtering: current bool-true text vs wanted PVE-CLI 1 -> satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "1"}}}
		if !op.Satisfied(`{"current":{"vlan_filtering":"true"}}`) {
			t.Fatalf("expected satisfied via boolean-aware compare")
		}
	})

	t.Run("vlan_filtering: current bool-false text vs wanted PVE-CLI 0 -> satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "0"}}}
		if !op.Satisfied(`{"current":{"vlan_filtering":"false"}}`) {
			t.Fatalf("expected satisfied via boolean-aware compare")
		}
	})

	t.Run("vlan_filtering: current true vs wanted 0 -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "0"}}}
		if op.Satisfied(`{"current":{"vlan_filtering":"true"}}`) {
			t.Fatalf("expected not satisfied: true != 0")
		}
	})

	// Required addition (Chair review): the empty-string case must land on
	// the safe side — a field genuinely present-but-set-to-"" must never be
	// treated as boolean-false-shaped, so it falls through to an exact
	// compare against "false"/"0" and correctly does NOT match.
	t.Run("current empty string vs wanted false/0 -> not satisfied (safe side)", func(t *testing.T) {
		opFalse := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "false"}}}
		if opFalse.Satisfied(`{"current":{"vlan_filtering":""}}`) {
			t.Fatalf("expected not satisfied: empty string must not match \"false\"")
		}
		opZero := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "0"}}}
		if opZero.Satisfied(`{"current":{"vlan_filtering":""}}`) {
			t.Fatalf("expected not satisfied: empty string must not match \"0\"")
		}
	})

	// Required addition (Chair review): every OTHER test in this suite
	// exercises Satisfied/Apply with exactly one Pairs entry, despite
	// `network set` explicitly supporting several — this is the only test
	// that would catch a regression where Satisfied stops checking every
	// field in the batch (e.g. only checking Pairs[0]). Two sub-cases: the
	// FIRST field already matches but the SECOND doesn't (proves Satisfied
	// doesn't stop at the first match), and the reverse (first mismatches,
	// second matches — proves it doesn't stop at the first check either).
	t.Run("multi-field: first matches, second mismatches -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{
			{Field: "mtu", Value: "9000"},
			{Field: "vlan_filtering", Value: "1"},
		}}
		if op.Satisfied(`{"current":{"mtu":"9000","vlan_filtering":"false"}}`) {
			t.Fatalf("expected not satisfied: the second field (vlan_filtering) doesn't match")
		}
	})

	t.Run("multi-field: first mismatches, second matches -> not satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{
			{Field: "mtu", Value: "9000"},
			{Field: "vlan_filtering", Value: "1"},
		}}
		if op.Satisfied(`{"current":{"mtu":"1500","vlan_filtering":"true"}}`) {
			t.Fatalf("expected not satisfied: the first field (mtu) doesn't match")
		}
	})

	t.Run("multi-field: both match -> satisfied", func(t *testing.T) {
		op := &NetworkFieldsEnsure{Pairs: []kvjson.Pair{
			{Field: "mtu", Value: "9000"},
			{Field: "vlan_filtering", Value: "1"},
		}}
		if !op.Satisfied(`{"current":{"mtu":"9000","vlan_filtering":"true"}}`) {
			t.Fatalf("expected satisfied: both fields match")
		}
	})
}

// fieldsEqual/parseBoolish's own direct coverage (TestFieldsEqual) moved to
// boolish_test.go as of the 2026-09-16 extraction (pveforge-vm-converge-fields)
// that made the helper shared with VMFieldsEnsure — see boolish.go.

// TestNetworkFieldsEnsure_ReadThenSatisfied_VLANFilteringBooleanCoercion is
// the end-to-end version of TestFieldsEqual's cases (boolish_test.go): PVE's
// raw JSON boolean true, coerced by kvjson.Scalar (via Read) into the literal
// text "true", must still converge against a caller-supplied
// PVE-CLI-conventional "1" once it reaches Satisfied — this is the exact
// scenario the Chair's review required a fix for (see fieldsEqual's own doc
// comment in boolish.go).
func TestNetworkFieldsEnsure_ReadThenSatisfied_VLANFilteringBooleanCoercion(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.getResponses["vmbr5"] = []getResponse{{fields: map[string]json.RawMessage{"vlan_filtering": rawBool(true)}}}
	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "vlan_filtering", Value: "1"}}}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !op.Satisfied(current) {
		t.Fatalf("expected satisfied: PVE JSON bool true should converge with caller-supplied \"1\"")
	}
}

// --- the stage carries the interface's CURRENT type --------------------

// TestNetworkFieldsEnsure_Apply_StageSendsTheInterfacesCurrentType: PVE
// requires type on PUT /nodes/{node}/network/{iface}, matching the existing
// interface's type. The stage sends exactly the requested fields plus the
// target's type as listed, for a bridge and for non-bridge interfaces alike —
// so a stage that hard-coded "bridge" fails every non-bridge row.
func TestNetworkFieldsEnsure_Apply_StageSendsTheInterfacesCurrentType(t *testing.T) {
	for _, typ := range []string{"bridge", "OVSBridge", "eth", "vlan"} {
		t.Run(typ, func(t *testing.T) {
			client := newFakeNetworkFieldsClient("pve1")
			target := func(mtu string) map[string]json.RawMessage {
				return ifaceEntry("eno5", map[string]json.RawMessage{"type": rawField(typ), "mtu": rawField(mtu)})
			}
			client.listResponses = []listResponse{
				{entries: []map[string]json.RawMessage{target("1500"), ifaceEntry("vmbr0", nil)}},
				{entries: []map[string]json.RawMessage{target("9000"), ifaceEntry("vmbr0", nil)}},
			}
			client.linkStates = []sshexec.LinkState{{Exists: true, Up: true}}
			client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

			op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "eno5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
			if err := op.Apply(context.Background()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			want := url.Values{"mtu": {"9000"}, "type": {typ}}.Encode()
			if got := client.lastStageParams.Encode(); got != want {
				t.Errorf("stage params = %q, want exactly %q", got, want)
			}
		})
	}
}

// TestNetworkFieldsEnsure_Apply_UnknownTypeRefusesBeforeStaging: without the
// target's current type the stage cannot be sent, and guessing one would be
// a type change — so Apply refuses before staging anything (nothing to
// revert, no commit).
func TestNetworkFieldsEnsure_Apply_UnknownTypeRefusesBeforeStaging(t *testing.T) {
	for name, target := range map[string]map[string]json.RawMessage{
		"target not listed": nil,
		"no type":           {"iface": rawField("vmbr5"), "mtu": rawField("1500")},
		"empty type":        {"iface": rawField("vmbr5"), "type": rawField("")},
		"null type":         {"iface": rawField("vmbr5"), "type": json.RawMessage("null")},
	} {
		t.Run(name, func(t *testing.T) {
			client := newFakeNetworkFieldsClient("pve1")
			entries := []map[string]json.RawMessage{ifaceEntry("vmbr0", nil)}
			if target != nil {
				entries = append(entries, target)
			}
			client.listResponses = []listResponse{{entries: entries}}
			op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
			err := op.Apply(context.Background())
			if err == nil || !strings.Contains(err.Error(), "refusing to stage") {
				t.Fatalf("Apply err = %v, want a refusal to stage", err)
			}
			if client.lastStageParams != nil || client.commitCalls != 0 || client.revertCalls != 0 {
				t.Errorf("staged=%v commits=%d reverts=%d, want nothing sent", client.lastStageParams, client.commitCalls, client.revertCalls)
			}
		})
	}
}

// TestNetworkFieldsEnsure_Validate_RefusesType: the stage sends the current
// type itself, so a caller-supplied type is refused rather than sent.
func TestNetworkFieldsEnsure_Validate_RefusesType(t *testing.T) {
	op := &NetworkFieldsEnsure{Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}, {Field: "type", Value: "OVSBridge"}}}
	if err := op.Validate(); err == nil || !strings.Contains(err.Error(), `"type" cannot be set`) {
		t.Fatalf("Validate = %v, want a refusal of the type field", err)
	}
}

// --- Apply: (a) matching before/after other-interface hashes -> commits ---

func TestNetworkFieldsEnsure_Apply_MTUSet_OtherInterfacesUnchanged_Commits(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{
		{entries: []map[string]json.RawMessage{
			ifaceEntry("vmbr5", map[string]json.RawMessage{"mtu": rawField("1500")}),
			ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")}),
			ifaceEntry("vmbr1", map[string]json.RawMessage{"bridge_ports": rawField("eth1")}),
		}},
		// second (post-stage) call: vmbr5 (the target) changed, vmbr0/vmbr1 identical.
		{entries: []map[string]json.RawMessage{
			ifaceEntry("vmbr5", map[string]json.RawMessage{"mtu": rawField("9000")}),
			ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")}),
			ifaceEntry("vmbr1", map[string]json.RawMessage{"bridge_ports": rawField("eth1")}),
		}},
	}
	client.linkStates = []sshexec.LinkState{{Exists: true, Up: true}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := &NetworkFieldsEnsure{
		Client: client, Node: "pve1", Iface: "vmbr5",
		Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}},
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
	if client.lastStageParams.Get("mtu") != "9000" {
		t.Fatalf("expected stage params to carry mtu=9000, got %v", client.lastStageParams)
	}
	if client.waitForTaskCalls != 1 {
		t.Fatalf("expected WaitForTask called once, got %d", client.waitForTaskCalls)
	}
	if len(op.Applied) != 1 || op.Applied[0] != "mtu" {
		t.Fatalf("expected Applied=[mtu], got %v", op.Applied)
	}
}

// --- Apply: (b) a DECOY other interface mutated during the stage window ->
// refused + reverted, error names which OTHER interface changed.

func TestNetworkFieldsEnsure_Apply_DecoyInterfaceChangedDuringStage_AbortsAndReverts(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{
		{entries: []map[string]json.RawMessage{
			ifaceEntry("vmbr5", map[string]json.RawMessage{"mtu": rawField("1500")}),
			ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")}),
		}},
		{entries: []map[string]json.RawMessage{
			ifaceEntry("vmbr5", map[string]json.RawMessage{"mtu": rawField("9000")}),
			ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth9")}), // decoy changed
		}},
	}

	op := &NetworkFieldsEnsure{
		Client: client, Node: "pve1", Iface: "vmbr5",
		Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}},
	}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "vmbr0") {
		t.Fatalf("expected error to name the changed OTHER interface vmbr0, got %v", err)
	}
	if !strings.Contains(err.Error(), "bridge_ports") {
		t.Fatalf("expected error to name the changed field bridge_ports, got %v", err)
	}
	if strings.Contains(err.Error(), "vmbr5") && !strings.Contains(err.Error(), "network fields ensure: vmbr5") {
		t.Fatalf("expected the error not to blame the target interface vmbr5 itself for the guard trip, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
	if client.revertCalls != 1 {
		t.Fatalf("expected revert called once, got %d", client.revertCalls)
	}
}

// --- Additional hard-error / propagation coverage -----------------------

func TestNetworkFieldsEnsure_Apply_PreStageListError_Propagates(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{err: errors.New("connection reset")}}

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("expected list error to propagate, got %v", err)
	}
	if client.stageCalls != 0 {
		t.Fatalf("expected stage never attempted, got %d", client.stageCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_StageError_Propagates(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", nil), ifaceEntry("vmbr0", nil)}}}
	client.stageErr = errors.New("pve rejected the staged update")

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pve rejected the staged update") {
		t.Fatalf("expected stage error to propagate, got %v", err)
	}
	if client.commitCalls != 0 {
		t.Fatalf("expected commit never called, got %d", client.commitCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_CommitError_Propagates(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", nil), ifaceEntry("vmbr0", nil)}}}
	client.commitErr = errors.New("pve rejected the commit")

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pve rejected the commit") {
		t.Fatalf("expected commit error to propagate, got %v", err)
	}
	if client.waitForTaskCalls != 0 {
		t.Fatalf("expected WaitForTask never called after a commit failure, got %d", client.waitForTaskCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_CommitReturnsEmptyUPID_HardError(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", nil), ifaceEntry("vmbr0", nil)}}}
	client.commitUPID = ""

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "commit returned no upid") {
		t.Fatalf("expected hard error naming the missing upid, got %v", err)
	}
	if client.waitForTaskCalls != 0 {
		t.Fatalf("expected WaitForTask never called, got %d", client.waitForTaskCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_WaitForTaskFails_Propagates(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", nil), ifaceEntry("vmbr0", nil)}}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"
	client.waitForTaskErr = errors.New("timed out waiting for task to complete")

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected wait-for-task error to propagate, got %v", err)
	}
	if client.linkCalls != 0 {
		t.Fatalf("expected post-apply LinkState never called after a WaitForTask failure, got %d", client.linkCalls)
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert attempted after commit's task already ran, got %d", client.revertCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_PostApplyLinkStateGone_HardError(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{ifaceEntry("vmbr5", nil), ifaceEntry("vmbr0", nil)}}}
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"
	client.linkStates = []sshexec.LinkState{{Exists: false}}

	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5", Pairs: []kvjson.Pair{{Field: "mtu", Value: "9000"}}}
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no longer exists after apply") {
		t.Fatalf("expected post-apply kernel state hard error, got %v", err)
	}
	if client.revertCalls != 0 {
		t.Fatalf("expected no revert attempted for a post-commit failure, got %d", client.revertCalls)
	}
}

func TestNetworkFieldsEnsure_Apply_ValidateError_PropagatesBeforeAnyCall(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	op := &NetworkFieldsEnsure{Client: client, Node: "pve1", Iface: "vmbr5"} // no Pairs
	err := op.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "at least one field") {
		t.Fatalf("expected Validate error, got %v", err)
	}
	if client.listCalls != 0 {
		t.Fatalf("expected no calls at all before Validate, got %d list calls", client.listCalls)
	}
}

// --- fetchAllInterfaces direct coverage ---------------------------------

func TestFetchAllInterfaces_MissingIfaceField_Error(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{
		{"bridge_ports": rawField("eth0")}, // no "iface" key
	}}}
	_, err := fetchAllInterfaces(context.Background(), client, "pve1")
	if err == nil || !strings.Contains(err.Error(), `"iface"`) {
		t.Fatalf("expected error naming the missing iface field, got %v", err)
	}
}

func TestFetchAllInterfaces_IndexesByIfaceKey(t *testing.T) {
	client := newFakeNetworkFieldsClient("pve1")
	client.listResponses = []listResponse{{entries: []map[string]json.RawMessage{
		ifaceEntry("vmbr0", map[string]json.RawMessage{"bridge_ports": rawField("eth0")}),
		ifaceEntry("vmbr1", map[string]json.RawMessage{"bridge_ports": rawField("eth1")}),
	}}}
	all, err := fetchAllInterfaces(context.Background(), client, "pve1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 interfaces, got %d: %v", len(all), all)
	}
	if s, _ := kvjson.Scalar(all["vmbr0"]["bridge_ports"]); s != "eth0" {
		t.Fatalf("expected vmbr0 bridge_ports=eth0, got %v", all["vmbr0"])
	}
}
