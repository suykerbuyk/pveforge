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
		return nil, pveAnswer(fmt.Sprintf("raw request: pve returned 500 Internal Server Error: iface '%s' does not exist", iface))
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
		return NetworkBridgeEnsure{Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeCreate}
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

	t.Run("mode unset -> error", func(t *testing.T) {
		op := base()
		op.mode = modeUnset
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "mode is unset") {
			t.Fatalf("expected a mode-unset error, got %v", err)
		}
	})

	t.Run("destroy with Wanted fields -> error", func(t *testing.T) {
		op := base()
		op.mode = modeDestroy
		op.Wanted = map[string]string{"bridge_ports": "eth0"}
		err := op.Validate()
		if err == nil || !strings.Contains(err.Error(), "destroy carries no Wanted") {
			t.Fatalf("expected a destroy-with-Wanted error, got %v", err)
		}
	})

	t.Run("valid destroy (no Wanted)", func(t *testing.T) {
		op := base()
		op.mode = modeDestroy
		op.Wanted = nil
		if err := op.Validate(); err != nil {
			t.Fatalf("expected no error for a fieldless destroy, got %v", err)
		}
	})
}

// --- Read / Satisfied ---------------------------------------------------

func TestNetworkBridgeEnsure_Read(t *testing.T) {
	t.Run("interface does not exist", func(t *testing.T) {
		client := newFakeNetworkBridgeClient("pve1")
		op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeDestroy}
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
		op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeDestroy}
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
	// ANTI-VACUITY (resume #13): each pair runs the SAME `current` through a
	// create op and a destroy op and asserts OPPOSITE results. A regression
	// that ignores op.mode (or reverts to the len(Wanted) discriminator)
	// collapses a pair to equal values and is caught here — these assertions
	// cannot pass vacuously, because create and destroy must disagree on both
	// an absent and a present interface.
	// A fully-live bridge: autostart present (PVE reports it on an interface
	// with an `auto` line), so a create — whose effectiveWanted now seeds
	// autostart=1 — is genuinely satisfied by it.
	const presentMatch = `{"type":"bridge","bridge_ports":"eth0","autostart":1}`
	mkCreate := func(w map[string]string) *NetworkBridgeEnsure {
		return NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", w)
	}
	mkDestroy := func() *NetworkBridgeEnsure {
		return NewNetworkBridgeDestroy(nil, "pve1", "vmbr99", "vmbr0")
	}

	t.Run("absent: create NOT satisfied, destroy satisfied", func(t *testing.T) {
		c, d := mkCreate(map[string]string{"bridge_ports": "eth0"}), mkDestroy()
		if c.Satisfied("") {
			t.Error("create against an absent iface must NOT be satisfied")
		}
		if !d.Satisfied("") {
			t.Error("destroy against an absent iface must be satisfied")
		}
	})

	t.Run("present & matching: create satisfied, destroy NOT satisfied", func(t *testing.T) {
		c, d := mkCreate(map[string]string{"bridge_ports": "eth0"}), mkDestroy()
		if !c.Satisfied(presentMatch) {
			t.Error("create with matching fields must be satisfied")
		}
		if d.Satisfied(presentMatch) {
			t.Error("destroy against a present iface must NOT be satisfied")
		}
	})

	// THE BUG-CATCHER (pveforge-network-bridge-create-false-noop-live): a
	// field-less create (empty Wanted) against an absent iface must NOT be
	// satisfied — the exact case that silently no-op'd as a destroy.
	t.Run("field-less create, absent -> NOT satisfied (bug-catcher)", func(t *testing.T) {
		if mkCreate(nil).Satisfied("") {
			t.Fatal("a field-less create against an absent iface must NOT be satisfied")
		}
		// And effectiveWanted still seeds type=bridge for a field-less create.
		if ew := mkCreate(nil).effectiveWanted(); ew["type"] != "bridge" {
			t.Fatalf("field-less create effectiveWanted = %v, want type=bridge", ew)
		}
	})

	// modeUnset must fail CLOSED in both directions — it is reachable by
	// idempotent.Run before Apply/Validate run, so it must never report
	// "already satisfied".
	t.Run("modeUnset fails closed", func(t *testing.T) {
		var op NetworkBridgeEnsure // zero value: modeUnset
		if op.Satisfied("") {
			t.Error("modeUnset must not satisfy an absent iface")
		}
		if op.Satisfied(presentMatch) {
			t.Error("modeUnset must not satisfy a present iface")
		}
	})

	// The create's type=bridge default is part of what is CHECKED, not only
	// of what is sent: an existing interface of another type with otherwise
	// matching fields is not the bridge that was asked for.
	// autostart=1 present in every `current` below so the assertion under
	// test (type, or an absent/mismatching NON-autostart field) is what drives
	// the result — not the autostart seed. Keeps these controls non-vacuous.
	t.Run("exists as another type, no type named -> create NOT satisfied", func(t *testing.T) {
		if mkCreate(map[string]string{"mtu": "9000"}).Satisfied(`{"type":"OVSBridge","mtu":"9000","active":"1","autostart":1}`) {
			t.Fatal("an OVSBridge must not satisfy a bridge create")
		}
	})
	t.Run("explicit type named and matching -> create satisfied", func(t *testing.T) {
		if !mkCreate(map[string]string{"mtu": "9000", "type": "OVSBridge"}).Satisfied(`{"type":"OVSBridge","mtu":"9000","active":"1","autostart":1}`) {
			t.Fatal("an explicitly named type that matches must satisfy")
		}
	})
	t.Run("exists with mismatching field -> create NOT satisfied", func(t *testing.T) {
		if mkCreate(map[string]string{"bridge_ports": "eth0"}).Satisfied(`{"type":"bridge","bridge_ports":"eth1","autostart":1}`) {
			t.Fatal("a mismatching field must not be satisfied")
		}
	})
	t.Run("missing wanted key -> create NOT satisfied", func(t *testing.T) {
		// mtu absent is the sole reason for the miss (type and autostart both
		// match), so this exercises the absent==never-matching rule for a
		// non-autostart field, not the autostart carve-out.
		if mkCreate(map[string]string{"mtu": "9000"}).Satisfied(`{"type":"bridge","autostart":1}`) {
			t.Fatal("an absent wanted key must not be satisfied")
		}
	})
}

// TestNetworkBridgeEnsure_Satisfied_BoolishFieldsConverge is the regression
// test for a real, shipped defect found 2026-09-20 while reviewing
// pveforge-mutation-success-second-signal's plan: Satisfied compared each
// field's current value against its wanted value with a plain !=, while
// BOTH sibling Ops already went through fieldsEqual for exactly this reason
// (networkfields.go's Satisfied, vmfields.go's Satisfied) — and boolish.go's
// own doc comment names vlan_filtering, a bridge field, as the motivating
// case.
//
// The consequence was not cosmetic. NetworkBridgeEnsure is the Op that
// drives a live stage -> guard -> commit -> ifreload sequence against a real
// node. An Op that can never report satisfied re-drives that entire sequence
// on every single invocation — precisely the blast radius the two-phase
// guard exists to avoid.
//
// Wanted carries whatever the caller typed (cmd/pveforge/network.go passes
// key=value args through unvalidated), while PVE answers with its own
// encoding: go-proxmox types NodeNetwork.Autostart and
// NodeNetwork.BridgeVLANAware as plain ints, and its IntOrBool exists
// upstream precisely because these fields arrive either way. Read preserves
// that raw JSON (fetchInterface returns map[string]json.RawMessage), so the
// cases below use PVE's NATIVE encodings — a JSON number and a JSON bool —
// rather than pre-stringified ones.
//
// The four want:false cases are the specificity control: a "fix" that simply
// returned true, or one that coerced every value through a boolean, would
// fail this test rather than pass it.
func TestNetworkBridgeEnsure_Satisfied_BoolishFieldsConverge(t *testing.T) {
	tests := []struct {
		name    string
		wanted  map[string]string
		current string
		want    bool
	}{
		// Every `current` below carries autostart:1, so that the field
		// actually under test (never autostart itself, except the one
		// autostart case) is what drives the result — a create's
		// effectiveWanted now seeds autostart=1, and Satisfied treats it like
		// any other wanted field, so a current WITHOUT autostart would miss
		// for the autostart reason and make these controls vacuous. The
		// dedicated autostart absent==0 semantics live in their own test
		// (TestNetworkBridgeEnsure_Satisfied_AutostartAware).

		// The headline case: this is what `network bridge create vmbr1
		// vlan_filtering=true` actually compares once PVE has applied it.
		{
			name:    "vlan_filtering: caller typed true, pve answers json number 1",
			wanted:  map[string]string{"vlan_filtering": "true"},
			current: `{"type":"bridge","vlan_filtering":1,"active":1,"autostart":1}`,
			want:    true,
		},
		{
			name:    "vlan_filtering: caller typed PVE-CLI 1, pve answers json bool true",
			wanted:  map[string]string{"vlan_filtering": "1"},
			current: `{"type":"bridge","vlan_filtering":true,"autostart":1}`,
			want:    true,
		},
		{
			name:    "autostart: caller typed false, pve answers json number 0",
			wanted:  map[string]string{"autostart": "false"},
			current: `{"type":"bridge","autostart":0}`,
			want:    true,
		},
		{
			name:    "bridge_vlan_aware: caller typed 0, pve answers json bool false",
			wanted:  map[string]string{"bridge_vlan_aware": "0"},
			current: `{"type":"bridge","bridge_vlan_aware":false,"autostart":1}`,
			want:    true,
		},

		// Specificity controls.
		{
			name:    "vlan_filtering: wanted 0 against a live true stays unsatisfied",
			wanted:  map[string]string{"vlan_filtering": "0"},
			current: `{"type":"bridge","vlan_filtering":true,"autostart":1}`,
			want:    false,
		},
		{
			// boolish.go deliberately excludes "" from its four-token set:
			// a field genuinely present-but-empty must never read as
			// boolean-false-shaped. Same case the sibling pins.
			name:    "empty string is not boolean-false-shaped",
			wanted:  map[string]string{"vlan_filtering": "false"},
			current: `{"type":"bridge","vlan_filtering":"","autostart":1}`,
			want:    false,
		},
		{
			// "yes"/"on" are outside parseBoolish's domain, so this falls
			// through to an exact compare and correctly does not match.
			name:    "yes is not boolish, so it does not match 1",
			wanted:  map[string]string{"vlan_filtering": "yes"},
			current: `{"type":"bridge","vlan_filtering":1,"autostart":1}`,
			want:    false,
		},
		{
			name:    "non-boolish mismatch still unsatisfied",
			wanted:  map[string]string{"bridge_ports": "eth0"},
			current: `{"type":"bridge","bridge_ports":"eth1","autostart":1}`,
			want:    false,
		},

		// The absent-key guard. Satisfied's own doc (and boolish.go's)
		// claim a key ABSENT from current state can never count as
		// already-matching, even against a wanted value that happens to
		// be the empty string — otherwise the Op would skip a live
		// stage/commit/ifreload it genuinely owed. Nothing pinned that
		// branch before: mutating its `return false` to `continue`
		// compiles and leaves the whole suite green (measured).
		// The nearest pre-existing case has the field PRESENT and wrong,
		// which exercises a different branch entirely. autostart:1 is
		// present so the miss is the vlan_filtering/bridge_stp key alone,
		// NOT the autostart carve-out (which is a different code path).
		{
			name:    "absent key is never already-matching",
			wanted:  map[string]string{"vlan_filtering": "1"},
			current: `{"type":"bridge","bridge_ports":"eth0","autostart":1}`,
			want:    false,
		},
		{
			// The edge boolish.go calls out by name: "" must not be
			// confused with absent, in either direction.
			name:    "absent key is not already-matching even for a wanted empty string",
			wanted:  map[string]string{"bridge_stp": ""},
			current: `{"type":"bridge","bridge_ports":"eth0","autostart":1}`,
			want:    false,
		},

		// Non-boolish equality must be untouched by the fix.
		{
			name:    "non-boolish string match unaffected",
			wanted:  map[string]string{"bridge_ports": "eth0"},
			current: `{"type":"bridge","bridge_ports":"eth0","autostart":1}`,
			want:    true,
		},
		{
			name:    "non-boolish numeric match unaffected",
			wanted:  map[string]string{"mtu": "9000"},
			current: `{"type":"bridge","mtu":9000,"autostart":1}`,
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op := NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", tc.wanted)
			if got := op.Satisfied(tc.current); got != tc.want {
				t.Fatalf("Satisfied(%s) with Wanted %v = %v, want %v", tc.current, tc.wanted, got, tc.want)
			}
			// Anti-vacuity: the SAME current in destroy mode must follow
			// !exists, never the create result — proof op.mode is consulted.
			if d := NewNetworkBridgeDestroy(nil, "pve1", "vmbr99", "vmbr0").Satisfied(tc.current); d != (tc.current == "") {
				t.Fatalf("destroy Satisfied(%s) = %v, want %v (!exists)", tc.current, d, tc.current == "")
			}
		})
	}
}

// --- Apply: helpers to build common scenario fields ---------------------

func mgmtFields(v string) map[string]json.RawMessage {
	return map[string]json.RawMessage{"bridge_ports": rawField(v), "digest": rawField("deadbeef")}
}

// --- (a) matching pre/pending management-bridge fields -> commit called, success.

// TestNetworkBridgeEnsure_Apply_ExistingOtherTypeRefusedBeforeStaging: a
// create of an interface that already exists as another type is refused
// before anything is staged — not staged for PVE or the guard to reject,
// and never reported as done. An existing bridge is not refused here (the
// step-4 guard still judges it, as before).
func TestNetworkBridgeEnsure_Apply_ExistingOtherTypeRefusedBeforeStaging(t *testing.T) {
	for name, c := range map[string]struct {
		wanted   map[string]string
		existing string
	}{
		"no type named, exists as OVSBridge": {map[string]string{"mtu": "9000"}, "OVSBridge"},
		"OVSBridge named, exists as bridge":  {map[string]string{"mtu": "9000", "type": "OVSBridge"}, "bridge"},
		"no type named, exists with no type": {map[string]string{"mtu": "9000"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			client := newFakeNetworkBridgeClient("pve1")
			client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
			fields := map[string]json.RawMessage{"mtu": rawField("9000")}
			if c.existing != "" {
				fields["type"] = rawField(c.existing)
			}
			client.getResponses["vmbr99"] = []getResponse{{fields: fields}}
			client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}

			op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", Wanted: c.wanted, mode: modeCreate}
			err := op.Apply(context.Background())
			if err == nil || !strings.Contains(err.Error(), "already exists as type") || !strings.Contains(err.Error(), "nothing staged") {
				t.Fatalf("Apply = %v, want a refusal naming the existing type", err)
			}
			if client.lastStageParams != nil || client.commitCalls != 0 || client.revertCalls != 0 {
				t.Errorf("staged=%v commits=%d reverts=%d, want nothing sent", client.lastStageParams, client.commitCalls, client.revertCalls)
			}
		})
	}
}

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
		mode:   modeCreate,
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
	// Exactly: the requested field, the interface, type=bridge (PVE requires
	// a type on a create and the caller named none), and autostart=1 (the
	// bring-up default — pveforge-network-bridge-create-no-autostart).
	if got, want := client.lastStageParams.Encode(), "autostart=1&bridge_ports=eth1&iface=vmbr99&type=bridge"; got != want {
		t.Fatalf("stage params = %q, want exactly %q", got, want)
	}
}

// TestNetworkBridgeEnsure_Apply_FieldlessCreateCreates is the end-to-end
// regression for pveforge-network-bridge-create-false-noop-live: a create with
// NO caller fields against an absent interface must actually stage (POST) and
// commit (PUT) a plain bridge, never silently no-op as a destroy. Built via
// the constructor, exactly as cmd/pveforge now does.
func TestNetworkBridgeEnsure_Apply_FieldlessCreateCreates(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{missing: true}} // absent before
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: true}}
	client.commitUPID = "UPID:pve1:00000001:00000002:00000003:00000004:test:root@pam:"

	op := NewNetworkBridgeCreate(client, "pve1", "vmbr99", "vmbr0", nil) // field-less
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.commitCalls != 1 || client.revertCalls != 0 {
		t.Fatalf("field-less create must stage+commit: commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
	// Exactly the interface, the type=bridge default, and the autostart=1
	// bring-up default — a real create, not a destroy and not a no-op.
	if got, want := client.lastStageParams.Encode(), "autostart=1&iface=vmbr99&type=bridge"; got != want {
		t.Fatalf("stage params = %q, want exactly %q", got, want)
	}
}

// TestNetworkBridgeEnsure_Apply_CreateSendsAnExplicitTypeAsGiven: a type the
// caller named is sent as given, not replaced by the default.
func TestNetworkBridgeEnsure_Apply_CreateSendsAnExplicitTypeAsGiven(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}} // same both reads (index clamps to last)
	client.getResponses["vmbr99"] = []getResponse{{missing: true}}             // guard: not yet live
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}} // same both reads
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: true}}
	client.commitUPID = "UPID:pve1:00000001:00000002:00000003:00000004:test:root@pam:"

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1", "type": "OVSBridge"},
		mode:   modeCreate,
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
	// Exactly: the requested field, the interface, the caller's explicit
	// type (sent as given, not replaced by the default), and autostart=1
	// (the bring-up default, which the caller did not name).
	if got, want := client.lastStageParams.Encode(), "autostart=1&bridge_ports=eth1&iface=vmbr99&type=OVSBridge"; got != want {
		t.Fatalf("stage params = %q, want exactly %q", got, want)
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}                                                    // identical every read
	client.getResponses["vmbr99"] = []getResponse{{missing: true}, {fields: map[string]json.RawMessage{"active": rawField("1")}}} // pre-stage: absent; guard: active
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
	client.getResponses["vmbr99"] = []getResponse{{missing: true}, {fields: map[string]json.RawMessage{"active": rawField("1")}}} // pre-stage: absent; guard: active
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}}

	op := &NetworkBridgeEnsure{
		Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0",
		Wanted: map[string]string{"bridge_ports": "eth1"},
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode: modeDestroy,
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

	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeDestroy}
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

	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeDestroy}
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
		mode:   modeCreate,
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
	op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", mode: modeDestroy}
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

// --- pveforge-network-bridge-create-no-autostart: the autostart fix --------

// TestNetworkBridgeEnsure_effectiveWanted_SeedsAndNormalizesAutostart pins the
// write-side of the fix: a create seeds autostart=1 when the caller named
// none, preserves/normalizes a caller value to PVE's 1/0 domain, and a
// destroy/unset carries nothing.
//
// Mutants killed:
//   - delete the `out["autostart"]="1"` seed line -> the field-less subcase
//     (autostart absent) goes red.
//   - make the seed unconditional (clobber a caller value) -> the autostart=0
//     and autostart=true subcases go red.
//   - drop normalizeAutostart's true->"1" rewrite -> the "true"->"1" subcase
//     goes red (PVE would reject a literal "true").
func TestNetworkBridgeEnsure_effectiveWanted_SeedsAndNormalizesAutostart(t *testing.T) {
	cases := []struct {
		name     string
		wanted   map[string]string
		wantAuto string // expected effectiveWanted["autostart"]; "" means key absent
	}{
		{"field-less create seeds 1", nil, "1"},
		{"caller 0 preserved", map[string]string{"autostart": "0"}, "0"},
		{"caller false normalized to 0", map[string]string{"autostart": "false"}, "0"},
		{"caller 1 kept", map[string]string{"autostart": "1"}, "1"},
		{"caller true normalized to 1", map[string]string{"autostart": "true"}, "1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ew := NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", c.wanted).effectiveWanted()
			if ew["type"] != "bridge" {
				t.Fatalf("effectiveWanted type = %q, want bridge", ew["type"])
			}
			if got, ok := ew["autostart"]; !ok || got != c.wantAuto {
				t.Fatalf("effectiveWanted autostart = %q (present=%v), want %q", got, ok, c.wantAuto)
			}
		})
	}

	// destroy and unset must carry nothing (nil map): autostart is a
	// create-only concern.
	if ew := NewNetworkBridgeDestroy(nil, "pve1", "vmbr99", "vmbr0").effectiveWanted(); ew != nil {
		t.Fatalf("destroy effectiveWanted = %v, want nil", ew)
	}
	var unset NetworkBridgeEnsure
	if ew := unset.effectiveWanted(); ew != nil {
		t.Fatalf("modeUnset effectiveWanted = %v, want nil", ew)
	}
}

// TestNormalizeAutostart and TestAutostartRequested pin the value domain
// (ruling 3): 1/true and 0/false only; yes/on/other out of domain.
//
// Mutant killed: widen parseBoolish to accept "yes"/"on" -> the out-of-domain
// cases go red; invert the b?"1":"0" mapping -> the true/false cases go red.
func TestNormalizeAutostart(t *testing.T) {
	for in, want := range map[string]string{"1": "1", "true": "1", "TRUE": "1", " 1 ": "1", "0": "0", "false": "0", "FALSE": "0"} {
		if got, ok := normalizeAutostart(in); !ok || got != want {
			t.Errorf("normalizeAutostart(%q) = (%q,%v), want (%q,true)", in, got, ok, want)
		}
	}
	for _, in := range []string{"yes", "on", "2", "", "enabled"} {
		if got, ok := normalizeAutostart(in); ok {
			t.Errorf("normalizeAutostart(%q) = (%q,true), want ok=false", in, got)
		}
	}
}

func TestAutostartRequested(t *testing.T) {
	truthy := []map[string]string{{"autostart": "1"}, {"autostart": "true"}, {"autostart": "TRUE"}}
	for _, m := range truthy {
		if !autostartRequested(m) {
			t.Errorf("autostartRequested(%v) = false, want true", m)
		}
	}
	falsy := []map[string]string{nil, {}, {"autostart": "0"}, {"autostart": "false"}, {"autostart": "yes"}, {"type": "bridge"}}
	for _, m := range falsy {
		if autostartRequested(m) {
			t.Errorf("autostartRequested(%v) = true, want false", m)
		}
	}
}

// TestNetworkBridgeEnsure_Validate_RejectsNonBooleanAutostart pins ruling 3's
// fail-before-POST: a non-boolean autostart is a clear pveforge error at
// Validate, while 1/true/0/false are accepted.
//
// Mutant killed: drop the autostart branch in Validate -> the "yes" case no
// longer errors and goes red.
func TestNetworkBridgeEnsure_Validate_RejectsNonBooleanAutostart(t *testing.T) {
	bad := NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", map[string]string{"autostart": "yes"})
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "autostart") || !strings.Contains(err.Error(), "not a boolean") {
		t.Fatalf("Validate(autostart=yes) = %v, want a clear non-boolean autostart error", err)
	}
	for _, v := range []string{"1", "true", "0", "false"} {
		if err := NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", map[string]string{"autostart": v}).Validate(); err != nil {
			t.Errorf("Validate(autostart=%q) = %v, want nil", v, err)
		}
	}
}

// TestNetworkBridgeEnsure_Satisfied_AutostartAware pins ruling 2: an ABSENT
// autostart key in the GET equals the 0/off state for the autostart field
// ONLY, so absent-or-0 matches wanted 0 and does NOT match wanted 1. This is
// what makes both a dormant (autostart=0) create and a live (autostart=1)
// create genuinely idempotent — and what converges a pre-existing dormant
// stanza (absent key) under the default autostart=1.
//
// Mutant killed: make Satisfied treat the autostart key like every other key
// (absent -> return false unconditionally) -> the "absent matches wanted 0"
// subcase goes red. Remove the absent==0 handling's "0" default -> same.
func TestNetworkBridgeEnsure_Satisfied_AutostartAware(t *testing.T) {
	cases := []struct {
		name    string
		wanted  map[string]string // caller Wanted (autostart seeded if absent)
		current string
		want    bool
	}{
		// Default create (seeds autostart=1) over a dormant stanza whose GET
		// omits autostart: NOT satisfied -> Apply re-drives and brings it up.
		{"absent key, default wants up -> not satisfied", nil, `{"type":"bridge"}`, false},
		// Explicit autostart=0 over the same dormant stanza: absent==0 matches
		// wanted 0 -> satisfied (dormant is genuinely idempotent).
		{"absent key, wanted down -> satisfied", map[string]string{"autostart": "0"}, `{"type":"bridge"}`, true},
		// Live bridge (GET reports autostart) under the default: satisfied.
		{"present 1, default wants up -> satisfied", nil, `{"type":"bridge","autostart":1}`, true},
		// Live bridge that the caller wants down: not satisfied.
		{"present 1, wanted down -> not satisfied", map[string]string{"autostart": "0"}, `{"type":"bridge","autostart":1}`, false},
		// Present 0 under the default: not satisfied (needs bring-up).
		{"present 0, default wants up -> not satisfied", nil, `{"type":"bridge","autostart":0}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NewNetworkBridgeCreate(nil, "pve1", "vmbr99", "vmbr0", c.wanted).Satisfied(c.current); got != c.want {
				t.Fatalf("Satisfied(%s) wanted %v = %v, want %v", c.current, c.wanted, got, c.want)
			}
		})
	}
}

// TestNetworkBridgeEnsure_Apply_FieldlessCreateRequestsAutostart is the
// end-to-end stage-body proof for the exact invocation the harness uses (a
// port-less, field-less create): the POST body carries autostart=1.
//
// Mutant killed: drop the autostart seed from effectiveWanted (so it never
// reaches the POST) -> the exact Encode() goes red. This is the Op-level twin
// of the CLI silent-no-op test.
func TestNetworkBridgeEnsure_Apply_FieldlessCreateRequestsAutostart(t *testing.T) {
	client := newHappyPathClient()
	op := NewNetworkBridgeCreate(client, "pve1", "vmbr99", "vmbr0", nil) // field-less, exactly as the harness runs it
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := client.lastStageParams.Encode(), "autostart=1&iface=vmbr99&type=bridge"; got != want {
		t.Fatalf("stage params = %q, want exactly %q (the field-less harness create must request autostart=1)", got, want)
	}
	if client.commitCalls != 1 || client.revertCalls != 0 {
		t.Fatalf("field-less create must stage+commit once: commits=%d reverts=%d", client.commitCalls, client.revertCalls)
	}
}

// TestNetworkBridgeEnsure_Apply_Step8KeysOffAutostart pins ruling 4+5: step-8
// kernel-liveness is keyed off whether autostart was REQUESTED (via
// effectiveWanted), and the negative (expect-not-live) assertion is skipped
// ONLY for the OVS port types PVE force-starts regardless of autostart
// (OVSPort/OVSIntPort/OVSBond with ovs_bridge set — see
// negativeLivenessReliable's PVE-source citation). bridge, OVSBridge, bond,
// vlan, eth all follow the autostart field, so their not-live assertion
// stands. Each subcase builds a fake whose POST-apply LinkState (call index 1
// on vmbr99) is the state under test; the guard self-check (call index 0)
// always shows not-yet-live for a create / live for a destroy.
//
// Mutants killed (verified by revert-and-watch-red):
//   - hardcode `wantExists := op.mode == modeCreate` -> the "autostart=0
//     bridge, kernel down -> ok" row goes red (it would demand live).
//   - read Wanted instead of effectiveWanted in step-8 -> the "default create,
//     kernel down -> error" row goes red (autostart lives only in
//     effectiveWanted, so the mutant would see no request and expect not-live).
//   - grok's exact under-assertion `negativeLivenessReliable { return
//     op.mode == modeDestroy }` (skip not-live for ALL creates) -> the
//     "autostart=0 OVSBridge, kernel up -> error" and "autostart=0 bond,
//     kernel up -> error" rows go red (the mutant would skip and succeed).
//   - the opposite over-assertion `negativeLivenessReliable { return true }`
//     (never skip) -> the "autostart=0 OVSIntPort+ovs_bridge, kernel up -> ok"
//     row goes red (the mutant would assert not-live and error on a
//     force-started port).
func TestNetworkBridgeEnsure_Apply_Step8KeysOffAutostart(t *testing.T) {
	cases := []struct {
		name       string
		mode       networkBridgeMode
		wanted     map[string]string
		postExists bool   // kernel LinkState.Exists after apply (vmbr99)
		wantErr    string // substring; "" means Apply must succeed
	}{
		{"default create wants live, kernel down -> error", modeCreate, nil, false, "expected exists=true"},
		{"default create wants live, kernel up -> ok", modeCreate, nil, true, ""},
		{"autostart=0 bridge, kernel down -> ok (dormant intended)", modeCreate, map[string]string{"autostart": "0"}, false, ""},
		{"autostart=0 bridge, kernel up -> error", modeCreate, map[string]string{"autostart": "0"}, true, "expected exists=false"},
		// OVSBridge follows the autostart field (PVE does NOT force-start it),
		// so a dormant OVSBridge that is somehow live is still a mismatch.
		{"autostart=0 OVSBridge, kernel up -> error (follows autostart)", modeCreate, map[string]string{"autostart": "0", "type": "OVSBridge"}, true, "expected exists=false"},
		// An OVS port attached to a bridge IS force-started regardless of
		// autostart, so the not-live assertion must be skipped (no error).
		{"autostart=0 OVSIntPort+ovs_bridge, kernel up -> ok (force-started, carve-out skip)", modeCreate, map[string]string{"autostart": "0", "type": "OVSIntPort", "ovs_bridge": "vmbr0"}, true, ""},
		// bond follows the autostart field too (not force-started).
		{"autostart=0 bond, kernel up -> error (follows autostart)", modeCreate, map[string]string{"autostart": "0", "type": "bond"}, true, "expected exists=false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := newFakeNetworkBridgeClient("pve1")
			client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
			client.getResponses["vmbr99"] = []getResponse{{missing: true}} // guard: not yet live
			client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
			client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: false}, {Exists: c.postExists}}
			client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

			op := &NetworkBridgeEnsure{Client: client, Node: "pve1", Iface: "vmbr99", ManagementBridge: "vmbr0", Wanted: c.wanted, mode: c.mode}
			err := op.Apply(context.Background())
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Apply = %v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Apply = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

// TestNetworkBridgeEnsure_Apply_DestroyStep8NilSafe proves ruling 4's destroy
// nil-safety through Apply (NOT a direct helper call): a destroy's
// effectiveWanted is nil, so step-8 passes that nil map to both
// autostartRequested and negativeLivenessReliable — this test proves neither
// panics on the nil map and that a destroy still expects not-live (a removed
// interface the kernel reports gone is a success).
//
// What this test pins is the nil-map safety and the destroy expect-not-live
// path specifically. It does NOT pin the effectiveWanted-vs-Wanted choice
// (that mutant is killed by the default-create rows in
// TestNetworkBridgeEnsure_Apply_Step8KeysOffAutostart, where autostart lives
// only in effectiveWanted): Wanted is also nil for a destroy, so the two reads
// are indistinguishable here.
func TestNetworkBridgeEnsure_Apply_DestroyStep8NilSafe(t *testing.T) {
	client := newFakeNetworkBridgeClient("pve1")
	client.getResponses["vmbr0"] = []getResponse{{fields: mgmtFields("eth0")}}
	client.getResponses["vmbr99"] = []getResponse{{fields: map[string]json.RawMessage{"active": rawField("1")}}}
	client.linkStates["vmbr0"] = []sshexec.LinkState{{Exists: true, Up: true}}
	client.linkStates["vmbr99"] = []sshexec.LinkState{{Exists: true}, {Exists: false}} // live at guard, gone after
	client.commitUPID = "UPID:pve1:1:1:1:1:test:root@pam:"

	op := NewNetworkBridgeDestroy(client, "pve1", "vmbr99", "vmbr0")
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("destroy Apply = %v, want success (nil effectiveWanted must not panic and must expect not-live)", err)
	}
	if client.commitCalls != 1 {
		t.Fatalf("expected one commit, got %d", client.commitCalls)
	}
}
