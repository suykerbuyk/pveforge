package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// VMFieldsEnsure's PostApply (post-apply-verify): after a batch that changed
// something, which of this Run's own changes does PVE hold as pending?

// runPending drives a one-field write of cores=4 through Run over
// fakeClient, whose RawRequest answers the config reads in call order —
// Run's Read, the field's own digest re-fetch, Run's final re-read — and
// PostApply's /pending read with pending.
func runPending(t *testing.T, op *VMFieldsEnsure, pending string) (Result, *fakeClient) {
	t.Helper()
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","cores":"2"}`),
		json.RawMessage(`{"digest":"d1","cores":"2"}`),
		json.RawMessage(`{"digest":"d2","cores":"4"}`),
	}, pendingResults: []json.RawMessage{json.RawMessage(pending)}}
	op.Client = client
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed || res.AfterErr != nil {
		t.Fatalf("Run = %+v, want a change observed cleanly", res)
	}
	return res, client
}

// T5: the check is one GET of the VM's /pending list at its exact path,
// with no query, after the final re-read.
func TestVMFieldsEnsure_PostApply_ReadsThePendingList(t *testing.T) {
	op := &VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4")}
	res, client := runPending(t, op, `[]`)
	if res.PostApplyErr != nil {
		t.Fatalf("PostApplyErr: %v", res.PostApplyErr)
	}
	want := []string{
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/config?",
		"GET /nodes/qa-pve-01/qemu/100/pending?",
	}
	if !slices.Equal(client.rawCalls, want) {
		t.Errorf("raw requests:\n got:  %q\n want: %q", client.rawCalls, want)
	}
	if op.Pending != nil || op.PendingDeletes != nil {
		t.Errorf("nothing is pending, got Pending %q, PendingDeletes %q", op.Pending, op.PendingDeletes)
	}
}

// T5, the converse: a Run that changed nothing does not read /pending.
func TestVMFieldsEnsure_PostApply_NoChangeNoRead(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1"}`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100}
	if err := op.PostApply(context.Background()); err != nil {
		t.Fatalf("PostApply: %v", err)
	}
	if client.pendingCalls != 0 || len(client.rawCalls) != 0 {
		t.Errorf("PostApply with nothing applied made %d request(s): %q", client.rawRequestCalls, client.rawCalls)
	}
}

// T6: only this Run's written keys that PVE holds as pending are reported —
// not a key someone else left pending, and not a key this Run wrote that
// took effect at once. The list is the one accumulated across the Run.
func TestVMFieldsEnsure_PostApply_ReportsOnlyThisRunsPendingKeys(t *testing.T) {
	op := &VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4")}
	res, _ := runPending(t, op, `[
		{"key":"cores","value":2,"pending":4},
		{"key":"memory","value":2048,"pending":4096},
		{"key":"name","value":"vm100"}
	]`)
	if res.PostApplyErr != nil {
		t.Fatalf("PostApplyErr: %v", res.PostApplyErr)
	}
	if !slices.Equal(op.Pending, []string{"cores"}) {
		t.Errorf("Pending = %q, want [cores]: memory is pending, but not by this Run", op.Pending)
	}

	// A written key PVE applied at once (no "pending") is not reported.
	op = &VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4")}
	runPending(t, op, `[{"key":"cores","value":4},{"key":"memory","value":2048,"pending":4096}]`)
	if op.Pending != nil {
		t.Errorf("Pending = %q, want none: cores took effect at once", op.Pending)
	}

	// Several keys, reported in the order this Run applied them.
	op = &VMFieldsEnsure{VMID: 100, Applied: []string{"sockets", "cores", "numa"}}
	op.Client = &fakeClient{node: "qa-pve-01", pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"numa","pending":1},{"key":"cores","pending":4},{"key":"sockets","value":1}]`)}}
	if err := op.PostApply(context.Background()); err != nil {
		t.Fatalf("PostApply: %v", err)
	}
	if !slices.Equal(op.Pending, []string{"cores", "numa"}) {
		t.Errorf("Pending = %q, want [cores numa] in applied order", op.Pending)
	}
}

// T7: a key this Run deleted that PVE holds as a pending removal
// ("delete": 1, or 2 when forced) is a pending delete — not a pending value
// — and a removal someone else left pending is not reported.
func TestVMFieldsEnsure_PostApply_ReportsThisRunsPendingDeletes(t *testing.T) {
	for name, del := range map[string]string{"delete 1": "1", "delete 2": "2"} {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{node: "qa-pve-01", pendingResults: []json.RawMessage{json.RawMessage(
				`[{"key":"description","value":"x","delete":` + del + `},{"key":"tags","value":"a","delete":1}]`)}}
			op := &VMFieldsEnsure{Client: client, VMID: 100, Deleted: []string{"description"}}
			if err := op.PostApply(context.Background()); err != nil {
				t.Fatalf("PostApply: %v", err)
			}
			if !slices.Equal(op.PendingDeletes, []string{"description"}) || op.Pending != nil {
				t.Errorf("PendingDeletes = %q, Pending = %q; want [description] and none", op.PendingDeletes, op.Pending)
			}
		})
	}
	// "delete": 0 is not a removal.
	client := &fakeClient{node: "qa-pve-01", pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"description","value":"x","delete":0}]`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deleted: []string{"description"}}
	if err := op.PostApply(context.Background()); err != nil {
		t.Fatalf("PostApply: %v", err)
	}
	if op.PendingDeletes != nil {
		t.Errorf("PendingDeletes = %q, want none for delete:0", op.PendingDeletes)
	}
}

// T8: a /pending answer no healthy PVE gives is ErrUnverifiableRead in
// Result.PostApplyErr — never read as "nothing pending" — and the Run
// itself still succeeds with its change observed.
func TestVMFieldsEnsure_PostApply_UnverifiablePayload(t *testing.T) {
	for name, payload := range map[string]string{
		"null":                 `null`,
		"an object":            `{"cores":{"pending":4}}`,
		"a string":             `"cores"`,
		"an entry not object":  `["cores"]`,
		"a null entry":         `[null]`,
		"an entry without key": `[{"value":2,"pending":4}]`,
		"a non-string key":     `[{"key":4,"pending":4}]`,
		"an empty key":         `[{"key":"","pending":4}]`,
		"delete out of range":  `[{"key":"cores","delete":3}]`,
		"delete not a number":  `[{"key":"cores","delete":"1"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			op := &VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4")}
			res, _ := runPending(t, op, payload)
			if !errors.Is(res.PostApplyErr, pve.ErrUnverifiableRead) {
				t.Fatalf("PostApplyErr = %v, want ErrUnverifiableRead", res.PostApplyErr)
			}
			if op.Pending != nil || op.PendingDeletes != nil {
				t.Errorf("an unverifiable read reported Pending %q, PendingDeletes %q", op.Pending, op.PendingDeletes)
			}
		})
	}
}

// T8, the transport half: a failed /pending read is PostApplyErr too, with
// its cause reachable.
func TestVMFieldsEnsure_PostApply_ReadFailure(t *testing.T) {
	boom := errors.New("boom")
	client := &fakeClient{node: "qa-pve-01", rawRequestErr: boom}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Applied: []string{"cores"}}
	if err := op.PostApply(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("PostApply = %v, want the read's error", err)
	}
	if op.Pending != nil {
		t.Errorf("a failed read reported Pending %q", op.Pending)
	}
}

// T9: keys are matched by presence, never by value: PVE canonicalises a
// written net0 (it gains a MAC), and its pending value is no exception.
func TestVMFieldsEnsure_PostApply_MatchesACanonicalisedValueByKey(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", pendingResults: []json.RawMessage{json.RawMessage(
		`[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=vmbr0","pending":"virtio=BC:24:11:00:00:01,bridge=vmbr1"}]`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("net0", "virtio,bridge=vmbr1"), Applied: []string{"net0"}}
	if err := op.PostApply(context.Background()); err != nil {
		t.Fatalf("PostApply: %v", err)
	}
	if !slices.Equal(op.Pending, []string{"net0"}) {
		t.Errorf("Pending = %q, want [net0]", op.Pending)
	}
}

// PostApply starts from nothing: a second call does not carry the first's
// findings over.
func TestVMFieldsEnsure_PostApply_ResetsItsFindings(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", pendingResults: []json.RawMessage{
		json.RawMessage(`[{"key":"cores","pending":4}]`),
		json.RawMessage(`[]`),
	}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Applied: []string{"cores"}}
	if err := op.PostApply(context.Background()); err != nil || !slices.Equal(op.Pending, []string{"cores"}) {
		t.Fatalf("first PostApply: %v, Pending %q", err, op.Pending)
	}
	if err := op.PostApply(context.Background()); err != nil || op.Pending != nil {
		t.Errorf("second PostApply: %v, Pending %q, want none", err, op.Pending)
	}
}
