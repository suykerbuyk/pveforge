package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

func TestVMFieldsEnsure_Validate(t *testing.T) {
	cases := []struct {
		name    string
		op      VMFieldsEnsure
		wantErr bool
	}{
		{"valid single field", VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4")}, false},
		{"valid multiple fields", VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4", "memory", "8192")}, false},
		{"zero vmid", VMFieldsEnsure{VMID: 0, Pairs: pairs("cores", "4")}, true},
		{"negative vmid", VMFieldsEnsure{VMID: -1, Pairs: pairs("cores", "4")}, true},
		{"no fields", VMFieldsEnsure{VMID: 100}, true},
		{"duplicate field name", VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4", "cores", "8")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.op.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVMFieldsEnsure_Apply_RejectsInvalidOpBeforeTouchingClient(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "cores", "8")}

	if err := op.Apply(context.Background()); err == nil {
		t.Fatal("expected a validation error")
	}
	if client.rawRequestCalls != 0 || client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 {
		t.Error("Client must not be touched when validation fails")
	}
}

// TestVMFieldsEnsure_Read_CoercesJSONTypedValuesToComparableStrings
// proves Read uses kvjson.Scalar — not a plain string-unmarshal — so a
// PVE field that comes back JSON-typed (e.g. "cores" as a bare number,
// not a quoted string) still compares correctly against a wanted value
// that's always a plain CLI string. This is the whole reason Read goes
// through the raw config endpoint instead of a hand-rolled per-field
// lookup: go-proxmox's typed struct wouldn't expose an arbitrary field
// like this at all.
func TestVMFieldsEnsure_Read_CoercesJSONTypedValuesToComparableStrings(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1","cores":4,"name":"web-01","protection":true}`),
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "name", "web-01", "protection", "true")}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	var m map[string]string
	if err := json.Unmarshal([]byte(current), &m); err != nil {
		t.Fatalf("unmarshal returned current: %v", err)
	}
	if m["cores"] != "4" {
		t.Errorf(`m["cores"] = %q, want "4" (a JSON number coerced to bare text)`, m["cores"])
	}
	if m["name"] != "web-01" {
		t.Errorf(`m["name"] = %q, want "web-01" (a JSON string unquoted)`, m["name"])
	}
	if m["protection"] != "true" {
		t.Errorf(`m["protection"] = %q, want "true"`, m["protection"])
	}
	if client.lastRawMethod != "GET" {
		t.Errorf("expected a GET, got %q", client.lastRawMethod)
	}
	if client.lastRawPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("path = %q", client.lastRawPath)
	}
}

// TestVMFieldsEnsure_Read_MultilineValueUnescaped pins that Read compares
// the RAW value, never kv's display quoting: PVE stores a multi-line
// description, and a field whose value is the string "null" is legal. If
// kvjson.Scalar ever returned kv's quoted form, an already-correct value
// would read as different and be rewritten on every run.
func TestVMFieldsEnsure_Read_MultilineValueUnescaped(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1","description":"line1\nline2\n","name":"null"}`),
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("description", "line1\nline2\n", "name", "null")}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !op.Satisfied(current) {
		t.Fatalf("Satisfied(%s) = false for values already equal to the wanted ones", current)
	}
}

// TestVMFieldsEnsure_Read_FieldAbsentFromConfig proves a field never set
// on the VM is simply absent from Read's map, not an error and not a
// spurious empty-string entry.
func TestVMFieldsEnsure_Read_FieldAbsentFromConfig(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1"}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("description", "hello")}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(current), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["description"]; ok {
		t.Errorf("expected description to be absent from the map, got %v", m)
	}
}

func TestVMFieldsEnsure_Read_PropagatesRawRequestError(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestErr: errors.New("network down")}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4")}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("expected an error when RawRequest fails")
	}
}

func TestVMFieldsEnsure_Read_MissingDigestIsAnError(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"cores":4}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4")}

	_, err := op.Read(context.Background())
	if err == nil {
		t.Fatal("expected an error when the response carries no digest")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("expected the error to mention the missing digest, got: %v", err)
	}
}

func TestVMFieldsEnsure_Satisfied(t *testing.T) {
	op := &VMFieldsEnsure{Pairs: pairs("cores", "4", "memory", "8192")}

	if op.Satisfied(`{}`) {
		t.Error("empty current state should not satisfy")
	}
	if op.Satisfied(`{"cores":"4"}`) {
		t.Error("a partial match (one of two fields) should not satisfy")
	}
	if !op.Satisfied(`{"cores":"4","memory":"8192"}`) {
		t.Error("expected both matching fields to satisfy")
	}
	if op.Satisfied(`not json`) {
		t.Error("corrupted current state must read as unsatisfied, not panic or true")
	}
}

// TestVMFieldsEnsure_Satisfied_AbsentFieldNeverMatchesEmptyWantedValue is
// the regression test for a real, shipped bug: a plain map lookup can't
// distinguish "field absent from current config" from "field present but
// genuinely set to the empty string" — both read as Go's zero value ""
// for a missing key. On a VM that had never had e.g. "description" set,
// Satisfied incorrectly reported a description="" batch as already
// satisfied — the write the caller explicitly asked for never happened,
// and the command exited 0 as if it succeeded. An absent field must never
// be considered already-matching, regardless of what the wanted value is.
func TestVMFieldsEnsure_Satisfied_AbsentFieldNeverMatchesEmptyWantedValue(t *testing.T) {
	op := &VMFieldsEnsure{Pairs: pairs("description", "")}
	if op.Satisfied(`{}`) {
		t.Error("an absent field must never be considered already satisfied, even when the wanted value is empty")
	}
}

// TestVMFieldsEnsure_Satisfied_PresentEmptyValueStillMatchesEmptyWanted
// is the companion proof that the fix above is presence-aware, not just
// "reject everything empty": a field genuinely present with an empty
// value must still satisfy a wanted empty value.
func TestVMFieldsEnsure_Satisfied_PresentEmptyValueStillMatchesEmptyWanted(t *testing.T) {
	op := &VMFieldsEnsure{Pairs: pairs("description", "")}
	if !op.Satisfied(`{"description":""}`) {
		t.Error("expected a field genuinely present with an empty value to satisfy a wanted empty value")
	}
}

// TestVMFieldsEnsure_Apply_SkipsAlreadySatisfiedField proves a field
// already at its wanted value is never written — only the field that
// actually needs to change is — matching BridgeIsolationEnsure's own
// skip-if-already-correct precedent for its hookscript field.
func TestVMFieldsEnsure_Apply_SkipsAlreadySatisfiedField(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d2"}`), // field-write's own fresh digest re-fetch
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "name", "web-01")}
	op.current = map[string]string{"cores": "4", "name": "old-name"} // cores already matches; name doesn't

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 1 {
		t.Fatalf("expected exactly 1 CAS write (only for name), got %d", client.setFieldCalls)
	}
	if client.lastField != "name" || client.lastValue != "web-01" {
		t.Errorf("expected the write to be name=web-01, got %s=%s", client.lastField, client.lastValue)
	}
}

// TestVMFieldsEnsure_Apply_AbsentFieldNeverSkipped is Apply's half of the
// Satisfied regression above: op.current[p.Field] == p.Value used to
// treat an absent field as matching an empty wanted value (Go's zero
// value for a missing map key), silently skipping a write the caller
// explicitly asked for. An absent field must always be attempted.
func TestVMFieldsEnsure_Apply_AbsentFieldNeverSkipped(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d2"}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("description", "")}
	op.current = map[string]string{} // description never set — absent, not empty-string-present

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 1 {
		t.Fatalf("expected the write to actually be attempted for an absent field even with an empty wanted value, got %d CAS calls", client.setFieldCalls)
	}
	if client.lastField != "description" || client.lastValue != "" {
		t.Errorf(`expected description="" to be written, got field=%q value=%q`, client.lastField, client.lastValue)
	}
}

// TestVMFieldsEnsure_Apply_TracksActuallyWrittenFields is the regression
// test for the second shipped bug: Applied must be populated by Apply
// itself, from the writes it actually performs — not derivable after the
// fact from idempotent.Result's Before/After (which can't reconstruct
// "what got written" when idempotent.Run's own best-effort post-Apply
// re-read fails; see cmd/pveforge's own end-to-end regression test for
// why that distinction matters to a real caller).
func TestVMFieldsEnsure_Apply_TracksActuallyWrittenFields(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d2"}`),
			json.RawMessage(`{"digest":"d3"}`),
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "name", "web-01")}
	op.current = map[string]string{"name": "web-01"} // name already matches; cores doesn't

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(op.Applied) != 1 || op.Applied[0] != "cores" {
		t.Errorf("expected Applied = [cores] (name was skipped, already satisfied), got %v", op.Applied)
	}
}

// TestVMFieldsEnsure_Apply_ResetsAppliedOnEachCall proves Applied
// reflects only THIS Apply call's own writes, not a stale accumulation
// left over from a previous, abandoned attempt (e.g. a
// conflict-triggered retry re-invokes Read/Satisfied/Apply from scratch).
func TestVMFieldsEnsure_Apply_ResetsAppliedOnEachCall(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d2"}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4")}
	op.current = map[string]string{}
	op.Applied = []string{"stale", "leftover"}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(op.Applied) != 1 || op.Applied[0] != "cores" {
		t.Errorf("expected Applied to be reset and contain only cores, got %v", op.Applied)
	}
}

// TestVMFieldsEnsure_Apply_RefetchesFreshDigestPerField is the direct
// proof of correctness fix #1 (vault "Locking design", 2026-09-14): a
// multi-field batch must NOT reuse one digest across multiple CAS writes,
// since PVE's digest guards the whole config blob — the first write's own
// success already advances it server-side. Scripts THREE distinct
// digests (d1 at Read time, d2 for field one's write, d3 for field two's
// write) and proves each CAS call actually used its own freshly re-fetched
// digest, not Read's original d1 and not one write's digest reused for
// the next.
func TestVMFieldsEnsure_Apply_RefetchesFreshDigestPerField(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1"}`), // Read
			json.RawMessage(`{"digest":"d2"}`), // field "cores"'s own pre-write re-fetch
			json.RawMessage(`{"digest":"d3"}`), // field "memory"'s own pre-write re-fetch
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "memory", "8192")}

	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(client.casCalls) != 2 {
		t.Fatalf("expected 2 CAS writes, got %d: %+v", len(client.casCalls), client.casCalls)
	}
	if client.casCalls[0].field != "cores" || client.casCalls[0].digest != "d2" {
		t.Errorf("first write = %+v, want field cores with the freshly re-fetched digest d2 (not Read's d1)", client.casCalls[0])
	}
	if client.casCalls[1].field != "memory" || client.casCalls[1].digest != "d3" {
		t.Errorf("second write = %+v, want field memory with its OWN freshly re-fetched digest d3 (not d1 or d2 reused)", client.casCalls[1])
	}
	// 1 Read + 2 per-field re-fetches — proves a fresh fetch happened for
	// EVERY write, including the first, not just the second onward.
	if client.rawRequestCalls != 3 {
		t.Errorf("expected 3 RawRequest calls (1 Read + 2 re-fetches), got %d", client.rawRequestCalls)
	}
}

// TestVMFieldsEnsure_Apply_RootOnlyFieldNeverAttemptsCAS is the direct
// proof of correctness fix #2 (vault "Locking design", 2026-09-14): a
// field already registered in sshexec.RootOnlyFields must route straight
// to the plain (non-CAS) setter, WITHOUT ever calling
// SetVMConfigFieldCAS at all — RoutedClient.SetVMConfigFieldCAS refuses
// such a field locally with text that never trips
// sshexec.IsRootOnlyWriteError, so relying on that fallback (as
// BridgeIsolationEnsure's existing pattern does) would silently regress
// "args" instead of routing it over SSH as it does today.
func TestVMFieldsEnsure_Apply_RootOnlyFieldNeverAttemptsCAS(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("args", "-foo")}
	op.current = map[string]string{} // args not previously set

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 0 {
		t.Errorf("expected SetVMConfigFieldCAS to never be called for a root-only field, got %d calls", client.setFieldCalls)
	}
	if client.rawRequestCalls != 0 {
		t.Errorf("expected no digest re-fetch for a root-only field (CAS is never attempted), got %d RawRequest calls", client.rawRequestCalls)
	}
	if client.setFieldPlainCalls != 1 || client.lastPlainField != "args" || client.lastPlainValue != "-foo" {
		t.Errorf("expected exactly one plain SetVMConfigField(args, -foo), got calls=%d field=%q value=%q",
			client.setFieldPlainCalls, client.lastPlainField, client.lastPlainValue)
	}
}

// TestVMFieldsEnsure_Apply_NormalFieldAlongsideRootOnlyField proves a
// batch mixing an already-registered root-only field with an ordinary
// REST-writable field routes EACH correctly: the root-only field skips
// CAS entirely (see above), while the ordinary field still gets its full
// CAS protection (its own fresh digest re-fetch and CAS call) — one
// field's routing must not affect the other's.
func TestVMFieldsEnsure_Apply_NormalFieldAlongsideRootOnlyField(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d2"}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "args", "-foo")}
	op.current = map[string]string{}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 1 || client.lastField != "cores" || client.lastDigest != "d2" {
		t.Errorf("expected exactly one CAS write for cores with digest d2, got calls=%d field=%q digest=%q",
			client.setFieldCalls, client.lastField, client.lastDigest)
	}
	if client.setFieldPlainCalls != 1 || client.lastPlainField != "args" {
		t.Errorf("expected exactly one plain write for args, got calls=%d field=%q",
			client.setFieldPlainCalls, client.lastPlainField)
	}
}

// TestVMFieldsEnsure_Apply_UnregisteredRootOnlyFallback covers the
// "field not yet in the registry" safety net, distinct from the
// already-registered case above: PVE itself rejects a REST CAS write with
// "only root can set", which DOES trip sshexec.IsRootOnlyWriteError, so
// Apply must fall back to the plain setter — mirroring
// BridgeIsolationEnsure's own existing fallback for this exact scenario.
func TestVMFieldsEnsure_Apply_UnregisteredRootOnlyFallback(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d2"}`)},
		setFieldErrs:      []error{errors.New(`set vm 100 field "somefield": only root can set 'somefield' config`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("somefield", "x")}
	op.current = map[string]string{}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.setFieldCalls != 1 {
		t.Errorf("expected exactly 1 CAS attempt before falling back, got %d", client.setFieldCalls)
	}
	if client.setFieldPlainCalls != 1 || client.lastPlainField != "somefield" {
		t.Errorf("expected the plain-setter fallback to be used, got calls=%d field=%q",
			client.setFieldPlainCalls, client.lastPlainField)
	}
}

func TestVMFieldsEnsure_Apply_WrapsDigestConflictAsErrConflict(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d2"}`)},
		setFieldErrs:      []error{errors.New("update rejected: digest mismatch")},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4")}
	op.current = map[string]string{}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrConflict) {
		t.Errorf("expected ErrConflict, got: %v", err)
	}
}

// TestVMFieldsEnsure_Apply_StopsAtFirstNonConflictFailure preserves vm
// set's existing documented "stop at first failure, no rollback"
// contract: the second field fails with an ordinary (non-conflict, non
// root-only) error, so the third must never be attempted.
func TestVMFieldsEnsure_Apply_StopsAtFirstNonConflictFailure(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d2"}`),
			json.RawMessage(`{"digest":"d3"}`),
		},
		setFieldErrs: []error{nil, errors.New("permission denied")},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("a_field", "1", "b_field", "2", "c_field", "3")}
	op.current = map[string]string{}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrConflict) {
		t.Error("an unrelated failure must not be wrapped as ErrConflict")
	}
	if client.setFieldCalls != 2 {
		t.Fatalf("expected exactly 2 CAS attempts (a_field succeeds, b_field fails, c_field never attempted), got %d", client.setFieldCalls)
	}
}

// TestVMFieldsEnsure_ViaRun_EndToEnd_NoOp exercises the full stack this
// package provides for a batch that's already fully satisfied.
func TestVMFieldsEnsure_ViaRun_EndToEnd_NoOp(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","cores":4}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4")}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected a no-op: cores is already 4")
	}
	if client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 {
		t.Error("no write should be attempted on a no-op")
	}
}

// TestVMFieldsEnsure_ViaRun_EndToEnd_MultiField exercises a real
// multi-field batch under one lock.Mutation hold end to end, proving both
// fields get written with their own correctly re-fetched digests.
func TestVMFieldsEnsure_ViaRun_EndToEnd_MultiField(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1"}`), // Read: neither field set yet
			json.RawMessage(`{"digest":"d2"}`), // cores' own re-fetch
			json.RawMessage(`{"digest":"d3"}`), // memory's own re-fetch
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "memory", "8192")}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if len(client.casCalls) != 2 {
		t.Fatalf("expected 2 CAS writes, got %d", len(client.casCalls))
	}
	if client.casCalls[0].digest == client.casCalls[1].digest {
		t.Errorf("expected each field to use its OWN freshly re-fetched digest, got the same digest %q for both", client.casCalls[0].digest)
	}
}

// TestVMFieldsEnsure_ViaRun_EndToEnd_ConflictThenSuccess_ResumesNotRedoes
// proves the retry-composes-correctly property this design depends on: a
// conflict on the SECOND field (after the first already succeeded)
// causes Run to retry the whole cycle from Read, but because Satisfied/
// Apply are field-aware, the retry's Apply must NOT re-write the first
// field again — it resumes from wherever the batch left off.
func TestVMFieldsEnsure_ViaRun_EndToEnd_ConflictThenSuccess_ResumesNotRedoes(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1"}`),             // first Read: neither field set
			json.RawMessage(`{"digest":"d2"}`),             // cores' re-fetch, first attempt
			json.RawMessage(`{"digest":"d3"}`),             // memory's re-fetch, first attempt (conflicts)
			json.RawMessage(`{"digest":"d4","cores":"4"}`), // retry's Read: cores already applied
			json.RawMessage(`{"digest":"d5"}`),             // memory's re-fetch, second attempt (succeeds)
		},
		setFieldErrs: []error{
			nil, // cores: succeeds
			errors.New("digest mismatch: concurrent change"), // memory: conflicts
			nil, // memory retry: succeeds
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "memory", "8192")}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true")
	}
	if len(client.casCalls) != 3 {
		t.Fatalf("expected 3 CAS attempts (cores once, memory twice), got %d: %+v", len(client.casCalls), client.casCalls)
	}
	coresAttempts := 0
	for _, c := range client.casCalls {
		if c.field == "cores" {
			coresAttempts++
		}
	}
	if coresAttempts != 1 {
		t.Errorf("expected cores to be written exactly once across both attempts (never redone after the retry), got %d", coresAttempts)
	}
}

// TestVMFieldsEnsure_ReadThenSatisfied_BooleanShapedFieldConverges is the
// VM-config analogue of NetworkFieldsEnsure's own
// TestNetworkFieldsEnsure_ReadThenSatisfied_VLANFilteringBooleanCoercion
// (networkfields_test.go): PVE's raw JSON boolean true, coerced by
// kvjson.Scalar (via Read) into the literal text "true", must still
// converge against a caller-supplied PVE-CLI-conventional "1" once it
// reaches Satisfied. "protection" is a confirmed go-proxmox IntOrBool
// field (types.go:1026) — the same field
// TestVMFieldsEnsure_Read_CoercesJSONTypedValuesToComparableStrings above
// already fixtures as PVE-boolean-true. Before Satisfied called
// fieldsEqual (boolish.go), this case failed forever: "true" != "1".
func TestVMFieldsEnsure_ReadThenSatisfied_BooleanShapedFieldConverges(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","protection":true}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("protection", "1")}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !op.Satisfied(current) {
		t.Fatal("expected satisfied: PVE JSON bool true should converge with caller-supplied \"1\"")
	}
}

// TestVMFieldsEnsure_ViaRun_EndToEnd_BooleanFieldAlreadyCorrectIsNoOp is the
// regression test for the user-visible behavior change this fix ships:
// before Satisfied called fieldsEqual, `vm set protection=1` against a VM
// PVE already reports as "protection":true returned Changed:true and
// issued a redundant CAS write on EVERY invocation (the old plain !=
// compare: "true" != "1"). Reverting Satisfied to that plain compare must
// make this test fail.
func TestVMFieldsEnsure_ViaRun_EndToEnd_BooleanFieldAlreadyCorrectIsNoOp(t *testing.T) {
	client := &fakeClient{
		node:              "qa-pve-01",
		rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","protection":true}`)},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("protection", "1")}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Changed {
		t.Error("expected Changed=false: protection is already true, matching caller-supplied \"1\"")
	}
	if client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 {
		t.Error("no write should be attempted: the field is already correct once boolean-shaped tokens are recognized as equal")
	}
}

// TestVMFieldsEnsure_ViaRun_EndToEnd_ApplySkipsAlreadyCorrectBooleanFieldInMixedBatch
// is the regression test for the second, more severe instance of the same
// bug: a multi-field batch where ONE field ("cores") genuinely needs a
// write, so Satisfied correctly returns false for the whole batch and
// Apply runs — but Apply's OWN per-field skip-check must still recognize
// that the OTHER field ("protection") is already correct in a different
// token form and must NOT re-write it. Before this fix, Apply's skip-check
// used a plain == and issued a needless CAS write against a live VM's
// config for "protection" on every such batch — a mutation nobody asked
// for, not just a wasted read. Asserts the CAS call COUNT (exactly one,
// for cores only), not merely the absence of an error: the count is the
// observable that distinguishes this bug from its fix.
func TestVMFieldsEnsure_ViaRun_EndToEnd_ApplySkipsAlreadyCorrectBooleanFieldInMixedBatch(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1","cores":2,"protection":true}`), // Read
			json.RawMessage(`{"digest":"d2"}`),                             // cores' own fresh-digest re-fetch
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4", "protection", "1")}
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	res, err := Run(context.Background(), testRosterPath(t), key, op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true: cores genuinely needs a write")
	}
	if len(client.casCalls) != 1 {
		t.Fatalf("expected exactly 1 CAS write (cores only; protection already matches via fieldsEqual), got %d: %+v", len(client.casCalls), client.casCalls)
	}
	if client.casCalls[0].field != "cores" {
		t.Errorf("expected the single CAS write to be for cores, got field %q", client.casCalls[0].field)
	}
}

// pairs is a small test helper building []kvjson.Pair from alternating
// field/value strings.
func pairs(fieldValue ...string) []kvjson.Pair {
	if len(fieldValue)%2 != 0 {
		panic("pairs: odd number of arguments")
	}
	out := make([]kvjson.Pair, 0, len(fieldValue)/2)
	for i := 0; i < len(fieldValue); i += 2 {
		out = append(out, kvjson.Pair{Field: fieldValue[i], Value: fieldValue[i+1]})
	}
	return out
}
