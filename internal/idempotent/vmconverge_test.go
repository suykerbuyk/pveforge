package idempotent

import (
	"reflect"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// TestBuildFieldsEnsure_OrderDeterminism asserts the returned Pairs is
// directly in ascending Field order for a 4-key desired map. This asserts
// sorted CONTENT, deliberately not "call BuildFieldsEnsure twice and diff":
// Go randomizes map iteration order per range, so a run-twice-equal check
// would only sometimes catch a removed sort.Strings call. Asserting the
// actual order fails deterministically whenever the sort is removed or
// broken.
func TestBuildFieldsEnsure_OrderDeterminism(t *testing.T) {
	desired := map[string]string{
		"name":       "web-01",
		"cores":      "4",
		"memory":     "8192",
		"agent":      "1",
		"protection": "0",
	}
	op, err := BuildFieldsEnsure(&fakeClient{node: "qa-pve-01"}, 100, desired)
	if err != nil {
		t.Fatalf("BuildFieldsEnsure: %v", err)
	}
	for i := 1; i < len(op.Pairs); i++ {
		if op.Pairs[i-1].Field >= op.Pairs[i].Field {
			t.Fatalf("Pairs not in ascending Field order: %q at index %d is not < %q at index %d (full: %+v)",
				op.Pairs[i-1].Field, i-1, op.Pairs[i].Field, i, op.Pairs)
		}
	}
}

// TestBuildFieldsEnsure_FieldValueFidelity asserts the exact resulting
// Pairs slice (content, not just length or field count) for a known
// desired map.
func TestBuildFieldsEnsure_FieldValueFidelity(t *testing.T) {
	desired := map[string]string{
		"cores":  "4",
		"memory": "8192",
		"name":   "web-01",
	}
	want := []kvjson.Pair{
		{Field: "cores", Value: "4"},
		{Field: "memory", Value: "8192"},
		{Field: "name", Value: "web-01"},
	}

	op, err := BuildFieldsEnsure(&fakeClient{node: "qa-pve-01"}, 100, desired)
	if err != nil {
		t.Fatalf("BuildFieldsEnsure: %v", err)
	}
	if !reflect.DeepEqual(op.Pairs, want) {
		t.Fatalf("Pairs = %+v, want %+v", op.Pairs, want)
	}
}

// TestBuildFieldsEnsure_RejectsEmptyDesired proves an empty desired map is
// rejected at construction time — before any VMFieldsEnsure is even
// touched — via VMFieldsEnsure.Validate()'s own existing "at least one
// field is required" check, not a second, message-duplicating check.
func TestBuildFieldsEnsure_RejectsEmptyDesired(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}

	op, err := BuildFieldsEnsure(client, 100, map[string]string{})
	if err == nil {
		t.Fatal("expected an error for an empty desired map")
	}
	if !strings.Contains(err.Error(), "at least one field") {
		t.Errorf("error = %q, want it to mention \"at least one field\"", err.Error())
	}
	if op != nil {
		t.Error("expected a nil Op on error")
	}
	if client.rawRequestCalls != 0 || client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 {
		t.Error("Client must not be touched when construction fails validation")
	}
}

// TestBuildFieldsEnsure_VMIDValidated proves a non-positive vmid is
// rejected via VMFieldsEnsure.Validate()'s own existing check, and that a
// valid vmid lands on the returned Op unchanged.
func TestBuildFieldsEnsure_VMIDValidated(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}

	if _, err := BuildFieldsEnsure(client, 0, map[string]string{"cores": "4"}); err == nil {
		t.Fatal("expected an error for vmid=0")
	} else if !strings.Contains(err.Error(), "vmid must be positive") {
		t.Errorf("error = %q, want it to mention \"vmid must be positive\"", err.Error())
	}

	op, err := BuildFieldsEnsure(client, 100, map[string]string{"cores": "4"})
	if err != nil {
		t.Fatalf("BuildFieldsEnsure: %v", err)
	}
	if op.VMID != 100 {
		t.Errorf("VMID = %d, want 100", op.VMID)
	}
}

// TestBuildFieldsEnsure_ClientPropagated proves the returned Op's Client
// is the same instance passed in, not a copy or a different value.
func TestBuildFieldsEnsure_ClientPropagated(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01"}

	op, err := BuildFieldsEnsure(client, 100, map[string]string{"cores": "4"})
	if err != nil {
		t.Fatalf("BuildFieldsEnsure: %v", err)
	}
	if op.Client != client {
		t.Error("expected the returned Op's Client to be the same instance passed in")
	}
}

// No test for a duplicate-field collision: unlike `vm set`'s ordered CLI
// args, a Go map[string]string cannot hold two entries with the same key
// — the collision VMFieldsEnsure.Validate() guards against is structurally
// unreachable from BuildFieldsEnsure's own input type, not merely untested.
