package idempotent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Deleting a key is not writing it empty: these pin the Op's half of that —
// presence alone decides a delete, and a delete is sent with PVE's delete
// parameter under the same digest discipline as a write.

func TestVMFieldsEnsure_Validate_Deletes(t *testing.T) {
	for name, c := range map[string]struct {
		op      VMFieldsEnsure
		wantErr string
	}{
		"deletes only":               {VMFieldsEnsure{VMID: 100, Deletes: []string{"description"}}, ""},
		"set and delete, disjoint":   {VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4"), Deletes: []string{"description"}}, ""},
		"field both set and deleted": {VMFieldsEnsure{VMID: 100, Pairs: pairs("cores", "4"), Deletes: []string{"cores"}}, "both set and deleted"},
		"field deleted twice":        {VMFieldsEnsure{VMID: 100, Deletes: []string{"description", "description"}}, "deleted more than once"},
		"empty delete name":          {VMFieldsEnsure{VMID: 100, Deletes: []string{""}}, "must be named"},
		"nothing to set or delete":   {VMFieldsEnsure{VMID: 100}, "at least one field"},
	} {
		t.Run(name, func(t *testing.T) {
			err := c.op.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate = %v, want an error containing %q", err, c.wantErr)
			}
		})
	}
}

// TestVMFieldsEnsure_DeleteSatisfiedByAbsenceOnly: Read records a delete
// target only when present, and Satisfied accepts a delete only when the key
// is absent — a key present with an empty value is NOT deleted, and must
// not read as satisfied.
func TestVMFieldsEnsure_DeleteSatisfiedByAbsenceOnly(t *testing.T) {
	for name, c := range map[string]struct {
		config string
		want   bool
	}{
		"absent":              {`{"digest":"d1"}`, true},
		"present, empty":      {`{"digest":"d1","description":""}`, false},
		"present, non-empty":  {`{"digest":"d1","description":"x"}`, false},
		"present, JSON null":  {`{"digest":"d1","description":null}`, false},
		"present as a number": {`{"digest":"d1","description":0}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(c.config)}}
			op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"description"}}
			current, err := op.Read(context.Background())
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got := op.Satisfied(current); got != c.want {
				t.Errorf("Satisfied(%s) = %v, want %v", current, got, c.want)
			}
		})
	}
}

// TestVMFieldsEnsure_EmptyWriteNotSatisfiedByAbsence is the converse: an
// absent key does not satisfy a write of "", so "" still writes.
func TestVMFieldsEnsure_EmptyWriteNotSatisfiedByAbsence(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1"}`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("description", "")}
	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if op.Satisfied(current) {
		t.Error(`an absent key must not satisfy description=""`)
	}
}

// TestVMFieldsEnsure_Apply_DeletesPresentKeyWithFreshDigest: a present key
// is deleted with a digest re-read immediately before the delete, never
// Read's, and reported in Deleted — never in Applied.
func TestVMFieldsEnsure_Apply_DeletesPresentKeyWithFreshDigest(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","description":"x"}`), // Read
		json.RawMessage(`{"digest":"d2","description":"x"}`), // fresh digest before the delete
	}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"description"}}
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []deleteCall{{field: "description", digest: "d2", cas: true}}; !slices.Equal(client.deletes, want) {
		t.Errorf("deletes = %+v, want %+v", client.deletes, want)
	}
	if client.setFieldCalls != 0 || client.setFieldPlainCalls != 0 {
		t.Errorf("a delete must not be sent as a write: %d CAS writes, %d plain writes", client.setFieldCalls, client.setFieldPlainCalls)
	}
	if !slices.Equal(op.Deleted, []string{"description"}) || len(op.Applied) != 0 {
		t.Errorf("Deleted = %v, Applied = %v; want [description] and none", op.Deleted, op.Applied)
	}
}

// TestVMFieldsEnsure_Apply_SkipsAbsentKey: a key already absent — at Read,
// or on the fresh re-read — is not sent: what PVE does with a delete of an
// absent key is unverified, and there is nothing to do.
func TestVMFieldsEnsure_Apply_SkipsAbsentKey(t *testing.T) {
	for name, reads := range map[string][]string{
		"absent at Read":         {`{"digest":"d1"}`},
		"gone by the fresh read": {`{"digest":"d1","description":"x"}`, `{"digest":"d2"}`},
	} {
		t.Run(name, func(t *testing.T) {
			var raw []json.RawMessage
			for _, r := range reads {
				raw = append(raw, json.RawMessage(r))
			}
			client := &fakeClient{node: "qa-pve-01", rawRequestResults: raw}
			op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"description"}}
			if _, err := op.Read(context.Background()); err != nil {
				t.Fatalf("Read: %v", err)
			}
			if err := op.Apply(context.Background()); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(client.deletes) != 0 || len(op.Deleted) != 0 {
				t.Errorf("deletes sent = %+v, Deleted = %v; want none", client.deletes, op.Deleted)
			}
		})
	}
}

// TestVMFieldsEnsure_Apply_SkipsAbsentRootOnlyKey: a root-only key has no
// fresh re-read before its delete, so Read's record is the only thing that
// stops an absent one from being sent over SSH.
func TestVMFieldsEnsure_Apply_SkipsAbsentRootOnlyKey(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1"}`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"args"}}
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(client.deletes) != 0 || len(op.Deleted) != 0 {
		t.Errorf("deletes sent = %+v, Deleted = %v; want none", client.deletes, op.Deleted)
	}
}

// TestVMFieldsEnsure_Apply_RootOnlyDeleteGoesOverSSH: a root-only key has
// no CAS (the SSH vector has none), so it is deleted with the plain,
// SSH-routed delete and no digest read.
func TestVMFieldsEnsure_Apply_RootOnlyDeleteGoesOverSSH(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{json.RawMessage(`{"digest":"d1","args":"-cpu host"}`)}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"args"}}
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []deleteCall{{field: "args"}}; !slices.Equal(client.deletes, want) {
		t.Errorf("deletes = %+v, want %+v (plain, no CAS)", client.deletes, want)
	}
	if client.rawRequestCalls != 1 {
		t.Errorf("raw requests = %d, want only Read's: a root-only delete needs no digest", client.rawRequestCalls)
	}
}

// TestVMFieldsEnsure_Apply_DeleteErrors: a digest conflict is ErrConflict
// (Run retries); PVE's root-only refusal falls back to the SSH delete once;
// anything else stops the batch with its own error.
func TestVMFieldsEnsure_Apply_DeleteErrors(t *testing.T) {
	present := []json.RawMessage{json.RawMessage(`{"digest":"d1","hookscript":"x"}`), json.RawMessage(`{"digest":"d2","hookscript":"x"}`)}

	t.Run("digest conflict", func(t *testing.T) {
		client := &fakeClient{node: "qa-pve-01", rawRequestResults: present, deleteCASErrs: []error{errors.New("pve returned 500: config digest mismatch")}}
		op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"hookscript"}}
		_, _ = op.Read(context.Background())
		if err := op.Apply(context.Background()); !errors.Is(err, ErrConflict) {
			t.Errorf("Apply = %v, want ErrConflict", err)
		}
	})
	t.Run("root-only refusal falls back to SSH", func(t *testing.T) {
		client := &fakeClient{node: "qa-pve-01", rawRequestResults: present, deleteCASErrs: []error{errors.New("pve returned 500: only root can set 'hookscript' config")}}
		op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"hookscript"}}
		_, _ = op.Read(context.Background())
		if err := op.Apply(context.Background()); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		// Straight to SSH after the refusal: no plain (REST-first) delete.
		if want := []deleteCall{{field: "hookscript", digest: "d2", cas: true}, {field: "hookscript", overSSH: true}}; !slices.Equal(client.deletes, want) {
			t.Errorf("deletes = %+v, want %+v", client.deletes, want)
		}
		if !slices.Equal(op.Deleted, []string{"hookscript"}) {
			t.Errorf("Deleted = %v", op.Deleted)
		}
	})
	t.Run("other error stops the batch", func(t *testing.T) {
		client := &fakeClient{node: "qa-pve-01", rawRequestResults: present, deleteCASErrs: []error{errors.New("pve returned 500: boom")}}
		op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"hookscript"}}
		_, _ = op.Read(context.Background())
		err := op.Apply(context.Background())
		if err == nil || errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "boom") {
			t.Errorf("Apply = %v, want the original error, not a conflict", err)
		}
		if len(op.Deleted) != 0 {
			t.Errorf("Deleted = %v, want none", op.Deleted)
		}
	})
}

// TestVMFieldsEnsure_Apply_SetsBeforeDeletes: deletes run after every
// write, whatever order the caller named them in.
func TestVMFieldsEnsure_Apply_SetsBeforeDeletes(t *testing.T) {
	client := &fakeClient{node: "qa-pve-01", rawRequestResults: []json.RawMessage{
		json.RawMessage(`{"digest":"d1","description":"x"}`),
		json.RawMessage(`{"digest":"d2","description":"x"}`),
		json.RawMessage(`{"digest":"d3","description":"x"}`),
	}}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("cores", "4"), Deletes: []string{"description"}}
	if _, err := op.Read(context.Background()); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(client.casCalls) != 1 || client.casCalls[0].digest != "d2" {
		t.Fatalf("writes = %+v, want the one write first, on d2", client.casCalls)
	}
	if want := []deleteCall{{field: "description", digest: "d3", cas: true}}; !slices.Equal(client.deletes, want) {
		t.Errorf("deletes = %+v, want %+v (after the write, on its own fresh digest)", client.deletes, want)
	}
}

// Through Run: a batch whose second field hits a digest conflict is retried
// from Read, and the retry skips the first field (already done). What the
// Op reports afterwards must still include that first field — it was
// written (or removed) on the first attempt.

func TestVMFieldsEnsure_Run_MidBatchConflictKeepsEarlierWrites(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1"}`),                 // Run's Read, attempt 1
			json.RawMessage(`{"digest":"d1"}`),                 // fresh digest for a
			json.RawMessage(`{"digest":"d2","a":"1"}`),         // fresh digest for b: conflicts
			json.RawMessage(`{"digest":"d3","a":"1"}`),         // Run's Read, attempt 2
			json.RawMessage(`{"digest":"d3","a":"1"}`),         // fresh digest for b
			json.RawMessage(`{"digest":"d4","a":"1","b":"2"}`), // Run's re-read
		},
		setFieldErrs: []error{nil, errors.New("update rejected: digest mismatch"), nil},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Pairs: pairs("a", "1", "b", "2")}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil || !res.Changed {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if client.setFieldCalls != 3 {
		t.Fatalf("CAS writes = %d, want 3 (a, b conflicting, b again)", client.setFieldCalls)
	}
	if want := []string{"a", "b"}; !slices.Equal(op.Applied, want) {
		t.Errorf("Applied = %v, want %v: a was written on the first attempt", op.Applied, want)
	}
}

func TestVMFieldsEnsure_Run_MidBatchConflictKeepsEarlierDeletes(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d1","a":"x","b":"y"}`), // Run's Read, attempt 1
			json.RawMessage(`{"digest":"d1","a":"x","b":"y"}`), // fresh digest for a
			json.RawMessage(`{"digest":"d2","b":"y"}`),         // fresh digest for b: conflicts
			json.RawMessage(`{"digest":"d3","b":"y"}`),         // Run's Read, attempt 2
			json.RawMessage(`{"digest":"d3","b":"y"}`),         // fresh digest for b
			json.RawMessage(`{"digest":"d4"}`),                 // Run's re-read
		},
		deleteCASErrs: []error{nil, errors.New("update rejected: digest mismatch"), nil},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"a", "b"}}
	res, err := Run(context.Background(), testRosterPath(t), testKey(), op, false)
	if err != nil || !res.Changed {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	if len(client.deletes) != 3 {
		t.Fatalf("deletes = %+v, want 3 (a, b conflicting, b again)", client.deletes)
	}
	if want := []string{"a", "b"}; !slices.Equal(op.Deleted, want) {
		t.Errorf("Deleted = %v, want %v: a was removed on the first attempt", op.Deleted, want)
	}
}

// TestVMFieldsEnsure_Apply_AccumulatesDeletedAcrossAttempts is the delete
// twin of ...AccumulatesAppliedAcrossAttempts: a key an earlier attempt of
// this Run removed stays reported, and a key removed on both attempts (it
// reappeared in between) is listed once.
func TestVMFieldsEnsure_Apply_AccumulatesDeletedAcrossAttempts(t *testing.T) {
	client := &fakeClient{
		node: "qa-pve-01",
		rawRequestResults: []json.RawMessage{
			json.RawMessage(`{"digest":"d2","a":"x","b":"y"}`), // fresh digest for a
			json.RawMessage(`{"digest":"d3","b":"y"}`),         // fresh digest for b
		},
	}
	op := &VMFieldsEnsure{Client: client, VMID: 100, Deletes: []string{"a", "b"}}
	op.current = map[string]string{"a": "x", "b": "y"} // a reappeared since the earlier attempt
	op.Deleted = []string{"a"}                         // removed by an earlier attempt of this Run

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(client.deletes) != 2 {
		t.Fatalf("deletes = %+v, want a and b sent", client.deletes)
	}
	if want := []string{"a", "b"}; !slices.Equal(op.Deleted, want) {
		t.Errorf("Deleted = %v, want %v (earlier deletes kept, each key once)", op.Deleted, want)
	}
}
