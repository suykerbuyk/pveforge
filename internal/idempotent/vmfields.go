package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// VMFieldsEnsure is idempotent-mutation-engine's Op for `vm set`
// (pveforge-vm-set-unlocked): ensure VMID's config holds every field in
// Pairs at its given value, as ONE Read/Satisfied/Apply cycle under a
// single lock.Mutation hold for the whole batch — see this task's own
// vault record ("Locking design", 2026-09-14) for why one Op for the
// whole batch was chosen over one Op per field (the latter would reopen a
// race window BETWEEN fields within a single invocation, since each
// field's lock would release before the next acquires).
//
// Unlike VMTagEnsure/BridgeIsolationEnsure (each modeling ONE fixed,
// go-proxmox-typed field), VMFieldsEnsure's fields are arbitrary
// caller-supplied names — vm set is deliberately the raw, schema-free
// write PRD §3.3 calls for ("nothing about our exotic device
// configuration is fought by an opinionated schema"). That's why Read
// below goes through Client.RawRequest rather than Client.GetVM:
// go-proxmox's typed VirtualMachineConfig only models a fixed, curated
// subset of PVE's actual config keys, so it cannot answer "what is field
// X's current value" for an arbitrary name the way this Op's Satisfied
// check needs — a raw GET of the same /config endpoint the write side
// already targets is the only mechanism correct for ANY field, known to
// go-proxmox's struct or not.
type VMFieldsEnsure struct {
	Client Client
	VMID   int
	// Pairs are the field=value pairs to ensure, in caller order —
	// Apply iterates them in this order (preserving vm set's existing
	// documented "stop at first failure" contract), even though Read/
	// Satisfied's own comparable-state representation is an
	// order-independent map.
	Pairs []kvjson.Pair

	// current is set by Read and consumed by Apply to skip a field
	// already at its wanted value — refreshed on every attempt, including
	// a Run-driven retry after ErrConflict.
	current map[string]string

	// Applied is the field names Apply actually wrote, in write order —
	// reset at the start of every Apply call and populated as each write
	// succeeds (never derived after the fact from Before/After diffing:
	// idempotent.Run's own best-effort post-Apply re-read can fail while
	// leaving Changed true and After==Before, which would make a diff-
	// based reconstruction silently report nothing for a real, successful
	// write — see cmd/pveforge's own regression test for this). Exported
	// so cmd/pveforge's RunE can report exactly what this Op wrote,
	// without idempotent.Run's Result type needing to know anything
	// field-shaped.
	Applied []string
}

// Validate reports whether op is well-formed: VMID must be positive, at
// least one field must be given, and no field name may repeat.
//
// Rejecting a duplicate field name (rather than silently applying it
// twice, as today's direct-write vm set does) is a deliberate behavior
// change: under this Op's map-based Satisfied snapshot, a repeated field
// name is a genuine ambiguity, not just redundancy — the map collapses to
// "last value wins" for the Satisfied comparison, while Apply's ordered
// iteration would still attempt to write BOTH values in sequence. Rather
// than carry that mismatch forward, it's refused outright (recorded
// decision, pveforge-vm-set-unlocked, 2026-09-14).
func (op *VMFieldsEnsure) Validate() error {
	if op.VMID <= 0 {
		return fmt.Errorf("vm fields ensure: vmid must be positive, got %d", op.VMID)
	}
	if len(op.Pairs) == 0 {
		return fmt.Errorf("vm fields ensure: vm %d: at least one field is required", op.VMID)
	}
	seen := make(map[string]bool, len(op.Pairs))
	for _, p := range op.Pairs {
		if seen[p.Field] {
			return fmt.Errorf("vm fields ensure: vm %d: field %q specified more than once", op.VMID, p.Field)
		}
		seen[p.Field] = true
	}
	return nil
}

// Read fetches vmid's current raw config (see this type's own doc
// comment on why RawRequest, not GetVM) and records each requested
// field's current value — via kvjson.Scalar, so a PVE field that comes
// back JSON-typed (e.g. "cores" as a number, not a string) still compares
// correctly against a wanted value that's always a plain CLI string —
// for Satisfied/Apply. A field absent from the current config (never
// set) is simply absent from the returned map, which Satisfied/Apply
// treat as not matching any non-empty wanted value.
func (op *VMFieldsEnsure) Read(ctx context.Context) (string, error) {
	snap, err := op.readConfig(ctx)
	if err != nil {
		return "", err
	}

	current := make(map[string]string, len(op.Pairs))
	for _, p := range op.Pairs {
		raw, ok := snap.fields[p.Field]
		if !ok {
			continue
		}
		s, err := kvjson.Scalar(raw)
		if err != nil {
			return "", fmt.Errorf("vm fields ensure: vm %d: field %q: %w", op.VMID, p.Field, err)
		}
		current[p.Field] = s
	}
	op.current = current

	b, err := json.Marshal(current)
	if err != nil {
		return "", fmt.Errorf("vm fields ensure: vm %d: encode current state: %w", op.VMID, err)
	}
	return string(b), nil
}

// Satisfied reports whether every requested field's current value
// already equals its wanted value — AND across fields, matching
// BridgeIsolationEnsure's own multi-dimension pattern: any one mismatch
// means the whole batch is not yet satisfied, so Apply runs (and itself
// skips only the fields that already match — see Apply).
//
// Uses the two-value map form deliberately: a plain m[p.Field] != p.Value
// comparison can't distinguish "field absent from current config" from
// "field present but genuinely set to the empty string" — both read as
// Go's zero value "" for a missing key. That ambiguity was a real,
// shipped bug: on a VM that had never had e.g. "description" set,
// Satisfied incorrectly reported a description="" batch as already
// satisfied, the write the caller explicitly asked for never happened,
// and the command exited 0 as if it succeeded. An absent field can never
// be considered already-matching, full stop — there is no way for a
// caller to ask this command for "leave it absent" in the first place, so
// treating absence as unconditionally unsatisfied loses nothing.
//
// Compares a present field via fieldsEqual (boolish.go, shared with
// NetworkFieldsEnsure as of pveforge-vm-converge-fields, 2026-09-16), not a
// plain ==: a boolean-shaped field (protection, onboot, template, and the
// other go-proxmox IntOrBool fields) can come back from PVE as a JSON bool
// while a caller types the PVE-CLI-conventional "1"/"0" — kvjson.Scalar
// (this Op's Read) has no normalization for that, and before this fix a
// plain != here meant such a field could never converge: Apply rewrote it
// on every single invocation, forever, even when it was already correct.
func (op *VMFieldsEnsure) Satisfied(current string) bool {
	var m map[string]string
	if err := json.Unmarshal([]byte(current), &m); err != nil {
		// Corrupted input reads as unsatisfied (safe to fail toward
		// re-Apply), matching parseBridgeIsolationState's own contract —
		// Satisfied has no error return to report this any other way.
		return false
	}
	for _, p := range op.Pairs {
		val, ok := m[p.Field]
		if !ok || !fieldsEqual(val, p.Value) {
			return false
		}
	}
	return true
}

// Apply validates op (see Validate), resets Applied (see that field's own
// doc comment), then iterates Pairs in order, skipping any field Read's
// snapshot already found matching (no wasted write on an already-correct
// field, matching BridgeIsolationEnsure's own hookscript
// skip-if-already-correct precedent) — via the two-value map form, same
// reasoning as Satisfied: a field absent from Read's snapshot must never
// be treated as already matching, even when the wanted value happens to
// be the empty string, since a plain map lookup can't tell "absent" from
// "present and empty" apart.
//
// This skip-check compares via fieldsEqual (boolish.go), not a plain ==,
// for the same reason Satisfied does (approved, pveforge-vm-converge-fields,
// 2026-09-16, under the standing "fix a real defect the moment it's found"
// rule): Satisfied can return false for the BATCH because one OTHER field
// genuinely needs a write, which means Apply runs for the whole batch — and
// before this fix, Apply's own per-field skip-check would then use a plain
// == and needlessly re-write a boolean-shaped field that was ALREADY
// correct in a different token form (e.g. current "true", wanted "1"). That
// is strictly worse than Satisfied's own bug: a needless read/compare cycle
// versus a needless CAS WRITE against a live VM's config — a mutation
// nobody asked for, an extra chance at a digest conflict, and noise in what
// the command reports as changed.
//
// Also applies the two correctness fixes this Op's whole design depends on
// (recorded, pveforge-vm-set-unlocked, "Locking design", 2026-09-14):
//
//  1. PVE's digest guards the WHOLE config blob, not one field — reusing
//     one digest (from Read, or from an earlier field's write in this
//     same Apply) across more than one CAS write would spuriously
//     conflict on the second write, not from real outside contention but
//     because the first write's own success already advanced PVE's
//     server-side digest. Fix: re-fetch a fresh digest (via readConfig,
//     never Read's original snapshot) immediately before EVERY REST-CAS
//     write, not just the second and later ones — simpler and uniformly
//     correct rather than special-casing "is this the first write."
//     Safe to do cheaply: the whole batch stays under one lock.Mutation
//     hold, so no other pveforge-managed mutation can interleave — a
//     conflict on a freshly re-fetched digest can only mean genuine
//     external interference (a different machine/roster, the PVE GUI),
//     exactly what digest-CAS exists to catch as defense-in-depth.
//  2. RoutedClient.SetVMConfigFieldCAS refuses LOCALLY, before any
//     network call, for any field already in sshexec.RootOnlyFields —
//     with a message deliberately not containing "only root can set", so
//     it can never trip sshexec.IsRootOnlyWriteError the way
//     BridgeIsolationEnsure's existing fallback expects. Naively copying
//     that fallback verbatim would silently regress a known root-only
//     field like "args": today it works transparently via
//     SetVMConfigField's own upfront sshexec.RootOnlyFields check. Fix:
//     Apply does that SAME upfront check itself — write via plain
//     SetVMConfigField (no CAS attempted at all) when the field is
//     already known root-only, and keep the IsRootOnlyWriteError
//     fallback as the safety net for a field not yet in that registry
//     (mirroring both existing precedents together, not just one).
//
// Stops at the first non-conflict error (preserving vm set's existing
// documented "stop at first failure, no rollback" contract) — a conflict
// instead returns an error wrapping ErrConflict so Run retries the WHOLE
// cycle from Read; because Satisfied/Apply are field-aware, that retry
// naturally resumes from wherever the batch left off rather than
// redoing already-applied fields.
func (op *VMFieldsEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}
	op.Applied = nil

	for _, p := range op.Pairs {
		if val, ok := op.current[p.Field]; ok && fieldsEqual(val, p.Value) {
			continue
		}

		if sshexec.RootOnlyFields[p.Field] {
			if err := op.Client.SetVMConfigField(ctx, op.VMID, p.Field, p.Value); err != nil {
				return fmt.Errorf("vm fields ensure: vm %d: set field %q: %w", op.VMID, p.Field, err)
			}
			op.Applied = append(op.Applied, p.Field)
			continue
		}

		snap, err := op.readConfig(ctx)
		if err != nil {
			return fmt.Errorf("vm fields ensure: vm %d: re-read digest before writing field %q: %w", op.VMID, p.Field, err)
		}

		if err := op.Client.SetVMConfigFieldCAS(ctx, op.VMID, p.Field, p.Value, snap.digest); err != nil {
			switch {
			case pve.IsDigestConflictError(err):
				return fmt.Errorf("vm fields ensure: vm %d: field %q: %w: %w", op.VMID, p.Field, ErrConflict, err)
			case sshexec.IsRootOnlyWriteError(err):
				if fallbackErr := op.Client.SetVMConfigField(ctx, op.VMID, p.Field, p.Value); fallbackErr != nil {
					return fmt.Errorf("vm fields ensure: vm %d: set field %q: rejected as root-only by rest, ssh fallback also failed: %w", op.VMID, p.Field, fallbackErr)
				}
			default:
				return fmt.Errorf("vm fields ensure: vm %d: set field %q: %w", op.VMID, p.Field, err)
			}
		}
		op.Applied = append(op.Applied, p.Field)
	}
	return nil
}

// vmConfigSnapshot is one point-in-time raw read of a VM's PVE config —
// shared by Read (to compare requested fields' current values) and by
// Apply (to re-fetch a fresh digest before every REST-CAS write; see
// Apply's own doc comment on why Read's digest can never be reused for
// that).
type vmConfigSnapshot struct {
	fields map[string]json.RawMessage
	digest string
}

// readConfig issues a raw GET against vmid's own /config endpoint (the
// same endpoint the write side already targets) and returns every field
// PVE reports plus the digest guarding the whole blob. Errors loudly if
// the response carries no digest at all, rather than silently proceeding
// with an empty one: an empty expectDigest disables CAS entirely
// (SetVMConfigFieldCAS's own doc comment), and a response missing digest
// signals something is already wrong with this read, better caught here
// — before any field in the batch is touched — than deep inside a later
// CAS write.
func (op *VMFieldsEnsure) readConfig(ctx context.Context) (vmConfigSnapshot, error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(op.Client.Node()), op.VMID)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return vmConfigSnapshot{}, fmt.Errorf("vm fields ensure: vm %d: read config: %w", op.VMID, err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return vmConfigSnapshot{}, fmt.Errorf("vm fields ensure: vm %d: read config: parse: %w", op.VMID, err)
	}

	var digest string
	if d, ok := fields["digest"]; ok {
		if err := json.Unmarshal(d, &digest); err != nil {
			return vmConfigSnapshot{}, fmt.Errorf("vm fields ensure: vm %d: read config: parse digest: %w", op.VMID, err)
		}
	}
	if digest == "" {
		return vmConfigSnapshot{}, fmt.Errorf("vm fields ensure: vm %d: read config: response carries no digest", op.VMID)
	}

	return vmConfigSnapshot{fields: fields, digest: digest}, nil
}
