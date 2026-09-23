// Package idempotent is pveforge-idempotent-mutation-engine's
// read-compare-mutate orchestration layer (PRD §3.4): every mutating
// command reads current state, no-ops ("already satisfied") if it already
// matches what's wanted, or mutates and reports what changed. --force
// bypasses the no-op check and re-applies unconditionally.
//
// This package bridges internal/lock's per-object serialization primitive
// with that contract: Run acquires the object's lock for the WHOLE
// cycle, so a concurrent reader never observes a state this mutation is
// still in the middle of changing, and so two concurrent mutations
// against the same object never interleave.
//
// Deliberately generic and PVE-agnostic — Op is a plain three-method
// contract; concrete implementations (e.g. VMTagEnsure) live alongside
// this package and hold whatever client/target/parameters they need
// internally. Run has no knowledge of VMs, config fields, or PVE's
// digest-CAS mechanism; an Op whose Apply targets a REST-writable field
// is responsible for its own digest-CAS retry (see ErrConflict below),
// using internal/pve's *CAS write methods — Ops that can't use CAS (SSH-
// routed root-only fields) simply don't signal ErrConflict and are never
// retried.
package idempotent

import (
	"context"
	"errors"
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// Op is one idempotent mutation. Implementations are typically stateful
// (a pointer receiver that records what Read observed, consumed by
// Satisfied and Apply on the same call) — Run calls Read/Satisfied/Apply
// on the same Op value throughout one cycle, including across a
// conflict-triggered retry (see ErrConflict).
type Op interface {
	// Read returns a comparable snapshot of current state. Called at the
	// start of every attempt (including a retry after ErrConflict), so an
	// implementation backed by a live read (e.g. GetVM) always reflects
	// the latest state before Satisfied/Apply run again.
	Read(ctx context.Context) (current string, err error)
	// Satisfied reports whether current already matches what's wanted.
	// Run skips Apply and reports Result{Changed: false} when this
	// returns true, unless force is set.
	Satisfied(current string) bool
	// Apply performs the actual mutation. If the underlying write was
	// rejected specifically because a compare-and-swap guard detected a
	// concurrent modification (e.g. a PVE digest mismatch —
	// pve.IsDigestConflictError), Apply should return an error wrapping
	// ErrConflict so Run retries the whole cycle instead of propagating
	// a terminal failure.
	Apply(ctx context.Context) error
}

// PostApplier is implemented by an Op that can check its own effect after
// a successful Apply — something only the Op can judge. A generic check
// (re-evaluating Satisfied on the re-read) cannot: VMCreate and VMClone read
// any error as "absent", so an unreadable re-read would turn a create that
// succeeded into a failure; PVE canonicalises some written values (net0
// gains a MAC, disk specs are rewritten), so an exact-string Satisfied is
// false right after a correct write; and the network Ops already verify
// inside Apply. Each Op that does not implement it says why on its type.
//
// Run calls PostApply at most once per Run: after an Apply that succeeded,
// after the final re-read, still under the object's lock — never on a
// no-op, never after a failed Apply, never on an attempt a conflict retry
// superseded. Its error is advisory, like a failed re-read: the mutation
// already happened, so it is reported in Result.PostApplyErr and never
// fails the Run. What the check found is recorded on the Op itself, the
// way VMFieldsEnsure records Applied, so Result stays field-agnostic.
type PostApplier interface {
	PostApply(ctx context.Context) error
}

// ErrConflict, when an Op's Apply returns an error wrapping this (via
// %w), tells Run the failure was a detected concurrent-modification
// conflict rather than a terminal one — Run responds by re-running the
// full Read/Satisfied/Apply cycle (up to maxConflictRetries times) instead
// of propagating the error, so a real conflict resolves itself the same
// way a human re-running the command would. An Op with no compare-and-
// swap mechanism available (e.g. a root-only field written over SSH,
// where internal/pve's digest-CAS doesn't apply at all) simply never
// returns this and is never retried by Run.
var ErrConflict = errors.New("idempotent: concurrent modification detected")

// maxConflictRetries bounds how many times Run re-runs the cycle after a
// conflict before giving up — a small, fixed bound rather than an
// unbounded retry loop, since internal/lock's own per-object
// serialization already prevents the vast majority of conflicts from ever
// happening in the first place (this path exists for races outside that
// lock's reach — see internal/pve's digest-CAS doc comments); a conflict
// that recurs past this many retries is more likely a genuine, persistent
// disagreement than transient contention, and should surface rather than
// retry forever.
const maxConflictRetries = 3

// Result reports what Run did.
type Result struct {
	// Changed reports whether Apply actually ran (false for a no-op).
	Changed bool
	// Before and After are Op.Read's string rendering of state at the
	// start and end of the cycle — After equals Before on a no-op (or
	// when Apply's own success can't be independently re-observed; see
	// AfterErr and Run's own doc comment on the best-effort re-read).
	Before, After string
	// AfterErr is non-nil only when Apply succeeded but Run's final
	// re-read failed: it wraps that read's cause, and After then holds
	// Before's value rather than re-observed state. It never fails the
	// Run — the mutation already happened — so a caller that reports
	// current state decides for itself how to say it was not re-read.
	AfterErr error
	// PostApplyErr is non-nil only when the Op is a PostApplier, Apply
	// succeeded, and PostApply then failed: it wraps that check's cause.
	// Like AfterErr it never fails the Run — the mutation already
	// happened — and the caller decides how to report it.
	PostApplyErr error
}

// Run acquires key's mutation lock (scoped to rosterPath, via
// internal/lock.Mutation), then executes op's read-compare-mutate cycle
// under it: Read current state; if Satisfied and not force, return a
// no-op Result without ever calling Apply; otherwise Apply, then
// best-effort Read again to report the new state (a failure on this final
// read does not undo or fail an otherwise-successful Apply — Result.After
// falls back to reporting the same value as Result.Before, since the
// mutation itself already succeeded, and Result.AfterErr carries the
// read's cause). If op is a PostApplier, its PostApply then runs once,
// still under the lock; its failure is Result.PostApplyErr, advisory.
//
// If Apply fails with an error wrapping ErrConflict, Run re-runs the
// entire cycle from Read, up to maxConflictRetries times, before giving
// up and returning the last conflict error — the lock is held across
// every retry, so no other pveforge-managed mutation can interleave with
// this one, whatever caused the conflict lives outside internal/lock's
// own reach.
func Run(ctx context.Context, rosterPath string, key lock.ObjectKey, op Op, force bool) (Result, error) {
	unlock, err := lock.Mutation(ctx, rosterPath, key)
	if err != nil {
		return Result{}, fmt.Errorf("idempotent: %s: %w", key, err)
	}
	defer func() { _ = unlock() }()

	var result Result
	for attempt := 1; ; attempt++ {
		current, err := op.Read(ctx)
		if err != nil {
			return Result{}, fmt.Errorf("idempotent: %s: read: %w", key, err)
		}
		result.Before = current
		result.After = current

		if !force && op.Satisfied(current) {
			result.Changed = false
			return result, nil
		}

		if err := op.Apply(ctx); err != nil {
			if errors.Is(err, ErrConflict) && attempt < maxConflictRetries {
				continue
			}
			return Result{}, fmt.Errorf("idempotent: %s: apply: %w", key, err)
		}

		result.Changed = true
		if after, readErr := op.Read(ctx); readErr == nil {
			result.After = after
		} else {
			result.AfterErr = fmt.Errorf("idempotent: %s: re-read: %w", key, readErr)
		}
		// Still under the lock (released by the deferred unlock), and only
		// here, on the one attempt whose Apply succeeded.
		if pa, ok := op.(PostApplier); ok {
			if err := pa.PostApply(ctx); err != nil {
				result.PostApplyErr = fmt.Errorf("idempotent: %s: post-apply check: %w", key, err)
			}
		}
		return result, nil
	}
}
