// Package dispatch is the run-scoped write gate behind pveforge's exit
// statuses 3 and 4 (contract plan §3.5).
//
// Exit 4 means "refused before anything was changed"; exit 3 means "a change
// was dispatched and its outcome was not observed". Neither is decided by
// the NAME of an error: the same sentinel is returned before a write by one
// verb and after it by another. They are decided by STATE:
//
//   - A Gate is created closed, in the command's context (With). Every
//     primitive that can change state on a PVE host or in the roster file
//     opens it, immediately before the change leaves the process (Open): the
//     REST round tripper for any non-GET/HEAD request, the root-SSH runner for
//     a command sent in write context, the idempotent engine before Apply, and
//     each roster writer's call site. Verbs never open it at their own
//     discretion.
//   - Refuse(ctx, err) is the ONLY constructor of the refused-before-write
//     marker, and returns it only while the gate is closed. Once any write has
//     been sent it returns err unchanged, so a post-write refusal exits 1 even
//     if a verb author mistakenly asks for 4.
//   - Unobserved marks an error whose change WAS dispatched and whose outcome
//     was not observed. It is built at the sites that know: a task wait that
//     started, and a root-SSH write that was sent and timed out.
//
// Local bookkeeping (<roster>.lock, <roster>.locks/, harness evidence, the
// harness ledger, the probe's harness-state/ file) is NOT a mutation: it does
// not open the gate.
package dispatch

import (
	"context"
	"errors"
	"sync/atomic"
)

type gateKey struct{}

// Gate is one run's write state. The zero value is a closed gate.
type Gate struct{ open atomic.Bool }

// With returns ctx carrying a fresh, closed gate, and the gate.
func With(ctx context.Context) (context.Context, *Gate) {
	g := &Gate{}
	return context.WithValue(ctx, gateKey{}, g), g
}

func from(ctx context.Context) *Gate {
	if ctx == nil {
		return nil
	}
	g, _ := ctx.Value(gateKey{}).(*Gate)
	return g
}

// Open opens the gate carried by ctx, if any. It is idempotent. It is called
// by the write funnels (see the package doc), never by a verb's own logic.
func Open(ctx context.Context) {
	if g := from(ctx); g != nil {
		g.open.Store(true)
	}
}

// Opened reports whether a write has been sent under ctx's gate. A context
// with no gate reports false.
func Opened(ctx context.Context) bool {
	g := from(ctx)
	return g != nil && g.open.Load()
}

// Has reports whether ctx carries a gate at all (a test asserts the command
// contexts do).
func Has(ctx context.Context) bool { return from(ctx) != nil }

// refusedBeforeWrite marks an error as a refusal made while the gate was
// closed: nothing was changed on a PVE host or in the roster file. The type is
// UNEXPORTED, and so is its field: Refuse is the only way to build one, in this
// package and out of it (a type alias or an aliased import cannot reach it).
type refusedBeforeWrite struct{ err error }

func (e *refusedBeforeWrite) Error() string { return e.err.Error() }
func (e *refusedBeforeWrite) Unwrap() error { return e.err }

// Refuse states a deliberate refusal. It returns the marker only while the
// gate carried by ctx is closed; a context with no gate, or an open gate,
// returns err unchanged (so it can never claim "nothing was changed" after a
// write). A nil err stays nil.
func Refuse(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	g := from(ctx)
	if g == nil || g.open.Load() {
		return err
	}
	return &refusedBeforeWrite{err: err}
}

// IsRefused reports whether err's chain holds a refusal built by Refuse.
func IsRefused(err error) bool {
	var r *refusedBeforeWrite
	return errors.As(err, &r)
}

// unobserved marks an error whose change was dispatched and whose outcome was
// not observed. Unexported like refusedBeforeWrite: Unobserve is the only way
// to build one, and the set of callers of Unobserve is pinned by a type-aware
// census (the task wait and the root-SSH write funnel). There is NO interface
// a foreign type can implement to be read as one: a closed mechanism.
type unobserved struct{ err error }

func (e *unobserved) Error() string { return e.err.Error() }
func (e *unobserved) Unwrap() error { return e.err }

// Unobserve marks err as the error of a change that was dispatched and whose
// outcome was not observed. The text and the chain are err's. A nil err stays
// nil.
func Unobserve(err error) error {
	if err == nil {
		return nil
	}
	return &unobserved{err: err}
}

// IsUnobserved reports whether err's chain holds an unobserved dispatch built
// by Unobserve.
func IsUnobserved(err error) bool {
	var u *unobserved
	return errors.As(err, &u)
}
