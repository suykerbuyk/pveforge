// Package lock is pveforge's per-object mutual-exclusion primitive for the
// idempotent-mutation-engine's concurrency mandate (PRD §3.4, operator
// decision 2026-09-13): every mutation against a given PVE object is
// always serialized against every other mutation OR read against that
// SAME object, with a pending mutation taking priority over a pending
// read — a read must never starve out a mutation waiting behind it.
//
// Reaches across separate pveforge processes sharing the same roster file
// (the actual, confirmed threat model: this project's own vibe-palace
// multi-agent workflow runs multiple concurrent orchestration-agent
// processes against shared PVE hosts) via OS-level advisory file locks
// (github.com/gofrs/flock), the same library and TryLockContext idiom
// internal/roster/writeback.go already uses for its own file-write
// consistency.
//
// Does NOT reach across different machines, or across two pveforge
// invocations using DIFFERENT roster files that happen to describe the
// same real target — internal/pve's digest-based compare-and-swap write
// methods are this project's accepted defense-in-depth for exactly that
// residual gap (see that package's own doc comments): it detects a lost
// race after the fact rather than preventing one, and doesn't apply at
// all to root-only fields written over the standing SSH vector, which
// have no digest concept.
//
// Mechanism: the classical starvation-free, writer-priority
// readers-writers lock, built from two OS file locks per object key — a
// "service queue" turnstile a writer (Mutation) holds for its entire
// wait-for-and-acquisition-of the resource lock, so no reader arriving
// after a writer starts waiting can be granted the resource lock ahead of
// it — and a "resource" lock taken in shared mode by readers (native
// flock(2) LOCK_SH: the kernel itself tracks concurrent shared holders
// and releases automatically on process crash/exit, so — unlike a
// hand-rolled counter file — there is no persistent state that can go
// stale if a caller crashes mid-hold) and exclusive mode by a mutation.
package lock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// ObjectKey identifies one lockable PVE object within one roster's scope.
// Kind is a short, open-ended vocabulary — "vm", "node", "storage",
// "network" today, matching pveforge-object-model-get-set's object
// classes — nothing here validates it against a closed list, so a future
// object class needs no change here. ID is that object's own natural
// identifier (a VMID as a string, a node name, a storage name, an
// interface name).
type ObjectKey struct {
	TargetID string
	Kind     string
	ID       string
}

// String renders k for logging/error messages.
func (k ObjectKey) String() string {
	return fmt.Sprintf("%s/%s/%s", k.TargetID, k.Kind, k.ID)
}

// pollInterval is how often a blocked acquisition attempt is retried
// while waiting on ctx (TryLockContext/TryRLockContext's own retry
// loop) — mirrors internal/roster/writeback.go's 100ms, tightened a
// little since a mutation cycle involving live PVE round-trips can hold
// the lock longer than a roster file write, so responsiveness to release
// matters more here. A var, not a const, purely so this package's own
// tests can shrink it instead of waiting on production timing.
var pollInterval = 20 * time.Millisecond

// keyFiles are the two lock files backing one ObjectKey.
type keyFiles struct {
	serviceQueue *flock.Flock // the turnstile
	resource     *flock.Flock // the actual per-object lock (shared or exclusive)
}

func filesFor(rosterPath string, key ObjectKey) keyFiles {
	dir := rosterPath + ".locks"
	stem := filepath.Join(dir, sanitizeKey(key))
	return keyFiles{
		serviceQueue: flock.New(stem + ".queue.lock"),
		resource:     flock.New(stem + ".resource.lock"),
	}
}

// sanitizeKey turns key into a filesystem-safe stem. TargetID/Kind/ID are
// operator/config-controlled, not external input, but a path separator or
// other unusual character in any of them must not be able to escape the
// locks directory or collide with an unrelated key — every character
// outside a small safe set is replaced with '_'.
func sanitizeKey(key ObjectKey) string {
	return sanitizePart(key.TargetID) + "__" + sanitizePart(key.Kind) + "__" + sanitizePart(key.ID)
}

func sanitizePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// Mutation acquires an exclusive lock for key, scoped to rosterPath,
// blocking (subject to ctx) until acquired. Must be held for the caller's
// ENTIRE read-compare-mutate cycle, not just the final write — releasing
// it early would let a concurrent reader observe state this mutation is
// still in the middle of changing. Every Read for the same key yields to
// this the instant it starts waiting: a Read that arrives after this call
// begins is never granted the resource lock ahead of it, no matter how
// long this call has to wait for already-in-progress reads to finish.
//
// Returns unlock, to be called exactly once when the cycle completes
// (typically via defer). The lock directory (rosterPath + ".locks") is
// created on demand if missing.
func Mutation(ctx context.Context, rosterPath string, key ObjectKey) (unlock func() error, err error) {
	kf, err := ensureLockDir(rosterPath, key)
	if err != nil {
		return nil, err
	}

	if err := acquire(ctx, kf.serviceQueue, false); err != nil {
		return nil, fmt.Errorf("lock %s: acquire service queue: %w", key, err)
	}
	if err := acquire(ctx, kf.resource, false); err != nil {
		_ = kf.serviceQueue.Unlock()
		return nil, fmt.Errorf("lock %s: acquire resource: %w", key, err)
	}
	if err := kf.serviceQueue.Unlock(); err != nil {
		_ = kf.resource.Unlock()
		return nil, fmt.Errorf("lock %s: release service queue: %w", key, err)
	}

	return func() error {
		return kf.resource.Unlock()
	}, nil
}

// Read acquires a shared lock for key that yields to any Mutation
// currently waiting or held for the same key — used by read-only
// commands that want a consistent view of an object without starving out
// a mutation queued behind them. Multiple Read calls for the same key may
// hold their locks concurrently; a Mutation call for that key blocks
// until every current Read holder releases, and (per Mutation's own doc
// comment) no new Read is granted ahead of a Mutation already waiting.
func Read(ctx context.Context, rosterPath string, key ObjectKey) (unlock func() error, err error) {
	kf, err := ensureLockDir(rosterPath, key)
	if err != nil {
		return nil, err
	}

	// The turnstile: block only long enough to prove no writer is
	// currently waiting-for-or-holding the resource lock ahead of us,
	// then release immediately — never held for the read itself.
	if err := acquire(ctx, kf.serviceQueue, false); err != nil {
		return nil, fmt.Errorf("lock %s: acquire service queue: %w", key, err)
	}
	if err := kf.serviceQueue.Unlock(); err != nil {
		return nil, fmt.Errorf("lock %s: release service queue: %w", key, err)
	}

	if err := acquire(ctx, kf.resource, true); err != nil {
		return nil, fmt.Errorf("lock %s: acquire resource (shared): %w", key, err)
	}
	return func() error {
		return kf.resource.Unlock()
	}, nil
}

func ensureLockDir(rosterPath string, key ObjectKey) (keyFiles, error) {
	kf := filesFor(rosterPath, key)
	if err := os.MkdirAll(filepath.Dir(kf.resource.Path()), 0o700); err != nil {
		return keyFiles{}, fmt.Errorf("lock %s: create lock directory: %w", key, err)
	}
	return kf, nil
}

// acquire blocks (subject to ctx) until l is locked — exclusively, or
// (shared=true) in shared mode — retrying every pollInterval, mirroring
// internal/roster/writeback.go's own TryLockContext idiom.
func acquire(ctx context.Context, l *flock.Flock, shared bool) error {
	var locked bool
	var err error
	if shared {
		locked, err = l.TryRLockContext(ctx, pollInterval)
	} else {
		locked, err = l.TryLockContext(ctx, pollInterval)
	}
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("timed out waiting for lock %s", l.Path())
	}
	return nil
}
