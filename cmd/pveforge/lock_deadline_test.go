package main

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// lockTestDeadline bounds every command run in this package's
// lock-contention tests (the ...BlocksOnPendingMutation and
// ...SharesLockKeyWithTypedCommand tests). A blocking half asserts the
// command fails with a lock-acquisition error inside it; a control half
// asserts the same command succeeds inside it.
//
// Every one of those commands resolves its client, decrypting the roster
// token, BEFORE it takes its lock. When that decrypt ran at the production
// scrypt work factor (~14s under -race) against a 200ms deadline, the
// deadline always expired before the lock was reached, so every blocking
// half passed whether or not the command took the right lock key. The
// fixtures are now cheap (see fixtureEncrypt), and the control half is what
// stops that from coming back silently: if anything before the lock ever
// eats this deadline again, the control fails loudly.
const lockTestDeadline = 2 * time.Second

// requireRunsBesideUnrelatedMutation is the specificity control for a
// lock-contention test. It holds a lock.Mutation on other (an object the
// command must NOT lock), runs cmd under lockTestDeadline, and fails the
// test unless cmd succeeds. It is fatal, so a blocking half never runs
// after a failed control.
func requireRunsBesideUnrelatedMutation(t *testing.T, rosterPath string, other lock.ObjectKey, cmd *cobra.Command) {
	t.Helper()
	unlock, err := lock.Mutation(context.Background(), rosterPath, other)
	if err != nil {
		t.Fatalf("control: acquire mutation on %s: %v", other, err)
	}
	defer func() { _ = unlock() }()

	ctx, cancel := context.WithTimeout(context.Background(), lockTestDeadline)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("control: with a mutation held only on %s, the command must succeed within %s, got: %v "+
			"(a deadline error here means something before the lock now eats the deadline, which would make this test's blocking half vacuous)",
			other, lockTestDeadline, err)
	}
}
