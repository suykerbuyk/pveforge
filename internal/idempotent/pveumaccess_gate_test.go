package idempotent

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// BeforeJoin is asked from Read, while the run's write gate is closed, so a
// refusal it makes with dispatch.Refuse is exit 4 and a read failure it returns
// plain is not; Run's post-write re-read (ReRead) never asks it again, and its
// refusal is never marked once a write has been sent.
func TestUserEnsure_BeforeJoinRunsInReadWhileTheGateIsClosed(t *testing.T) {
	run := func(t *testing.T, hook func(ctx context.Context, g []string) error, users []pve.AccessUser) (error, *fakeAccess, int) {
		// dropWrites: the write is accepted but not applied, so the re-read finds
		// the user still unsatisfied and a Read-style re-read WOULD ask again
		f := &fakeAccess{users: slices.Clone(users), dropWrites: true}
		asked := 0
		op := &UserEnsure{Client: f, UserID: "alice@pve", Groups: []string{"admins"}, BeforeJoin: func(ctx context.Context, g []string) error {
			asked++
			return hook(ctx, g)
		}}
		ctx, _ := dispatch.With(context.Background())
		_, err := Run(ctx, t.TempDir()+"/roster.toml", lock.ObjectKey{TargetID: "t", Kind: "user", ID: "alice@pve"}, op, false)
		return err, f, asked
	}
	refusal := errors.New("refused: an escalating group")
	t.Run("a refusal made with Refuse is marked and writes nothing", func(t *testing.T) {
		err, f, asked := run(t, func(ctx context.Context, _ []string) error { return dispatch.Refuse(ctx, refusal) }, nil)
		if !dispatch.IsRefused(err) || !errors.Is(err, refusal) || len(f.writes) != 0 || asked != 1 {
			t.Fatalf("err %v refused=%v writes %q asked %d", err, dispatch.IsRefused(err), f.writes, asked)
		}
	})
	t.Run("a plain error (a failed read) is not marked", func(t *testing.T) {
		err, f, _ := run(t, func(context.Context, []string) error { return refusal }, nil)
		if err == nil || dispatch.IsRefused(err) || len(f.writes) != 0 {
			t.Fatalf("err %v refused=%v writes %q", err, dispatch.IsRefused(err), f.writes)
		}
	})
	t.Run("the post-write re-read does not ask again", func(t *testing.T) {
		// the fake never reflects the write, so the re-read finds the user
		// still unsatisfied: Read would ask again, ReRead must not
		err, f, asked := run(t, func(context.Context, []string) error { return nil }, nil)
		if err != nil || len(f.writes) != 1 || asked != 1 {
			t.Fatalf("err %v writes %q asked %d (want one question, before the write)", err, f.writes, asked)
		}
	})
}
