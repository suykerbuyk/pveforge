package bootstrap

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// The --unique-tag root read runs exactly one command, a read, and decodes
// its answer strictly: a failed or malformed read is an error, never an
// empty list.
func TestRootAccess_ClusterGuests_RunsOnlyTheRead(t *testing.T) {
	const want = "pvesh get /cluster/resources --type vm --output-format json"
	if ClusterGuestsCommand != want {
		t.Fatalf("ClusterGuestsCommand = %q, want %q", ClusterGuestsCommand, want)
	}
	sess := &fakeSession{byCmd: map[string]fakeRunResult{
		want: {res: RunResult{Stdout: `[{"type":"lxc","vmid":200,"tags":"x"},{"type":"qemu","vmid":100}]`}},
	}}
	a, tr := newAccess(sess, nil)
	guests, err := a.ClusterGuests(context.Background())
	if err != nil || len(guests) != 2 || guests[0] != (pve.Guest{Type: "lxc", VMID: 200, Tags: "x"}) {
		t.Fatalf("ClusterGuests = %+v, %v", guests, err)
	}
	if !slices.Equal(sess.commands, []string{want}) || opened(tr) != 1 {
		t.Errorf("root ran %q over %d dial(s); want exactly the one read", sess.commands, opened(tr))
	}
}

func TestRootAccess_ClusterGuests_FailsClosed(t *testing.T) {
	for name, r := range map[string]fakeRunResult{
		"exits non-zero": {res: RunResult{ExitCode: 2, Stderr: "no such path"}},
		"null":           {res: RunResult{Stdout: "null"}},
		"not json":       {res: RunResult{Stdout: "garbage"}},
		"transport":      {err: errors.New("connection reset")},
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{ClusterGuestsCommand: r}}
		a, _ := newAccess(sess, nil)
		if guests, err := a.ClusterGuests(context.Background()); err == nil || guests != nil {
			t.Errorf("%s: %+v, %v; want an error and no list", name, guests, err)
		}
	}
}
