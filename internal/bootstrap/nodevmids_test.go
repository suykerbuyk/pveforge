package bootstrap

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// NodeQemuCommand is the node-scoped qemu-index read, shell-quoted — never
// /cluster/resources.
func TestNodeQemuCommand_QuotedAndNodeScoped(t *testing.T) {
	if got, want := NodeQemuCommand("pvh"), `pvesh get /nodes/'pvh'/qemu --output-format json`; got != want {
		t.Fatalf("NodeQemuCommand(\"pvh\") = %q, want the shell-quoted node-scoped form %q", got, want)
	}
}

// Happy path: the peer's own node matches, so NodeVMIDs reads its qemu list
// and returns the sorted VMID set. Both reads run as root over one dial.
func TestNodeVMIDs_HappyPath(t *testing.T) {
	listCmd := NodeQemuCommand("pvh")
	sess := &fakeSession{byCmd: map[string]fakeRunResult{
		PeerNodeReadCommand: {res: RunResult{Stdout: "nodes/pvh\n"}},
		listCmd:             {res: RunResult{Stdout: `[{"vmid":300},{"vmid":"100"},{"vmid":690}]`}},
	}}
	a, tr := newAccess(sess, nil)
	got, err := a.NodeVMIDs(context.Background(), "pvh")
	if err != nil {
		t.Fatalf("NodeVMIDs error: %v", err)
	}
	if want := []int{100, 300, 690}; !slices.Equal(got, want) {
		t.Fatalf("NodeVMIDs = %v, want %v", got, want)
	}
	if !slices.Equal(sess.commands, []string{PeerNodeReadCommand, listCmd}) {
		t.Errorf("commands = %q; want the identity read then the list read", sess.commands)
	}
	if opened(tr) != 1 {
		t.Errorf("root dialed %d time(s); want exactly one", opened(tr))
	}
}

// Central §2a invariant (red-first against a skip-the-gate mutant): the peer
// is node "A" but the caller asks for "B" (a legal roster Host=A/Node=B).
// NodeVMIDs MUST refuse and MUST NOT issue the (proxied) list read for B —
// even though the fake would answer B's list with a valid set. A mutant that
// drops verifyPeerNode accepts B's foreign set → this goes RED.
func TestNodeVMIDs_RefusesForeignPeer(t *testing.T) {
	listB := NodeQemuCommand("B")
	sess := &fakeSession{byCmd: map[string]fakeRunResult{
		PeerNodeReadCommand: {res: RunResult{Stdout: "nodes/A\n"}},
		// A valid list for B is seeded so a gate-skipping mutant would
		// "succeed" with a foreign node's set.
		listB: {res: RunResult{Stdout: `[{"vmid":700}]`}},
	}}
	a, _ := newAccess(sess, nil)
	got, err := a.NodeVMIDs(context.Background(), "B")
	if err == nil || !errors.Is(err, pve.ErrUnverifiableRead) || got != nil {
		t.Fatalf("NodeVMIDs(B) with peer A = %v, %v; want nil + ErrUnverifiableRead refusal", got, err)
	}
	if slices.Contains(sess.commands, listB) {
		t.Fatalf("the list read %q ran for a non-peer node; it must be refused before any (proxied) list read", listB)
	}
}

// Central §2a invariant (red-first against a path.Base substitute): a
// relative-traversal symlink target whose FINAL component equals node must be
// refused by the strict nodes/<segment> shape. path.Base("nodes/A/../pvh") ==
// "pvh" == node, so a path.Base mutant accepts it and reads the list → RED.
func TestNodeVMIDs_StrictPeerShape(t *testing.T) {
	listCmd := NodeQemuCommand("pvh")
	for name, peer := range map[string]string{
		"relative traversal": "nodes/A/../pvh\n",
		"traversal only":     "nodes/pvh/../other\n",
		"trailing slash":     "nodes/pvh/\n",
		"absolute target":    "/etc/pve/nodes/pvh\n",
		"dot segment":        "nodes/.\n",
		"dotdot segment":     "nodes/..\n",
		"non-nodes shape":    "pvh\n",
		"empty output":       "\n",
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{
			PeerNodeReadCommand: {res: RunResult{Stdout: peer}},
			// A valid list is seeded so a shape-loosening mutant would read it.
			listCmd: {res: RunResult{Stdout: `[{"vmid":100}]`}},
		}}
		a, _ := newAccess(sess, nil)
		got, err := a.NodeVMIDs(context.Background(), "pvh")
		if err == nil || !errors.Is(err, pve.ErrUnverifiableRead) || got != nil {
			t.Errorf("%s: NodeVMIDs = %v, %v; want nil + ErrUnverifiableRead refusal", name, got, err)
		}
		if slices.Contains(sess.commands, listCmd) {
			t.Errorf("%s: the list read ran despite a non-strict peer shape %q", name, peer)
		}
	}
}

// The identity read itself failing (undeterminable peer) refuses, and never
// reads the list. Happy shape confirms "nodes/pvh" == "pvh" passes elsewhere.
func TestNodeVMIDs_UndeterminablePeerRefuses(t *testing.T) {
	listCmd := NodeQemuCommand("pvh")
	for name, r := range map[string]fakeRunResult{
		"readlink exits non-zero": {res: RunResult{ExitCode: 1, Stderr: "readlink: /etc/pve/local: No such file or directory"}},
		"transport error":         {err: errors.New("connection reset")},
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{
			PeerNodeReadCommand: r,
			listCmd:             {res: RunResult{Stdout: `[{"vmid":100}]`}},
		}}
		a, _ := newAccess(sess, nil)
		got, err := a.NodeVMIDs(context.Background(), "pvh")
		if err == nil || !errors.Is(err, pve.ErrUnverifiableRead) || got != nil {
			t.Errorf("%s: NodeVMIDs = %v, %v; want nil + ErrUnverifiableRead refusal", name, got, err)
		}
		if slices.Contains(sess.commands, listCmd) {
			t.Errorf("%s: the list read ran despite an undeterminable peer node", name)
		}
	}
}

// With the peer verified, the list read still fails closed on a bad body.
func TestNodeVMIDs_ListFailsClosed(t *testing.T) {
	listCmd := NodeQemuCommand("pvh")
	for name, r := range map[string]fakeRunResult{
		"list exits non-zero": {res: RunResult{ExitCode: 2, Stderr: "no such path"}},
		"list null":           {res: RunResult{Stdout: "null"}},
		"list garbage":        {res: RunResult{Stdout: "garbage"}},
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{
			PeerNodeReadCommand: {res: RunResult{Stdout: "nodes/pvh\n"}},
			listCmd:             r,
		}}
		a, _ := newAccess(sess, nil)
		if got, err := a.NodeVMIDs(context.Background(), "pvh"); err == nil || got != nil {
			t.Errorf("%s: NodeVMIDs = %v, %v; want an error and no list", name, got, err)
		}
	}
}
