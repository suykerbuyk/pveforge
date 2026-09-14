package main

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

func TestAPIObjectKey_VM(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/nodes/qa-pve-01/qemu/100/config", "100"},
		{"/nodes/qa-pve-01/qemu/100/status/current", "100"},
		{"/nodes/qa-pve-01/qemu/100", "100"},
		// Leading-zero normalization (confirmed bug, adversarial review,
		// 2026-09-14): the raw capture "0100" must normalize to "100",
		// the same string vm.go's own strconv.Atoi/Itoa round-trip
		// produces for the SAME real VM — otherwise this and `vm get
		// <target> 0100` would silently take two different locks for one
		// real object. See TestNewAPICmd_SharesLockKeyWithTypedCommand_
		// LeadingZeroVMID for the full end-to-end interop proof.
		{"/nodes/qa-pve-01/qemu/0100/config", "100"},
		{"/nodes/qa-pve-01/qemu/000100/status/current", "100"},
	}
	for _, c := range cases {
		key, ok := apiObjectKey("qa-pve-01", c.path)
		if !ok {
			t.Errorf("path %q: expected a match", c.path)
			continue
		}
		want := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: c.want}
		if key != want {
			t.Errorf("path %q: key = %+v, want %+v", c.path, key, want)
		}
	}
}

// TestAPIObjectKey_VMOverflowingIDFallsThroughToNoMatch proves the
// strconv.Atoi failure branch (unreachable via the \d+ regex for any
// normal input, but reachable for an absurdly long digit string
// overflowing int) is handled as "no match" rather than panicking or
// keying on an unnormalized string.
func TestAPIObjectKey_VMOverflowingIDFallsThroughToNoMatch(t *testing.T) {
	huge := strings.Repeat("9", 400)
	if _, ok := apiObjectKey("qa-pve-01", "/nodes/qa-pve-01/qemu/"+huge+"/config"); ok {
		t.Error("expected an int-overflowing vmid to fall through to no match")
	}
}

func TestAPIObjectKey_StorageBothShapes(t *testing.T) {
	cases := []string{
		"/storage/local-lvm",
		"/nodes/qa-pve-01/storage/local-lvm/status",
		"/nodes/qa-pve-01/storage/local-lvm/content",
	}
	for _, path := range cases {
		key, ok := apiObjectKey("qa-pve-01", path)
		if !ok {
			t.Errorf("path %q: expected a match", path)
			continue
		}
		want := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "storage", ID: "local-lvm"}
		if key != want {
			t.Errorf("path %q: key = %+v, want %+v", path, key, want)
		}
	}
}

func TestAPIObjectKey_Network(t *testing.T) {
	key, ok := apiObjectKey("qa-pve-01", "/nodes/qa-pve-01/network/vmbr0")
	if !ok {
		t.Fatal("expected a match")
	}
	want := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "network", ID: "vmbr0"}
	if key != want {
		t.Errorf("key = %+v, want %+v", key, want)
	}
}

func TestAPIObjectKey_NodeUsesPathSegmentNotTargetID(t *testing.T) {
	cases := []struct {
		path string
	}{
		{"/nodes/qa-pve-02"},
		{"/nodes/qa-pve-02/status"},
	}
	for _, c := range cases {
		// targetID ("qa-pve-01") deliberately differs from the path's own
		// {node} segment ("qa-pve-02") — proving ID is derived from the
		// path, not from the routed client's own configured node, per
		// this task's resolved design (a raw escape hatch trusts its
		// caller on path correctness; a genuine cross-node path is the
		// caller's problem, not something to silently override).
		key, ok := apiObjectKey("qa-pve-01", c.path)
		if !ok {
			t.Errorf("path %q: expected a match", c.path)
			continue
		}
		want := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "node", ID: "qa-pve-02"}
		if key != want {
			t.Errorf("path %q: key = %+v, want %+v", c.path, key, want)
		}
	}
}

// TestAPIObjectKey_NodePatternDoesNotShadowMoreSpecificNouns proves the
// node pattern's own anchoring (exactly "/nodes/{node}" or
// "/nodes/{node}/status", not a general prefix) means it never
// accidentally claims a vm/storage/network path first.
func TestAPIObjectKey_NodePatternDoesNotShadowMoreSpecificNouns(t *testing.T) {
	cases := []struct {
		path     string
		wantKind string
	}{
		{"/nodes/qa-pve-01/qemu/100/config", "vm"},
		{"/nodes/qa-pve-01/storage/local-lvm/status", "storage"},
		{"/nodes/qa-pve-01/network/vmbr0", "network"},
	}
	for _, c := range cases {
		key, ok := apiObjectKey("qa-pve-01", c.path)
		if !ok {
			t.Errorf("path %q: expected a match", c.path)
			continue
		}
		if key.Kind != c.wantKind {
			t.Errorf("path %q: kind = %q, want %q", c.path, key.Kind, c.wantKind)
		}
	}
}

func TestAPIObjectKey_NoMatch(t *testing.T) {
	cases := []string{
		"/cluster/resources",
		"/version",
		"/pools",
		"/nodes",
		"/access/users",
	}
	for _, path := range cases {
		if _, ok := apiObjectKey("qa-pve-01", path); ok {
			t.Errorf("path %q: expected no match", path)
		}
	}
}
