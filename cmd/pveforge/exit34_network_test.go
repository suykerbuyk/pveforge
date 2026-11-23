package main

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Exit 3/4 for `network bridge create`, `network bridge destroy` and
// `network set` (contract plan §3.5, §4, AC-W2/W3). Every refusal boundary is
// run through runRoot with the THREE write logs (the fake PVE's non-GET log,
// the root-SSH write log, a sha256 snapshot of the roster) and the gate-
// agreement assertion of writeEnv.observe; each has a post-write twin that
// must exit NOT 4. The REST write gate opens at the stage request (or, for an
// idempotent Op, immediately before Apply): a refusal Apply makes after that is
// exit 1.

type netFixture struct {
	env    writeEnv
	roster string
	fs     *pvefake.SSHServer
}

// newNetFixture wires srv (a BridgeREST/FieldsREST server, or a proxy of one)
// and a root-SSH fake answering link reads. restWrites is the inner fake's
// write log. ifaceLink says whether the target interface exists in the kernel
// for each of its link reads (call index).
func newNetFixture(t *testing.T, srv *httptest.Server, restWrites func() []string, mgmt, iface string, ifaceExists func(n int) bool) netFixture {
	t.Helper()
	fs := pvefake.NewSSHServer(t)
	var mu sync.Mutex
	calls := 0
	fs.HandleExec(func(cmd string) (string, string, int) {
		switch cmd {
		case pvefake.LinkShowCmd(mgmt):
			return pvefake.LinkJSON(mgmt, true), "", 0
		case pvefake.LinkShowCmd(iface):
			mu.Lock()
			n := calls
			calls++
			mu.Unlock()
			if ifaceExists(n) {
				return pvefake.LinkJSON(iface, true), "", 0
			}
			return "", fmt.Sprintf(pvefake.LinkMissingStderrFmt, iface), 1
		}
		return "", "unexpected command", 127
	})
	rp := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	return netFixture{
		env:    writeEnv{roster: rp, restWrites: restWrites, sshWrites: sshWritesNotIn(fs, s2NetSSHRead)},
		roster: rp,
		fs:     fs,
	}
}

const (
	s2Node = "qa-pve-01"
	s2Mgmt = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
)

func (f netFixture) bridgeCreate(t *testing.T, mgmt, iface string, fields ...string) writeObservation {
	args := append([]string{"network", "bridge", "create", "--roster", f.roster, "--management-bridge", mgmt, s2Node, iface}, fields...)
	return f.env.observe(t, args...)
}

func (f netFixture) bridgeDestroy(t *testing.T, mgmt, iface string) writeObservation {
	return f.env.observe(t, "network", "bridge", "destroy", "--roster", f.roster, "--management-bridge", mgmt, s2Node, iface)
}

// ---- network bridge create --------------------------------------------------

// A create over an interface that already exists as another type is refused
// BEFORE the stage: exit 4, zero entries in all three logs.
func TestExit4_NetworkBridgeCreate_TypeMismatch_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.MgmtFields = s2Mgmt
	rest.IfaceFields = `{"iface":"vmbr9","type":"OVSBridge","mtu":"9000","active":1}`
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr9", func(int) bool { return true })

	o := f.bridgeCreate(t, "vmbr0", "vmbr9", "mtu=9000")
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "already exists as type OVSBridge") {
		t.Errorf("stderr = %q, want the type refusal", o.stderr)
	}
}

// A missing management bridge is a refusal before the stage.
func TestExit4_NetworkBridgeCreate_MissingManagementBridge_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.IfaceResponses = []string{pvefake.IfaceAbsent, pvefake.IfaceAbsent} // Run's Read of vmbr1; the vmbr7 snapshot
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr7", "vmbr1", func(int) bool { return false })

	o := f.bridgeCreate(t, "vmbr7", "vmbr1", "type=bridge")
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "management bridge vmbr7 does not exist") {
		t.Errorf("stderr = %q, want the missing-management-bridge refusal", o.stderr)
	}
}

// A malformed op (an iface key in the wanted fields) is refused before any
// request.
func TestExit4_NetworkBridgeCreate_InvalidOp_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return false })

	o := f.bridgeCreate(t, "vmbr0", "vmbr1", "iface=vmbr2")
	o.wantRefusedBeforeAnyWrite(t)
	if got := rest.Hits(); len(got) != 0 {
		t.Errorf("REST requests = %q, want none: a validation refusal precedes any request", got)
	}
}

// POST-WRITE TWIN of the three above: the stage HAPPENS, then the guard
// self-check refuses (the interface already reports active before the commit)
// and the stage is reverted. The same sentence of refusal, after a write:
// exit 1, never 4.
func TestExit1_NetworkBridgeCreate_GuardAfterStage_IsNotRefused(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.MgmtFields = s2Mgmt
	rest.IfaceResponses = []string{
		pvefake.IfaceAbsent, // Run's Read
		pvefake.IfaceAbsent, // the pre-stage existence read
		`{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1","active":1}`, // guard self-check: already active
	}
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return false })

	o := f.bridgeCreate(t, "vmbr0", "vmbr1", "type=bridge", "bridge_ports=eth1")
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 {
		t.Fatalf("exit %d, want 1 (a refused commit after a stage)", o.code)
	}
	if len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "POST ") || !strings.HasPrefix(o.rest[1], "DELETE ") {
		t.Errorf("REST writes = %q, want the stage POST then the revert DELETE", o.rest)
	}
	if !strings.Contains(o.stderr, "guard self-check failed") {
		t.Errorf("stderr = %q, want the guard's refusal", o.stderr)
	}
}

// The wait boundary (networkbridge.go, the commit task wait): the stage and
// the commit were SENT, the status poll fails, the outcome is unknown: exit 3.
func TestExit3_NetworkBridgeCreate_CommitWaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := pvefake.NetworkUPID(s2Node, "vmbr1")
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.MgmtFields = s2Mgmt
	rest.IfaceResponses = []string{pvefake.IfaceAbsent, pvefake.IfaceAbsent, `{"iface":"vmbr1","type":"bridge","bridge_ports":"eth1"}`}
	rest.CommitUPID = upid
	inner := rest.Server()
	defer inner.Close()
	srv, polls := pollFailProxy(t, inner)
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return false })

	o := f.bridgeCreate(t, "vmbr0", "vmbr1", "type=bridge", "bridge_ports=eth1")
	if o.code != 3 {
		t.Fatalf("exit %d, want 3 (commit dispatched, outcome not observed); stderr %q", o.code, o.stderr)
	}
	if !o.opened || len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "POST ") || !strings.HasPrefix(o.rest[1], "PUT ") {
		t.Errorf("REST writes = %q (gate %v), want the stage POST and the commit PUT, once each", o.rest, o.opened)
	}
	if polls.Load() < 1 {
		t.Errorf("polls = %d: the wait never polled, so it did not observe-and-fail", polls.Load())
	}
	if !strings.Contains(o.stderr, upid) {
		t.Errorf("stderr = %q, want the UPID", o.stderr)
	}
}

// ---- network bridge destroy -------------------------------------------------

func TestExit4_NetworkBridgeDestroy_MissingManagementBridge_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.IfaceResponses = []string{`{"iface":"vmbr1","type":"bridge","active":1}`, pvefake.IfaceAbsent}
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr7", "vmbr1", func(int) bool { return true })

	o := f.bridgeDestroy(t, "vmbr7", "vmbr1")
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "management bridge vmbr7 does not exist") {
		t.Errorf("stderr = %q, want the missing-management-bridge refusal", o.stderr)
	}
}

// Post-write twin: the DELETE stage happens, then the guard finds the
// interface already inactive: exit 1.
func TestExit1_NetworkBridgeDestroy_GuardAfterStage_IsNotRefused(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.MgmtFields = s2Mgmt
	rest.IfaceResponses = []string{
		`{"iface":"vmbr1","type":"bridge","active":1}`, // Run's Read
		`{"iface":"vmbr1","type":"bridge"}`,            // guard: no longer active after staging
	}
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return true })

	o := f.bridgeDestroy(t, "vmbr0", "vmbr1")
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "DELETE ") {
		t.Errorf("exit %d, REST writes %q: want 1 after the stage DELETE and its revert", o.code, o.rest)
	}
}

func TestExit3_NetworkBridgeDestroy_CommitWaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := pvefake.NetworkUPID(s2Node, "vmbr1")
	rest := pvefake.NewBridgeREST(t, s2Node)
	rest.MgmtFields = s2Mgmt
	live := `{"iface":"vmbr1","type":"bridge","active":1}`
	rest.IfaceResponses = []string{live, live}
	rest.CommitUPID = upid
	inner := rest.Server()
	defer inner.Close()
	srv, polls := pollFailProxy(t, inner)
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return true })

	o := f.bridgeDestroy(t, "vmbr0", "vmbr1")
	if o.code != 3 {
		t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
	}
	if len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "DELETE ") || !strings.HasPrefix(o.rest[1], "PUT ") || polls.Load() < 1 {
		t.Errorf("REST writes %q, polls %d: want the stage DELETE, the commit PUT, and a failed poll", o.rest, polls.Load())
	}
}

// ---- network set ------------------------------------------------------------

func newFieldsFixture(t *testing.T, rest *pvefake.FieldsREST, srv *httptest.Server, iface string) netFixture {
	t.Helper()
	return newNetFixture(t, srv, rest.Writes, "vmbr0", iface, func(int) bool { return true })
}

func (f netFixture) set(t *testing.T, iface string, pairs ...string) writeObservation {
	args := append([]string{"network", "set", "--roster", f.roster, s2Node, iface}, pairs...)
	return f.env.observe(t, args...)
}

// networkfields.go: an interface that is not in the node's interface list has
// no readable type, so the stage is refused ("refusing to stage"): before any
// write, exit 4.
func TestExit4_NetworkSet_TypeUnknown_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewFieldsREST(t, s2Node, "vmbr5")
	rest.IfaceResponses = []string{`{"iface":"vmbr5","type":"bridge","mtu":"1500"}`} // Run's Read sees it
	rest.ListResponses = []string{`[{"iface":"vmbr0","bridge_ports":"eth0"}]`}       // the node's list does not
	srv := rest.Server()
	defer srv.Close()
	f := newFieldsFixture(t, rest, srv, "vmbr5")

	o := f.set(t, "vmbr5", "mtu=9000")
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "refusing to stage") {
		t.Errorf("stderr = %q, want the type refusal", o.stderr)
	}
}

// An interface Run's Read cannot find is refused before any write too.
func TestExit4_NetworkSet_InterfaceMissing_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewFieldsREST(t, s2Node, "vmbr5")
	rest.IfaceResponses = []string{pvefake.IfaceAbsent}
	srv := rest.Server()
	defer srv.Close()
	f := newFieldsFixture(t, rest, srv, "vmbr5")

	f.set(t, "vmbr5", "mtu=9000").wantRefusedBeforeAnyWrite(t)
}

// "type" cannot be set: refused before any request.
func TestExit4_NetworkSet_InvalidOp_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewFieldsREST(t, s2Node, "vmbr5")
	srv := rest.Server()
	defer srv.Close()
	f := newFieldsFixture(t, rest, srv, "vmbr5")

	o := f.set(t, "vmbr5", "type=OVSBridge")
	o.wantRefusedBeforeAnyWrite(t)
	if got := rest.Hits(); len(got) != 0 {
		t.Errorf("REST requests = %q, want none", got)
	}
}

// Post-write twin (the mandatory network-stage twin): the stage PUT HAPPENS,
// then the other-interfaces guard finds an unrelated staged change and
// reverts: exit 1, never 4.
func TestExit1_NetworkSet_OtherInterfaceChangedAfterStage_IsNotRefused(t *testing.T) {
	rest := pvefake.NewFieldsREST(t, s2Node, "vmbr5")
	rest.IfaceResponses = []string{`{"iface":"vmbr5","type":"bridge","mtu":"1500"}`}
	rest.ListResponses = []string{
		`[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`,
		`[{"iface":"vmbr5","type":"bridge","mtu":"9000"},{"iface":"vmbr0","bridge_ports":"eth9"}]`, // someone else's stage
	}
	srv := rest.Server()
	defer srv.Close()
	f := newFieldsFixture(t, rest, srv, "vmbr5")

	o := f.set(t, "vmbr5", "mtu=9000")
	o.wantNotRefusedAfterWrite(t)
	if o.code != 1 || len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "PUT ") || !strings.HasPrefix(o.rest[1], "DELETE ") {
		t.Errorf("exit %d, REST writes %q: want 1 after the stage PUT and its revert DELETE", o.code, o.rest)
	}
	if !strings.Contains(o.stderr, "another interface's staged config changed") {
		t.Errorf("stderr = %q, want the guard's refusal", o.stderr)
	}
}

func TestExit3_NetworkSet_CommitWaitNotObserved(t *testing.T) {
	fastTaskTimings(t)
	upid := pvefake.NetworkUPID(s2Node, "vmbr5")
	rest := pvefake.NewFieldsREST(t, s2Node, "vmbr5")
	rest.IfaceResponses = []string{`{"iface":"vmbr5","type":"bridge","mtu":"1500"}`}
	same := `[{"iface":"vmbr5","type":"bridge","mtu":"1500"},{"iface":"vmbr0","bridge_ports":"eth0"}]`
	rest.ListResponses = []string{same}
	rest.CommitUPID = upid
	inner := rest.Server()
	defer inner.Close()
	srv, polls := pollFailProxy(t, inner)
	f := newFieldsFixture(t, rest, srv, "vmbr5")

	o := f.set(t, "vmbr5", "mtu=9000")
	if o.code != 3 {
		t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
	}
	if len(o.rest) != 2 || !strings.HasPrefix(o.rest[0], "PUT ") || !strings.HasPrefix(o.rest[1], "PUT ") || polls.Load() < 1 {
		t.Errorf("REST writes %q, polls %d: want the stage PUT, the commit PUT, and a failed poll", o.rest, polls.Load())
	}
	if !strings.Contains(o.stderr, upid) {
		t.Errorf("stderr = %q, want the UPID", o.stderr)
	}
}

// An empty management bridge (the flag is required but may be empty) is a
// validation refusal before any request, for destroy too.
func TestExit4_NetworkBridgeDestroy_InvalidOp_RefusedBeforeAnyWrite(t *testing.T) {
	rest := pvefake.NewBridgeREST(t, s2Node)
	srv := rest.Server()
	defer srv.Close()
	f := newNetFixture(t, srv, rest.Writes, "vmbr0", "vmbr1", func(int) bool { return true })

	o := f.bridgeDestroy(t, "", "vmbr1")
	o.wantRefusedBeforeAnyWrite(t)
	if got := rest.Hits(); len(got) != 0 {
		t.Errorf("REST requests = %q, want none", got)
	}
}
