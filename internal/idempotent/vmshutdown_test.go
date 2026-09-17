package idempotent

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	proxmox "github.com/luthermonson/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

const shutdownUPID = "UPID:qa-pve-01:00001236:0000ABCF:5F000002:qmshutdown:100:root@pam:"

// fakeVMShutdownClient is a scriptable VMShutdownClient, local to this test
// file — VMShutdown's Client interface is its own narrow shape
// (ShutdownVM, and deliberately no StopVM at all), so it gets its own small
// fake, matching this package's "one fake per interface shape" discipline.
//
// Every call is counted and every argument recorded, specifically so a test
// can assert not just THAT a call happened but WITH WHAT: a shutdown fake
// that never records its vmid would pass just as happily while the Op shut
// down a different VM.
type fakeVMShutdownClient struct {
	node string

	getVMResult *proxmox.VirtualMachine
	getVMErr    error
	getVMCalls  int
	lastGetNode string
	lastGetVMID int

	shutdownUPID  string
	shutdownErr   error
	shutdownCalls int
	lastShutdownV int

	waitForTaskErr   error
	waitForTaskCalls int
	lastWaitNode     string
	lastWaitUPID     string
}

func (f *fakeVMShutdownClient) Node() string { return f.node }

func (f *fakeVMShutdownClient) GetVM(_ context.Context, node string, vmid int) (*proxmox.VirtualMachine, error) {
	f.getVMCalls++
	f.lastGetNode = node
	f.lastGetVMID = vmid
	if f.getVMErr != nil {
		return nil, f.getVMErr
	}
	return f.getVMResult, nil
}

func (f *fakeVMShutdownClient) ShutdownVM(_ context.Context, vmid int) (string, error) {
	f.shutdownCalls++
	f.lastShutdownV = vmid
	if f.shutdownErr != nil {
		return "", f.shutdownErr
	}
	return f.shutdownUPID, nil
}

func (f *fakeVMShutdownClient) WaitForTask(_ context.Context, node, upid string) error {
	f.waitForTaskCalls++
	f.lastWaitNode = node
	f.lastWaitUPID = upid
	return f.waitForTaskErr
}

func runningClient() *fakeVMShutdownClient {
	return &fakeVMShutdownClient{
		node:         "qa-pve-01",
		getVMResult:  &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running"},
		shutdownUPID: shutdownUPID,
	}
}

func shutdownKey() lock.ObjectKey {
	return lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
}

// TestVMShutdown_Read_ReturnsTypedStatus pins that Read reports GetVM's
// typed .Status field — and that it scopes the read to this client's own
// node and the Op's own VMID, not some other VM's.
func TestVMShutdown_Read_ReturnsTypedStatus(t *testing.T) {
	// Only the statuses PVE's own /status/current actually produces. There
	// is no "paused" or "suspended" STATUS string — see the Op's doc comment
	// and TestVMShutdown_Read_MapsPausedFromQMPStatus below. An earlier
	// version of this row list asserted against both, which review correctly
	// called out as pinning values the Op could never return.
	for _, status := range []string{"running", "stopped"} {
		client := runningClient()
		client.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: status}
		op := &VMShutdown{Client: client, VMID: 100}

		current, err := op.Read(context.Background())
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if current != status {
			t.Errorf("Read = %q, want %q", current, status)
		}
		if client.lastGetNode != "qa-pve-01" {
			t.Errorf("GetVM node = %q, want qa-pve-01", client.lastGetNode)
		}
		if client.lastGetVMID != 100 {
			t.Errorf("GetVM vmid = %d, want 100", client.lastGetVMID)
		}
	}
}

// TestVMShutdown_Satisfied covers the single comparison this Op turns on:
// only "running" is unsatisfied. Anything else — already stopped, paused,
// suspended — is trivially satisfied, since this Op only ever transitions
// a VM FROM running.
func TestVMShutdown_Satisfied(t *testing.T) {
	op := &VMShutdown{VMID: 100}

	// NOT satisfied, each for its own reason. Everything below "" is a QEMU
	// run state PVE can report in qmpstatus while Status is still
	// "running" — none of them is a stopped VM, and an earlier version of
	// this list wrongly had "prelaunch" among the SATISFIED rows, which
	// would have skipped Apply entirely for a VM that had not shut down.
	for _, c := range []struct{ status, why string }{
		{"running", "there is a shutdown to do"},
		{"", "an empty status means the state was never determined, and an unusable read must never read as \"already stopped\""},
		{"paused", "a paused VM is NOT stopped; calling it satisfied would report a VM still holding its memory as already in the desired state"},
		{"prelaunch", "the QEMU process exists but has not started executing — not a stopped VM"},
		{"suspended", "suspend-to-RAM via qmpstatus is not a stopped VM"},
		{"io-error", "the guest is blocked on a failed device, not shut down"},
		{"internal-error", "a wedged QEMU is not a shut-down VM"},
		{"guest-panicked", "a panicked guest is still a running QEMU process"},
		{"watchdog", "a watchdog-tripped VM is not shut down"},
		{"postmigrate", "a mid-migration VM is not shut down"},
		{"a-run-state-qemu-invents-next-year", "an UNRECOGNISED state must fail closed, not read as stopped — this is the whole point of the allowlist"},
	} {
		if op.Satisfied(c.status) {
			t.Errorf("Satisfied(%q) = true, want false: %s", c.status, c.why)
		}
	}

	// Satisfied: the one state that genuinely means there is nothing to shut
	// down. A hibernated VM (suspend-to-disk) reaches this as "stopped" —
	// PVE reports Status "stopped" with Lock "suspended".
	if !op.Satisfied("stopped") {
		t.Error(`Satisfied("stopped") = false, want true — there is nothing to shut down`)
	}
}

// TestVMShutdown_NonRunningQMPStatesAreRefusedNotShutDown extends the paused
// fix to the family it belongs to. Review found the earlier version tested
// QMPStatus == "paused" specifically, so every NEIGHBOURING run state —
// prelaunch, io-error, guest-panicked, and the rest — fell through to
// vm.Status ("running") and got sent a graceful shutdown the guest could not
// service, hanging the caller for the full ten-minute task timeout: the exact
// failure the paused fix was written to prevent, one state over.
//
// The last row is the load-bearing one. go-proxmox defines only three status
// constants and enumerates no QMP run states, so the real set is QEMU's own
// open-ended RunState enum. A state nobody here has heard of must refuse.
func TestVMShutdown_NonRunningQMPStatesAreRefusedNotShutDown(t *testing.T) {
	for _, qmp := range []string{
		"paused", "prelaunch", "suspended", "io-error", "internal-error",
		"guest-panicked", "watchdog", "postmigrate", "inmigrate", "save-vm",
		"restore-vm", "a-run-state-qemu-invents-next-year",
	} {
		t.Run(qmp, func(t *testing.T) {
			client := runningClient()
			client.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running", QMPStatus: qmp}
			op := &VMShutdown{Client: client, VMID: 100}

			current, err := op.Read(context.Background())
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if current != qmp {
				t.Errorf("Read = %q, want %q — the qmp run state is the effective state", current, qmp)
			}
			if op.Satisfied(current) {
				t.Errorf("Satisfied(%q) = true; only a stopped VM is satisfied", current)
			}

			err = op.Apply(context.Background())
			if err == nil {
				t.Fatalf("Apply must refuse run state %q rather than sending a shutdown that cannot complete", qmp)
			}
			if !strings.Contains(err.Error(), qmp) {
				t.Errorf("error %q does not name the run state %q it refused on", err, qmp)
			}
			if client.shutdownCalls != 0 {
				t.Errorf("ShutdownVM called %d time(s) for run state %q, want 0", client.shutdownCalls, qmp)
			}
			if client.waitForTaskCalls != 0 {
				t.Errorf("WaitForTask called %d time(s) for run state %q, want 0", client.waitForTaskCalls, qmp)
			}

			// --force must not force a shutdown that physically cannot
			// complete, for any member of the family.
			c2 := runningClient()
			c2.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running", QMPStatus: qmp}
			if _, err := Run(context.Background(), testRosterPath(t), shutdownKey(), &VMShutdown{Client: c2, VMID: 100}, true); err == nil {
				t.Errorf("Run(force=true) must still refuse run state %q", qmp)
			}
			if c2.shutdownCalls != 0 {
				t.Errorf("ShutdownVM called %d time(s) under --force for run state %q, want 0", c2.shutdownCalls, qmp)
			}
		})
	}
}

// TestVMShutdown_Read_MapsPausedFromQMPStatus pins the status model this Op
// got wrong before review: PVE reports a paused (suspend-to-RAM) guest as
// Status "running" with QMPStatus "paused", never as a "paused" status of
// its own (go-proxmox virtual_machine.go:420-422). Read must map that pair
// itself — without this, a paused VM is indistinguishable from a running
// one and gets sent an ACPI request it cannot answer.
func TestVMShutdown_Read_MapsPausedFromQMPStatus(t *testing.T) {
	client := runningClient()
	client.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running", QMPStatus: "paused"}
	op := &VMShutdown{Client: client, VMID: 100}

	current, err := op.Read(context.Background())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if current != "paused" {
		t.Errorf("Read = %q, want paused — Status running + QMPStatus paused IS paused", current)
	}
	if op.Satisfied(current) {
		t.Error("a paused VM must not be satisfied")
	}

	// A genuinely running VM carries QMPStatus "running" (or empty); neither
	// may be mistaken for paused.
	for _, qmp := range []string{"", "running"} {
		c2 := runningClient()
		c2.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running", QMPStatus: qmp}
		got, err := (&VMShutdown{Client: c2, VMID: 100}).Read(context.Background())
		if err != nil {
			t.Fatalf("Read(qmp=%q): %v", qmp, err)
		}
		if got != "running" {
			t.Errorf("Read(qmp=%q) = %q, want running", qmp, got)
		}
	}
}

// TestVMShutdown_PausedVMIsRefusedNotShutDown is the behavioural half of the
// fix. Before it, the Op did the exact opposite of its own documentation: it
// sent a graceful shutdown to a paused guest, which cannot service the ACPI
// request, so WaitForTask blocked to the full ten-minute
// defaultTaskWaitTimeout before failing with a timeout that explained
// nothing. It must refuse immediately, with ZERO ShutdownVM calls, naming
// the state and the remedy.
func TestVMShutdown_PausedVMIsRefusedNotShutDown(t *testing.T) {
	paused := func() *fakeVMShutdownClient {
		c := runningClient()
		c.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "running", QMPStatus: "paused"}
		return c
	}

	client := paused()
	op := &VMShutdown{Client: client, VMID: 100}
	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("Apply must refuse a paused VM, not send it a shutdown it cannot answer")
	}
	if client.shutdownCalls != 0 {
		t.Errorf("ShutdownVM called %d time(s) for a paused VM, want 0", client.shutdownCalls)
	}
	if client.waitForTaskCalls != 0 {
		t.Errorf("WaitForTask called %d time(s) for a paused VM, want 0", client.waitForTaskCalls)
	}
	for _, want := range []string{"paused", "resume"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q — it must name the state and the remedy", err, want)
		}
	}

	// Through Run: a paused VM must surface as an error, never as a clean
	// no-op, and never as a successful shutdown.
	c2 := paused()
	op2 := &VMShutdown{Client: c2, VMID: 100}
	res, runErr := Run(context.Background(), testRosterPath(t), shutdownKey(), op2, false)
	if runErr == nil {
		t.Fatalf("Run must fail for a paused VM, got Result %+v", res)
	}
	if c2.shutdownCalls != 0 {
		t.Errorf("ShutdownVM called %d time(s) via Run for a paused VM, want 0", c2.shutdownCalls)
	}

	// --force must NOT be able to force a shutdown that physically cannot
	// complete: Run skips Satisfied under force, so the refusal has to live
	// in Apply (which is why Apply re-reads) rather than only in Satisfied.
	c3 := paused()
	op3 := &VMShutdown{Client: c3, VMID: 100}
	if _, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op3, true); err == nil {
		t.Error("Run(force=true) must still refuse a paused VM")
	}
	if c3.shutdownCalls != 0 {
		t.Errorf("ShutdownVM called %d time(s) under --force for a paused VM, want 0", c3.shutdownCalls)
	}
}

// TestVMShutdown_Read_RejectsEmptyStatus closes the third inconclusive-read
// door. GetVM can succeed while returning a VM with no status at all — a
// truncated or partial /status/current body unmarshals into a zero-valued
// struct with no error. That used to return ("", nil), which Satisfied read
// as "already stopped", so Run reported a clean no-op for a VM whose state
// was never determined and which may well still have been running. It is
// the exact polarity Read's own doc comment forbids.
func TestVMShutdown_Read_RejectsEmptyStatus(t *testing.T) {
	client := runningClient()
	client.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01"} // no Status
	op := &VMShutdown{Client: client, VMID: 100}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("Read must reject a VM with no run status rather than reporting an empty (satisfied) one")
	}

	res, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op, false)
	if err == nil {
		t.Fatalf("Run must fail on an undetermined status, got Result %+v", res)
	}
	if client.shutdownCalls != 0 {
		t.Errorf("ShutdownVM called %d time(s) after an undetermined status, want 0", client.shutdownCalls)
	}
}

// TestVMShutdown_Run_ShutsDownRunningVM is the end-to-end happy path
// through idempotent.Run: a running VM is not satisfied, Apply runs,
// ShutdownVM is called with THIS Op's vmid, and WaitForTask is handed the
// node and the UPID ShutdownVM itself returned — not some other UPID, and
// not an empty one.
func TestVMShutdown_Run_ShutsDownRunningVM(t *testing.T) {
	client := runningClient()
	op := &VMShutdown{Client: client, VMID: 100}

	res, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op, false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Changed {
		t.Error("expected Changed=true for a running VM")
	}
	if res.Before != "running" {
		t.Errorf("Before = %q, want running", res.Before)
	}
	if client.shutdownCalls != 1 {
		t.Fatalf("expected 1 ShutdownVM call, got %d", client.shutdownCalls)
	}
	if client.lastShutdownV != 100 {
		t.Errorf("ShutdownVM vmid = %d, want 100 — the Op must shut down ITS OWN vmid", client.lastShutdownV)
	}
	if client.waitForTaskCalls != 1 {
		t.Fatalf("expected 1 WaitForTask call, got %d", client.waitForTaskCalls)
	}
	if client.lastWaitUPID != shutdownUPID {
		t.Errorf("WaitForTask upid = %q, want ShutdownVM's own returned UPID %q", client.lastWaitUPID, shutdownUPID)
	}
	if client.lastWaitNode != "qa-pve-01" {
		t.Errorf("WaitForTask node = %q, want qa-pve-01", client.lastWaitNode)
	}
}

// TestVMShutdown_Apply_ThreadsVMIDAndUPID re-asserts the two identities
// above against a DIFFERENT vmid and a DIFFERENT UPID, so neither
// assertion can be satisfied by a hardcoded constant that merely happens
// to match the fixture the happy-path test uses. This is the gap class
// that let an earlier unit's destroy tests pass while acting on VMID+1.
func TestVMShutdown_Apply_ThreadsVMIDAndUPID(t *testing.T) {
	const otherUPID = "UPID:qa-pve-01:99:98:97:qmshutdown:4242:root@pam:"
	client := runningClient()
	client.shutdownUPID = otherUPID
	op := &VMShutdown{Client: client, VMID: 4242}

	if err := op.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if client.lastShutdownV != 4242 {
		t.Errorf("ShutdownVM vmid = %d, want 4242", client.lastShutdownV)
	}
	if client.lastWaitUPID != otherUPID {
		t.Errorf("WaitForTask upid = %q, want %q", client.lastWaitUPID, otherUPID)
	}
}

// TestVMShutdown_Run_AlreadyStoppedNeverCallsShutdown is the short-circuit
// this Op exists to get right: a VM that is already stopped is satisfied,
// Run skips Apply entirely, and ZERO ShutdownVM calls reach the client.
func TestVMShutdown_Run_AlreadyStoppedNeverCallsShutdown(t *testing.T) {
	// Both rows are states PVE genuinely reports. The hibernated row matters
	// specifically: suspend-to-disk is Status "stopped" with Lock
	// "suspended", NOT a "suspended" status, so it must short-circuit like
	// any other stopped VM.
	for _, c := range []struct {
		name string
		vm   *proxmox.VirtualMachine
	}{
		{"stopped", &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "stopped"}},
		{"hibernated (suspend-to-disk)", &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "stopped", Lock: "suspended"}},
	} {
		status := c.name
		t.Run(c.name, func(t *testing.T) {
			client := runningClient()
			client.getVMResult = c.vm
			op := &VMShutdown{Client: client, VMID: 100}

			res, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op, false)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Changed {
				t.Errorf("expected a no-op for a %q VM", status)
			}
			if client.shutdownCalls != 0 {
				t.Errorf("ShutdownVM called %d times for an already-%s VM, want 0", client.shutdownCalls, status)
			}
			if client.waitForTaskCalls != 0 {
				t.Errorf("WaitForTask called %d times for an already-%s VM, want 0", client.waitForTaskCalls, status)
			}
		})
	}
}

// TestVMShutdown_Run_ForceReappliesAgainstStoppedVM pins the one way a
// stopped VM does reach ShutdownVM: idempotent.Run's own --force bypass.
// Without this, the short-circuit test above would also pass for an Op
// whose Apply was simply broken.
func TestVMShutdown_Run_ForceReappliesAgainstStoppedVM(t *testing.T) {
	client := runningClient()
	client.getVMResult = &proxmox.VirtualMachine{Node: "qa-pve-01", Status: "stopped"}
	op := &VMShutdown{Client: client, VMID: 100}

	if _, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op, true); err != nil {
		t.Fatalf("Run(force): %v", err)
	}
	if client.shutdownCalls != 1 {
		t.Errorf("expected force to re-apply: 1 ShutdownVM call, got %d", client.shutdownCalls)
	}
}

// TestVMShutdown_Apply_PropagatesWaitForTaskFailure is the
// never-swallowed guarantee, for both failure shapes WaitForTask produces:
// a task that ran and failed (pve.TaskFailedError — a guest that refused
// the ACPI request), and a task whose outcome was never observed at all
// (a timeout). Either one leaves the VM potentially still running;
// reporting success would be a lie.
func TestVMShutdown_Apply_PropagatesWaitForTaskFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"task failed", &pve.TaskFailedError{UPID: shutdownUPID, ExitStatus: "shutdown failed"}},
		{"timeout", proxmox.ErrTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := runningClient()
			client.waitForTaskErr = c.err
			op := &VMShutdown{Client: client, VMID: 100}

			err := op.Apply(context.Background())
			if err == nil {
				t.Fatal("Apply must fail when WaitForTask fails — never swallow it")
			}
			if !errors.Is(err, c.err) {
				t.Errorf("Apply error %v does not wrap WaitForTask's own error %v", err, c.err)
			}

			// Same failure through the full Run cycle, since Run is what
			// callers actually use: it must surface, not be flattened into
			// a successful Result.
			client2 := runningClient()
			client2.waitForTaskErr = c.err
			op2 := &VMShutdown{Client: client2, VMID: 100}
			res, runErr := Run(context.Background(), testRosterPath(t), shutdownKey(), op2, false)
			if runErr == nil {
				t.Fatalf("Run must fail when WaitForTask fails, got Result %+v", res)
			}
			if !errors.Is(runErr, c.err) {
				t.Errorf("Run error %v does not wrap WaitForTask's own error %v", runErr, c.err)
			}
		})
	}
}

// TestVMShutdown_Apply_PropagatesShutdownVMFailure: a rejected shutdown
// call (PVE's own verbatim text — a locked VM, say) is a hard Apply error,
// and WaitForTask is never called on the empty UPID that came back with it.
func TestVMShutdown_Apply_PropagatesShutdownVMFailure(t *testing.T) {
	sentinel := errors.New("VM 100 is locked (backup)")
	client := runningClient()
	client.shutdownErr = sentinel
	op := &VMShutdown{Client: client, VMID: 100}

	err := op.Apply(context.Background())
	if err == nil {
		t.Fatal("Apply must fail when ShutdownVM fails")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Apply error %v does not wrap ShutdownVM's own error", err)
	}
	if client.waitForTaskCalls != 0 {
		t.Errorf("WaitForTask called %d times after a failed ShutdownVM, want 0", client.waitForTaskCalls)
	}
}

// TestVMShutdown_Read_PropagatesGetVMError is the polarity guard: an
// inconclusive read must NOT be folded into an empty status the way
// VMCreate.Read folds its own. An empty status is not "running", so
// Satisfied would call it satisfied and Run would skip Apply — a transient
// blip against a still-running VM would report a successful shutdown that
// never happened.
func TestVMShutdown_Read_PropagatesGetVMError(t *testing.T) {
	sentinel := errors.New("connection refused")
	client := runningClient()
	client.getVMErr = sentinel
	op := &VMShutdown{Client: client, VMID: 100}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("Read must propagate a GetVM error, never fold it into an empty status")
	} else if !errors.Is(err, sentinel) {
		t.Errorf("Read error %v does not wrap GetVM's own error", err)
	}

	// Through Run: the failure must surface as a Run error, and Apply must
	// never have run. If Read swallowed the error instead, this Run would
	// return a clean no-op Result and nobody would ever know.
	res, err := Run(context.Background(), testRosterPath(t), shutdownKey(), op, false)
	if err == nil {
		t.Fatalf("Run must fail on an unreadable VM, got Result %+v", res)
	}
	if client.shutdownCalls != 0 {
		t.Errorf("ShutdownVM called %d times after an unreadable state, want 0", client.shutdownCalls)
	}
}

// TestVMShutdown_Read_RejectsNilVM covers the defensive nil guard: a
// (nil, nil) GetVM return must surface as an error, not panic and not read
// as an empty — and therefore satisfied — status.
func TestVMShutdown_Read_RejectsNilVM(t *testing.T) {
	client := runningClient()
	client.getVMResult = nil
	op := &VMShutdown{Client: client, VMID: 100}

	if _, err := op.Read(context.Background()); err == nil {
		t.Fatal("Read must reject a nil VM rather than reporting an empty (satisfied) status")
	}
}

// TestVMShutdown_ExposesNoHardStopPath is the structural enforcement of
// this task's design point at the Op layer: no force/hard/timeout field on
// the Op, and a Client interface that cannot even NAME PVE's hard stop.
//
// Three legs, and their reach stated honestly:
//
//  1. The Op's field set — a Force/Hard/Timeout field fails here.
//  2. The Client interface's method set — StopVM appearing would mean Apply
//     COULD escalate at all.
//  3. internal/sourceguard's call-graph walk across the WHOLE package, not
//     one file. Review showed the previous one-file text scan was defeated
//     by moving the dangerous code to a sibling file, which is an ordinary
//     contributor mistake rather than an adversarial trick.
//
// What this does NOT catch, and does not claim to: reflection over the
// concrete client (reflect.ValueOf(op.Client).MethodByName(...)) reaches
// *pve.RoutedClient.StopVM in production while every fake this suite can
// build lacks the method, so no test here can observe it. That is deliberate
// evasion, not accident; the threat model is a contributor who buries
// escalation without realising callers cannot see it.
func TestVMShutdown_ExposesNoHardStopPath(t *testing.T) {
	// 1. Exported field set is exactly {Client, VMID}.
	ty := reflect.TypeOf(VMShutdown{})
	var exported []string
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if f.IsExported() {
			exported = append(exported, f.Name)
		}
		// No field of any visibility may be named for an escalation knob.
		for _, bad := range []string{"force", "hard", "kill", "stop", "timeout"} {
			if strings.Contains(strings.ToLower(f.Name), bad) {
				t.Errorf("VMShutdown has a field %q — that is the escalation knob this Op exists to refuse", f.Name)
			}
		}
	}
	sort.Strings(exported)
	if want := []string{"Client", "VMID"}; !reflect.DeepEqual(exported, want) {
		t.Errorf("VMShutdown exported fields = %v, want exactly %v", exported, want)
	}

	// 2. The Client interface's method set is exactly the four this Op needs.
	ifc := reflect.TypeOf((*VMShutdownClient)(nil)).Elem()
	var methods []string
	for i := 0; i < ifc.NumMethod(); i++ {
		methods = append(methods, ifc.Method(i).Name)
	}
	sort.Strings(methods)
	if want := []string{"GetVM", "Node", "ShutdownVM", "WaitForTask"}; !reflect.DeepEqual(methods, want) {
		t.Errorf("VMShutdownClient methods = %v, want exactly %v — widening this interface "+
			"(StopVM above all) is what would make an escalation possible at all", methods, want)
	}

	// 3. Package-wide call graph reachable from this Op.
	tokens, err := sourceguard.ReachableTokens(".", []string{"VMShutdown.Apply", "VMShutdown.Read", "VMShutdown.Satisfied"})
	if err != nil {
		t.Fatalf("sourceguard: %v", err)
	}
	forbidden := []string{"status/stop", "StopVM", "forceStop", "force", "skiplock", "hard", "kill"}
	for _, hit := range sourceguard.FindForbidden(tokens, forbidden) {
		t.Errorf("code reachable from VMShutdown names a hard-stop token — %s; "+
			"this Op exposes no escalation path of any kind (see VMShutdown's own doc comment)", hit)
	}
}
