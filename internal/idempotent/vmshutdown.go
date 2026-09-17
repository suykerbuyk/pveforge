package idempotent

import (
	"context"
	"fmt"

	proxmox "github.com/luthermonson/go-proxmox"
)

// VMShutdownClient is the subset of *pve.RoutedClient a VM-shutdown Op
// needs: a typed read (for the VM's run status), Node (to scope that read),
// the graceful shutdown call itself, and WaitForTask to block until PVE's
// asynchronous shutdown task actually finishes. Defined here, not as the
// concrete *pve.RoutedClient, so this package's own tests use a
// lightweight in-package fake instead of pve's network/SSH test harness —
// *pve.RoutedClient satisfies it structurally (see compat_test.go).
//
// Note what is NOT in this interface: StopVM. A shutdown Op that cannot
// name PVE's hard stop cannot escalate to it, whatever a future edit to
// Apply might otherwise be tempted to do — see VMShutdown's own doc
// comment, and TestVMShutdown_ExposesNoHardStopPath, which pins this
// method set so that temptation fails the suite rather than shipping.
type VMShutdownClient interface {
	// GetVM fetches vmid's current status and config on node. VMShutdown
	// uses this for the typed .Status field only — unlike VMCreate/
	// VMDestroy/VMFieldsEnsure, it needs no raw-config read, since a
	// shutdown's whole comparable state is "is it running".
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// ShutdownVM issues PVE's graceful shutdown for vmid, returning the
	// resulting task's UPID.
	ShutdownVM(ctx context.Context, vmid int) (string, error)
	// WaitForTask polls a PVE task (by UPID) to completion.
	WaitForTask(ctx context.Context, node, upid string) error
}

// VMShutdown is idempotent-mutation-engine's Op for a GRACEFUL VM shutdown
// (pveforge-vm-lifecycle-ops item 2e): if VMID is running, ask the guest OS
// to shut itself down and wait for PVE's task to finish; if it is already
// stopped, do nothing at all; if it is PAUSED, refuse (see Apply).
//
// HOW PVE ACTUALLY REPORTS THESE STATES, because an earlier version of this
// comment got it wrong and the tests pinned values the Op could never
// produce. /status/current's `status` field is effectively binary —
// "running" or "stopped" — and the finer detail lives in `qmpstatus`.
// Confirmed against go-proxmox's own predicates (virtual_machine.go:376-435):
//
//   - PAUSED (suspend-to-RAM, `qm suspend`): Status == "running",
//     QMPStatus == "paused". There is no "paused" status string. Read maps
//     this pair to "paused" itself so the Op can act on it at all — and
//     does the same for every OTHER non-running qmpstatus (prelaunch,
//     io-error, internal-error, watchdog, guest-panicked, suspended,
//     postmigrate, …), since a guest in any of them is equally unable to
//     answer an ACPI request. See Read on why that set is treated as open
//     rather than enumerated.
//   - HIBERNATED (suspend-to-disk, `qm suspend --todisk`): Status ==
//     "stopped" with Lock == "suspended". It reads as, and is treated as,
//     stopped — correctly: there is nothing running to shut down.
//   - There is no "suspended" status string either. Nothing here should
//     ever compare against one.
//
// This Op exposes NO hard-stop path — no Force field, no Hard field, no
// "timeout then kill" behaviour, and its Client interface cannot even name
// StopVM. That is the entire point of the Op, not an omission: the epic
// frames escalation from a graceful shutdown to a forcible kill as a
// CALLER decision, belonging to a future higher-level orchestration ("shut
// down, and if it hasn't completed within N, hard-stop") where the caller
// can see that killing a running VM is on the table. A `force` knob here
// would mean a caller who wrote only "shut down" could destroy unflushed
// guest state without ever having asked for that.
//
// TestVMShutdown_ExposesNoHardStopPath pins this struct's field set, the
// VMShutdownClient method set, and — across the whole package, via
// internal/sourceguard's call-graph walk — the absence of stop/kill/force
// tokens in anything reachable from this Op. Stated honestly: that catches
// an ACCIDENTAL reintroduction, including one written in a sibling file. It
// does not and cannot defeat deliberate evasion (reflection over the
// concrete client, a method name assembled at runtime); no static check
// can, and this one does not claim to. See pve.ShutdownVM's own comment for
// the same limit stated at the primitive layer.
//
// PVE's own status/shutdown endpoint accepts a `timeout` parameter (its
// own graceful deadline, distinct from WaitForTask's poll timeout) which is
// deliberately not surfaced as a field here either — an additive follow-up
// once real shutdown durations have been observed against a live host. See
// pve.ShutdownVM's doc comment for why PVE's separate `forceStop`
// parameter is out of scope permanently rather than merely deferred.
type VMShutdown struct {
	Client VMShutdownClient
	VMID   int
}

// Read returns VMID's current run status, straight from GetVM's typed
// .Status field — no raw-config read needed here, unlike VMCreate/
// VMDestroy, since "is it running" is the whole of this Op's comparable
// state.
//
// A GetVM error PROPAGATES rather than being folded into an empty status
// the way VMCreate.Read folds its own. The polarity is what makes the
// difference: an empty status is not "running", so a Satisfied that treated
// it as a state would call it satisfied, and idempotent.Run would skip
// Apply entirely (its documented no-op path, op.go) — a transient network
// blip against a VM that is in fact still running would then report a
// successful, changed-nothing shutdown while the VM kept running. An
// inconclusive read must never read as "already stopped." Same reasoning
// VMDestroy.Read's own doc comment gives for refusing to fold its errors
// into "already gone."
//
// THREE ways a read can be inconclusive, and all three are refused here
// rather than two: a GetVM error, a nil VM, and — the one review caught
// this Op having left open while its own comment forbade it — a VM that
// came back fine but carries NO status at all (a truncated or partial
// /status/current body unmarshals into a zero-valued struct with no error).
// That third case used to return ("", nil) and read as satisfied.
func (op *VMShutdown) Read(ctx context.Context) (string, error) {
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		return "", fmt.Errorf("vm shutdown: vm %d: read: %w", op.VMID, err)
	}
	if vm == nil {
		// Defensive: GetVM's own contract never returns (nil, nil), but a
		// nil here would otherwise panic rather than surfacing as the
		// unusable read it is — and, per Read's doc comment above, an
		// unusable read must never be allowed to read as "already stopped."
		return "", fmt.Errorf("vm shutdown: vm %d: read: no vm returned", op.VMID)
	}
	if vm.Status == "" {
		return "", fmt.Errorf("vm shutdown: vm %d: read: pve reported no run status", op.VMID)
	}
	// PVE reports a VM whose QEMU process exists as Status "running" and
	// carries the ACTUAL run state in QMPStatus. "paused" is only the most
	// familiar member of that family; a VM can equally be prelaunch,
	// suspended, io-error, internal-error, watchdog, guest-panicked,
	// postmigrate, inmigrate, save-vm, restore-vm and so on, and in NONE of
	// them can the guest service the ACPI request a graceful shutdown sends.
	//
	// So this does not test for "paused" — it mirrors go-proxmox's own
	// IsRunning predicate (virtual_machine.go:377) exactly: genuinely
	// running means Status "running" AND QMPStatus either absent or
	// "running". Anything else surfaces as its own QMP state string for
	// Satisfied and Apply to act on.
	//
	// DELIBERATELY NOT AN ALLOWLIST OF QMP STATES. go-proxmox defines only
	// three status constants (virtual_machine.go:17-19) and enumerates no
	// QMP run states at all; the full set is QEMU's own RunState enum,
	// which this project has not verified against a live host or a local
	// source. Hardcoding a guessed list would mean any state omitted from it
	// silently read as "running" and hung the caller for ten minutes — the
	// exact failure the earlier paused-only check produced for every state
	// that was not literally "paused". Treating QMPStatus as an OPEN set and
	// failing closed on anything that is not affirmatively running is the
	// only form of this check that cannot be wrong by omission.
	if vm.Status == proxmox.StatusVirtualMachineRunning &&
		vm.QMPStatus != "" && vm.QMPStatus != proxmox.StatusVirtualMachineRunning {
		return vm.QMPStatus, nil
	}
	return vm.Status, nil
}

// Satisfied reports whether VMID is already in the state a graceful
// shutdown would produce. Only a genuinely not-running VM qualifies:
//
//   - "stopped" (including a hibernated VM, which PVE reports as stopped)
//     is satisfied — there is nothing to shut down.
//   - EVERYTHING ELSE is not, and this is an ALLOWLIST rather than a
//     denylist on purpose. Read can now return any QEMU run state PVE puts
//     in qmpstatus (see Read), and that set is open-ended. A denylist would
//     have to name every non-running state, and any it missed would fall
//     through to "satisfied" — reporting a VM that is paused, in io-error,
//     or guest-panicked as "already shut down" and skipping Apply entirely.
//     An allowlist fails the other way: an unrecognised state is not
//     satisfied, Apply runs, and Apply refuses it by name.
//   - "running" is therefore not satisfied: that is the one transition this
//     Op performs.
//   - "" is not satisfied. An empty status means the state was never
//     determined, and an unusable read must never read as "already
//     stopped". Read no longer returns an empty status without an error, so
//     idempotent.Run cannot reach this branch; it is kept for a caller that
//     compares a state it obtained some other way.
func (op *VMShutdown) Satisfied(current string) bool {
	return current == proxmox.StatusVirtualMachineStopped
}

// Apply asks the guest to shut itself down and waits for PVE's task to
// finish. A WaitForTask failure — a genuine task failure
// (pve.TaskFailedError) or a timeout (pve.IsTaskTimeoutError) — is this
// Op's own Apply error, never swallowed: a guest that ignored the ACPI
// request or hung on its own shutdown leaves the VM running, and reporting
// that as success would be exactly the "command exits 0 but did something
// other than what was asked" failure this package's other Ops go out of
// their way to avoid.
//
// There is no escalation step after this failure, by design — see this
// type's own doc comment. A caller that wants one composes it itself.
//
// Apply RE-READS the current state before acting, rather than trusting what
// Read observed earlier in the cycle. Two reasons: it keeps the paused
// refusal below working when Apply is called directly (a test, or a caller
// that skips the Read/Satisfied pair) and under idempotent.Run's --force
// path, which bypasses Satisfied entirely — --force must not be able to
// force a shutdown that physically cannot complete. The extra GetVM is
// cheap next to a shutdown that otherwise blocks for ten minutes.
func (op *VMShutdown) Apply(ctx context.Context) error {
	current, err := op.Read(ctx)
	if err != nil {
		return err
	}
	// A guest that is not affirmatively running cannot service the ACPI
	// request a graceful shutdown sends, so PVE's task would never complete
	// and WaitForTask would block for the full defaultTaskWaitTimeout — ten
	// minutes (internal/pve/task.go) — before failing with a timeout that
	// says nothing about why. Refusing here is immediate and names the
	// actual state.
	//
	// The accepted set is an ALLOWLIST of exactly two states, for the reason
	// Satisfied's doc comment gives: paused, prelaunch, io-error,
	// guest-panicked and the rest of QEMU's run states are an open set, and
	// a denylist would hang the caller for ten minutes on every member it
	// failed to name. "stopped" is accepted rather than refused because
	// reaching Apply with a stopped VM means --force, and asking PVE to shut
	// down an already-stopped VM is harmless — it is the pre-existing
	// behaviour and not this guard's business.
	switch current {
	case proxmox.StatusVirtualMachineRunning, proxmox.StatusVirtualMachineStopped:
	default:
		return fmt.Errorf("vm shutdown: vm %d is in qemu run state %q, not running; a graceful shutdown cannot complete because the guest cannot service the acpi request — resume or recover the vm first", op.VMID, current)
	}

	upid, err := op.Client.ShutdownVM(ctx, op.VMID)
	if err != nil {
		return fmt.Errorf("vm shutdown: vm %d: %w", op.VMID, err)
	}

	if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		return fmt.Errorf("vm shutdown: vm %d: %w", op.VMID, err)
	}
	return nil
}
