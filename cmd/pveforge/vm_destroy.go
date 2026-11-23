package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// This file is `pveforge vm destroy`: the production verb with the
// destroy-retry-safety contract (vault task pveforge-vm-destroy-verb-retry-
// safety, spec doc/vm-destroy-retry-safety-spec.md) designed in.
//
// The decision order is the spec's, and the first step that fires decides the
// outcome: usage → object lock → visibility probe + in-flight determination →
// --yes → placement/existence → status gate, stop, dispatch, wait, gone-proof.
// The determination, the gone-proof and the status gate are U4, U5 and
// idempotent.VMDestroy's; this file is the ORDER and the MAPPING of their
// answers to one report on stdout and one exit status, and nothing else.
//
// Invariants this file keeps (each has a mutant, vm_destroy_test.go):
//
//   - 0 DELETE and 0 STOP on every refusal; no DELETE after any stop failure;
//   - "ok" only on a JudgeGone GONE — post-dispatch from DestroyEnd, never from
//     WaitForTask() == nil (which is also nil for "WARNINGS: n");
//   - exit 4 never after a dispatch; a refusal carries no `upid` and no `reason`;
//   - the lock precedes any network contact; a local file never decides.
//
// DO NOT paste the idiom of `pveforge harness vm destroy` (harness_vm.go):
// it issues the DELETE after the gated stop, returns the wait error as a plain
// exit 1, and proves "gone" with outer.VMGone, whose pool leg 403s once PVE
// removes the guest's pool membership. Nor idempotent.VMDestroy.Apply, which
// never determines and treats a nil wait as success.

// destroyVerdictTimeout bounds the gone-proof's reads (the free-proof and, on a
// retry, the member scan of about 2N+4 sequential reads). It is PROVISIONAL, as
// pve's destroyDeterminationTimeout is: whether 120s is the right number is the
// spec's open question Q7 and is settled by neither this constant nor a test
// of it. Its expiry is never an interrupt: post-dispatch it is "proof
// unestablished" (exit 3), pre-dispatch a refusal (exit 4).
const destroyVerdictTimeout = 120 * time.Second

// The four outcomes (spec I2b), the closed value set of the `outcome` field.
const (
	outcomeOK      = "ok"
	outcomeFailed  = "failed"
	outcomeUnknown = "unknown"
	outcomeRefused = "refused"
)

// The `reason` values, a closed set carried only by failed and unknown rows.
const (
	reasonDeadline            = "deadline"
	reasonReadFailure         = "read-failure"
	reasonInterrupted         = "interrupted"
	reasonProofUnestablished  = "proof-unestablished"
	reasonDispatchUnconfirmed = "dispatch-unconfirmed"
	reasonStopUnknown         = "stop-unknown"
	reasonUnclean             = "unclean"
	reasonTaskFailed          = "task-failed"
	reasonDispatchRefused     = "dispatch-refused"
	reasonStopFailed          = "stop-failed"
)

// destroyReport is the ONE value `vm destroy` renders, through ONE
// kvjson.Render, so -o kv and -o json agree by construction. Every field but
// target, vmid and outcome is omitempty: a fact that is unknown for an outcome
// is ABSENT in both formats (kvjson.Scalar would print it as null).
//
// Presence rules, held per row by the tests: upid only on an ok/failed/unknown
// row that has a destroy identity and NEVER on a refusal; inflight_* only on
// B4/B4b/B4c; reason only on failed/unknown; already_destroyed only on B5-gone;
// stop_upid only on the two stop rows and only if one was decoded.
type destroyReport struct {
	Target           string `json:"target"`
	VMID             int    `json:"vmid"`
	Outcome          string `json:"outcome"`
	Situation        string `json:"situation,omitempty"`
	Reason           string `json:"reason,omitempty"`
	UPID             string `json:"upid,omitempty"`
	ExitStatus       string `json:"exitstatus,omitempty"`
	AlreadyDestroyed bool   `json:"already_destroyed,omitempty"`
	InflightUPID     string `json:"inflight_upid,omitempty"`
	InflightType     string `json:"inflight_type,omitempty"`
	StopUPID         string `json:"stop_upid,omitempty"`
	PriorUPID        string `json:"prior_upid,omitempty"`
	PriorExitStatus  string `json:"prior_exitstatus,omitempty"`
	Node             string `json:"node,omitempty"`
	OtherNode        string `json:"other_node,omitempty"`
	Observed         string `json:"observed,omitempty"`
	Read             string `json:"read,omitempty"`
	Error            string `json:"error,omitempty"`
	Privilege        string `json:"privilege,omitempty"`
	Condition        string `json:"condition,omitempty"`
	// Fix is the one command that grants what a refused read lacked, present
	// only on a refusal whose Privilege is a Sys.Audit that PVE answered 403
	// for: `doctor`'s own remedy, from the same format string.
	Fix string `json:"fix,omitempty"`
	// rosterNode is the node the token's client is bound to (not rendered): a
	// refusal naming another member's /nodes/<m> gets a different fix.
	rosterNode string
}

// bound cuts every PVE-derived string field with boundErrText BEFORE Render:
// Render does not bound, and runRoot bounds only the error it prints on
// stderr, so an unbounded body would otherwise reach stdout whole.
func (r *destroyReport) bound() {
	for _, p := range []*string{&r.Situation, &r.Reason, &r.UPID, &r.ExitStatus, &r.InflightUPID, &r.InflightType,
		&r.StopUPID, &r.PriorUPID, &r.PriorExitStatus, &r.Node, &r.OtherNode, &r.Observed, &r.Read, &r.Error,
		&r.Privilege, &r.Condition, &r.Fix} {
		*p = boundErrText(*p)
	}
}

// destroyResult is a finished invocation: the report, and the error whose TYPE
// sets the exit status (nil for ok). cause is non-nil for every outcome but ok.
type destroyResult struct {
	rep   destroyReport
	cause error
}

// err maps the outcome to the typed error runRoot turns into a status. The
// constructors are the only way to build the two typed errors (exitstatus.go).
func (d destroyResult) err() error {
	switch d.rep.Outcome {
	case outcomeOK:
		return nil
	case outcomeUnknown:
		return newOutcomeUnknownError(d.cause)
	case outcomeRefused:
		return newRefusedError(d.cause)
	default:
		return d.cause
	}
}

// errText is an error's text, bounded: the one place a PVE-derived error
// becomes a report field.
// fixFor is the remedy a refusal names: doctor's, for a Sys.Audit privilege
// PVE refused (Privilege is set only from a 403, never from a 5xx, a timeout, a
// truncated list or a lock), and nothing for any other refusal.
func fixFor(privilege, target, rosterNode string) string {
	if !strings.HasPrefix(privilege, "Sys.Audit") {
		return ""
	}
	fix := fmt.Sprintf(doctorFixFmt, target)
	// A refusal on ANOTHER member's node: the grant on / already reaches every
	// node, so if the token holds the role, the command answers "already
	// enabled" and the cause is the token's own override row on that node.
	// Say so, so the operator is not sent in a loop.
	if node, ok := strings.CutPrefix(privilege, "Sys.Audit on /nodes/"); ok && node != "" && node != rosterNode {
		fix += fmt.Sprintf("; if it reports already enabled, check the token's own ACL rows on /nodes/%s: an override there hides Sys.Audit", node)
	}
	return fix
}

// withFix names the remedy on a refusal, in the report and in the error text.
func (d destroyResult) withFix() destroyResult {
	if fix := fixFor(d.rep.Privilege, d.rep.Target, d.rep.rosterNode); fix != "" {
		d.rep.Fix = fix
		d.cause = fmt.Errorf("%w; run: %s", d.cause, fix)
	}
	return d
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return boundErrText(err.Error())
}

// destroyDeps is what runVMDestroy needs. The client is the concrete
// *pve.RoutedClient — the HTTP fixture is the test double, so no interface
// mirrors it — and the budget is a field with its production default, so a test
// shortens it without a package-level seam.
type destroyDeps struct {
	client        *pve.RoutedClient
	target        string
	stderr        io.Writer
	verdictBudget time.Duration
}

type destroyInput struct {
	vmid int
	yes  bool
}

// pvePermissionCheck is the sentence PVE puts in a 403 body, e.g.
// "Permission check failed (/vms/691, VM.Allocate)".
var pvePermissionCheck = regexp.MustCompile(`Permission check failed \([^)]*\)`)

var canonicalVMID = regexp.MustCompile(`^[1-9][0-9]*$`)

// parseDestroyVMID accepts only a canonical positive decimal: the verb acts on
// an identifier the operator stated literally, so "+100" and "0100" (which
// strconv.Atoi would take, and the lock key would normalise) are refused.
func parseDestroyVMID(arg string) (int, error) {
	if !canonicalVMID.MatchString(arg) {
		return 0, fmt.Errorf("invalid vmid %q: want a canonical decimal number such as 100", arg)
	}
	vmid, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid vmid %q: %w", arg, err)
	}
	return vmid, nil
}

func newVMDestroyCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "destroy <target-id> <vmid>",
		Short: "Destroy a VM, with its disks, and prove it is gone",
		Long: `Destroy the VM <vmid> on the target's node, purging it and its disks, and
report one of four outcomes on stdout (the "outcome" field, identical in -o kv
and -o json) and in the exit status:

outcome  exit  meaning
  ok       exit 0  the VM is proven gone (the destroy task ended exactly OK and PVE says the vmid is free)
  failed   exit 1  a known failure; do not retry blindly
  unknown  exit 3  a destroy or stop request may have been sent and its outcome was not observed
  refused  exit 4  NOTHING was dispatched; wait and re-run

Re-running the same command resolves an unknown outcome: it asks PVE what
became of the earlier destroy. PVE decides, never a local file. The command
refuses while PVE shows an unfinished destroy, migrate, clone, restore, stop or
shutdown of this vmid, and when it cannot establish that none is running.

It is irreversible and destroys exactly the VM you name. Nothing here protects
against naming the wrong VM correctly. --yes is required, and is checked after
the reads, so a refusal tells you the real reason first (a re-run that only
resolves an earlier destroy needs --yes too).

The token must hold Sys.Audit on /nodes/<node> (to see every task there),
VM.PowerMgmt (the stop) and VM.Allocate (the destroy); resolving a RETRY also
needs Sys.Audit on / (the cluster member list). A destroy issued seconds after a
shutdown of the same VM refuses until that task has ended.

The object lock is held for the whole run; --lock-wait bounds acquiring it
only. The wait for the task is not configurable (up to 10 minutes).`,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm this irreversible destroy (required)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		// Usage errors are exit 1 with an empty stdout, before any roster
		// read or network contact.
		vmid, err := parseDestroyVMID(args[1])
		if err != nil {
			return err
		}
		client, err := resolveRoutedClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}

		render := func(res destroyResult) error {
			res.rep.bound()
			rerr := kvjson.Render(cmd.OutOrStdout(), format, res.rep)
			return errors.Join(res.err(), rerr)
		}

		// Step 1b: the object lock, before ANY request to PVE. A lock that is
		// not acquired is a refusal that dispatched nothing.
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)})
		if err != nil {
			return render(lockRefused(args[0], vmid, err))
		}
		defer func() { _ = unlock() }()

		deps := destroyDeps{client: client, target: args[0], stderr: cmd.ErrOrStderr(), verdictBudget: destroyVerdictTimeout}
		return render(runVMDestroy(cmd.Context(), deps, destroyInput{vmid: vmid, yes: yes}))
	}
	markDestructive(cmd)
	return cmd
}

func lockRefused(target string, vmid int, err error) destroyResult {
	rep := destroyReport{
		Target: target, VMID: vmid, Outcome: outcomeRefused, Situation: "B10",
		Observed:  fmt.Sprintf("the object lock for vm %d on target %s was not acquired", vmid, target),
		Read:      "lock",
		Error:     errText(err),
		Condition: "re-run once the other pveforge command holding the lock on this vm has finished, or raise --lock-wait (it bounds acquiring the lock only)",
	}
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: refused (B10): %w", vmid, err)}
}

// runVMDestroy is steps 2-6 of the decision order. It never renders and never
// takes the lock; its caller holds it for the whole call.
func runVMDestroy(ctx context.Context, d destroyDeps, in destroyInput) destroyResult {
	client, vmid := d.client, in.vmid
	node := client.Node()
	base := destroyReport{Target: d.target, VMID: vmid, rosterNode: node}

	// Steps 2 and 3: the visibility probe and the in-flight determination.
	det := client.DetermineDestroyInFlight(ctx, vmid)
	if !det.Proceed {
		if det.Refusal == nil {
			// Never reachable by the determination's own contract; fail closed.
			return refuse(base, "B10", "the in-flight determination gave no answer", "re-run once PVE can be read completely")
		}
		return refusedFromInFlight(base, det.Refusal)
	}

	// Step 4: --yes, AFTER the determination so an operator who also has an
	// in-flight destroy is told that first.
	if !in.yes {
		r := refuse(base, "B4d", "--yes was not given: this destroy is irreversible and must be confirmed",
			"re-run with --yes to confirm (a re-run that only resolves an earlier destroy needs --yes too)")
		return r
	}

	// Step 5: placement and existence, from this verb's OWN node-local config
	// read. idempotent.VMDestroy.Read goes through RawRequest, so a 403 is a
	// *pve.StatusError that pve.HTTPStatus sees; GetVM would not.
	op := &idempotent.VMDestroy{Client: client, VMID: vmid}
	cur, rerr := op.Read(ctx)
	presence := pve.PresenceHere
	switch {
	case rerr == nil && cur == "":
		presence = pve.PresenceAbsent
	case rerr == nil:
		presence = pve.PresenceHere
	default:
		if code, ok := pve.HTTPStatus(rerr); ok && code == 403 {
			presence = pve.PresenceForbidden
		} else {
			// The verb's own refusal: JudgeGone never refuses on an unreadable
			// presence, it is the caller's job.
			r := refuse(base, "B10", fmt.Sprintf("the node-local config of vm %d on node %s could not be read", vmid, node),
				fmt.Sprintf("re-run once GET /nodes/%s/qemu/%d/config answers", node, vmid))
			r.rep.Read = fmt.Sprintf("GET /nodes/%s/qemu/%d/config", node, vmid)
			r.rep.Error = errText(rerr)
			return r
		}
	}
	if presence == pve.PresenceAbsent || presence == pve.PresenceForbidden {
		return d.judge(ctx, base, pve.GoneEvidence{Presence: presence, Dispatched: false})
	}

	// Step 6: the VM is here. A prior failed destroy is visible, never a reason
	// to refuse (B6).
	if det.LastDestroy != nil && !det.LastDestroyEndedOK {
		base.PriorUPID, base.PriorExitStatus = det.LastDestroy.UPID, det.LastDestroy.Status
		fmt.Fprintf(d.stderr, "notice: %s: vm %d: a prior destroy %s ended %s; this is a new attempt\n",
			kvjson.QuoteValue(boundErrText(d.target)), vmid, kvjson.QuoteValue(boundErrText(det.LastDestroy.UPID)),
			kvjson.QuoteValue(boundErrText(det.LastDestroy.Status)))
	}

	// The status gate and the gated stop. classifyStop is the ONLY classifier
	// of a StatusGatedStop error, and no error from here reaches the DELETE.
	if err := op.StatusGatedStop(ctx); err != nil {
		return classifyStop(base, vmid, err)
	}

	upid, derr := client.DestroyVM(ctx, vmid, true)
	if derr != nil {
		return classifyDispatch(base, vmid, derr)
	}
	base.UPID = upid

	if werr := client.WaitForTask(ctx, node, upid); werr != nil {
		return classifyWait(ctx, base, vmid, werr)
	}

	// The wait returned nil, which is also nil for "WARNINGS: n": how the
	// destroy ENDED is read from PVE's per-task status, by exact exit string.
	vctx, cancel := context.WithTimeout(ctx, d.verdictBudget)
	defer cancel()
	end, eerr := client.DestroyEnd(vctx, vmid, upid)
	ev := pve.GoneEvidence{Dispatched: true, Destroy: end}
	if eerr != nil {
		ev.DestroyReadErr = errText(eerr)
	}
	return d.judgeWith(vctx, base, ev)
}

// judge runs JudgeGone under the verdict budget.
func (d destroyDeps) judge(ctx context.Context, base destroyReport, ev pve.GoneEvidence) destroyResult {
	vctx, cancel := context.WithTimeout(ctx, d.verdictBudget)
	defer cancel()
	return d.judgeWith(vctx, base, ev)
}

func (d destroyDeps) judgeWith(vctx context.Context, base destroyReport, ev pve.GoneEvidence) destroyResult {
	v := d.client.JudgeGone(vctx, base.VMID, ev)
	return mapVerdict(base, v, ev.Dispatched)
}

func refuse(base destroyReport, situation, observed, condition string) destroyResult {
	rep := base
	rep.Outcome, rep.Situation, rep.Observed, rep.Condition = outcomeRefused, situation, observed, condition
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: refused (%s): %s; %s", base.VMID, situation, observed, condition)}
}

// refusedFromInFlight builds a refusal ONLY from the determination's own
// InFlightRefusal: the wording lives there, once. No upid, no reason.
func refusedFromInFlight(base destroyReport, r *pve.InFlightRefusal) destroyResult {
	rep := base
	rep.Outcome, rep.Situation = outcomeRefused, string(r.Situation)
	rep.Node, rep.Condition = r.Node, r.Condition
	if r.Situation == pve.SituationUnreadable {
		rep.Read, rep.Error, rep.Privilege = r.Read, r.ReadErr, r.Privilege
		rep.Observed = fmt.Sprintf("%s could not be completed", r.Read)
	} else {
		rep.InflightUPID, rep.InflightType = r.UPID, r.TaskType
		rep.Observed = fmt.Sprintf("a non-terminal %s task %s for vm %d is in flight on node %s", r.TaskType, r.UPID, r.VMID, r.Node)
	}
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: refused (%s): %s; %s", base.VMID, rep.Situation, rep.Observed, r.Condition)}.withFix()
}

// mapVerdict maps U5's verdict to an outcome:
// GONE→ok, UNCLEAN→failed, UNPROVEN→unknown (3), and UNREADABLE, ELSEWHERE,
// ABSENT-NO-TASK and IN-FLIGHT-ELSEWHERE→refused (4).
func mapVerdict(base destroyReport, v *pve.GoneVerdict, dispatched bool) destroyResult {
	rep := base
	rep.Node = v.Node
	switch v.Situation {
	case pve.GoneProven:
		rep.Outcome, rep.UPID, rep.ExitStatus = outcomeOK, v.UPID, v.ExitStatus
		if dispatched {
			rep.Situation = "B1"
		} else {
			rep.Situation, rep.AlreadyDestroyed, rep.Node = "B5-gone", true, v.DecidedOn
		}
		return destroyResult{rep: rep}
	case pve.GoneUnclean:
		rep.Outcome, rep.Reason, rep.UPID, rep.ExitStatus = outcomeFailed, reasonUnclean, v.UPID, v.ExitStatus
		rep.Observed, rep.Condition = v.Observed, v.Condition
		rep.Situation = "B5-unclean"
		if dispatched {
			rep.Situation = "B1-unclean"
		}
		return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %s", base.VMID, v.Observed)}
	case pve.GoneUnproven:
		// This invocation dispatched the destroy and cannot prove how it ended:
		// the identity (base.UPID) is kept, the exit is 3.
		rep.Outcome, rep.Reason, rep.Situation = outcomeUnknown, reasonProofUnestablished, "B1-unproven"
		rep.Observed, rep.Read, rep.Error, rep.Condition, rep.Privilege = v.Observed, v.Read, v.ReadErr, v.Condition, v.Privilege
		return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: dispatched, but not proven gone: %s", base.VMID, v.Observed)}
	}
	// Every other verdict is a refusal: nothing was dispatched (the dispatched
	// bit makes a post-dispatch failure UNPROVEN above, never one of these).
	rep.Outcome = outcomeRefused
	rep.Observed, rep.Read, rep.Error, rep.Privilege, rep.Condition = v.Observed, v.Read, v.ReadErr, v.Privilege, v.Condition
	rep.OtherNode = v.OtherNode
	switch v.Situation {
	case pve.GoneElsewhere:
		rep.Situation = "B5-elsewhere"
	case pve.GoneAbsentNoTask:
		rep.Situation = "B5-absent-without-task"
	case pve.GoneInFlightElsewhere:
		rep.Situation, rep.InflightUPID = "B4", v.UPID
	default: // GoneUnreadable, and any value this switch does not know: fail closed
		rep.Situation = "B10"
	}
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: refused (%s): %s; %s", base.VMID, rep.Situation, v.Observed, v.Condition)}.withFix()
}

// answeredDefinitively reports whether err is PVE's own answer that a worker
// was NOT released: a 4xx, or a 500/501 (a die before fork_worker). Anything
// else — no answer, a gateway status (502-504, 595-599), a 2xx whose body is
// not a UPID — may mean a worker exists and the response was lost.
func answeredDefinitively(err error) bool {
	code, ok := pve.HTTPStatus(err)
	return ok && ((code >= 400 && code < 500) || code == 500 || code == 501)
}

// classifyStop is the ONLY classifier of a StatusGatedStop error. It branches
// on the error CHAIN, not on the phase alone, and no result of it reaches the
// DELETE. (The destroy-wait "interrupted if the command ctx is done" arm never
// runs on this chain: a stop task past WaitForTask's own deadline with the
// command ctx live is stop-unknown.)
func classifyStop(base destroyReport, vmid int, err error) destroyResult {
	var sg *idempotent.StopGateError
	if !errors.As(err, &sg) {
		// Unreachable (StatusGatedStop returns only *StopGateError); fail safe.
		rep := base
		rep.Outcome, rep.Situation, rep.Reason, rep.Error = outcomeUnknown, "stop-unknown", reasonStopUnknown, errText(err)
		return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: stop: %w", vmid, err)}
	}
	rep := base
	switch sg.Phase {
	case idempotent.StopGatePhaseStatusGate:
		// Nothing was dispatched: the fail-closed gate read could not be made.
		r := refuse(base, "B10", fmt.Sprintf("the run status of vm %d could not be read (status gate)", vmid),
			"re-run once the VM's status can be read")
		r.rep.Read, r.rep.Error = "status gate", errText(sg)
		return r
	case idempotent.StopGatePhaseStopPost:
		if answeredDefinitively(sg) {
			rep.Outcome, rep.Situation, rep.Reason = outcomeFailed, "stop-failed", reasonStopFailed
		} else {
			rep.Outcome, rep.Situation, rep.Reason = outcomeUnknown, "stop-unknown", reasonStopUnknown
		}
	default: // StopGatePhaseStopWait: a stop task was dispatched
		rep.StopUPID = sg.UPID
		var tf *pve.TaskFailedError
		if errors.As(sg, &tf) {
			rep.Outcome, rep.Situation, rep.Reason = outcomeFailed, "stop-failed", reasonStopFailed
		} else {
			rep.Outcome, rep.Situation, rep.Reason = outcomeUnknown, "stop-unknown", reasonStopUnknown
		}
	}
	rep.Error = errText(sg)
	rep.Observed = fmt.Sprintf("the stop that precedes the destroy of vm %d did not complete; the destroy was NOT dispatched", vmid)
	if rep.Outcome == outcomeUnknown {
		rep.Condition = "re-run: the next run asks PVE, and refuses (B4c) while that stop is unfinished"
	}
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %w", vmid, sg)}
}

// classifyDispatch is the DELETE's failure. PVE's own refusal (4xx, 500, 501)
// is a known failure with nothing dispatched; no answer at all, a gateway
// status, or a 2xx without a UPID is UNKNOWN, with no upid: a worker may exist
// and the next run resolves it through the determination.
func classifyDispatch(base destroyReport, vmid int, err error) destroyResult {
	rep := base
	rep.UPID = ""
	rep.Error = errText(err)
	if answeredDefinitively(err) {
		rep.Outcome, rep.Situation, rep.Reason = outcomeFailed, "dispatch-refused", reasonDispatchRefused
		rep.Observed = fmt.Sprintf("PVE refused the destroy of vm %d; nothing was destroyed", vmid)
		switch code, _ := pve.HTTPStatus(err); code {
		case 403:
			// Name the privilege a destroy needs, and quote PVE's OWN sentence
			// as the observation: the path and privilege PVE names are PVE's to
			// say, never invented here.
			rep.Privilege = "VM.Allocate"
			if m := pvePermissionCheck.FindString(rep.Error); m != "" {
				rep.Observed = fmt.Sprintf("PVE refused the destroy of vm %d (403): %q", vmid, m)
			}
			rep.Condition = "this token lacks the privilege to destroy the VM (the verb uses the roster token only and never falls back to root)"
		case 401:
			// A bad token is not a missing privilege: name none.
			rep.Observed = fmt.Sprintf("PVE did not accept the roster's token for the destroy of vm %d (401)", vmid)
			rep.Condition = "fix or re-mint the target's token (the verb uses the roster token only and never falls back to root)"
		}
		return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %w", vmid, err)}
	}
	rep.Outcome, rep.Situation, rep.Reason = outcomeUnknown, reasonDispatchUnconfirmed, reasonDispatchUnconfirmed
	rep.Observed = fmt.Sprintf("the destroy of vm %d got no definite answer: a worker may exist", vmid)
	rep.Condition = "re-run: the next run asks PVE what became of it"
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %w", vmid, err)}
}

// classifyWait is the DESTROY task's wait failure (the stop's is classifyStop).
func classifyWait(ctx context.Context, base destroyReport, vmid int, err error) destroyResult {
	rep := base
	var tf *pve.TaskFailedError
	if errors.As(err, &tf) {
		rep.Outcome, rep.Situation, rep.Reason, rep.ExitStatus = outcomeFailed, "task-failed", reasonTaskFailed, tf.ExitStatus
		rep.Error = errText(err)
		return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %w", vmid, err)}
	}
	rep.Outcome = outcomeUnknown
	switch {
	case ctx.Err() != nil:
		rep.Situation, rep.Reason = "B9", reasonInterrupted
	case pve.IsTaskTimeoutError(err):
		rep.Situation, rep.Reason = "B2", reasonDeadline
	default:
		rep.Situation, rep.Reason = "B3", reasonReadFailure
	}
	rep.Error = errText(err)
	rep.Condition = "re-run: the next run asks PVE how the destroy ended, or follow the upid up directly"
	return destroyResult{rep: rep, cause: fmt.Errorf("vm destroy: vm %d: %w", vmid, err)}
}
