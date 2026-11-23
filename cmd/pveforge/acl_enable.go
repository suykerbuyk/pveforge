package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// newACLEnableVMDestroyCmd is `pveforge acl enable-vm-destroy`: the one command
// that gives the roster's own token what `vm destroy` needs, with no
// hand-written pveum and no rotation. The work is internal/bootstrap's
// EnableVMDestroy; this is its flag set, its lock identity and its report.
func newACLEnableVMDestroyCmd() *cobra.Command {
	var role, vmidArg string
	var dryRun, noSSHKey, roleOnly, yes bool
	var resolveFormat func() (kvjson.Format, error)
	cmd := &cobra.Command{
		Use:   "enable-vm-destroy <target-id> [--role NAME] [--dry-run] [--role-only] [--yes] [--vmid N]",
		Short: "Give the roster's token the privileges `vm destroy` needs, without rotating it",
		Long: `One command, one question: plan, confirm, write, check.

It prints the plan (the role's privileges, the widening, the pveum commands),
asks "Proceed? [y/N]" on a terminal, writes, and then runs the check "pveforge
doctor" makes on the token (the same reads "vm destroy" makes first). The
report carries ready and verdict (read them together): ready, or the exact rows
still missing or unknown, and which bootstrap form is safe afterwards. Ready
means the privilege reads on the roster node and / (node-level unless --vmid),
not that every VM can be destroyed; an exit 1 whose verdict says the check did
not run means nothing was verified. --yes answers the question for scripts: it
writes the plan the locked re-read decides, screened to the same two command
shapes, with no confirmed-plan comparison (nothing was confirmed). With no terminal and no --yes a run that would write is refused (exit
4) with nothing written; a run that would write nothing never asks. --dry-run
prints the plan and stops: it never asks and runs no check. The check is
node-level unless --vmid N names a VM. Exit status: 0 when written (or already
enabled) and ready; 4 when refused before anything was written (not confirmed, no
terminal, or any refusal listed below, a lock-wait timeout included); 3 when a
pveum write was sent and ran out of time (its outcome is unknown); 1 when the
grant is in place but the check is not ready, for a failed read (a role list
that times out is exit 1), and for every error after the first write was sent
(the report's wrote and ready fields say which).

Make the target's roster token able to run "pveforge vm destroy": add Sys.Audit,
which PVEVMAdmin lacks, as root over SSH with pveum. The token is NOT revoked or
re-minted: its secret and its existing grants are kept.

It ensures a role (default ` + bootstrap.DefaultVMDestroyRole + `, or --role) holding exactly PVEVMAdmin's
privileges, read from PVE now, plus Sys.Audit, and adds it to the token on /
with propagate 1, additively. The role id may not start with "pve" in any case
(PVE refuses it). The privileges are printed.

  - With --role-only (the order for a fresh or rebuilt target) only the role is
    ensured: the token's permissions are never read and nothing is added to it,
    whatever the roster holds. Then mint the token with:
    pveforge bootstrap <target-id> --grant /:` + bootstrap.DefaultVMDestroyRole + `::1
    A rebuilt node's roster still holds the old token record, which PVE no
    longer knows: without --role-only the command would treat it as a token to
    upgrade and refuse. A roster that holds no token at all gets the role only
    too.
  - Otherwise a target whose token already holds PVEVMAdmin on / is upgraded in
    place.

After the upgrade, bootstrap --grant /:` + bootstrap.DefaultVMDestroyRole + `::1 is reused (nothing changes).
bootstrap --grant /:PVEVMAdmin::1 would now REVOKE the token for every holder:
its privileges are wider than PVEVMAdmin's. Do not run it.

Refused, with nothing written:
  - a role of that name that exists with a different privilege set (PVE's role
    update replaces a set other principals may hold; fix it by hand);
  - a token that does not already hold PVEVMAdmin's privileges (this verb never
    widens a limited token), one with a grant below / that a later bootstrap
    would call too wide, or one inheriting Administrator (root@pam with no
    token ACL);
  - a role that would confer an escalating privilege (` + escalatingList + `).

The write is verified by reading the token's effective permissions back, not
the ACL row: a token owned by a non-root user must have Sys.Audit itself, and
this verb never grants the owner. If the role is no longer exactly the derived
set afterwards, or the token's actual permissions break the invariant the grant
was judged by (bootstrap --grant /:R::1 would not accept them, or the token
gained more than Sys.Audit: a concurrent root editor), the error names the
pveum acl delete that takes the grant back; pveforge deletes nothing. A tree
that merely differs from the prediction but holds the invariant is a success
with a note on stderr.
The roles are read just before the write: PVE has no compare-and-set, so an
edit by another root session between the read and the write is detected after
the fact, not prevented. The command holds bootstrap's per-target lock for the
write. --dry-run reads, judges and prints what it would send.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := resolveFormat()
			if err != nil {
				return err
			}
			vmid := 0
			if cmd.Flags().Changed("vmid") {
				if vmid, err = parseDestroyVMID(vmidArg); err != nil {
					return refuseBeforeWrite(cmd, err)
				}
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			access, _, rest, closeAll, err := openRootAccessAndRESTRefusing(cmd, args[0], noSSHKey, true, func(err error) error { return refuseBeforeWrite(cmd, err) })
			if err != nil {
				return err
			}
			defer closeAll()
			// The verdict's node read lock, taken after bootstrap's write lock
			// is released; built here, from cmd.Context(), like doctor's.
			readLock := func() (func() error, error) {
				if rest == nil {
					return nil, errors.New("no token client to read the verdict with")
				}
				return lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "node", ID: rest.Node()})
			}
			// bootstrap's write lock is taken inside EnableVMDestroy, with this
			// command's own context (the lock-wait guard's sink rule).
			enable := func(req bootstrap.EnableVMDestroyRequest) (*bootstrap.EnableVMDestroyResult, error) {
				return bootstrap.EnableVMDestroy(cmd.Context(), access, req)
			}
			return runEnableFlow(cmd, enableFlow{readLock: readLock, enable: enable,
				rest: rest, format: format, target: args[0], rosterPath: rosterPath,
				role: role, dryRun: dryRun, roleOnly: roleOnly, yes: yes, vmid: vmid,
			})
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "the role to ensure and grant (default "+bootstrap.DefaultVMDestroyRole+"); its id may not start with \"pve\" in any case")
	cmd.Flags().BoolVar(&roleOnly, "role-only", false, "ensure and validate the role only: never read the token's permissions and never add the role to it, whatever the roster holds (the order for a fresh or rebuilt target: this, then bootstrap --grant /:"+bootstrap.DefaultVMDestroyRole+"::1)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the write without asking (required when there is no terminal to ask on); has no effect with --dry-run")
	cmd.Flags().StringVar(&vmidArg, "vmid", "", "also check the privileges on this VM in the final verdict (a canonical decimal vmid)")
	resolveFormat = addOutputFlag(cmd)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "read and judge everything, print the commands that would be sent, write nothing")
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	cmd.Flags().String("host-key-fingerprint", "", hostKeyFingerprintAccessUsage)
	addRosterFlag(cmd)
	// A real run takes bootstrap's per-target lock; --lock-wait bounds the wait.
	addLockWaitFlag(cmd)
	// destructive, as acl grant: a widened grant can be used before it is
	// revoked.
	markDestructive(cmd)
	return cmd
}

// enableReport is what the verb renders, through ONE kvjson.Render (a second
// one writes the pre-prompt plan to stderr). Every string is bounded.
type enableReport struct {
	Target     string      `json:"target"`
	Role       string      `json:"role"`
	Privileges []string    `json:"privileges"`
	Outcome    string      `json:"outcome"`
	Token      string      `json:"token,omitempty"`
	Widened    []string    `json:"widened,omitempty"`
	Wrote      bool        `json:"wrote"`
	DryRun     bool        `json:"dry_run,omitempty"`
	Planned    []string    `json:"planned,omitempty"`
	Notes      []string    `json:"notes,omitempty"`
	Ready      *bool       `json:"ready,omitempty"` // absent unless a verdict ran
	Scope      string      `json:"scope,omitempty"`
	Verdict    string      `json:"verdict,omitempty"`
	Rows       []doctorRow `json:"rows,omitempty"`
	AfterRule  string      `json:"after_rule,omitempty"`
	Next       string      `json:"next,omitempty"`
}

// The outcomes the report adds to bootstrap's (upgraded, already_enabled,
// role_only): a plan shown before the prompt, a refusal for want of a
// confirmation, and an answer of no.
const (
	enableOutcomePlan     = "plan"
	enableOutcomeRefused  = "refused"
	enableOutcomeDeclined = "declined"
)

func (r *enableReport) bound() {
	for _, list := range []*[]string{&r.Privileges, &r.Widened, &r.Planned, &r.Notes} {
		for i := range *list {
			(*list)[i] = boundErrText((*list)[i])
		}
	}
	for i := range r.Rows {
		for _, p := range []*string{&r.Rows[i].Requirement, &r.Rows[i].Path, &r.Rows[i].Verdict, &r.Rows[i].Hint, &r.Rows[i].Detail} {
			*p = boundErrText(*p)
		}
	}
	for _, p := range []*string{&r.Target, &r.Role, &r.Outcome, &r.Token, &r.Scope, &r.Verdict, &r.AfterRule, &r.Next} {
		*p = boundErrText(*p)
	}
}

// enableFlow is one run's inputs.
type enableFlow struct {
	rest       *pve.RoutedClient
	format     kvjson.Format
	target     string
	rosterPath string
	role       string
	dryRun     bool
	roleOnly   bool
	yes        bool
	vmid       int
	readLock   func() (func() error, error)
	enable     func(bootstrap.EnableVMDestroyRequest) (*bootstrap.EnableVMDestroyResult, error)
}

func (f enableFlow) request() bootstrap.EnableVMDestroyRequest {
	return bootstrap.EnableVMDestroyRequest{
		Role: f.role, RoleOnly: f.roleOnly, RosterPath: f.rosterPath, TargetID: f.target,
	}
}

// reportOf is the report for a bootstrap result, before any verdict.
func (f enableFlow) reportOf(res *bootstrap.EnableVMDestroyResult) enableReport {
	rep := enableReport{
		Target: f.target, Role: res.Role, Privileges: res.Privileges, Outcome: res.Outcome, Token: res.TokenID,
		Widened: res.Widened, DryRun: res.DryRun, Planned: res.Planned, Notes: res.Notes,
	}
	if !res.DryRun {
		rep.Wrote = res.Outcome == bootstrap.EnableUpgraded || (res.Outcome == bootstrap.EnableRoleOnly && res.RoleCreated)
	}
	return rep
}

// runEnableFlow is the whole operator flow: plan, confirm, write, verdict.
//
//  1. Unless --yes, a DRY pass reads and judges everything with no lock. Every
//     refusal of the verb happens here, before any question is asked.
//  2. If the plan writes nothing, there is nothing to confirm. If it writes
//     and --dry-run was given, that is the answer. Otherwise the person is
//     asked (stderr, a terminal on stdin AND stderr), or --yes stands for the
//     answer; with neither, the run is refused with nothing written.
//  3. The REAL pass takes bootstrap's lock, re-reads, and must be about to send
//     exactly the confirmed commands (ExpectPlan), or it refuses. The prompt is
//     never inside that lock.
//  4. After a write, or when already enabled, the verdict is doctor's
//     (doctorVerdict), never a computation of this file.
func runEnableFlow(cmd *cobra.Command, f enableFlow) error {
	out := cmd.OutOrStdout()
	if f.dryRun {
		req := f.request()
		req.DryRun = true
		res, err := f.enable(req)
		if err != nil {
			return err
		}
		rep := f.reportOf(res)
		rep.bound()
		return kvjson.Render(out, f.format, rep)
	}

	var res *bootstrap.EnableVMDestroyResult
	if f.yes {
		// --yes stands for the answer: no plan pass, the single real run the
		// verb always was. It judges and refuses inside, with nothing written.
		var err error
		if res, err = f.enable(f.request()); err != nil {
			return err
		}
	} else {
		planReq := f.request()
		planReq.DryRun = true
		plan, err := f.enable(planReq)
		if err != nil {
			return err
		}
		if len(plan.Planned) == 0 {
			// Nothing would be written: no question, no --yes needed.
			plan.DryRun = false
			res = plan
		} else {
			decl := f.reportOf(plan)
			decl.Outcome, decl.DryRun = enableOutcomePlan, false
			if err := f.confirm(cmd, decl); err != nil {
				return err // the refusal (exit 4), or a signal; the report is rendered
			}
			realReq := f.request()
			realReq.ExpectPlan = slices.Clone(plan.Planned)
			if res, err = f.enable(realReq); err != nil {
				return err
			}
		}
	}
	return f.finish(cmd, res)
}

// confirm asks, or refuses for want of a terminal. It returns nil only on an
// affirmative answer. On "no" and on no terminal it renders the report and
// returns the refusal (exit 4, nothing dispatched); on a signal it returns the
// prompt-interrupted error.
func (f enableFlow) confirm(cmd *cobra.Command, planRep enableReport) error {
	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	refuse := func(outcome string, why error) error {
		planRep.Outcome, planRep.Wrote = outcome, false
		planRep.bound()
		rerr := kvjson.Render(out, f.format, planRep)
		return errors.Join(newRefusedError(why), rerr)
	}
	if !confirmTerminal() {
		return refuse(enableOutcomeRefused, fmt.Errorf("acl enable-vm-destroy: the plan needs a confirmation and there is no terminal to ask on; nothing was written: re-run with --yes to confirm"))
	}
	shown := planRep
	shown.bound()
	if err := kvjson.Render(errOut, f.format, shown); err != nil {
		return err
	}
	ok, err := confirmAsk(cmd.Context(), confirmInput(), errOut)
	if err != nil {
		if errors.Is(err, roster.ErrPromptInterrupted) {
			return err
		}
		return refuse(enableOutcomeDeclined, fmt.Errorf("acl enable-vm-destroy: no answer (%w); nothing was written", err))
	}
	if !ok {
		return refuse(enableOutcomeDeclined, errors.New("acl enable-vm-destroy: not confirmed; nothing was written"))
	}
	return nil
}

// finish renders the result of a real pass and, unless it was role-only, runs
// the verdict.
func (f enableFlow) finish(cmd *cobra.Command, res *bootstrap.EnableVMDestroyResult) error {
	rep := f.reportOf(res)
	if res.Outcome == bootstrap.EnableRoleOnly {
		rep.Next = fmt.Sprintf("mint the token with: pveforge bootstrap %s --grant /:%s::1", f.target, res.Role)
		rep.bound()
		return kvjson.Render(cmd.OutOrStdout(), f.format, rep)
	}
	rep.AfterRule = fmt.Sprintf("re-bootstrap this token only with: pveforge bootstrap %s --grant /:%s::1; --grant /:PVEVMAdmin::1 now REVOKES it", f.target, res.Role)

	// The verdict. Every arm below ends in ONE decideVerdict call (doctor.go),
	// the only writer of `ready` and `verdict`; an arm that could not read says
	// why in unread, and is never ready.
	var verr error
	var unread string
	var vrep doctorReport
	if f.rest == nil {
		unread, verr = "no token client", errors.New("acl enable-vm-destroy: the verdict could not be read: no token client")
	} else if r, err := doctorVerdict(cmd.Context(), f.rest, f.readLock, f.target, f.vmid); err != nil {
		unread, verr = "the verdict read failed", fmt.Errorf("acl enable-vm-destroy: the verdict could not be read: %w", err)
	} else {
		vrep = r
		// A node path where the grant is correct but Sys.Audit is still not
		// effective (the token's own override row): vm destroy's status read
		// refuses there. It comes from the library's structured field, never a
		// note's text, and becomes a missing row for each path.
		for _, path := range res.AuditNotEffective {
			vrep.Rows = append(vrep.Rows, auditNotEffectiveRow(path))
		}
	}
	ready, line := decideVerdict(vrep, f.vmid, unread)
	rep.Ready, rep.Verdict = &ready, line
	if unread == "" {
		rep.Rows = vrep.Rows
		rep.Scope = "node"
		if f.vmid > 0 {
			rep.Scope = "node+vm"
		}
		if !ready {
			c := classifyRows(vrep)
			did := "nothing was written"
			if rep.Wrote {
				did = "the grant was written"
			}
			verr = fmt.Errorf("acl enable-vm-destroy: %s privileges are not ready on target %s (%d missing, %d unknown); %s: see the verdict and rows in the report",
				doctorVerb, f.target, c.missing, c.unknown, did)
		}
	}
	rep.bound()
	rerr := kvjson.Render(cmd.OutOrStdout(), f.format, rep)
	return errors.Join(verr, rerr)
}
