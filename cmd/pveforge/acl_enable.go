package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
)

// newACLEnableVMDestroyCmd is `pveforge acl enable-vm-destroy`: the one command
// that gives the roster's own token what `vm destroy` needs, with no
// hand-written pveum and no rotation. The work is internal/bootstrap's
// EnableVMDestroy; this is its flag set, its lock identity and its report.
func newACLEnableVMDestroyCmd() *cobra.Command {
	var role string
	var dryRun, noSSHKey, roleOnly bool
	cmd := &cobra.Command{
		Use:   "enable-vm-destroy <target-id> [--role NAME] [--dry-run] [--role-only]",
		Short: "Give the roster's token the privileges `vm destroy` needs, without rotating it",
		Long: `Make the target's roster token able to run "pveforge vm destroy": add Sys.Audit,
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
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			access, _, closeAll, err := openRootAccess(cmd, args[0], noSSHKey, true)
			if err != nil {
				return err
			}
			defer closeAll()
			res, err := bootstrap.EnableVMDestroy(cmd.Context(), access, bootstrap.EnableVMDestroyRequest{
				Role: role, DryRun: dryRun, RoleOnly: roleOnly, RosterPath: rosterPath, TargetID: args[0],
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			prefix := args[0] + ": "
			if res.DryRun {
				prefix += "dry run: "
			}
			fmt.Fprintf(out, "%srole %s holds %d privileges: %s\n", prefix, res.Role, len(res.Privileges), strings.Join(res.Privileges, ","))
			switch res.Outcome {
			case bootstrap.EnableRoleOnly:
				fmt.Fprintf(out, "%sthe roster holds no token for this target: role %s ready; mint the token with: pveforge bootstrap %s --grant /:%s::1\n", prefix, res.Role, args[0], res.Role)
			case bootstrap.EnableAlreadyEnabled:
				fmt.Fprintf(out, "%salready enabled: %s holds %s on / (nothing changed)\n", prefix, res.TokenID, res.Role)
			case bootstrap.EnableUpgraded:
				fmt.Fprintf(out, "%s%s gains %s on / (widening: %s)\n", prefix, res.TokenID, res.Role, strings.Join(res.Widened, ","))
			}
			for _, n := range res.Notes {
				fmt.Fprintf(cmd.ErrOrStderr(), "note: %s%s\n", prefix, n)
			}
			for _, c := range res.Planned {
				fmt.Fprintf(out, "%swould run: %s\n", prefix, c)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "the role to ensure and grant (default "+bootstrap.DefaultVMDestroyRole+"); its id may not start with \"pve\" in any case")
	cmd.Flags().BoolVar(&roleOnly, "role-only", false, "ensure and validate the role only: never read the token's permissions and never add the role to it, whatever the roster holds (the order for a fresh or rebuilt target: this, then bootstrap --grant /:"+bootstrap.DefaultVMDestroyRole+"::1)")
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
