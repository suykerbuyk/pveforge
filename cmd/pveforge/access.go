package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// `pveforge user ensure`, `group ensure` and `acl grant` (task
// pveforge-pveum-user-group-acl-ops, 6a): principals and ACLs, written as
// root over SSH with pveum so the roster's token never needs User.Modify or
// Permissions.Modify. See bootstrap.RootAccess for the transport. And
// `access inventory` (task pveforge-pveum-inventory-read, 6b): the same
// lists, read as root, joined with the node's accounts.

// newAccessTransport is the SSH transport the access commands dial root
// with; a test replaces it.
var newAccessTransport = bootstrap.NewSSHTransport

// accessSSHPort is the port root is dialed on, as RoutedClient's standing
// SSH vector uses: the roster has no per-target SSH port.
const accessSSHPort = "22"

// escalatingList names bootstrap.EscalatingPrivileges for help text, so the
// text can never drift from the list the checks use.
var escalatingList = strings.Join(bootstrap.EscalatingPrivileges, ", ")

const noSSHKeyAccessUsage = "connect as root with the PVE password (" + pvePasswordEnvVar + ", else a prompt) for this run only, trusting the host key on first use, as bootstrap --no-ssh-key does; required for a target that holds no SSH key"

// openRootAccess loads targetID and returns its RootAccess, dialing nothing
// yet, and a func that closes whatever it opened. tokenView gives it the
// roster token's REST view and identity, for the Ensures' reads and the
// self checks; without it the token's secret is never decrypted.
func openRootAccess(cmd *cobra.Command, targetID string, noSSHKey, tokenView bool) (*bootstrap.RootAccess, *roster.Target, func(), error) {
	a, t, _, closeAll, err := openRootAccessAndREST(cmd, targetID, noSSHKey, tokenView)
	return a, t, closeAll, err
}

// openRootAccessAndREST is openRootAccess that also returns the token's
// RoutedClient it built (nil when the target holds no token, or tokenView
// is false), so a command that needs both root and the REST client loads
// the roster and resolves its passphrase once. A target that holds no SSH
// key is refused, unless noSSHKey, before the passphrase is asked for.
func openRootAccessAndREST(cmd *cobra.Command, targetID string, noSSHKey, tokenView bool) (*bootstrap.RootAccess, *roster.Target, *pve.RoutedClient, func(), error) {
	rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	r, err := roster.Load(rosterPath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load roster %s: %w", rosterPath, err)
	}
	t := r.Find(targetID)
	if t == nil {
		return nil, nil, nil, nil, fmt.Errorf("target %q not found in roster %s", targetID, rosterPath)
	}
	if !noSSHKey && t.SSH == nil {
		return nil, nil, nil, nil, fmt.Errorf("target %q holds no SSH key: pass --no-ssh-key to connect as root with the PVE password for this run", targetID)
	}
	pass, err := roster.ResolvePassphraseContext(cmd.Context())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	opts := bootstrap.AccessOptions{Addr: net.JoinHostPort(t.Host, accessSSHPort)}
	closeREST := func() {}
	var rest *pve.RoutedClient
	if tokenView && t.Token != nil {
		rc, err := pve.NewRoutedClient(t, pass)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		rest, opts.REST, opts.OwnToken, closeREST = rc, rc, t.Token.ID, func() { _ = rc.Close() }
	}
	if noSSHKey {
		opts.Password = resolvePVEPassword
	} else {
		key, err := roster.DecryptString(t.SSH.PrivateKeyEnc, pass)
		if err != nil {
			closeREST()
			return nil, nil, nil, nil, fmt.Errorf("decrypt ssh key for %q: %w", targetID, err)
		}
		opts.SSHUser, opts.PrivateKeyPEM, opts.HostKeyFingerprint = t.SSH.User, key, t.SSH.HostKeyFingerprint
	}
	a := bootstrap.NewRootAccess(opts, newAccessTransport())
	return a, t, rest, func() { _ = a.Close(); closeREST() }, nil
}

// optionalText returns a flag's value when it was given, refusing a value
// that could not be printed on one line.
func optionalText(cmd *cobra.Command, name string) (*string, error) {
	if !cmd.Flags().Changed(name) {
		return nil, nil
	}
	v, err := cmd.Flags().GetString(name)
	if err != nil {
		return nil, err
	}
	if kvjson.LineUnsafe(v) {
		return nil, fmt.Errorf("--%s must not hold a control character or line break, or begin or end with whitespace", name)
	}
	return &v, nil
}

// ensureVerb is the word a Result earns: created, updated or unchanged.
func ensureVerb(res idempotent.Result) string {
	switch {
	case !res.Changed:
		return "unchanged"
	case res.Before == "absent":
		return "created"
	}
	return "updated"
}

func newUserCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "user", Short: "Ensure PVE users (written as root over SSH)"}
	cmd.AddCommand(newUserEnsureCmd())
	return cmd
}

func newUserEnsureCmd() *cobra.Command {
	var enable, disable, noSSHKey, allowEscalating bool
	var groups []string
	cmd := &cobra.Command{
		Use:   "ensure <target-id> <userid>",
		Short: "Create a PVE user, or bring it to the state asked for",
		Long: `Create a PVE user, or bring it to the state asked for. Idempotent: a user
already as asked is left alone, and root is never connected to.

The write runs as root over SSH with pveum, never with the roster's API token,
which must never hold User.Modify. The read that decides whether to write uses
the token, and root's pveum when the token may not read users.

--enable and --disable set the user's state; with neither, a new user is
enabled and an existing one keeps its state. --comment and --email are set
when given. --group adds the user to a group (repeatable); membership is only
ever added, never removed. A @pve user is created with no password: it cannot
log in until one is set with pveum passwd. A @pam user also needs an account on
the node, which PVE does not create.

Joining a group grants the group's ACLs, so --group is guarded like acl grant:
  - the user that owns the roster's own token may join no group (always; there
    is no override);
  - no user may join a group that holds, on any path, a role conferring
    an escalating privilege (` + escalatingList + `), unless
    --allow-escalating-role is given (read as root before the write).
Allowed, each escalating holding of each group joined is warned about.

These checks hold only for the groups, ACLs and roles as read just before the
write. A group granted an escalating role, or a role widened (pveum role
modify), after the join is not caught: the user then holds it unwarned.
Nothing serialises user ensure against acl grant, or either against changes
made outside pveforge.

Disabling the user that owns the roster's own token is refused: it would lock
pveforge out of the target.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetID, userID := args[0], args[1]
			if err := pve.CheckUserID(userID); err != nil {
				return err
			}
			if enable && disable {
				return errors.New("--enable and --disable are mutually exclusive")
			}
			comment, err := optionalText(cmd, "comment")
			if err != nil {
				return err
			}
			email, err := optionalText(cmd, "email")
			if err != nil {
				return err
			}
			for _, g := range groups {
				if err := pve.CheckGroupID(g); err != nil {
					return fmt.Errorf("--group: %w", err)
				}
			}
			var want *bool
			if enable || disable {
				want = &enable
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			access, t, closeAll, err := openRootAccess(cmd, targetID, noSSHKey, true)
			if err != nil {
				return err
			}
			defer closeAll()
			if t.Token != nil {
				if own, _, _ := strings.Cut(t.Token.ID, "!"); strings.EqualFold(own, userID) {
					if disable {
						return fmt.Errorf("refusing to disable %s: it owns the roster's own token %s, so pveforge would lock itself out of %s", userID, t.Token.ID, targetID)
					}
					if len(groups) > 0 {
						return fmt.Errorf("refusing --group for %s: it owns the roster's own token %s, and joining a group grants it that group's ACLs", userID, t.Token.ID)
					}
				}
			}
			var joins []bootstrap.EscalatingJoin
			op := &idempotent.UserEnsure{Client: access, UserID: userID, Enable: want, Comment: comment, Email: email, Groups: groups,
				BeforeJoin: func(ctx context.Context, add []string) error {
					var err error
					joins, err = access.CheckGroupJoin(ctx, userID, add, allowEscalating)
					return err
				}}
			key := lock.ObjectKey{TargetID: targetID, Kind: "user", ID: userID}
			res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false)
			if err != nil {
				return err
			}
			verb := ensureVerb(res)
			fmt.Fprintf(cmd.OutOrStdout(), "%s: user %s %s\n", targetID, userID, verb)
			if verb == "created" && strings.HasSuffix(userID, "@pve") {
				fmt.Fprintf(cmd.ErrOrStderr(), "notice: %s: user %s has no password: it cannot log in until one is set with pveum passwd\n", targetID, userID)
			}
			if res.Changed && disable {
				fmt.Fprintf(cmd.ErrOrStderr(), "notice: %s: user %s is disabled: it cannot log in, and its API tokens stop working\n", targetID, userID)
			}
			for _, j := range joins {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: user %s joined group %s, which holds %s on %s conferring %s: the user can widen its own or anyone's access\n",
					targetID, userID, j.Group, j.Entry.Role, j.Entry.Path, strings.Join(j.Privs, ","))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "enable the user")
	cmd.Flags().BoolVar(&disable, "disable", false, "disable the user: it can no longer log in or use its API tokens")
	cmd.Flags().String("comment", "", "set the user's comment")
	cmd.Flags().String("email", "", "set the user's email")
	cmd.Flags().StringArrayVar(&groups, "group", nil, "add the user to this group (repeatable; membership is only added)")
	cmd.Flags().BoolVar(&allowEscalating, "allow-escalating-role", false, "allow joining a group that holds a role conferring an escalating privilege: "+escalatingList)
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	markMutating(cmd)
	return cmd
}

func newGroupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Ensure PVE groups (written as root over SSH)"}
	cmd.AddCommand(newGroupEnsureCmd())
	return cmd
}

func newGroupEnsureCmd() *cobra.Command {
	var noSSHKey bool
	cmd := &cobra.Command{
		Use:   "ensure <target-id> <groupid>",
		Short: "Create a PVE group, or set its comment",
		Long: `Create a PVE group, or set its comment when --comment is given. Idempotent:
a group already as asked is left alone, and root is never connected to. The
write runs as root over SSH with pveum, as for user ensure. A group's members
are set on its users (user ensure --group).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetID, groupID := args[0], args[1]
			if err := pve.CheckGroupID(groupID); err != nil {
				return err
			}
			comment, err := optionalText(cmd, "comment")
			if err != nil {
				return err
			}
			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}
			access, _, closeAll, err := openRootAccess(cmd, targetID, noSSHKey, true)
			if err != nil {
				return err
			}
			defer closeAll()
			op := &idempotent.GroupEnsure{Client: access, GroupID: groupID, Comment: comment}
			key := lock.ObjectKey{TargetID: targetID, Kind: "group", ID: groupID}
			res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: group %s %s\n", targetID, groupID, ensureVerb(res))
			return nil
		},
	}
	cmd.Flags().String("comment", "", "set the group's comment")
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	markMutating(cmd)
	return cmd
}

func newACLCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "acl", Short: "Grant PVE ACL entries (written as root over SSH)"}
	cmd.AddCommand(newACLGrantCmd())
	return cmd
}

func newACLGrantCmd() *cobra.Command {
	var user, group, token string
	var grants []string
	var allowEscalating, noSSHKey bool
	cmd := &cobra.Command{
		Use:   "grant <target-id> (--user <userid> | --group <groupid> | --token <tokenid>) --grant PATH:ROLE[:PRIVS[:PROPAGATE]]...",
		Short: "Grant a role on a path to a user, group or token",
		Long: `Grant a role on a path to a user, group or token, as root over SSH with pveum
acl modify. The roster's API token never holds Permissions.Modify.

--grant PATH:ROLE[:PRIVS[:PROPAGATE]] is repeatable, as for bootstrap:
PROPAGATE is 0 unless given as 1, and PRIVS, when given, must be exactly the
role's privileges on PVE.

Refused before anything is granted:
  - a grant to the roster's own token, to the user that owns it, or to a
    group that user is in (always; there is no override);
  - a role conferring an escalating privilege (` + escalatingList + `),
    unless --allow-escalating-role is given;
  - an unknown role, a role with no privileges, or PRIVS that differ from
    the role's.

The ACL list is read back afterwards as root, and each grant's exact entry
(path, role, principal, propagate) must be in it. PVE merges a repeated
grant, so repeating one changes nothing there. A grant cannot be undone by
pveforge: revoke it with pveum acl delete.

The checks hold only for the roles, groups and users as read just before the
grant. A grant to a group reaches every member, including one who joins
later; a role widened (pveum role modify) after the grant widens it. Nothing
serialises acl grant against user ensure, or either against changes made
outside pveforge.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var principals []bootstrap.Principal
			for kind, id := range map[string]string{"user": user, "group": group, "token": token} {
				if id != "" {
					principals = append(principals, bootstrap.Principal{Kind: kind, ID: id})
				}
			}
			if len(principals) != 1 {
				return errors.New("give exactly one of --user, --group or --token")
			}
			if len(grants) == 0 {
				return errors.New("acl grant requires at least one --grant PATH:ROLE[:PRIVS[:PROPAGATE]]")
			}
			parsed, err := bootstrap.ParseGrants(grants)
			if err != nil {
				return err
			}
			access, _, closeAll, err := openRootAccess(cmd, args[0], noSSHKey, true)
			if err != nil {
				return err
			}
			defer closeAll()
			out, err := access.GrantACL(cmd.Context(), bootstrap.GrantRequest{Principal: principals[0], Grants: parsed, AllowEscalatingRole: allowEscalating})
			if err != nil {
				return err
			}
			for _, e := range out.Entries {
				propagate := 0
				if e.Propagate {
					propagate = 1
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: granted %s on %s to %s %s (propagate %d)\n", args[0], e.Role, e.Path, e.Type, e.UGID, propagate)
			}
			for _, g := range out.Escalating {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s: %s on %s, granted to %s, confers %s: its holder can widen its own or anyone's access\n",
					args[0], g.Grant.Role, g.Grant.Path, principals[0], strings.Join(g.Privs, ","))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "grant to this user (<name>@<realm>)")
	cmd.Flags().StringVar(&group, "group", "", "grant to this group")
	cmd.Flags().StringVar(&token, "token", "", "grant to this API token (<name>@<realm>!<tokenname>)")
	cmd.Flags().StringArrayVar(&grants, "grant", nil, "a grant PATH:ROLE[:PRIVS[:PROPAGATE]] (repeatable; PROPAGATE defaults to 0)")
	cmd.Flags().BoolVar(&allowEscalating, "allow-escalating-role", false, "allow a role conferring an escalating privilege: "+escalatingList)
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	addRosterFlag(cmd)
	// destructive: a widened grant may be used before it is revoked, and
	// what is done with it cannot be undone; an escalating role hands out
	// root-equivalence.
	markDestructive(cmd)
	return cmd
}

func newAccessCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "access", Short: "Read PVE's users, groups and ACLs (as root over SSH)"}
	cmd.AddCommand(newAccessInventoryCmd())
	return cmd
}

// accessInventoryResult is access inventory's output: the target, then the
// inventory's own fields.
type accessInventoryResult struct {
	Target string `json:"target"`
	*bootstrap.AccessInventory
}

func newAccessInventoryCmd() *cobra.Command {
	var noSSHKey bool
	cmd := &cobra.Command{
		Use:   "inventory <target-id>",
		Short: "List every user, group and ACL entry, and each @pam user's account on the node",
		Long: `List every PVE user, group and ACL entry on a target, read as root over SSH
with pveum, never with the roster's API token: a token's view is filtered by
its privileges, and a shorter list would look complete. Nothing is written.

  - users: each user's realm, state, groups, and the ACL entries it holds,
    both those naming it and, marked "via", those of each group it is in.
    A @pam user is looked up on the node (getent passwd): os_account_status
    is "found", with the account, or "absent"; any other realm is "not-pam".
  - groups: each group's members (null when PVE's answer did not list them:
    unknown, not none) and the ACL entries naming it.
  - acls: every ACL entry, API tokens' included; a token appears only here.

Every ACL entry whose role confers an escalating privilege (` + escalatingList + `)
lists those privileges under "escalating". Effective permissions (paths,
propagation and roles combined) are not computed: see pveum user permissions.

A user's groups, and so the entries marked "via", come from the user list's
groups field, which every user must carry, cross-checked against each
group's members both ways: if the two lists disagree, or a field is
missing, the inventory fails rather than show a user holding less than it
does. The node's accounts are looked up with getent passwd, for @pam users
only; an account no PVE user names is not listed. A name getent would read
as a UID (digits, optionally after '+') cannot be looked up by name: it is
"unchecked". The roster's API token is not used or decrypted.

The lists are read one after another with no lock held: a change made while
they are read, by pveforge or anyone else, can show half-applied.`,
		Args: cobra.ExactArgs(1),
	}
	resolveFormat := addOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		access, _, closeAll, err := openRootAccess(cmd, args[0], noSSHKey, false)
		if err != nil {
			return err
		}
		defer closeAll()
		inv, err := access.Inventory(cmd.Context())
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, accessInventoryResult{Target: args[0], AccessInventory: inv})
	}
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	addRosterFlag(cmd)
	markSafe(cmd)
	return cmd
}
