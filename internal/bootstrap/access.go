package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// RootAccess is the root channel for PVE's principals and ACLs (task
// pveforge-pveum-user-group-acl-ops, 6a): every write runs as root over SSH
// through pveum, the same channel bootstrap mints and grants its own token
// on, so the roster's token never needs User.Modify or Permissions.Modify
// (the operator's ruling; the over-broad-token rule is not relaxed).
//
// Reads that decide whether to write (UserEnsure/GroupEnsure's Read) go over
// the token's REST view first, and over root's pveum only when that view is
// refused (401/403) or the target holds no token: a run whose objects are
// already as asked never opens root at all. The ACL grant's own reads (the
// role list, a group's members, the read-back) go over the root session that
// makes the grant, which sees every entry a token's filtered view might not.
//
// The session is dialed on first use: with the target's stored key and
// pinned host key, or, keyless (Password set), as root with that per-run
// password and the host key trusted on first use, exactly as bootstrap's
// --no-ssh-key does.
//
// NOT LIVE-VERIFIED: the pveum flag names used here (user add/modify
// --enable/--comment/--email/--groups/--append, group add/modify --comment,
// acl modify --users/--groups/--tokens/--roles/--propagate, and the list
// commands' --output-format json) are reproduced from PVE's documentation,
// like bootstrap's own token commands.
type RootAccess struct {
	opts      AccessOptions
	transport SSHTransport
	session   SSHSession
}

// AccessOptions configures a RootAccess.
type AccessOptions struct {
	// Addr is the target's SSH address, host:port.
	Addr string
	// SSHUser, PrivateKeyPEM and HostKeyFingerprint are the target's stored
	// SSH auth. Unused when Password is set.
	SSHUser            string
	PrivateKeyPEM      []byte
	HostKeyFingerprint string
	// Password, when set, makes the session keyless: root with this per-run
	// password, the host key trusted on first use. It is called only when
	// the session is first needed.
	Password func(ctx context.Context) (string, error)
	// REST is the token's view, for the Ensure reads; nil when the target
	// holds no token, so every read goes over root.
	REST AccessReader
	// OwnToken is the roster token's id, "<userid>!<name>", or "" when the
	// target holds none. A grant to it, or to its user, is refused.
	OwnToken string
}

// AccessReader is the token's REST view of users and groups.
type AccessReader interface {
	ListUsers(ctx context.Context) ([]pve.AccessUser, error)
	ListGroups(ctx context.Context) ([]pve.AccessGroup, error)
}

// NewRootAccess returns a RootAccess that dials nothing until it is used.
func NewRootAccess(opts AccessOptions, transport SSHTransport) *RootAccess {
	return &RootAccess{opts: opts, transport: transport}
}

// Close closes the session, if one was opened.
func (a *RootAccess) Close() error {
	if a.session == nil {
		return nil
	}
	return a.session.Close()
}

// Connect opens the root session now, asking for the password first when
// the session is keyless, rather than on the first command. A caller that
// is about to take a pveforge lock connects first, so a prompt or a slow
// dial never holds the lock.
func (a *RootAccess) Connect(ctx context.Context) error {
	_, err := a.root(ctx)
	return err
}

// root returns the session, dialing it on first use.
func (a *RootAccess) root(ctx context.Context) (SSHSession, error) {
	if a.session != nil {
		return a.session, nil
	}
	if a.opts.Password != nil {
		pw, err := a.opts.Password(ctx)
		if err != nil {
			return nil, err
		}
		s, _, err := a.transport.DialWithPassword(ctx, a.opts.Addr, "root", pw, "")
		if err != nil {
			return nil, fmt.Errorf("connect as root with the password: %w", err)
		}
		a.session = s
		return s, nil
	}
	s, err := a.transport.ReconnectWithPinnedKey(ctx, a.opts.Addr, a.opts.SSHUser, a.opts.PrivateKeyPEM, a.opts.HostKeyFingerprint)
	if err != nil {
		return nil, fmt.Errorf("connect as %s with the stored key: %w", a.opts.SSHUser, err)
	}
	a.session = s
	return s, nil
}

// pveum runs one command as root and returns its stdout: a pveum command,
// or ClusterGuests' one pvesh read. It is RootAccess's only command runner.
func (a *RootAccess) pveum(ctx context.Context, cmd string) (string, error) {
	s, err := a.root(ctx)
	if err != nil {
		return "", err
	}
	res, err := s.Run(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("run %s: %w", firstWords(cmd), err)
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s exited %d: %s", firstWords(cmd), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return res.Stdout, nil
}

// ClusterGuestsCommand is the one command ClusterGuests runs as root: a
// read of PVE's cluster resource list, nothing else.
const ClusterGuestsCommand = "pvesh get /cluster/resources --type vm --output-format json"

// ClusterGuests lists every QEMU VM and LXC container in the cluster, with
// its tags, as root@pam (ClusterGuestsCommand). root's read is filtered by
// no ACL: PVE drops a guest from a token's list unless the token holds
// VM.Audit on that guest's own /vms/<vmid>, and no read a token can make
// proves none was dropped. The reply is decoded strictly
// (pve.ParseClusterGuests); any failure is an error, never an empty list.
func (a *RootAccess) ClusterGuests(ctx context.Context) ([]pve.Guest, error) {
	out, err := a.pveum(ctx, ClusterGuestsCommand)
	if err != nil {
		return nil, fmt.Errorf("list the cluster's guests as root: %w", err)
	}
	return pve.ParseClusterGuests([]byte(out))
}

// refusedByToken reports whether a REST read failed because the token may
// not read it (401/403): the one failure root's read replaces. Anything
// else — a transport error, a 5xx, a malformed answer — stays an error.
func refusedByToken(err error) bool {
	code, ok := pve.HTTPStatus(err)
	return ok && (code == http.StatusUnauthorized || code == http.StatusForbidden)
}

// ListUsers reads every user, over the token's view, or root's when that is
// refused or the target holds no token.
func (a *RootAccess) ListUsers(ctx context.Context) ([]pve.AccessUser, error) {
	if a.opts.REST != nil {
		users, err := a.opts.REST.ListUsers(ctx)
		if err == nil || !refusedByToken(err) {
			return users, err
		}
	}
	out, err := a.pveum(ctx, "pveum user list --full 1 --output-format json")
	if err != nil {
		return nil, err
	}
	return pve.ParseAccessUsers([]byte(out))
}

// ListGroups reads every group, as ListUsers reads users.
func (a *RootAccess) ListGroups(ctx context.Context) ([]pve.AccessGroup, error) {
	if a.opts.REST != nil {
		groups, err := a.opts.REST.ListGroups(ctx)
		if err == nil || !refusedByToken(err) {
			return groups, err
		}
	}
	return a.rootGroups(ctx)
}

func (a *RootAccess) rootGroups(ctx context.Context) ([]pve.AccessGroup, error) {
	out, err := a.pveum(ctx, "pveum group list --output-format json")
	if err != nil {
		return nil, err
	}
	return pve.ParseAccessGroups([]byte(out))
}

// AddUser creates a user as root. A @pve user is left with no password: it
// cannot log in until an operator sets one (pveum passwd). The enable flag
// is always sent.
func (a *RootAccess) AddUser(ctx context.Context, spec idempotent.UserSpec) error {
	cmd := "pveum user add " + sshexec.ShellQuote(spec.UserID) + userFlags(spec)
	if len(spec.Groups) > 0 {
		cmd += " --groups " + sshexec.ShellQuote(strings.Join(spec.Groups, ","))
	}
	_, err := a.pveum(ctx, cmd)
	return err
}

// ModifyUser updates a user as root. The enable flag is always sent (an
// update that omits it re-enables the user); groups are appended, never
// replaced.
func (a *RootAccess) ModifyUser(ctx context.Context, spec idempotent.UserSpec) error {
	cmd := "pveum user modify " + sshexec.ShellQuote(spec.UserID) + userFlags(spec)
	if len(spec.Groups) > 0 {
		cmd += " --groups " + sshexec.ShellQuote(strings.Join(spec.Groups, ",")) + " --append 1"
	}
	_, err := a.pveum(ctx, cmd)
	return err
}

// userFlags renders a UserSpec's --enable, --comment and --email.
func userFlags(spec idempotent.UserSpec) string {
	enable := 0
	if spec.Enable {
		enable = 1
	}
	s := fmt.Sprintf(" --enable %d", enable)
	if spec.Comment != nil {
		s += " --comment " + sshexec.ShellQuote(*spec.Comment)
	}
	if spec.Email != nil {
		s += " --email " + sshexec.ShellQuote(*spec.Email)
	}
	return s
}

// AddGroup creates a group as root.
func (a *RootAccess) AddGroup(ctx context.Context, groupID string, comment *string) error {
	cmd := "pveum group add " + sshexec.ShellQuote(groupID)
	if comment != nil {
		cmd += " --comment " + sshexec.ShellQuote(*comment)
	}
	_, err := a.pveum(ctx, cmd)
	return err
}

// ModifyGroup sets a group's comment as root.
func (a *RootAccess) ModifyGroup(ctx context.Context, groupID, comment string) error {
	_, err := a.pveum(ctx, "pveum group modify "+sshexec.ShellQuote(groupID)+" --comment "+sshexec.ShellQuote(comment))
	return err
}

// ---- the ACL grant ----

// Principal is who an ACL grant is for: Kind "user", "group" or "token".
type Principal struct {
	Kind, ID string
}

func (p Principal) String() string { return p.Kind + " " + p.ID }

// EscalatingPrivileges are the privileges that let their holder widen its
// own or anyone's power, or reach past PVE's permission model: grant ACLs,
// create or change users and realms, change or get a console on the node,
// drive a VM's QEMU monitor, allocate storage definitions, or change
// hardware mappings. A grant conferring any of them, directly or through
// group membership, is refused unless explicitly allowed. The list is the
// operator's (2026-09-24, task pveforge-pveum-user-group-acl-ops).
var EscalatingPrivileges = []string{
	"Permissions.Modify", "User.Modify", "Sys.Modify", "Realm.Allocate",
	"Sys.Console", "VM.Monitor", "Realm.AllocateUser", "Datastore.Allocate", "Mapping.Modify",
}

var (
	// ErrSelfGrant: a grant to pveforge's own token or its user, or to a
	// group that user is in. Always refused.
	ErrSelfGrant = errors.New("refusing to grant to pveforge's own principal")
	// ErrEscalatingRole: a grant conferring an escalating privilege,
	// without --allow-escalating-role.
	ErrEscalatingRole = errors.New("refusing an escalating role")
	// ErrUnknownGroup: a group grant names a group PVE does not have.
	ErrUnknownGroup = errors.New("no such group on PVE")
	// ErrGrantNotConfirmed: the ACL list read after a grant does not hold
	// its exact entry.
	ErrGrantNotConfirmed = errors.New("the grant is not in the ACL list read back after it")
)

// GrantRequest is one `pveforge acl grant`.
type GrantRequest struct {
	Principal Principal
	// Grants, as ParseGrants returns them: explicit, propagate 0 unless
	// asked, a pinned privilege set checked against the role's.
	Grants              []Grant
	AllowEscalatingRole bool
}

// EscalatingGrant is an allowed grant that confers escalating privileges.
type EscalatingGrant struct {
	Grant Grant
	Privs []string
}

// GrantOutcome is what a grant did.
type GrantOutcome struct {
	// Entries are the confirmed ACL entries, one per grant, in order.
	Entries []pve.ACLEntry
	// Escalating are the grants allowed by AllowEscalatingRole.
	Escalating []EscalatingGrant
}

// CheckPrincipal reports whether p is a well-formed principal.
func CheckPrincipal(p Principal) error {
	switch p.Kind {
	case "user":
		return pve.CheckUserID(p.ID)
	case "group":
		return pve.CheckGroupID(p.ID)
	case "token":
		return pve.CheckTokenID(p.ID)
	}
	return fmt.Errorf("%w: kind %q is not user, group or token", pve.ErrInvalidPrincipal, p.Kind)
}

// ownUser is the user that owns the roster's token, or "".
func (a *RootAccess) ownUser() string {
	u, _, _ := strings.Cut(a.opts.OwnToken, "!")
	return u
}

// checkNotSelf refuses a grant to the roster's own token or its user,
// before anything is dialed. Ids are compared ignoring case, which only
// ever refuses more.
func (a *RootAccess) checkNotSelf(p Principal) error {
	if a.opts.OwnToken == "" {
		return nil
	}
	switch {
	case p.Kind == "token" && strings.EqualFold(p.ID, a.opts.OwnToken):
		return fmt.Errorf("%w: %s is the roster's own token", ErrSelfGrant, p.ID)
	case p.Kind == "user" && strings.EqualFold(p.ID, a.ownUser()):
		return fmt.Errorf("%w: %s owns the roster's token %s", ErrSelfGrant, p.ID, a.opts.OwnToken)
	}
	return nil
}

// GrantACL grants every requested grant to the principal as root, after
// refusing, before any write:
//   - a malformed principal or grant;
//   - the roster's own token or its user (checked before any dial), or a
//     group that user belongs to (read as root);
//   - an unknown role, a role with no privileges, or a pinned privilege set
//     that is not exactly the role's (bootstrap's grant rules);
//   - a grant conferring an escalating privilege, unless allowed.
//
// It then reads the ACL list back as root and requires each grant's exact
// entry: path, role, principal and propagate. PVE merges a repeated grant,
// so a run that repeats one changes nothing there.
func (a *RootAccess) GrantACL(ctx context.Context, req GrantRequest) (*GrantOutcome, error) {
	if err := CheckPrincipal(req.Principal); err != nil {
		return nil, err
	}
	want, err := normalizeGrants(req.Grants)
	if err != nil {
		return nil, err
	}
	if err := a.checkNotSelf(req.Principal); err != nil {
		return nil, err
	}

	rolePrivs, err := a.rolePrivs(ctx, want)
	if err != nil {
		return nil, err
	}
	if req.Principal.Kind == "group" {
		if err := a.checkGroupNotSelf(ctx, req.Principal.ID); err != nil {
			return nil, err
		}
	}
	out := &GrantOutcome{}
	for _, g := range want {
		conferred := rolePrivs[g.Role]
		if g.Privs != nil {
			conferred = g.Privs
		}
		esc := escalating(conferred)
		if len(esc) == 0 {
			continue
		}
		if !req.AllowEscalatingRole {
			return nil, fmt.Errorf("%w: %s on %s confers %s; pass --allow-escalating-role to grant it anyway (nothing was granted)",
				ErrEscalatingRole, g.Role, g.Path, strings.Join(esc, ","))
		}
		out.Escalating = append(out.Escalating, EscalatingGrant{Grant: g, Privs: esc})
	}

	var applied []string
	for i, g := range want {
		if err := a.aclModify(ctx, req.Principal, g); err != nil {
			done := "none was applied"
			if len(applied) > 0 {
				done = "already applied: " + strings.Join(applied, "; ")
			}
			return nil, fmt.Errorf("grant %d of %d (%s on %s) failed, %s: %w", i+1, len(want), g.Role, g.Path, done, err)
		}
		applied = append(applied, fmt.Sprintf("%s on %s", g.Role, g.Path))
	}

	acls, err := a.rootACLs(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the ACL list back: %w", err)
	}
	for _, g := range want {
		e := pve.ACLEntry{Path: g.Path, Role: g.Role, Type: req.Principal.Kind, UGID: req.Principal.ID, Propagate: g.Propagate}
		if !slices.Contains(acls, e) {
			return nil, fmt.Errorf("%w: %s on %s for %s, propagate %t", ErrGrantNotConfirmed, g.Role, g.Path, req.Principal, g.Propagate)
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// rolePrivs reads the role list as root and applies bootstrap's grant
// rules to want: every role exists and grants something, and a pinned
// privilege set is exactly the role's.
func (a *RootAccess) rolePrivs(ctx context.Context, want []Grant) (map[string][]string, error) {
	all, err := a.allRolePrivs(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, g := range want {
		if _, done := out[g.Role]; !done {
			privs, ok := all[g.Role]
			if !ok {
				return nil, fmt.Errorf("%w: %q", ErrUnknownRole, g.Role)
			}
			if len(privs) == 0 {
				return nil, fmt.Errorf("%w: %s", ErrRoleHasNoPrivileges, g.Role)
			}
			out[g.Role] = privs
		}
		if g.Privs != nil {
			if missing, extra := setDiff(g.Privs, out[g.Role]); len(missing) > 0 || len(extra) > 0 {
				return nil, fmt.Errorf("%w: %s at %s: pinned but not in the role [%s], in the role but not pinned [%s]; nothing was granted",
					ErrPinnedPrivsMismatch, g.Role, g.Path, strings.Join(missing, ","), strings.Join(extra, ","))
			}
		}
	}
	return out, nil
}

// allRolePrivs reads the role list as root: every role's privileges.
func (a *RootAccess) allRolePrivs(ctx context.Context) (map[string][]string, error) {
	s, err := a.root(ctx)
	if err != nil {
		return nil, err
	}
	var roles []struct {
		RoleID string  `json:"roleid"`
		Privs  *string `json:"privs"`
	}
	if err := runJSONArray(ctx, s, "pveum role list --output-format json", &roles); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(roles))
	for _, r := range roles {
		privs, err := parseRolePrivs(r.Privs)
		if err != nil {
			return nil, fmt.Errorf("role %s: %w", r.RoleID, err)
		}
		out[r.RoleID] = privs
	}
	return out, nil
}

// rootACLs reads the ACL list as root.
func (a *RootAccess) rootACLs(ctx context.Context) ([]pve.ACLEntry, error) {
	raw, err := a.pveum(ctx, "pveum acl list --output-format json")
	if err != nil {
		return nil, err
	}
	return pve.ParseACLEntries([]byte(raw))
}

// escalating returns the escalating privileges among privs.
func escalating(privs []string) []string {
	var out []string
	for _, p := range EscalatingPrivileges {
		if slices.Contains(privs, p) {
			out = append(out, p)
		}
	}
	return out
}

// checkGroupNotSelf refuses a group the roster token's user is in: granting
// to it would widen pveforge's own token's ceiling. It fails closed, reading
// membership twice as root: the group list must carry the group's "users"
// field (a missing or null field is not "no members"), and the owner's own
// entry in the full user list must be found; either one naming the group is
// a refusal.
func (a *RootAccess) checkGroupNotSelf(ctx context.Context, groupID string) error {
	groups, err := a.rootGroups(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(groups, func(g pve.AccessGroup) bool { return g.GroupID == groupID })
	if i < 0 {
		return fmt.Errorf("%w: %q", ErrUnknownGroup, groupID)
	}
	own := a.ownUser()
	if own == "" {
		return nil
	}
	if !groups[i].UsersListed {
		return fmt.Errorf("cannot tell whether group %s holds %s, which owns the roster's token: the group list carries no members field for it: %w", groupID, own, pve.ErrUnverifiableRead)
	}
	for _, u := range groups[i].Users {
		if strings.EqualFold(u, own) {
			return fmt.Errorf("%w: group %s holds %s, which owns the roster's token %s", ErrSelfGrant, groupID, u, a.opts.OwnToken)
		}
	}
	out, err := a.pveum(ctx, "pveum user list --full 1 --output-format json")
	if err != nil {
		return err
	}
	users, err := pve.ParseAccessUsers([]byte(out))
	if err != nil {
		return err
	}
	j := slices.IndexFunc(users, func(u pve.AccessUser) bool { return strings.EqualFold(u.UserID, own) })
	if j < 0 {
		return fmt.Errorf("cannot tell whether group %s holds %s: the user list has no entry for it: %w", groupID, own, pve.ErrUnverifiableRead)
	}
	if slices.Contains(users[j].Groups, groupID) {
		return fmt.Errorf("%w: %s, which owns the roster's token %s, is in group %s", ErrSelfGrant, users[j].UserID, a.opts.OwnToken, groupID)
	}
	return nil
}

// EscalatingJoin is a group, joined with AllowEscalatingRole, that holds a
// role conferring escalating privileges.
type EscalatingJoin struct {
	Group string
	Entry pve.ACLEntry
	Privs []string
}

// CheckGroupJoin decides whether userID may be added to groups. Joining a
// group is a grant: the user gains every ACL the group holds. So:
//   - the user owning the roster's token may join no group at all, with no
//     override (checked before anything is dialed);
//   - any other user may not join a group holding, on any path, a role that
//     confers an escalating privilege, unless allowEscalating, in which
//     case every such holding, of every group, is returned for the caller
//     to report. Refused, the error names every one.
//
// The ACL and role lists are read as root. The answer holds for the lists
// as read: a group or role widened after the join, or an ACL granted to the
// group by a concurrent `acl grant`, is not seen (nothing serialises the
// two commands).
func (a *RootAccess) CheckGroupJoin(ctx context.Context, userID string, groups []string, allowEscalating bool) ([]EscalatingJoin, error) {
	if own := a.ownUser(); own != "" && strings.EqualFold(userID, own) {
		return nil, fmt.Errorf("%w: %s owns the roster's token %s, and joining a group grants it that group's ACLs", ErrSelfGrant, userID, a.opts.OwnToken)
	}
	if len(groups) == 0 {
		return nil, nil
	}
	roles, err := a.allRolePrivs(ctx)
	if err != nil {
		return nil, err
	}
	acls, err := a.rootACLs(ctx)
	if err != nil {
		return nil, err
	}
	var out []EscalatingJoin
	for _, g := range groups {
		for _, e := range acls {
			if e.Type != "group" || e.UGID != g {
				continue
			}
			privs, ok := roles[e.Role]
			if !ok {
				return nil, fmt.Errorf("group %s holds role %s on %s, which the role list does not have: %w", g, e.Role, e.Path, pve.ErrUnverifiableRead)
			}
			esc := escalating(privs)
			if len(esc) == 0 {
				continue
			}
			out = append(out, EscalatingJoin{Group: g, Entry: e, Privs: esc})
		}
	}
	if len(out) > 0 && !allowEscalating {
		held := make([]string, len(out))
		for i, j := range out {
			held[i] = fmt.Sprintf("group %s holds %s on %s, which confers %s", j.Group, j.Entry.Role, j.Entry.Path, strings.Join(j.Privs, ","))
		}
		return nil, fmt.Errorf("%w: %s; joining a group grants what it holds; pass --allow-escalating-role to add %s anyway (nothing was changed)",
			ErrEscalatingRole, strings.Join(held, "; "), userID)
	}
	return out, nil
}

// aclModify grants g to p as root: `pveum acl modify` with the whole grant
// stated, --propagate explicit (pveum's default is 1).
func (a *RootAccess) aclModify(ctx context.Context, p Principal, g Grant) error {
	propagate := 0
	if g.Propagate {
		propagate = 1
	}
	flag := map[string]string{"user": "--users", "group": "--groups", "token": "--tokens"}[p.Kind]
	_, err := a.pveum(ctx, fmt.Sprintf("pveum acl modify %s %s %s --roles %s --propagate %d",
		sshexec.ShellQuote(g.Path), flag, sshexec.ShellQuote(p.ID), sshexec.ShellQuote(g.Role), propagate))
	return err
}
