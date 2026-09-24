package bootstrap

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// The access inventory (task pveforge-pveum-inventory-read, 6b): PVE's
// users, groups and ACL entries, each ACL entry flagged with the escalating
// privileges its role confers, and each @pam user joined to its account on
// the node. Everything is read as root, on the RootAccess session, with the
// same readers 6a's writes decide on: the token's REST view may be filtered
// by its privileges and answer a SHORTER list with 200, which an inventory
// cannot tell from a complete one (the Chair's ruling, 2026-09-24).
//
// A user's group memberships, and so the ACL entries it holds "via" a
// group, come from the user list's "groups" field, which every user must
// carry, and are cross-checked both ways against each group's members:
// the two answers must agree, or the inventory is an unverifiable read,
// never a user shown holding less than it does.
//
// The node's accounts are looked up only for @pam users, with getent
// passwd run as root; an account no PVE user names is not listed. getent
// reads a key strtoul parses whole (digits, optionally after a '+') as a
// UID, not a name, so such a name is never sent: it is reported
// "unchecked".
//
// The reads are not atomic, and no lock is held: a change made between
// them, by pveforge or anyone else, can show half-applied.
//
// LIVE-VERIFIED 2026-09-24, by the Chair as root on qa-pve-02 (PVE
// 9.2.11), read-only: `pveum user list --full 1 --output-format json`
// carries "groups" on every user, "" for a user in no group, so requiring
// the field (pve.AccessUser.GroupsListed) refuses nothing real; "tokens" is
// null, or a list for a user holding tokens, and is deliberately not
// parsed (tokens are listed only through their ACL entries). `pveum acl
// list --output-format json` entries carry exactly path, propagate (a
// number), roleid, type ("user" and "token" seen) and ugid. That host has
// no groups, so the group list's "users" shape is still unverified live.
//
// NOT LIVE-VERIFIED: getent's exit status 2 for "one or more keys were not
// found" is read from getent(1), and passwd(5)'s seven fields from its man
// page, not observed on a PVE host; nor is how the node's NSS answers a
// keyed lookup for an account it would not enumerate.

// Values of InventoryUser.OSAccountStatus.
const (
	OSAccountFound  = "found"
	OSAccountAbsent = "absent"
	OSAccountNotPAM = "not-pam"
	// OSAccountUnchecked: a @pam user whose name getent would read as a
	// UID, so it cannot be looked up by name.
	OSAccountUnchecked = "unchecked"
)

// AccessInventory is every user, group and ACL entry on a target.
type AccessInventory struct {
	Users  []InventoryUser  `json:"users"`
	Groups []InventoryGroup `json:"groups"`
	// ACLs is every entry, tokens' included: a token is listed only here.
	ACLs []InventoryACL `json:"acls"`
}

// InventoryACL is one ACL entry. Via names the group a user holds it
// through; it is empty for an entry naming the principal itself.
// Escalating lists the EscalatingPrivileges its role confers.
type InventoryACL struct {
	Path       string   `json:"path"`
	Role       string   `json:"role"`
	Type       string   `json:"type"`
	UGID       string   `json:"ugid"`
	Propagate  bool     `json:"propagate"`
	Via        string   `json:"via,omitempty"`
	Escalating []string `json:"escalating,omitempty"`
}

// InventoryUser is one user, with the ACL entries naming it and those of
// each group it is in. Effective permissions (paths, propagation, roles
// combined) are not computed: pveum user permissions does that.
type InventoryUser struct {
	UserID  string         `json:"userid"`
	Realm   string         `json:"realm"`
	Enabled bool           `json:"enabled"`
	Comment string         `json:"comment,omitempty"`
	Email   string         `json:"email,omitempty"`
	Groups  []string       `json:"groups"`
	ACLs    []InventoryACL `json:"acls"`
	// OSAccount is the node's account for a @pam user, when it has one.
	OSAccount       *OSAccount `json:"os_account"`
	OSAccountStatus string     `json:"os_account_status"`
}

// InventoryGroup is one group. Members is nil when the group list carried
// no members field for it: unknown, not none.
type InventoryGroup struct {
	GroupID string         `json:"groupid"`
	Comment string         `json:"comment,omitempty"`
	Members []string       `json:"members"`
	ACLs    []InventoryACL `json:"acls"`
}

// OSAccount is a passwd(5) entry on the node.
type OSAccount struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

// Inventory reads the access inventory as root: the user, group, ACL and
// role lists, then one getent for every @pam user (none when there are
// none). Any read that cannot be verified fails the whole inventory; no
// entry is ever defaulted.
func (a *RootAccess) Inventory(ctx context.Context) (*AccessInventory, error) {
	users, err := a.rootUsers(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := a.rootGroups(ctx)
	if err != nil {
		return nil, err
	}
	acls, err := a.rootACLs(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := a.allRolePrivs(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkMembership(users, groups); err != nil {
		return nil, err
	}

	inv := &AccessInventory{Users: []InventoryUser{}, Groups: []InventoryGroup{}, ACLs: []InventoryACL{}}
	for _, e := range acls {
		privs, ok := roles[e.Role]
		if !ok {
			return nil, fmt.Errorf("%s %s holds role %s on %s, which the role list does not have: %w", e.Type, e.UGID, e.Role, e.Path, pve.ErrUnverifiableRead)
		}
		inv.ACLs = append(inv.ACLs, InventoryACL{Path: e.Path, Role: e.Role, Type: e.Type, UGID: e.UGID, Propagate: e.Propagate, Escalating: escalating(privs)})
	}
	// held returns the entries naming principal id of kind. The Type
	// comparison changes no answer today, since a user id holds an '@', a
	// group id none and a token id a '!', so dropping it is an EQUIVALENT
	// mutant (the Chair's ruling, 2026-09-24); it stays, so the join never
	// rests on id shapes.
	held := func(kind, id, via string) []InventoryACL {
		out := []InventoryACL{}
		for _, e := range inv.ACLs {
			if e.Type == kind && e.UGID == id {
				e.Via = via
				out = append(out, e)
			}
		}
		return out
	}

	var pam []string
	for _, u := range users {
		_, realm, _ := strings.Cut(u.UserID, "@")
		iu := InventoryUser{UserID: u.UserID, Realm: realm, Enabled: u.Enabled, Comment: u.Comment, Email: u.Email,
			Groups: append([]string{}, u.Groups...), ACLs: held("user", u.UserID, ""), OSAccountStatus: OSAccountNotPAM}
		for _, g := range u.Groups {
			iu.ACLs = append(iu.ACLs, held("group", g, g)...)
		}
		if realm == "pam" {
			if name, _, _ := strings.Cut(u.UserID, "@"); numericKey(name) {
				iu.OSAccountStatus = OSAccountUnchecked
			} else {
				iu.OSAccountStatus = OSAccountAbsent
				pam = append(pam, u.UserID)
			}
		}
		inv.Users = append(inv.Users, iu)
	}
	for _, g := range groups {
		ig := InventoryGroup{GroupID: g.GroupID, Comment: g.Comment, ACLs: held("group", g.GroupID, "")}
		if g.UsersListed {
			ig.Members = append([]string{}, g.Users...)
		}
		inv.Groups = append(inv.Groups, ig)
	}

	if len(pam) == 0 {
		return inv, nil
	}
	accounts, err := a.rootOSAccounts(ctx, pam)
	if err != nil {
		return nil, err
	}
	for i := range inv.Users {
		u := &inv.Users[i]
		if u.OSAccountStatus != OSAccountAbsent {
			continue
		}
		name, _, _ := strings.Cut(u.UserID, "@")
		if acct, ok := accounts[name]; ok {
			u.OSAccount, u.OSAccountStatus = &acct, OSAccountFound
		}
	}
	return inv, nil
}

// checkMembership requires the user list and the group list to agree on
// who is in which group: every user carries a groups field; each group a
// user names exists and, when its members are listed, lists the user; and
// each listed member exists and names the group.
func checkMembership(users []pve.AccessUser, groups []pve.AccessGroup) error {
	byGroup := make(map[string]pve.AccessGroup, len(groups))
	for _, g := range groups {
		byGroup[g.GroupID] = g
	}
	byUser := make(map[string]pve.AccessUser, len(users))
	for _, u := range users {
		if !u.GroupsListed {
			return fmt.Errorf("the user list carries no groups field for %s, so the groups it holds ACLs through are unknown: %w", u.UserID, pve.ErrUnverifiableRead)
		}
		byUser[u.UserID] = u
	}
	for _, u := range users {
		for _, g := range u.Groups {
			grp, ok := byGroup[g]
			if !ok {
				return fmt.Errorf("the user list puts %s in group %s, which the group list does not have: %w", u.UserID, g, pve.ErrUnverifiableRead)
			}
			if grp.UsersListed && !slices.Contains(grp.Users, u.UserID) {
				return fmt.Errorf("the user list puts %s in group %s, whose members do not include it: %w", u.UserID, g, pve.ErrUnverifiableRead)
			}
		}
	}
	for _, g := range groups {
		for _, m := range g.Users {
			u, ok := byUser[m]
			if !ok {
				return fmt.Errorf("group %s lists member %s, which the user list does not have: %w", g.GroupID, m, pve.ErrUnverifiableRead)
			}
			if !slices.Contains(u.Groups, g.GroupID) {
				return fmt.Errorf("group %s lists member %s, whose groups do not include it: %w", g.GroupID, m, pve.ErrUnverifiableRead)
			}
		}
	}
	return nil
}

// numericKey reports whether getent would read name as a UID: glibc's
// getent passwd tries a key as a number first when strtoul parses all of
// it (base 10, an optional sign). A leading '-' or whitespace cannot reach
// here (pve.CheckUserID), so that is digits after an optional '+'.
func numericKey(name string) bool {
	d := strings.TrimPrefix(name, "+")
	return d != "" && strings.Trim(d, "0123456789") == ""
}

// rootOSAccounts looks up the node's account for each @pam user id in one
// getent call, and returns those found, by name. getent exits 0 when every
// key was found and 2 when one or more was not; anything else, or an
// answer that does not agree with its exit status, is an error.
func (a *RootAccess) rootOSAccounts(ctx context.Context, pamUserIDs []string) (map[string]OSAccount, error) {
	var names []string
	for _, id := range pamUserIDs {
		if err := pve.CheckUserID(id); err != nil {
			return nil, err
		}
		name, _, _ := strings.Cut(id, "@")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = sshexec.ShellQuote(n)
	}
	s, err := a.root(ctx)
	if err != nil {
		return nil, err
	}
	cmd := "getent passwd -- " + strings.Join(quoted, " ")
	res, err := s.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("run getent passwd: %w", err)
	}
	if res.ExitCode != 0 && res.ExitCode != 2 {
		return nil, fmt.Errorf("getent passwd exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	out, err := parsePasswd(res.Stdout, names)
	if err != nil {
		return nil, err
	}
	if missing := len(names) - len(out); (res.ExitCode == 0) != (missing == 0) {
		return nil, fmt.Errorf("getent passwd exited %d but printed %d of the %d accounts asked for: %w", res.ExitCode, len(out), len(names), pve.ErrUnverifiableRead)
	}
	return out, nil
}

// parsePasswd parses getent's passwd(5) lines: name:passwd:uid:gid:gecos:
// home:shell. A line that is not seven fields, holds a bad uid or gid,
// names an account not asked for, or repeats one, is an unverifiable read.
func parsePasswd(stdout string, asked []string) (map[string]OSAccount, error) {
	out := map[string]OSAccount{}
	if stdout == "" {
		return out, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 {
			return nil, fmt.Errorf("getent passwd printed a line of %d fields, not 7: %w", len(f), pve.ErrUnverifiableRead)
		}
		if !slices.Contains(asked, f[0]) {
			return nil, fmt.Errorf("getent passwd printed account %q, which was not asked for: %w", f[0], pve.ErrUnverifiableRead)
		}
		if _, dup := out[f[0]]; dup {
			return nil, fmt.Errorf("getent passwd printed account %q twice: %w", f[0], pve.ErrUnverifiableRead)
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || uid < 0 || gid < 0 {
			return nil, fmt.Errorf("getent passwd: account %q has uid %q, gid %q: %w", f[0], f[2], f[3], pve.ErrUnverifiableRead)
		}
		out[f[0]] = OSAccount{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}
	}
	return out, nil
}
