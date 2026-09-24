package idempotent

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// UserEnsure and GroupEnsure are the Ops behind `pveforge user ensure` and
// `pveforge group ensure` (task pveforge-pveum-user-group-acl-ops, 6a).
//
// Transport, by the operator's ruling: every write runs as root over SSH
// with pveum, so the roster's token never needs User.Modify. Reads decide
// whether to write; a read over the token's REST view that PVE filters by
// privilege can miss an existing object, and the resulting create is then
// refused by PVE as a duplicate: loud, never a silent overwrite.
//
// There is no compare-and-swap: /access objects carry no digest, so the
// internal/lock lock idempotent.Run takes (Kind "user" or "group") is these
// Ops' only serialisation, and Apply never returns ErrConflict.

// UserSpec is one pveum user write. A nil field is not sent; Enable is
// always sent, because pveum's (and PVE's) update re-enables a user whose
// enable flag is omitted.
type UserSpec struct {
	UserID  string
	Enable  bool
	Comment *string
	Email   *string
	// Groups are added: on an existing user they are appended to its
	// memberships (pveum's --append 1), never replacing them.
	Groups []string
}

// UserEnsureClient is what UserEnsure needs: the user list, and root's
// pveum add and modify.
type UserEnsureClient interface {
	ListUsers(ctx context.Context) ([]pve.AccessUser, error)
	AddUser(ctx context.Context, spec UserSpec) error
	ModifyUser(ctx context.Context, spec UserSpec) error
}

// UserEnsure ensures UserID exists with Enable (when set), Comment and
// Email (when set), and membership of every group in Groups. Unset fields
// are left as they are; group membership is only ever added.
type UserEnsure struct {
	Client  UserEnsureClient
	UserID  string
	Enable  *bool // nil: a new user is enabled; an existing one keeps its state
	Comment *string
	Email   *string
	Groups  []string
	// BeforeJoin, when set, is asked before any write that adds the user
	// to groups, with exactly the groups that write adds. Joining a group
	// grants its ACLs, so an error here refuses the write: nothing is sent.
	BeforeJoin func(ctx context.Context, groups []string) error

	found *pve.AccessUser // set by Read
}

// Read scans the whole user list for UserID. A list that cannot be read is
// an error, never "absent".
func (op *UserEnsure) Read(ctx context.Context) (string, error) {
	users, err := op.Client.ListUsers(ctx)
	if err != nil {
		return "", err
	}
	op.found = nil
	for i := range users {
		if users[i].UserID == op.UserID {
			u := users[i]
			op.found = &u
			break
		}
	}
	return renderUser(op.found), nil
}

// renderUser is Read's comparable rendering: "absent", or every field
// UserEnsure decides on, quoted, groups sorted.
func renderUser(u *pve.AccessUser) string {
	if u == nil {
		return "absent"
	}
	groups := slices.Clone(u.Groups)
	slices.Sort(groups)
	return fmt.Sprintf("enable=%t comment=%q email=%q groups=%q", u.Enabled, u.Comment, u.Email, strings.Join(groups, ","))
}

// Satisfied reports whether the user exists with every requested value.
func (op *UserEnsure) Satisfied(string) bool {
	u := op.found
	if u == nil {
		return false
	}
	if op.Enable != nil && *op.Enable != u.Enabled {
		return false
	}
	if op.Comment != nil && *op.Comment != u.Comment {
		return false
	}
	if op.Email != nil && *op.Email != u.Email {
		return false
	}
	return len(op.missingGroups()) == 0
}

// missingGroups are the requested groups the user is not yet in, sorted.
func (op *UserEnsure) missingGroups() []string {
	var have []string
	if op.found != nil {
		have = op.found.Groups
	}
	var missing []string
	for _, g := range op.Groups {
		if !slices.Contains(have, g) && !slices.Contains(missing, g) {
			missing = append(missing, g)
		}
	}
	slices.Sort(missing)
	return missing
}

// Apply creates the user, or modifies it. A new user is enabled unless
// Enable says otherwise; an existing one is sent its own current state
// when Enable is unset, so the write never re-enables it by omission.
func (op *UserEnsure) Apply(ctx context.Context) error {
	if op.found == nil {
		enable := true
		if op.Enable != nil {
			enable = *op.Enable
		}
		groups := slices.Clone(op.Groups)
		slices.Sort(groups)
		groups = slices.Compact(groups)
		if err := op.beforeJoin(ctx, groups); err != nil {
			return err
		}
		return op.Client.AddUser(ctx, UserSpec{UserID: op.UserID, Enable: enable, Comment: op.Comment, Email: op.Email, Groups: groups})
	}
	enable := op.found.Enabled
	if op.Enable != nil {
		enable = *op.Enable
	}
	missing := op.missingGroups()
	if err := op.beforeJoin(ctx, missing); err != nil {
		return err
	}
	return op.Client.ModifyUser(ctx, UserSpec{UserID: op.UserID, Enable: enable, Comment: op.Comment, Email: op.Email, Groups: missing})
}

// beforeJoin asks BeforeJoin about groups, when there are any to join.
func (op *UserEnsure) beforeJoin(ctx context.Context, groups []string) error {
	if op.BeforeJoin == nil || len(groups) == 0 {
		return nil
	}
	return op.BeforeJoin(ctx, groups)
}

// GroupEnsureClient is what GroupEnsure needs: the group list, and root's
// pveum add and modify.
type GroupEnsureClient interface {
	ListGroups(ctx context.Context) ([]pve.AccessGroup, error)
	AddGroup(ctx context.Context, groupID string, comment *string) error
	ModifyGroup(ctx context.Context, groupID, comment string) error
}

// GroupEnsure ensures GroupID exists, with Comment when set. A group's
// members are set on its users (UserEnsure.Groups), never here.
type GroupEnsure struct {
	Client  GroupEnsureClient
	GroupID string
	Comment *string

	found *pve.AccessGroup // set by Read
}

// Read scans the whole group list for GroupID. A list that cannot be read
// is an error, never "absent".
func (op *GroupEnsure) Read(ctx context.Context) (string, error) {
	groups, err := op.Client.ListGroups(ctx)
	if err != nil {
		return "", err
	}
	op.found = nil
	for i := range groups {
		if groups[i].GroupID == op.GroupID {
			g := groups[i]
			op.found = &g
			break
		}
	}
	if op.found == nil {
		return "absent", nil
	}
	return fmt.Sprintf("comment=%q", op.found.Comment), nil
}

// Satisfied reports whether the group exists with the requested comment.
func (op *GroupEnsure) Satisfied(string) bool {
	return op.found != nil && (op.Comment == nil || *op.Comment == op.found.Comment)
}

// Apply creates the group, or sets its comment. An existing group with no
// comment requested has nothing to set (reachable only under force).
func (op *GroupEnsure) Apply(ctx context.Context) error {
	if op.found == nil {
		return op.Client.AddGroup(ctx, op.GroupID, op.Comment)
	}
	if op.Comment == nil {
		return nil
	}
	return op.Client.ModifyGroup(ctx, op.GroupID, *op.Comment)
}
