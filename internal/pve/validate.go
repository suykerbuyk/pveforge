package pve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNoGrants: the token authenticates but its effective permission tree
// is empty — it holds no privilege anywhere. A fresh Proxmox token has zero
// permissions until an ACL grants it some, and nothing about its own
// authentication surfaces that.
var ErrNoGrants = errors.New("token authenticates but holds no privileges anywhere (the ACL grant is missing or did not take effect)")

// ErrWrongScope: the token holds privileges, but not everything requested —
// a requested privilege is missing at a requested path, or is held there
// without the requested propagation.
var ErrWrongScope = errors.New("token's grants do not cover what was requested")

// ErrScopeTooWide: the token holds a privilege, at some path, that no
// requested grant confers there — its effective scope exceeds the request.
var ErrScopeTooWide = errors.New("token's grants reach beyond what was requested")

// ValidateTokenGrants asks PVE what c's token can actually do and checks it
// against want, both ways:
//
//   - an upper bound over the token's whole effective tree
//     (EffectivePermissions): every (path, privilege, propagate) in it must
//     be conferred by one requested grant, else ErrScopeTooWide;
//   - presence at each requested path, from PVE's own ?path= answer
//     (PathPermissions): every privilege of the grant must be held there,
//     with propagate when the grant propagates, else ErrWrongScope.
//
// An empty tree is ErrNoGrants. ErrScopeTooWide wins when both checks fail.
// A grant's privileges are its pinned Privs, else its role's live
// definition (RolePrivileges, read once per distinct unpinned role); the
// choice is made per grant. A malformed want is ErrInvalidGrant before any
// request. A 401/403 is ErrNotAuthorized; any other failure, or a payload a
// healthy PVE does not produce (ErrUnverifiableRead), is none of these
// verdicts.
//
// A privilege held with propagate 1 at P is conferred by a propagating
// grant at P or at an ancestor of P. One held with propagate 0 is conferred
// by a grant at P; by a propagating grant at an ancestor (PVE's privsep
// intersection can lower the flag); or, for P under /vms/ or /storage/, by
// any /pool/ grant (pool-derived privileges carry propagate 0).
//
// Known limits:
//
//  1. Pool membership is not read. A propagate-0 privilege on any /vms/<n>
//     or /storage/<s> is accepted when some /pool/ grant confers it,
//     whether or not <n> or <s> is a member of that pool. For storage this
//     is not harmless when the pool role carries Datastore.* privileges.
//     Follow-up: pveforge-validator-pool-membership.
//  2. Delegation on pool members. A token holding VM.Allocate on a pool
//     member can add propagate-0 ACL rows there, for any principal, with
//     privileges it already holds there. For itself such a row is a subset
//     of the pool role on a member path, which limit 1 already accepts; for
//     anyone else it is invisible here, since only the token's OWN
//     effective permissions are read. A nil result makes no claim about
//     delegations.
//  3. Role definitions are read live unless pinned: a role widened on PVE
//     widens the bound with it. Grant.Privs pins it.
//  4. For a non-root token owner, PVE intersects the token's privileges
//     with the owner's, so an owner lacking a privilege (or holding it
//     without propagate) makes a correct grant read as ErrWrongScope. A
//     caller that may revoke on ErrWrongScope must first check the owner
//     (bootstrap does, before any remove).
//  5. A 403 from an intermediary (a proxy) reads as ErrNotAuthorized.
//  6. The bound is only as wide as the tree PVE returns: its default top
//     paths, every ACL path and every pool member. On PVE 9.2.11 every
//     grantable path is one of those.
//  7. The reads AS the token are source-derived, not yet live-captured:
//     that a token may GET /access/permissions and GET /access/roles/{id}
//     (both user => 'all') and sees its own tree, and the propagate-0 flag
//     on pool-derived privileges, come from PVE 9.2.11's source; every live
//     capture so far was made as root (pvesh --userid <token>). A token
//     refused a role read would read as ErrNotAuthorized, a verdict.
func ValidateTokenGrants(ctx context.Context, c *Client, want []Grant) error {
	if err := CheckGrants(want); err != nil {
		return fmt.Errorf("validate token grants: %w", err)
	}
	tree, err := c.EffectivePermissions(ctx)
	if err != nil {
		return fmt.Errorf("validate token grants: %w", readFailure("read effective permissions", err))
	}
	if len(tree) == 0 {
		return fmt.Errorf("validate token grants: %w", ErrNoGrants)
	}

	privs := make([]map[string]bool, len(want))
	roleCache := map[string][]string{}
	for i, g := range want {
		list := g.Privs
		if list == nil {
			cached, ok := roleCache[g.Role]
			if !ok {
				if cached, err = c.RolePrivileges(ctx, g.Role); err != nil {
					return fmt.Errorf("validate token grants: %w", readFailure("read role "+g.Role, err))
				}
				roleCache[g.Role] = cached
			}
			list = cached
		}
		privs[i] = make(map[string]bool, len(list))
		for _, p := range list {
			privs[i][p] = true
		}
	}

	var wide error
	for _, path := range sortedKeys(tree) {
		var unsourced []string
		for _, priv := range sortedKeys(tree[path]) {
			if !conferred(want, privs, path, priv, tree[path][priv]) {
				unsourced = append(unsourced, priv)
			}
		}
		if len(unsourced) > 0 {
			wide = fmt.Errorf("validate token grants: %w: at %s the token holds %s, which no requested grant confers there", ErrScopeTooWide, path, strings.Join(unsourced, ","))
			break
		}
	}

	// Presence runs for every grant, even once the bound has failed: a read
	// failure here still surfaces, and no grant is skipped.
	var missing error
	for i, g := range want {
		held, err := c.PathPermissions(ctx, g.Path)
		if err != nil {
			return fmt.Errorf("validate token grants: %w", readFailure("read permissions at "+g.Path, err))
		}
		var absent, flat []string
		for _, p := range sortedKeys(privs[i]) {
			prop, ok := held[p]
			switch {
			case !ok:
				absent = append(absent, p)
			case g.Propagate && !prop:
				flat = append(flat, p)
			}
		}
		if missing == nil && (len(absent) > 0 || len(flat) > 0) {
			missing = fmt.Errorf("validate token grants: %w: at %s the token lacks [%s] and holds without propagate [%s]", ErrWrongScope, g.Path, strings.Join(absent, ","), strings.Join(flat, ","))
		}
	}

	if wide != nil {
		return wide
	}
	return missing
}

// readFailure returns a read's error for a verdict-bearing caller. A
// rejected credential (ErrNotAuthorized) becomes fixed text plus the HTTP
// status: it is a verdict, and bootstrap puts a verdict's text in its
// report, so PVE's response body (unbounded, and possibly multi-line) must
// not ride along. Any other error is returned as it is. RawRequest's own
// text is unchanged.
func readFailure(what string, err error) error {
	if !errors.Is(err, ErrNotAuthorized) {
		return err
	}
	code := 0
	if c, ok := HTTPStatus(err); ok {
		code = c
	}
	return fmt.Errorf("%s: %w (PVE answered HTTP %d)", what, ErrNotAuthorized, code)
}

// conferred reports whether one requested grant confers priv at path with
// the propagate flag prop (see ValidateTokenGrants).
func conferred(want []Grant, privs []map[string]bool, path, priv string, prop bool) bool {
	for i, g := range want {
		if !privs[i][priv] {
			continue
		}
		if prop {
			if g.Propagate && (path == g.Path || under(path, g.Path)) {
				return true
			}
			continue
		}
		if path == g.Path || (g.Propagate && under(path, g.Path)) {
			return true
		}
		if strings.HasPrefix(g.Path, "/pool/") && (strings.HasPrefix(path, "/vms/") || strings.HasPrefix(path, "/storage/")) {
			return true
		}
	}
	return false
}

// under reports whether path is strictly below ancestor.
func under(path, ancestor string) bool {
	if ancestor == "/" {
		return path != "/"
	}
	return strings.HasPrefix(path, ancestor+"/")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
