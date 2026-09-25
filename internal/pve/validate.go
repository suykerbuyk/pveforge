package pve

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	proxmox "github.com/suykerbuyk/go-proxmox"
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
// An empty tree is ErrNoGrants. A read failure during presence is returned
// first; then ErrScopeTooWide; then a bound that could not be settled
// (ErrUnverifiableRead, below); then ErrWrongScope.
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
// a /pool/ grant, or a propagating grant at exactly /pool, when P is a
// member of that pool (pool-derived privileges carry propagate 0).
//
// Pool membership (pveforge-validator-pool-membership) is resolved only
// when the bound needs it — some path holds a privilege only a pool grant
// confers — and only for a /pool/<id> grant without propagate whose
// privileges include Pool.Audit and whose ?path= answer shows the token
// holding Pool.Audit there. Then the members are read (PoolMembers) before
// and after a second tree read, and a path is a member if either read has
// it. A path conferred by nothing but such a pool, that is not a member,
// is ErrScopeTooWide only if its object exists (existence: /cluster/nextid
// for a VM, the storage list for a storage); an absent or invisible one —
// an orphaned pool entry, whose config is gone (hand-deleted, or a corrupted
// cluster filesystem) — is ErrUnverifiableRead naming it. Every failure
// of the membership and existence reads is flattened into
// ErrUnverifiableRead and never wraps its cause, so no 401/403 there can
// become a revoking ErrNotAuthorized.
//
// Known limits:
//
//  1. Pool membership is read only as above. For a propagating pool grant,
//     or one whose Pool.Audit the token does not hold, a propagate-0
//     privilege on any /vms/<n> or /storage/<s> is still accepted when the
//     pool grant confers it, whether or not <n> or <s> is a member. For
//     storage this is not harmless when the pool role carries Datastore.*
//     privileges.
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
//     refused a role read would read as ErrNotAuthorized, a verdict. So do
//     the membership reads: the GET /pools?poolid= answer (whose Pool.Audit
//     check PVE 9.2.11 does not enforce), the /cluster/nextid and GET
//     /storage existence reads, and that the members list can omit an
//     orphaned guest (its config gone) the permission tree still derives
//     from the pool.
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

	// Pool membership, resolved lazily: only when some path in the tree is
	// conferred by nothing but a pool grant that could be resolved. A tree
	// with no such path (D5's at mint: an empty pool) makes exactly the
	// requests it always made.
	members := make([]map[string]bool, len(want))
	held := map[string]map[string]bool{} // ?path= answers read early, reused by presence
	if cands := poolCandidates(want, privs, tree); len(cands) > 0 {
		var gated []int
		for _, i := range cands {
			h, err := c.PathPermissions(ctx, want[i].Path)
			if err != nil {
				return fmt.Errorf("validate token grants: %w", readFailure("read permissions at "+want[i].Path, err))
			}
			held[want[i].Path] = h
			if _, ok := h["Pool.Audit"]; ok {
				gated = append(gated, i)
			}
		}
		if len(gated) > 0 {
			// Members before and after a second tree read; a path counts as
			// a member if either read has it, so a pool change racing the
			// tree read never makes a member look like a non-member.
			before, err := readPoolMembers(ctx, c, want, gated)
			if err != nil {
				return err
			}
			// The second tree read. The first read already succeeded, so any
			// failure here — a 401/403, an empty tree, a payload that does
			// not decode — is transient or a change in flight, never a
			// verdict: flattened, like the membership reads.
			if tree, err = c.EffectivePermissions(ctx); err != nil {
				return unverifiable("re-read effective permissions", err)
			}
			if len(tree) == 0 {
				return fmt.Errorf("validate token grants: %w: the second read of the effective permissions was empty, though the first was not", ErrUnverifiableRead)
			}
			after, err := readPoolMembers(ctx, c, want, gated)
			if err != nil {
				return err
			}
			for _, i := range gated {
				for p := range after[i] {
					before[i][p] = true
				}
				members[i] = before[i]
			}
		}
	}

	// The bound. A path whose privileges only a pool grant would confer, and
	// that is not a member of the resolved pool, is too wide only if the
	// object exists: an absent one is an orphaned pool entry (a config gone
	// by hand or by a corrupted cluster filesystem) or an object the token
	// cannot see, and gets no verdict. A definite ErrScopeTooWide
	// on any path wins over such a non-verdict, so the scan goes on past it.
	var wide, unsure error
	ex := &existence{c: c}
	for _, path := range sortedKeys(tree) {
		var unsourced []string
		for _, priv := range sortedKeys(tree[path]) {
			if !conferred(want, privs, members, path, priv, tree[path][priv]) {
				unsourced = append(unsourced, priv)
			}
		}
		if len(unsourced) == 0 {
			continue
		}
		if onlyMembership(want, privs, path, unsourced, tree[path]) {
			exists, err := ex.check(ctx, path)
			if err != nil || !exists {
				if unsure == nil {
					if err == nil {
						err = fmt.Errorf("validate token grants: %w: at %s the token holds %s through pool membership, but %s is not a member of the pool and does not exist or is not visible to the token (an orphaned pool entry, whose config is gone?)", ErrUnverifiableRead, path, strings.Join(unsourced, ","), path)
					}
					unsure = err
				}
				continue
			}
		}
		wide = fmt.Errorf("validate token grants: %w: at %s the token holds %s, which no requested grant confers there", ErrScopeTooWide, path, strings.Join(unsourced, ","))
		break
	}

	// Presence runs for every grant, even once the bound has failed: a read
	// failure here still surfaces, and no grant is skipped.
	var missing error
	for i, g := range want {
		h, ok := held[g.Path]
		if !ok {
			var err error
			if h, err = c.PathPermissions(ctx, g.Path); err != nil {
				return fmt.Errorf("validate token grants: %w", readFailure("read permissions at "+g.Path, err))
			}
		}
		var absent, flat []string
		for _, p := range sortedKeys(privs[i]) {
			prop, ok := h[p]
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
	if unsure != nil {
		return unsure
	}
	return missing
}

// poolCandidates returns the indices of the pool grants whose membership
// the bound needs resolved, or none. A grant is resolvable when it is a
// /pool/<id> grant without propagate whose privileges include Pool.Audit
// (whether the token really holds it there is the caller's ?path= read).
// They are needed only if some path in tree holds, with propagate 0, a
// privilege that the pool clause alone confers — one that stops being
// conferred once every resolvable grant's membership is taken as empty.
func poolCandidates(want []Grant, privs []map[string]bool, tree map[string]map[string]bool) []int {
	var cands []int
	empty := make([]map[string]bool, len(want))
	for i, g := range want {
		if strings.HasPrefix(g.Path, "/pool/") && !g.Propagate && privs[i]["Pool.Audit"] {
			cands = append(cands, i)
			empty[i] = map[string]bool{}
		}
	}
	if len(cands) == 0 {
		return nil
	}
	for path, set := range tree {
		for priv, prop := range set {
			if !prop && conferred(want, privs, nil, path, priv, false) && !conferred(want, privs, empty, path, priv, false) {
				return cands
			}
		}
	}
	return nil
}

// readPoolMembers reads each gated grant's pool members. Any failure is
// flattened (unverifiable): the token was just seen to hold Pool.Audit on
// the pool, so a refused or malformed read is a non-answer, never a verdict.
func readPoolMembers(ctx context.Context, c *Client, want []Grant, gated []int) (map[int]map[string]bool, error) {
	out := make(map[int]map[string]bool, len(gated))
	for _, i := range gated {
		poolid := strings.TrimPrefix(want[i].Path, "/pool/")
		m, err := c.PoolMembers(ctx, poolid)
		if err != nil {
			return nil, unverifiable("read members of pool "+poolid, err)
		}
		out[i] = m
	}
	return out, nil
}

// onlyMembership reports whether every unsourced privilege at path would
// be conferred if membership were not resolved: the path fails the bound
// only because it is not a member of a resolved pool.
func onlyMembership(want []Grant, privs []map[string]bool, path string, unsourced []string, set map[string]bool) bool {
	for _, priv := range unsourced {
		if !conferred(want, privs, nil, path, priv, set[priv]) {
			return false
		}
	}
	return true
}

// vmsPathRE is a guest's ACL path, /vms/<vmid>.
var vmsPathRE = regexp.MustCompile(`^/vms/([1-9][0-9]*)$`)

// existence answers whether the object at a member-shaped ACL path exists.
//
//   - /vms/<n>: GET /cluster/nextid?vmid=<n> (vmidFree). It is user =>
//     'all' and consults the whole cluster VM list whatever the caller's
//     privileges, so a VM the token cannot audit still reads as existing;
//     "VM <n> already exists" is present, a free id is absent — an
//     orphaned pool entry: user.cfg still lists the VM in the pool, but its
//     config is gone. No normal PVE path produces one: a destroy that dies
//     between destroy_vm and remove_vm_access leaves the config in place (a
//     zombie that the vmlist, and so the members list, still carry). It
//     takes a hand-deleted config or a corrupted cluster filesystem.
//   - /storage/<id>: GET /storage (StorageIDs), read once. PVE lists only
//     storages the caller holds Datastore.Audit or Datastore.AllocateSpace
//     on (pve-storage Config.pm index, check_any), so one it cannot see
//     reads as absent: the non-verdict, the fail-safe direction.
//
// Every failure is flattened (unverifiable), never a verdict.
type existence struct {
	c        *Client
	storages map[string]bool
}

func (e *existence) check(ctx context.Context, path string) (bool, error) {
	if m := vmsPathRE.FindStringSubmatch(path); m != nil {
		vmid, err := strconv.Atoi(m[1])
		if err != nil {
			return false, unverifiable("check whether "+path+" exists", err)
		}
		free, err := e.c.vmidFree(ctx, vmid)
		if err != nil {
			return false, unverifiable("check whether "+path+" exists", err)
		}
		return !free, nil
	}
	if id, ok := strings.CutPrefix(path, "/storage/"); ok && storageIDRE.MatchString(id) {
		if e.storages == nil {
			s, err := e.c.StorageIDs(ctx)
			if err != nil {
				return false, unverifiable("check whether "+path+" exists", err)
			}
			e.storages = s
		}
		return e.storages[id], nil
	}
	return false, fmt.Errorf("validate token grants: %w: cannot check whether %s exists: not a guest or storage path", ErrUnverifiableRead, path)
}

// unverifiable flattens a read's failure into ErrUnverifiableRead for the
// membership and existence reads. It never wraps the cause (%w): bootstrap
// decides whether to revoke with errors.Is over the whole chain
// (isVerdict), so a wrapped 401/403 would still be ErrNotAuthorized, a
// revoking verdict, from a read that proves nothing about the grants. An
// HTTP answer is named by its status alone, never its body; any other
// cause is bounded and quoted onto one line.
func unverifiable(what string, err error) error {
	var se *StatusError
	var pse *proxmox.StatusError
	switch {
	case errors.As(err, &se):
		return fmt.Errorf("validate token grants: %w: %s: PVE answered HTTP %d", ErrUnverifiableRead, what, se.Code)
	case errors.As(err, &pse):
		return fmt.Errorf("validate token grants: %w: %s: PVE answered HTTP %d", ErrUnverifiableRead, what, pse.StatusCode)
	case errors.Is(err, ErrNotAuthorized):
		// go-proxmox's own 401/403, which carries no status.
		return fmt.Errorf("validate token grants: %w: %s: PVE answered HTTP 401/403 (not authorized)", ErrUnverifiableRead, what)
	}
	text := err.Error()
	if len(text) > 256 {
		cut := 256
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "…"
	}
	return fmt.Errorf("validate token grants: %w: %s: %s", ErrUnverifiableRead, what, strconv.Quote(text))
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
// the propagate flag prop (see ValidateTokenGrants). members holds each
// grant's resolved pool membership, nil (or a nil entry) for unresolved:
// a resolved pool grant confers on a member path only if it is a member.
func conferred(want []Grant, privs []map[string]bool, members []map[string]bool, path, priv string, prop bool) bool {
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
		// Pool-derived privileges carry propagate 0 on member paths. A pool
		// grant confers them on its own pool's members; a propagating grant
		// at exactly /pool reaches every pool's (roles("/pool/<x>")
		// inherits it), which HasPrefix("/pool", "/pool/") alone missed.
		if (strings.HasPrefix(g.Path, "/pool/") || (g.Path == "/pool" && g.Propagate)) &&
			(strings.HasPrefix(path, "/vms/") || strings.HasPrefix(path, "/storage/")) {
			if members == nil || members[i] == nil || members[i][path] {
				return true
			}
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
