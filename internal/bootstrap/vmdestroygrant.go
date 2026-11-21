package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// `pveforge acl enable-vm-destroy` (task pveforge-bootstrap-ensure-roles-
// and-grants): make the roster's own token able to run `vm destroy` without
// rotating it.
//
// `vm destroy` needs Sys.Audit, which PVEVMAdmin lacks. The verb ensures a
// custom role R = privileges(PVEVMAdmin) ∪ {Sys.Audit}, read LIVE in the same
// run, and adds R to the token additively. It is a separate operation from
// bootstrap on purpose: bootstrap's token phase owns the one code path that
// removes a token (removeHeld), and a verdict class exists only to authorise a
// remove. This file has no remove arm, and a guard
// (internal/sourceguard/enablegrant_guard_test.go) pins that none of
// removeHeld, mintAndPersist, tokenPhase, grantAll, removeCmd,
// roster.ClearTokenAuth or roster.WriteTokenAuth is reachable from it (INV-1).
//
// The two invariants, both pinned by tests that call the guards directly:
//
//	INV-1  the verb can never revoke or re-mint a token, on any outcome. The
//	       only mutating commands it can send are the two argv shapes
//	       screenEnableArgv accepts; it never writes the roster; none of its
//	       errors wraps a verdict sentinel.
//	INV-2  when it writes, the token's net effective widening is exactly
//	       {Sys.Audit}; when it does not write (already_enabled), none.
//
// Everything below runs as root over SSH through RootAccess, the channel
// `acl grant` uses. The roster's token never holds Permissions.Modify.

// DefaultVMDestroyRole is the role the verb ensures unless --role names
// another. PVE refuses a new role whose id starts with PVE in any case
// (API2/Role.pm create_role, since libpve-access-control 8.0.0), so the
// natural "PVEForge…" cannot exist.
const DefaultVMDestroyRole = "ForgeVMAdminAudit"

const (
	vmAdminRoleName       = "PVEVMAdmin"
	administratorRoleName = "Administrator"
	// auditPrivilege is the one privilege R adds to PVEVMAdmin.
	auditPrivilege = "Sys.Audit"

	// The two mutating commands the verb can send, as the words pveum is
	// given. Nothing else is ever written.
	cmdRoleAdd   = "pveum role add"
	cmdACLModify = "pveum acl modify"
)

// Outcomes of EnableVMDestroy.
const (
	// EnableRoleOnly: the roster holds no token, so the role was ensured and
	// no ACL was written.
	EnableRoleOnly = "role_only"
	// EnableUpgraded: R was added to the token, which now holds
	// PVEVMAdmin's privileges plus Sys.Audit.
	EnableUpgraded = "upgraded"
	// EnableAlreadyEnabled: the token already holds R through its own ACL row
	// and nothing was written.
	EnableAlreadyEnabled = "already_enabled"
)

var (
	// ErrRoleName: the role id is not one PVE would create (its charset, or
	// the case-insensitive PVE prefix). Refused before anything is dialed.
	ErrRoleName = errors.New("refusing this role name")
	// ErrUnknownPrivilege: a privilege of the derived set is not in
	// Administrator's, which is PVE's own list of every valid privilege.
	ErrUnknownPrivilege = errors.New("a privilege is not one PVE knows")
	// ErrRoleConflict: a role of this name exists with a different privilege
	// set (or changed while the verb ran). PVE's role update REPLACES, so the
	// verb never updates a role other principals may hold.
	ErrRoleConflict = errors.New("a role of this name exists with a different privilege set")
	// ErrNotVMAdminToken: the grant would widen the token by more than
	// Sys.Audit, so it does not already hold what PVEVMAdmin gives. This
	// verb upgrades an existing VM-admin token; it never widens a limited one.
	ErrNotVMAdminToken = errors.New("the token does not already hold PVEVMAdmin's privileges")
	// ErrUpgradeWouldNotConverge: the token's predicted effective tree, once R
	// is added, is not exactly what `bootstrap --grant /:R::1` would accept
	// (a privilege beyond R's somewhere, e.g. a descendant grant or an
	// inherited Administrator). A later bootstrap would revoke it, so the verb
	// refuses and writes nothing.
	ErrUpgradeWouldNotConverge = errors.New("adding the role would not leave a token that bootstrap accepts for this role")
	// ErrRoleChangedDuringGrant: the role no longer holds exactly the
	// derived set after the grant.
	ErrRoleChangedDuringGrant = errors.New("the role changed while it was being granted")
	// ErrGrantNotEffective: after the write the token's effective
	// permissions at / do not hold the whole role (a non-root owner lacking
	// them: PVE intersects a privilege-separated token with its owner).
	ErrGrantNotEffective = errors.New("the grant is in the ACL but is not effective")
	// ErrPostWriteInvariant: the token's ACTUAL effective tree after the write
	// fails the invariant the grant was judged by before it: it is not what
	// `bootstrap --grant /:R::1` accepts, or it widened the token by more than
	// Sys.Audit. (A tree that merely differs from the prediction, and holds the
	// invariant, is a success with a note, not this error.)
	ErrPostWriteInvariant = errors.New("the token's effective permissions after the grant break the invariant")
	// ErrTokenChangedUnderLock: the roster's token for the target is not the
	// one the run was set up with: a bootstrap that held the lock rotated or
	// replaced it while this run waited.
	ErrTokenChangedUnderLock = errors.New("the roster's token changed while waiting for the lock")
	// ErrEnableScreen: a command the verb was about to send is not one of the
	// two shapes it may send. A programming error; nothing was sent.
	ErrEnableScreen = errors.New("enable-vm-destroy refused to send a command that is not one of its two shapes")
)

// vmRoleIDRE is PVE's verify_rolename (AccessControl.pm); pvePrefixRE the
// namespace create_role refuses, case-insensitively (Role.pm).
var (
	vmRoleIDRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	pvePrefixRE = regexp.MustCompile(`(?i)^pve`)
	// splitListRE is PVE's split_list: comma, semicolon or whitespace.
	splitListRE = regexp.MustCompile(`[,;\s]+`)
)

// checkVMDestroyRole reports whether id is a role id the verb may create.
func checkVMDestroyRole(id string) error {
	switch {
	case id == "" || !vmRoleIDRE.MatchString(id):
		return fmt.Errorf("%w: %q is not a role id (letters, digits, '.', '-', '_')", ErrRoleName, id)
	case strings.HasPrefix(id, "-"):
		// PVE's role-id charset allows a leading '-', and pveum's own option
		// parser would read "--delete" or "-x" as a flag: the screen's "no
		// --delete in any spelling" must hold for the role id too.
		return fmt.Errorf("%w: %q starts with '-', which pveum would read as an option", ErrRoleName, id)
	case pvePrefixRE.MatchString(id):
		return fmt.Errorf("%w: PVE refuses a new role whose id starts with \"PVE\" in any case; %q cannot be created", ErrRoleName, id)
	}
	return nil
}

// splitPrivList splits a role list "privs" string the way PVE's split_list
// does, dropping empties, so a successful create is never read as a failure
// over a separator.
func splitPrivList(s string) []string {
	var out []string
	for _, p := range splitListRE.Split(s, -1) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EnableVMDestroyRequest is one `pveforge acl enable-vm-destroy`.
type EnableVMDestroyRequest struct {
	// Role is the role to ensure; "" means DefaultVMDestroyRole.
	Role string
	// DryRun reads and judges everything and writes nothing.
	DryRun bool
	// RoleOnly ensures and validates the role and nothing else: the token's
	// tree is never read and no ACL is written, whatever the roster holds. It
	// is the order for a fresh or rebuilt target, whose roster may still hold
	// a token PVE no longer knows (`--role-only`, then bootstrap --grant
	// /:R::1). There is no heuristic "token absent" detection.
	RoleOnly bool
	// RosterPath and TargetID name bootstrap's per-target lock, which the verb
	// takes for the whole write (a bootstrap of the same target can remove the
	// token the verb is granting to). Both are required unless DryRun.
	RosterPath string
	TargetID   string
}

// EnableVMDestroyResult is what the verb did, or with DryRun would do.
type EnableVMDestroyResult struct {
	Role string
	// Privileges is D, the role's privilege set: PVEVMAdmin's, live, plus
	// Sys.Audit. Always printed, so the operator sees what the role holds.
	Privileges  []string
	Outcome     string
	RoleCreated bool
	// TokenID is the roster's own token, "" when it holds none.
	TokenID string
	// Widened is the privileges the token gained: the actual difference after
	// a write (INV-2: exactly [Sys.Audit]), the predicted one on a dry run.
	Widened []string
	DryRun  bool
	// Planned is the commands a dry run would send, as they would be sent.
	Planned []string
	// Notes are informational: the written grant held the invariant but the
	// token's actual tree differs from the prediction (the paths are named).
	Notes []string
}

// enableParams is what a write is screened against: everything the two
// accepted shapes are made of.
type enableParams struct {
	role    string
	privs   []string // D, sorted
	tokenID string
}

// EnableVMDestroy ensures the role and, when the roster holds a token, adds
// the role to it. See the file comment for the invariants. The order is: read
// everything, judge, write the role if absent, write the ACL, verify.
//
// It is a top-level function, not a method, because it is the verb's lock
// sink: internal/lock/lockguard lists this file in TakerFiles and requires
// every command that reaches a sink to carry --lock-wait and pass its own
// context. The checks that need no host run first, so a refused name never
// dials; credentials are resolved before the lock, so a prompt never happens
// holding it.
func EnableVMDestroy(ctx context.Context, a *RootAccess, req EnableVMDestroyRequest) (*EnableVMDestroyResult, error) {
	role := req.Role
	if role == "" {
		role = DefaultVMDestroyRole
	}
	if err := checkVMDestroyRole(role); err != nil {
		return nil, err
	}
	tokenID := a.opts.OwnToken
	if req.RoleOnly {
		tokenID = ""
	}
	if tokenID != "" {
		if err := pve.CheckTokenID(tokenID); err != nil {
			return nil, err
		}
	}
	if !req.DryRun && (req.RosterPath == "" || req.TargetID == "") {
		return nil, errors.New("enable-vm-destroy needs the roster path and target id for the per-target lock")
	}
	if err := a.ResolveCredentials(ctx); err != nil {
		return nil, err
	}
	if !req.DryRun {
		// bootstrap's own key: an upgrade and a bootstrap of one target on one
		// roster serialise. Held to the end, across the write AND the
		// effective read-back.
		unlock, err := lock.Mutation(ctx, req.RosterPath, lock.ObjectKey{TargetID: req.TargetID, Kind: "bootstrap", ID: "token"})
		if err != nil {
			return nil, fmt.Errorf("enable-vm-destroy %s: acquire the per-target bootstrap lock: %w", req.TargetID, err)
		}
		defer func() { _ = unlock() }()
		// The token id the command was set up with was read from the roster
		// BEFORE the lock. A bootstrap that held the lock may have rotated it
		// since: re-read it here and refuse if it changed, rather than grant
		// to an id this run never saw. (--role-only never uses the token.)
		if !req.RoleOnly {
			cur, err := heldTokenID(Options{TargetID: req.TargetID, RosterPath: req.RosterPath})
			if err != nil {
				return nil, fmt.Errorf("enable-vm-destroy %s: re-read the roster's token under the lock: %w", req.TargetID, err)
			}
			if cur != a.opts.OwnToken {
				return nil, fmt.Errorf("%w: %s held %q when this run started and holds %q now; nothing was changed, run it again",
					ErrTokenChangedUnderLock, req.TargetID, a.opts.OwnToken, cur)
			}
		}
	}
	return a.enableVMDestroy(ctx, req, role, tokenID)
}

// enableVMDestroy is EnableVMDestroy's body, run under its lock.
func (a *RootAccess) enableVMDestroy(ctx context.Context, req EnableVMDestroyRequest, role, tokenID string) (*EnableVMDestroyResult, error) {
	roles, err := a.roleSets(ctx)
	if err != nil {
		return nil, err
	}
	d, err := deriveRoleSet(roles)
	if err != nil {
		return nil, err
	}
	live, haveRole := roles[role]
	if haveRole {
		if missing, extra := setDiff(d, live); len(missing) > 0 || len(extra) > 0 {
			return nil, roleConflict(role, missing, extra)
		}
	}
	p := enableParams{role: role, privs: d, tokenID: tokenID}
	res := &EnableVMDestroyResult{Role: role, Privileges: slices.Clone(d), TokenID: tokenID, DryRun: req.DryRun}

	if tokenID == "" {
		res.Outcome = EnableRoleOnly
		if !haveRole {
			res.RoleCreated = true
			if err := a.ensureRole(ctx, p, req.DryRun, res); err != nil {
				return nil, err
			}
		}
		return res, nil
	}

	// Reads that decide whether and how to write, all before any write.
	acls, err := a.rootACLs(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the ACL list: %w", err)
	}
	tree, err := a.userTree(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	owner, _, _ := strings.Cut(tokenID, "!")
	var ownerTree map[string]map[string]bool
	if owner != "root@pam" {
		if ownerTree, err = a.userTree(ctx, owner); err != nil {
			return nil, err
		}
	}

	if haveRole && alreadyEnabled(acls, tokenID, role, tree, d) {
		res.Outcome = EnableAlreadyEnabled
		return res, nil
	}

	predicted, err := predictTree(tree, ownerTree, acls, tokenID, d)
	if err != nil {
		return nil, err
	}
	if err := judgePredicted(predicted, tree, role, d); err != nil {
		if ownerTree != nil && errors.Is(err, ErrUpgradeWouldNotConverge) {
			err = fmt.Errorf("%w; the token's owner %s is not root@pam, and PVE intersects a privilege-separated token with its owner, so the owner itself must hold the role's privileges on / with propagate 1 (this verb never grants the owner)", err, owner)
		}
		return nil, err
	}
	res.Outcome = EnableUpgraded
	res.Widened = widenedBy(tree, predicted)

	if !haveRole {
		res.RoleCreated = true
	}
	if req.DryRun {
		if !haveRole {
			res.Planned = append(res.Planned, renderEnable(1, p))
		}
		res.Planned = append(res.Planned, renderEnable(2, p))
		return res, nil
	}

	if !haveRole {
		if err := a.ensureRole(ctx, p, false, res); err != nil {
			return nil, err
		}
	}
	if err := a.enableWrite(ctx, p, enableACLArgv(p)); err != nil {
		return nil, err
	}

	// Verification. The role is re-read and must be set-equal to D (never
	// merely a superset): PVE has no compare-and-set, so a concurrent root
	// role editor can widen R between the read above and this write. That
	// window is a documented limit; this detects it and names the repair.
	repair := fmt.Sprintf("pveum acl delete / --tokens %s --roles %s", sshexec.ShellQuote(tokenID), sshexec.ShellQuote(role))
	after, err := a.roleSets(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the role back after the grant: %w", err)
	}
	if missing, extra := setDiff(d, after[role]); len(missing) > 0 || len(extra) > 0 {
		return nil, fmt.Errorf("%w: %s now differs from the set granted (missing [%s], extra [%s]); the ACL row stays and the verb deletes nothing: to take it back, run: %s",
			ErrRoleChangedDuringGrant, role, strings.Join(missing, ","), strings.Join(extra, ","), repair)
	}
	actual, err := a.userTree(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("read the token's permissions back after the grant: %w", err)
	}
	if missing := missingAt(actual, "/", d); len(missing) > 0 {
		return nil, fmt.Errorf("%w: at / the token still lacks [%s] after %s was added (PVE intersects a privilege-separated token with its owner %s, which needs Sys.Audit on / with propagate 1; this verb never grants the owner); the ACL row stays",
			ErrGrantNotEffective, strings.Join(missing, ","), role, owner)
	}
	// The success condition is the INVARIANT, not prediction exactness: the
	// actual tree is judged by the same two halves as the predicted one was
	// before the write, with R's privileges taken as D (the set just verified
	// equal above, never a fresh read of R). A pool member path the predictor
	// does not model, for instance, can hold a flag-0 Sys.Audit after a correct
	// grant; that is a difference worth a note, not a reason to tell the
	// operator to delete a good grant.
	if converge, beyond := checkTree(actual, tree, role, d); converge != nil || len(beyond) > 0 {
		why := "the tree is not what bootstrap --grant /:" + role + "::1 accepts"
		if converge != nil {
			why += ": " + oneLine(converge.Error())
		} else {
			why = "it widened the token by [" + strings.Join(beyond, ",") + "] beyond Sys.Audit"
		}
		return nil, fmt.Errorf("%w: %s; the ACL row stays and the verb deletes nothing: to take it back, run: %s", ErrPostWriteInvariant, why, repair)
	}
	if diff := treeDiff(actual, predicted); diff != "" {
		res.Notes = append(res.Notes, "the token's effective permissions differ from the prediction, but hold the invariant (accepted): "+diff)
	}
	// vm destroy's first read is GET /nodes/<node>/status, which needs Sys.Audit
	// on that node's path. A token with its own override row on /nodes or a
	// /nodes/<n> path is not reached by the new role there, so the upgrade can
	// succeed while destroy would still refuse on that node. Say so; the grant
	// is correct and nothing more is written.
	if missing := nodePathsLackingAudit(actual); len(missing) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("Sys.Audit is not effective at [%s], where vm destroy's status read needs it: vm destroy will refuse on those nodes; run: pveforge doctor %s",
			strings.Join(missing, ","), req.TargetID))
	}
	res.Widened = widenedBy(tree, actual)
	return res, nil
}

// nodePathsLackingAudit returns /nodes and every /nodes/<n> path in the tree
// that does not hold Sys.Audit (at any propagate flag), sorted.
func nodePathsLackingAudit(tree map[string]map[string]bool) []string {
	var out []string
	for path, set := range tree {
		if path == "/nodes" || strings.HasPrefix(path, "/nodes/") {
			if _, held := set[auditPrivilege]; !held {
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// roleConflict names both diffs of a role that exists with another set.
func roleConflict(role string, missing, extra []string) error {
	return fmt.Errorf("%w: %s lacks [%s] and holds [%s] beyond the derived set; nothing was changed. PVE's role update replaces the set, so the verb does not touch a role other principals may hold: pick another --role, or fix this one by hand with pveum role modify",
		ErrRoleConflict, role, strings.Join(missing, ","), strings.Join(extra, ","))
}

// deriveRoleSet is D: PVEVMAdmin's privileges, as read from PVE now, plus
// Sys.Audit, sorted. It must be a subset of Administrator's, which is PVE's
// own list of every valid privilege, and must confer no escalating privilege:
// the role is granted to pveforge's own token, and a future PVEVMAdmin that
// gained one must make the verb refuse, never self-grant it.
func deriveRoleSet(roles map[string][]string) ([]string, error) {
	vm, ok := roles[vmAdminRoleName]
	if !ok || len(vm) == 0 {
		return nil, fmt.Errorf("the role list has no %s (or it holds no privileges): cannot derive the role", vmAdminRoleName)
	}
	admin, ok := roles[administratorRoleName]
	if !ok || len(admin) == 0 {
		return nil, fmt.Errorf("the role list has no %s: cannot validate the role's privileges against PVE's own list", administratorRoleName)
	}
	set := map[string]bool{auditPrivilege: true}
	for _, p := range vm {
		set[p] = true
	}
	d := make([]string, 0, len(set))
	for p := range set {
		d = append(d, p)
	}
	sort.Strings(d)
	if missing, _ := setDiff(d, admin); len(missing) > 0 {
		return nil, fmt.Errorf("%w: [%s] is not in %s's privileges, PVE's list of every valid privilege", ErrUnknownPrivilege, strings.Join(missing, ","), administratorRoleName)
	}
	if esc := escalating(d); len(esc) > 0 {
		return nil, fmt.Errorf("%w: %s plus %s would confer %s; refusing to grant an escalating privilege to pveforge's own token",
			ErrEscalatingRole, vmAdminRoleName, auditPrivilege, strings.Join(esc, ","))
	}
	return d, nil
}

// roleSets reads the role list as root and returns every role's privilege
// set, split on PVE's split_list separators, trimmed, sorted and deduplicated.
// A missing "privs" field, a duplicate role or a malformed name is an error.
func (a *RootAccess) roleSets(ctx context.Context) (map[string][]string, error) {
	const cmd = "pveum role list --output-format json"
	stdout, err := a.pveum(ctx, cmd)
	if err != nil {
		return nil, err
	}
	var list []struct {
		RoleID string  `json:"roleid"`
		Privs  *string `json:"privs"`
	}
	if err := decodeJSONArray(cmd, stdout, &list); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(list))
	for _, r := range list {
		if _, dup := out[r.RoleID]; dup {
			return nil, fmt.Errorf("role list: role %s is listed twice: %w", r.RoleID, pve.ErrUnverifiableRead)
		}
		if r.Privs == nil {
			return nil, fmt.Errorf("role list: role %s has no \"privs\" field: %w", r.RoleID, pve.ErrUnverifiableRead)
		}
		seen := map[string]bool{}
		privs := []string{}
		for _, p := range splitPrivList(*r.Privs) {
			if !privNameRE.MatchString(p) {
				return nil, fmt.Errorf("role list: role %s holds a name that is not a privilege name: %w", r.RoleID, pve.ErrUnverifiableRead)
			}
			if !seen[p] {
				seen[p] = true
				privs = append(privs, p)
			}
		}
		sort.Strings(privs)
		out[r.RoleID] = privs
	}
	return out, nil
}

// userTree reads a user's or token's whole effective permission tree as root:
// `pveum user permissions <id>` with no --path prints the same object GET
// /access/permissions answers, decoded by the same strict decoder.
func (a *RootAccess) userTree(ctx context.Context, id string) (map[string]map[string]bool, error) {
	out, err := a.pveum(ctx, fmt.Sprintf("pveum user permissions %s --output-format json", sshexec.ShellQuote(id)))
	if err != nil {
		return nil, err
	}
	tree, err := pve.DecodePermissionTree([]byte(strings.TrimSpace(out)))
	if err != nil {
		return nil, fmt.Errorf("read the effective permissions of %s: %w", id, err)
	}
	return tree, nil
}

// ensureRole creates the role (shape 1) unless dry-run, and verifies by a
// re-read that it holds exactly D. A create that fails is re-read once: a
// racing writer that created the same set is success, any other set a
// conflict.
func (a *RootAccess) ensureRole(ctx context.Context, p enableParams, dry bool, res *EnableVMDestroyResult) error {
	if dry {
		res.Planned = append(res.Planned, renderEnable(1, p))
		return nil
	}
	werr := a.enableWrite(ctx, p, enableRoleArgv(p))
	if werr != nil && errors.Is(werr, ErrRootWriteOutcomeUnknown) {
		return werr
	}
	roles, err := a.roleSets(ctx)
	if err != nil {
		if werr != nil {
			return werr
		}
		return fmt.Errorf("read the role back after creating it: %w", err)
	}
	live, ok := roles[p.role]
	if !ok {
		if werr != nil {
			return werr
		}
		return fmt.Errorf("%w: %s is not in the role list after it was created", ErrRoleConflict, p.role)
	}
	if missing, extra := setDiff(p.privs, live); len(missing) > 0 || len(extra) > 0 {
		return roleConflict(p.role, missing, extra)
	}
	if werr != nil {
		res.RoleCreated = false // a racing writer made it; same set
	}
	return nil
}

// ---- the argv screen ----

// enableRoleArgv and enableACLArgv are the only two argv tuples the verb
// builds. enableWrite screens them again before sending.
func enableRoleArgv(p enableParams) []string {
	return append(strings.Fields(cmdRoleAdd), p.role, "--privs", strings.Join(p.privs, ","))
}

func enableACLArgv(p enableParams) []string {
	return append(strings.Fields(cmdACLModify), "/", "--tokens", p.tokenID, "--roles", p.role, "--propagate", "1")
}

// screenEnableArgv accepts exactly two argv tuples and nothing else, compared
// element by element, never by prefix:
//
//	pveum role add <R> --privs <D sorted, comma-joined, no spaces>
//	pveum acl modify / --tokens <the token id> --roles <R> --propagate 1
//
// No other flag, no --delete in any spelling, no second role or token. It
// returns which shape matched. R, D's joined string and the token id are
// checked too: valid, and needing no shell escaping, so the string the
// renderer builds round-trips through the shell as that argv.
func screenEnableArgv(argv []string, p enableParams) (shape int, err error) {
	if err := checkVMDestroyRole(p.role); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEnableScreen, err)
	}
	if len(p.privs) == 0 || !sort.StringsAreSorted(p.privs) {
		return 0, fmt.Errorf("%w: the privilege list is empty or not sorted", ErrEnableScreen)
	}
	for _, priv := range p.privs {
		if !privNameRE.MatchString(priv) {
			return 0, fmt.Errorf("%w: %q is not a privilege name", ErrEnableScreen, priv)
		}
	}
	joined := strings.Join(p.privs, ",")
	values := []string{p.role, joined}
	if p.tokenID != "" {
		if err := pve.CheckTokenID(p.tokenID); err != nil {
			return 0, fmt.Errorf("%w: %w", ErrEnableScreen, err)
		}
		values = append(values, p.tokenID)
	}
	for _, v := range values {
		if sshexec.ShellQuote(v) != "'"+v+"'" {
			return 0, fmt.Errorf("%w: a value needs shell escaping", ErrEnableScreen)
		}
	}
	switch {
	case slices.Equal(argv, enableRoleArgv(p)):
		return 1, nil
	case p.tokenID != "" && slices.Equal(argv, enableACLArgv(p)):
		return 2, nil
	}
	return 0, fmt.Errorf("%w", ErrEnableScreen)
}

// renderEnable is the command line for a shape, every value single-quoted as
// aclModify does. The path is quoted too, as aclModify quotes it.
func renderEnable(shape int, p enableParams) string {
	if shape == 1 {
		return cmdRoleAdd + " " + sshexec.ShellQuote(p.role) + " --privs " + sshexec.ShellQuote(strings.Join(p.privs, ","))
	}
	return cmdACLModify + " " + sshexec.ShellQuote("/") + " --tokens " + sshexec.ShellQuote(p.tokenID) +
		" --roles " + sshexec.ShellQuote(p.role) + " --propagate 1"
}

// enableWrite is the verb's only write: screen the argv, render it, send it
// through pveumWrite (the bounded, outcome-unknown-aware root write). It is
// the one place the file reaches pveumWrite.
func (a *RootAccess) enableWrite(ctx context.Context, p enableParams, argv []string) error {
	shape, err := screenEnableArgv(argv, p)
	if err != nil {
		return err
	}
	return a.pveumWrite(ctx, renderEnable(shape, p))
}

// ---- already_enabled, prediction, judgement ----

// alreadyEnabled is true only if ALL of: a TOKEN ACL row for exactly this
// token, path /, role R, propagate 1; and the token's effective permissions at
// / hold every privilege of D with propagate 1. (R == D is checked by the
// caller: the role exists with exactly D.) Any other source of the
// privileges — a user row, a different role, no row, root@pam's inherited
// Administrator — is not success: a later `bootstrap --grant /:R::1` would not
// be `reused` for it.
func alreadyEnabled(acls []pve.ACLEntry, tokenID, role string, tree map[string]map[string]bool, d []string) bool {
	row := pve.ACLEntry{Path: "/", Role: role, Type: "token", UGID: tokenID, Propagate: true}
	return slices.Contains(acls, row) && len(missingAt(tree, "/", d)) == 0
}

// missingAt returns the privileges of want the tree does not hold at path
// with propagate 1.
func missingAt(tree map[string]map[string]bool, path string, want []string) []string {
	var out []string
	for _, p := range want {
		if !tree[path][p] {
			out = append(out, p)
		}
	}
	return out
}

// defaultTopPaths are the paths PVE always lists in a permission tree
// (RPCEnvironment.pm get_effective_permissions), whether or not the caller
// holds anything there.
var defaultTopPaths = []string{"/", "/access", "/access/groups", "/nodes", "/pool", "/sdn", "/storage", "/vms"}

// predictTree is the token's effective tree after R (the privileges d) is
// added to it at / with propagate 1, as a DELTA over the tree as read: it never
// rebuilds the tree from rows, so it cannot disagree with the read about
// anything it does not touch.
//
// The composition rule is PVE's, from AccessControl.pm roles() and
// RPCEnvironment.pm compile_acl_path. For a privilege-separated token the walk
// from / down to a path consults only the TOKEN's own rows (a token id is in
// no group and holds no user rows); a token row at a node applies at the path
// if the node is the path itself or the row propagates, and it REPLACES
// everything inherited so far. So a new row at / reaches exactly the paths
// that inherit from /: those with no token row of this token that applies
// strictly below /. At such a path a privilege's flag is the OR of the flags
// of the roles holding it, and for a non-root owner it is ANDed with the
// owner's. A path with its own applicable deeper row is unchanged.
//
// A NoAccess row anywhere makes the answer unpredictable: it is refused.
func predictTree(tree, ownerTree map[string]map[string]bool, acls []pve.ACLEntry, tokenID string, d []string) (map[string]map[string]bool, error) {
	var own []pve.ACLEntry
	paths := map[string]bool{}
	for _, p := range defaultTopPaths {
		paths[p] = true
	}
	for p := range tree {
		paths[p] = true
	}
	for _, e := range acls {
		paths[e.Path] = true
		if e.Type == "token" && e.UGID == tokenID {
			if e.Role == "NoAccess" {
				return nil, fmt.Errorf("%w: the token has a NoAccess row at %s, which makes its permissions unpredictable", ErrUpgradeWouldNotConverge, e.Path)
			}
			own = append(own, e)
		}
	}
	out := make(map[string]map[string]bool, len(paths))
	for p, set := range tree {
		out[p] = make(map[string]bool, len(set))
		for priv, flag := range set {
			out[p][priv] = flag
		}
	}
	for p := range paths {
		if !inheritsFromRoot(p, own) {
			continue
		}
		if out[p] == nil {
			out[p] = map[string]bool{}
		}
		for _, priv := range d {
			ownerFlag := true
			if ownerTree != nil {
				f, held := ownerTree[p][priv]
				if !held {
					continue
				}
				ownerFlag = f
			}
			out[p][priv] = out[p][priv] || ownerFlag
		}
	}
	return out, nil
}

// inheritsFromRoot reports whether path takes its roles from the token's
// row at /: no row of the token at a node strictly below / applies there.
func inheritsFromRoot(path string, own []pve.ACLEntry) bool {
	for _, e := range own {
		if e.Path == "/" {
			continue
		}
		if e.Path == path || strings.HasPrefix(path, e.Path+"/") {
			if e.Path == path || e.Propagate {
				return false
			}
		}
	}
	return true
}

// judgePredicted is the whole-tree precondition. BOTH halves must hold:
//
//	(b) pve.JudgeTree — the validator's own comparison, the one bootstrap's
//	    `reused` rests on — accepts the predicted tree against /:R::1. This
//	    catches a descendant extra grant and an inherited Administrator, which
//	    a later bootstrap would call ErrScopeTooWide and revoke.
//	(c) the predicted widening is at most {Sys.Audit}. (b) alone is not C1: the
//	    predicted tree is "what the token held plus D", which /:R::1 confers
//	    by construction, so a LIMITED or EMPTY token's prediction passes (b)
//	    too. (c) is what keeps the verb from giving a token privileges it never
//	    held.
//
// Refusals are the verb's own error types, built from a translated
// description, never %w of the validator's error: no verdict sentinel is in
// the chain, so nothing downstream can mistake one for a bootstrap verdict.
func judgePredicted(predicted, tree map[string]map[string]bool, role string, d []string) error {
	converge, beyond := checkTree(predicted, tree, role, d)
	if converge != nil {
		return fmt.Errorf("%w: %s; nothing was changed", ErrUpgradeWouldNotConverge, oneLine(converge.Error()))
	}
	if len(beyond) > 0 {
		return fmt.Errorf("%w: adding %s would also give it [%s] somewhere it does not hold them now; nothing was changed. This verb upgrades a token that already holds %s; it never widens a limited one",
			ErrNotVMAdminToken, role, strings.Join(beyond, ","), vmAdminRoleName)
	}
	return nil
}

// checkTree is the two halves, applied to any tree the token has or would
// have (the predicted one before the write, the actual one after it):
//
//	converge: pve.JudgeTree accepts the tree against /:R::1 with R's
//	          privileges d; nil means bootstrap would call the token reused.
//	beyond:   the privileges the tree holds that before did not, other than
//	          Sys.Audit (a flag-0 Sys.Audit gain counts as Sys.Audit).
func checkTree(after, before map[string]map[string]bool, role string, d []string) (converge error, beyond []string) {
	privs := map[string]bool{}
	for _, p := range d {
		privs[p] = true
	}
	want := []pve.Grant{{Path: "/", Role: role, Propagate: true}}
	held := map[string]map[string]bool{"/": after["/"]}
	converge = pve.JudgeTree(context.Background(), want, []map[string]bool{privs}, after, nil, held,
		func(context.Context, string) (bool, error) {
			return false, errors.New("an existence check was asked for, which a /:R::1 judgement never needs")
		},
		func(_ context.Context, path string) (map[string]bool, error) { return after[path], nil })
	beyond = slices.DeleteFunc(widenedBy(before, after), func(p string) bool { return p == auditPrivilege })
	return converge, beyond
}

// widenedBy returns the privileges present or newly propagating in after that
// before did not hold, sorted.
func widenedBy(before, after map[string]map[string]bool) []string {
	set := map[string]bool{}
	for path, privs := range after {
		for priv, flag := range privs {
			old, held := before[path][priv]
			if !held || (flag && !old) {
				set[priv] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// treeDiff describes the first difference between two trees ("" if equal),
// ignoring paths that hold nothing in either.
func treeDiff(actual, predicted map[string]map[string]bool) string {
	norm := func(t map[string]map[string]bool) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for p, s := range t {
			if len(s) > 0 {
				out[p] = s
			}
		}
		return out
	}
	a, p := norm(actual), norm(predicted)
	paths := map[string]bool{}
	for k := range a {
		paths[k] = true
	}
	for k := range p {
		paths[k] = true
	}
	sorted := make([]string, 0, len(paths))
	for k := range paths {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, path := range sorted {
		var onlyActual, onlyPredicted, flags []string
		for priv, f := range a[path] {
			pf, ok := p[path][priv]
			switch {
			case !ok:
				onlyActual = append(onlyActual, priv)
			case pf != f:
				flags = append(flags, priv)
			}
		}
		for priv := range p[path] {
			if _, ok := a[path][priv]; !ok {
				onlyPredicted = append(onlyPredicted, priv)
			}
		}
		if len(onlyActual)+len(onlyPredicted)+len(flags) > 0 {
			sort.Strings(onlyActual)
			sort.Strings(onlyPredicted)
			sort.Strings(flags)
			return fmt.Sprintf("at %s the token holds [%s] that was not predicted, lacks [%s] that was, and differs in propagation on [%s]",
				path, strings.Join(onlyActual, ","), strings.Join(onlyPredicted, ","), strings.Join(flags, ","))
		}
	}
	return ""
}

// oneLine collapses a message to a single bounded line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
