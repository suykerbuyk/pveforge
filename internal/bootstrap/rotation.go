package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Token outcomes, reported on success AND failure (Result.TokenOutcome).
const (
	// OutcomeMinted: a new token was created and persisted; this run revoked
	// nothing.
	OutcomeMinted = "minted"
	// OutcomeReplaced: the roster's previous token was replaced by a new,
	// persisted one. Result.PriorRevoked says whether this run removed the
	// old one on PVE (it may already have been gone).
	OutcomeReplaced = "replaced"
	// OutcomeReused: the roster's token still validates; nothing changed.
	OutcomeReused = "reused"
	// OutcomeRevokedNotReplaced: this run removed the previous token on PVE
	// and no replacement survived. Every copy of the old secret is dead.
	OutcomeRevokedNotReplaced = "revoked_not_replaced"
	// OutcomeDiscarded: no token created by this run survives, and nothing
	// was revoked by this run (a fresh token minted then removed, or an
	// abort before any add).
	OutcomeDiscarded = "discarded"
	// OutcomeImported: an externally minted token was validated and is now
	// held by the roster (Import). Nothing was created or revoked on PVE.
	OutcomeImported = "imported"
	// OutcomeAlreadyHeld: Import found exactly this token (id and secret)
	// already held, and it still validates; nothing was written.
	OutcomeAlreadyHeld = "already_held"
	// OutcomeNotImported: Import did not write the token (it failed
	// validation, or could not be verified). Nothing on PVE was touched.
	OutcomeNotImported = "not_imported"
)

// Validation states (Result.Validation).
const (
	ValidationVerified   = "verified"
	ValidationUnverified = "unverified"
	ValidationFailed     = "failed"
	ValidationNotRun     = "not_run"
)

// Result.RosterToken values.
const (
	// RosterTokenCleared: this roster's copy of a token known to be dead was
	// removed.
	RosterTokenCleared = "cleared"
	// RosterTokenStaleRevoked: this run revoked the token on PVE but could
	// not clear the roster's copy, which now points at a dead credential.
	RosterTokenStaleRevoked = "stale_revoked"
	// RosterTokenStaleAbsent: the roster's copy points at a token that no
	// longer exists on PVE, and clearing it failed. Nothing was revoked by
	// this run.
	RosterTokenStaleAbsent = "stale_absent"
)

// PriorTokenUnknown (Result.PriorToken): a remove of the previous token hit
// a transport error and the follow-up read could not establish whether the
// token still exists. It may have been revoked.
const PriorTokenUnknown = "unknown"

// Result.LeftoverState values: how sure the run is that Result.LeftoverToken
// still exists on PVE.
const (
	// LeftoverExists: after its remove failed, the token was read as
	// present, so it is still live on PVE.
	LeftoverExists = "exists"
	// LeftoverMayExist: a transport error left it unknown whether the token
	// exists, and the follow-up read could not establish it.
	LeftoverMayExist = "may_exist"
)

var (
	// ErrPriorTokenRevoked wraps every failure after this run removed the
	// target's previous token on PVE: the old secret is dead for every
	// holder, and no replacement was persisted.
	ErrPriorTokenRevoked = errors.New("this run revoked the target's previous API token on PVE and did not replace it")
	// ErrUnknownRole: the requested ACL role does not exist on PVE.
	ErrUnknownRole = errors.New("the requested ACL role does not exist on PVE")
	// ErrUnknownNode: the requested node is not in the cluster's node list.
	ErrUnknownNode = errors.New("the requested node is not a member of the PVE cluster")
	// ErrTokenNotHeld: an API token of the requested name exists on PVE but
	// this roster does not hold it. It is never removed: it may be in use by
	// another roster.
	ErrTokenNotHeld = errors.New("an API token of this name already exists on PVE and this roster does not hold it")
	// ErrInvalidACLPath: a grant's path is not a path PVE would accept.
	ErrInvalidACLPath = errors.New("invalid ACL path")
	// ErrTokenUndecryptable: the roster holds the requested token, it still
	// exists on PVE, and its secret will not decrypt with the given
	// passphrase. A decrypt failure is not a verdict about the token (the
	// passphrase may simply be wrong), so it is never removed.
	ErrTokenUndecryptable = errors.New("the roster's token for this target will not decrypt with the given passphrase (a wrong passphrase, or corruption)")
	// ErrInvalidTokenOwner: --token-owner is not a PVE principal pveforge
	// can own a token with (CheckTokenOwner). Refused before any SSH, and
	// never a verdict.
	ErrInvalidTokenOwner = errors.New("invalid token owner")
	// ErrTokenOwnerMismatch: the roster holds a token owned by another
	// principal and this run named no owner, so the owner it would use is
	// only a default. Minting would orphan the held token and silently
	// re-point the roster at a different principal, so the run is refused
	// before any SSH. Naming the owner explicitly is what makes such a
	// change deliberate. Never a verdict: nothing is removed.
	ErrTokenOwnerMismatch = errors.New("the roster's token belongs to another owner and no --token-owner was given")
	// ErrKeylessWithPersistedSSH: --no-ssh-key was given for a target whose
	// roster entry carries an [targets.ssh] block. Using that key would
	// contradict the flag, and ignoring it would leave a credential the
	// operator believes is gone, so the run is refused before any SSH.
	// Never a verdict: nothing is removed.
	ErrKeylessWithPersistedSSH = errors.New("--no-ssh-key, but this roster holds an SSH keypair for the target")
	// ErrKeylessTargetNeedsFlag: the roster holds a token for this target
	// and NO SSH block — the state a keyless bootstrap leaves — and this
	// run did not pass --no-ssh-key, so it would install and persist an SSH
	// key on a target kept deliberately keyless. Refused before any SSH.
	// Never a verdict.
	//
	// This and ErrKeylessWithPersistedSSH are MUTUALLY EXCLUSIVE: that one
	// requires the flag, this one requires its absence. Both run after
	// ErrTokenOwnerMismatch, so a run tripping both an identity and a
	// transport condition reports the identity one (TestRun_CT4c…,
	// TestRun_CT5d…).
	ErrKeylessTargetNeedsFlag = errors.New("this target holds a token but no SSH key (bootstrapped with --no-ssh-key, or its token imported), so --no-ssh-key is required")
	// ErrRoleHasNoPrivileges: a requested role exists on PVE but grants
	// nothing (NoAccess), so no token holding it could ever validate.
	ErrRoleHasNoPrivileges = errors.New("the requested ACL role grants no privileges")
	// ErrPinnedPrivsMismatch: a grant's pinned privileges are not exactly
	// its role's privileges on PVE. An ACL confers the whole role, so a pin
	// must equal it; for a single grant under a root owner any difference is
	// certain to fail validation (a verdict, which on a re-run would revoke
	// the held token and then fail to replace it). Refused before anything
	// is removed, whatever the configuration. Not a verdict.
	ErrPinnedPrivsMismatch = errors.New("a grant's pinned privileges differ from its role's privileges on PVE")
	// ErrOwnerLacksPrivileges: the token's owner (a non-root user) does not
	// itself hold what is requested. PVE intersects a privsep token's
	// privileges with its owner's, so such a token could never validate;
	// bootstrap aborts before removing anything, since a verdict against
	// the held token would only be the owner's limit showing through. Not a
	// verdict: it never leads to a remove.
	ErrOwnerLacksPrivileges = errors.New("the token owner does not hold the requested privileges")
	// ErrOwnerDisabled: the token's owner (a non-root user) is disabled or
	// expired. PVE rejects every token of such an owner (401), which is not
	// a verdict about the token (re-enabling the owner restores it), so
	// bootstrap aborts before removing anything. Not a verdict.
	ErrOwnerDisabled = errors.New("the token owner is disabled or expired")
)

// verdictSentinels are the definite verdicts about a token's grants. Only a
// verdict may lead to removing a token this roster holds: removal revokes
// the secret for every holder, so a transient or unverifiable error must
// never trigger it.
var verdictSentinels = []error{ErrWrongScope, ErrNoGrants, ErrNotAuthorized, ErrScopeTooWide}

// postMintRetrySentinels are the post-mint verdicts that may be propagation
// lag right after a mint, so they are retried a bounded number of times
// before they count: a fresh credential (ErrNotAuthorized) and a fresh ACL
// (ErrNoGrants, ErrWrongScope) can both lag. ErrScopeTooWide is never here:
// "too wide" cannot be lag.
var postMintRetrySentinels = []error{ErrNotAuthorized, ErrNoGrants, ErrWrongScope}

func isVerdict(err error) bool         { return matchesAny(err, verdictSentinels) }
func postMintRetryable(err error) bool { return matchesAny(err, postMintRetrySentinels) }

func matchesAny(err error, set []error) bool {
	for _, s := range set {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// Seams (unexported package vars, the project's idiom for tests).
var (
	dryRunTokenWrite    = roster.DryRunTokenWrite
	writeTokenAuthFn    = roster.WriteTokenAuth // Import's write; a test can make it store something else
	cleanupTimeout      = 30 * time.Second
	postMintRetryDelay  = 1 * time.Second
	persistTargetMetaFn = persistTargetMeta
)

// postMintAttempts bounds the post-mint validation loop.
const postMintAttempts = 3

// ---- grant paths: exact mirrors of PVE's own checks ----

var (
	aclPathCharsetRE = regexp.MustCompile(`^[[:alnum:]._/-]+$`)
	aclSlashRunRE    = regexp.MustCompile(`/+`)
	// aclCheckPathRE mirrors PVE::AccessControl::check_path, the whitelist
	// `pveum acl modify` applies (API2/ACL.pm:162-167), as of
	// libpve-access-control 9.1.1 (AccessControl.pm:1281-1318, read on
	// qa-pve-02). A newer PVE that widens its whitelist is refused here
	// before anything happens (fail-closed); one that narrows it fails at
	// the grant, which is reported.
	aclCheckPathRE = regexp.MustCompile(`^(?:` + strings.Join([]string{
		`/`, `/access`, `/access/groups`, `/access/groups/[[:alnum:]._-]+`,
		`/access/realm`, `/access/realm/[[:alnum:]._-]+`,
		`/nodes`, `/nodes/[[:alnum:]._-]+`,
		`/pool`, `/pool/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,2}`,
		`/sdn`, `/sdn/controllers`, `/sdn/controllers/[[:alnum:]_-]+`,
		`/sdn/dns`, `/sdn/dns/[[:alnum:]]+`,
		`/sdn/fabrics`, `/sdn/fabrics/[[:alnum:]]+`,
		`/sdn/ipams`, `/sdn/ipams/[[:alnum:]]+`,
		`/sdn/prefix-lists`, `/sdn/prefix-lists/[[:alnum:]]+`,
		`/sdn/route-maps`, `/sdn/route-maps/[[:alnum:]]+`,
		`/sdn/zones`, `/sdn/zones/[[:alnum:]._-]+`,
		`/sdn/zones/[[:alnum:]._-]+/[[:alnum:]._-]+`,
		`/sdn/zones/[[:alnum:]._-]+/[[:alnum:]._-]+/[1-9][0-9]{0,3}`,
		`/storage`, `/storage/[[:alnum:]._-]+`,
		`/vms`, `/vms/[1-9][0-9]{2,}`,
		`/mapping`, `/mapping/[[:alnum:]._-]+`, `/mapping/[[:alnum:]._-]+/[[:alnum:]._-]+`,
	}, `|`) + `)$`)
)

// normalizeACLPath mirrors PVE::AccessControl::normalize_path
// (AccessControl.pm:1263-1277): a Perl-false input ("" or "0") is undef
// before any mapping; then runs of "/" collapse, one trailing "/" is
// stripped, empty becomes "/", a missing leading "/" is added, and the
// charset is checked.
func normalizeACLPath(p string) (string, bool) {
	if p == "" || p == "0" {
		return "", false
	}
	p = aclSlashRunRE.ReplaceAllString(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !aclPathCharsetRE.MatchString(p) {
		return "", false
	}
	return p, true
}

// checkedACLPath returns p normalized, or ErrInvalidACLPath.
func checkedACLPath(p string) (string, error) {
	n, ok := normalizeACLPath(p)
	if !ok || !aclCheckPathRE.MatchString(n) {
		return "", fmt.Errorf("%w %q: PVE would refuse it (normalize_path/check_path)", ErrInvalidACLPath, p)
	}
	return n, nil
}

// ---- strict, non-echoing reads ----

// runJSONArray runs a read-only command that prints a JSON array and decodes
// it into out. It refuses everything that is not a successful, non-empty,
// non-null array: an empty or "null" answer is never read as "no items".
// Errors never echo stdout (it could be anything); they give its byte length.
func runJSONArray(ctx context.Context, s SSHSession, cmd string, out interface{}) error {
	res, err := s.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("run %s: %w", firstWords(cmd), err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited %d: %s", firstWords(cmd), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	trimmed := strings.TrimSpace(res.Stdout)
	if trimmed == "" {
		return fmt.Errorf("%s printed nothing (expected a JSON array)", firstWords(cmd))
	}
	if trimmed == "null" {
		return fmt.Errorf("%s printed null (expected a JSON array)", firstWords(cmd))
	}
	if !strings.HasPrefix(trimmed, "[") {
		return fmt.Errorf("%s printed %d bytes that are not a JSON array", firstWords(cmd), len(trimmed))
	}
	if err := json.Unmarshal([]byte(trimmed), out); err != nil {
		return fmt.Errorf("%s printed %d bytes that do not parse as the expected JSON array", firstWords(cmd), len(trimmed))
	}
	return nil
}

// firstWords names a command in an error without its arguments.
func firstWords(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) > 4 {
		f = f[:4]
	}
	return strings.Join(f, " ")
}

func tokenListCmd(userID string) string {
	return fmt.Sprintf("pveum user token list %s --output-format json", sshexec.ShellQuote(userID))
}

// tokenPresent reads the user's token list and reports whether tokenID is
// in it.
func tokenPresent(ctx context.Context, s SSHSession, userID, tokenID string) (bool, error) {
	var list []struct {
		TokenID string `json:"tokenid"`
	}
	if err := runJSONArray(ctx, s, tokenListCmd(userID), &list); err != nil {
		return false, err
	}
	for _, t := range list {
		if t.TokenID == tokenID {
			return true, nil
		}
	}
	return false, nil
}

// preflight runs every check that can run before anything is removed:
// every requested role exists and grants something, the node exists, the
// token's owner can hold what is requested (checkOwner), whether the
// requested token exists on PVE, and a dry run of every roster write this
// run may need. It returns present.
func preflight(ctx context.Context, s SSHSession, opts Options, want []Grant, owner ownerReader) (bool, error) {
	var roles []struct {
		RoleID string  `json:"roleid"`
		Privs  *string `json:"privs"`
	}
	if err := runJSONArray(ctx, s, "pveum role list --output-format json", &roles); err != nil {
		return false, fmt.Errorf("preflight: %w", err)
	}
	rolePrivs := map[string][]string{}
	for _, g := range want {
		if _, done := rolePrivs[g.Role]; done {
			continue
		}
		i := indexFunc(len(roles), func(i int) bool { return roles[i].RoleID == g.Role })
		if i < 0 {
			return false, fmt.Errorf("preflight: %w: %q", ErrUnknownRole, g.Role)
		}
		privs, err := parseRolePrivs(roles[i].Privs)
		if err != nil {
			return false, fmt.Errorf("preflight: role %s: %w", g.Role, err)
		}
		if len(privs) == 0 {
			return false, fmt.Errorf("preflight: %w: %s", ErrRoleHasNoPrivileges, g.Role)
		}
		rolePrivs[g.Role] = privs
	}
	for _, g := range want {
		if g.Privs == nil {
			continue
		}
		if missing, extra := setDiff(g.Privs, rolePrivs[g.Role]); len(missing) > 0 || len(extra) > 0 {
			return false, fmt.Errorf("preflight: %w: %s at %s: pinned but not in the role [%s], in the role but not pinned [%s]; no token was touched",
				ErrPinnedPrivsMismatch, g.Role, g.Path, strings.Join(missing, ","), strings.Join(extra, ","))
		}
	}
	var nodes []struct {
		Node string `json:"node"`
	}
	if err := runJSONArray(ctx, s, "pvesh get /nodes --output-format json", &nodes); err != nil {
		return false, fmt.Errorf("preflight: %w", err)
	}
	if indexFunc(len(nodes), func(i int) bool { return nodes[i].Node == opts.Node }) < 0 {
		return false, fmt.Errorf("preflight: %w: %q", ErrUnknownNode, opts.Node)
	}
	if err := checkOwner(ctx, owner, opts.TokenOwner, want, rolePrivs); err != nil {
		return false, fmt.Errorf("preflight: %w", err)
	}
	present, err := tokenPresent(ctx, s, opts.TokenOwner, opts.TokenID)
	if err != nil {
		return false, fmt.Errorf("preflight: %w", err)
	}
	if err := dryRunTokenWrite(opts.RosterPath, opts.TargetID); err != nil {
		return false, fmt.Errorf("preflight: %w", err)
	}
	return present, nil
}

// privNameRE is PVE's privilege-name shape (as internal/pve checks it).
var privNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]*$`)

// parseRolePrivs strictly parses a role list entry's "privs" field: a
// comma-joined list of privilege names, "" for a role with none. A missing
// field or a malformed name is an error, never "no privileges".
func parseRolePrivs(privs *string) ([]string, error) {
	if privs == nil {
		return nil, errors.New(`the role list entry has no "privs" field`)
	}
	if *privs == "" {
		return nil, nil
	}
	out := strings.Split(*privs, ",")
	for _, p := range out {
		if !privNameRE.MatchString(p) {
			return nil, errors.New(`the role list's "privs" holds a name that is not a privilege name`)
		}
	}
	return out, nil
}

// setDiff returns the members of a not in b and of b not in a, each sorted.
func setDiff(a, b []string) (onlyA, onlyB []string) {
	inA := make(map[string]bool, len(a))
	for _, x := range a {
		inA[x] = true
	}
	inB := make(map[string]bool, len(b))
	for _, x := range b {
		inB[x] = true
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	for _, x := range a {
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

// ---- the owner check ----

// ownerReader reads what PVE says about a token owner. sshOwnerReader is
// today's; an API-only mode can supply one that reads over the API instead
// (GET /access/users/<owner>, GET /access/permissions?userid=<owner>&path=,
// which needs Sys.Audit on /access), and checkOwner stays as it is.
type ownerReader interface {
	// ownerActive reports whether owner is enabled and not expired.
	ownerActive(ctx context.Context, owner string) (bool, error)
	// ownerPerms returns owner's effective privileges at exactly path:
	// privilege → propagate.
	ownerPerms(ctx context.Context, owner, path string) (map[string]bool, error)
}

// checkOwner aborts before anything is removed when a non-root owner can
// never hold what is requested, because PVE intersects a privsep token's
// privileges with its owner's: the owner is disabled or expired
// (ErrOwnerDisabled), or at some grant's path lacks a privilege the grant
// confers, or holds it without propagate for a propagating grant
// (ErrOwnerLacksPrivileges). A grant's privileges are its pinned Privs, else
// its role's (rolePrivs, from the preflight's role list).
//
// root@pam is exempt and nothing is read for it: PVE answers root with
// Administrator's full privilege set at propagate 1 and applies no
// intersection to its tokens. In today's SSH mode the SSH user IS the owner
// and pveum refuses to run as anyone but root, so a non-root owner's run
// already aborts at the preflight's role list; this check is what keeps a
// run safe once the SSH user (root) and the owner differ.
func checkOwner(ctx context.Context, rd ownerReader, owner string, want []Grant, rolePrivs map[string][]string) error {
	if owner == "root@pam" {
		return nil
	}
	active, err := rd.ownerActive(ctx, owner)
	if err != nil {
		return fmt.Errorf("check token owner %s: %w", owner, err)
	}
	if !active {
		return fmt.Errorf("%w: %s; no token was touched", ErrOwnerDisabled, owner)
	}
	read := map[string]map[string]bool{}
	for _, g := range want {
		perms, ok := read[g.Path]
		if !ok {
			if perms, err = rd.ownerPerms(ctx, owner, g.Path); err != nil {
				return fmt.Errorf("check token owner %s at %s: %w", owner, g.Path, err)
			}
			read[g.Path] = perms
		}
		privs := g.Privs
		if privs == nil {
			privs = rolePrivs[g.Role]
		}
		missing, flagOnly := ownerCovers(perms, g, privs)
		if len(missing) > 0 || len(flagOnly) > 0 {
			return fmt.Errorf("%w: %s at %s lacks [%s] and holds without propagate [%s]; no token was touched",
				ErrOwnerLacksPrivileges, owner, g.Path, strings.Join(missing, ","), strings.Join(flagOnly, ","))
		}
	}
	return nil
}

// ownerCovers compares an owner's privileges at g.Path (perms: privilege →
// propagate) with privs, what g confers: missing are privileges the owner
// lacks there; flagOnly are privileges it holds only without propagate,
// when g propagates. Both sorted.
func ownerCovers(perms map[string]bool, g Grant, privs []string) (missing, flagOnly []string) {
	for _, p := range privs {
		prop, ok := perms[p]
		switch {
		case !ok:
			missing = append(missing, p)
		case g.Propagate && !prop:
			flagOnly = append(flagOnly, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(flagOnly)
	return missing, flagOnly
}

// sshOwnerReader reads the owner through pveum over the preflight's session.
type sshOwnerReader struct{ s SSHSession }

func (r sshOwnerReader) ownerActive(ctx context.Context, owner string) (bool, error) {
	var users []struct {
		UserID string `json:"userid"`
		Enable *int64 `json:"enable"`
		Expire *int64 `json:"expire"`
	}
	if err := runJSONArray(ctx, r.s, "pveum user list --output-format json", &users); err != nil {
		return false, err
	}
	i := indexFunc(len(users), func(i int) bool { return users[i].UserID == owner })
	if i < 0 {
		return false, errors.New("the owner is not in pveum's user list")
	}
	u := users[i]
	if u.Enable == nil || u.Expire == nil {
		return false, errors.New(`the owner's user list entry lacks "enable" or "expire"`)
	}
	expired := *u.Expire > 0 && *u.Expire <= time.Now().Unix()
	return *u.Enable == 1 && !expired, nil
}

func (r sshOwnerReader) ownerPerms(ctx context.Context, owner, path string) (map[string]bool, error) {
	cmd := fmt.Sprintf("pveum user permissions %s --path %s --output-format json", sshexec.ShellQuote(owner), sshexec.ShellQuote(path))
	res, err := r.s.Run(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", firstWords(cmd), err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", firstWords(cmd), res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	// Exactly {"<path>": {"<Priv>": 0|1, ...}}; an empty inner object is
	// zero privileges. Errors give the byte length, never stdout.
	trimmed := strings.TrimSpace(res.Stdout)
	var tree map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &tree); err != nil || tree == nil {
		return nil, fmt.Errorf("%s printed %d bytes that are not a permission object", firstWords(cmd), len(trimmed))
	}
	set, ok := tree[path]
	if len(tree) != 1 || !ok || set == nil {
		return nil, fmt.Errorf("%s: the answer is not keyed by exactly the requested path", firstWords(cmd))
	}
	perms := make(map[string]bool, len(set))
	for name, v := range set {
		if !privNameRE.MatchString(name) {
			return nil, fmt.Errorf("%s: the answer holds a name that is not a privilege name", firstWords(cmd))
		}
		switch string(v) {
		case "1", "true":
			perms[name] = true
		case "0", "false":
			perms[name] = false
		default:
			return nil, fmt.Errorf("%s: privilege %s has a flag that is not 0/1/true/false", firstWords(cmd), name)
		}
	}
	return perms, nil
}

// indexFunc returns the first i in [0, n) for which pred holds, or -1.
func indexFunc(n int, pred func(int) bool) int {
	for i := 0; i < n; i++ {
		if pred(i) {
			return i
		}
	}
	return -1
}

// heldToken is what this roster holds for the target's token.
type heldToken struct {
	ID         string // "" when the roster holds no token
	Secret     string // set only when it decrypted
	DecryptErr error  // non-nil when it is held but will not decrypt
}

// loadHeldToken reads the roster's token for the target. A roster that will
// not load is an error (a local fault, never a reason to mint); a token that
// will not decrypt is reported in DecryptErr. It decrypts ONLY the token
// secret, never the SSH key (see loadExistingSSHAuth).
func loadHeldToken(opts Options) (heldToken, error) {
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return heldToken{}, fmt.Errorf("load roster %s: %w", opts.RosterPath, err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil {
		return heldToken{}, fmt.Errorf("target %q not found in roster", opts.TargetID)
	}
	if tg.Token == nil {
		return heldToken{}, nil
	}
	secret, err := roster.DecryptString(tg.Token.SecretEnc, opts.Passphrase)
	if err != nil {
		return heldToken{ID: tg.Token.ID, DecryptErr: err}, nil
	}
	return heldToken{ID: tg.Token.ID, Secret: string(secret)}, nil
}

// ---- the run ----

// sshIdentity is this run's in-memory SSH identity. freshSession reconnects
// with exactly these values and never re-reads them from the roster: the
// run lock serializes only other bootstraps, and a hand edit mid-run must
// not redirect a reconnect.
type sshIdentity struct {
	addr, user    string
	privateKeyPEM []byte
	hostKeyFP     string
	// password and keyless are set only by a --no-ssh-key run: it holds no
	// keypair, so a redial re-authenticates with the password, pinned to
	// the fingerprint this run captured. Both live here for the run's
	// duration and nowhere else — runner does not outlive Run.
	password string
	keyless  bool
}

type tokenState int

const (
	tokenAbsent tokenState = iota
	tokenPresentState
	tokenUnreadable
)

// runner carries one Run's state through the token phase.
type runner struct {
	ctx       context.Context
	opts      Options
	transport SSHTransport
	api       APIValidator
	session   SSHSession
	ident     sshIdentity
	fullID    string
	// want is the requested grant list (requestedGrants): the grants
	// issued, owner-checked, skip-checked and validated post-mint.
	want []Grant
	res  *Result
	// removed: this run removed the roster-held token on PVE.
	removed bool
	// cleanupErr collects why a cleanup step left a token behind.
	cleanupErr error
}

// cleanupCtx returns a fresh, bounded context for ONE cleanup step. It is
// detached from r.ctx (context.WithoutCancel), so a cancelled command
// context cannot skip the step that makes the post-remove window safe or
// reportable, and it is created immediately before that step: never one
// deadline started at the remove, which the forward steps would consume.
func (r *runner) cleanupCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.ctx), cleanupTimeout)
}

// freshSession replaces a session that returned a transport error with a
// new one, reconnected with this run's in-memory identity (pinned host key:
// it cannot reach a different host or key). The old session is closed and
// every later step uses the new one. One attempt; no loop.
func (r *runner) freshSession(ctx context.Context) error {
	s, err := r.reconnect(ctx)
	if err != nil {
		return err
	}
	_ = r.session.Close()
	r.session = s
	return nil
}

// reconnect re-establishes this run's session with this run's own identity.
// A keyless run has no keypair, so it re-authenticates with the password,
// PINNED to the fingerprint captured on this run's first connection: a
// redial can no more reach a different host than a keyed reconnect can.
func (r *runner) reconnect(ctx context.Context) (SSHSession, error) {
	if r.ident.keyless {
		s, _, err := r.transport.DialWithPassword(ctx, r.ident.addr, r.ident.user, r.ident.password, r.ident.hostKeyFP)
		return s, err
	}
	return r.transport.ReconnectWithPinnedKey(ctx, r.ident.addr, r.ident.user, r.ident.privateKeyPEM, r.ident.hostKeyFP)
}

// reread establishes, after a transport error, whether the requested token
// exists: re-read, never infer.
func (r *runner) reread() tokenState {
	return r.readToken(true)
}

// readToken reads whether the requested token exists, as a cleanup step
// with its own budget. reconnect replaces the session first (after a
// transport error); otherwise the current, working session is used.
func (r *runner) readToken(reconnect bool) tokenState {
	sctx, cancel := r.cleanupCtx()
	defer cancel()
	if reconnect {
		if err := r.freshSession(sctx); err != nil {
			return tokenUnreadable
		}
	}
	present, err := tokenPresent(sctx, r.session, r.opts.TokenOwner, r.opts.TokenID)
	if err != nil {
		return tokenUnreadable
	}
	if present {
		return tokenPresentState
	}
	return tokenAbsent
}

func (r *runner) removeCmd() string {
	return fmt.Sprintf("pveum user token remove %s %s", sshexec.ShellQuote(r.opts.TokenOwner), sshexec.ShellQuote(r.opts.TokenID))
}

// fail returns the partial result for a failure after the token phase began.
func (r *runner) fail(cause error) (*Result, error) {
	if r.removed {
		r.res.TokenOutcome = OutcomeRevokedNotReplaced
	} else {
		r.res.TokenOutcome = OutcomeDiscarded
	}
	if r.res.Validation == "" {
		r.res.Validation = ValidationNotRun
	}
	err := cause
	if r.cleanupErr != nil {
		err = fmt.Errorf("%w; and the cleanup left the token behind: %w", cause, r.cleanupErr)
	}
	if r.removed {
		err = fmt.Errorf("%w: %w", ErrPriorTokenRevoked, err)
	}
	return r.res, fmt.Errorf("bootstrap %s: %w", r.opts.TargetID, err)
}

// removeFresh removes the token this run created, as a cleanup step. If it
// cannot be proven gone it is reported as LeftoverToken.
func (r *runner) removeFresh() {
	sctx, cancel := r.cleanupCtx()
	res, err := r.session.Run(sctx, r.removeCmd())
	cancel()
	if err == nil && res.ExitCode == 0 {
		return
	}
	// Failed or ambiguous: re-read before claiming the token exists. A
	// non-zero exit can also mean it is already gone; the working session
	// reads it, while a transport error needs a fresh one.
	state := LeftoverExists
	switch r.readToken(err != nil) {
	case tokenAbsent:
		return
	case tokenUnreadable:
		state = LeftoverMayExist
	}
	if err != nil {
		r.cleanupErr = fmt.Errorf("remove the fresh token %s: %w", r.fullID, err)
	} else {
		r.cleanupErr = fmt.Errorf("remove the fresh token %s: pveum user token remove exited %d: %s", r.fullID, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	r.leftover(state)
}

// leftover reports the fresh token as left behind on PVE: the id alone in
// LeftoverToken, and how sure that is in LeftoverState.
func (r *runner) leftover(state string) {
	r.res.LeftoverToken = r.fullID
	r.res.LeftoverState = state
}

// validatePostMint runs the bounded post-mint validation. Any verdict seen
// inside the window and not followed by a success is a verdict: a secret PVE
// rejected once is never persisted because a later attempt merely failed to
// connect. A plain error on the first attempt is not retried.
func (r *runner) validatePostMint(secret string) (verdict, nonVerdict error) {
	cfg := APIConfig{Host: r.opts.Host, APIPort: r.opts.APIPort, InsecureTLS: r.opts.InsecureTLS, TokenID: r.fullID, TokenSecret: secret}
	var sawVerdict error // the last retryable verdict seen, if any
	for attempt := 1; attempt <= postMintAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(postMintRetryDelay):
			case <-r.ctx.Done():
				if sawVerdict != nil {
					return sawVerdict, nil
				}
				return nil, r.ctx.Err()
			}
		}
		err := r.api.ValidateTokenGrants(r.ctx, cfg, r.want)
		switch {
		case err == nil:
			return nil, nil
		case isVerdict(err) && !postMintRetryable(err):
			return err, nil
		case postMintRetryable(err):
			sawVerdict = err
		case sawVerdict == nil:
			// A plain error before any verdict: not retried.
			return nil, err
		}
		// Otherwise a plain error after a retryable verdict: keep trying;
		// only a later success can clear the verdict.
	}
	return sawVerdict, nil
}

// mintAndPersist is the forward token phase after any remove and clear:
// add → parse → grant → validate → persist. Every failure is reported
// through r.fail with the partial result.
func (r *runner) mintAndPersist(successOutcome, orphan string) (*Result, error) {
	addCmd := fmt.Sprintf("pveum user token add %s %s --privsep 1 --output-format json",
		sshexec.ShellQuote(r.opts.TokenOwner), sshexec.ShellQuote(r.opts.TokenID))
	res, err := r.session.Run(r.ctx, addCmd)
	if err != nil {
		// Ambiguous: the add may have run. Re-read, never infer.
		switch r.reread() {
		case tokenPresentState:
			// Ours, but its secret was never received: unusable. Remove it.
			r.removeFresh()
		case tokenUnreadable:
			r.leftover(LeftoverMayExist)
		}
		return r.fail(fmt.Errorf("run pveum user token add: %w", err))
	}
	if res.ExitCode != 0 {
		return r.fail(fmt.Errorf("pveum user token add exited %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr)))
	}
	secret, err := parseTokenSecret(res.Stdout)
	if err != nil {
		r.removeFresh()
		return r.fail(fmt.Errorf("create token: %w", err))
	}
	if err := grantAll(r.ctx, r.session, r.fullID, r.want); err != nil {
		r.removeFresh()
		return r.fail(fmt.Errorf("grant acl: %w", err))
	}

	verdict, nonVerdict := r.validatePostMint(secret)
	if verdict != nil {
		r.res.Validation = ValidationFailed
		r.removeFresh()
		return r.fail(fmt.Errorf("the fresh token failed validation: %w", verdict))
	}
	if nonVerdict != nil {
		r.res.Validation = ValidationUnverified
	} else {
		r.res.Validation = ValidationVerified
	}

	if err := roster.WriteTokenAuth(r.opts.RosterPath, r.opts.TargetID, roster.TokenWrite{
		TokenID:         r.fullID,
		SecretPlaintext: []byte(secret),
	}, r.opts.Passphrase); err != nil {
		r.removeFresh()
		return r.fail(fmt.Errorf("persist token auth: %w", err))
	}
	r.res.TokenOutcome = successOutcome
	r.res.Grants = copyGrants(r.want)
	r.res.OrphanedToken = orphan
	if err := persistTargetMetaFn(r.opts); err != nil {
		return r.res, fmt.Errorf("bootstrap %s: %w", r.opts.TargetID, err)
	}
	if nonVerdict != nil {
		return r.res, fmt.Errorf("bootstrap %s: the token was persisted but its grants could not be verified: %w", r.opts.TargetID, nonVerdict)
	}
	return r.res, nil
}

// tokenPhase classifies the run (§2.3 of the plan) from the roster's held
// token, the skip-check and the preflight's present, and performs it.
func (r *runner) tokenPhase(present bool) (*Result, error) {
	held, err := loadHeldToken(r.opts)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", r.opts.TargetID, err)
	}
	notHeld := func() error {
		return fmt.Errorf("bootstrap %s: %w: %s; to replace it deliberately, remove it first: pveum user token remove %s %s (this revokes it for every holder)",
			r.opts.TargetID, ErrTokenNotHeld, r.fullID, sshexec.ShellQuote(r.opts.TokenOwner), sshexec.ShellQuote(r.opts.TokenID))
	}

	switch {
	case held.ID == "":
		if present {
			return nil, notHeld()
		}
		return r.mintAndPersist(OutcomeMinted, "")
	case held.ID != r.fullID:
		// A changed --token-id: the old token is never removed or cleared.
		if present {
			return nil, notHeld()
		}
		return r.mintAndPersist(OutcomeMinted, held.ID)
	}

	// The roster holds exactly the requested token.
	var reason string
	var reasonErr error
	if held.DecryptErr != nil {
		// A decrypt failure is not a verdict about the token: a wrong
		// passphrase fails the same way as corruption, and the SSH key
		// decrypting proves nothing (a first bootstrap with a wrong
		// passphrase wrote that key under it). A token still on PVE is
		// never removed on it. One already gone from PVE is known dead, and
		// is replaced below with nothing revoked.
		if present {
			return nil, fmt.Errorf("bootstrap %s: %w: %s; the token was left untouched on PVE and in the roster. If it really is lost, remove it deliberately: pveum user token remove %s %s (this revokes it for every holder)",
				r.opts.TargetID, ErrTokenUndecryptable, r.fullID, sshexec.ShellQuote(r.opts.TokenOwner), sshexec.ShellQuote(r.opts.TokenID))
		}
		reason = "persisted token undecryptable"
		reasonErr = held.DecryptErr
	} else {
		err := r.api.ValidateTokenGrants(r.ctx, APIConfig{
			Host: r.opts.Host, APIPort: r.opts.APIPort, InsecureTLS: r.opts.InsecureTLS,
			TokenID: held.ID, TokenSecret: held.Secret,
		}, r.want)
		if err == nil {
			r.res.TokenOutcome = OutcomeReused
			r.res.Grants = copyGrants(r.want)
			r.res.Validation = ValidationVerified
			if err := persistTargetMetaFn(r.opts); err != nil {
				return r.res, fmt.Errorf("bootstrap %s: %w", r.opts.TargetID, err)
			}
			return r.res, nil
		}
		if !isVerdict(err) {
			return nil, fmt.Errorf("bootstrap %s: the existing token could not be checked (not a verdict about it, so nothing was changed): %w", r.opts.TargetID, err)
		}
		reason, reasonErr = err.Error(), err
	}
	r.res.ReplacedReason = reason
	r.res.ReplacedErr = reasonErr

	if present {
		if res, err, stop := r.removeHeld(); stop {
			return res, err
		}
	}
	// Known dead now: removed by this run, or absent on PVE. Clear the
	// roster's copy BEFORE the add, so any later failure or crash leaves
	// "no token", never a pointer to a dead one.
	if err := roster.ClearTokenAuth(r.opts.RosterPath, r.opts.TargetID); err != nil {
		if r.removed {
			r.res.RosterToken = RosterTokenStaleRevoked
		} else {
			r.res.RosterToken = RosterTokenStaleAbsent
		}
		return r.fail(fmt.Errorf("clear the roster's copy of the dead token: %w", err))
	}
	r.res.RosterToken = RosterTokenCleared
	return r.mintAndPersist(OutcomeReplaced, "")
}

// removeHeld removes the roster-held token on PVE. stop reports that the
// run must end with (res, err).
func (r *runner) removeHeld() (res *Result, err error, stop bool) {
	out, runErr := r.session.Run(r.ctx, r.removeCmd())
	if runErr == nil {
		if out.ExitCode != 0 {
			return nil, fmt.Errorf("bootstrap %s: pveum user token remove exited %d; pveforge did not revoke the token: %s", r.opts.TargetID, out.ExitCode, strings.TrimSpace(out.Stderr)), true
		}
		r.removed = true
		r.res.PriorRevoked = true
		return nil, nil, false
	}
	// Ambiguous: the remove may have run. Re-read, never infer.
	switch r.reread() {
	case tokenAbsent:
		r.removed = true
		r.res.PriorRevoked = true
		return nil, nil, false
	case tokenPresentState:
		return nil, fmt.Errorf("bootstrap %s: pveum user token remove failed (%v) and the token still exists; pveforge did not revoke it", r.opts.TargetID, runErr), true
	default:
		// Unknown whether it was revoked. The roster may point at a dead
		// token: clear it, then stop.
		r.removed = true
		r.res.PriorRevoked = true
		r.res.PriorToken = PriorTokenUnknown
		if cerr := roster.ClearTokenAuth(r.opts.RosterPath, r.opts.TargetID); cerr != nil {
			r.res.RosterToken = RosterTokenStaleRevoked
		} else {
			r.res.RosterToken = RosterTokenCleared
		}
		res, err := r.fail(fmt.Errorf("pveum user token remove failed (%v) and the follow-up read could not establish whether the token still exists", runErr))
		return res, err, true
	}
}
