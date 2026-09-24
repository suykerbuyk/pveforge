// Package bootstrap implements pveforge's "nothing exists yet" -> "fully
// token-authenticated roster entry" flow (PRD §3.2), plus the token
// creation/ACL-grant validation this task's own research findings flagged
// as a silent-failure risk if skipped. The token's scope is always explicit
// (Options.Grants, parsed from --grant by ParseGrants): there is no default
// grant, and bootstrap fails closed without one.
//
// Orchestration logic here (Run and its helpers) depends only on the
// SSHTransport and APIValidator interfaces below, not on internal/sshexec
// or internal/pve directly — those two packages do real network I/O, and
// keeping them behind small interfaces is what makes this package's own
// tests fast, deterministic, and free of any live-host dependency. The
// concrete adapters wiring the real packages to these interfaces live in
// deps.go; cmd/pveforge/bootstrap.go is the only other caller of those
// constructors. (internal/lock and internal/roster are local files, not
// network I/O, and are used directly: Run holds a per-target lock.Mutation
// for its whole duration.)
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// RunResult is one remote command's outcome, mirroring sshexec.Result —
// duplicated here (rather than imported) so this package's core logic
// doesn't need to depend on sshexec's concrete type for it.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// SSHSession is a live, already-authenticated remote command-execution
// session — what Client.Run(ctx, cmd) gives bootstrap once a Dial has
// succeeded.
type SSHSession interface {
	Run(ctx context.Context, cmd string) (RunResult, error)
	Close() error
}

// SSHTransport is the subset of SSH transport capability the bootstrap
// flow needs, narrowed to an interface so tests can fake it without any
// real network connection. NewSSHTransport (deps.go) provides the
// production implementation, backed by internal/sshexec.
//
// The two connection methods below express deliberately different trust
// models, not just different call signatures — see Run's doc comment for
// which one applies when:
type SSHTransport interface {
	// InstallPubkeyViaPassword connects to addr as user via password auth,
	// idempotently installs authorizedKeyLine into authorized_keys, and
	// returns the host key fingerprint captured trust-on-first-use during
	// that connection. Used ONLY for a target's true first bootstrap (no
	// SSH auth persisted yet) — every later Run must not touch password
	// auth or TOFU again.
	InstallPubkeyViaPassword(ctx context.Context, addr, user, password, authorizedKeyLine string) (hostKeyFingerprint string, err error)

	// DialWithKey connects to addr as user using privateKeyPEM, verifying
	// the host key against hostKeyFingerprint (pinned, per
	// sshexec.PinnedHostKeyCallback). Used immediately after
	// InstallPubkeyViaPassword, pinned against the fingerprint that call
	// just captured — proves the freshly installed key actually works
	// before anything is persisted.
	DialWithKey(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error)

	// DialWithPassword connects to addr as user with password auth, for a
	// run that installs no key (Options.NoSSHKey). pin is "" on a run's
	// FIRST connection — the presented host key is trusted on first use,
	// captured, and returned — or the fingerprint this run already
	// captured, in which case the connection is refused unless the host
	// presents that same key. One method rather than two: the pin argument
	// IS the difference between the two trust models, the same distinction
	// InstallPubkeyViaPassword (capture) and DialWithKey (pin) draw.
	DialWithPassword(ctx context.Context, addr, user, password, pin string) (session SSHSession, hostKeyFingerprint string, err error)

	// ReconnectWithPinnedKey connects using a keypair and host key
	// fingerprint already persisted from a PRIOR successful bootstrap of
	// this target — no password auth, no TOFU capture. Unlike DialWithKey
	// right after a fresh TOFU capture (where the fingerprint being
	// checked against is whatever was just presented, so it can't
	// meaningfully fail), a mismatch here is a REAL security check: it
	// means whatever now answers at this network address presented a
	// different host key than the one this target was pinned to. That
	// must be a hard stop, never a silent re-pin — see Run's doc comment.
	ReconnectWithPinnedKey(ctx context.Context, addr, user string, privateKeyPEM []byte, hostKeyFingerprint string) (SSHSession, error)
}

// APIConfig is the subset of pve.ClientConfig APIValidator needs.
type APIConfig struct {
	Host        string
	APIPort     int
	InsecureTLS bool
	TokenID     string
	TokenSecret string
}

// APIValidator is the subset of pve's capability bootstrap needs to prove
// a token holds exactly the requested grants: PVE's own answer for what the
// token can do must cover want and reach no further (pve.ValidateTokenGrants
// and its known limits). NewAPIValidator (deps.go) provides the production
// implementation, backed by internal/pve.
type APIValidator interface {
	ValidateTokenGrants(ctx context.Context, cfg APIConfig, want []Grant) error
}

// Options configures one bootstrap run against a single target.
type Options struct {
	TargetID    string
	Host        string
	Node        string
	APIPort     int
	InsecureTLS bool
	SSHPort     int // 0 => 22

	// PVEUsername is the SSH LOGIN: a PAM/realm username, e.g. "root@pam".
	// Only @pam (or bare, defaulting to pam: "root" becomes "root@pam")
	// realm users are supported — anything else has no corresponding
	// SSH-reachable Linux system account. The token's OWNER is TokenOwner.
	PVEUsername string
	// PVEPassword is the login's password. In the ordinary flow it is used
	// ONCE, for the pubkey-install step. With NoSSHKey it authenticates
	// EVERY connection this run makes, including the in-run redial after a
	// transport error (TestRun_CT2_KeylessRedialIsPinnedToThisRun), so it
	// must still be available after the first dial.
	PVEPassword string

	// NoSSHKey runs keyless: this run authenticates with PVEPassword for
	// its own duration only, installs no key on the target and persists no
	// SSH auth in the roster. The host key is trusted on FIRST USE on every
	// such run — there is no stored fingerprint to pin against — and the
	// fingerprint actually accepted is reported as Result.HostKeyFingerprint,
	// so a run can be audited afterwards. Within one run a later connection
	// is pinned to that same fingerprint, so a redial cannot reach a
	// different host.
	//
	// A target bootstrapped this way holds a token and no [targets.ssh]
	// block, so every later run of it needs the flag again
	// (ErrKeylessTargetNeedsFlag); and the flag is refused against a target
	// that does hold an SSH block (ErrKeylessWithPersistedSSH).
	NoSSHKey bool

	// TokenOwner is the PVE principal that owns the token, e.g.
	// "pveforge-harness@pve". It is NOT a Linux login and needs no SSH
	// account: the run logs in as PVEUsername and addresses this principal
	// with pveum. Empty means the login itself (applyDefaults), which is
	// what every roster written before token owners existed holds.
	//
	// Changing it deliberately leaves the previous token live on PVE, held
	// by no roster, reported as Result.OrphanedToken and never revoked. An
	// ACCIDENTAL change — the roster holds another principal's token and no
	// owner was given — is refused before any SSH (ErrTokenOwnerMismatch).
	TokenOwner string

	// TokenID is the token's own name (not including the userid prefix),
	// e.g. "pveforge" -> full token id "root@pam!pveforge".
	TokenID string
	// Grants are the ACL grants the token must hold, each a role on a path
	// with its own propagate flag and, optionally, a pinned privilege set.
	// There is no default: Run refuses an empty list (fail closed) before
	// it touches the roster, the lock or the network. Run normalizes every
	// path as PVE does (requestedGrants) before anything else uses it.
	// ParseGrants builds them from the CLI's --grant specs.
	Grants []Grant

	RosterPath string
	// Passphrase is the roster's, proven against the roster (Run proves
	// it again under its lock, free when the proof still stands).
	Passphrase roster.Passphrase
}

// Result reports what Run did. Run returns a non-nil *Result together with
// an error whenever the token phase had begun (a remove, a clear or an add
// was attempted), so a failure is reported, never silent: TokenOutcome and
// Validation always say what happened to the credential.
type Result struct {
	HostKeyFingerprint string
	// TokenID is the full "userid!tokenname" of the requested token.
	TokenID string

	// TokenOutcome is one of the Outcome* constants.
	TokenOutcome string
	// Validation is one of the Validation* constants.
	Validation string
	// Grants is the scope the token this run leaves in the roster holds:
	// the normalized, validated request. It is set only when a token
	// survives (TokenOutcome minted, replaced or reused), together with
	// TokenOutcome; a run that leaves no token behind reports none. A
	// LeftoverToken is deliberately excluded: it is not held by the roster
	// and its warning already tells the operator to remove it.
	Grants []Grant
	// ReplacedReason says why the roster's previous token was replaced (a
	// verdict about it, or "persisted token undecryptable" for a token that
	// will not decrypt and no longer exists on PVE; one that still exists
	// is never replaced, see ErrTokenUndecryptable); ReplacedErr is the same
	// as an error, for errors.Is.
	ReplacedReason string
	ReplacedErr    error
	// PriorRevoked reports that this run removed the roster's previous
	// token on PVE: every copy of its secret, in every roster, is dead.
	PriorRevoked bool
	// OrphanedToken names a token a changed --token-id left live on PVE,
	// held by no roster any more. Never removed. Set only once the new
	// token is persisted.
	OrphanedToken string
	// LeftoverToken is the id of a token this run created but could not
	// prove removed; its secret is lost. It holds the id alone.
	LeftoverToken string
	// LeftoverState is LeftoverExists or LeftoverMayExist when
	// LeftoverToken is set, else "".
	LeftoverState string
	// RosterToken is one of the RosterToken* constants, or "".
	RosterToken string
	// PriorToken is PriorTokenUnknown when a remove's outcome could not be
	// established.
	PriorToken string
}

// Run executes the full bootstrap flow: establish an SSH connection to the
// target (see the connection-strategy branch below), create a scoped API
// token (and grant it every requested ACL, opts.Grants) over that connection
// via pveum, validate that the token holds exactly those grants, then
// persist the token to the roster. There is no default grant: an empty
// opts.Grants is refused first, before the roster, the lock or the network.
//
// Connection strategy, and why it's a hard branch rather than "try
// password, fall back if that fails": once a target has SSH auth
// persisted from a prior successful bootstrap, that keypair and its host
// key fingerprint are proof of a specific, already-verified identity for
// this target. Re-running password auth + trust-on-first-use every time
// would blindly re-trust and silently re-pin whatever key the network
// address presents NOW — which is exactly wrong the one time it matters:
// a network path that has started pointing somewhere else (DNS/IP reuse,
// a rebuilt or compromised box) would be silently accepted and re-pinned,
// after which the standing SSH vector trusts the new key for everything.
// So:
//   - Target already has SSH auth + a pinned fingerprint on file:
//     reconnect directly with that keypair via ReconnectWithPinnedKey.
//     A mismatch (or any other failure) is a hard stop — see that
//     method's doc comment — never a fallback to password auth.
//   - Target has no SSH auth yet (true first bootstrap): generate a
//     fresh keypair, install it via password auth + TOFU capture
//     (InstallPubkeyViaPassword), then prove it works with DialWithKey.
//
// Either way, once a session is established, SSH auth is persisted to the
// roster IMMEDIATELY if it's new (before the token/ACL/validate steps that
// are far more likely to fail transiently — a network drop, an ACL role
// typo, propagation delay). This is what makes a retry after a partial
// failure land in the "already has SSH auth" branch above instead of
// generating a brand-new keypair — and therefore orphaning the
// previously-installed one in authorized_keys — on every retry.
//
// The token phase (tokenPhase, rotation.go) never removes a token without
// a definite verdict about a token THIS roster holds, and never removes a
// same-named token this roster does not hold, or one whose held secret
// will not decrypt (a wrong passphrase is not a verdict about the token).
// Removal revokes the secret for every holder, so a transient or
// unverifiable error aborts instead.
// Every check that can run before a remove does (preflight, rotation.go),
// the roster's copy of a dead token is cleared right after the remove, and
// every later failure is reported with a partial Result.
//
// The whole run holds a per-target lock.Mutation, so two bootstraps of one
// target on one roster cannot interleave remove and add (tokens are removed
// by name, so an interleaving could revoke the other run's fresh token).
func Run(ctx context.Context, opts Options, transport SSHTransport, api APIValidator) (*Result, error) {
	// Whether the caller named an owner, captured before applyDefaults
	// fills it in: an owner that merely defaulted may not silently re-point
	// a roster that holds another principal's token (checkHeldTokenOwner).
	ownerGiven := opts.TokenOwner != ""
	applyDefaults(&opts)
	if err := CheckTokenOwner(opts.TokenOwner); err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}
	// The one requested grant list: issued, owner-checked, skip-checked and
	// validated post-mint as this same value. Checked first, before the
	// roster is read, the lock taken or any SSH: bootstrap fails closed
	// without an explicit grant.
	want, err := requestedGrants(opts)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}
	defaultHostNodeFromRoster(&opts)
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}
	sshUser, err := pamLocalUser(opts.PVEUsername)
	if err != nil {
		return nil, err
	}

	unlock, err := lock.Mutation(ctx, opts.RosterPath, lock.ObjectKey{TargetID: opts.TargetID, Kind: "bootstrap", ID: "token"})
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: acquire the per-target bootstrap lock: %w", opts.TargetID, err)
	}
	defer func() { _ = unlock() }()

	if err := ensureTargetExists(opts); err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}

	// The roster's token must belong to the principal this run addresses,
	// unless the caller deliberately said otherwise. Before any SSH.
	if err := checkHeldTokenOwner(opts, ownerGiven); err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}

	// Then the transport question, on the same terms: the roster's SSH
	// state must match what this run says it is. Identity is checked first
	// (above), so a run tripping both reports the owner. Also before any
	// SSH, and decrypting nothing.
	if err := checkKeylessState(opts); err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}

	addr := fmt.Sprintf("%s:%d", opts.Host, opts.SSHPort)
	fullTokenID := opts.TokenOwner + "!" + opts.TokenID

	// The roster passphrase must open what the roster already holds, or a
	// secret written under it would split the roster. The CLI proved it
	// before prompting for anything else; this re-check — after the state
	// checks above, which decrypt nothing and so must not depend on the
	// passphrase, and before the first decrypt or dial — is free when that
	// proof stands, and it is the decrypt loadExistingSSHAuth then reuses.
	if err := opts.Passphrase.Prove(opts.RosterPath, opts.TargetID); err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}
	existing, err := loadExistingSSHAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}

	r := &runner{ctx: ctx, opts: opts, transport: transport, api: api, fullID: fullTokenID, want: want}

	switch {
	case opts.NoSSHKey:
		// Keyless: one password session for this run only. No keypair is
		// generated, no key is installed on the target, and nothing is
		// written to the roster's [targets.ssh]. The host key is trusted
		// on first use (pin ""), and the fingerprint it returns is both
		// reported (r.res below) and pinned for any redial this run makes
		// (freshSession).
		session, fp, err := transport.DialWithPassword(ctx, addr, sshUser, opts.PVEPassword, "")
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: connect with password (no ssh key): %w", opts.TargetID, err)
		}
		if fp == "" {
			// A capture that yields nothing would silently degrade this
			// run's later redial to a SECOND trust-on-first-use, and drop
			// host_key_fingerprint from the result (omitempty), so the run
			// could not be audited afterwards. Refuse instead, as
			// PinnedHostKeyCallback refuses its own empty input.
			_ = session.Close()
			return nil, fmt.Errorf("bootstrap %s: connect with password (no ssh key): the transport captured no host key fingerprint", opts.TargetID)
		}
		r.session = session
		defer func() { _ = r.session.Close() }()
		r.ident = sshIdentity{addr: addr, user: sshUser, password: opts.PVEPassword, hostKeyFP: fp, keyless: true}

	case existing != nil:
		session, err := transport.ReconnectWithPinnedKey(ctx, addr, sshUser, existing.PrivateKeyPEM, existing.HostKeyFingerprint)
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: reconnect with previously-pinned ssh key: %w — this needs deliberate operator reconciliation; pveforge will not silently re-trust and re-pin a different host key", opts.TargetID, err)
		}
		r.session = session
		defer func() { _ = r.session.Close() }()
		r.ident = sshIdentity{addr: addr, user: sshUser, privateKeyPEM: existing.PrivateKeyPEM, hostKeyFP: existing.HostKeyFingerprint}

	default:
		keypair, genErr := sshexec.GenerateEd25519Keypair(fmt.Sprintf("pveforge@%s", opts.TargetID))
		if genErr != nil {
			return nil, fmt.Errorf("bootstrap %s: generate keypair: %w", opts.TargetID, genErr)
		}

		hostKeyFP, err := transport.InstallPubkeyViaPassword(ctx, addr, sshUser, opts.PVEPassword, keypair.AuthorizedKeyLine)
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: install pubkey: %w", opts.TargetID, err)
		}

		session, err := transport.DialWithKey(ctx, addr, sshUser, keypair.PrivateKeyPEM, hostKeyFP)
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: connect with fresh key: %w", opts.TargetID, err)
		}
		r.session = session
		defer func() { _ = r.session.Close() }()
		r.ident = sshIdentity{addr: addr, user: sshUser, privateKeyPEM: keypair.PrivateKeyPEM, hostKeyFP: hostKeyFP}

		// Persist immediately — proven to work, and this is what makes a
		// later failure in this same Run safe to retry without generating a
		// second keypair.
		if err := roster.WriteSSHAuth(opts.RosterPath, opts.TargetID, roster.SSHWrite{
			User:                sshUser,
			PublicKey:           keypair.AuthorizedKeyLine,
			HostKeyFingerprint:  hostKeyFP,
			PrivateKeyPlaintext: keypair.PrivateKeyPEM,
		}, opts.Passphrase); err != nil {
			return nil, fmt.Errorf("bootstrap %s: persist ssh auth: %w", opts.TargetID, err)
		}
	}
	r.res = &Result{HostKeyFingerprint: r.ident.hostKeyFP, TokenID: fullTokenID}

	present, err := preflight(ctx, r.session, opts, want, sshOwnerReader{r.session})
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}
	return r.tokenPhase(present)
}

// persistTargetMeta writes opts' resolved Host/Node/APIPort/InsecureTLS
// back into the roster for opts.TargetID — closing
// pveforge-bootstrap-insecure-tls-not-persisted: ensureTargetExists only
// ever writes these fields once, via AppendTarget, for a target's
// first-ever roster entry. A target that already had a bare [[targets]]
// block before this Run started (hand-added per the roster template's
// own documented convention, or left over from a bootstrap that predates
// this fix) never got them written at all — so e.g. `bootstrap
// --insecure-tls` against such a target silently lost that setting the
// moment bootstrap finished, even though bootstrap's OWN HTTPS calls
// (ValidateTokenGrants, in the skip-check and post-mint) correctly used
// it for themselves.
//
// Called from BOTH of Run's success paths (the token-recreate-skipped
// fast path and the full mint-a-fresh-token path) — not just the full
// path — since either can be the first time a given target's metadata
// actually gets persisted; a target reached via the fast path might just
// as easily be one with a hand-added bare roster entry.
//
// roster.UpdateTargetFields is itself a true no-op when every field
// already matches what's persisted, so this never causes gratuitous
// roster churn on an ordinary retry that changed nothing — and by the
// time this runs, opts already reflects defaultHostNodeFromRoster's own
// restore-from-roster step (called at the very top of Run, before
// validateOptions), so a retry that OMITS --insecure-tls against a
// target that already has it set has ALREADY had opts.InsecureTLS
// restored to true before this call ever sees it — this cannot
// re-introduce the exact drift defaultHostNodeFromRoster exists to
// prevent, it only closes the gap of nothing ever having persisted the
// value in the first place.
func persistTargetMeta(opts Options) error {
	return roster.UpdateTargetFields(opts.RosterPath, opts.TargetID, roster.TargetMeta{
		Host:        opts.Host,
		Node:        opts.Node,
		APIPort:     opts.APIPort,
		InsecureTLS: opts.InsecureTLS,
	})
}

// defaultHostNodeFromRoster fills opts.Host/opts.Node/opts.APIPort/
// opts.InsecureTLS from the roster's already-recorded values for
// opts.TargetID, when the target already exists there and the caller left
// the corresponding field at its zero value. This is what makes
// --host/--node genuinely optional on a retry against an already-created
// target — matching cmd/pveforge/bootstrap.go's own flag help text
// ("required unless the target already exists in the roster") — rather
// than that text describing a fallback that nothing actually implements.
// A true first bootstrap, where the target has no roster record yet,
// still requires Host/Node explicitly: there is nothing to fall back to,
// and validateOptions (called right after this) still enforces that.
//
// APIPort/InsecureTLS get the same treatment for the same underlying
// reason: a target's API port and TLS posture shouldn't silently drift
// from what it was originally bootstrapped with just because a retry
// left those flags at their defaults. Unlike Host/Node, the CLI's own
// flag help text doesn't promise this fallback for these two — closing
// the gap anyway per pveforge-bootstrap-skip-token-recreate-when-valid's
// "Related residual finding," since a target's port/TLS posture is
// exactly the kind of thing that shouldn't drift unnoticed.
//
// Note on InsecureTLS specifically: because it's a plain bool, this
// cannot distinguish "the operator explicitly wants secure TLS" from
// "the flag was simply left unset" — both read as the zero value
// (false). So if a target was originally bootstrapped with
// --insecure-tls and a later retry omits the flag, this restores the
// original (insecure) setting rather than hardening it; deliberately
// forcing a target back to strict TLS currently requires editing the
// roster directly rather than a bare retry. Accepted tradeoff for the
// case this function exists to close (silent drift away from what a
// target was actually bootstrapped with).
//
// Errors are swallowed here deliberately — this is a best-effort
// convenience lookup, not the place real roster problems should surface.
// A bad/missing roster path either leaves Host/Node blank (caught moments
// later by validateOptions with a clear message) or, for an existing
// roster with real problems, gets its own clearer error from
// ensureTargetExists right afterward.
func defaultHostNodeFromRoster(opts *Options) {
	if opts.RosterPath == "" || opts.TargetID == "" {
		return
	}
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return
	}
	tg := r.Find(opts.TargetID)
	if tg == nil {
		return
	}
	if opts.Host == "" {
		opts.Host = tg.Host
	}
	if opts.Node == "" {
		opts.Node = tg.Node
	}
	if opts.APIPort == 0 {
		opts.APIPort = tg.APIPort
	}
	if !opts.InsecureTLS {
		opts.InsecureTLS = tg.InsecureTLS
	}
}

func applyDefaults(opts *Options) {
	if opts.SSHPort == 0 {
		opts.SSHPort = 22
	}
	if opts.PVEUsername == "" {
		opts.PVEUsername = "root@pam"
	}
	// A bare name defaults to pam (pamLocalUser), and it must say so
	// everywhere it is used: PVE's userid format requires "@realm", so a
	// bare "root" would build the invalid token id "root!pveforge".
	if !strings.Contains(opts.PVEUsername, "@") {
		opts.PVEUsername += "@pam"
	}
	// The owner defaults to the login, AFTER that canonicalization: a bare
	// --pve-user root owns its token as root@pam, never as "root".
	if opts.TokenOwner == "" {
		opts.TokenOwner = opts.PVEUsername
	}
}

func validateOptions(opts *Options) error {
	switch {
	case opts.TargetID == "":
		return fmt.Errorf("bootstrap: target id is required")
	case opts.Host == "":
		return fmt.Errorf("bootstrap: host is required")
	case opts.Node == "":
		return fmt.Errorf("bootstrap: node is required")
	case opts.PVEPassword == "":
		return fmt.Errorf("bootstrap: PVE password is required")
	case opts.TokenID == "":
		return fmt.Errorf("bootstrap: token id is required")
	case opts.RosterPath == "":
		return fmt.Errorf("bootstrap: roster path is required")
	case opts.Passphrase.IsZero():
		return fmt.Errorf("bootstrap: roster passphrase is required")
	}
	return nil
}

// pamLocalUser derives the SSH-login username from a PVE PAM/realm
// username. Only @pam (or a bare username, assumed pam) is accepted: a
// PVE realm user backed by LDAP/AD or a non-PAM authentication source has
// no corresponding Linux system account to SSH into.
func pamLocalUser(pveUsername string) (string, error) {
	name, realm, found := strings.Cut(pveUsername, "@")
	if !found {
		name = pveUsername
	}
	if name == "" {
		return "", fmt.Errorf("pve username %q: the user name is empty", pveUsername)
	}
	if !found {
		return name, nil
	}
	if realm != "pam" {
		return "", fmt.Errorf("pve username %q: only @pam realm users have a corresponding SSH-reachable system account, got @%s", pveUsername, realm)
	}
	return name, nil
}

// ensureTargetExists appends a bare (auth-free) [[targets]] entry for
// opts.TargetID if the roster doesn't already have one, so `pveforge
// bootstrap` is a one-command entry point starting from a roster that
// merely exists (created via `pveforge roster init`) but has no entry for
// this target yet.
func ensureTargetExists(opts Options) error {
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return fmt.Errorf("load roster %s (create it first with `pveforge roster init`): %w", opts.RosterPath, err)
	}
	if r.Find(opts.TargetID) != nil {
		return nil
	}
	return roster.AppendTarget(opts.RosterPath, roster.Target{
		ID:          opts.TargetID,
		Host:        opts.Host,
		Node:        opts.Node,
		APIPort:     opts.APIPort,
		InsecureTLS: opts.InsecureTLS,
	})
}

// existingSSHAuth is what a prior successful bootstrap already proved and
// persisted for a target: a working keypair and the host key fingerprint
// it was pinned to.
type existingSSHAuth struct {
	PrivateKeyPEM      []byte
	HostKeyFingerprint string
}

// loadExistingSSHAuth returns opts.TargetID's persisted SSH auth,
// decrypted with opts.Passphrase, or nil if this target has no SSH auth
// with a pinned host key fingerprint yet — i.e. this is its true first
// bootstrap. A target whose SSH auth exists but (unexpectedly) has no
// fingerprint on file is treated the same as "none yet": Run's own
// first-bootstrap path always writes a keypair and its fingerprint
// together (see Run), so this only happens for roster state this task's
// own code never produced, and re-bootstrapping (rather than reconnecting
// with an unpinned keypair) is the safer default.
//
// Deliberately decrypts ONLY tg.SSH.PrivateKeyEnc (opts.Passphrase.Decrypt)
// — never tg.Resolve, which unconditionally also decrypts Token.SecretEnc
// (see roster.Target.Resolve). This call has no use for the token secret,
// and a target can have both auth types persisted; an unrelated
// Token-decrypt failure (corruption, format drift, anything) must not
// block a perfectly good SSH reconnect that doesn't even touch that data.
//
// Called after ensureTargetExists, so opts.TargetID is guaranteed to exist
// in the roster by the time this runs.
func loadExistingSSHAuth(opts Options) (*existingSSHAuth, error) {
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return nil, fmt.Errorf("load roster %s: %w", opts.RosterPath, err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil {
		return nil, fmt.Errorf("target %q not found in roster", opts.TargetID)
	}
	if tg.SSH == nil || tg.SSH.HostKeyFingerprint == "" {
		return nil, nil
	}
	privateKeyPEM, err := opts.Passphrase.Decrypt(tg.SSH.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt existing ssh keypair for %q: %w", opts.TargetID, err)
	}
	return &existingSSHAuth{
		PrivateKeyPEM:      privateKeyPEM,
		HostKeyFingerprint: tg.SSH.HostKeyFingerprint,
	}, nil
}

// parseTokenSecret extracts the token secret from `pveum user token add
// --output-format json`'s stdout. It tries the CLI's typical bare-value
// shape ({"value": "..."}) first, then falls back to the REST-API-style
// {"data": {"value": "..."}} envelope in case the installed pveum wraps it
// the same way the HTTP API does — deliberately lenient rather than
// asserting one shape, given this hasn't been checked against a live host.
// Either way, it fails loudly rather than silently returning the wrong
// string if neither shape matches.
//
// The failure branch deliberately never echoes stdout: a response that
// fails to parse as either expected shape is exactly the case most likely
// to actually contain the real secret under a differently-shaped response
// than assumed, and this task's own standing rule is that no secret
// material ever appears in an error string. Only bounded, non-secret
// information is reported instead — the parsed top-level JSON key names,
// or (if it isn't even a JSON object) the byte length.
func parseTokenSecret(stdout string) (string, error) {
	var direct struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(stdout), &direct); err == nil && direct.Value != "" {
		return direct.Value, nil
	}
	var enveloped struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &enveloped); err == nil && enveloped.Data.Value != "" {
		return enveloped.Data.Value, nil
	}

	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &generic); err == nil {
		keys := make([]string, 0, len(generic))
		for k := range generic {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", fmt.Errorf(`parse pveum token add output: no "value" field found (top-level keys: %v)`, keys)
	}
	return "", fmt.Errorf("parse pveum token add output: unexpected output shape (%d bytes, not a JSON object)", len(stdout))
}

// requestedGrants is the single construction site of Run's want: opts.Grants
// normalized and checked (normalizeGrants). An empty list is ErrInvalidGrant.
func requestedGrants(opts Options) ([]Grant, error) {
	return normalizeGrants(opts.Grants)
}

// normalizeGrants returns a copy of gs with every path normalized as PVE
// does (checkedACLPath: normalize_path, then check_path's whitelist) and
// the result checked (checkGrants): non-empty, each grant well formed, and
// no two grants on one normalized path. Privs are copied, never shared.
func normalizeGrants(gs []Grant) ([]Grant, error) {
	out := make([]Grant, 0, len(gs))
	for _, g := range gs {
		p, err := checkedACLPath(g.Path)
		if err != nil {
			return nil, err
		}
		n := Grant{Path: p, Role: g.Role, Propagate: g.Propagate}
		if g.Privs != nil {
			n.Privs = append([]string{}, g.Privs...)
		}
		out = append(out, n)
	}
	if err := checkGrants(out); err != nil {
		return nil, err
	}
	return out, nil
}

// copyGrants returns a deep copy of gs (Privs included), so a Result never
// shares a slice with the run's own want.
func copyGrants(gs []Grant) []Grant {
	out := make([]Grant, len(gs))
	for i, g := range gs {
		out[i] = g
		if g.Privs != nil {
			out[i].Privs = append([]string{}, g.Privs...)
		}
	}
	return out
}

// The token owner's shape, as PVE's own PVE::Auth::Plugin::verify_username
// takes it: <name>@<realm>, split on "@".
//
// The NAME rule is a denial list, not an allowlist: PVE accepts [^\s:/]+
// there, so real userids carry "$" (an AD machine account) or "+", and
// refusing those would be pveforge's bug rather than PVE's. What must be
// refused is "!", the separator fullTokenID concatenates with: an owner
// holding one would build a token id the operator never asked for, and
// would make every held.ID comparison meaningless. Whitespace, ":" and "/"
// PVE itself refuses.
//
// Two deliberate, fail-closed deviations from PVE: PVE splits on the LAST
// "@", so it accepts "a@b@pve", and its name charset admits "!". Both are
// refused here.
var (
	tokenOwnerNameRE  = regexp.MustCompile(`^[^\s:/!@]+$`)
	tokenOwnerRealmRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.\-_]+$`)
)

// CheckTokenOwner reports whether owner is a PVE principal pveforge can own
// a token with. There is no @pam canonicalization: --pve-user is a Linux
// login whose realm is pam by construction, while an owner is any PVE
// principal, and guessing a realm would address a different user.
func CheckTokenOwner(owner string) error {
	name, realm, found := strings.Cut(owner, "@")
	if !found {
		return fmt.Errorf("%w: %q: an owner needs its realm, as name@realm", ErrInvalidTokenOwner, owner)
	}
	if !tokenOwnerNameRE.MatchString(name) {
		return fmt.Errorf("%w: %q: the user name is empty or holds a character PVE (or a token id) would not accept", ErrInvalidTokenOwner, owner)
	}
	if !tokenOwnerRealmRE.MatchString(realm) {
		return fmt.Errorf("%w: %q: the realm must start with a letter and be at least two characters", ErrInvalidTokenOwner, owner)
	}
	return nil
}

// heldTokenID returns the token id this target's roster entry holds, or ""
// when it holds none (including a target with no entry yet: a first
// bootstrap). It decrypts NOTHING — only the id is read, so an
// undecryptable secret still reaches its own path (ErrTokenUndecryptable),
// mirroring loadExistingSSHAuth's "decrypt only what you need".
func heldTokenID(opts Options) (string, error) {
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return "", fmt.Errorf("load roster %s: %w", opts.RosterPath, err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil || tg.Token == nil {
		return "", nil
	}
	return tg.Token.ID, nil
}

// heldSSHBlock reports whether this target's roster entry carries an
// [targets.ssh] block AT ALL — present with or without a fingerprint. It
// decrypts NOTHING, mirroring heldTokenID.
//
// This is deliberately a different question from loadExistingSSHAuth's,
// which answers "is there usable, pinned auth" and so returns nil for a
// block whose host_key_fingerprint is empty (bootstrap.go, its tg.SSH
// check) as well as for no block at all. A keypair on file is a credential
// whether or not it is pinned, so the keyless checks must not use that
// summary. tg == nil or tg.SSH == nil is false, so a first bootstrap never
// refuses.
func heldSSHBlock(opts Options) (bool, error) {
	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return false, fmt.Errorf("load roster %s: %w", opts.RosterPath, err)
	}
	tg := r.Find(opts.TargetID)
	if tg == nil || tg.SSH == nil {
		return false, nil
	}
	return true, nil
}

// checkKeylessState refuses a run whose SSH posture contradicts the
// roster's, before any SSH and without decrypting anything:
//
//   - --no-ssh-key against a target that holds an SSH block
//     (ErrKeylessWithPersistedSSH): the key would stay on file and on the
//     host while the flag says there is none;
//   - no --no-ssh-key against a target that holds a token and no block
//     (ErrKeylessTargetNeedsFlag): the state a keyless bootstrap leaves, so
//     the run would install and persist a key on a target kept keyless.
//
// The two are mutually exclusive (one needs the flag, the other its
// absence), and both run after checkHeldTokenOwner, so an overlapping run
// reports the identity error first. Each message carries its own remedy;
// they are mirror images, so the pairing is asserted as ordered substrings
// (TestRun_CT4…, TestRun_CT5…).
//
// pveforge-roster-token-import will legitimately produce "a token and no
// SSH block" for a target that was never keyless; such a target then needs
// --no-ssh-key, or its token block removed, to bootstrap. That task names
// the same interaction.
func checkKeylessState(opts Options) error {
	block, err := heldSSHBlock(opts)
	if err != nil {
		return err
	}
	if opts.NoSSHKey {
		if !block {
			return nil
		}
		return fmt.Errorf("%w: %s; remove that target's [targets.ssh] block by hand to keep it keyless (this revokes no token), or drop --no-ssh-key to keep using the stored key",
			ErrKeylessWithPersistedSSH, opts.TargetID)
	}
	if block {
		return nil
	}
	heldID, err := heldTokenID(opts)
	if err != nil || heldID == "" {
		return err
	}
	return fmt.Errorf("%w: %s holds the token %s and no SSH auth (it was bootstrapped keyless, or its token was imported); pass --no-ssh-key to keep this target keyless, or remove its [targets.token] block by hand to re-bootstrap it with an SSH key",
		ErrKeylessTargetNeedsFlag, opts.TargetID, heldID)
}

// checkHeldTokenOwner refuses an ACCIDENTAL change of principal: the roster
// holds a token owned by someone other than the owner this run defaulted
// to, and the caller named no owner. Nothing persists the owner (unlike
// host/node/port/TLS, which defaultHostNodeFromRoster restores), so without
// this a forgotten --token-owner would silently mint under a different
// principal, orphan the roster's token and re-point the roster at the new
// one.
//
// A caller that DID name an owner keeps the deliberate behaviour: the old
// token is orphaned, never revoked (tokenPhase's changed-id branch).
//
// It is not a verdict: it is in neither classification table, so it can
// never lead to a remove.
func checkHeldTokenOwner(opts Options, ownerGiven bool) error {
	if ownerGiven {
		return nil
	}
	heldID, err := heldTokenID(opts)
	if err != nil || heldID == "" {
		return err
	}
	heldOwner, heldName, found := strings.Cut(heldID, "!")
	if found && heldOwner == opts.TokenOwner {
		return nil
	}
	// A held id that names no owner — no "!" at all ("pveforge"), or an
	// empty owner part ("!pveforge") — cannot be proven to match, so it is
	// refused too. It has no principal to offer back: suggesting
	// "--token-owner <the whole id>", or an empty one, would only earn a
	// CheckTokenOwner refusal. Ask for one explicitly instead. (No roster
	// this code ever wrote looks so; a hand edit can.)
	if !found || heldOwner == "" {
		return fmt.Errorf("%w: the roster holds %q, which names no owner, so pveforge cannot tell whose token it is; this run would address %s: pass --token-owner explicitly, as name@realm, to say which principal holds this target's token",
			ErrTokenOwnerMismatch, heldID, opts.TokenOwner+"!"+opts.TokenID)
	}
	also := ""
	if heldName != opts.TokenID {
		also = fmt.Sprintf(" (the token name differs too: the roster holds %q, this run asks for %q)", heldName, opts.TokenID)
	}
	// The pairing is the whole remedy: the HELD owner keeps the token,
	// the DEFAULTED owner changes principal (and orphans it).
	return fmt.Errorf("%w: the roster holds %s, but this run would address %s%s; pass --token-owner %s to keep addressing that principal, or --token-owner %s to change it deliberately (which leaves %s live on PVE, held by nobody)",
		ErrTokenOwnerMismatch, heldID, opts.TokenOwner+"!"+opts.TokenID, also, heldOwner, opts.TokenOwner, heldID)
}

// grantHint is the syntax a refused or missing --grant points at.
const grantHint = "PATH:ROLE[:PRIVS[:PROPAGATE]]"

// ParseGrants parses the CLI's --grant specs, each PATH:ROLE[:PRIVS[:PROPAGATE]]:
// PRIVS a comma-separated privilege list (empty: unpinned, the role's live
// privileges), PROPAGATE exactly 0 or 1 (absent: 0). The result is
// normalized and checked like Run's own (normalizeGrants). No spec at all is
// refused with the syntax hint: bootstrap requires an explicit grant.
func ParseGrants(specs []string) ([]Grant, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("%w: bootstrap requires at least one --grant %s", ErrInvalidGrant, grantHint)
	}
	gs := make([]Grant, 0, len(specs))
	for _, s := range specs {
		g, err := parseGrant(s)
		if err != nil {
			return nil, err
		}
		gs = append(gs, g)
	}
	return normalizeGrants(gs)
}

// parseGrant splits one spec into a Grant, without normalizing or
// checking its path.
func parseGrant(spec string) (Grant, error) {
	f := strings.Split(spec, ":")
	if len(f) < 2 || len(f) > 4 {
		return Grant{}, fmt.Errorf("%w: --grant %q: want %s", ErrInvalidGrant, spec, grantHint)
	}
	if f[0] == "" || f[1] == "" {
		return Grant{}, fmt.Errorf("%w: --grant %q: PATH and ROLE are required (%s)", ErrInvalidGrant, spec, grantHint)
	}
	g := Grant{Path: f[0], Role: f[1]}
	if len(f) >= 3 && f[2] != "" {
		if f[2] == "0" || f[2] == "1" {
			return Grant{}, fmt.Errorf("%w: --grant %q: %s is not a privilege name; to set propagate, use PATH:ROLE::%s", ErrInvalidGrant, spec, f[2], f[2])
		}
		g.Privs = strings.Split(f[2], ",")
	}
	if len(f) == 4 {
		switch f[3] {
		case "0":
		case "1":
			g.Propagate = true
		default:
			return Grant{}, fmt.Errorf("%w: --grant %q: PROPAGATE must be 0 or 1", ErrInvalidGrant, spec)
		}
	}
	// The rest (the path's normalization and PVE's whitelist, the role id,
	// the privilege names) is checked after normalization, by
	// normalizeGrants, exactly as Run checks it.
	return g, nil
}

// grantACL grants g to the token identified by fullTokenID
// (userid!tokenname), stating the whole grant: path, role and an explicit
// --propagate 0|1 (pveum's default is 1). The exact `pveum acl modify` flag
// names are reproduced from PVE documentation (`pveum help acl modify`),
// like the token add/remove commands in rotation.go.
func grantACL(ctx context.Context, session SSHSession, fullTokenID string, g Grant) error {
	propagate := 0
	if g.Propagate {
		propagate = 1
	}
	cmd := fmt.Sprintf("pveum acl modify %s --tokens %s --roles %s --propagate %d",
		sshexec.ShellQuote(g.Path), sshexec.ShellQuote(fullTokenID), sshexec.ShellQuote(g.Role), propagate)
	res, err := session.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("run pveum acl modify: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("pveum acl modify exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}

// grantAll issues every grant of want, in order, stopping at the first
// failure.
func grantAll(ctx context.Context, session SSHSession, fullTokenID string, want []Grant) error {
	for _, g := range want {
		if err := grantACL(ctx, session, fullTokenID, g); err != nil {
			return err
		}
	}
	return nil
}

// secretRedacted replaces a secret in redactedError's text.
const secretRedacted = "<redacted>"

// redactedError is err with every occurrence of a secret removed from its
// text. It unwraps to err, so errors.Is and errors.As see the cause
// unchanged. Only the raw secret is replaced: a transformed copy of it
// (URL-, base64- or JSON-escaped) is not recognised.
type redactedError struct {
	err    error
	secret string
}

func (e redactedError) Error() string {
	return strings.ReplaceAll(e.err.Error(), e.secret, secretRedacted)
}
func (e redactedError) Unwrap() error { return e.err }

// redactSecret wraps err so its text never shows secret; an empty secret
// leaves err as it is.
func redactSecret(err error, secret string) error {
	if secret == "" {
		return err
	}
	return redactedError{err: err, secret: secret}
}

// ErrTokenAlreadyHeld: Import was asked to import a token into a target
// whose roster entry already holds a different one, without Replace. Not a
// verdict about anything; nothing was written.
var ErrTokenAlreadyHeld = errors.New("the target already holds a different token")

// ErrInvalidImportTokenID: Import's token id is not "<owner>!<name>" with an
// owner CheckTokenOwner accepts and a PVE token name.
var ErrInvalidImportTokenID = errors.New("invalid token id")

// ErrInvalidTokenSecret: the imported secret is empty, too long, or holds
// whitespace or a control character. Its text never includes the secret.
var ErrInvalidTokenSecret = errors.New("invalid token secret")

// tokenNameRE is PVE's token-name format (pve-tokenid's name part).
var tokenNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.\-_]+$`)

// MaxImportedSecretLen bounds an imported secret. A PVE token secret is a
// UUID (36 bytes); anything near this bound is not one.
const MaxImportedSecretLen = 4096

// CheckImportTokenID reports whether id is a full token id Import accepts.
func CheckImportTokenID(id string) error {
	owner, name, found := strings.Cut(id, "!")
	if !found {
		return fmt.Errorf("%w: %s: want <user>@<realm>!<token name>", ErrInvalidImportTokenID, kvjson.QuoteValue(id))
	}
	if err := CheckTokenOwner(owner); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidImportTokenID, err)
	}
	if !tokenNameRE.MatchString(name) {
		return fmt.Errorf("%w: %s: the token name must start with a letter and hold only letters, digits and . - _", ErrInvalidImportTokenID, kvjson.QuoteValue(name))
	}
	return nil
}

// CheckTokenSecret reports whether secret can be a token secret: non-empty,
// at most MaxImportedSecretLen bytes, and free of whitespace and control
// characters. The error never includes the secret.
func CheckTokenSecret(secret string) error {
	switch {
	case secret == "":
		return fmt.Errorf("%w: it is empty", ErrInvalidTokenSecret)
	case len(secret) > MaxImportedSecretLen:
		return fmt.Errorf("%w: it is longer than %d bytes", ErrInvalidTokenSecret, MaxImportedSecretLen)
	case strings.ContainsFunc(secret, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		return fmt.Errorf("%w: it holds whitespace or a control character", ErrInvalidTokenSecret)
	}
	return nil
}

// ImportOptions configures one Import.
type ImportOptions struct {
	TargetID    string
	Host        string // defaulted from an existing roster target
	Node        string // defaulted from an existing roster target
	APIPort     int
	InsecureTLS bool
	// TokenID is the full "<user>@<realm>!<name>" of the token minted
	// outside pveforge.
	TokenID string
	// Secret is the token's secret, read by the caller from non-terminal
	// stdin — never argv or the environment.
	Secret string
	// Grants is what the token must hold, exactly (ValidateTokenGrants).
	Grants []Grant
	// Replace lets Import overwrite a DIFFERENT token the roster holds for
	// the target. The old token is never revoked: it is reported as
	// orphaned (still live on PVE, held by no roster).
	Replace    bool
	RosterPath string
	Passphrase roster.Passphrase
}

// Import puts a token minted outside pveforge into the roster, but only
// once PVE proves it holds exactly Grants — the same effective-permissions
// validation bootstrap runs, with bootstrap's bounded retry for a freshly
// minted token's propagation lag.
//
// An import creates nothing on PVE and so NEVER removes or revokes
// anything, whatever the validation says: a verdict and a non-verdict alike
// only mean the token is not written. It needs no SSH and no password: it
// holds no transport at all, so bootstrap's remove path is out of its
// reach. Its checks run as the token alone, so an ErrWrongScope may be the
// token owner's own limit showing through (pve.ValidateTokenGrants, limit
// 4); nothing is removed, so that is safe to report as it is.
//
// It holds bootstrap's per-target token lock for the whole run, so an
// import and a bootstrap of the same target never interleave.
func Import(ctx context.Context, opts ImportOptions, api APIValidator) (_ *Result, err error) {
	// No error Import returns may carry the secret. PVE's (or a proxy's)
	// error body can echo the request — "Authorization: PVEAPIToken=
	// <id>=<secret>" — and runRoot prints the error. Redacted here, once,
	// for every return path; errors.Is still reaches the cause.
	defer func() {
		if err != nil {
			err = redactSecret(err, opts.Secret)
		}
	}()
	if err := roster.ValidateTargetID(opts.TargetID); err != nil {
		return nil, fmt.Errorf("import token: %w", err)
	}
	if err := CheckImportTokenID(opts.TokenID); err != nil {
		return nil, fmt.Errorf("import token %s: %w", opts.TargetID, err)
	}
	if err := CheckTokenSecret(opts.Secret); err != nil {
		return nil, fmt.Errorf("import token %s: %w", opts.TargetID, err)
	}
	want, err := normalizeGrants(opts.Grants)
	if err != nil {
		return nil, fmt.Errorf("import token %s: %w", opts.TargetID, err)
	}
	bopts := Options{
		TargetID: opts.TargetID, Host: opts.Host, Node: opts.Node, APIPort: opts.APIPort,
		InsecureTLS: opts.InsecureTLS, RosterPath: opts.RosterPath, Passphrase: opts.Passphrase,
	}
	defaultHostNodeFromRoster(&bopts)
	if bopts.Host == "" || bopts.Node == "" {
		return nil, fmt.Errorf("import token %s: --host and --node are required for a target the roster does not have yet", opts.TargetID)
	}
	if bopts.APIPort == 0 {
		bopts.APIPort = 8006
	}

	unlock, err := lock.Mutation(ctx, opts.RosterPath, lock.ObjectKey{TargetID: opts.TargetID, Kind: "bootstrap", ID: "token"})
	if err != nil {
		return nil, fmt.Errorf("import token %s: acquire the per-target bootstrap lock: %w", opts.TargetID, err)
	}
	defer func() { _ = unlock() }()

	r, err := roster.Load(opts.RosterPath)
	if err != nil {
		return nil, fmt.Errorf("import token %s: load roster %s (create it first with `pveforge roster init`): %w", opts.TargetID, opts.RosterPath, err)
	}
	exists := r.Find(opts.TargetID) != nil
	var held heldToken
	if exists {
		if held, err = loadHeldToken(bopts); err != nil {
			return nil, fmt.Errorf("import token %s: %w", opts.TargetID, err)
		}
		// A held token that will not decrypt is refused outright, --replace
		// included and before anything is validated: with a mistyped
		// passphrase, "replace" would overwrite the only roster copy of a
		// live token's secret. Bootstrap refuses the same state the same way.
		if held.DecryptErr != nil {
			return nil, fmt.Errorf("import token %s: %w: the roster holds %s; check the roster passphrase (%s) — nothing was validated or written, and --replace cannot override this", opts.TargetID, ErrTokenUndecryptable, kvjson.QuoteValue(held.ID), roster.PassphraseEnvVar)
		}
		if err := dryRunTokenWrite(opts.RosterPath, opts.TargetID); err != nil {
			return nil, fmt.Errorf("import token %s: the roster would refuse the write, so nothing was validated or written: %w", opts.TargetID, err)
		}
	}
	// The passphrase must open what the roster already holds, or the token
	// would be sealed under a key the rest of the roster cannot share.
	// Before the validator's network call; free when the command proved it
	// already, or when the held token above just decrypted under it.
	if err := opts.Passphrase.Prove(opts.RosterPath, opts.TargetID); err != nil {
		return nil, fmt.Errorf("import token %s: %w", opts.TargetID, err)
	}
	sameToken := held.ID == opts.TokenID && held.DecryptErr == nil && held.Secret == opts.Secret
	if held.ID != "" && !sameToken && !opts.Replace {
		return nil, fmt.Errorf("import token %s: %w: %s; pass --replace to replace the roster's copy (the held token is not revoked, and stays live on PVE)", opts.TargetID, ErrTokenAlreadyHeld, kvjson.QuoteValue(held.ID))
	}

	res := &Result{TokenID: opts.TokenID, TokenOutcome: OutcomeNotImported}
	run := &runner{ctx: ctx, opts: bopts, api: api, fullID: opts.TokenID, want: want, res: res}
	verdict, nonVerdict := run.validatePostMint(opts.Secret)
	switch {
	case verdict != nil:
		res.Validation = ValidationFailed
		return res, fmt.Errorf("import token %s: the token does not hold exactly the requested grants, so it was not imported (nothing on PVE was touched; if the owner is not root, its own privileges bound the token's): %w", opts.TargetID, verdict)
	case nonVerdict != nil:
		res.Validation = ValidationUnverified
		return res, fmt.Errorf("import token %s: the token's grants could not be verified, so it was not imported (nothing on PVE was touched): %w", opts.TargetID, nonVerdict)
	}
	res.Validation = ValidationVerified
	res.Grants = want

	if sameToken {
		res.TokenOutcome = OutcomeAlreadyHeld
		return res, nil
	}
	if !exists {
		if err := ensureTargetExists(bopts); err != nil {
			return res, fmt.Errorf("import token %s: add the target to the roster: %w", opts.TargetID, err)
		}
	}
	if err := writeTokenAuthFn(opts.RosterPath, opts.TargetID, roster.TokenWrite{TokenID: opts.TokenID, SecretPlaintext: []byte(opts.Secret)}, opts.Passphrase); err != nil {
		return res, fmt.Errorf("import token %s: write the token to the roster: %w", opts.TargetID, err)
	}
	// The write's proof serves this read only if the file holds exactly the
	// bytes it sealed (a proof is keyed on the armored text); anything else
	// on disk is really decrypted.
	back, err := loadHeldToken(bopts)
	if err != nil || back.ID != opts.TokenID || back.DecryptErr != nil || back.Secret != opts.Secret {
		return res, fmt.Errorf("import token %s: the roster did not read back the token just written (check it with pveforge roster validate)", opts.TargetID)
	}
	res.TokenOutcome = OutcomeImported
	if held.ID != "" && held.ID != opts.TokenID {
		res.OrphanedToken = held.ID
	}
	return res, nil
}
