// Package bootstrap implements pveforge's "nothing exists yet" -> "fully
// token-authenticated roster entry" flow (PRD §3.2), plus the token
// creation/ACL-grant validation this task's own research findings flagged
// as a silent-failure risk if skipped.
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
	"fmt"
	"sort"
	"strings"

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
// a freshly created token actually has working grants. NewAPIValidator
// (deps.go) provides the production implementation, backed by internal/pve.
type APIValidator interface {
	ValidateTokenGrants(ctx context.Context, cfg APIConfig, expectNode string) error
}

// Options configures one bootstrap run against a single target.
type Options struct {
	TargetID    string
	Host        string
	Node        string
	APIPort     int
	InsecureTLS bool
	SSHPort     int // 0 => 22

	// PVEUsername is a PAM/realm username, e.g. "root@pam". Only @pam (or
	// bare, defaulting to pam) realm users are supported — anything else
	// has no corresponding SSH-reachable Linux system account.
	PVEUsername string
	PVEPassword string

	// TokenID is the token's own name (not including the userid prefix),
	// e.g. "pveforge" -> full token id "root@pam!pveforge".
	TokenID string
	// ACLPath and ACLRole scope the freshly created token's grant.
	// Defaults: "/" and "PVEVMAdmin" (see applyDefaults).
	ACLPath string
	ACLRole string

	RosterPath string
	Passphrase string
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
// token (and grant its ACL) over that connection via pveum, validate the
// token's grants actually work, then persist the token to the roster.
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
	applyDefaults(&opts)
	defaultHostNodeFromRoster(&opts)
	if err := validateOptions(&opts); err != nil {
		return nil, err
	}
	aclPath, err := checkedACLPath(opts.ACLPath)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}
	opts.ACLPath = aclPath
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

	addr := fmt.Sprintf("%s:%d", opts.Host, opts.SSHPort)
	fullTokenID := opts.PVEUsername + "!" + opts.TokenID

	existing, err := loadExistingSSHAuth(opts)
	if err != nil {
		return nil, fmt.Errorf("bootstrap %s: %w", opts.TargetID, err)
	}

	r := &runner{ctx: ctx, opts: opts, transport: transport, api: api, fullID: fullTokenID}

	if existing != nil {
		session, err := transport.ReconnectWithPinnedKey(ctx, addr, sshUser, existing.PrivateKeyPEM, existing.HostKeyFingerprint)
		if err != nil {
			return nil, fmt.Errorf("bootstrap %s: reconnect with previously-pinned ssh key: %w — this needs deliberate operator reconciliation; pveforge will not silently re-trust and re-pin a different host key", opts.TargetID, err)
		}
		r.session = session
		defer func() { _ = r.session.Close() }()
		r.ident = sshIdentity{addr: addr, user: sshUser, privateKeyPEM: existing.PrivateKeyPEM, hostKeyFP: existing.HostKeyFingerprint}
	} else {
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

	present, err := preflight(ctx, r.session, opts)
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
	if opts.ACLPath == "" {
		opts.ACLPath = "/"
	}
	if opts.ACLRole == "" {
		opts.ACLRole = "PVEVMAdmin"
	}
	if opts.PVEUsername == "" {
		opts.PVEUsername = "root@pam"
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
	case opts.Passphrase == "":
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
		return pveUsername, nil
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
// Deliberately decrypts ONLY tg.SSH.PrivateKeyEnc via roster.DecryptString
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
	privateKeyPEM, err := roster.DecryptString(tg.SSH.PrivateKeyEnc, opts.Passphrase)
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

// grantACL grants role at path to the token identified by fullTokenID
// (userid!tokenname). The exact `pveum acl modify` flag names are reproduced
// from PVE documentation, like the token add/remove commands in rotation.go.
func grantACL(ctx context.Context, session SSHSession, fullTokenID, path, role string) error {
	cmd := fmt.Sprintf("pveum acl modify %s --tokens %s --roles %s",
		sshexec.ShellQuote(path), sshexec.ShellQuote(fullTokenID), sshexec.ShellQuote(role))
	res, err := session.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("run pveum acl modify: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("pveum acl modify exited %d: %s", res.ExitCode, res.Stderr)
	}
	return nil
}
