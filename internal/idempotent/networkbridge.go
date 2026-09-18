package idempotent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// rawNetworkClient is the minimal shape the free functions below need —
// just the raw REST passthrough, parameterized explicitly by (client, node)
// rather than a receiver, so networkfields.go's NetworkFieldsEnsure can
// call the identical stage/commit/revert/fetch primitives NetworkBridgeEnsure
// uses without duplicating their bodies. Both NetworkBridgeClient and
// NetworkFieldsClient satisfy this structurally.
type rawNetworkClient interface {
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
}

// NetworkBridgeClient is the subset of *pve.RoutedClient NetworkBridgeEnsure
// needs: the raw REST passthrough (PVE's network-config API has no
// go-proxmox-typed stage/commit split — see NetworkBridgeEnsure's own doc
// comment on why raw calls are load-bearing here, not a shortcut), the
// kernel-level link-state primitive (internal/sshexec.LinkState, Phase 1 of
// this task), task polling, and the node this client is scoped to.
// *pve.RoutedClient satisfies this interface structurally (see
// compat_test.go) — defined here, not as the concrete type, for the same
// reason as this package's other Client-shaped interfaces (vmtag.go,
// bridgeisolation.go): a lightweight in-package fake instead of pve's
// network/SSH test harness.
type NetworkBridgeClient interface {
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// RawRequest issues a raw PVE REST call — see pve.RoutedClient.RawRequest's
	// own doc comment. NetworkBridgeEnsure uses this exclusively for every
	// network-config read/write in this file; see this file's own doc
	// comment on why the go-proxmox typed network methods must never be
	// substituted in.
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	// LinkState reports one network interface's live kernel link state —
	// see sshexec.Client.LinkState's own doc comment. Used both as the
	// independent, PVE-REST-orthogonal half of this Op's guard mechanism
	// (Apply's step 4) and for the mandatory post-apply verification
	// (Apply's steps 7-8).
	LinkState(ctx context.Context, iface string) (sshexec.LinkState, error)
	// WaitForTask polls a PVE task (identified by the UPID a mutating call
	// returned) to completion — see pve.Client.WaitForTask's own doc
	// comment. NetworkBridgeEnsure.Apply's step 6b MUST call this and let
	// it complete before ever inspecting post-apply state.
	WaitForTask(ctx context.Context, node, upid string) error
}

// networkInterfaceMissingSubstring is the text this project EXPECTS a
// RawRequest error to contain when the target PVE network interface doesn't
// exist (matched case-insensitively against the error's full formatted
// text, which for a *pve.RoutedClient ultimately comes from
// Client.RawRequest's "raw request: pve returned %s: %s" wrapping of PVE's
// own HTTP status/body — see internal/pve/rawrequest.go). Chosen by analogy
// with this project's OWN established convention for exactly this class of
// "does this thing exist" question: sshexec.LinkState's
// linkDoesNotExistSubstring uses the identical phrase for iproute2's `ip`
// command, and TapLinkState's own tapDoesNotExistSubstring follows the same
// pattern. PVE's actual HTTP status/error body for a GET against an unknown
// node network interface is NOT independently verified against a live host
// in this implementation session (same empirical-verification-gap
// discipline flagged throughout this project — see sshexec.LinkState,
// sshexec.RootOnlyFields, the digest-conflict error text). If a live host's
// exact wording differs, fetchInterface falls back to treating the
// RawRequest failure as a hard Read/Apply error instead of "does not
// exist" — a safe failure mode: it can only ever narrow down a case this
// function would otherwise misreport as "exists", it never masks a real
// problem as benign.
const networkInterfaceMissingSubstring = "does not exist"

func isMissingNetworkInterfaceError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), networkInterfaceMissingSubstring)
}

// NetworkBridgeEnsure is idempotent.Op for creating or destroying one PVE
// node-level network interface (typically a bridge) via PVE's own
// stage/commit network-config model — POST or DELETE
// /nodes/{node}/network[/{iface}] stages a pending change, and a SEPARATE
// PUT /nodes/{node}/network commits every staged change on the node at
// once and triggers ifupdown2's live reload.
//
// # Apply must NEVER call go-proxmox's typed Node.NewNetwork or
// # NodeNetwork.Delete (nodes_network.go) as a "simpler" alternative
//
// This is the single most important constraint in this file, stated
// explicitly and by name because nothing about a normal code review or a
// naive test would catch a regression here: go-proxmox's own
// Node.NewNetwork and NodeNetwork.Delete (see
// github.com/suykerbuyk/go-proxmox's nodes_network.go) each AUTO-COMMIT
// internally — every one of them calls n.NetworkReload(ctx) (PVE's own
// PUT /nodes/{node}/network) itself, immediately after its own POST/DELETE,
// with no way to opt out. Reaching for either of those "obviously simpler,
// already-typed" helpers instead of the raw stage/commit calls this Apply
// performs by hand would silently collapse the ENTIRE stage -> guard ->
// commit gap this Op exists to create down to a single, uninspectable,
// un-guarded write — with NO compiler error (both satisfy nothing this
// package's interfaces check for; the swap type-checks fine) and NO
// obviously broken test (a fake client that doesn't itself model the
// auto-reload behavior would happily let such a change pass every existing
// assertion). Every one of this file's safety properties — the pre/post
// stanza-hash comparison, the two-signal guard self-check, the mandatory
// task-poll before any post-apply inspection, the mandatory kernel
// verification — depends entirely on commit being a SEPARATE, own-chosen
// step that this code controls. This is a load-bearing regression guard,
// not a nicety: do not "simplify" Apply by routing it through either of
// those two go-proxmox methods, ever, for any reason.
type NetworkBridgeEnsure struct {
	Client NetworkBridgeClient
	Node   string
	// Iface is the target bridge to create or destroy.
	Iface string
	// ManagementBridge is the node's own management bridge (e.g. "vmbr0")
	// — the interface this Op reads before and after staging Iface's
	// change, purely as a canary: if ANYTHING about ManagementBridge's own
	// pending config changed during the stage window (something else
	// concurrently staged a change on this node — PVE's staged changes are
	// node-wide, not per-interface), committing now would also commit that
	// unrelated change, so Apply refuses and reverts instead. Required,
	// with NO default: guessing wrong here (e.g. defaulting to "vmbr0" on
	// a node where that isn't the management bridge) would silently
	// disable this entire safety mechanism by watching an interface that
	// isn't reliably present/stable, which is worse than no guard at all
	// disguised as one. This is a deliberate safety property, not an
	// oversight — do not add a default.
	ManagementBridge string
	// Wanted is the field=value pairs to ensure on Iface for a CREATE.
	// nil or empty means "destroy Iface" instead.
	Wanted map[string]string

	// currentFields, preStanzaHash, and preKernelState are populated by
	// Apply's own step 1 (the pre-stage snapshot of ManagementBridge) and
	// consumed by Apply's later steps (5, 7) within that SAME Apply call —
	// refreshed at the very start of every Apply invocation. Unlike
	// VMFieldsEnsure/BridgeIsolationEnsure's analogous fields, these are
	// NOT populated by this Op's own Read method: Read (see below) reports
	// on Iface itself, for idempotent.Run's Satisfied check, which is an
	// entirely different question from "has ManagementBridge's own pending
	// config changed since I started staging" — the guard mechanism these
	// three fields serve has no reason to run before Apply actually
	// intends to mutate something.
	currentFields  map[string]json.RawMessage
	preStanzaHash  string
	preKernelState sshexec.LinkState
}

// Validate reports whether op is well-formed. Node, Iface, and
// ManagementBridge are all required — see ManagementBridge's own doc
// comment on why there is deliberately no default for it. Also rejects
// Wanted containing an "iface" key: Apply itself sets "iface" from op.Iface
// when staging a create (see stage), so a caller-supplied "iface" entry in
// Wanted would be silently overwritten by op.Iface anyway — better to
// refuse the ambiguity outright than let a caller believe their own
// "iface" value took effect.
func (op *NetworkBridgeEnsure) Validate() error {
	if op.Node == "" {
		return fmt.Errorf("network bridge ensure: node is required")
	}
	if op.Iface == "" {
		return fmt.Errorf("network bridge ensure: iface is required")
	}
	if op.ManagementBridge == "" {
		return fmt.Errorf("network bridge ensure: management bridge is required (no default is provided — see NetworkBridgeEnsure.ManagementBridge's own doc comment)")
	}
	if _, ok := op.Wanted["iface"]; ok {
		return fmt.Errorf("network bridge ensure: iface %s: Wanted must not itself contain an \"iface\" key; Apply always sets it from Iface", op.Iface)
	}
	return nil
}

// Read fetches Iface's own current raw config — GET
// /nodes/{node}/network/{iface} — DISTINCT from ManagementBridge, which
// Apply's guard mechanism reads for an entirely different purpose (see
// NetworkBridgeEnsure's own doc comment on currentFields). If Iface
// currently doesn't exist, Read represents that as the empty string "" —
// see isMissingNetworkInterfaceError's own doc comment for exactly how
// "doesn't exist" is detected from a RawRequest error, since PVE's precise
// error shape here is unverified against a live host. If Iface exists,
// Read canonicalizes its fields (sorted keys, via encoding/json's own
// deterministic map-marshal ordering) into a JSON string for comparison —
// this is deliberately the SAME canonicalization approach canonicalHash
// uses below, just returned directly as a string instead of hashed: unlike
// canonicalHash's ManagementBridge stanza (which excludes "digest"
// specifically to avoid false-positive guard trips from unrelated
// whole-node digest churn), there is no such exclusion here, since Read's
// result is never hash-compared against itself — Satisfied only ever
// inspects the specific keys named in Wanted.
func (op *NetworkBridgeEnsure) Read(ctx context.Context) (string, error) {
	fields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.Iface)
	if err != nil {
		return "", fmt.Errorf("network bridge ensure: read %s: %w", op.Iface, err)
	}
	if !exists {
		return "", nil
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("network bridge ensure: read %s: encode: %w", op.Iface, err)
	}
	return string(b), nil
}

// Satisfied implements the semantics approved for this Op (distinct from,
// and more specific than, anything written elsewhere for this task): for a
// CREATE (Wanted non-empty), satisfied only if Iface currently exists AND
// every key in Wanted already matches its current value — a subset match,
// since PVE returns many more fields than any caller sets (same reasoning
// as VMFieldsEnsure.Satisfied's two-value-map handling of "absent" vs.
// "present and empty": a key ABSENT from current can never be considered
// already matching, even against a wanted value that happens to be the
// empty string). For a DESTROY (Wanted nil/empty), satisfied only if Iface
// currently does NOT exist.
func (op *NetworkBridgeEnsure) Satisfied(current string) bool {
	exists := current != ""

	if len(op.Wanted) == 0 {
		return !exists
	}
	if !exists {
		return false
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(current), &fields); err != nil {
		// Corrupted input reads as unsatisfied (safe to fail toward
		// re-Apply) — Satisfied has no error return to report this any
		// other way, matching parseBridgeIsolationState's own contract.
		return false
	}
	for field, wanted := range op.Wanted {
		raw, ok := fields[field]
		if !ok {
			return false
		}
		got, err := kvjson.Scalar(raw)
		if err != nil || got != wanted {
			return false
		}
	}
	return true
}

// Apply performs the full stage -> guard -> commit -> poll -> verify
// sequence — see this Op's own doc comment for why every one of these
// steps must go through raw REST calls, never go-proxmox's typed
// Node.NewNetwork/NodeNetwork.Delete. This Op has NO compare-and-swap/
// digest mechanism available (PVE network interfaces have no Digest field
// — verified project fact): Apply never returns an error wrapping
// ErrConflict, since there is nothing for idempotent.Run to usefully retry
// here — every failure path below is terminal.
func (op *NetworkBridgeEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	// --- Step 1: pre-stage snapshot of ManagementBridge -----------------
	fields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.ManagementBridge)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: pre-stage snapshot of management bridge %s: %w", op.Iface, op.ManagementBridge, err)
	}
	if !exists {
		return fmt.Errorf("network bridge ensure: %s: management bridge %s does not exist", op.Iface, op.ManagementBridge)
	}
	op.currentFields = fields
	op.preStanzaHash, err = canonicalHash(fields)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: %w", op.Iface, err)
	}
	op.preKernelState, err = op.Client.LinkState(ctx, op.ManagementBridge)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: pre-stage kernel snapshot of management bridge %s: %w", op.Iface, op.ManagementBridge, err)
	}

	// --- Step 2: stage -----------------------------------------------
	if err := op.stage(ctx); err != nil {
		return fmt.Errorf("network bridge ensure: %s: stage: %w", op.Iface, err)
	}

	// --- Step 3: post-stage, pre-commit snapshot of ManagementBridge ---
	pendingFields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.ManagementBridge)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: post-stage snapshot of management bridge %s: %w", op.Iface, op.ManagementBridge, err)
	}
	if !exists {
		return fmt.Errorf("network bridge ensure: %s: management bridge %s vanished immediately after staging", op.Iface, op.ManagementBridge)
	}
	pendingStanzaHash, err := canonicalHash(pendingFields)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: %w", op.Iface, err)
	}

	// --- Step 4: guard self-check (critical — never omit or weaken) ---
	// Must run, and must be allowed to abort, BEFORE step 5's compare ever
	// runs: a pre/pending ManagementBridge hash match is not by itself
	// sufficient proof that nothing has happened yet — see this method's
	// own guardSelfCheck for the two independent signals checked here.
	if err := op.guardSelfCheck(ctx); err != nil {
		return err
	}

	// --- Step 5: compare -------------------------------------------
	// NO --force bypass exists for this check, on purpose: unlike a
	// digest-CAS conflict (which a caller might reasonably want to force
	// past, accepting the risk), a stanza mismatch here means PVE staged
	// changes on this node that this Op never asked for and knows nothing
	// about — there is no safe way to "force" past that. A future edit
	// must NOT wire --force (or any other bypass) through to skip this.
	if pendingStanzaHash != op.preStanzaHash {
		diff := diffFields(op.currentFields, pendingFields)
		return op.abortAndRevert(ctx, fmt.Sprintf("management bridge %s's staged config changed during the stage window (refusing to commit an unrelated staged change): %s", op.ManagementBridge, diff))
	}

	// --- Step 6: commit ----------------------------------------------
	upid, err := op.commit(ctx)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: commit: %w", op.Iface, err)
	}

	// --- Step 6b: poll to completion (critical, not optional) ---------
	// Must complete — success or a translated failure — before step 7
	// ever runs. A failure here is terminal: PVE's own apply already ran
	// against interfaces.new by the time a task can report success or
	// failure, so there is nothing "pending" left to revert.
	if err := op.Client.WaitForTask(ctx, op.Node, upid); err != nil {
		return fmt.Errorf("network bridge ensure: %s: commit task %s did not complete successfully (no revert attempted: pve may already have applied this change, in whole or in part): %w", op.Iface, upid, err)
	}

	// --- Step 7: mandatory post-apply kernel verification, management
	// bridge FIRST. A mismatch here can't be prevented, only detected —
	// no automatic remediation is attempted.
	postKernel, err := op.Client.LinkState(ctx, op.ManagementBridge)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: post-apply kernel check of management bridge %s: %w", op.Iface, op.ManagementBridge, err)
	}
	if postKernel.Exists != op.preKernelState.Exists || postKernel.Up != op.preKernelState.Up {
		return fmt.Errorf("network bridge ensure: %s: management bridge %s's kernel link state changed unexpectedly during apply (before: exists=%v up=%v; after: exists=%v up=%v) — pve has already committed and reconfigured the kernel; no automatic remediation attempted",
			op.Iface, op.ManagementBridge, op.preKernelState.Exists, op.preKernelState.Up, postKernel.Exists, postKernel.Up)
	}

	// --- Step 8: only after step 7 passes, check Iface's own new kernel
	// state matches what create/destroy intended.
	ifaceLink, err := op.Client.LinkState(ctx, op.Iface)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: post-apply kernel check: %w", op.Iface, err)
	}
	wantExists := len(op.Wanted) > 0
	if ifaceLink.Exists != wantExists {
		return fmt.Errorf("network bridge ensure: %s: post-apply kernel state mismatch: expected exists=%v, kernel reports exists=%v", op.Iface, wantExists, ifaceLink.Exists)
	}

	return nil
}

// guardSelfCheck is Apply's step 4: re-reads Iface itself (never
// ManagementBridge) via two signals independent of one another —
// (a) PVE-native: the "active" field on a fresh GET of Iface's own config,
// and (b) kernel-native: op.Client.LinkState(ctx, op.Iface), which never
// goes through PVE's REST layer at all. For a CREATE, both signals must
// show Iface NOT yet live (active falsy AND LinkState.Exists false). For a
// DESTROY, both signals must show Iface STILL live (active truthy AND
// LinkState.Exists true). If either signal already shows the POST-COMMIT
// state before commit was ever called, this is the fail-closed case: abort
// exactly as step 5 does (same revert call, same never-fall-through
// behavior) and return a hard error naming exactly which signal
// contradicted two-phase semantics.
func (op *NetworkBridgeEnsure) guardSelfCheck(ctx context.Context) error {
	fields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.Iface)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: guard self-check: read iface state: %w", op.Iface, err)
	}
	active := false
	if exists {
		if raw, ok := fields["active"]; ok {
			s, err := kvjson.Scalar(raw)
			if err != nil {
				return fmt.Errorf("network bridge ensure: %s: guard self-check: parse active flag: %w", op.Iface, err)
			}
			active = activeTruthy(s)
		}
	}

	link, err := op.Client.LinkState(ctx, op.Iface)
	if err != nil {
		return fmt.Errorf("network bridge ensure: %s: guard self-check: read kernel link state: %w", op.Iface, err)
	}

	creating := len(op.Wanted) > 0
	if creating {
		if active {
			return op.abortAndRevert(ctx, fmt.Sprintf("guard self-check failed: op.Iface %s already reports active=true immediately after staging, before commit", op.Iface))
		}
		if link.Exists {
			return op.abortAndRevert(ctx, fmt.Sprintf("guard self-check failed: op.Iface %s's LinkState already shows Exists=true immediately after staging, before commit", op.Iface))
		}
		return nil
	}

	// destroy
	if !active {
		return op.abortAndRevert(ctx, fmt.Sprintf("guard self-check failed: op.Iface %s already reports active=false immediately after staging, before commit", op.Iface))
	}
	if !link.Exists {
		return op.abortAndRevert(ctx, fmt.Sprintf("guard self-check failed: op.Iface %s's LinkState already shows Exists=false immediately after staging, before commit", op.Iface))
	}
	return nil
}

// activeTruthy extracts a PVE "active" field's kvjson.Scalar-rendered
// string into a bool. PVE's active value may come back as a JSON string,
// number, or bool depending on version (go-proxmox's own
// NodeNetwork.Active field is typed StringOrInt for exactly this reason);
// treated as truthy unless the extracted string is empty, "0", "false", or
// "null" (case-insensitive).
func activeTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "null":
		return false
	default:
		return true
	}
}

// stage is Apply's step 2: for a create, POST /nodes/{node}/network with
// Wanted's fields plus iface=Iface; for a destroy, DELETE
// /nodes/{node}/network/{Iface}. Targets ONLY Iface — never
// ManagementBridge.
func (op *NetworkBridgeEnsure) stage(ctx context.Context) error {
	if len(op.Wanted) > 0 {
		params := url.Values{}
		for field, value := range op.Wanted {
			params.Set(field, value)
		}
		params.Set("iface", op.Iface)
		path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(op.Node))
		_, err := op.Client.RawRequest(ctx, http.MethodPost, path, params)
		return err
	}

	path := fmt.Sprintf("/nodes/%s/network/%s", url.PathEscape(op.Node), url.PathEscape(op.Iface))
	_, err := op.Client.RawRequest(ctx, http.MethodDelete, path, nil)
	return err
}

// commitNetworkStage is Apply's step 6: PUT /nodes/{node}/network with no
// params, committing every staged change on the node at once. Returns the
// UPID PVE reports for the resulting task — typically a bare JSON string,
// unwrapped via kvjson.Scalar (which already handles both a quoted JSON
// string and a bare/unquoted response body, the same coercion
// VMFieldsEnsure's Read relies on for other raw PVE fields).
//
// Free function (see rawNetworkClient's own doc comment) so
// NetworkFieldsEnsure's Apply can commit through the identical call.
func commitNetworkStage(ctx context.Context, client rawNetworkClient, node string) (string, error) {
	path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(node))
	raw, err := client.RawRequest(ctx, http.MethodPut, path, nil)
	if err != nil {
		return "", err
	}
	upid, err := kvjson.Scalar(raw)
	if err != nil {
		return "", fmt.Errorf("parse commit upid: %w", err)
	}
	if upid == "" || upid == "null" {
		return "", fmt.Errorf("commit returned no upid")
	}
	return upid, nil
}

func (op *NetworkBridgeEnsure) commit(ctx context.Context) (string, error) {
	return commitNetworkStage(ctx, op.Client, op.Node)
}

// revertNetworkStage issues PVE's whole-node "discard every staged change"
// call — DELETE /nodes/{node}/network, with NO iface — and returns a hard
// error combining reason with the revert's own outcome. Used by both step
// 4's guard self-check and step 5's stanza-mismatch compare, which share
// identical "never fall through to commit" semantics.
//
// This specific DELETE-with-no-iface call has NO go-proxmox library
// precedent (go-proxmox only exposes a per-interface NodeNetwork.Delete,
// which targets exactly one iface and auto-commits via NetworkReload — see
// this Op's own doc comment on why that method must never be used here
// anyway) and is UNTESTED against a live PVE host in this implementation
// session, the same empirical-verification-gap discipline flagged
// elsewhere in this project.
//
// Free function (see rawNetworkClient's own doc comment) so
// NetworkFieldsEnsure's Apply can revert through the identical call —
// deliberately the SAME whole-node discard, not a scoped one: PVE's
// staging area is node-wide by design, there is no per-interface discard
// primitive, and in the concurrent-human-webUI case the only alternative
// would be committing someone else's unreviewed staged change, which is
// strictly worse. 3b inherits this unchanged from reviewed 3a.
func revertNetworkStage(ctx context.Context, client rawNetworkClient, node, reason string) error {
	path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(node))
	_, revertErr := client.RawRequest(ctx, http.MethodDelete, path, nil)
	if revertErr != nil {
		return fmt.Errorf("%s (reverting staged changes also failed: %v)", reason, revertErr)
	}
	return errors.New(reason)
}

func (op *NetworkBridgeEnsure) abortAndRevert(ctx context.Context, reason string) error {
	err := revertNetworkStage(ctx, op.Client, op.Node, reason)
	return fmt.Errorf("network bridge ensure: %s: %w", op.Iface, err)
}

// fetchInterface issues GET /nodes/{node}/network/{iface} and reports
// whether iface currently exists. A RawRequest error whose text matches
// isMissingNetworkInterfaceError is treated as "doesn't exist" (exists ==
// false, err == nil), not as a hard failure — see that function's own doc
// comment on the exact detection method. A response body that is exactly
// JSON null (PVE's own explicit "nothing to report" shape — see
// pve.RawRequest's unwrapDataEnvelope) is treated the same way, as a
// defensive second case alongside the error-text check, in case a future
// PVE version reports a missing interface as an empty 2xx body instead of
// an error.
//
// Free function (not a NetworkBridgeEnsure method) so networkfields.go's
// NetworkFieldsEnsure can call it directly for its own target-interface
// reads, rather than duplicating this body — see rawNetworkClient's own
// doc comment.
func fetchInterface(ctx context.Context, client rawNetworkClient, node, iface string) (map[string]json.RawMessage, bool, error) {
	path := fmt.Sprintf("/nodes/%s/network/%s", url.PathEscape(node), url.PathEscape(iface))
	raw, err := client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		if isMissingNetworkInterfaceError(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, fmt.Errorf("parse: %w", err)
	}
	return fields, true, nil
}

// fetchAllInterfaces issues a single raw GET against /nodes/{node}/network
// (the LIST endpoint, no iface segment — the same path commitNetworkStage/
// revertNetworkStage below already hit for PUT/DELETE) and returns every
// interface's own raw fields, keyed by each entry's own "iface" field.
// Used by NetworkFieldsEnsure's "every other interface unchanged" guard in
// place of one fetchInterface call per other interface, per this task's own
// review finding that the list endpoint is cheaper and closes a narrow
// read/hash non-atomicity gap a typed-enumeration-plus-N-raw-GETs approach
// would have.
//
// CAVEAT — unverified against a live host: confirmed from the vendored
// go-proxmox source (nodes_network.go) that this endpoint returns a JSON
// ARRAY with each element carrying its own "iface" key, matching what
// go-proxmox's own typed Node.Networks decodes. NOT confirmed: that each
// array element's raw JSON carries the same set of untyped fields (e.g.
// vlan_filtering, which go-proxmox's NodeNetwork struct doesn't type at
// all) that a single GET /nodes/{node}/network/{iface} call returns for
// that same interface — decoding both into the same typed struct only
// proves parity for the fields that struct actually types. If a live host
// shows the list response omits fields the single-GET carries, this
// function silently makes NetworkFieldsEnsure's guard WEAKER than 3a's
// per-interface guard (a changed-but-omitted field on some other interface
// would go undetected). Fail-closed remedy in that case: abandon this
// single-list-call optimization and revert the guard to N per-interface
// fetchInterface calls, accepting the extra REST calls — do not continue
// trusting a guard already known to be weaker than it appears.
func fetchAllInterfaces(ctx context.Context, client rawNetworkClient, node string) (map[string]map[string]json.RawMessage, error) {
	path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(node))
	raw, err := client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	byIface := make(map[string]map[string]json.RawMessage, len(entries))
	for _, fields := range entries {
		ifaceRaw, ok := fields["iface"]
		if !ok {
			return nil, fmt.Errorf(`list response entry missing "iface" field`)
		}
		iface, err := kvjson.Scalar(ifaceRaw)
		if err != nil {
			return nil, fmt.Errorf("parse iface name: %w", err)
		}
		byIface[iface] = fields
	}
	return byIface, nil
}

// canonicalHash marshals fields with keys sorted (encoding/json already
// sorts map[string]json.RawMessage keys lexically on marshal), EXCLUDING
// any key literally equal to "digest" — a whole-node value that changes on
// ANY staged change anywhere on the node, which would cause false-positive
// guard trips unrelated to the interface actually being watched — then
// SHA-256s the resulting canonical JSON bytes and returns the hex digest.
func canonicalHash(fields map[string]json.RawMessage) (string, error) {
	filtered := make(map[string]json.RawMessage, len(fields))
	for k, v := range fields {
		if k == "digest" {
			continue
		}
		filtered[k] = v
	}
	b, err := json.Marshal(filtered)
	if err != nil {
		return "", fmt.Errorf("canonicalize fields: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// diffFields renders a human-readable summary of which keys differ between
// before and after (added/removed/changed), excluding "digest" for the
// same reason canonicalHash excludes it — used for step 5's error message
// so a caller sees exactly what changed, not just "hash mismatch".
func diffFields(before, after map[string]json.RawMessage) string {
	keys := make(map[string]bool, len(before)+len(after))
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var diffs []string
	for _, k := range sorted {
		if k == "digest" {
			continue
		}
		bv, bok := before[k]
		av, aok := after[k]
		switch {
		case bok && !aok:
			diffs = append(diffs, fmt.Sprintf("%s: removed (was %s)", k, string(bv)))
		case !bok && aok:
			diffs = append(diffs, fmt.Sprintf("%s: added (now %s)", k, string(av)))
		case bok && aok && !bytes.Equal(bv, av):
			diffs = append(diffs, fmt.Sprintf("%s: %s -> %s", k, string(bv), string(av)))
		}
	}
	if len(diffs) == 0 {
		return "fields differ but no per-key difference was found (possible key-ordering/whitespace artifact)"
	}
	return strings.Join(diffs, "; ")
}

// NetworkLockKey is the per-NODE lock.ObjectKey every network-config
// mutation on target/node shares — deliberately NOT per-interface: every
// stage/commit/revert call in this file targets the SAME node-level PVE
// resource (PVE's staged network config is node-wide, not per-interface)
// regardless of which interface a given Op instance is touching, so two
// concurrent NetworkBridgeEnsure Apply calls against different interfaces
// on the SAME node must still be serialized against each other, or one's
// stage/commit window could race the other's. This is a reviewed,
// load-bearing decision — do not key this by Iface. Exported so callers
// outside this package (e.g. cmd/pveforge) can construct the correct lock
// key for a NetworkBridgeEnsure Apply without re-deriving this reasoning.
func NetworkLockKey(target, node string) lock.ObjectKey {
	return lock.ObjectKey{TargetID: target, Kind: "network", ID: node}
}
