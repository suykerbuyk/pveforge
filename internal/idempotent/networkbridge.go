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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
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

// networkInterfaceMissingSubstring is the phrase this project EXPECTS PVE
// to use when the target network interface doesn't exist. It is consulted
// only inside the "iface" entry of a parameter-verification body (form 2 in
// isMissingNetworkInterfaceError), matched case-insensitively; form 1's
// pattern spells the same phrase inline, adjacent to the quoted name. It is
// never matched against the error's full text: that would let any
// unrelated "does not exist" read as a missing interface. Chosen by analogy
// with this project's OWN established convention for exactly this class of
// "does this thing exist" question: sshexec.LinkState's
// linkDoesNotExistSubstring uses the identical phrase for iproute2's `ip`
// command, and TapLinkState's own tapDoesNotExistSubstring follows the same
// pattern. PVE's actual HTTP status/error body for a GET against an unknown
// node network interface is NOT independently verified against a live host
// in this implementation session (same empirical-verification-gap
// discipline flagged throughout this project — see sshexec.LinkState,
// sshexec.RootOnlyFields, the digest-conflict error text).
const networkInterfaceMissingSubstring = "does not exist"

// isMissingNetworkInterfaceError reports whether err is PVE saying that
// iface ITSELF does not exist. It fails CLOSED: reading a missing interface
// as "absent" satisfies a destroy, so a false positive turns the destroy
// into a silent no-op that reports success, while a false negative is a
// loud error that surfaces on the first live run. Anything short of PVE
// unambiguously naming iface as missing is therefore NOT a match.
//
// It must be an answer from PVE ("pve returned"), never a transport error,
// whose text quotes the request URL and so always contains iface's name.
// Then exactly one of two forms applies, form 2 checked first:
//
//   - Form 2, structured. If the body carries PVE's parameter-verification
//     map ({"errors":{...}}), ONLY its "iface" entry is consulted, and it must
//     say "does not exist". If that entry quotes an interface name, it
//     must quote exactly one, equal to iface (case-sensitive, as interface
//     names are). If it quotes none, it must be the generic phrase alone
//     ("interface does not exist"), which counts as iface because the
//     request path named iface. Every other parameter's entry (storage,
//     vmid, ...) is ignored, even one that names iface. Form 1 is never
//     consulted when the map is present.
//   - Form 1, unstructured. Otherwise, the text must name iface with the
//     interface noun, quoted, immediately followed by the phrase: iface
//     'NAME' does not exist or interface "NAME" does not exist. The noun
//     and the phrase match in any case; the name matches exactly. The
//     quotes are what bound the name, so "eth0" never matches "eth0:1",
//     "vmbr1" never matches "vmbr1.100", "vmbr10", "vmbr1_x" or "vmbr1-x",
//     and "br0" never matches "vmbr0".
//
// UNVERIFIED against a live host: PVE's exact response for GET
// /nodes/{node}/network/{iface} on a missing interface. The expectation is
// a 400 parameter-verification error (raise_param_exc({ iface =>
// "interface does not exist" })), which form 2 accepts. Form 1 is a hedge
// for a response that names the interface in free text instead. If PVE
// answers in any other shape, the error propagates as a hard Read/Apply
// error instead of "absent", which is the safe direction for both create
// and destroy.
func isMissingNetworkInterfaceError(err error, iface string) bool {
	if err == nil || iface == "" {
		return false
	}
	msg := err.Error()
	if !strings.Contains(msg, "pve returned") {
		return false
	}
	if entries, structured := pveParameterErrors(msg); structured {
		return ifaceEntryNamesTarget(entries["iface"], iface)
	}
	q := regexp.QuoteMeta(iface)
	return regexp.MustCompile(`(?i:\b(?:iface|interface))\s+(?:'` + q + `'|"` + q + `")\s+(?i:does not exist)`).MatchString(msg)
}

// pveParameterErrors decodes the "errors" map of a PVE parameter-
// verification body carried in msg. structured reports whether msg carries
// such a body at all; a body that mentions "errors" but does not decode is
// still reported as structured, with no usable entries, so that it can
// never fall back to the unstructured form.
func pveParameterErrors(msg string) (entries map[string]string, structured bool) {
	i := strings.IndexByte(msg, '{')
	if i < 0 {
		return nil, false
	}
	var body struct {
		Errors map[string]json.RawMessage `json:"errors"`
	}
	if err := json.NewDecoder(strings.NewReader(msg[i:])).Decode(&body); err != nil || body.Errors == nil {
		return nil, strings.Contains(msg[i:], `"errors"`)
	}
	entries = make(map[string]string, len(body.Errors))
	for k, raw := range body.Errors {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			entries[k] = text
		}
	}
	return entries, true
}

var (
	quotedInterfaceName     = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
	genericInterfaceMissing = regexp.MustCompile(`(?i)^\s*(?:(?:iface|interface)\s+)?does not exist\.?\s*$`)
)

// ifaceEntryNamesTarget reports whether the "iface" parameter entry of a
// PVE parameter-verification body says that iface does not exist.
func ifaceEntryNamesTarget(entry, iface string) bool {
	if !strings.Contains(strings.ToLower(entry), networkInterfaceMissingSubstring) {
		return false
	}
	names := quotedInterfaceName.FindAllStringSubmatch(entry, -1)
	if len(names) == 0 {
		return genericInterfaceMissing.MatchString(entry)
	}
	return len(names) == 1 && names[0][1]+names[0][2] == iface
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
//
// A present field is compared via fieldsEqual (boolish.go), NOT a plain ==,
// exactly as NetworkFieldsEnsure.Satisfied and VMFieldsEnsure.Satisfied
// already do. Wanted carries whatever the caller typed while PVE answers in
// its own encoding, so a boolean-shaped bridge field — vlan_filtering,
// autostart, bridge_vlan_aware, all typed as plain ints or IntOrBool on
// go-proxmox's own NodeNetwork — converges regardless of which literal form
// each side used. This was a real, shipped defect (found 2026-09-20, while
// reviewing pveforge-mutation-success-second-signal's plan): with a plain
// !=, `network bridge create ... vlan_filtering=true` could never report
// satisfied against PVE's own "1", so every invocation re-drove the entire
// stage -> guard -> commit -> ifreload sequence against a live node — the
// exact blast radius this Op's two-phase guard exists to avoid. See
// TestNetworkBridgeEnsure_Satisfied_BoolishFieldsConverge.
//
// This is the only field-VALUE comparison in this file. The four plain !=
// that remain are deliberately not fieldsEqual, because none of them
// compares a caller-supplied value against a PVE-reported one: current's
// emptiness (Satisfied's own exists check), the staged-stanza hash the
// guard compares against its pre-stage snapshot, and the two post-apply
// kernel-state checks, which compare Go bools from LinkState to Go bools.
// fieldsEqual would be meaningless on all four.
func (op *NetworkBridgeEnsure) Satisfied(current string) bool {
	exists := current != ""

	wanted := op.effectiveWanted()
	if len(wanted) == 0 {
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
	for field, want := range wanted {
		raw, ok := fields[field]
		if !ok {
			return false
		}
		got, err := kvjson.Scalar(raw)
		if err != nil || !fieldsEqual(got, want) {
			return false
		}
	}
	return true
}

// effectiveWanted is what a create actually asks for: Wanted, plus
// type=bridge when the caller named no type — PVE requires a type on a
// create, and a bridge is what this Op is named after. Satisfied and stage
// both use it, so the default that is sent is also the default that is
// checked: an existing interface of another type with otherwise matching
// fields is not "already up to date". Empty for a destroy.
func (op *NetworkBridgeEnsure) effectiveWanted() map[string]string {
	if len(op.Wanted) == 0 {
		return nil
	}
	out := make(map[string]string, len(op.Wanted)+1)
	for k, v := range op.Wanted {
		out[k] = v
	}
	if _, ok := out["type"]; !ok {
		out["type"] = "bridge"
	}
	return out
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

	// A create of an interface that already exists as another type cannot
	// be what was asked: refuse it here, before anything is staged, rather
	// than stage a create PVE (or the step-4 guard) would then reject.
	if want := op.effectiveWanted(); len(want) > 0 {
		existing, exists, err := fetchInterface(ctx, op.Client, op.Node, op.Iface)
		if err != nil {
			return fmt.Errorf("network bridge ensure: %s: pre-stage read: %w", op.Iface, err)
		}
		if exists {
			got := ""
			if raw, ok := existing["type"]; ok {
				got, _ = kvjson.Scalar(raw)
			}
			if got != want["type"] {
				return fmt.Errorf("network bridge ensure: %s: already exists as type %s, not %s; refusing to create it (nothing staged)", op.Iface, kvjson.QuoteValue(got), kvjson.QuoteValue(want["type"]))
			}
		}
	}

	// --- Step 2: stage -----------------------------------------------
	// A failed stage is NOT reverted. The revert discards every staged
	// change on the node, and when our own stage failed, whatever is still
	// pending most likely belongs to someone else. From here on, every
	// failure before the commit reverts: our stage is known to exist.
	if err := op.stage(ctx); err != nil {
		return fmt.Errorf("network bridge ensure: %s: stage: %w", op.Iface, err)
	}

	// --- Step 3: post-stage, pre-commit snapshot of ManagementBridge ---
	pendingFields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.ManagementBridge)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: post-stage snapshot of management bridge %s: %w", op.Iface, op.ManagementBridge, err))
	}
	if !exists {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: management bridge %s vanished immediately after staging", op.Iface, op.ManagementBridge))
	}
	pendingStanzaHash, err := canonicalHash(pendingFields)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: %w", op.Iface, err))
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
	// A failed commit reverts. If PVE refused it, our stage is still
	// pending and must not be left for the next apply to commit. If the
	// outcome is unknown (a transport error, or no usable UPID), the apply
	// worker may already be running; the revert is safe in either order,
	// because it lands either after the worker has consumed interfaces.new
	// (a no-op) or before (the apply then changes nothing). So the error
	// says the outcome is unknown, and never claims "not applied".
	upid, err := op.commit(ctx)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: commit failed, outcome unknown (the change may or may not have been applied): %w", op.Iface, err))
	}

	// --- Step 6b: poll to completion (critical, not optional) ---------
	// Must complete — success or a translated failure — before step 7
	// ever runs. A failure here is terminal: PVE's own apply already ran
	// against interfaces.new by the time a task can report success or
	// failure, so there is nothing "pending" left to revert.
	//
	// Do NOT add a revert here as a hedge. Once the commit has consumed
	// our stage, anything still pending on the node belongs to someone
	// else, and the revert is a whole-node discard: it would wipe their
	// staged work, not ours.
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
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: guard self-check: read iface state: %w", op.Iface, err))
	}
	active := false
	if exists {
		if raw, ok := fields["active"]; ok {
			s, err := kvjson.Scalar(raw)
			if err != nil {
				return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: guard self-check: parse active flag: %w", op.Iface, err))
			}
			active = activeTruthy(s)
		}
	}

	link, err := op.Client.LinkState(ctx, op.Iface)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network bridge ensure: %s: guard self-check: read kernel link state: %w", op.Iface, err))
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
	if want := op.effectiveWanted(); len(want) > 0 {
		// effectiveWanted carries the type=bridge default when the caller
		// named no type: PVE's schema lists type as required on this
		// create. UNVERIFIED against a live host: that PVE refuses the
		// create without type — the nested harness
		// (pveforge-nested-pve-test-harness) must check it.
		params := url.Values{}
		for field, value := range want {
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
	return revertStagedAfter(ctx, client, node, errors.New(reason))
}

// revertTimeout bounds revertStagedAfter's own request, which runs detached
// from the caller's context (see there).
const revertTimeout = 30 * time.Second

// revertStagedAfter is revertNetworkStage for a failure that already is an
// error: it issues the same whole-node discard and returns cause itself,
// annotated with the revert's own failure if that failed too. It never
// flattens cause to text, so errors.Is and errors.As on the result still
// reach it (pve.ErrUnverifiableRead from a post-stage read, for one).
// Every failure after a successful stage and before a successful commit
// returns through here, so a staged change is never left pending on the
// node for whatever applies next to commit.
//
// The revert does NOT run on ctx. A cancelled or expired caller context is
// exactly when a half-done Apply most needs to clean up, and a revert that
// inherited the cancellation would never reach PVE, leaving the stage
// pending for the next apply to commit. So it runs detached from ctx's
// cancellation (context.WithoutCancel keeps ctx's values), bounded by
// revertTimeout so a hung PVE cannot hold the caller forever.
func revertStagedAfter(ctx context.Context, client rawNetworkClient, node string, cause error) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revertTimeout)
	defer cancel()
	path := fmt.Sprintf("/nodes/%s/network", url.PathEscape(node))
	if _, revertErr := client.RawRequest(rctx, http.MethodDelete, path, nil); revertErr != nil {
		return fmt.Errorf("%w (reverting staged changes also failed: %v)", cause, revertErr)
	}
	return cause
}

func (op *NetworkBridgeEnsure) abortAndRevert(ctx context.Context, reason string) error {
	err := revertNetworkStage(ctx, op.Client, op.Node, reason)
	return fmt.Errorf("network bridge ensure: %s: %w", op.Iface, err)
}

// fetchInterface issues GET /nodes/{node}/network/{iface} and reports
// whether iface currently exists. A RawRequest error that
// isMissingNetworkInterfaceError classifies as iface itself missing is
// treated as "doesn't exist" (exists == false, err == nil), not as a hard
// failure — see that function's own doc comment on the exact detection
// method. A 2xx body that is exactly JSON null is NOT: it is refused as
// pve.ErrUnverifiableRead. It was once read as "doesn't exist" too, in case
// a future PVE version reported a missing interface that way, but for a
// destroy "absent" means "already done", so a null answer silently turned
// the destroy into a no-op that reported success.
//
// Free function (not a NetworkBridgeEnsure method) so networkfields.go's
// NetworkFieldsEnsure can call it directly for its own target-interface
// reads, rather than duplicating this body — see rawNetworkClient's own
// doc comment.
func fetchInterface(ctx context.Context, client rawNetworkClient, node, iface string) (map[string]json.RawMessage, bool, error) {
	path := fmt.Sprintf("/nodes/%s/network/%s", url.PathEscape(node), url.PathEscape(iface))
	raw, err := client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		if isMissingNetworkInterfaceError(err, iface) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, false, fmt.Errorf("interface %s: %w: payload was null", iface, pve.ErrUnverifiableRead)
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
	// A node always lists at least the interface being edited, so a null or
	// empty list is a payload PVE never really answered. Accepting it would
	// make both snapshots empty and the "every other interface unchanged"
	// comparison vacuously true.
	if len(entries) == 0 {
		return nil, fmt.Errorf("interface list on %s: %w: payload was null or empty", node, pve.ErrUnverifiableRead)
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
