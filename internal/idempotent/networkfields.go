package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// NetworkFieldsClient is the subset of *pve.RoutedClient NetworkFieldsEnsure
// needs: the raw REST passthrough (same reasoning as NetworkBridgeClient's
// own doc comment — PVE's network-config API has no go-proxmox-typed
// stage/commit split), the kernel-level link-state primitive, and task
// polling. Unlike NetworkBridgeClient, this interface has no
// GetNetworkInterfaces: the "every other interface" guard reads the raw
// LIST endpoint directly via RawRequest (see fetchAllInterfaces in
// networkbridge.go), so the typed getter isn't needed at all.
type NetworkFieldsClient interface {
	Node() string
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	LinkState(ctx context.Context, iface string) (sshexec.LinkState, error)
	WaitForTask(ctx context.Context, node, upid string) error
}

// NetworkFieldsEnsure is idempotent.Op for `network set` (3b): ensure Iface's
// config holds every field in Pairs at its given value, via PVE's own
// two-phase stage/commit model — the SAME model NetworkBridgeEnsure (3a)
// uses, reusing its NetworkLockKey and the free stage/commit/revert/fetch
// functions in networkbridge.go rather than reimplementing them (see this
// task's own vault record, "3a source verification" and "Implementation
// plan", for exactly what was and wasn't already reusable as of 3a).
//
// Unlike NetworkBridgeEnsure's guard (a single canary interface, the node's
// management bridge), this Op's guard is BROADER: an MTU/vlan_filtering
// apply can touch the whole /etc/network/interfaces file's semantics, so
// EVERY OTHER interface on the node must be proven byte-identical (via
// canonicalHash) before this Op will commit — any difference in any
// excluded interface aborts and reverts, same as 3a's own "no --force
// bypass" discipline.
type NetworkFieldsEnsure struct {
	Client NetworkFieldsClient
	Node   string
	// Iface is the target interface whose fields this Op ensures.
	Iface string
	// Pairs are the field=value pairs to ensure, in caller order — reuses
	// kvjson.Pair, the same type VMFieldsEnsure uses, rather than inventing
	// a second pair type for this Op.
	Pairs []kvjson.Pair

	// current is set by Read and consumed by Satisfied — Iface's own
	// current field values for exactly the fields named in Pairs. Refreshed
	// on every Read call, matching VMFieldsEnsure.current's own contract.
	current map[string]string

	// Applied is the field names Apply actually wrote, in Pairs order —
	// reset at the start of every Apply call. Exported so cmd/pveforge's
	// RunE can report exactly what this Op wrote, same reasoning as
	// VMFieldsEnsure.Applied's own doc comment.
	Applied []string
}

// networkFieldsState is Read's comparable-state JSON shape: Current holds
// op.Iface's own field values (what Satisfied inspects). OtherHashes is
// deliberately never populated by Read — the "every other interface"
// guard is an Apply-only concern, refreshed fresh at the start of every
// Apply call, the same reasoning NetworkBridgeEnsure gives for why its own
// currentFields/preStanzaHash aren't Read-populated — but the field is kept
// in this type so the comparable-state blob stays round-trippable the way
// idempotent.Run's Result.Before/After expects, matching the two-dimension
// encoding precedent this Op's own design record cites.
type networkFieldsState struct {
	Current     map[string]string `json:"current"`
	OtherHashes map[string]string `json:"otherHashes,omitempty"`
}

// Validate reports whether op is well-formed: Node and Iface are required,
// at least one field must be given, and no field name may repeat — mirrors
// VMFieldsEnsure.Validate's own duplicate-field rejection.
func (op *NetworkFieldsEnsure) Validate() error {
	if op.Node == "" {
		return fmt.Errorf("network fields ensure: node is required")
	}
	if op.Iface == "" {
		return fmt.Errorf("network fields ensure: iface is required")
	}
	if len(op.Pairs) == 0 {
		return fmt.Errorf("network fields ensure: iface %s: at least one field is required", op.Iface)
	}
	seen := make(map[string]bool, len(op.Pairs))
	for _, p := range op.Pairs {
		if seen[p.Field] {
			return fmt.Errorf("network fields ensure: iface %s: field %q specified more than once", op.Iface, p.Field)
		}
		if p.Field == "type" {
			return fmt.Errorf("network fields ensure: iface %s: \"type\" cannot be set: the stage always sends the interface's current type itself, as PVE requires, and an interface's type cannot be changed this way", op.Iface)
		}
		seen[p.Field] = true
	}
	return nil
}

// Read fetches Iface's own current raw config (via the free fetchInterface
// function in networkbridge.go — see NetworkFieldsEnsure's own doc comment
// on why this task reuses it rather than duplicating it) and records each
// requested field's current value via kvjson.Scalar, same coercion
// VMFieldsEnsure.Read relies on. A field absent from Iface's current
// config is simply absent from the returned map — see fieldsEqual's own
// doc comment on why that absence must never be conflated with a
// present-but-empty value.
func (op *NetworkFieldsEnsure) Read(ctx context.Context) (string, error) {
	fields, exists, err := fetchInterface(ctx, op.Client, op.Node, op.Iface)
	if err != nil {
		return "", fmt.Errorf("network fields ensure: %s: read: %w", op.Iface, err)
	}
	if !exists {
		return "", fmt.Errorf("network fields ensure: %s: interface does not exist", op.Iface)
	}

	current := make(map[string]string, len(op.Pairs))
	for _, p := range op.Pairs {
		raw, ok := fields[p.Field]
		if !ok {
			continue
		}
		s, err := kvjson.Scalar(raw)
		if err != nil {
			return "", fmt.Errorf("network fields ensure: %s: field %q: %w", op.Iface, p.Field, err)
		}
		current[p.Field] = s
	}
	op.current = current

	b, err := json.Marshal(networkFieldsState{Current: current})
	if err != nil {
		return "", fmt.Errorf("network fields ensure: %s: encode current state: %w", op.Iface, err)
	}
	return string(b), nil
}

// Satisfied reports whether every requested field's current value already
// equals its wanted value, via fieldsEqual (not a plain == compare) so a
// boolean-shaped field like vlan_filtering converges regardless of which
// literal encoding PVE and the caller each used — see fieldsEqual's own
// doc comment. An absent field can never be considered already-matching,
// same discipline as VMFieldsEnsure.Satisfied and NetworkBridgeEnsure.Satisfied.
func (op *NetworkFieldsEnsure) Satisfied(current string) bool {
	var state networkFieldsState
	if err := json.Unmarshal([]byte(current), &state); err != nil {
		// Corrupted input reads as unsatisfied (safe to fail toward
		// re-Apply) — Satisfied has no error return to report this any
		// other way, matching parseBridgeIsolationState's own contract.
		return false
	}
	for _, p := range op.Pairs {
		val, ok := state.Current[p.Field]
		if !ok || !fieldsEqual(val, p.Value) {
			return false
		}
	}
	return true
}

// Apply performs the full stage -> guard -> commit -> poll -> verify
// sequence, reusing 3a's free stage/commit/revert/fetch functions from
// networkbridge.go throughout (see this Op's own doc comment). Like
// NetworkBridgeEnsure, this Op has no compare-and-swap/digest mechanism:
// every failure path below is terminal, never wrapping ErrConflict.
//
// Deliberately has NO step analogous to NetworkBridgeEnsure's step-4 guard
// self-check on op.Iface itself: that check works because bridge
// create/destroy is a binary exists/not-exists transition with two
// independent pre/post signals: an MTU/vlan_filtering field SET has no
// equivalent binary signal to check between stage and commit (the field's
// current value is arbitrary, and neither PVE's "active" field nor kernel
// LinkState reflects a pending field-level change) — see this task's own
// vault record ("Design choices needing a decision") for why re-reading
// op.Iface's own fields mid-stage was considered and rejected rather than
// silently omitted.
func (op *NetworkFieldsEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}
	op.Applied = nil

	// --- Step 1: pre-stage snapshot of every OTHER interface ------------
	before, err := fetchAllInterfaces(ctx, op.Client, op.Node)
	if err != nil {
		return fmt.Errorf("network fields ensure: %s: pre-stage snapshot of other interfaces: %w", op.Iface, err)
	}
	beforeHashes, err := otherInterfaceHashes(before, op.Iface)
	if err != nil {
		return fmt.Errorf("network fields ensure: %s: %w", op.Iface, err)
	}
	// The stage must carry the interface's current type (see stage), read
	// here from this same pre-stage snapshot rather than from Read, so it is
	// the freshest value under the lock and Apply never depends on a Read it
	// did not do. Nothing is staged yet, so a failure needs no revert.
	ifaceType, err := currentInterfaceType(before, op.Iface)
	if err != nil {
		return fmt.Errorf("network fields ensure: %s: %w", op.Iface, err)
	}

	// --- Step 2: stage ---------------------------------------------------
	// A failed stage is NOT reverted, for NetworkBridgeEnsure.Apply's
	// reason: the revert is a whole-node discard, and when our own stage
	// failed, whatever is pending most likely belongs to someone else. From
	// here on, every failure before the commit reverts.
	if err := op.stage(ctx, ifaceType); err != nil {
		return fmt.Errorf("network fields ensure: %s: stage: %w", op.Iface, err)
	}

	// --- Step 3: post-stage, pre-commit snapshot of every OTHER interface
	after, err := fetchAllInterfaces(ctx, op.Client, op.Node)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network fields ensure: %s: post-stage snapshot of other interfaces: %w", op.Iface, err))
	}
	afterHashes, err := otherInterfaceHashes(after, op.Iface)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network fields ensure: %s: %w", op.Iface, err))
	}

	// --- Step 4: compare — NO --force bypass, same reasoning as 3a's own
	// step 5: a mismatch here means PVE staged changes on this node that
	// this Op never asked for and knows nothing about.
	if diff := changedOtherInterfaces(before, after, beforeHashes, afterHashes); diff != "" {
		revertErr := revertNetworkStage(ctx, op.Client, op.Node,
			fmt.Sprintf("another interface's staged config changed during the stage window (refusing to commit an unrelated staged change): %s", diff))
		return fmt.Errorf("network fields ensure: %s: %w", op.Iface, revertErr)
	}

	// --- Step 5: commit ----------------------------------------------
	// A failed commit reverts, and the error says the outcome is unknown,
	// for NetworkBridgeEnsure.Apply's step-6 reason.
	upid, err := commitNetworkStage(ctx, op.Client, op.Node)
	if err != nil {
		return revertStagedAfter(ctx, op.Client, op.Node, fmt.Errorf("network fields ensure: %s: commit failed, outcome unknown (the change may or may not have been applied): %w", op.Iface, err))
	}

	// --- Step 5b: poll to completion (critical, not optional) ----------
	// No revert here, and none may be added as a hedge: once the commit
	// has consumed our stage, anything still pending belongs to someone
	// else, and the whole-node discard would wipe it.
	if err := op.Client.WaitForTask(ctx, op.Node, upid); err != nil {
		return fmt.Errorf("network fields ensure: %s: commit task %s did not complete successfully (no revert attempted: pve may already have applied this change, in whole or in part): %w", op.Iface, upid, err)
	}

	// --- Step 6: mandatory post-apply kernel verification of op.Iface
	// itself — see sshexec.LinkState's own doc comment: it carries no MTU
	// field, so this can only assert the interface still EXISTS, never
	// that the new field values actually took effect at the kernel level.
	link, err := op.Client.LinkState(ctx, op.Iface)
	if err != nil {
		return fmt.Errorf("network fields ensure: %s: post-apply kernel check: %w", op.Iface, err)
	}
	if !link.Exists {
		return fmt.Errorf("network fields ensure: %s: post-apply kernel state mismatch: interface no longer exists after apply — pve has already committed and reconfigured the kernel; no automatic remediation attempted", op.Iface)
	}

	op.Applied = make([]string, len(op.Pairs))
	for i, p := range op.Pairs {
		op.Applied[i] = p.Field
	}
	return nil
}

// stage is Apply's step 2: PUT /nodes/{node}/network/{iface} with Pairs'
// field=value params plus type=ifaceType, the interface's CURRENT type
// (never caller-supplied: Validate refuses a "type" pair). PVE's schema
// lists type as required on this PUT, and PVE's update_network requires it
// to match the existing interface's type. go-proxmox's NodeNetwork.Update
// sends it too, because it PUTs the whole NodeNetwork struct; sending only
// the changed fields, as this did before, omitted it.
//
// UNVERIFIED against a live host: that PVE refuses this PUT without type,
// and accepts it with the unchanged current type alongside only the changed
// fields (every other existing field left as it is). The nested harness
// (pveforge-nested-pve-test-harness) must check both, on a bridge and on a
// non-bridge interface, and that a type differing from the current one is
// refused.
func (op *NetworkFieldsEnsure) stage(ctx context.Context, ifaceType string) error {
	params := url.Values{}
	for _, p := range op.Pairs {
		params.Set(p.Field, p.Value)
	}
	params.Set("type", ifaceType)
	path := fmt.Sprintf("/nodes/%s/network/%s", url.PathEscape(op.Node), url.PathEscape(op.Iface))
	_, err := op.Client.RawRequest(ctx, http.MethodPut, path, params)
	return err
}

// currentInterfaceType is iface's "type" in a fetchAllInterfaces snapshot.
// A missing interface, or one without a non-empty string type, is an error:
// the stage cannot be sent without it, and guessing one would be a type
// change.
func currentInterfaceType(all map[string]map[string]json.RawMessage, iface string) (string, error) {
	fields, ok := all[iface]
	if !ok {
		return "", fmt.Errorf("interface is not in the node's interface list, so its current type is unknown; refusing to stage")
	}
	raw, ok := fields["type"]
	if !ok {
		return "", fmt.Errorf("interface has no type in the node's interface list; refusing to stage without one")
	}
	var typ string
	if err := json.Unmarshal(raw, &typ); err != nil || typ == "" {
		return "", fmt.Errorf("interface's type %s is not a non-empty string; refusing to stage", raw)
	}
	return typ, nil
}

// otherInterfaceHashes canonicalHashes every interface in all EXCEPT
// exclude, for the guard's before/after comparison.
func otherInterfaceHashes(all map[string]map[string]json.RawMessage, exclude string) (map[string]string, error) {
	hashes := make(map[string]string, len(all))
	for iface, fields := range all {
		if iface == exclude {
			continue
		}
		h, err := canonicalHash(fields)
		if err != nil {
			return nil, fmt.Errorf("hash interface %s: %w", iface, err)
		}
		hashes[iface] = h
	}
	return hashes, nil
}

// changedOtherInterfaces compares before/after hash snapshots (see
// otherInterfaceHashes) and, for every interface whose hash differs (added,
// removed, or changed), renders a per-field diff via diffFields — the same
// function 3a's own step 5 uses — against beforeFields/afterFields' raw
// field maps, so the guard's error names exactly which field on exactly
// which OTHER interface changed, not just "something changed".
func changedOtherInterfaces(beforeFields, afterFields map[string]map[string]json.RawMessage, beforeHashes, afterHashes map[string]string) string {
	names := make(map[string]bool, len(beforeHashes)+len(afterHashes))
	for k := range beforeHashes {
		names[k] = true
	}
	for k := range afterHashes {
		names[k] = true
	}
	sorted := make([]string, 0, len(names))
	for k := range names {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var diffs []string
	for _, iface := range sorted {
		if beforeHashes[iface] == afterHashes[iface] {
			continue
		}
		diffs = append(diffs, fmt.Sprintf("%s: %s", iface, diffFields(beforeFields[iface], afterFields[iface])))
	}
	return strings.Join(diffs, "; ")
}
