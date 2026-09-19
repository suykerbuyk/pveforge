package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// BridgeIsolationClient is the subset of *pve.RoutedClient's capability
// BridgeIsolationEnsure needs: a typed read (for Hookscript/Digest/
// Status), the digest-aware routed write plus its non-CAS fallback (see
// Apply's own doc comment on why), and the snippet-deployment/live-tap
// primitives pveforge-bridge-isolation-via-hookscript built
// (internal/pve/routed.go's UploadSnippet/TapLinkState/
// SetBridgePortIsolated, backed by internal/sshexec/bridgelink.go).
// Defined here, not as the concrete *pve.RoutedClient, for the same reason
// as this package's existing Client interface (vmtag.go): a lightweight
// in-package fake instead of pve's network/SSH test harness —
// *pve.RoutedClient satisfies this interface structurally (see
// compat_test.go).
type BridgeIsolationClient interface {
	// GetVM fetches vmid's current status and config on node.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// SetVMConfigFieldCAS sets one VM config field, honoring expectDigest
	// as a compare-and-swap guard.
	SetVMConfigFieldCAS(ctx context.Context, vmid int, field, value, expectDigest string) error
	// SetVMConfigField sets one VM config field unconditionally, routed
	// over REST or the standing SSH vector as sshexec.RootOnlyFields
	// dictates. Used as Apply's fallback for hookscript specifically —
	// see Apply's own doc comment.
	SetVMConfigField(ctx context.Context, vmid int, field, value string) error
	// UploadSnippet deploys content to PVE's "snippets" storage content
	// type on storageID, as filename.
	UploadSnippet(ctx context.Context, storageID, filename string, content []byte) error
	// TapLinkState reports one tap device's live bridge-port state.
	TapLinkState(ctx context.Context, tap string) (sshexec.TapLinkState, error)
	// SetBridgePortIsolated immediately sets or clears one tap device's
	// live bridge-port isolation flag.
	SetBridgePortIsolated(ctx context.Context, tap string, isolated bool) error
}

// BridgeIsolationEnsure is pveforge-bridge-isolation-via-hookscript's
// idempotent.Op: ensure Linux bridge port isolation survives every boot of
// vmid, on every net interface listed in NetIndices — the PRD's original
// canonical driving example for this whole package (superseded by
// VMTagEnsure as the mechanism's own proof case specifically because this
// one needed two missing primitives — hookscript deployment and tap-device
// control — built first; see this task's own doc comment in vibe-palace
// for the split).
//
// One Op instance covers ALL of vmid's isolated interfaces, not one
// instance per (vmid, netIndex) pair: every interface's isolation state is
// driven by the SAME hookscript config field and the SAME deployed
// snippet file, so two independent Op instances for the same vmid but
// different NetIndices would each regenerate and overwrite that shared
// state on every Apply — the second Op's Apply would silently revert the
// first's effect. Bundling them into one Op/one script avoids that
// footgun by construction (recorded decision, pveforge-bridge-isolation-
// via-hookscript, 2026-09-14).
//
// This mutation has TWO pieces of state to reconcile, not one (unlike
// VMTagEnsure's single Tags field): the durable hookscript config wiring
// (persists across reboots, applied by PVE itself at every future
// post-start) and the live, ephemeral tap-device isolation flag (recreated
// fresh on every boot, and only actionable while the VM is currently
// running — see Read/Satisfied's own handling of the not-running case).
type BridgeIsolationEnsure struct {
	Client BridgeIsolationClient
	VMID   int
	// NetIndices are the VM's net<N> interface indices to isolate (e.g.
	// []int{0} for just net0). Must be non-empty, non-negative, and
	// contain no duplicates — see Validate.
	NetIndices []int
	// StorageID is the PVE storage (configured with the "snippets"
	// content type) the generated script is deployed to — e.g. "local".
	// Required; which storage has snippets enabled varies by deployment,
	// so this is never hardcoded.
	StorageID string

	// digest, hookscript, and running are set by Read and consumed by
	// Apply — refreshed on every attempt, including a Run-driven retry
	// after ErrConflict, so a retry's Apply always CAS-guards against the
	// latest digest rather than one from a now-stale first attempt.
	digest     string
	hookscript string
	running    bool
}

// Validate reports whether op is well-formed. Same defense-in-depth
// discipline as VMTagEnsure.Validate/NVMeDrive.Validate: StorageID is
// embedded directly into a filesystem path (RoutedClient.UploadSnippet)
// and must not be able to introduce unexpected characters, even though it
// is software/operator-controlled today, not free-form external input.
func (op *BridgeIsolationEnsure) Validate() error {
	if op.VMID <= 0 {
		return fmt.Errorf("bridge isolation ensure: vmid must be positive, got %d", op.VMID)
	}
	if len(op.NetIndices) == 0 {
		return fmt.Errorf("bridge isolation ensure: vm %d: at least one net index is required", op.VMID)
	}
	seen := make(map[int]bool, len(op.NetIndices))
	for _, idx := range op.NetIndices {
		if idx < 0 {
			return fmt.Errorf("bridge isolation ensure: vm %d: net index %d is negative", op.VMID, idx)
		}
		if seen[idx] {
			return fmt.Errorf("bridge isolation ensure: vm %d: net index %d listed more than once", op.VMID, idx)
		}
		seen[idx] = true
	}
	if !isSafeStorageID(op.StorageID) {
		return fmt.Errorf("bridge isolation ensure: vm %d: storage id %q is empty or contains unsafe characters", op.VMID, op.StorageID)
	}
	return nil
}

// Read fetches vmid's current Hookscript/Digest/Status, and — only while
// the VM is actually running — every configured net index's live tap
// bridge-port state. While the VM is stopped, its tap devices don't exist
// yet (they're created fresh on next boot), so there is nothing live to
// check yet — Satisfied treats that as trivially satisfied on the tap
// dimension, deferring entirely to the hookscript firing on next boot.
func (op *BridgeIsolationEnsure) Read(ctx context.Context) (string, error) {
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		return "", fmt.Errorf("bridge isolation ensure: read vm %d: %w", op.VMID, err)
	}
	cfg, err := requireVMConfig(vm, op.VMID, "bridge isolation ensure")
	if err != nil {
		return "", err
	}
	hookscript := cfg.Hookscript
	digest := cfg.Digest
	op.hookscript = hookscript
	op.digest = digest
	op.running = vm.Status == "running"

	state := bridgeIsolationState{Hookscript: hookscript, Running: op.running}
	if op.running {
		state.Taps = make([]tapObservation, 0, len(op.NetIndices))
		for _, idx := range op.NetIndices {
			ts, err := op.Client.TapLinkState(ctx, sshexec.TapDeviceName(op.VMID, idx))
			if err != nil {
				return "", fmt.Errorf("bridge isolation ensure: read tap state for vm %d net%d: %w", op.VMID, idx, err)
			}
			state.Taps = append(state.Taps, tapObservation{NetIndex: idx, Exists: ts.Exists, Isolated: ts.Isolated})
		}
	}
	return state.String(), nil
}

// Satisfied reports whether current already reflects both pieces of
// wanted state: the hookscript field pointing at this Op's deployed
// snippet, and — only if the VM is running — every configured net index's
// tap already isolated.
func (op *BridgeIsolationEnsure) Satisfied(current string) bool {
	state := parseBridgeIsolationState(current)
	if state.Hookscript != op.wantedHookscript() {
		return false
	}
	if !state.Running {
		return true
	}
	taps := make(map[int]tapObservation, len(state.Taps))
	for _, t := range state.Taps {
		taps[t.NetIndex] = t
	}
	for _, idx := range op.NetIndices {
		tap, ok := taps[idx]
		if !ok || !tap.Exists || !tap.Isolated {
			return false
		}
	}
	return true
}

// Apply (1) deploys the generated hookscript content unconditionally —
// cheap and always-correct to repeat, so there is no need to hash-compare
// against previously-deployed content (same "naive but safe to repeat"
// precedent as NVMeDrive.Apply); (2) wires VirtualMachineConfig.Hookscript
// at the wanted value if it isn't already, CAS-guarded by the digest Read
// last observed; (3) if the VM is currently running, immediately applies
// isolation to every configured tap — a hookscript only fires on FUTURE
// boot events, so this is the only way "ensure isolation right now" can
// be satisfied for an already-running VM (recorded decision,
// pveforge-bridge-isolation-via-hookscript, 2026-09-14: this is a hard
// Apply error if it fails, never swallowed as best-effort, since applying
// immediately is one of the two things this feature is required to do,
// not a nicety).
//
// Whether "hookscript" is REST-writable from a scoped token the way
// "tags" is, or root-only like "args", is UNVERIFIED against a live host
// in this implementation session (same empirical-verification-gap
// discipline as sshexec.RootOnlyFields itself). SetVMConfigFieldCAS (unlike
// the plain SetVMConfigField) has no automatic retry-over-SSH built in for
// an unregistered root-only field — it just surfaces PVE's rejection — so
// this Apply does that fallback itself: on
// sshexec.IsRootOnlyWriteError(err), it retries via the plain
// (non-CAS) SetVMConfigField before giving up.
func (op *BridgeIsolationEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	if err := op.Client.UploadSnippet(ctx, op.StorageID, op.snippetFilename(), op.scriptContent()); err != nil {
		return fmt.Errorf("bridge isolation ensure: vm %d: upload snippet: %w", op.VMID, err)
	}

	wanted := op.wantedHookscript()
	if op.hookscript != wanted {
		if err := op.Client.SetVMConfigFieldCAS(ctx, op.VMID, "hookscript", wanted, op.digest); err != nil {
			switch {
			case pve.IsDigestConflictError(err):
				return fmt.Errorf("bridge isolation ensure: vm %d: %w: %w", op.VMID, ErrConflict, err)
			case sshexec.IsRootOnlyWriteError(err):
				if fallbackErr := op.Client.SetVMConfigField(ctx, op.VMID, "hookscript", wanted); fallbackErr != nil {
					return fmt.Errorf("bridge isolation ensure: vm %d: set hookscript: rejected as root-only by rest, ssh fallback also failed: %w", op.VMID, fallbackErr)
				}
			default:
				return fmt.Errorf("bridge isolation ensure: vm %d: set hookscript: %w", op.VMID, err)
			}
		}
	}

	if op.running {
		for _, idx := range op.NetIndices {
			tap := sshexec.TapDeviceName(op.VMID, idx)
			if err := op.Client.SetBridgePortIsolated(ctx, tap, true); err != nil {
				return fmt.Errorf("bridge isolation ensure: vm %d: apply live isolation to %s: %w", op.VMID, tap, err)
			}
		}
	}
	return nil
}

// snippetFilename is the deployed script's filename — one per VM (see
// this type's own doc comment on why NOT one per net index), but embedding
// a stable, sorted encoding of NetIndices too: without that, changing
// NetIndices on an already-wired, currently-STOPPED VM would leave
// wantedHookscript unchanged, and Satisfied (which compares only the
// hookscript field for a stopped VM — there being nothing live to check
// yet) would report the op already satisfied without ever re-deploying the
// script or CAS-writing anything, silently shipping forward a stale script
// that isolates the OLD net index set only. Embedding NetIndices here
// means a changed set produces a genuinely different wanted value, so the
// existing hookscript-comparison check in Satisfied catches the mismatch
// with no separate state dimension needed. (A NetIndices change does
// orphan the previous set's snippet file on the storage backend —
// unreferenced and harmless, just not cleaned up; accepted as a minor
// cosmetic gap, not a correctness one.)
func (op *BridgeIsolationEnsure) snippetFilename() string {
	return fmt.Sprintf("pveforge-bridge-isolate-vm%d-%s.sh", op.VMID, op.netIndicesSuffix())
}

// netIndicesSuffix renders op.NetIndices as a stable, sorted, filename-safe
// suffix (e.g. []int{1, 0} and []int{0, 1} both render "net0-1") — sorted
// so the wanted hookscript value depends only on the SET of configured net
// indices, not the order NetIndices happens to be given in.
func (op *BridgeIsolationEnsure) netIndicesSuffix() string {
	indices := append([]int(nil), op.NetIndices...)
	sort.Ints(indices)
	parts := make([]string, len(indices))
	for i, idx := range indices {
		parts[i] = strconv.Itoa(idx)
	}
	return "net" + strings.Join(parts, "-")
}

// wantedHookscript is PVE's documented "<storage>:snippets/<filename>"
// hookscript config value syntax — NOT independently verified against a
// live host in this implementation session (same empirical-verification
// gap as sshexec.TapDeviceName's naming convention).
func (op *BridgeIsolationEnsure) wantedHookscript() string {
	return fmt.Sprintf("%s:snippets/%s", op.StorageID, op.snippetFilename())
}

// scriptContent renders the hookscript itself: a POSIX sh script that
// no-ops on every PVE hookscript phase except post-start, where it
// attempts to isolate every configured tap and ALWAYS exits 0 regardless
// of whether that attempt succeeded.
//
// Always exiting 0 is load-bearing, not a style choice: PVE's hookscript
// contract treats a non-zero exit on pre-start/pre-stop (and possibly
// other phases — see the PVE hookscript documentation) as a signal to
// ABORT that lifecycle action. A transient failure setting a bridge flag
// must never be able to block a VM from booting or stopping. Whether the
// tap device is reliably already attached to its bridge by the time
// post-start fires (as opposed to a brief startup race) is UNVERIFIED
// against a live host in this implementation session — if that turns out
// to be flaky, a retry loop inside this script is the natural follow-up,
// deliberately not built speculatively here.
func (op *BridgeIsolationEnsure) scriptContent() []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Generated by pveforge — do not edit by hand; Apply overwrites this file\n")
	b.WriteString("# every time bridge-isolation state is reconciled for this VM.\n")
	b.WriteString("#\n")
	b.WriteString("# Always exits 0: a non-zero exit on any phase other than post-start would\n")
	b.WriteString("# abort that PVE lifecycle action (e.g. blocking the VM from starting or\n")
	b.WriteString("# stopping), which this best-effort networking tweak must never do.\n")
	b.WriteString(`if [ "$2" = "post-start" ]; then` + "\n")
	for _, idx := range op.NetIndices {
		fmt.Fprintf(&b, "  bridge link set dev %s isolated on 2>/dev/null || true\n", sshexec.TapDeviceName(op.VMID, idx))
	}
	b.WriteString("fi\n")
	b.WriteString("exit 0\n")
	return []byte(b.String())
}

// isSafeStorageID reports whether s is non-empty and every rune is an
// ASCII letter, digit, '-', '_', or '.' — PVE storage IDs' own documented
// naming rules, and safe to embed directly into a filesystem path
// (RoutedClient.UploadSnippet).
func isSafeStorageID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// tapObservation is one net index's observed live tap state, as encoded
// into/decoded from Run's comparable current-state string. Exported fields
// (despite the type itself being unexported) so encoding/json can see
// them — see bridgeIsolationState.String's own doc comment on why this is
// JSON-encoded rather than hand-rolled delimited text.
type tapObservation struct {
	NetIndex int  `json:"net_index"`
	Exists   bool `json:"exists"`
	Isolated bool `json:"isolated"`
}

// bridgeIsolationState is BridgeIsolationEnsure's comparable "current
// state" — both pieces of it (see this Op's own doc comment): the
// hookscript wiring and, only while running, every observed tap's state.
type bridgeIsolationState struct {
	Hookscript string           `json:"hookscript"`
	Running    bool             `json:"running"`
	Taps       []tapObservation `json:"taps,omitempty"`
}

// String renders s as JSON — deliberately NOT a hand-rolled ";"/"="
// delimited format (an earlier version of this code used one): Hookscript
// is sourced directly from PVE's live VirtualMachineConfig.Hookscript
// (Read), which is EXTERNAL, unvalidated data — unlike every value
// pveforge itself controls here (StorageID, NetIndices), nothing
// constrains what characters a hookscript value set by some other tool, or
// by a human via the PVE GUI, might contain. A delimiter-joined format
// would misparse (silently truncate or shift fields) if that value ever
// contained a literal ';' or '=', and Satisfied could then report a false
// match. This string only needs to be internally comparable
// (Result.Before/After equality, Satisfied's own re-parse) — not
// human-readable — so encoding/json's unambiguous escaping is a strictly
// safer default with no real downside.
//
// Taps is sorted by NetIndex first, so two reads observing the identical
// state always produce byte-identical JSON regardless of the order
// NetIndices was iterated in.
func (s bridgeIsolationState) String() string {
	sorted := append([]tapObservation(nil), s.Taps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].NetIndex < sorted[j].NetIndex })
	s.Taps = sorted

	b, err := json.Marshal(s)
	if err != nil {
		// Unreachable in practice: every field of bridgeIsolationState is a
		// plain string/bool/int, none of which json.Marshal can fail on.
		// Encoded distinctly from any real state (a real Hookscript value
		// can never itself be valid JSON that also matches this shape),
		// so this can never be silently mistaken for a legitimate state.
		return fmt.Sprintf("bridgeisolationstate-marshal-error:%v", err)
	}
	return string(b)
}

// parseBridgeIsolationState reverses bridgeIsolationState.String. A
// malformed or unparseable string decodes to the zero-value state
// (Hookscript == "", never satisfying a real wantedHookscript) rather than
// erroring — Satisfied's own contract has no error return, so corrupted
// input should read as narrowly "unsatisfied" (safe to fail toward
// re-Apply) rather than panic.
func parseBridgeIsolationState(s string) bridgeIsolationState {
	var result bridgeIsolationState
	_ = json.Unmarshal([]byte(s), &result)
	return result
}
