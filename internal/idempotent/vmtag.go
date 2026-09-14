package idempotent

import (
	"context"
	"fmt"
	"strings"

	proxmox "github.com/luthermonson/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// Client is the subset of *pve.RoutedClient a VM-config-mutating Op
// needs: a typed read (for Tags and the config Digest) and the
// digest-aware routed write. Defined here, not as the concrete
// *pve.RoutedClient, so this package's own tests use a lightweight
// in-package fake instead of pve's network/SSH test harness —
// *pve.RoutedClient satisfies this interface structurally (see
// compat_test.go).
type Client interface {
	// GetVM fetches vmid's current status and config on node.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// SetVMConfigFieldCAS sets one VM config field, routed over REST or
	// the standing SSH vector as sshexec.RootOnlyFields dictates,
	// honoring expectDigest as a compare-and-swap guard when the routed
	// field supports it (REST-writable fields only — see
	// pve.RoutedClient.SetVMConfigFieldCAS's own doc comment on the
	// root-only-field asymmetry).
	SetVMConfigFieldCAS(ctx context.Context, vmid int, field, value, expectDigest string) error
}

// VMTagEnsure is the idempotent-mutation-engine's proof case (per
// pveforge-idempotent-mutation-engine's recorded decision 4): ensure vmid
// carries Tag among its semicolon-separated Tags. Chosen over the
// originally-proposed bridge-port-isolation example specifically because
// every primitive it needs (a typed read exposing Tags and Digest, a
// REST-writable — not root-only — config field, digest-based CAS) is
// already fully wired end-to-end; bridge isolation needs hookscript
// deployment, which nothing in this codebase builds yet (tracked
// separately as pveforge-bridge-isolation-via-hookscript).
//
// Tags is REST-writable (unlike args), so this exercises the digest-CAS
// retry path for real — see Apply. Not idempotent by itself in the
// duplicate-tag sense of "did someone else already add this tag between
// our read and our write"; that's exactly what the CAS guard plus Run's
// ErrConflict retry handles.
type VMTagEnsure struct {
	Client Client
	VMID   int
	Tag    string

	// tags and digest are set by Read and consumed by Satisfied/Apply —
	// refreshed on every attempt, including a Run-driven retry after
	// ErrConflict, so a retry's Apply always CAS-guards against the
	// latest digest rather than the one from a now-stale first attempt.
	tags   []string
	digest string
}

// Validate reports whether op is well-formed: Tag must be non-empty and
// must not contain tagSeparator — the one character this format actually
// uses to delimit entries. Without this, a Tag like "foo;bar" would
// silently fragment into two separate tags on the next read/write
// round-trip (Satisfied's exact-string match against the whole original
// Tag could then never match again, causing a non-idempotent re-append
// on every invocation), and an empty Tag appended to a non-empty existing
// list would produce a dangling trailing separator on the wire. Same
// defense-in-depth discipline as NVMeDrive.Validate
// (internal/device/nvme.go) — a single forbidden-character check is
// sufficient here, since there's no comma-delimited QEMU option syntax to
// worry about, just the one separator this format uses.
func (op *VMTagEnsure) Validate() error {
	if op.Tag == "" {
		return fmt.Errorf("vm tag ensure: vm %d: tag is empty", op.VMID)
	}
	if strings.Contains(op.Tag, tagSeparator) {
		return fmt.Errorf("vm tag ensure: vm %d: tag %q contains the tag separator %q", op.VMID, op.Tag, tagSeparator)
	}
	return nil
}

// Read fetches vmid's current VirtualMachineConfig and records its Tags
// (split on proxmox.TagSeperator) and Digest for Satisfied/Apply. Returns
// the raw Tags string as the comparable "current state" Run reports in
// Result.Before/After.
func (op *VMTagEnsure) Read(ctx context.Context) (string, error) {
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		return "", fmt.Errorf("vm tag ensure: read vm %d: %w", op.VMID, err)
	}
	var tagsStr, digest string
	if vm.VirtualMachineConfig != nil {
		tagsStr = vm.VirtualMachineConfig.Tags
		digest = vm.VirtualMachineConfig.Digest
	}
	op.tags = splitTags(tagsStr)
	op.digest = digest
	return tagsStr, nil
}

// Satisfied reports whether op.Tag is already among current's tags.
func (op *VMTagEnsure) Satisfied(current string) bool {
	for _, t := range splitTags(current) {
		if t == op.Tag {
			return true
		}
	}
	return false
}

// Apply validates op (see Validate) before touching anything else, then
// appends op.Tag to the tags Read last observed and writes the merged
// list back via SetVMConfigFieldCAS, guarded by the digest Read last
// observed. A digest-conflict rejection (pve.IsDigestConflictError)
// is reported as an error wrapping ErrConflict, so Run re-reads and
// retries rather than propagating a stale-state failure — a genuinely
// concurrent write (from anything outside internal/lock's reach: a
// different machine, a different roster file, the PVE GUI) is exactly
// what this guard exists to catch.
func (op *VMTagEnsure) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	merged := make([]string, 0, len(op.tags)+1)
	merged = append(merged, op.tags...)
	merged = append(merged, op.Tag)
	newTags := strings.Join(merged, tagSeparator)

	err := op.Client.SetVMConfigFieldCAS(ctx, op.VMID, "tags", newTags, op.digest)
	if err != nil {
		if pve.IsDigestConflictError(err) {
			return fmt.Errorf("vm tag ensure: vm %d: %w: %w", op.VMID, ErrConflict, err)
		}
		return fmt.Errorf("vm tag ensure: vm %d: %w", op.VMID, err)
	}
	return nil
}

// tagSeparator is go-proxmox's own tag-list separator
// (proxmox.TagSeperator, ";") — referenced through the exported constant
// rather than re-declared, so this package's own separator can never
// silently drift from the one go-proxmox's TagsSlice/HasTag helpers
// assume when a caller inspects the same VirtualMachineConfig elsewhere.
const tagSeparator = proxmox.TagSeperator

func splitTags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, tagSeparator)
}
