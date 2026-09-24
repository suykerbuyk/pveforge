package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// VMCreateClient is the subset of *pve.RoutedClient a VM-create Op needs:
// a typed read (to detect whether the vmid is already taken), Node (to
// scope both the read and CreateVM to the right target), the create call
// itself, and WaitForTask to block until PVE's asynchronous create task
// actually finishes. Defined here, not as the concrete *pve.RoutedClient,
// so this package's own tests use a lightweight in-package fake instead of
// pve's network/SSH test harness — *pve.RoutedClient satisfies this
// interface structurally (see compat_test.go's existing pattern for
// VMTagEnsure/VMFieldsEnsure's own Client interfaces).
type VMCreateClient interface {
	// GetVM fetches vmid's current status and config on node. VMCreate
	// uses this only to detect "does something already answer to this
	// vmid" — see Read's own doc comment on why ANY error here reads as
	// "no" rather than being propagated.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// CreateVM issues PVE's create-VM call for vmid, with params as the
	// raw create parameters, returning the resulting task's UPID.
	CreateVM(ctx context.Context, vmid int, params url.Values) (string, error)
	// WaitForTask polls a PVE task (by UPID) to completion.
	WaitForTask(ctx context.Context, node, upid string) error
}

// VMCreate is idempotent-mutation-engine's Op for `vm create`
// (pveforge-vm-lifecycle-ops): ensure VMID exists as a VM, creating it
// from Params if it doesn't yet.
//
// Params is the caller-validated, already form-shaped set of raw PVE
// create parameters (net0, ipconfig0, agent, tags, cores, memory, scsi0,
// ...) — NOT a structured create-options type, mirroring VMFieldsEnsure's
// own raw/schema-free precedent (vm set's whole reason for existing:
// "nothing about our exotic device configuration is fought by an
// opinionated schema" — PRD §3.3). Tags are handled with no special
// casing at all: the caller simply puts a "tags" key in Params before
// calling Apply, exactly like any other create parameter — PVE sets tags
// atomically as part of the same create call, so there is no separate
// post-create tag write the way VMTagEnsure needs for an EXISTING VM.
// Likewise, "agent=1" (a config-time-only field) is entirely a caller
// responsibility reflected in Params — this Op enforces nothing about it;
// the one structural correctness issue this Op DOES own is netN/ipconfigN
// pairing (see Validate).
//
// A ReReader and a PostApplier (pveforge-post-apply-verification-and-
// pending, P3): Read's any-error-is-absent contract holds before the create
// only; the re-read after it is ReRead, which tells PVE's own "no such VM"
// from a read that failed, and PostApply reports a create whose task
// succeeded but whose VM is then not found.
type VMCreate struct {
	Client VMCreateClient
	VMID   int
	Params url.Values

	// createdMissing is ReRead's finding that PVE answered "no such VM"
	// after the create, consumed by PostApply without another request.
	createdMissing bool
}

var (
	_ ReReader    = (*VMCreate)(nil)
	_ PostApplier = (*VMCreate)(nil)
)

// CreatedNotFoundError is VMCreate.PostApply's error: the create task
// reported success, yet the re-read after it found PVE answering that the
// VM does not exist. Advisory, through Result.PostApplyErr.
type CreatedNotFoundError struct{ VMID int }

func (e *CreatedNotFoundError) Error() string {
	return fmt.Sprintf("vm create: vm %d: the create task succeeded but PVE then reported the vm does not exist", e.VMID)
}

// Validate reports whether op.Params is well-formed: every ipconfigN key
// present must have a matching netN key also present.
//
// This matters because an orphan ipconfigN — a static IP config with no
// corresponding network interface to attach it to — does not fail loudly
// on PVE's side; it silently leaves that interface without networking,
// exactly the kind of "command exits 0 but did something other than what
// was asked" failure mode this project's other Ops (VMFieldsEnsure,
// VMTagEnsure) already go out of their way to avoid. Checking it here,
// client-side, catches it before the create call is ever made.
//
// Exported and standalone — NOT inlined into Apply — specifically because
// idempotent.Run calls Satisfied before Apply and skips Apply entirely
// once VMID is already satisfied (Run's own documented no-op path): a
// caller that wants this validation enforced even on that already-
// satisfied path (so a malformed Params on a vmid that happens to already
// exist doesn't silently pass unnoticed) must call Validate itself ahead
// of the Read/Satisfied/Apply cycle, the same way cmd/pveforge's `vm set`
// command explicitly calls VMFieldsEnsure.Validate before idempotent.Run
// rather than relying on Apply's own internal call.
func (op *VMCreate) Validate() error {
	netIdx := make(map[int]bool)
	for key := range op.Params {
		if n, ok := interfaceIndexFromKey(key, "net"); ok {
			netIdx[n] = true
		}
	}
	for key := range op.Params {
		n, ok := interfaceIndexFromKey(key, "ipconfig")
		if !ok {
			continue
		}
		if !netIdx[n] {
			return fmt.Errorf("vm create: vm %d: ipconfig%d has no matching net%d", op.VMID, n, n)
		}
	}
	return nil
}

// interfaceIndexFromKey extracts N from a PVE per-interface config key
// shaped "<prefix>N" (e.g. interfaceIndexFromKey("net0", "net") -> 0,
// true; interfaceIndexFromKey("ipconfig3", "ipconfig") -> 3, true). ok is
// false for anything that isn't exactly prefix followed by one or more
// ASCII digits and nothing else — a different prefix entirely, a bare
// prefix with no digits, or a non-numeric/mixed suffix.
func interfaceIndexFromKey(key, prefix string) (n int, ok bool) {
	suffix := strings.TrimPrefix(key, prefix)
	if suffix == key || suffix == "" {
		return 0, false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Read reports whether VMID already answers to something on this client's
// node, via Client.GetVM. ANY error from GetVM — not found, a transient
// network failure, an auth problem, anything — is treated as "VM does not
// exist yet" and Read returns ("", nil), never an error: Apply's own
// CreateVM call is the only authoritative existence check this Op relies
// on, and a real vmid collision surfaces there with PVE's own verbatim
// error text (preserved end-to-end by RawRequest) rather than through any
// inference Read might have drawn from GetVM's failure mode. Treating a
// GetVM error as anything other than "doesn't exist" here would risk the
// opposite mistake: a transient GetVM failure (a momentary network blip)
// incorrectly reporting a real, already-created VM as failed-to-read
// rather than letting Satisfied correctly find it already there.
//
// A successful GetVM marshals the whole returned *proxmox.VirtualMachine
// as the comparable "current state" string — its only real requirement is
// "non-empty when the VM exists", which Satisfied alone consumes.
func (op *VMCreate) Read(ctx context.Context) (string, error) {
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		return "", nil
	}
	b, err := json.Marshal(vm)
	if err != nil {
		return "", fmt.Errorf("vm create: vm %d: encode current state: %w", op.VMID, err)
	}
	return string(b), nil
}

// Satisfied reports whether current is non-empty — i.e. whether Read
// found something already answering to VMID. Re-running `vm create`
// against an already-created VMID is idempotent-satisfied: it is never
// re-created, regardless of whether its config happens to match Params
// (this Op has no concept of "drift" the way VMFieldsEnsure does — `vm
// set` is the tool for reconciling an existing VM's fields).
func (op *VMCreate) Satisfied(current string) bool {
	return current != ""
}

// Apply validates op (see Validate) before touching anything else, then
// creates the VM and waits for PVE's create task to finish.
//
// Tags need no separate handling here: the caller having already put a
// "tags" key in op.Params before calling Apply is the entire mechanism —
// see this type's own doc comment.
func (op *VMCreate) Apply(ctx context.Context) error {
	if err := op.Validate(); err != nil {
		return err
	}

	upid, err := op.Client.CreateVM(ctx, op.VMID, op.Params)
	if err != nil {
		return fmt.Errorf("vm create: vm %d: %w", op.VMID, err)
	}

	if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		return fmt.Errorf("vm create: vm %d: %w", op.VMID, err)
	}
	return nil
}

// ReRead is Run's re-read after a successful Apply, and only that (see
// ReReader). Unlike Read it does not read every GetVM error as "absent":
//   - the VM is present: its marshalled state, as Read gives it;
//   - PVE's own answer that this vmid's config does not exist
//     (isMissingVMError, the same classifier VMDestroy uses): "" — absent,
//     recorded for PostApply;
//   - any other error: that error, which Run reports as Result.AfterErr,
//     because a read that failed says nothing about whether the VM exists.
//
// NOT verified against a live host, owed to pveforge-nested-pve-test-
// harness: what PVE 9.2 answers for a missing vmid's status/current (see
// pve.NotFound's caveat), and that a VM whose create task reported OK is
// readable at once, so that "absent" here is never a false alarm.
func (op *VMCreate) ReRead(ctx context.Context) (string, error) {
	op.createdMissing = false
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.VMID)
	if err != nil {
		if isMissingVMError(err, op.VMID) {
			op.createdMissing = true
			return "", nil
		}
		return "", fmt.Errorf("vm create: vm %d: %w", op.VMID, err)
	}
	b, err := json.Marshal(vm)
	if err != nil {
		return "", fmt.Errorf("vm create: vm %d: encode current state: %w", op.VMID, err)
	}
	return string(b), nil
}

// PostApply reports a *CreatedNotFoundError when ReRead found PVE saying
// the VM just created does not exist. It makes no request of its own; when
// ReRead failed instead, it returns nil, because Result.AfterErr already
// says the result could not be re-read.
func (op *VMCreate) PostApply(context.Context) error {
	if op.createdMissing {
		return &CreatedNotFoundError{VMID: op.VMID}
	}
	return nil
}
