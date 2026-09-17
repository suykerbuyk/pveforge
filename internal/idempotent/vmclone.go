package idempotent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	proxmox "github.com/luthermonson/go-proxmox"
)

// VMCloneClient is the subset of *pve.RoutedClient a VM-clone Op needs: a
// typed read (to detect whether the NEW vmid is already taken), Node (to
// scope the read, the raw config read, and WaitForTask), RawRequest (to
// read the SOURCE VM's raw config for its boot-disk storage — the same
// raw-config-read idiom VMFieldsEnsure uses, and for the same reason: the
// disk key is itself caller-supplied, e.g. "scsi0"/"virtio0", so
// go-proxmox's typed VirtualMachineConfig cannot answer for an arbitrary
// name), StorageType (the linked-clone pre-check's whole mechanism), the
// clone call itself, and WaitForTask to block until PVE's asynchronous
// clone task finishes. *pve.RoutedClient satisfies this interface
// structurally (see compat_test.go).
type VMCloneClient interface {
	// GetVM fetches vmid's current status and config on node. VMClone
	// uses this only to detect "does something already answer to
	// NewVMID" — see Read's own doc comment on why ANY error here reads
	// as "no" rather than being propagated.
	GetVM(ctx context.Context, node string, vmid int) (*proxmox.VirtualMachine, error)
	// Node returns the PVE node name this client is scoped to.
	Node() string
	// RawRequest issues a raw PVE REST call — see pve.RoutedClient.RawRequest's
	// own doc comment. VMClone uses this only to read the SOURCE VM's raw
	// config for the linked-clone storage pre-check.
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
	// StorageType resolves a storage's backend type string on node.
	// REQUIRED in this interface, not merely convenient: Apply's
	// linked-clone pre-check calls it through Client, and without this
	// entry (plus pve.RoutedClient's own pass-through) the check this
	// whole Op exists for cannot be written at all (Chair review,
	// 2026-09-14).
	StorageType(ctx context.Context, node, storageID string) (string, error)
	// CloneVM clones sourceVMID into newVMID, returning the task's UPID.
	CloneVM(ctx context.Context, sourceVMID, newVMID int, params url.Values) (string, error)
	// WaitForTask polls a PVE task (by UPID) to completion.
	WaitForTask(ctx context.Context, node, upid string) error
}

// VMClone is idempotent-mutation-engine's Op for `vm clone`
// (pveforge-vm-lifecycle-ops item 2b): ensure NewVMID exists as a VM,
// cloning it from SourceVMID if it doesn't yet.
//
// Shares VMCreate's Op shape exactly — existence-based Read/Satisfied at
// the NEW vmid, a UPID-returning clone call handed straight to
// WaitForTask — and adds one thing VMCreate has no analogue for: a
// client-side LINKED-CLONE STORAGE PRE-CHECK that refuses before the
// clone call is ever made (see Apply).
//
// The check covers EVERY disk the clone will copy, not one nominated disk.
// PVE clones all of a VM's disks, so a check that looked at only one of
// them would not be a guard: a source with scsi0 on lvmthin and scsi1 on
// nfs, cloned onto lvmthin, would pass on scsi0 while PVE silently
// full-cloned scsi1 — the exact hazard this Op exists to prevent, one disk
// over from where the guard was looking. (Executed against an earlier,
// single-disk revision of this Op; scope widened by operator decision,
// 2026-09-17. The vault task body still describes the single-disk design
// and is stale on this point.)
//
// The pre-check is deliberately conservative: storage Type strings must
// match EXACTLY. PVE's real linked-clone storage-family compatibility
// matrix (which Type pairs actually support a linked clone vs. silently
// force a full one) is UNVERIFIED against a live host as of this writing,
// so this errs toward a false-positive refusal — rejecting a linked clone
// PVE might have allowed — rather than a false negative, which is the
// hazard that actually matters here: silently letting a FULL clone
// through unannounced when the caller asked for a linked one, consuming
// the source's full disk footprint with no indication anything differed
// from what was asked. Do not loosen this into a compatibility table
// without confirming the real matrix against qa-pve-01/qa-pve-02 first.
type VMClone struct {
	Client VMCloneClient
	// SourceVMID is the VM being cloned FROM; it appears in the clone
	// call's own URL path.
	SourceVMID int
	// NewVMID is the VM being cloned TO — already resolved by the caller
	// (via NextVMID) before this Op is constructed, never left for the
	// library to fill in. Read/Satisfied check existence at THIS vmid.
	NewVMID int
	// Params carries the raw PVE clone parameters — full, storage,
	// target, name, pool, snapname. "newid" need not be present: CloneVM
	// stamps NewVMID onto the form authoritatively either way.
	Params url.Values
}

// Read reports whether NewVMID already answers to something on this
// client's node, via Client.GetVM. ANY error from GetVM — not found, a
// transient network failure, an auth problem, anything — is treated as
// "VM does not exist yet" and Read returns ("", nil), never an error:
// Apply's own CloneVM call is the only authoritative existence check this
// Op relies on, and a real vmid collision surfaces there with PVE's own
// verbatim error text (preserved end-to-end by RawRequest) rather than
// through any inference Read might have drawn from GetVM's failure mode.
// Treating a GetVM error as anything other than "doesn't exist" here
// would risk the opposite mistake: a transient GetVM failure incorrectly
// reporting a real, already-cloned VM as failed-to-read rather than
// letting Satisfied correctly find it already there. Verbatim the same
// reasoning as VMCreate.Read's, and for the same reason.
func (op *VMClone) Read(ctx context.Context) (string, error) {
	vm, err := op.Client.GetVM(ctx, op.Client.Node(), op.NewVMID)
	if err != nil {
		return "", nil
	}
	b, err := json.Marshal(vm)
	if err != nil {
		return "", fmt.Errorf("vm clone: vm %d: encode current state: %w", op.NewVMID, err)
	}
	return string(b), nil
}

// Satisfied reports whether current is non-empty — i.e. whether Read
// found something already answering to NewVMID. Re-running `vm clone`
// against an already-populated NewVMID is idempotent-satisfied: it is
// never re-cloned, regardless of whether that VM actually came from
// SourceVMID (this Op has no concept of drift, matching VMCreate).
func (op *VMClone) Satisfied(current string) bool {
	return current != ""
}

// Apply runs the linked-clone storage pre-check FIRST — refusing before
// Client.CloneVM is called at all if it fails — then clones and waits for
// PVE's clone task to finish.
//
// The ordering is the entire point, not an implementation detail: a
// refusal that happened AFTER the clone call would be worthless, since
// the mismatched clone would already be running server-side. Nothing in
// this method may be reordered ahead of the check.
//
// A duplicate "full" key is refused before any of this, since Params is
// multi-valued and Get would silently consult only the first (see below).
//
// The check runs only when Params's "full" is not "1" — i.e. on the
// LINKED-clone path, which is also PVE's own default when "full" is unset
// entirely, so an unset "full" is treated as a linked clone rather than
// assumed harmless. A full clone (full=1) skips the check entirely: it
// copies the disks outright and has no linked-clone storage-family
// constraint to enforce, so applying the check there would refuse
// perfectly valid cross-storage-type full clones for no reason.
func (op *VMClone) Apply(ctx context.Context) error {
	// A duplicate "full" is refused outright rather than resolved. Params
	// is a url.Values — a multi-valued map — and Get returns only the
	// FIRST value, so Add("full","1") followed by Add("full","0") would
	// read as a full clone here and skip the storage check entirely, while
	// the wire carried "full=1&full=0" and PVE decided for itself which
	// duplicate to honour. Which one PVE's parameter parser takes is NOT
	// verified against a live host, exactly like the storage-family matrix
	// this Op's whole pre-check is conservative about; an unverifiable
	// input must therefore refuse rather than be guessed at, or the guard
	// can be bypassed completely by any caller that builds Params with Add
	// instead of Set, or merges two parameter maps (found by independent
	// review, executed: the clone reached CloneVM with mismatched storage
	// and StorageType never consulted at all).
	if len(op.Params["full"]) > 1 {
		return fmt.Errorf(
			"vm clone: vm %d to %d: %q specified %d times (%v); pveforge cannot tell which value PVE would honour, so pass exactly one",
			op.SourceVMID, op.NewVMID, "full", len(op.Params["full"]), op.Params["full"])
	}

	if op.Params.Get("full") != "1" {
		if err := op.checkLinkedCloneStorage(ctx); err != nil {
			return err
		}
	}

	upid, err := op.Client.CloneVM(ctx, op.SourceVMID, op.NewVMID, op.Params)
	if err != nil {
		return fmt.Errorf("vm clone: vm %d to %d: %w", op.SourceVMID, op.NewVMID, err)
	}

	if err := op.Client.WaitForTask(ctx, op.Client.Node(), upid); err != nil {
		return fmt.Errorf("vm clone: vm %d to %d: %w", op.SourceVMID, op.NewVMID, err)
	}
	return nil
}

// checkLinkedCloneStorage resolves the storage type of EVERY disk the
// clone will copy and the requested TARGET storage's type, and returns an
// error unless all of them match exactly.
//
// Returns nil immediately when Params carries no "storage" key: with no
// target storage requested, PVE clones onto each disk's own storage, so
// source and target are the same storage by construction — identical type,
// nothing to compare. That is not a loosening of the guard, it is the
// absence of two different storages to guard between; refusing here would
// reject the single most common linked-clone invocation there is.
//
// Every OTHER way this check can fail to reach a verdict — a disk-shaped
// key whose value will not parse, a storage that will not resolve — returns
// an error rather than proceeding. That asymmetry is the load-bearing rule
// of the all-disks design: SKIPPING anything the check cannot understand
// would reintroduce exactly the false negative widening the check exists to
// close, while making the guard look more thorough than before. Weaker in
// fact, stronger in appearance, is the worst available outcome here.
//
// A source with no disk-shaped keys at all returns nil. That is not a
// skipped verdict, and it rests on TWO refusals upstream rather than one:
// an unparseable disk refuses rather than being dropped, AND an empty or
// unusable config body refuses rather than reading as a disk-free VM (see
// sourceDisks). With both in place an empty disk set genuinely means the
// config was read, was populated, and named no disks — a diskless VM, or
// one whose only drive is a CD-ROM — and such a clone has no
// storage-family constraint to enforce.
func (op *VMClone) checkLinkedCloneStorage(ctx context.Context) error {
	targetStorage := op.Params.Get("storage")
	if targetStorage == "" {
		return nil
	}

	disks, err := op.sourceDisks(ctx)
	if err != nil {
		return err
	}
	if len(disks) == 0 {
		return nil
	}

	node := op.Client.Node()
	targetType, err := op.Client.StorageType(ctx, node, targetStorage)
	if err != nil {
		return fmt.Errorf("vm clone: vm %d to %d: resolve target storage %q: %w", op.SourceVMID, op.NewVMID, targetStorage, err)
	}

	// Memoized: several disks commonly share one storage, and re-resolving
	// it per disk would multiply REST calls for no added information.
	seen := make(map[string]string, len(disks))
	for _, d := range disks {
		sourceType, ok := seen[d.storage]
		if !ok {
			sourceType, err = op.Client.StorageType(ctx, node, d.storage)
			if err != nil {
				return fmt.Errorf("vm clone: vm %d to %d: %s: resolve source storage %q: %w", op.SourceVMID, op.NewVMID, d.key, d.storage, err)
			}
			seen[d.storage] = sourceType
		}
		if sourceType != targetType {
			// A detached (unusedN) disk gets its own wording. It is the
			// refusal most likely to baffle: the VM's LIVE disks can all
			// match the target perfectly and the clone still stops, over a
			// volume the user thinks they already moved off. Saying only
			// "disk unused0" invites the reading that something is wrong
			// with a disk in use, and the generic "pass full=1" remedy
			// points at a different operation entirely — a full clone
			// copies every disk outright, which is not what someone who
			// just wants their leftover ignored is asking for.
			if _, detached := interfaceIndexFromKey(d.key, "unused"); detached {
				return fmt.Errorf(
					"vm clone: vm %d to %d: linked clone requires matching storage types, and %s — a DETACHED disk still listed in the source vm's config, not a disk in use — is %q (storage %q) while target storage %q is %q. pveforge checks detached disks because whether pve copies them on a clone is not verified; to proceed, either remove %s from vm %d (pve: Hardware -> select the unused disk -> Remove) or pass full=1 for a full clone",
					op.SourceVMID, op.NewVMID, d.key, sourceType, d.storage, targetStorage, targetType, d.key, op.SourceVMID)
			}
			return fmt.Errorf(
				"vm clone: vm %d to %d: linked clone requires matching storage types, but disk %s is %q (storage %q) while target storage %q is %q; pass full=1 for a full clone across storage types",
				op.SourceVMID, op.NewVMID, d.key, sourceType, d.storage, targetStorage, targetType)
		}
	}
	return nil
}

// sourceDisk is one disk-shaped entry of the source VM's config, paired
// with the storage id its volume lives on.
type sourceDisk struct {
	key     string
	storage string
}

// diskKeyPrefixes are the config-key prefixes that carry a disk volume.
//
// Derived, not assumed: go-proxmox models PVE's repeating config keys as
// separate maps (types.go:1074-1085) and splits them into disk-bearing
// groups — IDEs, SCSIs, SATAs, VirtIOs, Unuseds — and non-disk-bearing ones
// — Nets, Numas, HostPCIs, Serials, USBs, Parallels, IPConfigs. The two
// disk-bearing SINGLETONS are separate typed fields, EFIDisk0 ("efidisk0")
// and TPMState0 ("tpmstate0"). This list is exactly that disk-bearing set,
// and nothing else in that model carries a storage volume.
//
// Matching is prefix-then-pure-digits (via interfaceIndexFromKey, shared
// with VMCreate.Validate) — the same rule go-proxmox uses for the same
// reason it documents at types.go:1182: it keeps "scsihw", which shares the
// "scsi" prefix but has no numeric suffix, from being read as a disk.
//
// "unused" is included DELIBERATELY (operator ruling, 2026-09-17: the check
// STAYS — dropping it would reopen a real hole if PVE does copy detached
// disks, which is unverified). This is the one entry whose PVE behaviour is
// not verified: an unusedN entry is a disk detached from the
// VM but still present in its config, and whether PVE copies it on a clone
// has NOT been confirmed against a live host. Including it is safe under
// either answer, which is why it is not a guess: if PVE does copy such a
// disk, checking it is necessary and correct; if PVE does not, checking it
// can only ever produce the false-positive refusal this Op explicitly
// prefers — and only when the detached disk's storage family actually
// mismatches, never merely because one exists. Ignoring it instead would be
// the one unsafe option.
//
// HOW OFTEN THAT FALSE REFUSAL ACTUALLY FIRES is higher than the paragraph
// above suggests, and the reason is structural rather than statistical: the
// two conditions are CORRELATED. PVE's "Move disk" is what creates an
// unusedN entry in the first place — it leaves the source volume attached as
// unusedN whenever "Delete source" is left unchecked, the GUI default — and
// moving a disk ACROSS storage families is exactly the migration people
// perform. So the leftover is typically sitting on the old family by
// construction, and a VM whose live disks all match the clone target can
// still be refused over it, on every subsequent clone, until someone
// detaches it. The refusal above is therefore worded specifically for this
// case rather than sharing the generic one; a guard that fires on ordinary
// VMs with an unactionable message is a guard people switch off, which is
// the same worry that makes the CD-ROM skip precise.
//
// This is consequently the PRIORITY question for the nested-PVE harness: if
// PVE does not copy unusedN entries on a clone, "unused" comes out of this
// list and the false refusals disappear entirely. Until that is measured,
// fail-closed stands.
var diskKeyPrefixes = []string{"scsi", "virtio", "sata", "ide", "efidisk", "tpmstate", "unused"}

// isDiskKey reports whether a raw-config key names a disk slot.
func isDiskKey(key string) bool {
	for _, prefix := range diskKeyPrefixes {
		if _, ok := interfaceIndexFromKey(key, prefix); ok {
			return true
		}
	}
	return false
}

// sourceDisks reads the SOURCE VM's raw config and returns every
// disk-shaped entry paired with the storage id its volume lives on,
// ordered by key so a refusal names the same disk run after run.
//
// CD-ROM entries are skipped: "ide2: local:iso/debian.iso,media=cdrom" is
// an image mounted in a drive, not a disk being copied, and PVE regenerates
// a cloud-init drive on the target rather than cloning it. Treating those
// as disks would refuse perfectly ordinary VMs whose ISO happens to sit on
// a different storage family — and a guard that cries wolf is a guard
// people switch off.
//
// Anything else that cannot be parsed into "<storage>:<volume>" is an
// ERROR, never a skipped entry — see checkLinkedCloneStorage's own doc
// comment on why skipping is the one thing this design must not do.
//
// Goes through RawRequest against the same /config endpoint VMFieldsEnsure
// reads, not the typed GetVM getter, for VMFieldsEnsure's own documented
// reason: go-proxmox's typed VirtualMachineConfig models only a fixed,
// curated subset of PVE's config keys.
func (op *VMClone) sourceDisks(ctx context.Context) ([]sourceDisk, error) {
	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(op.Client.Node()), op.SourceVMID)
	raw, err := op.Client.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("vm clone: vm %d to %d: read source config: %w", op.SourceVMID, op.NewVMID, err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("vm clone: vm %d to %d: read source config: parse: %w", op.SourceVMID, op.NewVMID, err)
	}
	// An EMPTY config map means the body was unusable, not that the VM has
	// nothing configured: a real QEMU config always carries non-disk keys
	// (digest, boot, smbios1, ...). Two shapes land here with no error at
	// all, which is why this needs its own check rather than relying on the
	// Unmarshal above:
	//
	//   - JSON "null" — unmarshalling null into a map is a documented no-op
	//     in encoding/json, leaving fields nil. RawRequest's own
	//     unwrapDataEnvelope (internal/pve/rawrequest.go) returns exactly
	//     json.RawMessage("null") for an ENTIRELY EMPTY HTTP body as well as
	//     for {"data":null}, so a PVE 200 with no body arrives here.
	//   - "{}" — a truncated or partial config object.
	//
	// Without this, both produced zero disks, and an empty disk set read as
	// "diskless, nothing to enforce" — silently skipping the whole check and
	// letting a linked clone across incompatible storage families proceed.
	// That is the exact false negative this check exists to close, one level
	// up from the disk entry: found by independent review, executed, and a
	// REGRESSION introduced by widening the check from a single named field
	// (whose map lookup simply missed on a nil map, and refused) to an
	// iteration, where iterating nothing is indistinguishable from a VM that
	// genuinely has no disks. Distinguishing the two is the whole job here:
	// a populated config with no disk-shaped keys still proceeds (see
	// checkLinkedCloneStorage), an unusable body does not.
	if len(fields) == 0 {
		return nil, fmt.Errorf("vm clone: vm %d to %d: read source config: pve returned an empty config for the source vm; refusing rather than treating an unreadable config as a vm with no disks", op.SourceVMID, op.NewVMID)
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		if isDiskKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	disks := make([]sourceDisk, 0, len(keys))
	for _, key := range keys {
		var value string
		if err := json.Unmarshal(fields[key], &value); err != nil {
			return nil, fmt.Errorf("vm clone: vm %d to %d: disk %s: unexpected value %s: %w", op.SourceVMID, op.NewVMID, key, fields[key], err)
		}
		if isCDROM(value) {
			continue
		}
		volume, _, _ := strings.Cut(value, ",")
		// Cut at the FIRST ':' — a PVE volume id is always
		// "<storage>:<volume>", and the storage id itself never contains a
		// colon. Cutting at the first one (rather than splitting on every
		// colon and taking field 0) keeps a volume portion that somehow
		// carries its own colon intact in the discarded remainder, so it
		// can never shift what counts as the storage.
		storage, _, found := strings.Cut(volume, ":")
		if !found || storage == "" {
			return nil, fmt.Errorf("vm clone: vm %d to %d: disk %s value %q has no \"<storage>:\" prefix to resolve a storage type from", op.SourceVMID, op.NewVMID, key, value)
		}
		disks = append(disks, sourceDisk{key: key, storage: storage})
	}
	return disks, nil
}

// isCDROM reports whether a disk-slot value is a CD-ROM/ISO mount rather
// than a disk being cloned — PVE marks these with a "media=cdrom" option.
func isCDROM(value string) bool {
	for _, opt := range strings.Split(value, ",") {
		if strings.TrimSpace(opt) == "media=cdrom" {
			return true
		}
	}
	return false
}
