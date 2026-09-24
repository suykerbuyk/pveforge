package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// currentPseudoSnapshot is the name PVE gives the synthetic entry its
// snapshot-list endpoint always returns alongside the real snapshots. It
// represents the live running state ("You are here!"), not a snapshot
// anything can be created as, rolled back to, or deleted — confirmed
// against go-proxmox's own recorded PVE 9.x fixture
// (tests/mocks/pve9x/virtual_machines.go:898-925), where it appears with
// snaptime 0 and neither a parent nor a vmstate field.
//
// Every consumer that reasons about "the snapshots that exist" must
// exclude it — see realSnapshots.
const currentPseudoSnapshot = "current"

// pendingReservedName is the other snapshot name PVE reserves: a VM's
// config file keeps its pending changes in a section named [PENDING], so a
// snapshot section of that name would collide with it. Unlike "current" it
// is not a list entry — PVE never creates a snapshot by that name — so only
// CreateSnapshot refuses it; the destructive paths (isPseudoEntryName) have
// nothing named "pending" to meet.
//
// UNVERIFIED against a live host, owed to pveforge-nested-pve-test-harness
// (from a reading of PVE's source, not observed): qemu-server's snapshot
// create refuses lc($snapname) eq 'pending', i.e. in any case. Refusing it
// here, before any request, is safe whether or not PVE does: the worst case
// is refusing a name PVE would have allowed.
const pendingReservedName = "pending"

// isPseudoEntryName reports whether name, trimmed, is exactly the "current"
// pseudo-entry. It is the reserved-name guard of the three DESTRUCTIVE-path
// primitives — NewerSnapshots, Rollback and CascadeDeleteSnapshots — which
// must refuse the pseudo-entry but must still reach every REAL snapshot,
// including one named "Current": case-folding here made such a snapshot a
// dead end (it counted as newer, via realSnapshots, and then could be
// neither deleted nor rolled back to). Exact, like realSnapshots, because
// PVE's own pseudo-entry is always exactly "current".
//
// Trimmed because no real snapshot name can carry whitespace, so refusing
// a padded " current" loses nothing and keeps it off the network.
//
// CreateSnapshot deliberately does NOT use this: refusing to CREATE any
// case variant of "current" is a conservative policy of its own (see its
// guard), and the asymmetry is intended.
//
// UNVERIFIED against a live host, owed to pveforge-nested-pve-test-harness
// (from a reading of PVE's source, not observed): PVE's snapshot names are
// pve-configid, ^[a-z][a-z0-9_]{1,40}$ case-insensitively, so "Current" is a
// legal name; qemu-server's snapshot create refuses only $snapname eq
// 'current' (exact), so "Current" can be created through the web UI or qm.
// If PVE in fact refuses "Current" too, nothing here is wrong: a "Current"
// target is then simply not found after one list read, and nothing
// destructive is sent.
func isPseudoEntryName(name string) bool {
	return strings.TrimSpace(name) == currentPseudoSnapshot
}

// ListSnapshots returns every entry PVE reports for vmid's snapshot list —
// GET /nodes/{node}/qemu/{vmid}/snapshot — INCLUDING the synthetic
// "current" pseudo-entry. The raw list is deliberately what this returns:
// filtering is realSnapshots' job, kept separate so a caller that
// genuinely wants to see the whole list as PVE reports it (a `snapshot
// list` command rendering the chain, say) still can. The one thing it
// refuses is a {"data":null} payload, which is no list at all: that is
// ErrUnverifiableRead, never an empty list. A legitimately empty [] is
// returned as is.
//
// Goes through c.pc.Get rather than RawRequest — this is a plain read, and
// reads in this package go through go-proxmox while writes go through
// RawRequest (see rawrequest.go's own doc comment for why the write path
// is separate; the 500/501 body-discarding bug that forces it only matters
// where PVE's diagnostic text is the point).
//
// Decodes into go-proxmox's own *proxmox.VirtualMachineSnapshot for the
// read side only. That struct carries an unexported client field plus
// exported Node/VMID fields (all tagged json:"-"), which go-proxmox's own
// VirtualMachine.Snapshots populates after decoding and this method
// deliberately does not: they stay nil/zero here, exactly as GetVM leaves
// *proxmox.VirtualMachine's client nil (see vms.go). Never call the
// returned values' instance methods (Rollback, Delete, Config,
// UpdateConfig, SubResources) — every one of them routes through the nil
// client and through the same handleResponse this package avoids.
func (c *Client) ListSnapshots(ctx context.Context, node string, vmid int) ([]*proxmox.VirtualMachineSnapshot, error) {
	if node == "" {
		return nil, fmt.Errorf("list snapshots for vm %d: node is required", vmid)
	}
	var snaps []*proxmox.VirtualMachineSnapshot
	path := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", url.PathEscape(node), vmid)
	if err := c.pc.Get(ctx, path, &snaps); err != nil {
		return nil, fmt.Errorf("list snapshots for vm %d: %w", vmid, err)
	}
	if snaps == nil {
		return nil, fmt.Errorf("list snapshots for vm %d: %w: list payload was null", vmid, ErrUnverifiableRead)
	}
	return snaps, nil
}

// realSnapshots drops the "current" pseudo-entry from a ListSnapshots
// result, leaving only snapshots that actually exist on disk. Shared by
// CreateSnapshot's collision check and its post-create verification, and
// intended for every later consumer that asks "what snapshots does this VM
// have" (the rollback side's newest-check and cascade ordering included).
//
// Returns a new slice; the input is never modified. A nil or empty input
// yields an empty, non-nil slice.
//
// This filter makes TWO exclusions, and both are load-bearing at every
// call site:
//
//  1. The "current" pseudo-entry, by name.
//  2. Any nil element. PVE's snapshot list is decoded into a slice of
//     POINTERS, so a JSON null in the array — `{"data":[null, ...]}` —
//     decodes to a nil element. Every caller that reaches for s.Name
//     without this filter dereferences that nil and PANICS, in a codebase
//     with no panic recovery anywhere outside its test files. This is not
//     hypothetical defense in depth: it is the only thing standing between
//     a malformed list response and a crash, and it is what makes calling
//     realSnapshots inside CreateSnapshot's own two loops mandatory rather
//     than redundant. An earlier revision of this comment argued those two
//     calls were unreachable belt-and-braces because the reserved-name
//     guard already rejects "current" first. That was wrong: it reasoned
//     about exclusion (1) and forgot exclusion (2), which no name-based
//     guard upstream can substitute for.
//
// Deliberate asymmetry with CreateSnapshot's reserved-name guard, which
// compares trimmed and case-INsensitively while this compares exactly:
// the two have opposite failure directions.
//
//   - The GUARD refuses a name. Matching too broadly is safe — the worst
//     outcome is refusing a name the caller could have been allowed.
//   - This FILTER drops an entry. Matching too broadly is UNSAFE. PVE's
//     pseudo-entry is always exactly "current", so folding case here would
//     silently remove a real snapshot named "Current" — a legitimate,
//     distinct snapshot creatable from the web UI or `qm` — from the
//     collision check and from the post-create verification alike. Hiding
//     a real snapshot is strictly worse than refusing a name.
//
// Broad where refusing, exact where dropping. Any later consumer of this
// helper (the rollback side's newest-check and cascade ordering are the
// next ones) inherits that premise and should not "fix" the asymmetry.
func realSnapshots(snaps []*proxmox.VirtualMachineSnapshot) []*proxmox.VirtualMachineSnapshot {
	real := make([]*proxmox.VirtualMachineSnapshot, 0, len(snaps))
	for _, s := range snaps {
		if s == nil || s.Name == currentPseudoSnapshot {
			continue
		}
		real = append(real, s)
	}
	return real
}

// ErrSnapshotExists reports that CreateSnapshot refused because a real
// snapshot of that name already exists on the VM. Matchable with
// errors.As against *ErrSnapshotExists.
//
// This is a proactive, client-side refusal raised BEFORE PVE's create
// endpoint is ever called — deliberately, rather than letting PVE reject
// the duplicate itself: PVE's own duplicate-name error text is unverified
// against a live host here, and a snapshot create is not the place to
// discover that the rejection arrives in some shape this project can't
// recognize.
type ErrSnapshotExists struct {
	VMID int
	Name string
}

func (e *ErrSnapshotExists) Error() string {
	return fmt.Sprintf("snapshot %q already exists on vm %d", e.Name, e.VMID)
}

// ErrReservedSnapshotName reports that a snapshot operation refused because
// the name it was given is reserved by PVE. CreateSnapshot also refuses
// "pending" (pendingReservedName), in any case; everything below is about
// "current", and the message names whichever of the two was met.
//
// "current" is PVE's pseudo-entry — matched
// trimmed and case-insensitively by CreateSnapshot, which refuses to create
// any spelling of it, and trimmed but EXACTLY by NewerSnapshots, Rollback
// and CascadeDeleteSnapshots (isPseudoEntryName), which must still reach a
// real snapshot named "Current". Matchable with errors.As against
// *ErrReservedSnapshotName. Raised by CreateSnapshot, NewerSnapshots,
// Rollback and CascadeDeleteSnapshots — which is why its message says "not
// a real snapshot" rather than naming any one operation.
//
// Deliberately a SEPARATE error type, raised by a SEPARATE guard, from
// ErrSnapshotExists above — not a special case folded into the collision
// check. The collision check runs against realSnapshots' output, which
// removes the "current" entry by construction; asking it to also catch a
// create call NAMED "current" is asking it to find an entry it just
// filtered out. An earlier draft of this design did exactly that, and the
// result was that `CreateSnapshot(..., "current", ...)` found no collision
// and fell straight through to POSTing snapname=current at PVE for real.
// Keeping this guard independent — and running it before ListSnapshots is
// called at all — means it cannot be bypassed by anything realSnapshots
// does or doesn't filter, now or later.
type ErrReservedSnapshotName struct {
	VMID int
	Name string
}

func (e *ErrReservedSnapshotName) Error() string {
	if strings.EqualFold(strings.TrimSpace(e.Name), pendingReservedName) {
		return fmt.Sprintf("snapshot name %q is reserved on vm %d: PVE keeps a VM's pending changes in a config section of that name, so no snapshot can take it", e.Name, e.VMID)
	}
	return fmt.Sprintf("snapshot name %q is reserved on vm %d: %q is PVE's own pseudo-entry for the live running state, not a real snapshot", e.Name, e.VMID, currentPseudoSnapshot)
}

// CreateSnapshot takes a snapshot of vmid on node, including the VM's RAM
// state, and does not return until PVE's own worker task has finished and
// the snapshot has been verified to exist.
//
// vmstate=1 is ALWAYS sent and is deliberately not a parameter. A snapshot
// taken without it captures disk state only: rolling back to one cannot
// restore a running VM, it can only restore its disks, which makes it a
// silently broken restore point for the running-VM case this function
// exists to serve. A caller that genuinely wants a disk-only snapshot
// needs a separate, differently named function that says so in its name —
// never a flag on this one, where the default could be flipped by a
// caller who didn't understand the consequence.
//
// description is sent only when non-empty.
//
// The write goes through RawRequest, not go-proxmox's own
// VirtualMachine.NewSnapshot, for two independent reasons: NewSnapshot
// (virtual_machine.go:868) posts only {"snapname": name} and has no
// parameter for vmstate or description at all, so it structurally cannot
// send the one parameter this function considers load-bearing; and it
// routes through handleResponse (proxmox.go:446-449), which discards the
// response body entirely on HTTP 500/501 — the statuses PVE uses for most
// create-time rejections — the same swallow every other mutating
// primitive in this package already routes around.
//
// The order of operations matters and is not incidental:
//
//  1. Reserved-name guard, BEFORE any network call at all. See
//     ErrReservedSnapshotName for why this cannot be folded into step 2.
//  2. Collision refusal against the existing real snapshots, before PVE's
//     create endpoint is ever touched. Steps 2 and 4 both read through
//     listSnapshotsVerifiable, so an empty (swallowed) list is reported as
//     an unverifiable read rather than as "no collision" or "absent".
//  3. POST, then WaitForTask on the returned UPID — PVE's snapshot create
//     is asynchronous even when it completes near-instantly.
//  4. A DUAL post-verify: the snapshot must be present in a fresh listing
//     AND carry a non-zero Vmstate. Either check alone can pass on a
//     partially-successful snapshot — a disk-only snapshot that lost its
//     RAM state still appears in the list, and a stale/rolled-back listing
//     can be missing an entry whose vmstate nothing ever looked at (cite:
//     quantum-ng snapshot.sh:398-456). Both are required.
func (c *Client) CreateSnapshot(ctx context.Context, node string, vmid int, name, description string) error {
	if node == "" {
		return fmt.Errorf("create snapshot on vm %d: node is required", vmid)
	}
	// Trimmed, for the same reason the reserved-name guard below is
	// trimmed: a name that is nothing but padding is not a name. Without
	// this, "   " clears this check, then clears the reserved-name guard
	// too (trimming to "" never equals "current"), matches no existing
	// snapshot, and reaches PVE as snapname="   ". That is the same
	// padding-defeats-a-guard class as the reserved-name bypass — and it
	// lived one line above that bypass's own fix, which is exactly how
	// this kind of gap survives a review that is looking somewhere else.
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("create snapshot on vm %d: name is required", vmid)
	}

	// Step 1. Independent of everything below it, and of whatever
	// realSnapshots filters.
	//
	// Trimmed AND case-folded, because this guard's job is to refuse, and
	// a refusal should match the concept rather than one spelling of it.
	// Deliberately broader than the destructive-path guard
	// (isPseudoEntryName, exact): refusing to CREATE "Current" costs only a
	// name, while refusing to delete or roll back to an existing "Current"
	// would strand a real snapshot.
	// " current", "current " and "\tcurrent" all reach PVE's create
	// endpoint with the padding intact if only case is normalized — and
	// "PVE will reject it anyway" is precisely the assumption this guard
	// exists in order not to depend on. The name is compared trimmed but
	// reported and sent untrimmed: this refuses padded variants, it does
	// not silently rewrite what the caller asked for.
	if strings.EqualFold(strings.TrimSpace(name), currentPseudoSnapshot) {
		return &ErrReservedSnapshotName{VMID: vmid, Name: name}
	}
	// PVE's other reserved name, refused the same way: trimmed, in any case,
	// before any request (see pendingReservedName, and its caveat).
	if strings.EqualFold(strings.TrimSpace(name), pendingReservedName) {
		return &ErrReservedSnapshotName{VMID: vmid, Name: name}
	}

	// Step 2. Through listSnapshotsVerifiable, not ListSnapshots: this is a
	// check that REFUSES on presence, so an empty read — which go-proxmox
	// hands back with a nil error for a 404/502/503/504/595-599 — would see
	// no collision and let the POST through.
	existing, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return fmt.Errorf("create snapshot %q on vm %d: %w", name, vmid, err)
	}
	for _, s := range realSnapshots(existing) {
		if s.Name == name {
			return &ErrSnapshotExists{VMID: vmid, Name: name}
		}
	}

	// Step 3.
	params := url.Values{}
	params.Set("snapname", name)
	params.Set("vmstate", "1")
	if description != "" {
		params.Set("description", description)
	}

	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/snapshot", url.PathEscape(node), vmid), params)
	if err != nil {
		return fmt.Errorf("create snapshot %q on vm %d: %w", name, vmid, err)
	}
	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return fmt.Errorf("create snapshot %q on vm %d: %w", name, vmid, err)
	}
	if err := c.WaitForTask(ctx, node, upid); err != nil {
		return fmt.Errorf("create snapshot %q on vm %d: %w", name, vmid, err)
	}

	// Step 4. Through listSnapshotsVerifiable for the reason given at step
	// 2. This check already failed closed on an empty read, but it failed
	// for the wrong reason — "absent from the snapshot list", sending an
	// operator after a snapshot that may well exist.
	after, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return fmt.Errorf("verify snapshot %q on vm %d: %w", name, vmid, err)
	}
	for _, s := range realSnapshots(after) {
		if s.Name != name {
			continue
		}
		if s.Vmstate == 0 {
			return fmt.Errorf("verify snapshot %q on vm %d: task reported success but the snapshot has no vm state captured (vmstate=0): it can restore disks only, not a running vm", name, vmid)
		}
		return nil
	}
	return fmt.Errorf("verify snapshot %q on vm %d: task reported success but the snapshot is absent from the snapshot list", name, vmid)
}

// listSnapshotsVerifiable is ListSnapshots plus one refusal: a list that
// does not contain PVE's own "current" pseudo-entry is reported as an
// UNVERIFIABLE read (ErrUnverifiableRead), never as a VM that has no
// snapshots.
//
// PVE's snapshot list always includes the "current" pseudo-entry (see
// currentPseudoSnapshot), so no response describing a live VM can lack it.
// go-proxmox's Get decodes a {"data":null} envelope into an empty list
// with a NIL error, for a 200 and, on the current pin, also for a 404,
// 502, 503, 504 or 595-599 response (measured by driving the real library
// against an httptest server; only 400, 401/403, 500 and 501 become errors
// there). ListSnapshots itself now refuses that null payload as
// ErrUnverifiableRead (pveforge-read-status-swallow's P1 guard), so it
// never reaches this check. What is left for this check is every non-null
// answer no live VM produces: an empty [] list, a list of JSON nulls, or a
// list that lacks "current".
//
// Why every snapshot read that decides something goes through this, and
// not just some of them: what a swallowed read does depends on the
// question being asked. A check that asks "is it absent?" (the cascade's
// post-verify) reads an empty list as YES and fails OPEN. A check that
// refuses on presence (CreateSnapshot's collision check, the cascade's
// pre-state) sees nothing and waves the mutation through. A check that
// asks "is it present?" (CreateSnapshot's post-verify, NewerSnapshots'
// target lookup) fails closed — but names the wrong cause, "absent" or
// "not found", and sends an operator looking for a snapshot that is there.
// All three are answered truthfully only by refusing the read itself.
//
// Requiring "current" by exact name, rather than merely a non-empty list,
// subsumes the empty list and the list made only of JSON nulls (which
// realSnapshots would reduce to exactly the empty set the absence-checks
// misread) — and also refuses a non-empty, healthy-looking list that
// nonetheless lacks "current", which no real PVE response is. The name is
// matched exactly, for realSnapshots' reason: PVE's pseudo-entry is always
// exactly "current".
//
// UNVERIFIED against a live host that PVE never omits "current". If it ever
// does, this check fails CLOSED: a spurious refusal, never a wrong answer.
//
// The refusal wraps ErrUnverifiableRead (unverifiable.go), the sentinel the
// read-status-swallow work shares, so callers match it with errors.Is
// rather than by text.
//
// ListSnapshots itself returns the raw list as PVE reported it, refusing
// only a null payload — its documented contract — and this is unexported
// because the "current" refusal is a policy of the operations below, not
// of a plain read.
func (c *Client) listSnapshotsVerifiable(ctx context.Context, node string, vmid int) ([]*proxmox.VirtualMachineSnapshot, error) {
	snaps, err := c.ListSnapshots(ctx, node, vmid)
	if err != nil {
		return nil, err
	}
	for _, s := range snaps {
		if s != nil && s.Name == currentPseudoSnapshot {
			return snaps, nil
		}
	}
	return nil, fmt.Errorf("snapshot list for vm %d has no %q pseudo-entry, which PVE always includes for a live vm: %w", vmid, currentPseudoSnapshot, ErrUnverifiableRead)
}

// ErrNotNewestSnapshot reports that Rollback refused because snapshots
// newer than the rollback target exist on the VM — snapshots a rollback
// would discard. Matchable with errors.As against *ErrNotNewestSnapshot.
//
// Like ErrSnapshotExists, this is a proactive, client-side refusal raised
// BEFORE PVE's rollback endpoint is ever called. Newer carries the blocking
// set as data, ascending (oldest-of-the-newer first), so a caller deciding
// whether to clear the way does not need a second NewerSnapshots call — a
// second read across a second race window — to recover what this refusal
// already knew. To clear it, pass CascadeOrder() (not Newer) to
// CascadeDeleteSnapshots, then retry Rollback.
type ErrNotNewestSnapshot struct {
	VMID   int
	Target string
	// Newer is ascending: oldest-of-the-newer first, the order a human
	// reads a snapshot chain in. It is NOT the order to delete in — see
	// CascadeOrder.
	Newer []string
}

func (e *ErrNotNewestSnapshot) Error() string {
	quoted := make([]string, len(e.Newer))
	for i, n := range e.Newer {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	verb := "snapshots exist"
	if len(e.Newer) == 1 {
		verb = "snapshot exists"
	}
	return fmt.Sprintf("rollback vm %d to snapshot %q refused: %d newer %s and would be discarded: %s",
		e.VMID, e.Target, len(e.Newer), verb, strings.Join(quoted, ", "))
}

// CascadeOrder returns Newer reversed — newest-first — which is the order
// CascadeDeleteSnapshots expects. Newer itself stays ascending because that
// is the order a human reads a snapshot chain in.
//
// This exists so the reversal lives in one tested place rather than at
// every call site. NewerSnapshots/Newer and CascadeDeleteSnapshots want
// opposite orders, and forwarding Newer straight into a cascade deletes
// oldest-first — which, unless PVE enforces leaf-only deletion (unverified
// against a live host), silently works. Returns a new slice; Newer is not
// modified.
func (e *ErrNotNewestSnapshot) CascadeOrder() []string {
	out := make([]string, len(e.Newer))
	for i, n := range e.Newer {
		out[len(e.Newer)-1-i] = n
	}
	return out
}

// NewerSnapshots returns every real snapshot of vmid created after target,
// sorted ascending by Snaptime (oldest-of-the-newer first). An empty result
// means target is the newest snapshot. Rollback's pre-flight is built on
// it; a caller may also use it directly to see what a rollback would
// discard.
//
// "Created after" means a strictly greater Snaptime. Snaptime is whole unix
// seconds, so two snapshots can share one — rare for CreateSnapshot's own
// vmstate snapshots (a RAM dump is not sub-second) but reachable for
// disk-only snapshots taken from the web UI or `qm`. When any other real
// snapshot shares target's Snaptime, NewerSnapshots REFUSES: it cannot tell
// which is newer, and reporting the peer as newer would invite a caller to
// cascade-delete a snapshot that may be older. It deliberately does not
// tie-break on the Parent chain, whose real shape on a live host is
// unverified (go-proxmox's mock gives "current" no parent at all) —
// guessing a chain shape in order to PERMIT a destructive operation is the
// wrong direction to be wrong in. Monotonicity of Snaptime with creation
// order is itself assumed, not verified; nothing here can detect a
// violation of it.
//
// Ties AMONG the newer snapshots (not with target) are not refused: every
// one of them is newer than target either way, so the refusal's answer —
// "these would be discarded" — is correct regardless. What a tie does leave
// ambiguous is their relative order, and therefore the order
// ErrNotNewestSnapshot.CascadeOrder hands to a cascade. The sort is stable,
// so tied entries keep the order PVE listed them in; nothing claims that
// order is chronological. If PVE enforces leaf-only deletion and the
// guessed order is wrong, the delete PVE refuses stops the cascade at its
// first failure — it fails safe. If PVE does not enforce it, the order is
// harmless.
//
// Refuses before any network call on an empty node, a blank or
// whitespace-only target, and a target naming the "current" pseudo-entry
// (*ErrReservedSnapshotName) — the same local refusals CreateSnapshot
// makes. No vmid rule: no primitive in this package has one. Reads through
// listSnapshotsVerifiable, so a swallowed read is reported as unverifiable
// rather than as "not found".
func (c *Client) NewerSnapshots(ctx context.Context, node string, vmid int, target string) ([]*proxmox.VirtualMachineSnapshot, error) {
	if node == "" {
		return nil, fmt.Errorf("newer snapshots of vm %d: node is required", vmid)
	}
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("newer snapshots of vm %d: snapshot name is required", vmid)
	}
	if isPseudoEntryName(target) {
		return nil, fmt.Errorf("newer snapshots of vm %d: %w", vmid, &ErrReservedSnapshotName{VMID: vmid, Name: target})
	}

	snaps, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("newer snapshots of vm %d: %w", vmid, err)
	}
	real := realSnapshots(snaps)

	var found *proxmox.VirtualMachineSnapshot
	for _, s := range real {
		if s.Name == target {
			found = s
			break
		}
	}
	if found == nil {
		return nil, fmt.Errorf("newer snapshots of vm %d: snapshot %q not found", vmid, target)
	}

	newer := make([]*proxmox.VirtualMachineSnapshot, 0, len(real))
	for _, s := range real {
		if s == found {
			continue
		}
		if s.Snaptime == found.Snaptime {
			return nil, fmt.Errorf("newer snapshots of vm %d: %q has the same snaptime as %q (%d); pveforge cannot determine which is newer, so this rollback cannot be pre-flighted",
				vmid, s.Name, target, found.Snaptime)
		}
		if s.Snaptime > found.Snaptime {
			newer = append(newer, s)
		}
	}
	sort.SliceStable(newer, func(i, j int) bool { return newer[i].Snaptime < newer[j].Snaptime })
	return newer, nil
}

// Rollback rolls vmid back to the snapshot name on node, and does not
// return until PVE's own worker task has finished. It NEVER deletes
// anything, under any parameter: if snapshots newer than name exist, it
// refuses with *ErrNotNewestSnapshot and the caller decides, in a separate
// and separately auditable call (CascadeDeleteSnapshots), whether to
// destroy them first.
//
// Newest-only is PVEFORGE POLICY, not a claim that this mirrors a PVE rule.
// The operator approved it in the snapshot-lifecycle epic's spec, and it
// fails in the conservative direction. Whether PVE's REST endpoint enforces
// anything similar itself is UNVERIFIED against a live host: go-proxmox's
// own VirtualMachineSnapshot.Rollback is a bare, unconditional POST. It is
// recalled, also UNVERIFIED, that PVE's ZFS storage plugin refuses rollback
// to a snapshot that is not the most recent (volume_rollback_is_possible:
// "can't rollback, '<snap>' is not most recent snapshot") while qcow2 and
// LVM-thin permit it — if so, newest-only is a real PVE rule on ZFS-backed
// disks and pveforge policy everywhere else. Either way the client-side
// check below may be the ONLY protection on a given host, so a rollback
// that must bypass it goes through the raw escape hatch deliberately:
// `pveforge api post /nodes/{node}/qemu/{vmid}/snapshot/{snap}/rollback`.
//
// The pre-flight and the POST are a check-then-act with no lock between
// them: a snapshot created on the same VM in that window invalidates the
// check. Closing that needs ONE lock.Mutation hold (Kind "vm") spanning
// pre-flight, any cascade, and this call — see the task's own TOCTOU note.
// This primitive sits below the locking layer and cannot take it itself.
//
// Order of operations:
//
//  1. Local refusals before any network call: node, a blank or
//     whitespace-only name, and the reserved "current" name.
//  2. NewerSnapshots — refuse with *ErrNotNewestSnapshot if non-empty,
//     WITHOUT calling PVE's rollback endpoint at all.
//  3. POST .../snapshot/{name}/rollback through RawRequest (not go-proxmox's
//     VirtualMachineSnapshot.Rollback, which routes through the
//     body-discarding handleResponse), then WaitForTask on the returned UPID.
//
// There is no post-verify beyond WaitForTask's own exit-status check
// (*TaskFailedError), deliberately. The only list-observable trace of a
// rollback would be the "current" entry's Parent — a shape unverified on a
// live host — and a guard built on a guessed shape would fail correct
// rollbacks. Proof that the guest's state really was restored is the
// in-guest witness's job (pveforge-vm-rollback-witness), not this one's.
//
// PVE's rollback "start" parameter is deliberately not sent; PVE's own
// default (unverified here) applies.
func (c *Client) Rollback(ctx context.Context, node string, vmid int, name string) error {
	// These three repeat NewerSnapshots' own refusals on purpose, and wrap
	// with this operation's prefix so the two are distinguishable: without
	// its own guards, Rollback's refusals would come from the callee — the
	// masking 5a measured, where deleting an outer node guard survived a
	// substring check because the inner guard said the same words.
	if node == "" {
		return fmt.Errorf("rollback vm %d: node is required", vmid)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("rollback vm %d: snapshot name is required", vmid)
	}
	if isPseudoEntryName(name) {
		return fmt.Errorf("rollback vm %d: %w", vmid, &ErrReservedSnapshotName{VMID: vmid, Name: name})
	}

	newer, err := c.NewerSnapshots(ctx, node, vmid, name)
	if err != nil {
		return fmt.Errorf("rollback vm %d to snapshot %q: %w", vmid, name, err)
	}
	if len(newer) > 0 {
		names := make([]string, len(newer))
		for i, s := range newer {
			names[i] = s.Name
		}
		return &ErrNotNewestSnapshot{VMID: vmid, Target: name, Newer: names}
	}

	path := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot/%s/rollback", url.PathEscape(node), vmid, url.PathEscape(name))
	raw, err := c.RawRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("rollback vm %d to snapshot %q: %w", vmid, name, err)
	}
	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return fmt.Errorf("rollback vm %d to snapshot %q: %w", vmid, name, err)
	}
	if err := c.WaitForTask(ctx, node, upid); err != nil {
		return fmt.Errorf("rollback vm %d to snapshot %q: %w", vmid, name, err)
	}
	return nil
}

// CascadeDeleteSnapshots deletes each of names from vmid on node, strictly
// sequentially and in the given order, and returns the names it actually
// deleted. It is the caller-driven step that clears the way for a Rollback
// refused with *ErrNotNewestSnapshot: pass that error's CascadeOrder()
// (newest-first), NOT its Newer field. Deleting newest-first (leaf-first)
// satisfies a "can't delete a non-leaf snapshot" rule if PVE enforces one
// — UNVERIFIED against a live host — and is a safe superset if it doesn't.
//
// The contract is a GOAL STATE, not a transcript: on success, none of
// names exists on vmid. That is what makes the rest of this work:
//
//   - A name already absent from the pre-state read is skipped, not
//     refused, so the call is safely retryable after a partial failure. A
//     mistyped name destroys nothing, and is caught one step later anyway:
//     the retried Rollback still refuses, because the real newer snapshot
//     is still there. A name repeated in names is deleted once.
//   - deleted records progress AS IT HAPPENS, never derived afterwards —
//     the same discipline as VMFieldsEnsure.Applied — so after a failure
//     the caller can tell "nothing was deleted" from "three of five were".
//     Skipped names are not in it: it is the destructive set, not the
//     requested set. It is returned on every path, including errors.
//   - It stops at the first failure (never batched, never parallel: a
//     partial cascade must leave a known state — cite: quantum-ng
//     snapshot.sh:468-538). The remedy is to re-run the same call.
//   - A WaitForTask error for which IsTaskOutcomeUnknown is true (for
//     example a timeout, a failed or canceled status poll, or a poll
//     answer outside PVE's contract) means that one delete's
//     outcome is unknown, and that name is NOT in deleted. Unlike a VM
//     destroy, retrying here is safe: the retry's fresh pre-state read
//     skips whatever actually landed.
//
// Refuses before any network call on an empty node, an empty names, any
// blank or whitespace-only entry, and any entry naming the "current"
// pseudo-entry (*ErrReservedSnapshotName) — without that last one,
// names=["current"] would DELETE .../snapshot/current. No vmid rule.
//
// Never trusts the DELETE responses: after the last delete, it re-reads the
// list and refuses if any of names is still present. An entry mid-delete
// (Snapstate "delete") is still present, so that refuses too. Both reads go
// through listSnapshotsVerifiable. That matters most HERE: the post-verify
// asks "are these absent?", which an empty swallowed read would answer
// yes, and the pre-state read decides which names to skip, which an empty
// swallowed read would make all of them.
//
// This is the first primitive in this repo that mutates a LIST of objects;
// every other mutating primitive is single-target.
func (c *Client) CascadeDeleteSnapshots(ctx context.Context, node string, vmid int, names []string) (deleted []string, err error) {
	if node == "" {
		return nil, fmt.Errorf("cascade delete snapshots of vm %d: node is required", vmid)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("cascade delete snapshots of vm %d: at least one snapshot name is required", vmid)
	}
	for i, n := range names {
		if strings.TrimSpace(n) == "" {
			return nil, fmt.Errorf("cascade delete snapshots of vm %d: snapshot name %d of %d is blank", vmid, i+1, len(names))
		}
		if isPseudoEntryName(n) {
			return nil, fmt.Errorf("cascade delete snapshots of vm %d: %w", vmid, &ErrReservedSnapshotName{VMID: vmid, Name: n})
		}
	}

	before, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return nil, fmt.Errorf("cascade delete snapshots of vm %d: pre-state read: %w", vmid, err)
	}
	present := make(map[string]bool)
	for _, s := range realSnapshots(before) {
		present[s.Name] = true
	}

	deleted = make([]string, 0, len(names))
	for _, n := range names {
		if !present[n] {
			continue
		}
		path := fmt.Sprintf("/nodes/%s/qemu/%d/snapshot/%s", url.PathEscape(node), vmid, url.PathEscape(n))
		raw, err := c.RawRequest(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return deleted, fmt.Errorf("cascade delete snapshots of vm %d: delete %q: %w", vmid, n, err)
		}
		upid, err := decodeUPIDScalar(raw)
		if err != nil {
			return deleted, fmt.Errorf("cascade delete snapshots of vm %d: delete %q: %w", vmid, n, err)
		}
		if err := c.WaitForTask(ctx, node, upid); err != nil {
			return deleted, fmt.Errorf("cascade delete snapshots of vm %d: delete %q: %w", vmid, n, err)
		}
		deleted = append(deleted, n)
		delete(present, n)
	}

	after, err := c.listSnapshotsVerifiable(ctx, node, vmid)
	if err != nil {
		return deleted, fmt.Errorf("cascade delete snapshots of vm %d: verify: %w", vmid, err)
	}
	stillThere := make(map[string]bool)
	for _, s := range realSnapshots(after) {
		stillThere[s.Name] = true
	}
	var remaining []string
	reported := make(map[string]bool)
	for _, n := range names {
		if stillThere[n] && !reported[n] {
			remaining = append(remaining, fmt.Sprintf("%q", n))
			reported[n] = true
		}
	}
	if len(remaining) > 0 {
		return deleted, fmt.Errorf("cascade delete snapshots of vm %d: verify: %d snapshot(s) still present after the cascade: %s",
			vmid, len(remaining), strings.Join(remaining, ", "))
	}
	return deleted, nil
}
