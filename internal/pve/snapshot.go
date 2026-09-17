package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	proxmox "github.com/luthermonson/go-proxmox"
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

// ListSnapshots returns every entry PVE reports for vmid's snapshot list —
// GET /nodes/{node}/qemu/{vmid}/snapshot — INCLUDING the synthetic
// "current" pseudo-entry. The raw list is deliberately what this returns:
// filtering is realSnapshots' job, kept separate so a caller that
// genuinely wants to see the whole list as PVE reports it (a `snapshot
// list` command rendering the chain, say) still can.
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

// ErrReservedSnapshotName reports that CreateSnapshot refused because the
// requested name is PVE's reserved "current" pseudo-entry (matched
// case-insensitively). Matchable with errors.As against
// *ErrReservedSnapshotName.
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
	return fmt.Sprintf("snapshot name %q is reserved on vm %d: %q is PVE's own pseudo-entry for the live running state, not a snapshot that can be created", e.Name, e.VMID, currentPseudoSnapshot)
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
//     create endpoint is ever touched.
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
	// " current", "current " and "\tcurrent" all reach PVE's create
	// endpoint with the padding intact if only case is normalized — and
	// "PVE will reject it anyway" is precisely the assumption this guard
	// exists in order not to depend on. The name is compared trimmed but
	// reported and sent untrimmed: this refuses padded variants, it does
	// not silently rewrite what the caller asked for.
	if strings.EqualFold(strings.TrimSpace(name), currentPseudoSnapshot) {
		return &ErrReservedSnapshotName{VMID: vmid, Name: name}
	}

	// Step 2.
	existing, err := c.ListSnapshots(ctx, node, vmid)
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

	// Step 4.
	after, err := c.ListSnapshots(ctx, node, vmid)
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
