package pve

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// maxNextVMIDWalkAttempts bounds NextVMID's walk-forward search for a free
// vmid past its starting candidate — a defensive cap against a pathological
// exclude set (or persistent PVE-side contention) driving the search into
// an effectively unbounded loop.
const maxNextVMIDWalkAttempts = 1000

// NextVMID resolves a vmid for a new VM/CT: either the caller's explicit
// pin (if free), or PVE's own next-available suggestion, walked forward
// past anything in exclude or genuinely taken per PVE.
//
// pin == 0 means "no pin, auto-allocate" — a safe sentinel because PVE's
// vmid schema has a documented minimum of 100, so a real vmid can never be
// 0.
//
// exclude is a client-side blocklist of vmids this run has provisionally
// claimed or just freed — a safety margin against pvestatd's own cache lag
// handing the same id back twice within one process before PVE's state has
// caught up. It is not a request to permanently retire an id across
// separate runs. Values outside PVE's valid vmid range are harmless here:
// pin routes through vmidFree and fails safe on PVE's own rejection, and
// exclude entries below the NextID() baseline are simply never reached by
// the walk-forward search.
func (c *Client) NextVMID(ctx context.Context, pin int, exclude ...int) (int, error) {
	excluded := make(map[int]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}

	if pin != 0 {
		if excluded[pin] {
			return 0, fmt.Errorf("next vmid: pin %d is also in the exclude list", pin)
		}
		free, err := c.vmidFree(ctx, pin)
		if err != nil {
			return 0, fmt.Errorf("next vmid: check pin %d: %w", pin, err)
		}
		if !free {
			return 0, fmt.Errorf("next vmid: pin %d is already taken", pin)
		}
		return pin, nil
	}

	// Deliberately calls c.pc.Get directly rather than go-proxmox's own
	// Cluster(ctx)+Cluster.NextID(ctx) — Client.Cluster(ctx) unconditionally
	// issues an extra GET /cluster/status probe first (swallowed only on an
	// auth failure) before it will even return a *Cluster to call NextID
	// on, which would both cost a wasted round-trip on every non-pinned
	// call and make NextVMID fail on a /cluster/status-specific error even
	// when /cluster/nextid itself is fine. This mirrors Cluster.NextID's
	// own implementation exactly (a bare string response, parsed with
	// strconv.Atoi) and vmidFree's own direct-Get pattern below.
	var raw string
	if err := c.pc.Get(ctx, "/cluster/nextid", &raw); err != nil {
		return 0, fmt.Errorf("next vmid: %w", err)
	}
	candidate, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("next vmid: parse nextid response %q: %w", raw, err)
	}
	if !excluded[candidate] {
		// The raw, untouched NextID() value is trusted free on PVE's own
		// word — no vmidFree call needed.
		return candidate, nil
	}

	// Every candidate reached by walking forward from here — including one
	// that merely clears the exclude filter — gets an explicit vmidFree
	// check before being returned; PVE never vouched for anything past the
	// first candidate.
	for i := 1; i <= maxNextVMIDWalkAttempts; i++ {
		next := candidate + i
		if excluded[next] {
			continue // locally-claimed; skip without a network call
		}
		free, err := c.vmidFree(ctx, next)
		if err != nil {
			return 0, fmt.Errorf("next vmid: check %d: %w", next, err)
		}
		if free {
			return next, nil
		}
		// taken per PVE — keep advancing
	}
	return 0, fmt.Errorf("next vmid: no free vmid found within %d attempts past %d", maxNextVMIDWalkAttempts, candidate)
}

// vmidFree reports whether vmid is currently free, via PVE's own
// GET /cluster/nextid?vmid=N check — pveforge's own reimplementation of
// what go-proxmox's Cluster.CheckID intended, using a proper pointer
// target rather than depending on that library method directly (avoids
// tying pveforge to upstream error-text matching inside a dependency, and
// avoids inheriting any latent bug there even though the one found in
// v0.8.1 is currently inert).
func (c *Client) vmidFree(ctx context.Context, vmid int) (bool, error) {
	var ret string
	err := c.pc.Get(ctx, fmt.Sprintf("/cluster/nextid?vmid=%d", vmid), &ret)
	if err == nil {
		return true, nil
	}
	if isVMIDTakenError(err, vmid) {
		return false, nil
	}
	return false, err
}

// isVMIDTakenError reports whether err looks like PVE's own rejection text
// for this specific vmid already being in use — parameterized on vmid
// (fmt.Sprintf("VM %d already exists", vmid), compared case-insensitively,
// mirroring IsDigestConflictError's lowercasing precedent) rather than a
// bare "already exists" substring, so an unrelated PVE error that happens
// to mention some other resource "already exists" is never misclassified
// as this vmid being taken.
func isVMIDTakenError(err error, vmid int) bool {
	if err == nil {
		return false
	}
	want := strings.ToLower(fmt.Sprintf("VM %d already exists", vmid))
	return strings.Contains(strings.ToLower(err.Error()), want)
}
