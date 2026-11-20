package pve

import (
	"context"
	"fmt"
)

// This file is the destroy-retry-safety contract's GONE-PROOF (invariant I3):
// "destroyed" is asserted only from positive proof, and everything short of it
// is a named non-answer.
//
// The central invariant, and the reason there is no `error` return anywhere on
// this path:
//
//	NEVER report GONE unless the destroy that decides it ended EXACTLY "OK" —
//	post-dispatch, this invocation's own UPID; on a retry, the NEWEST qmdestroy
//	for the vmid across EVERY cluster member, read fresh, roster node included —
//	AND the cluster-wide free-proof is Free from a strict 200 echo.
//
//	NEVER block permanently on a healthy cluster: a token that cannot see the VM
//	(403 on the node-local read), a principal-filtered placement read that is
//	empty or failing, and an unrelated member being offline AFTER our own
//	dispatch must not turn a provable GONE into a refusal.
//
// What this file deliberately does NOT use: the node-local config read as proof
// (a 403 and a missing config are the same to a token that left the pool; it is
// the caller's input and shapes wording only), the principal-filtered
// /cluster/resources read (detail only), the harness's pool leg
// (outer.VMGone — wrong for a token whose pool membership PVE removes before
// the config), and WaitForTask's nil (which is also nil for "WARNINGS: n").

// GoneSituation names the one outcome JudgeGone reached.
type GoneSituation string

const (
	// GoneProven: proven destroyed. The ONLY situation with Gone == true.
	GoneProven GoneSituation = "gone"
	// GoneUnclean (B5-unclean, FAILED): the newest destroy ended, but not
	// exactly OK; volumes may have been left behind.
	GoneUnclean GoneSituation = "unclean"
	// GoneElsewhere (B5-elsewhere, REFUSED): the vmid is still claimed
	// cluster-wide although it is not seen here (Invisible says whether the
	// roster node's own read was a 403 rather than absent).
	GoneElsewhere GoneSituation = "elsewhere"
	// GoneAbsentNoTask (B5-absent, REFUSED): free, but no destroy was
	// observed on any member.
	GoneAbsentNoTask GoneSituation = "absent-no-task"
	// GoneUnproven (UNKNOWN): this invocation dispatched the destroy and
	// the proof could not be established.
	GoneUnproven GoneSituation = "unproven"
	// GoneUnreadable (B10, REFUSED): a retry whose free-proof, member list
	// or a member's task view could not be read completely.
	GoneUnreadable GoneSituation = "unreadable"
	// GoneInFlightElsewhere (REFUSED): a non-terminal hazardous task for
	// the vmid on a member.
	GoneInFlightElsewhere GoneSituation = "in-flight-elsewhere"
)

// Presence is what the caller's node-local config read said. It is INPUT and
// never proof: it shapes wording, and PresenceHere is refused as a caller error.
// The zero value is PresenceUnreadable.
type Presence int

const (
	PresenceUnreadable Presence = iota // the read failed or was not made
	PresenceHere                       // the config is served here: not a gone-proof candidate
	PresenceAbsent                     // PVE said the config does not exist
	PresenceForbidden                  // 403: absent and present-but-invisible read the same
)

// GoneEvidence is what the caller brings. Everything else JudgeGone reads
// itself, at judgement time.
type GoneEvidence struct {
	Presence Presence

	// Dispatched is the one bit that decides exit 3 versus exit 4 for the same
	// failed proof: "this invocation dispatched the destroy". A refusal after
	// our own dispatch would hide an UNKNOWN.
	Dispatched bool

	// Destroy is how OUR OWN dispatched destroy ended (Client.DestroyEnd).
	// Used only when Dispatched. DestroyReadErr is set instead when that read
	// failed.
	Destroy        *DestroyEnd
	DestroyReadErr string
}

// GoneVerdict is the answer: exactly one situation, carrying the three things
// every refusal must name (I5): the vmid; what was observed; and the condition
// that would change the answer.
type GoneVerdict struct {
	Situation GoneSituation
	// Gone is true iff Situation == GoneProven.
	Gone bool

	Node string
	VMID int

	// The destroy that decided it (Gone, Unclean).
	UPID       string
	ExitStatus string
	DecidedOn  string // the node whose row decided it, for a retry

	// What was observed.
	Observed  string
	Read      string
	ReadErr   string
	OtherNode string // the node an in-flight / unreadable / elsewhere verdict is about
	Privilege string // set only when a probe or the member list answered 403
	Invisible bool   // Elsewhere: the roster node's own read was a 403

	// Condition is what would change the answer.
	Condition string
}

// scanResult is the cross-node scan's outcome, injected into judge so the table
// tests and mutants can drive the decision directly.
type scanResult struct {
	// Membership is set when the member list could not be established.
	Membership *NodeSet
	// Refusal is the first node whose view was refused (unreadable, or a
	// non-terminal hazardous task).
	Refusal *InFlightRefusal
	// Newest is the newest terminal qmdestroy across every member, and
	// NewestNode its node.
	Newest     *TaskRow
	NewestNode string
}

// JudgeGone decides whether the destroy of vmid (roster node `node`) is proven.
//
// Order is the invariant (§G5/G11/G19 of the plan): (1) the free-proof — an
// unverified or in-use answer after our own dispatch is UNPROVEN, on a retry
// UNREADABLE / ELSEWHERE; (2) post-dispatch: our own UPID's exit string; (3)
// retry: the member list, then EVERY member read fresh through
// nodeDestroyView, folded with betterDestroy. U4's earlier roster-node answer is
// never an input.
func (c *Client) JudgeGone(ctx context.Context, node string, vmid int, ev GoneEvidence) *GoneVerdict {
	free := c.FreeProof(ctx, vmid)
	scan := func() scanResult { return c.scanMembers(ctx, node, vmid) }
	place := func() Placement { return c.PlacementOf(ctx, vmid) }
	return judge(node, vmid, free, ev, scan, place)
}

// scanMembers reads the member list and then every member, roster node
// included, FRESH, through U4's per-node read.
func (c *Client) scanMembers(ctx context.Context, roster string, vmid int) scanResult {
	set := c.ClusterNodes(ctx, roster)
	if !set.Complete {
		return scanResult{Membership: &set}
	}
	var out scanResult
	for _, name := range set.Names {
		view, refusal := nodeDestroyView(ctx, c, name, vmid, destroyTaskListLimit)
		if refusal != nil {
			return scanResult{Refusal: refusal}
		}
		if view.Newest != nil && betterDestroy(*view.Newest, out.Newest) {
			row := *view.Newest
			out.Newest, out.NewestNode = &row, name
		}
	}
	return out
}

// judge is JudgeGone's pure core. Tests and mutants call it directly.
func judge(node string, vmid int, free FreeResult, ev GoneEvidence, scan func() scanResult, place func() Placement) *GoneVerdict {
	v := &GoneVerdict{Node: node, VMID: vmid}

	// A caller error, handled before anything is read: the VM is served on the
	// roster node, so this is not a gone-proof candidate at all.
	if ev.Presence == PresenceHere {
		v.Observed = fmt.Sprintf("the roster node %s still serves vm %d's config", node, vmid)
		v.Condition = fmt.Sprintf("a vm that is present is destroyed, not proven gone: dispatch the destroy, or re-run once vm %d is absent", vmid)
		return unprovenOrUnreadable(v, ev)
	}

	// (1) The free-proof comes first. A vmid that is in use costs no node scan,
	// and no scan may turn it into GONE.
	switch free.State {
	case VMIDFree:
		// fall through to the destroy leg
	case VMIDInUse:
		if ev.Dispatched {
			v.Observed = fmt.Sprintf("this invocation's destroy of vm %d ended, but PVE still says the vmid is in use: %s", vmid, free.Detail)
			v.Read, v.ReadErr = free.Read, free.Detail
			v.Condition = fmt.Sprintf("re-run: a later invocation resolves it (already destroyed once /cluster/nextid reports vmid %d free)", vmid)
			v.Situation = GoneUnproven
			return v
		}
		p := place()
		v.Situation = GoneElsewhere
		v.Invisible = ev.Presence == PresenceForbidden
		v.OtherNode = p.Node
		switch {
		case p.Seen:
			v.Observed = fmt.Sprintf("vmid %d is not served on roster node %s but PVE still claims it cluster-wide, on node %s", vmid, node, p.Node)
		case v.Invisible:
			v.Observed = fmt.Sprintf("vmid %d is claimed cluster-wide but this token cannot see it on roster node %s (403 on its config): present and invisible, or on another node", vmid, node)
		default:
			v.Observed = fmt.Sprintf("vmid %d is not served on roster node %s but PVE still claims it cluster-wide", vmid, node)
		}
		v.Read, v.ReadErr = free.Read, free.Detail
		v.Condition = fmt.Sprintf("re-run once vmid %d is free cluster-wide, or target the node that holds it", vmid)
		return v
	default: // VMIDUnverified, and any unset value: never read as free
		v.Observed = fmt.Sprintf("the cluster-wide free-proof for vmid %d could not be established: %s", vmid, free.Detail)
		v.Read, v.ReadErr = free.Read, free.Detail
		v.Condition = fmt.Sprintf("re-run once %s answers 200 for vmid %d", free.Read, vmid)
		return unprovenOrUnreadable(v, ev)
	}

	// (2) Post-dispatch: our own destroy's exit string. No scan: this
	// invocation holds the UPID, the stale-row hazard exists only for a retry's
	// inherited row, and an offline unrelated member must not block a clean ok.
	if ev.Dispatched {
		switch {
		case ev.DestroyReadErr != "" || ev.Destroy == nil:
			v.Observed = fmt.Sprintf("how this invocation's destroy of vm %d ended could not be read: %s", vmid, ev.DestroyReadErr)
			v.ReadErr = ev.DestroyReadErr
			v.Condition = "re-run: a later invocation reads how the destroy ended from PVE's task log"
			v.Situation = GoneUnproven
		case !ev.Destroy.EndedOK():
			uncleanVerdict(v, ev.Destroy.UPID, ev.Destroy.ExitStatus, "")
		default:
			v.Situation, v.Gone = GoneProven, true
			v.UPID, v.ExitStatus = ev.Destroy.UPID, ev.Destroy.ExitStatus
		}
		return v
	}

	// (3) Retry: every member, fresh.
	sr := scan()
	switch {
	case sr.Membership != nil:
		v.Situation = GoneUnreadable
		v.Read, v.ReadErr, v.Privilege = sr.Membership.Read, sr.Membership.Detail, sr.Membership.Privilege
		v.Observed = fmt.Sprintf("the cluster member list could not be established, so a destroy of vmid %d on another node cannot be ruled out: %s", vmid, sr.Membership.Detail)
		v.Condition = fmt.Sprintf("re-run once %s and GET /nodes both answer and the member list names node %s", sr.Membership.Read, node)
		if v.Privilege != "" {
			v.Condition = fmt.Sprintf("grant this token %s, then re-run", v.Privilege)
		}
	case sr.Refusal != nil:
		r := sr.Refusal
		v.OtherNode = r.Node
		v.Read, v.ReadErr, v.Privilege = r.Read, r.ReadErr, r.Privilege
		v.Condition = r.Condition
		if r.Situation == SituationUnreadable {
			v.Situation = GoneUnreadable
			v.Observed = fmt.Sprintf("node %s's task view for vmid %d could not be read completely, so a newer destroy there cannot be ruled out", r.Node, vmid)
		} else {
			v.Situation = GoneInFlightElsewhere
			v.UPID = r.UPID
			v.Observed = fmt.Sprintf("node %s has a non-terminal %s task %s for vmid %d", r.Node, r.TaskType, r.UPID, vmid)
		}
	case sr.Newest == nil:
		v.Situation = GoneAbsentNoTask
		v.Observed = fmt.Sprintf("vmid %d is free, but no destroy of it is visible on any cluster member: absence alone is not a gone-proof", vmid)
		v.Condition = fmt.Sprintf("none a re-run can supply from PVE's task log; confirm vmid %d independently (GET /cluster/nextid) if it is known to be destroyed", vmid)
	case !sr.Newest.EndedOK():
		uncleanVerdict(v, sr.Newest.UPID, sr.Newest.Status, sr.NewestNode)
	default:
		v.Situation, v.Gone = GoneProven, true
		v.UPID, v.ExitStatus, v.DecidedOn = sr.Newest.UPID, sr.Newest.Status, sr.NewestNode
	}
	return v
}

func unprovenOrUnreadable(v *GoneVerdict, ev GoneEvidence) *GoneVerdict {
	if ev.Dispatched {
		v.Situation = GoneUnproven
	} else {
		v.Situation = GoneUnreadable
	}
	return v
}

func uncleanVerdict(v *GoneVerdict, upid, exit, onNode string) {
	v.Situation = GoneUnclean
	v.UPID, v.ExitStatus, v.DecidedOn = upid, exit, onNode
	v.Observed = fmt.Sprintf("the newest destroy of vmid %d, task %s, ended %q rather than OK: the guest is not proven cleanly destroyed and volumes may have been left behind", v.VMID, upid, exit)
	v.Condition = "none a re-run can change: inspect the task log and scan for orphan volumes; do not retry blindly"
}
