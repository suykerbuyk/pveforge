package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// This file is the destroy-retry-safety contract's IN-FLIGHT DETERMINATION:
// before a destroy is dispatched, ask PVE — and only PVE — whether a hazardous
// task for this vmid is still running, and how the newest destroy ended.
//
// The central invariant, and the reason every failure below is a REFUSAL and
// none is an error a caller could swallow:
//
//	NEVER answer "proceed" while PVE (as this token sees it) shows a
//	non-terminal hazardous task for the vmid; and refuse whenever the answer
//	cannot be established — a read that fails or cannot be decoded, a page that
//	is full, a probe that is not a 200.
//
// There is deliberately no `error` return. A signature of
// (*InFlightDetermination, error) invites an `if err != nil { proceed }`
// branch; this one has nowhere for that branch to live.

// Situation names which row of the spec's situation table a refusal belongs to.
// It is chosen by the matched task's TYPE, never by a default, because the rows
// do not forbid the same things: only B4c also forbids a stop request.
type Situation string

const (
	// SituationDestroy (B4): a non-terminal qmdestroy.
	SituationDestroy Situation = "B4"
	// SituationInFlightOther (B4b): a non-terminal qmigrate, hamigrate,
	// qmclone or qmrestore.
	SituationInFlightOther Situation = "B4b"
	// SituationStop (B4c): a non-terminal qmstop or qmshutdown. The verb's own
	// status gate would issue a SECOND stop, so this refusal must precede it.
	SituationStop Situation = "B4c"
	// SituationUnreadable (B10): the determination could not be completed.
	SituationUnreadable Situation = "B10"
)

// hazardousTypes is THE hazardous set and its situation table in ONE list: a
// task type is hazardous iff it is a key, and the situation it refuses under is
// its value. Matching and situation-choice read the same map, so the spec's two
// lists ("I1's set" and "step 4's table") cannot drift apart and no non-terminal
// match can reach a type this table cannot name.
//
// qmreset and qmreboot are ALLOWED and so absent. qmmove is EXCLUDED by
// operator ruling (its reassign worker's composite id is not returned by a
// vmid= query) and is absent too; its storage-move form carries a plain id and
// would be visible, but the ruling stands.
var hazardousTypes = map[string]Situation{
	"qmdestroy":  SituationDestroy,
	"qmigrate":   SituationInFlightOther,
	"hamigrate":  SituationInFlightOther,
	"qmclone":    SituationInFlightOther,
	"qmrestore":  SituationInFlightOther,
	"qmstop":     SituationStop,
	"qmshutdown": SituationStop,
}

// destroyTaskListLimit is the explicit positive page size of the
// determination's task-list query. It is a SIZING CHOICE, not a proof: PVE
// rotates its task index by file SIZE (about 50000 bytes, after an append), a
// short legal index line is about 62 bytes, running tasks are not capped, and
// two index files plus the active file can therefore exceed it. When they do
// the page is full, the determination REFUSES, and it keeps refusing until
// retention rotates (accepted residual R-LIMIT). Refusing is the safe
// direction; "this cannot permanently block" is not claimed.
const destroyTaskListLimit = 2000

// destroyDeterminationTimeout bounds the determination's own reads (the probe
// and the task list). It is PROVISIONAL: whether 30s is the right number is
// the spec's open question Q7 and is not settled by this constant or by a test
// of it. The verb-level deadline that also covers the free-proof read is the
// verb's, not this function's.
const destroyDeterminationTimeout = 30 * time.Second

// InFlightRefusal is why a determination said no, carrying the three things
// every refusal must name (spec I5): the vmid; what was observed; and the
// condition that would change the answer. The wording lives HERE, once, and
// the verb renders it.
type InFlightRefusal struct {
	Situation Situation
	Node      string
	VMID      int

	// Observed, for a B4-family refusal: the in-flight task.
	UPID     string
	TaskType string

	// Observed, for a B10 refusal: the read that could not be completed.
	Read    string
	ReadErr string

	// Privilege is the missing privilege, set ONLY when the probe answered 403.
	Privilege string

	// Condition is what would change the answer.
	Condition string
}

// InFlightDetermination is the answer. Exactly one of Proceed or Refusal is
// meaningful: Proceed true carries no Refusal, and a Refusal means do not
// proceed.
type InFlightDetermination struct {
	Proceed bool
	Refusal *InFlightRefusal

	// LastDestroy is the newest TERMINAL qmdestroy for the vmid, or nil when
	// none is visible. LastDestroyEndedOK is true only when its status is
	// exactly "OK". Both are set whenever a determination proceeds, and are the
	// datum the gone-proof and the failed-then-retry rows consume.
	LastDestroy        *TaskRow
	LastDestroyEndedOK bool
}

// EndedOK reports whether the task ended cleanly: its status is EXACTLY "OK".
// "WARNINGS: 1", an error string, "unexpected status", an empty status and any
// near-spelling are all not OK — a destroy that left a disk behind reads
// WARNINGS, and a permissive comparison would report it destroyed.
func (r TaskRow) EndedOK() bool { return exactOK(r.Status) }

// inFlightQuery is the determination's request, built purely so its shape can
// be asserted without a server. It sends source=all (a running task lives only
// in the active half, a finished destroy only in the archive half, and the
// verb needs both), the decimal vmid (so PVE filters before it truncates), an
// explicit positive limit, and NOTHING else: no start (a non-zero start would
// make a short page stop meaning "exhausted"), no typefilter (the hazardous set
// has seven types), and Since left zero (a process-derived since is forbidden).
func inFlightQuery(node string, vmid int) TaskListQuery {
	return inFlightQueryLimit(node, vmid, destroyTaskListLimit)
}

func inFlightQueryLimit(node string, vmid, limit int) TaskListQuery {
	return TaskListQuery{
		Node:   node,
		Source: TaskListAll,
		Limit:  limit,
		VMID:   strconv.Itoa(vmid),
	}
}

// DetermineDestroyInFlight asks PVE whether a destroy of vmid on node may
// proceed. See the file comment for the invariant it keeps.
func (c *Client) DetermineDestroyInFlight(ctx context.Context, node string, vmid int) *InFlightDetermination {
	return determine(ctx, c, node, vmid, destroyTaskListLimit, destroyDeterminationTimeout)
}

// determine is DetermineDestroyInFlight with its limit and budget as arguments,
// so a test can exercise truncation and the deadline without building 2000 rows
// or waiting 30 seconds. The exported function passes the production constants.
func determine(ctx context.Context, c *Client, node string, vmid, limit int, budget time.Duration) *InFlightDetermination {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	view, refusal := nodeDestroyView(ctx, c, node, vmid, limit)
	if refusal != nil {
		return refuse(refusal)
	}
	d := &InFlightDetermination{Proceed: true}
	if view.Newest != nil {
		row := *view.Newest
		d.LastDestroy = &row
		d.LastDestroyEndedOK = row.EndedOK()
	}
	return d
}

// nodeView is what one node's task index says about one vmid: the newest
// TERMINAL qmdestroy, or nil when none is visible. It carries no verdict. A
// node whose view cannot be established, or that shows a non-terminal
// hazardous task, is not a nodeView at all: nodeDestroyView returns a refusal.
type nodeView struct {
	Newest *TaskRow
}

// nodeDestroyView is the determination's per-node read, and the ONE place it
// lives: the visibility probe, the task-list query, the type-and-id row loop,
// the truncation refusal and the newest-destroy pick. determine calls it for
// the roster node; the gone-proof's cross-node scan (goneproof.go) calls it for
// every member. It is factored out of determine, never copied, so a rule fixed
// here is fixed for both.
//
// It applies no budget of its own: the caller's ctx bounds it.
func nodeDestroyView(ctx context.Context, c *Client, node string, vmid, limit int) (*nodeView, *InFlightRefusal) {
	// Step 2 of the decision order: the visibility precondition. A 200 from an
	// owner-filtered task list is the measured failure mode, so ask PVE whether
	// this token is an auditor of the node BEFORE trusting the list. Nodes.pm's
	// status handler requires exactly Sys.Audit on /nodes/{node}, the same
	// privilege and path Tasks.pm uses to decide whether to filter by owner.
	//
	// RawRequest, and the STATUS CODE only. `errors.Is(err, ErrNotAuthorized)`
	// is true for 401 as well as 403 (a bad token is not a missing privilege),
	// and the typed GetNode read cannot tell them apart at all: a token client
	// collapses both to the bare sentinel. The privilege is named from the
	// code, never by echoing PVE's body.
	statusPath := fmt.Sprintf("/nodes/%s/status", url.PathEscape(node))
	if _, err := c.RawRequest(ctx, http.MethodGet, statusPath, nil); err != nil {
		if code, ok := HTTPStatus(err); ok && code == http.StatusForbidden {
			priv := fmt.Sprintf("Sys.Audit on /nodes/%s", node)
			return nil, &InFlightRefusal{
				Situation: SituationUnreadable, Node: node, VMID: vmid,
				Read: "GET " + statusPath, ReadErr: err.Error(), Privilege: priv,
				Condition: fmt.Sprintf("grant this token %s, then re-run: without it the task list is filtered to the token's own tasks and cannot show whether a destroy of vmid %d is in flight", priv, vmid),
			}
		}
		return nil, unreadableRefusal(node, vmid, "GET "+statusPath, err.Error())
	}

	// The task list's path is NOT spelled here: TaskList is the module's one
	// holder of it (tasklist_guard_test.go), so this read is named by what it is.
	listRead := "task list for node " + node
	page, err := c.TaskList(ctx, inFlightQueryLimit(node, vmid, limit))
	if err != nil {
		return nil, unreadableRefusal(node, vmid, listRead, err.Error())
	}

	want := strconv.Itoa(vmid)
	var newest *TaskRow
	for i := range page.Rows {
		r := page.Rows[i]
		// Type AND decimal id, never id alone: the id collision set is large
		// (a qmstart shares a qmcreate's id) and PVE's own vmid= filter is only
		// an optimisation this check does not trust.
		if r.ID != want {
			continue
		}
		if sit, hazardous := hazardousTypes[r.Type]; hazardous {
			if !r.Terminal() {
				return nil, inFlightRefusal(sit, node, vmid, r)
			}
		}
		if r.Type == "qmdestroy" && r.Terminal() && betterDestroy(r, newest) {
			newest = &page.Rows[i]
		}
	}

	// A full page is not a negative answer: PVE stops at `limit`, and with no
	// start on the wire a page shorter than limit means the filtered set is
	// exhausted while a page of exactly limit may be the head of a longer one.
	// A specific refusal above wins over this generic one.
	if page.Truncated {
		return nil, &InFlightRefusal{
			Situation: SituationUnreadable, Node: node, VMID: vmid, Read: listRead,
			ReadErr:   fmt.Sprintf("the task list for vmid %d returned a full page of %d rows and may be truncated, so it cannot show that nothing is in flight", vmid, len(page.Rows)),
			Condition: fmt.Sprintf("re-run once the retained task log for node %s holds fewer than %d tasks that match vmid %d; a full page is never read as \"nothing in flight\"", node, limit, vmid),
		}
	}
	return &nodeView{Newest: newest}, nil
}

// betterDestroy reports whether r should replace cur as the newest terminal
// destroy: a greater starttime wins, and on a TIE the row that did NOT end OK
// wins. starttime has one-second resolution, so ties are real, and a tie
// between an OK and a failed destroy must resolve toward "it failed" — the
// direction that never reports a destroy clean on a coin flip.
func betterDestroy(r TaskRow, cur *TaskRow) bool {
	if cur == nil {
		return true
	}
	if r.StartTime != cur.StartTime {
		return r.StartTime > cur.StartTime
	}
	return !r.EndedOK() && cur.EndedOK()
}

func refuse(r *InFlightRefusal) *InFlightDetermination {
	return &InFlightDetermination{Refusal: r}
}

func unreadableRefusal(node string, vmid int, read, readErr string) *InFlightRefusal {
	return &InFlightRefusal{
		Situation: SituationUnreadable, Node: node, VMID: vmid, Read: read, ReadErr: readErr,
		Condition: fmt.Sprintf("re-run once %s can be read completely; \"cannot ask\" is not \"nothing in flight\" for vmid %d", read, vmid),
	}
}

func inFlightRefusal(sit Situation, node string, vmid int, r TaskRow) *InFlightRefusal {
	cond := fmt.Sprintf("re-run once task %s (%s) has ended and is listed as finished", r.UPID, r.Type)
	if sit == SituationStop {
		cond = fmt.Sprintf("re-run once the stop task %s (%s) has ended and is listed as finished; no stop request was issued", r.UPID, r.Type)
	}
	return &InFlightRefusal{
		Situation: sit, Node: node, VMID: vmid, UPID: r.UPID, TaskType: r.Type, Condition: cond,
	}
}
