package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// TaskRow is one row of PVE's task list (GET /nodes/{node}/tasks).
//
// PVE's row carries more than the four fields the item-69/70 recovery needed:
// a live PVE 9.2 row was measured to carry endtime, id, node, pid, pstart,
// starttime, status, tokenid, type, upid and user. Status and EndTime are
// decoded here because the WIRE has them — an earlier reading of this code
// concluded PVE did not supply task state, which was true of the struct and
// false of PVE.
type TaskRow struct {
	UPID      string `json:"upid"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	StartTime int64  `json:"starttime"`
	Status    string `json:"status"`
	EndTime   int64  `json:"endtime"`
	Node      string `json:"node"`
	User      string `json:"user"`
}

// Terminal reports whether this task has finished, and does so ONLY from a
// positive endtime. Every other shape — no endtime, a zero endtime, a status
// this code does not recognise, a row PVE grew a field on — reports NOT
// terminal.
//
// The direction matters and is not symmetric: a caller deciding whether to
// dispatch an irreversible operation must treat "I cannot tell" as "it may
// still be running". A status-driven classification would instead have to
// enumerate PVE's terminal spellings and would call an unrecognised one
// terminal, which fails OPEN.
func (r TaskRow) Terminal() bool { return r.EndTime > 0 }

// TaskListSource is the `source` parameter of GET /nodes/{node}/tasks.
// PVE's own default is archive (finished tasks only); this reader has no
// default, because a request that forgot to ask for active tasks cannot see a
// running one and its empty answer is indistinguishable from "none".
const (
	TaskListArchive = "archive"
	TaskListActive  = "active"
	TaskListAll     = "all"
)

// TaskListQuery is one GET /nodes/{node}/tasks request.
//
// Limit has no default ON PURPOSE. PVE's schema gives `limit` a minimum of 0,
// which invites reading 0 as "no limit" — and limit=0 was MEASURED live to
// return zero rows with HTTP 200. A reader that sent it would report "no task
// matched" forever, with every status green. Validate rejects it rather than
// documenting it.
type TaskListQuery struct {
	Node   string // required
	Source string // required: one of the TaskList* constants
	Limit  int    // required, > 0
	VMID   string // optional decimal vmid; "" sends no vmid filter
	Since  int64  // optional unix seconds; 0 = no window. Applied client-side
}

// ErrTaskListQuery is returned for every malformed TaskListQuery. It is a
// sentinel so a caller can tell "I asked wrongly" from "PVE answered badly".
var ErrTaskListQuery = fmt.Errorf("task list query")

// Validate reports why this query may not be sent. It is called by TaskList
// before any network contact.
func (q TaskListQuery) Validate() error {
	if q.Node == "" {
		return fmt.Errorf("%w: node is required", ErrTaskListQuery)
	}
	switch q.Source {
	case TaskListArchive, TaskListActive, TaskListAll:
	default:
		return fmt.Errorf("%w: source must be %q, %q or %q, got %q",
			ErrTaskListQuery, TaskListArchive, TaskListActive, TaskListAll, q.Source)
	}
	if q.Limit <= 0 {
		return fmt.Errorf("%w: limit must be > 0, got %d: PVE answers limit=0 with zero rows and HTTP 200, which reads as \"no task matched\"", ErrTaskListQuery, q.Limit)
	}
	if q.Since < 0 {
		return fmt.Errorf("%w: since must not be negative, got %d", ErrTaskListQuery, q.Since)
	}
	return nil
}

func (q TaskListQuery) params() url.Values {
	v := url.Values{"source": {q.Source}, "limit": {strconv.Itoa(q.Limit)}}
	if q.VMID != "" {
		v.Set("vmid", q.VMID)
	}
	return v
}

// TaskListPage is what one TaskList request returned.
//
// Truncated is the half a row count cannot express: PVE stops at `limit`, so a
// page holding exactly Limit rows MAY be the head of a longer answer. A caller
// that treats such a page as the whole answer is reading a cut-off list as a
// complete one. This reader REPORTS truncation; what to do about it is the
// caller's decision, not this function's.
type TaskListPage struct {
	Rows      []TaskRow
	Truncated bool
	Query     TaskListQuery
}

// TaskList is the module's ONE reader of PVE's task list.
//
// On any failure it returns a nil page. That matters more than it looks:
// encoding/json reports an UnmarshalTypeError for an off-type field and STILL
// populates the slice, leaving the bad field at its zero value — so a row whose
// endtime could not be decoded would read as endtime 0, i.e. NOT terminal but
// also not trustworthy. Returning the partially-decoded rows alongside the
// error would hand a caller a list that looks answerable and is not.
func (c *Client) TaskList(ctx context.Context, q TaskListQuery) (*TaskListPage, error) {
	if err := q.Validate(); err != nil {
		return nil, fmt.Errorf("task list on %q: %w", q.Node, err)
	}
	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/tasks", url.PathEscape(q.Node)), q.params())
	if err != nil {
		return nil, fmt.Errorf("task list on %q: %w", q.Node, err)
	}
	var rows []TaskRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("task list on %q: task list shape: %w", q.Node, err)
	}
	return &TaskListPage{Rows: rows, Truncated: len(rows) >= q.Limit, Query: q}, nil
}

// findTaskUPIDLimit is the page size FindTaskUPID asks for: PVE's own default,
// which is what this call has always had implicitly (it sent no limit). Stated
// explicitly so the request is legible, NOT widened — widening it would change
// which row "the newest match" is for a live-exercised capture path.
const findTaskUPIDLimit = 50

// FindTaskUPID recovers one task's UPID from PVE's task list by TYPE AND id —
// the item-69/70 qmcreate recovery (vm create prints no UPID, vm.go:306). It
// filters on BOTH type and id, never id alone: a qmstart shares the id of the
// qmcreate, so "the UPID whose id is <vmid>" could be the start. `since` (unix
// seconds, 0 = ignore) bounds the create window. Of the matches it returns the
// newest; zero matches is an error.
//
// It is a thin wrapper over TaskList and asks for exactly what it asked for
// before: the archive, PVE's default page size, no vmid filter. Truncation is
// deliberately not consulted — this call was already bounded at 50 rows when it
// sent no limit at all, so reporting on it would be a NEW refusal on a path
// that has been shipping.
func (c *Client) FindTaskUPID(ctx context.Context, node, taskType, wantID string, since int64) (string, error) {
	page, err := c.TaskList(ctx, TaskListQuery{
		Node:   node,
		Source: TaskListArchive,
		Limit:  findTaskUPIDLimit,
		Since:  since,
	})
	if err != nil {
		return "", fmt.Errorf("find %s task for id %q on %q: %w", taskType, wantID, node, err)
	}
	best := TaskRow{}
	found := false
	for _, r := range page.Rows {
		if r.Type != taskType || r.ID != wantID || r.StartTime < since {
			continue
		}
		if !found || r.StartTime > best.StartTime {
			best, found = r, true
		}
	}
	if !found {
		return "", fmt.Errorf("find %s task for id %q on %q: no matching task (type AND id)", taskType, wantID, node)
	}
	return best.UPID, nil
}
