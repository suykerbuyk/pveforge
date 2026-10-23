//go:build harness

// Batch A A-MUT captures (pveforge-nested-pve-test-harness items 68-agent, 69,
// 70a, 70b). Same rules as capture_harness.go: built only under the `harness`
// tag, in package pve so it can reach the production client, the agent matcher,
// the UPID grammar/validator and the task-exit regex; adds no production
// behaviour. The ASSERTIONS here — not `pveforge api`'s exit status, which is 0
// on both OK and WARNINGS (api.go:232-234) — are the non-vacuity gate.

package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ---- item 68-agent: CaptureAgentRejection -------------------------------

// AgentRejection is one item-68 capture: the raw rejection a guest-agent read
// got from an agent-declared-but-absent guest, and whether it is the agent-off
// answer under test (as opposed to a not-found 500, a 595/596, or an auth
// rejection).
type AgentRejection struct {
	Node          string `json:"node"`
	VMID          int    `json:"vmid"`
	Code          int    `json:"code,omitempty"`
	RejectionText string `json:"rejection_text"`
	AgentOff      bool   `json:"agent_off"`
	Auth          bool   `json:"auth"`
}

// ErrAgentReachable: the agent answered, so there is no rejection to capture.
var ErrAgentReachable = errors.New("agent interfaces returned no rejection: the guest agent answered")

// isAgentOff is item-68's agent-off discriminator and a mutation target: the
// rejection text matches an agentUnavailableSubstrings entry (the production
// matcher, via IsAgentUnavailableError) AND it is not an auth rejection — a
// 401/403 (ErrNotAuthorized) is never "agent off", however its body reads.
func isAgentOff(err error) bool {
	if errors.Is(err, ErrNotAuthorized) {
		return false
	}
	return IsAgentUnavailableError(err)
}

// CaptureAgentRejection calls the production AgentInterfaces on an
// agent-declared-but-absent guest, records the raw rejection, and reports
// whether it is the agent-off answer (for the right reason). A successful
// agent answer is itself the finding, returned as ErrAgentReachable.
func (c *Client) CaptureAgentRejection(ctx context.Context, node string, vmid int) (*AgentRejection, error) {
	_, err := c.AgentInterfaces(ctx, node, vmid)
	if err == nil {
		return nil, fmt.Errorf("capture agent rejection on vm %d: %w", vmid, ErrAgentReachable)
	}
	rej := &AgentRejection{
		Node:          node,
		VMID:          vmid,
		RejectionText: err.Error(),
		Auth:          errors.Is(err, ErrNotAuthorized),
		AgentOff:      isAgentOff(err),
	}
	var se *StatusError
	if errors.As(err, &se) {
		rej.Code = se.Code
	}
	return rej, nil
}

// ---- items 69/70a/70b: CaptureTaskUPID ----------------------------------

// UPIDSpelling is a task's UPID broken into PVE's eight fields, plus the
// production validateUPIDShape verdict. The id field is EMPTY for an
// all-guests task (vzdump --all); the user field carries a token as
// `<user>!<token>`.
type UPIDSpelling struct {
	UPID      string `json:"upid"`
	Node      string `json:"node"`
	PID       string `json:"pid"`
	PStart    string `json:"pstart"`
	StartTime string `json:"starttime"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	User      string `json:"user"`
	Valid     bool   `json:"valid"`
	ValidErr  string `json:"valid_err,omitempty"`
}

// ParseUPIDSpelling splits upid into PVE's eight fields
// (UPID:node:pid:pstart:starttime:type:id:user:) and records
// validateUPIDShape's verdict (task.go:342). It never guesses: a string that
// is not that shape is an error, not a half-filled spelling.
func ParseUPIDSpelling(upid string) (*UPIDSpelling, error) {
	parts := strings.Split(upid, ":")
	// UPID:node:pid:pstart:starttime:type:id:user: -> 9 parts incl. the
	// trailing empty from the final colon.
	if len(parts) < 9 || parts[0] != "UPID" {
		return nil, fmt.Errorf("not a UPID of PVE's eight-field form: %q", upid)
	}
	sp := &UPIDSpelling{
		UPID: upid, Node: parts[1], PID: parts[2], PStart: parts[3], StartTime: parts[4],
		Type: parts[5], ID: parts[6], User: parts[7],
	}
	if err := validateUPIDShape(upid); err != nil {
		sp.ValidErr = err.Error()
	} else {
		sp.Valid = true
	}
	return sp, nil
}

// ExpectUPID is a per-field spelling expectation; a nil field is not checked,
// a non-nil one must match exactly — so ID pointing at "" asserts the id field
// is EMPTY (vzdump --all), distinct from "don't care".
type ExpectUPID struct {
	Type *string
	ID   *string
	User *string
}

// Check reports every expected-field mismatch (the item-70 spelling assert).
func (sp *UPIDSpelling) Check(exp ExpectUPID) error {
	var miss []string
	if exp.Type != nil && sp.Type != *exp.Type {
		miss = append(miss, fmt.Sprintf("type %q != %q", sp.Type, *exp.Type))
	}
	if exp.ID != nil && sp.ID != *exp.ID {
		miss = append(miss, fmt.Sprintf("id %q != %q", sp.ID, *exp.ID))
	}
	if exp.User != nil && sp.User != *exp.User {
		miss = append(miss, fmt.Sprintf("user %q != %q", sp.User, *exp.User))
	}
	if len(miss) > 0 {
		return fmt.Errorf("UPID %q spelling: %s", sp.UPID, strings.Join(miss, "; "))
	}
	return nil
}

// taskRow is one row of PVE's task list (GET /nodes/{node}/tasks).
type taskRow struct {
	UPID      string `json:"upid"`
	Type      string `json:"type"`
	ID        string `json:"id"`
	StartTime int64  `json:"starttime"`
}

// FindTaskUPID recovers one task's UPID from PVE's task list by TYPE AND id —
// the item-69/70 qmcreate recovery (vm create prints no UPID, vm.go:306). It
// filters on BOTH type and id, never id alone: a qmstart shares the id of the
// qmcreate, so "the UPID whose id is <vmid>" could be the start. `since` (unix
// seconds, 0 = ignore) bounds the create window. Of the matches it returns the
// newest; zero matches is an error.
func (c *Client) FindTaskUPID(ctx context.Context, node, taskType, wantID string, since int64) (string, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/tasks", url.PathEscape(node)), nil)
	if err != nil {
		return "", fmt.Errorf("find %s task for id %q on %q: %w", taskType, wantID, node, err)
	}
	var rows []taskRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return "", fmt.Errorf("find %s task for id %q on %q: task list shape: %w", taskType, wantID, node, err)
	}
	best := taskRow{}
	found := false
	for _, r := range rows {
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

// ---- item 69: CaptureTaskExitStatus -------------------------------------

// TaskExitStatus is one item-69 capture read from PVE's OWN task-status
// endpoint (not the client's WaitForTask wrapper — hazard #5).
type TaskExitStatus struct {
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
	IsWarnings bool   `json:"is_warnings"`
}

// CaptureTaskExitStatus GETs PVE's own /nodes/{n}/tasks/{upid}/status
// (url.PathEscape the UPID, goneproof.go:47) and records the raw exitstatus,
// reporting whether it is EXACTLY `WARNINGS: <n>` (taskExitWarnings,
// task.go:118) — an `OK` or any trailing byte makes IsWarnings false.
func (c *Client) CaptureTaskExitStatus(ctx context.Context, node, upid string) (*TaskExitStatus, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid)), nil)
	if err != nil {
		return nil, fmt.Errorf("capture task exitstatus for %q on %q: %w", upid, node, err)
	}
	var st struct {
		Status     string `json:"status"`
		ExitStatus string `json:"exitstatus"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("capture task exitstatus for %q on %q: status shape: %w", upid, node, err)
	}
	return &TaskExitStatus{
		UPID:       upid,
		Status:     st.Status,
		ExitStatus: st.ExitStatus,
		IsWarnings: taskExitWarnings.MatchString(st.ExitStatus),
	}, nil
}
