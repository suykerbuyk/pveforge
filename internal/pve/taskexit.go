package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// TaskExitStatus is one read of PVE's OWN per-task status endpoint
// (GET /nodes/{n}/tasks/{upid}/status), not the client's WaitForTask wrapper.
//
// It was promoted out of the `harness` build (it lived in
// capture_harness_amut.go as item 69's capture) so the production
// destroy-retry-safety contract can reach it: WaitForTask returns nil for BOTH
// "OK" and "WARNINGS: <n>" (taskExitSucceeded mirrors PVE::UPID::status_is_error),
// so a nil from the wait is NOT "ended exactly OK". The gone-proof needs the raw
// exitstatus string, and this is the module's one reader of it.
type TaskExitStatus struct {
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
	IsWarnings bool   `json:"is_warnings"`

	// The body's own identity fields, kept off the capture report (json:"-")
	// and consumed only by DestroyEnd's binding check. On the wire PVE decodes
	// type/id/node/user from the PATH upid and overwrites the body's upid with
	// the request path (Tasks.pm read_task_status), so these repeat the path:
	// the binding is a FIXTURE defence — it kills a fake that echoes the
	// caller's UPID with another task's fields — and not a second observation.
	BodyUPID string `json:"-"`
	BodyType string `json:"-"`
	BodyID   string `json:"-"`
	BodyNode string `json:"-"`
}

// CaptureTaskExitStatus GETs PVE's own /nodes/{n}/tasks/{upid}/status
// (url.PathEscape the UPID) and records the raw exitstatus, reporting whether
// it is EXACTLY `WARNINGS: <n>` (taskExitWarnings) — an `OK` or any trailing
// byte makes IsWarnings false.
//
// This function holds the per-task path literal and is allow-listed by name in
// TestTaskList_IsThePackagesOnlyTaskPathHolder; DestroyEnd goes through it
// rather than spelling the path again.
func (c *Client) CaptureTaskExitStatus(ctx context.Context, node, upid string) (*TaskExitStatus, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid)), nil)
	if err != nil {
		return nil, fmt.Errorf("capture task exitstatus for %q on %q: %w", upid, node, err)
	}
	var st struct {
		UPID       string `json:"upid"`
		Type       string `json:"type"`
		ID         string `json:"id"`
		Node       string `json:"node"`
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
		BodyUPID:   st.UPID,
		BodyType:   st.Type,
		BodyID:     st.ID,
		BodyNode:   st.Node,
	}, nil
}

// exactOK is THE rule for "ended cleanly": the exit string is byte-for-byte
// "OK". "WARNINGS: 1" (a disk left behind), an error string, "unexpected
// status", an empty string, a near-spelling ("ok", "OK ", "OKAY") are all not
// OK. It is deliberately NOT taskExitSucceeded, which accepts WARNINGS: that is
// the predicate for "the worker exited 0", and pasting it here is the likeliest
// way to report a partial destroy as clean. It has exactly one home so the rule
// has exactly one mutation point; TaskRow.EndedOK and DestroyEnd.EndedOK both
// call it.
func exactOK(exitStatus string) bool { return exitStatus == taskExitOK }

// DestroyEnd is how ONE destroy task ended: its UPID and the raw exit string.
// It exists only for a task that has STOPPED with a non-empty exit string;
// "still running", "unreadable" and "the body names another task" are errors
// from Client.DestroyEnd, never a DestroyEnd value.
type DestroyEnd struct {
	UPID       string
	ExitStatus string
}

// EndedOK reports whether the destroy ended exactly "OK".
func (e DestroyEnd) EndedOK() bool { return exactOK(e.ExitStatus) }

// DestroyEnd reads how the destroy task upid (the one this invocation
// dispatched, for vmid on node) ended, from PVE's per-task status endpoint.
//
// It binds the answer to the task asked about — the body's upid, type
// (qmdestroy), id (the decimal vmid) and node must all match — requires
// status "stopped" and a non-empty exitstatus (PVE::UPID::read_status always
// yields one for a finished task), and otherwise returns an error. A task that
// is still running, or a read that failed, is an error: the caller must treat
// it as "not proven", never as a clean end.
func (c *Client) DestroyEnd(ctx context.Context, node string, vmid int, upid string) (*DestroyEnd, error) {
	if err := validateUPIDShape(upid); err != nil {
		return nil, fmt.Errorf("destroy end of vm %d: %w", vmid, err)
	}
	st, err := c.CaptureTaskExitStatus(ctx, node, upid)
	if err != nil {
		return nil, fmt.Errorf("destroy end of vm %d: %w", vmid, err)
	}
	switch {
	case st.BodyUPID != upid:
		return nil, fmt.Errorf("destroy end of vm %d: the status body names task %q, not %q", vmid, st.BodyUPID, upid)
	case st.BodyType != "qmdestroy":
		return nil, fmt.Errorf("destroy end of vm %d: task %s is a %q task, not qmdestroy", vmid, upid, st.BodyType)
	case st.BodyID != strconv.Itoa(vmid):
		return nil, fmt.Errorf("destroy end of vm %d: task %s is for id %q", vmid, upid, st.BodyID)
	case st.BodyNode != node:
		return nil, fmt.Errorf("destroy end of vm %d: task %s ran on node %q, not %q", vmid, upid, st.BodyNode, node)
	case st.Status != "stopped":
		return nil, fmt.Errorf("destroy end of vm %d: task %s is %q, not stopped", vmid, upid, st.Status)
	case st.ExitStatus == "":
		return nil, fmt.Errorf("destroy end of vm %d: task %s stopped with no exit status: %w", vmid, upid, ErrUnverifiableRead)
	}
	return &DestroyEnd{UPID: upid, ExitStatus: st.ExitStatus}, nil
}
