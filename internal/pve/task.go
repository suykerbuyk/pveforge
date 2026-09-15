package pve

import (
	"context"
	"fmt"
	"strings"
	"time"

	proxmox "github.com/luthermonson/go-proxmox"
)

// defaultTaskPollInterval is how often WaitForTask polls a running task's
// status. A var, not a const, purely so this package's own tests can point
// it at a few milliseconds instead of waiting out a real second per poll
// tick — production code never changes it. Mirrors the same pattern
// routed.go already uses for sshPort.
var defaultTaskPollInterval = time.Second

// defaultTaskWaitTimeout bounds how long WaitForTask will keep polling a
// task that never leaves the "running" state before giving up with
// proxmox.ErrTimeout. A var for the same test-override reason as
// defaultTaskPollInterval above.
var defaultTaskWaitTimeout = 10 * time.Minute

// TaskFailedError reports that a PVE task ran to completion but finished
// unsuccessfully (ExitStatus other than "OK") — distinct from a transport
// or timeout error, which WaitForTask returns wrapped with context but not
// as a TaskFailedError, since those mean the task's actual outcome was
// never observed at all.
type TaskFailedError struct {
	UPID       string
	ExitStatus string
}

func (e *TaskFailedError) Error() string {
	return fmt.Sprintf("task %s failed: %s", e.UPID, e.ExitStatus)
}

// WaitForTask polls a PVE task to completion and reports whether it
// succeeded. node is the PVE node the task is running on (a UPID embeds
// its own node, but callers already know which node they dispatched the
// mutation to, and RoutedClient's own pass-through keeps node as an
// explicit parameter to match GetVM and the other typed getters, rather
// than relying solely on what's embedded in upid).
//
// upid's shape is validated BEFORE it is ever handed to proxmox.NewTask or
// used in any network call. This matters because of a confirmed bug in
// go-proxmox@v0.8.1's NewTask: its own guard is `len(sp) < 7`, but it then
// indexes sp[7] — a UPID that splits into exactly 7 colon-separated fields
// passes that guard and then panics with an out-of-range index inside
// NewTask itself. A genuine PVE UPID always has 9 fields (8 colons), so
// this can't fire from real PVE output, but pveforge has no panic recovery
// anywhere, so a malformed UPID reaching that code must never be allowed
// to get there at all — and since proxmox.Task.Ping calls NewTask again on
// every single poll, the check has to happen once, up front, here, rather
// than relying on anything downstream.
//
// A related, still-unfixed-upstream risk in the same area: proxmox.Task's
// UnmarshalJSON copies every field present in a status response onto the
// Task via reflection, including UPID and Node — a response body that
// omits those two fields silently zeroes them on the Task, which can then
// nil-panic inside go-proxmox's own Ping on a later poll (NewTask("", ...)
// returns nil, and Ping dereferences it). Real PVE always sends both
// fields, so this hasn't been observed against a live cluster, but it's
// worth knowing before adding a second caller (e.g. the create/clone/
// destroy Ops landing with pveforge-vm-lifecycle-ops): it lives inside
// go-proxmox's own response handling, past anything this function's own
// pre-check can reach.
func (c *Client) WaitForTask(ctx context.Context, node, upid string) error {
	if node == "" {
		return fmt.Errorf("wait for task: node is required")
	}
	if upid == "" {
		return fmt.Errorf("wait for task: upid is required")
	}
	if strings.Count(upid, ":") < 7 {
		return fmt.Errorf("wait for task: malformed upid %q: expected at least 8 colon-separated fields", upid)
	}

	task := proxmox.NewTask(proxmox.UPID(upid), c.pc)
	if task == nil {
		// proxmox.NewTask only returns nil for an empty UPID today, which
		// the check above already excludes — this stays as a defensive
		// backstop against that behavior ever changing upstream, not dead
		// code: this same library boundary already proved unreliable once
		// (the sp[7] off-by-one this function's pre-check guards against).
		return fmt.Errorf("wait for task: empty upid")
	}
	if task.Node != node {
		return fmt.Errorf("wait for task: upid %q is for node %q, not %q", upid, task.Node, node)
	}

	if err := task.Wait(ctx, defaultTaskPollInterval, defaultTaskWaitTimeout); err != nil {
		return fmt.Errorf("wait for task %s: %w", upid, err)
	}

	if !task.IsSuccessful {
		return &TaskFailedError{UPID: upid, ExitStatus: task.ExitStatus}
	}
	return nil
}
