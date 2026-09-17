package pve

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// ShutdownVM issues PVE's GRACEFUL shutdown call —
// POST /nodes/{node}/qemu/{vmid}/status/shutdown — which asks the guest OS
// to shut itself down (ACPI power button / guest agent), as opposed to
// StopVM (vmdestroy.go), which is PVE's hard, immediate stop: the
// equivalent of pulling the power cord, with no chance for the guest to
// flush filesystems or run its own shutdown hooks.
//
// This primitive deliberately exposes NO hard-stop path at all — not as a
// default, not as an opt-in parameter, not as a fallback on timeout. The
// epic (pveforge-vm-lifecycle-ops, item 2e) frames escalation as a CALLER
// decision: a future higher-level "shut down, and if it hasn't completed
// within N, hard-stop" orchestration composes ShutdownVM and StopVM
// explicitly, at a layer where the caller can see that a forcible kill is
// on the table. Burying that escalation inside a shared primitive would
// mean a caller who asked only for a graceful shutdown could forcibly kill
// a running VM — and lose its unflushed guest state — without ever having
// written anything that says so.
//
// WHAT ENFORCES THAT, AND WHAT IT CANNOT DO. Three checks back this up, and
// it is worth being precise about their reach rather than implying a
// guarantee they do not provide (an earlier version of this comment did,
// and review took it apart):
//
//   - TestShutdownVM_MakesExactlyOneRequestOnEveryPath asserts
//     BEHAVIOURALLY that no scenario — success, a PVE rejection, a
//     malformed body — produces more than one outbound request. This is the
//     strongest of the three: it does not care how an escalation is spelled
//     or which file it lives in, only that a second call would be visible
//     on the wire.
//   - TestShutdownVM_ExposesNoHardStopPath pins this method's SIGNATURE by
//     reflection, so a force/timeout parameter cannot be added silently.
//   - The same test walks the call graph reachable from ShutdownVM across
//     the WHOLE package (internal/sourceguard) for stop/kill/force tokens,
//     so a hard-stop helper in a sibling file is caught too.
//
// What none of them can do is stop a contributor who is deliberately
// evading them — a verb assembled from fragments at runtime, or reflection,
// defeats any static check, and chasing that is a treadmill. The threat
// model here is an ACCIDENT: a future contributor adding escalation because
// it seemed helpful, without realising a caller could not see it. Against
// that these hold; against a determined evader they do not, and they are
// not claimed to.
//
// PVE's own status/shutdown endpoint additionally accepts a `timeout`
// query parameter — its own graceful-shutdown deadline, distinct from
// WaitForTask's poll timeout, after which PVE itself gives up. It is NOT
// exposed here in this first cut: it is an additive follow-up, to be
// chosen once real shutdown durations have been observed against a live
// host (the same "revisit with empirical timing data" discipline
// task.go's defaultTaskWaitTimeout already applies to itself). Note that
// PVE's `forceStop` parameter — which DOES escalate to a hard stop when
// that deadline expires — is a separate parameter, and is out of scope for
// this primitive permanently, not just for this first cut.
//
// Goes through RawRequest rather than go-proxmox's own
// VirtualMachine.Shutdown (virtual_machine.go:402), for the same reason
// CreateVM, StopVM, and DestroyVM do: go-proxmox's handleResponse
// (proxmox.go:446-449) discards the response body entirely on HTTP
// 500/501 — exactly the statuses PVE uses for a shutdown-time rejection (a
// VM that is locked by a backup, a VM that isn't running) — and this
// project's raw write path exists precisely so that diagnostic text
// reaches the caller verbatim.
//
// Returns the UPID of the PVE task the shutdown call kicks off — a
// graceful shutdown is always asynchronous on PVE's side, since it waits
// on the guest — for the caller to hand to WaitForTask.
func (c *Client) ShutdownVM(ctx context.Context, node string, vmid int) (string, error) {
	if node == "" {
		return "", fmt.Errorf("shutdown vm %d: node is required", vmid)
	}

	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu/%d/status/shutdown", url.PathEscape(node), vmid), nil)
	if err != nil {
		return "", fmt.Errorf("shutdown vm %d: %w", vmid, err)
	}

	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return "", fmt.Errorf("shutdown vm %d: %w", vmid, err)
	}
	return upid, nil
}
