package sshexec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// TapDeviceName renders PVE's tap-naming convention for one VM's virtual
// NIC: "tap<vmid>i<netIndex>" (e.g. tap100i0 for VM 100's net0). Documented
// PVE convention, NOT independently verified against a live host in this
// implementation session — same empirical-verification gap flagged
// elsewhere in this project (sshexec.RootOnlyFields, the digest-conflict
// error text, internal/device's QEMU args: syntax).
func TapDeviceName(vmid, netIndex int) string {
	return fmt.Sprintf("tap%di%d", vmid, netIndex)
}

// TapLinkState is one tap device's observed bridge-port state.
type TapLinkState struct {
	// Exists reports whether tap currently exists as a network interface at
	// all — false is the expected, benign state whenever the owning VM
	// isn't running (its tap is created fresh on every boot and destroyed
	// on shutdown), not an error condition.
	Exists bool
	// Isolated reports the bridge port's "isolated" flag. Only meaningful
	// when Exists is true.
	Isolated bool
}

// tapDoesNotExistSubstring is the text this project EXPECTS iproute2's
// `bridge` command to include in its stderr when asked about a tap device
// that doesn't currently exist — based on documented `bridge`/iproute2
// behavior, NOT independently verified against a live host in this
// implementation session (same gap as TapDeviceName's naming convention
// above). If a live host's exact wording differs, TapLinkState falls back
// to treating the command's failure as a hard error instead — a safe
// failure mode, since it only ever narrows down a case this function would
// otherwise misreport as "exists" or panic trying to parse; it never masks
// a real problem as "tap missing".
const tapDoesNotExistSubstring = "does not exist"

// bridgeLinkEntry is the subset of `bridge -j link show`'s per-interface
// JSON object this project needs.
type bridgeLinkEntry struct {
	IfName   string `json:"ifname"`
	Isolated bool   `json:"isolated"`
}

// TapLinkState reports tap's current bridge-port state by running
// `bridge -j link show dev <tap>` (JSON output — considerably more robust
// to parse than bridge's plain-text table format). Runs over c's existing
// SSH connection, which must be authenticated as a user with sufficient
// privilege to run `bridge` (root, in practice).
func (c *Client) TapLinkState(ctx context.Context, tap string) (TapLinkState, error) {
	if tap == "" {
		return TapLinkState{}, fmt.Errorf("tap link state: tap device name is required")
	}

	cmd := fmt.Sprintf("bridge -j link show dev %s", ShellQuote(tap))
	res, err := c.Run(ctx, cmd)
	if err != nil {
		return TapLinkState{}, fmt.Errorf("tap link state for %s: %w", tap, err)
	}
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, tapDoesNotExistSubstring) {
			return TapLinkState{Exists: false}, nil
		}
		return TapLinkState{}, fmt.Errorf("tap link state for %s: bridge exited %d: %s", tap, res.ExitCode, res.Stderr)
	}

	var entries []bridgeLinkEntry
	if err := json.Unmarshal([]byte(res.Stdout), &entries); err != nil {
		return TapLinkState{}, fmt.Errorf("tap link state for %s: parse bridge output: %w", tap, err)
	}
	if len(entries) == 0 {
		return TapLinkState{Exists: false}, nil
	}
	return TapLinkState{Exists: true, Isolated: entries[0].Isolated}, nil
}

// SetBridgePortIsolated sets or clears tap's bridge-port "isolated" flag
// via `bridge link set dev <tap> isolated on|off`, immediately affecting a
// live, already-running interface. Runs over c's existing SSH connection
// (root, in practice). Returns an error if tap doesn't currently exist —
// callers that want to skip a not-yet-running VM's tap gracefully should
// check TapLinkState first rather than relying on this to distinguish that
// case.
func (c *Client) SetBridgePortIsolated(ctx context.Context, tap string, isolated bool) error {
	if tap == "" {
		return fmt.Errorf("set bridge port isolated: tap device name is required")
	}

	onOff := "off"
	if isolated {
		onOff = "on"
	}
	cmd := fmt.Sprintf("bridge link set dev %s isolated %s", ShellQuote(tap), onOff)
	res, err := c.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("set bridge port isolated for %s: %w", tap, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("set bridge port isolated for %s: bridge exited %d: %s", tap, res.ExitCode, res.Stderr)
	}
	return nil
}
