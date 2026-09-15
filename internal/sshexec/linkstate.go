package sshexec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// LinkState is one network interface's observed link state, as reported by
// `ip link show` — a bridge-level sibling to TapLinkState (which reports a
// tap device's bridge-port state via `bridge -j link show` instead). Use
// LinkState for questions about a bridge (or any other top-level interface)
// itself; use TapLinkState for questions about a tap's membership/isolation
// on a bridge it's enslaved to.
type LinkState struct {
	// Exists reports whether iface currently exists as a network interface
	// at all — false is a benign, expected state (e.g. a bridge that hasn't
	// been created yet), not an error condition.
	Exists bool
	// Up reports whether the interface is administratively/operationally
	// up. Only meaningful when Exists is true.
	Up bool
}

// linkDoesNotExistSubstring is the text this project EXPECTS iproute2's
// `ip` command to include in its stderr when asked about an interface that
// doesn't currently exist — based on documented `ip`/iproute2 behavior, NOT
// independently verified against a live host in this implementation
// session (same empirical-verification gap flagged elsewhere in this
// project: TapDeviceName's naming convention, sshexec.RootOnlyFields, the
// digest-conflict error text, and TapLinkState's own
// tapDoesNotExistSubstring above). If a live host's exact wording differs,
// LinkState falls back to treating the command's failure as a hard error
// instead — a safe failure mode, since it only ever narrows down a case
// this function would otherwise misreport as "exists" or panic trying to
// parse; it never masks a real problem as "interface missing".
const linkDoesNotExistSubstring = "does not exist"

// ipLinkEntry is the subset of `ip -j link show`'s per-interface JSON
// object this project needs.
//
// The exact JSON shape of `ip -j link show` is NOT independently verified
// against a live PVE host in this implementation session (same
// empirical-verification gap noted on linkDoesNotExistSubstring and
// TapDeviceName above). Per documented iproute2 behavior, each entry
// carries an "operstate" string (one of "UP", "DOWN", "UNKNOWN", etc. —
// "UNKNOWN" commonly appears for interfaces, like some bridges, whose
// driver doesn't track carrier state) and a "flags" array of strings that
// may include "UP" (the administrative state, IFF_UP) independently of
// operstate. This code treats the interface as Up if EITHER operstate is
// exactly "UP" OR flags contains "UP" — a deliberately permissive OR,
// chosen because operstate alone can under-report a bridge that is
// administratively up but sitting at "UNKNOWN", and flags alone doesn't
// capture actual carrier/operational state. This is a judgment call, not a
// live-verified fact; if a live host's real output disagrees, the
// discrepancy is expected to surface as a wrong Up value here, not a
// crash or a wrong Exists value.
type ipLinkEntry struct {
	IfName    string   `json:"ifname"`
	OperState string   `json:"operstate"`
	Flags     []string `json:"flags"`
}

// LinkState reports iface's current link state by running
// `ip -j link show dev <iface>` (JSON output — considerably more robust to
// parse than ip's plain-text format). Deliberately uses the standard `ip`
// form rather than `bridge -j link show` (see TapLinkState): `ip -j link
// show dev <iface>` reports the queried link's own attributes and works
// for any interface (bridge, tap, physical NIC, ...), whereas `bridge -j
// link show` only enumerates bridge ports. Runs over c's existing SSH
// connection, which must be authenticated as a user with sufficient
// privilege to run `ip` (root, in practice).
func (c *Client) LinkState(ctx context.Context, iface string) (LinkState, error) {
	if iface == "" {
		return LinkState{}, fmt.Errorf("link state: interface name is required")
	}

	cmd := fmt.Sprintf("ip -j link show dev %s", ShellQuote(iface))
	res, err := c.Run(ctx, cmd)
	if err != nil {
		return LinkState{}, fmt.Errorf("link state for %s: %w", iface, err)
	}
	if res.ExitCode != 0 {
		if strings.Contains(res.Stderr, linkDoesNotExistSubstring) {
			return LinkState{Exists: false}, nil
		}
		return LinkState{}, fmt.Errorf("link state for %s: ip exited %d: %s", iface, res.ExitCode, res.Stderr)
	}

	var entries []ipLinkEntry
	if err := json.Unmarshal([]byte(res.Stdout), &entries); err != nil {
		return LinkState{}, fmt.Errorf("link state for %s: parse ip output: %w", iface, err)
	}
	if len(entries) == 0 {
		return LinkState{Exists: false}, nil
	}

	entry := entries[0]
	up := strings.EqualFold(entry.OperState, "UP")
	if !up {
		for _, flag := range entry.Flags {
			if strings.EqualFold(flag, "UP") {
				up = true
				break
			}
		}
	}
	return LinkState{Exists: true, Up: up}, nil
}
