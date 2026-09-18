package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// defaultAgentExecPollInterval is how often WaitForAgentExec polls a
// dispatched guest command's exec-status when the caller passes a
// non-positive pollInterval. A var, not a const, for the same
// test-override reason as task.go's defaultTaskPollInterval — production
// code never changes it.
var defaultAgentExecPollInterval = 500 * time.Millisecond

// defaultAgentExecTimeout bounds how long WaitForAgentExec keeps polling
// a command that never reports an exit, when the caller passes a
// non-positive timeout. A var for the same test-override reason as
// defaultAgentExecPollInterval above.
//
// UNVERIFIED against real guest command timing on a live host — flagged
// explicitly, matching defaultTaskWaitTimeout's precedent for the
// identical kind of guess.
var defaultAgentExecTimeout = 2 * time.Minute

// ErrAgentExecTimeout reports that a dispatched guest command's exit was
// never observed within WaitForAgentExec's deadline.
//
// This is NOT a failure of the command. The command may still be
// running, may have already completed, or (if every status poll was
// itself failing) may have been lost along with the agent. A caller must
// treat it the way IsTaskTimeoutError's own doc comment describes: the
// outcome is unknown, so do not re-execute a non-idempotent guest
// command on the strength of it.
//
// Deliberately pveforge's own sentinel rather than proxmox.ErrTimeout:
// reusing the latter would make IsTaskTimeoutError report true for a
// guest-exec deadline, and those two mean different things and imply
// different recovery.
var ErrAgentExecTimeout = errors.New("guest agent exec did not report exit before the deadline")

// ErrNoGuestInterfaces indicates the guest agent answered but reported no
// usable interfaces at all (an empty list, or nothing but loopback).
// Distinct from ErrNoInterfaceForMAC on purpose: it means the agent is up
// and has nothing to say, which must never be rendered as a confident
// answer about an address.
var ErrNoGuestInterfaces = errors.New("guest agent reported no interfaces")

// ErrNoInterfaceForMAC indicates no guest-reported interface carries the
// requested MAC. Never falls back to "the first interface in the list."
var ErrNoInterfaceForMAC = errors.New("no guest interface reports the given mac address")

// ErrAmbiguousInterfaceForMAC indicates more than one guest-reported
// interface carries the requested MAC — real for bond, bridge and
// macvlan members, which share a hardware address. The caller must
// disambiguate rather than have this package guess.
var ErrAmbiguousInterfaceForMAC = errors.New("more than one guest interface reports the given mac address")

// ErrNoAddressForMAC indicates an interface matched the requested MAC but
// reports no usable address. Distinct from ErrNoInterfaceForMAC because
// it means something different to the caller: the NIC is there and the
// join worked, the guest simply has no routable address on it yet (the
// mid-DHCP case) — wait and retry, rather than fix the MAC.
var ErrNoAddressForMAC = errors.New("guest interface matched the mac address but reports no usable ip address")

// ErrAmbiguousAddressForMAC indicates an interface matched the requested
// MAC and reports more than one usable address, so "the address of this
// NIC" has no single answer. Use AddressesForMAC to see them all.
var ErrAmbiguousAddressForMAC = errors.New("guest interface reports more than one usable ip address")

// ErrNoMACInNetConfig indicates a PVE netN config value carries no MAC
// address in any recognised position.
var ErrNoMACInNetConfig = errors.New("net config value contains no mac address")

// agentUnavailableSubstrings are the PVE error texts this project
// EXPECTS a guest-agent-unreachable rejection to contain — taken from
// go-proxmox's own matcher (virtual_machine.go:694 greps the literal
// "500 QEMU guest agent is not running") plus the second message PVE
// uses when the VM's config carries agent: 0, which that matcher misses
// entirely.
//
// NOT independently verified against a live host, same empirical gap
// flagged throughout this project (digestConflictErrorSubstring,
// rootOnlyErrorSubstring). See IsAgentUnavailableError for why nothing
// in this package's correctness depends on these matching.
var agentUnavailableSubstrings = []string{
	"qemu guest agent is not running",
	"no qemu guest agent configured",
}

// IsAgentUnavailableError reports whether err's message looks like PVE
// rejected a guest-agent call because the agent was not reachable — the
// VM is off, the agent is not installed, it is still coming up, or the
// VM's config never enabled it. A best-effort refinement of an error
// that was already being returned; it can only ever narrow one, never
// manufacture one.
//
// Deliberately NOT load-bearing, and no caller should make a correctness
// decision on it. Two independent reasons, both confirmed from source:
//
//   - The text it matches is one PVE puts in the HTTP status line's
//     REASON PHRASE. HTTP/2 carries no reason phrase, and Go synthesises
//     Response.Status from the status code alone in that case — and this
//     package's client reaches HTTP/2, since it uses
//     http.DefaultTransport (client.go), which sets ForceAttemptHTTP2.
//     Against a host that negotiates h2 the text is gone before pveforge
//     ever sees the error.
//   - PVE uses at least two different messages for the same underlying
//     condition, and they share no substring.
//
// So a false negative is expected and costs only message quality. What
// carries correctness instead is the outcome taxonomy: any non-2xx from
// a guest-agent call is an unobserved outcome carrying PVE's verbatim
// text, and WaitForAgentExec retries uniformly under the caller's
// deadline rather than asking this predicate anything.
func IsAgentUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range agentUnavailableSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

// AgentExecStatus is one guest command's exec-status, decoded from PVE's
// own payload.
//
// A pveforge-owned type rather than go-proxmox's AgentExecStatus
// (types.go:2217), for two reasons beyond this package's standing
// preference for its own raw decode path. go-proxmox types Signal as a
// bool, but QEMU Guest Agent's GuestExecStatus reports signal as the
// signal NUMBER and omits exitcode entirely when a process was
// signal-terminated — so a SIGKILLed command decoded through a plain
// bool Signal and a plain int ExitCode reads as ExitCode == 0, which is
// indistinguishable from a clean success. And go-proxmox types
// ErrTruncated as a plain bool while typing OutTruncated as IntOrBool,
// an asymmetry that is evidence about that library rather than about
// PVE; IntOrBool accepts true/false AND 0/1 (its UnmarshalJSON runs the
// raw bytes through strconv.ParseBool), so it is a strict superset at no
// cost and both flags use it here.
//
// Read NOTHING but Exited until Exited != 0. A 2xx response with
// Exited == 0 means the call succeeded and the command has not finished
// — the "successful call that returns nothing useful" case this unit
// exists to keep separate from a real answer.
type AgentExecStatus struct {
	// Exited is PVE's own completion gate. Zero means the command is
	// still running; every other field is meaningless until it is not.
	Exited int

	// ExitCode is the command's exit status, valid only when ExitCodeSet
	// is true. A non-zero value is a SUCCESSFUL exec of a failing
	// command, never an exec that did not happen.
	ExitCode int

	// ExitCodeSet records whether PVE actually sent an exitcode. QGA
	// omits it on a signal kill, where the Go zero value would otherwise
	// read as a clean exit.
	ExitCodeSet bool

	OutData      string
	OutTruncated proxmox.IntOrBool
	ErrData      string
	ErrTruncated proxmox.IntOrBool

	// Signal is the signal number that terminated the command, or nil
	// when it was not signal-terminated.
	Signal *int

	// Raw is PVE's verbatim exec-status payload, kept so nothing PVE
	// reported is lost even if a field above is typed wrong — the same
	// standing rule decodeUPIDScalar's doc comment invokes.
	Raw json.RawMessage
}

// Succeeded reports the one combination that means the command ran and
// finished cleanly: it exited, it was not killed by a signal, and PVE
// reported an exit code of zero.
//
// A signal kill is deliberately not success even though QGA leaves
// exitcode absent in that case (which a plain int field would surface as
// 0).
//
// The Signal check is kept even though ExitCodeSet already rejects every
// well-formed signal kill on its own: QGA documents signal and exitcode
// as mutually exclusive, and this is the line that holds if a PVE or QGA
// build ever sends both. Without it such a response would report a
// SIGKILLed command as a clean success. That contract violation is the
// one case in which this check decides anything, so it has its own
// fixture in the tests — otherwise the line would be deletable with a
// green suite.
//
// Callers wanting "the command failed" as a Go error check this
// themselves — matching sshexec.Run's own contract, where a non-zero
// remote exit status is data on the result and the error return is
// reserved for outcomes that were never observed.
func (s *AgentExecStatus) Succeeded() bool {
	if s == nil || s.Exited == 0 {
		return false
	}
	if s.Signal != nil {
		return false
	}
	return s.ExitCodeSet && s.ExitCode == 0
}

// AgentExecTimeoutError reports that a guest command's exit was never
// observed before WaitForAgentExec's deadline elapsed.
//
// LastErr is the most recent status-poll error, or nil when every poll
// succeeded and the command simply had not exited yet. That difference
// is this type's whole diagnostic value — "the agent kept answering and
// the command kept running" and "every poll failed and here is PVE's
// last complaint" are different situations that a bare sentinel cannot
// tell apart.
//
// Typed, mirroring TaskFailedError (task.go) — this package's existing
// precedent for an outcome carrying structured detail a sentinel cannot
// express.
type AgentExecTimeoutError struct {
	VMID    int
	PID     int
	Timeout time.Duration
	Polls   int
	LastErr error
}

func (e *AgentExecTimeoutError) Error() string {
	if e.LastErr != nil {
		return fmt.Sprintf("wait for agent exec on vm %d pid %d: %s after %s (%d polls); last poll error: %v",
			e.VMID, e.PID, ErrAgentExecTimeout.Error(), e.Timeout, e.Polls, e.LastErr)
	}
	return fmt.Sprintf("wait for agent exec on vm %d pid %d: %s after %s (%d polls); every poll succeeded and the command had not exited",
		e.VMID, e.PID, ErrAgentExecTimeout.Error(), e.Timeout, e.Polls)
}

// Unwrap exposes both ErrAgentExecTimeout and, when there was one, the
// last poll error — so errors.Is finds the sentinel and any transport
// sentinel underneath it.
func (e *AgentExecTimeoutError) Unwrap() []error {
	if e.LastErr != nil {
		return []error{ErrAgentExecTimeout, e.LastErr}
	}
	return []error{ErrAgentExecTimeout}
}

// IsAgentExecTimeoutError reports whether err is (or wraps) the deadline
// WaitForAgentExec returns when a guest command's exit was never
// observed. False for a context cancellation and false for a command
// that ran and exited non-zero — those are different outcomes and a
// caller that cannot tell them apart will retry blind.
//
// Mirrors IsTaskTimeoutError's precedent of giving callers pveforge's
// own predicate rather than expecting them to match on an error value
// from elsewhere.
func IsAgentExecTimeoutError(err error) bool {
	return errors.Is(err, ErrAgentExecTimeout)
}

// AgentExec dispatches command inside vmid's guest via the QEMU guest
// agent — POST /nodes/{node}/qemu/{vmid}/agent/exec — and returns the
// pid PVE assigns the running command, for WaitForAgentExec to poll.
//
// command is argv, not a shell line: PVE executes command[0] with
// command[1:] as its arguments and no shell is involved, so anything
// needing shell semantics must say so explicitly (e.g.
// []string{"/bin/sh", "-c", script}). inputData is fed to the command's
// stdin and is sent raw, not base64.
//
// Goes through RawRequest rather than go-proxmox's own
// VirtualMachine.AgentExec, for this project's standing reason —
// go-proxmox's handleResponse discards the response body entirely on
// HTTP 500/501, which is exactly the status PVE uses to report that the
// guest agent is not running — and for two defects specific to that
// method: it never checks its own Post error, so every transport failure
// surfaces as the misleading "no pid returned from agent exec command",
// and it decodes the pid with an unchecked type assertion
// (int(p.(float64))) that panics rather than erroring if PVE ever
// returns a stringified pid. This package has no panic recovery
// anywhere, the same reasoning WaitForTask applies to NewTask's own
// off-by-one.
//
// An error here means the command was NOT dispatched: the agent may be
// absent, the VM stopped, the agent still coming up, or simply
// unresponsive. This method does not attempt to tell those apart — PVE's
// own verbatim text reaches the caller instead of a guess about it (see
// IsAgentUnavailableError for the best-effort refinement and why it is
// not load-bearing). It never reports a dispatch failure as a zero pid
// with a nil error.
//
// UNVERIFIED against a live host: command is sent as repeated form
// values (command=a&command=b&command=c), PVE's own -alist array
// convention under form encoding. go-proxmox sends this endpoint a JSON
// array instead, since its Post path JSON-encodes; if a live host
// rejects the form encoding, the fallback is a JSON-bodied request
// rather than a different form shape.
func (c *Client) AgentExec(ctx context.Context, node string, vmid int, command []string, inputData string) (int, error) {
	if node == "" {
		return 0, fmt.Errorf("agent exec on vm %d: node is required", vmid)
	}
	if len(command) == 0 {
		return 0, fmt.Errorf("agent exec on vm %d: command is required", vmid)
	}
	for i, arg := range command {
		if arg == "" {
			return 0, fmt.Errorf("agent exec on vm %d: command element %d is empty", vmid, i)
		}
	}

	form := url.Values{}
	form["command"] = command
	form.Set("input-data", inputData)

	raw, err := c.RawRequest(ctx, http.MethodPost,
		fmt.Sprintf("/nodes/%s/qemu/%d/agent/exec", url.PathEscape(node), vmid), form)
	if err != nil {
		return 0, fmt.Errorf("agent exec on vm %d: %w", vmid, err)
	}

	pid, err := decodeAgentExecPID(raw)
	if err != nil {
		return 0, fmt.Errorf("agent exec on vm %d: %w", vmid, err)
	}
	return pid, nil
}

// decodeAgentExecPID decodes raw — RawRequest's already
// envelope-unwrapped response — as PVE's {"pid": N} exec dispatch reply.
//
// A strict sibling of decodeUPIDScalar rather than a reuse of
// kvjson.Scalar, for the reason that function's own doc comment gives:
// a permissive decode would reinterpret an unexpected shape as a
// plausible-looking value instead of surfacing it as the decode failure
// it is. The int-specific trap this adds on top: an ABSENT "pid" key
// leaves the Go zero value with no error at all, so presence is checked
// explicitly through a pointer and never inferred from pid != 0.
func decodeAgentExecPID(raw json.RawMessage) (int, error) {
	if string(trimJSON(raw)) == "null" {
		return 0, fmt.Errorf("decode exec pid: unexpected response %s: expected an object with a pid, got null", raw)
	}
	var reply struct {
		PID *int `json:"pid"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return 0, fmt.Errorf("decode exec pid: unexpected response %s: %w", raw, err)
	}
	if reply.PID == nil {
		return 0, fmt.Errorf("decode exec pid: unexpected response %s: no pid field", raw)
	}
	return *reply.PID, nil
}

// agentExecStatusWire is the wire shape of PVE's exec-status payload,
// decoded into the exported AgentExecStatus by AgentExecStatus below.
//
// Pointer fields are the ones whose ABSENCE carries meaning: exitcode is
// omitted on a signal kill, and signal is absent on a normal exit.
//
// Note this payload sits DIRECTLY under the data envelope, with no inner
// "result" key — unlike network-get-interfaces, which has one. The
// asymmetry is PVE's, not a mistake here; go-proxmox's own fixtures
// document it in the same words.
type agentExecStatusWire struct {
	Exited       int               `json:"exited"`
	ExitCode     *int              `json:"exitcode"`
	OutData      string            `json:"out-data"`
	OutTruncated proxmox.IntOrBool `json:"out-truncated"`
	ErrData      string            `json:"err-data"`
	ErrTruncated proxmox.IntOrBool `json:"err-truncated"`
	Signal       *int              `json:"signal"`
}

// AgentExecStatus fetches one dispatched guest command's status —
// GET /nodes/{node}/qemu/{vmid}/agent/exec-status?pid={pid}.
//
// Returns the status as PVE reported it, including for a command that
// has not finished (Exited == 0). Interpreting that gate is the caller's
// job, or WaitForAgentExec's; this method does not wait and does not
// judge. An error means the status was not retrieved at all, which says
// nothing about what the command did.
func (c *Client) AgentExecStatus(ctx context.Context, node string, vmid, pid int) (*AgentExecStatus, error) {
	if node == "" {
		return nil, fmt.Errorf("agent exec status on vm %d: node is required", vmid)
	}

	params := url.Values{}
	params.Set("pid", strconv.Itoa(pid))

	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/qemu/%d/agent/exec-status", url.PathEscape(node), vmid), params)
	if err != nil {
		return nil, fmt.Errorf("agent exec status on vm %d pid %d: %w", vmid, pid, err)
	}

	status, err := decodeAgentExecStatus(raw)
	if err != nil {
		return nil, fmt.Errorf("agent exec status on vm %d pid %d: %w", vmid, pid, err)
	}
	return status, nil
}

func decodeAgentExecStatus(raw json.RawMessage) (*AgentExecStatus, error) {
	if string(trimJSON(raw)) == "null" {
		return nil, fmt.Errorf("decode exec status: unexpected response %s: expected an exec-status object, got null", raw)
	}
	var wire agentExecStatusWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode exec status: unexpected response %s: %w", raw, err)
	}

	status := &AgentExecStatus{
		Exited:       wire.Exited,
		OutData:      wire.OutData,
		OutTruncated: wire.OutTruncated,
		ErrData:      wire.ErrData,
		ErrTruncated: wire.ErrTruncated,
		Signal:       wire.Signal,
		Raw:          raw,
	}
	if wire.ExitCode != nil {
		status.ExitCode = *wire.ExitCode
		status.ExitCodeSet = true
	}
	return status, nil
}

// WaitForAgentExec polls a dispatched guest command's exec-status until
// it reports an exit, the caller's ctx ends, or timeout elapses.
//
// pollInterval and timeout fall back to package defaults when
// non-positive. The deadline is an explicit parameter rather than a
// package var (WaitForTask's own shape) because a witness deadline is
// per-call policy — pveforge-vm-rollback-witness supplies its own.
//
// Returns the status for ANY completed command, including one that
// exited non-zero or was killed by a signal: those ran, and a caller
// that needs "the command failed" as a Go error asks Succeeded(). The
// error return is reserved for outcomes that were never observed at all.
//
// Behavior on a failed status poll: it retries. A poll failure is not
// treated as a terminal answer, because the alternative is worse — a
// transient blip would return an error that tells the caller nothing
// about whether the guest command ran, and the caller's only route to an
// answer would be re-executing a command that is not idempotent.
// Re-polling the pid, by contrast, is free and side-effect-free, and the
// retry window is bounded by the caller's own timeout. The most recent
// poll error is carried forward and reported on the returned
// AgentExecTimeoutError rather than discarded.
//
// A CONTEXT error is the exception and fails fast: the caller has said
// to stop, and burning the remaining deadline on calls that cannot
// succeed serves nobody. It comes back wrapped, so
// errors.Is(err, context.Canceled) and errors.Is(err,
// context.DeadlineExceeded) both work and IsAgentExecTimeoutError
// reports false — a cancellation and an expired deadline are different
// things.
func (c *Client) WaitForAgentExec(ctx context.Context, node string, vmid, pid int, pollInterval, timeout time.Duration) (*AgentExecStatus, error) {
	if node == "" {
		return nil, fmt.Errorf("wait for agent exec on vm %d: node is required", vmid)
	}
	if pollInterval <= 0 {
		pollInterval = defaultAgentExecPollInterval
	}
	if timeout <= 0 {
		timeout = defaultAgentExecTimeout
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastErr error
	polls := 0
	for {
		status, err := c.AgentExecStatus(ctx, node, vmid, pid)
		polls++
		switch {
		case err == nil:
			lastErr = nil
			if status.Exited != 0 {
				return status, nil
			}
		case ctx.Err() != nil:
			// The caller stopped us; do not spend the remaining
			// deadline on calls that cannot succeed.
			//
			// Not redundant with the select's own ctx.Done() case
			// below, which is what makes this worth stating: when the
			// caller cancels AND the deadline has already elapsed, both
			// of that select's cases are ready at once and Go picks
			// between them at RANDOM — so roughly half of those calls
			// would report a deadline when what actually happened is
			// that the caller stopped. Deciding it here makes the
			// classification deterministic, and a caller cannot act on
			// one that changes run to run.
			return nil, fmt.Errorf("wait for agent exec on vm %d pid %d: %w", vmid, pid, ctx.Err())
		default:
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for agent exec on vm %d pid %d: %w", vmid, pid, ctx.Err())
		case <-deadline.C:
			return nil, &AgentExecTimeoutError{
				VMID: vmid, PID: pid, Timeout: timeout, Polls: polls, LastErr: lastErr,
			}
		case <-ticker.C:
		}
	}
}

// AgentIPAddress is one address the guest agent reports on an interface.
// Mirrors PVE's own per-address object shape, which is an OBJECT and
// never a bare string.
type AgentIPAddress struct {
	Address string `json:"ip-address"`
	Type    string `json:"ip-address-type"`
	Prefix  int    `json:"prefix"`
}

// AgentInterface is one interface the guest agent reports, carrying its
// own MAC — which is what makes a MAC join against pveforge's netN
// config values possible in the first place.
type AgentInterface struct {
	Name            string           `json:"name"`
	HardwareAddress string           `json:"hardware-address"`
	IPAddresses     []AgentIPAddress `json:"ip-addresses"`
}

// agentInterfacesWire is the inner envelope PVE wraps this one endpoint's
// payload in, INSIDE the data envelope RawRequest already strips.
//
// This is not uniform across the agent surface and must not be
// generalised: agent/exec and agent/exec-status put their payloads
// directly under data, while agent/network-get-interfaces nests its
// array under a "result" key. go-proxmox states the rule in its own
// words — "PVE wraps most QGA responses in a single {"result": ...}
// envelope on top of the standard {"data": ...} envelope the client
// already strips" — and its exec-status fixture carries the matching
// exception note. Decoding this endpoint as a bare array fails on every
// live call.
type agentInterfacesWire struct {
	Result []AgentInterface `json:"result"`
}

// AgentInterfaces fetches the interfaces the guest agent reports —
// GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces.
//
// Loopback is filtered out, matching go-proxmox's own precedent for this
// endpoint. An empty result is returned as an empty slice with a nil
// error: "the agent answered and reported nothing" is a real answer this
// method is allowed to give, and AddressForMAC is where that becomes the
// refusal it needs to be rather than a confident address.
func (c *Client) AgentInterfaces(ctx context.Context, node string, vmid int) ([]AgentInterface, error) {
	if node == "" {
		return nil, fmt.Errorf("agent interfaces on vm %d: node is required", vmid)
	}

	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/qemu/%d/agent/network-get-interfaces", url.PathEscape(node), vmid), nil)
	if err != nil {
		return nil, fmt.Errorf("agent interfaces on vm %d: %w", vmid, err)
	}
	if string(trimJSON(raw)) == "null" {
		return nil, fmt.Errorf("agent interfaces on vm %d: unexpected response %s: expected an object with a result list, got null", vmid, raw)
	}

	var wire agentInterfacesWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("agent interfaces on vm %d: unexpected response %s: %w", vmid, raw, err)
	}

	ifaces := make([]AgentInterface, 0, len(wire.Result))
	for _, iface := range wire.Result {
		if iface.Name == "lo" {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

// AddressesForMAC returns every address the guest reports on the single
// interface carrying mac, unfiltered and in the order the agent gave
// them — for a caller that wants to choose for itself rather than have
// AddressForMAC refuse on its behalf.
//
// Applies the same 0/1/many contract to the INTERFACE join that
// AddressForMAC does; only the address-level narrowing is skipped.
func AddressesForMAC(ifaces []AgentInterface, mac string) ([]AgentIPAddress, error) {
	iface, err := interfaceForMAC(ifaces, mac)
	if err != nil {
		return nil, err
	}
	return iface.IPAddresses, nil
}

// AddressForMAC joins a guest-reported interface list against one
// configured MAC and returns that NIC's single usable address.
//
// Two independently-fetched sets are being correlated, so every way the
// join can fail to produce exactly one answer gets its own sentinel and
// every one of them errs toward refusing rather than guessing — matching
// FindByTag's established 0/1/many contract rather than inventing a new
// shape:
//
//   - nothing to join against    -> ErrNoGuestInterfaces
//   - no interface carries mac   -> ErrNoInterfaceForMAC
//   - several interfaces do      -> ErrAmbiguousInterfaceForMAC
//   - matched, no usable address -> ErrNoAddressForMAC
//   - matched, several usable    -> ErrAmbiguousAddressForMAC
//
// It never falls back to "the first interface in the list" — the
// shortcut quantum-ng's own script rejected after finding it unreliable,
// and the reason this joins on MAC at all.
//
// "Usable" excludes loopback and link-local (IPv6 fe80::/10, IPv4
// 169.254.0.0/16). That filter is what makes the many-check workable
// rather than useless: essentially every real dual-stack Linux guest
// reports an IPv6 link-local alongside its real address, so without it
// this would either refuse on every such guest or, worse, confidently
// return fe80::... as the answer. Filtering first means it refuses only
// on genuine ambiguity.
func AddressForMAC(ifaces []AgentInterface, mac string) (AgentIPAddress, error) {
	iface, err := interfaceForMAC(ifaces, mac)
	if err != nil {
		return AgentIPAddress{}, err
	}

	var usable []AgentIPAddress
	for _, addr := range iface.IPAddresses {
		if isUsableGuestAddress(addr.Address) {
			usable = append(usable, addr)
		}
	}

	switch len(usable) {
	case 0:
		return AgentIPAddress{}, fmt.Errorf("address for mac %q: interface %q: %w", mac, iface.Name, ErrNoAddressForMAC)
	case 1:
		return usable[0], nil
	default:
		return AgentIPAddress{}, fmt.Errorf("address for mac %q: interface %q: %d usable addresses: %w",
			mac, iface.Name, len(usable), ErrAmbiguousAddressForMAC)
	}
}

// interfaceForMAC is the interface half of the join, shared by
// AddressForMAC and AddressesForMAC so both apply an identical contract.
func interfaceForMAC(ifaces []AgentInterface, mac string) (AgentInterface, error) {
	want, err := canonicalMAC(mac)
	if err != nil {
		return AgentInterface{}, fmt.Errorf("address for mac %q: %w", mac, err)
	}
	if len(ifaces) == 0 {
		return AgentInterface{}, fmt.Errorf("address for mac %q: %w", mac, ErrNoGuestInterfaces)
	}

	var matches []AgentInterface
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			continue
		}
		got, err := canonicalMAC(iface.HardwareAddress)
		if err != nil {
			// An interface the guest reports without a parseable MAC
			// cannot participate in a MAC join; skipping it is not the
			// same as matching it.
			continue
		}
		if got == want {
			matches = append(matches, iface)
		}
	}

	switch len(matches) {
	case 0:
		return AgentInterface{}, fmt.Errorf("address for mac %q: %w", mac, ErrNoInterfaceForMAC)
	case 1:
		return matches[0], nil
	default:
		return AgentInterface{}, fmt.Errorf("address for mac %q: %d matches: %w", mac, len(matches), ErrAmbiguousInterfaceForMAC)
	}
}

// canonicalMAC normalises a MAC to net.HardwareAddr's canonical
// lowercase colon form, so "AA-BB-CC-DD-EE-FF" and "aa:bb:cc:dd:ee:ff"
// join correctly instead of silently failing to match. An unparseable
// value is an error, never a value that quietly matches nothing.
func canonicalMAC(mac string) (string, error) {
	parsed, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return "", fmt.Errorf("unparseable mac address %q: %w", mac, err)
	}
	return parsed.String(), nil
}

// isUsableGuestAddress reports whether addr is an address a caller could
// actually reach the guest on — excluding loopback and link-local, which
// a guest reports alongside its real address and which are never the
// answer to "what address is this NIC on".
func isUsableGuestAddress(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() {
		return false
	}
	return !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

// MACFromNetConfig extracts the MAC address from a PVE netN config value
// (e.g. "virtio=BC:24:11:2E:C5:4A,bridge=vmbr0,firewall=1") — the other
// half of the MAC join, since AddressForMAC's caller has to get the MAC
// from somewhere and the VM's own config is where it lives.
//
// Prefers an explicit "macaddr=" key when present; otherwise takes the
// first comma-separated k=v pair whose VALUE parses as a MAC. Matching
// on the value rather than on the key avoids maintaining an allowlist of
// PVE NIC models (virtio, e1000, e1000e, vmxnet3, rtl8139, ...), which
// grows whenever PVE adds one and would silently return
// ErrNoMACInNetConfig for any model not on it.
func MACFromNetConfig(netValue string) (string, error) {
	var fallback string
	for _, part := range strings.Split(netValue, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		canonical, err := canonicalMAC(value)
		if err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "macaddr") {
			return canonical, nil
		}
		if fallback == "" {
			fallback = canonical
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("mac from net config %q: %w", netValue, ErrNoMACInNetConfig)
	}
	return fallback, nil
}

// VMNetMACs reads vmid's config and returns the configured MAC of every
// netN interface, keyed by N — the config-side set of the MAC join.
//
// Reads the raw config via RawRequest rather than GetVM's typed
// proxmox.VirtualMachineConfig, which models only Net0 through Net5: a
// VM with net6 or higher would silently lose those interfaces, and
// silently returning a short map is exactly the kind of confident-but-
// incomplete answer this unit exists to avoid. A netN value carrying no
// MAC is skipped rather than failing the whole read — one unusual
// interface must not make the other interfaces unreadable.
func (c *Client) VMNetMACs(ctx context.Context, node string, vmid int) (map[int]string, error) {
	if node == "" {
		return nil, fmt.Errorf("vm net macs on vm %d: node is required", vmid)
	}

	raw, err := c.RawRequest(ctx, http.MethodGet,
		fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(node), vmid), nil)
	if err != nil {
		return nil, fmt.Errorf("vm net macs on vm %d: %w", vmid, err)
	}
	if string(trimJSON(raw)) == "null" {
		return nil, fmt.Errorf("vm net macs on vm %d: unexpected response %s: expected a config object, got null", vmid, raw)
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("vm net macs on vm %d: unexpected response %s: %w", vmid, raw, err)
	}

	macs := map[int]string{}
	for key, rawValue := range config {
		n, ok := netConfigIndex(key)
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			continue
		}
		mac, err := MACFromNetConfig(value)
		if err != nil {
			continue
		}
		macs[n] = mac
	}
	return macs, nil
}

// netConfigIndex extracts N from a PVE "netN" config key. ok is false for
// anything that is not exactly "net" followed by one or more ASCII
// digits — "net" alone, "netx", "network", or a mixed suffix. Mirrors
// internal/idempotent's own interfaceIndexFromKey, kept local rather than
// exported across the package boundary for one caller.
func netConfigIndex(key string) (int, bool) {
	suffix, found := strings.CutPrefix(key, "net")
	if !found || suffix == "" {
		return 0, false
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return n, true
}

// trimJSON trims surrounding whitespace from a raw JSON value so the
// explicit null checks above compare against the value itself. Mirrors
// decodeUPIDScalar's own bytes.TrimSpace guard, which exists because
// json.Unmarshal of a JSON null is a documented no-op on a non-pointer
// target rather than a type error — a silently zero result would
// otherwise sail straight through.
func trimJSON(raw json.RawMessage) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}
