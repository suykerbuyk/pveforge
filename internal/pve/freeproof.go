package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// VMIDState is the free-proof's three-way answer. The zero value is
// VMIDUnverified on purpose: an unset result must never read as "free".
type VMIDState int

const (
	// VMIDUnverified: PVE did not give a positive answer either way.
	VMIDUnverified VMIDState = iota
	// VMIDFree: GET /cluster/nextid?vmid=N answered 200 with a single scalar
	// equal to N.
	VMIDFree
	// VMIDInUse: PVE answered 400 and said, in the BODY, that this vmid is in use.
	VMIDInUse
)

// FreeResult is what FreeProof established. There is deliberately no `error`
// return (the in-flight determination's idiom): a signature of (bool, error)
// invites `if err != nil { treat as free }`, and this one has nowhere for that
// branch to live.
type FreeResult struct {
	State  VMIDState
	Read   string // the read that was made
	Detail string // set unless State is VMIDFree: what was observed, one line
}

// FreeProof asks PVE whether vmid is free cluster-wide: GET /cluster/nextid
// with exactly `vmid=N` and nothing else.
//
// WHY THIS IS NOT vmidFree. vmidFree returns (true, nil) for ANY non-empty
// string PVE answers with, so a 200 echoing a different vmid, a longer one or a
// prefix reads as "free". That is the right trade for the create path's
// pin check (a false "free" is caught by the create itself) and the wrong one
// here, where a false "free" is the difference between "destroyed" and
// "something else is still there". FreeProof requires the 200 to carry a single
// JSON scalar equal to THIS vmid (the number N or the string "N", the rule the
// harness's outer.VMIDFree already applies — not imported: the production verb
// must not depend on internal/harness). vmidFree is left untouched.
//
// PVE source (pve-manager API2/Cluster.pm nextid): `permissions => { user =>
// 'all' }`, so this read is NOT principal-filtered; "free" means absent from the
// local pmxcfs guest list, cluster-wide. At 9.2.11 an in-use id is a param
// exception whose body reads "VM N already exists"; on master (commit 0b2f7eea,
// not in 9.2.12) it reads "guest ID N is already in use", and with the next-id
// option's `enforce` set an id outside the range, or with `unique` one used
// before, is also a 400 — which is NOT "in use" and is reported as Unverified
// with that detail (accepted residual R-ENFORCE: fails closed, never a false
// "free").
//
// KNOWN LIMIT, accepted (R-VMLIST): every request begins with cfs_update, and a
// pmxcfs IPC failure empties the guest list, after which nextid answers 200 for
// EVERY id. No client can tell that from freedom; the gone-proof's other leg
// (an exactly-OK destroy) is what stands against it.
func (c *Client) FreeProof(ctx context.Context, vmid int) FreeResult {
	const read = "GET /cluster/nextid"
	if vmid <= 0 {
		return FreeResult{State: VMIDUnverified, Read: read, Detail: fmt.Sprintf("vmid %d is not a valid vmid", vmid)}
	}
	raw, err := c.RawRequest(ctx, http.MethodGet, "/cluster/nextid", url.Values{"vmid": {strconv.Itoa(vmid)}})
	if err != nil {
		// In use is a 400 AND the sentence about THIS vmid in the error text or
		// the body. A 500 quoting it, a 403, a transport error, or a 400 about
		// another vmid is Unverified: never "in use", and never "free".
		if code, ok := HTTPStatus(err); ok && code == http.StatusBadRequest {
			if isVMIDTakenError(err, vmid) {
				return FreeResult{State: VMIDInUse, Read: read, Detail: "PVE says the vmid is already in use: " + oneLine(err.Error())}
			}
			if nextIDEnforcementRejection(err, vmid) {
				return FreeResult{State: VMIDUnverified, Read: read, Detail: fmt.Sprintf("PVE's next-id enforcement rejects vmid %d (range or \"used before\"), which says nothing about whether a guest holds it, so the vmid cannot be proven free on this cluster: %s", vmid, oneLine(err.Error()))}
			}
		}
		return FreeResult{State: VMIDUnverified, Read: read, Detail: oneLine(err.Error())}
	}
	if !scalarEqualsInt(raw, vmid) {
		return FreeResult{State: VMIDUnverified, Read: read, Detail: fmt.Sprintf("answered 200 but not with a single scalar equal to %d", vmid)}
	}
	return FreeResult{State: VMIDFree, Read: read}
}

// scalarEqualsInt reports whether raw is exactly one JSON scalar equal to n:
// the number n (via json.Number, no float coercion) or the string decimal of n.
// A second value after it ("690\n\"691\""), null, an array, an object, another
// vmid, a longer one and a prefix are all not equal.
func scalarEqualsInt(raw json.RawMessage, n int) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	if dec.More() {
		return false
	}
	switch t := v.(type) {
	case json.Number:
		return t.String() == strconv.Itoa(n)
	case string:
		return t == strconv.Itoa(n)
	default:
		return false
	}
}

// nextIDEnforcementRejection reports whether err is master's next-id
// enforcement refusing this vmid for a reason other than "a guest holds it".
func nextIDEnforcementRejection(err error, vmid int) bool {
	text := strings.ToLower(takenText(err))
	id := strconv.Itoa(vmid)
	for _, frag := range []string{
		"guest id " + id + " is below the lower boundary",
		"guest id " + id + " is not below the upper boundary",
		"guest id " + id + " was used before",
	} {
		if strings.Contains(text, frag) {
			return true
		}
	}
	return false
}

// takenText is the text a "this vmid is in use" classifier reads: the error's
// own message AND the response body. On the wire PVE's sentence is in the
// body's errors.vmid (the reason phrase is only "Parameter verification
// failed."), and a StatusError's message carries the body — but the body is
// named here too so a message that stops quoting it cannot silently blind the
// classifier.
func takenText(err error) string {
	var b strings.Builder
	b.WriteString(err.Error())
	var se *StatusError
	if errors.As(err, &se) {
		b.WriteString(" ")
		b.Write(se.Body)
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
