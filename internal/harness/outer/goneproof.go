package outer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// upidRE ports lib.sh:607: PVE::Tools::upid_encode's shape, the pid/pstart/
// starttime fields in hex. Groups: 1=node, 2=type, 3=id (decimal). The final
// user field forbids ':' and whitespace/control (the shell's
// `[^:[:space:][:cntrl:]]`).
var upidRE = regexp.MustCompile(`^UPID:([A-Za-z0-9.-]+):[0-9A-F]{8}:[0-9A-F]{8,}:[0-9A-F]{8}:([a-z]+):([0-9]+):[^:[:space:][:cntrl:]]+:$`)

// taskStatus is /nodes/<node>/tasks/<upid>/status, the fields lib.sh:623-624
// re-asserts on the BODY. PVE reports id and exitstatus as strings.
type taskStatus struct {
	UPID       string `json:"upid"`
	Type       string `json:"type"`
	ID         string `json:"id"`
	Node       string `json:"node"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
}

// DestroyTaskOK ports harness_destroy_task_ok (lib.sh:601-628): the destroy
// of vmid, whose task UPID is given, ran as a qmdestroy task for this vmid on
// this node that PVE reports stopped with exitstatus exactly "OK". WARNINGS
// (a disk the worker could not free) is NOT OK. Two independent checks: the
// UPID STRING is parsed and bound to (node, qmdestroy, vmid), AND — the S1
// requirement — the status BODY's own upid/type/id/node fields are
// re-asserted, so a status whose body names a different task fails even
// though the UPID string parsed fine.
func DestroyTaskOK(ctx context.Context, r Reader, cfg Config, vmid int, upid string) error {
	m := upidRE.FindStringSubmatch(upid)
	if m == nil {
		return fmt.Errorf("the destroy of VM %d printed no task UPID", vmid)
	}
	if m[1] != cfg.Node || m[2] != "qmdestroy" || m[3] != strconv.Itoa(vmid) {
		return fmt.Errorf("the destroy of VM %d printed %s, which is not a qmdestroy task for VM %d on %s", vmid, upid, vmid, cfg.Node)
	}
	raw, err := r.RawRequest(ctx, http.MethodGet, fmt.Sprintf("/nodes/%s/tasks/%s/status", cfg.Node, url.PathEscape(upid)), nil)
	if err != nil {
		return fmt.Errorf("the status of the destroy task %s could not be read: %w", upid, err)
	}
	var st taskStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("the status of the destroy task %s has an unexpected shape: %w", upid, err)
	}
	// Body re-assert (S1): all seven of lib.sh:623-624's conditions, read
	// from the body itself, not the UPID string.
	if st.UPID != upid || st.Type != "qmdestroy" || st.ID != strconv.Itoa(vmid) || st.Node != cfg.Node || st.Status != "stopped" || st.ExitStatus != "OK" {
		return fmt.Errorf("the destroy task %s is not a stopped qmdestroy of VM %d on %s with exitstatus OK (WARNINGS means a disk was not freed)", upid, vmid, cfg.Node)
	}
	return nil
}

// VMIDFree ports harness_vmid_free (lib.sh:572-589): GET /cluster/nextid for
// vmid answers 200 with EXACTLY vmid — PVE answers 200 with the asked id only
// when no VM anywhere in the cluster holds it (400 otherwise). The unwrapped
// body is a single scalar, a JSON number equal to vmid OR a JSON string equal
// to its decimal (lib.sh:585). A string that is not exactly the decimal —
// and anything else — is NOT free. (Must NOT use pve.vmidFree, which returns
// true for any non-empty string, S2.)
func VMIDFree(ctx context.Context, r Reader, vmid int) error {
	raw, err := r.RawRequest(ctx, http.MethodGet, "/cluster/nextid", url.Values{"vmid": {strconv.Itoa(vmid)}})
	if err != nil {
		return fmt.Errorf("/cluster/nextid did not answer 200 for VMID %d: it is in use, or the read failed: %w", vmid, err)
	}
	if !scalarEqualsInt(raw, vmid) {
		return fmt.Errorf("/cluster/nextid answered 200 for VMID %d, but not with %d", vmid, vmid)
	}
	return nil
}

// scalarEqualsInt reports whether raw is a single JSON scalar equal to n:
// the number n (via json.Number, no float coercion) or the string decimal of
// n. Pinned so a mutant that relaxes it (accept any string, or use
// pve.vmidFree) has a concrete line to revert (S2).
func scalarEqualsInt(raw json.RawMessage, n int) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	// lib.sh:585's `jq -s 'length == 1'`: exactly one scalar, nothing after
	// it. A second value (690\n"691") must NOT read as free.
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

// VMGone ports harness_vm_gone (lib.sh:633-652): the destroy task ended OK,
// the VMID is free cluster-wide, and the pool no longer lists it (every
// member's vmid a number, so a string "690" cannot alias). Any failed leg
// means "not proven", returned as a descriptive error; nil means proven gone.
func VMGone(ctx context.Context, r Reader, cfg Config, vmid int, upid string) error {
	if err := DestroyTaskOK(ctx, r, cfg, vmid, upid); err != nil {
		return err
	}
	if err := VMIDFree(ctx, r, vmid); err != nil {
		return err
	}
	pool, err := readPool(ctx, r, cfg.Pool)
	if err != nil {
		return err
	}
	for _, m := range pool.Members {
		// lib.sh:648 requires every member's vmid be a number, so a string
		// "690" cannot alias. A non-numeric member is an unexpected shape:
		// fail closed (not proven gone) rather than read past it.
		id, ok := numericVMID(m.VMID)
		if !ok {
			return fmt.Errorf("pool %s: a member's vmid is not a number (unexpected shape)", cfg.Pool)
		}
		if id == vmid {
			return fmt.Errorf("pool %s still lists VM %d", cfg.Pool, vmid)
		}
	}
	return nil
}
