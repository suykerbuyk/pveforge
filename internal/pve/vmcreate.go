package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// CreateVM issues PVE's create-VM call — POST /nodes/{node}/qemu — for
// vmid on node. params carries every OTHER raw PVE create parameter the
// caller wants set at creation time (name, net0, ipconfig0, agent, tags,
// cores, memory, scsi0, ...); this method's only job on top of that is
// stamping vmid onto it and dispatching the call — no structured
// create-options type, mirroring vm set's own raw/schema-free precedent
// (see VMFieldsEnsure's doc comment in internal/idempotent for why a
// schema-free write is the right shape for PVE's own exotic, ever-growing
// parameter surface).
//
// Returns the UPID of the PVE task the create call kicks off — creating a
// VM is always asynchronous on PVE's side, even for a trivial config — so
// the caller is expected to hand this straight to WaitForTask.
//
// Goes through RawRequest — this project's own raw-HTTP write path — for
// the same reason RawRequest and vmconfig.go's SetVMConfigFieldCAS do:
// go-proxmox's handleResponse discards the response body entirely on HTTP
// 500/501, which is exactly the status PVE tends to use for a create-time
// rejection (a vmid collision, an invalid parameter, an out-of-space
// storage target). Losing that text here would defeat the entire reason
// this project has its own raw write path: PVE's own diagnostic text is
// supposed to reach the caller unparsed and verbatim (RawRequest's own
// doc comment).
func (c *Client) CreateVM(ctx context.Context, node string, vmid int, params url.Values) (string, error) {
	if node == "" {
		return "", fmt.Errorf("create vm %d: node is required", vmid)
	}

	if params == nil {
		params = url.Values{}
	}
	params.Set("vmid", strconv.Itoa(vmid))

	raw, err := c.RawRequest(ctx, http.MethodPost, fmt.Sprintf("/nodes/%s/qemu", url.PathEscape(node)), params)
	if err != nil {
		return "", fmt.Errorf("create vm %d: %w", vmid, err)
	}

	upid, err := decodeUPIDScalar(raw)
	if err != nil {
		return "", fmt.Errorf("create vm %d: %w", vmid, err)
	}
	return upid, nil
}

// decodeUPIDScalar decodes raw — RawRequest's already envelope-unwrapped
// response — as a plain JSON string, the shape PVE returns for a create
// call's UPID (RawRequest's own doc comment notes this exact case: "PVE
// often returns a UPID task-id string for POST").
//
// Deliberately does NOT reuse internal/kvjson.Scalar for this, even though
// it does something superficially similar: Scalar is built for
// kvjson.Render's KV-rendering use case, where silently falling back to
// the raw trimmed JSON text for any non-string value is the CORRECT,
// permissive behavior — it exists to render arbitrary already-successful
// getter output, not to validate a specific expected shape. Reusing it
// here would mean a malformed or unexpected CreateVM response (PVE
// returning an object, a number, or null instead of the UPID string this
// endpoint is documented to return) gets silently reinterpreted as some
// plausible-looking string rather than surfaced as the decode failure it
// actually is — exactly the kind of silent misread this project's own
// standing rule (PVE's response must propagate cleanly, never get
// swallowed or reworded) exists to prevent. json.Unmarshal into a plain
// Go string is strict by construction for any non-string value EXCEPT
// JSON null, which encoding/json specifically defines as a no-op on a
// non-pointer target rather than a type-mismatch error — handled here as
// an explicit extra check, since a silently empty UPID would otherwise
// sail straight through to WaitForTask.
func decodeUPIDScalar(raw json.RawMessage) (string, error) {
	if string(bytes.TrimSpace(raw)) == "null" {
		return "", fmt.Errorf("decode upid: unexpected response %s: expected a UPID string, got null", raw)
	}
	var upid string
	if err := json.Unmarshal(raw, &upid); err != nil {
		return "", fmt.Errorf("decode upid: unexpected response %s: %w", raw, err)
	}
	return upid, nil
}
