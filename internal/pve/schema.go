package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// OptionsSchema issues an HTTP OPTIONS request against path (e.g.
// "/nodes/{node}/qemu/{vmid}/config") and returns PVE's own schema
// response verbatim — unwrapped from go-proxmox's "data" envelope (the
// same envelope every other read on this client already goes through),
// but otherwise unreshaped. This is pveforge-discoverability-schema's
// layer 1: PRD §3.5 calls for exposing/proxying Proxmox's own OPTIONS-
// method introspection (the same mechanism pvesh itself is built on)
// rather than hand-authoring a parallel schema, so this method
// deliberately does no translation into a different dialect — that would
// itself be a second, hand-maintained schema representation that could
// drift from PVE's actual (version-dependent) shape, exactly the risk
// PRD §3.5 warns against.
//
// Goes through go-proxmox's own Req rather than a raw HTTP request (the
// way vmconfig.go's write path has to): go-proxmox's handleResponse only
// discards the response body on HTTP 500/501, and a valid OPTIONS
// request returns 200 with an ordinary JSON body its envelope-unwrap
// already handles correctly — none of the reasons vmconfig.go bypasses
// go-proxmox apply here.
//
// NOTE: the exact response shape (a per-HTTP-method breakdown of
// parameter schema: type, description, optional, default, enum, and
// occasionally pattern/format, per Proxmox's own internal API-schema
// dialect) is based on documented Proxmox API-viewer/pvesh behavior, NOT
// independently verified against a live host in this implementation
// session — the same empirical-verification gap flagged elsewhere in
// this project (rootOnlyErrorSubstring, digestConflictErrorSubstring,
// NVMeDrive's QEMU syntax). Whether OPTIONS requires a syntactically real
// node/vmid in path (vs. a placeholder) is similarly unverified. Confirm
// against a live PVE host before a caller (the planned discover CLI)
// trusts this shape for real path grammar.
func (c *Client) OptionsSchema(ctx context.Context, path string) (json.RawMessage, error) {
	if path == "" {
		return nil, fmt.Errorf("options schema: path is required")
	}
	var raw json.RawMessage
	if err := c.pc.Req(ctx, http.MethodOptions, path, nil, &raw); err != nil {
		return nil, fmt.Errorf("options schema %s: %w", path, err)
	}
	return raw, nil
}
