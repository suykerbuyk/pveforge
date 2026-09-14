package pve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SetVMConfigField sets a single VM config field via PVE's raw
// /nodes/{node}/qemu/{vmid}/config endpoint — the schema-free write
// primitive PRD §3.3 calls for (raw name/value pairs matching Proxmox's
// own parameter names 1:1).
//
// This makes its own HTTP request rather than going through go-proxmox's
// Client.Req / VirtualMachine.Config(Sync): go-proxmox's handleResponse
// discards the response body entirely on HTTP 500/501
// (`return errors.New(res.Status)`, body never read) — and that is
// exactly the status Proxmox uses for the root-only-field rejection this
// project is built around (verified: HTTP 500, "only root can set 'args'
// config"). Going through go-proxmox for this call would mean that text
// could never be surfaced. Everything else on Client (reads, ListNodes)
// keeps using go-proxmox unchanged; only this one write path is raw.
//
// On a non-2xx response, the error includes the response body TRIMMED but
// otherwise VERBATIM — deliberately not parsed as JSON or reformatted.
// This project's own standing rule is that Proxmox's error text must
// propagate cleanly to the CLI user, not get swallowed or reworded, and
// PVE's exact error-body shape across versions/endpoints hasn't been
// independently verified against a live host (same empirical-verification
// gap flagged for the root-only-fields registry and pveum's JSON output
// in the bootstrap task) — passing it through unparsed is the safe
// default until that's confirmed.
func (c *Client) SetVMConfigField(ctx context.Context, node string, vmid int, field, value string) error {
	if node == "" {
		return fmt.Errorf("set vm %d field %q: node is required", vmid, field)
	}
	if field == "" {
		return fmt.Errorf("set vm %d config: field name is required", vmid)
	}

	form := url.Values{}
	form.Set(field, value)

	// url.PathEscape(node): node is roster-config-controlled, not external
	// input, so this is cheap hardening rather than a real threat model —
	// but an unescaped node name containing '/', '#', '?', or a space
	// would otherwise silently corrupt the request path instead of
	// failing loudly. vmid is already safe (formatted from an int).
	reqURL := fmt.Sprintf("%s/nodes/%s/qemu/%d/config", c.baseURL, url.PathEscape(node), vmid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("set vm %d field %q: build request: %w", vmid, field, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", c.authHeader)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("set vm %d field %q: %w", vmid, field, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("set vm %d field %q: read response: %w", vmid, field, err)
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("set vm %d field %q: pve returned %s: %s", vmid, field, res.Status, strings.TrimSpace(string(body)))
}
