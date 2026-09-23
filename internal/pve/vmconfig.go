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
// own parameter names 1:1). Unconditional: it does not check that the
// config hasn't changed since it was last read. Callers that need that
// guarantee (pveforge-idempotent-mutation-engine's whole reason for
// existing) want SetVMConfigFieldCAS instead; this is a thin wrapper
// around it with an empty expectDigest.
func (c *Client) SetVMConfigField(ctx context.Context, node string, vmid int, field, value string) error {
	return c.SetVMConfigFieldCAS(ctx, node, vmid, field, value, "")
}

// SetVMConfigFieldCAS is SetVMConfigField with an optional
// compare-and-swap guard: when expectDigest is non-empty, it's sent as
// PVE's own "digest" config-write parameter, and PVE itself rejects the
// write (rather than pveforge attempting any client-side detection) if
// the VM's config changed since expectDigest was read (typically via
// GetVM's VirtualMachineConfig.Digest) — Proxmox's own server-side
// optimistic-concurrency primitive, requiring no new pveforge-side lock
// manager for the race it covers. See IsDigestConflictError for
// recognizing that specific rejection.
//
// This is defense-in-depth ALONGSIDE internal/lock's per-object
// serialization, not a replacement for it: digest-CAS only detects a
// race after it happened (the second writer's PUT is rejected) and
// provides no ordering/priority guarantee on its own — it cannot make a
// pending mutation take priority over a pending read the way
// internal/lock does. It matters most for a race internal/lock's file
// lock can't see at all: a different machine, a different roster file
// describing the same real target, or a write from outside pveforge
// entirely (the PVE GUI, another tool).
//
// IMPORTANT ASYMMETRY: this is a REST-API-only mechanism. PVE's
// digest parameter has no equivalent for root-only fields written over
// the standing SSH vector (`qm set` reads/writes the local config file
// directly and has no digest/compare-and-swap flag at all) — for those
// fields (args, confirmed; see sshexec.RootOnlyFields), internal/lock's
// file lock is the ONLY race-prevention mechanism available, with no
// defense-in-depth fallback. RoutedClient.SetVMConfigFieldCAS refuses
// outright for such fields rather than silently proceeding without the
// guarantee the caller asked for — see that method's own doc comment.
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
// PVE's exact error-body shape across versions/endpoints — including for
// a digest mismatch specifically — hasn't been independently verified
// against a live host (same empirical-verification gap flagged for the
// root-only-fields registry and pveum's JSON output in the bootstrap
// task) — passing it through unparsed is the safe default until that's
// confirmed. See IsDigestConflictError's own doc comment for the same
// caveat on recognizing a digest conflict specifically.
func (c *Client) SetVMConfigFieldCAS(ctx context.Context, node string, vmid int, field, value, expectDigest string) error {
	if node == "" {
		return fmt.Errorf("set vm %d field %q: node is required", vmid, field)
	}
	if field == "" {
		return fmt.Errorf("set vm %d config: field name is required", vmid)
	}

	form := url.Values{}
	form.Set(field, value)
	if expectDigest != "" {
		form.Set("digest", expectDigest)
	}
	return c.putVMConfig(ctx, node, vmid, form, fmt.Sprintf("set vm %d field %q", vmid, field))
}

// DeleteVMConfigField is DeleteVMConfigFieldCAS with no digest guard.
func (c *Client) DeleteVMConfigField(ctx context.Context, node string, vmid int, field string) error {
	return c.DeleteVMConfigFieldCAS(ctx, node, vmid, field, "")
}

// DeleteVMConfigFieldCAS removes field from vmid's config entirely, through
// PVE's own `delete` parameter — distinct from SetVMConfigFieldCAS(field, ""),
// which leaves the key present with empty content. The request carries
// `delete=<field>` (and `digest`, under the same compare-and-swap rules as
// SetVMConfigFieldCAS) and never `<field>=`, and goes through the same
// synchronous PUT, so errors surface exactly as a set's do.
//
// NOT verified against a live host, and deliberately not guessed at here:
//   - on a running VM, whether a key that cannot be hot-unplugged is removed
//     at once or recorded as a PENDING delete. GET /config (current=0, the
//     default) returns the pending-applied view, so a pending delete would
//     already read as absent there — consistent with how a pending set
//     already reads as its new value;
//   - what PVE answers for deleting a key that is already absent. Callers
//     (idempotent.VMFieldsEnsure) skip an absent key rather than depend on it;
//   - whether PVE accepts an empty value for fields beyond free-text ones,
//     which is what separates "write empty" from "unset" for a given key.
func (c *Client) DeleteVMConfigFieldCAS(ctx context.Context, node string, vmid int, field, expectDigest string) error {
	if node == "" {
		return fmt.Errorf("delete vm %d field %q: node is required", vmid, field)
	}
	if field == "" {
		return fmt.Errorf("delete vm %d config: field name is required", vmid)
	}

	form := url.Values{}
	form.Set("delete", field)
	if expectDigest != "" {
		form.Set("digest", expectDigest)
	}
	return c.putVMConfig(ctx, node, vmid, form, fmt.Sprintf("delete vm %d field %q", vmid, field))
}

// putVMConfig sends form to vmid's config with the synchronous PUT, and
// prefixes every error with what (e.g. `set vm 100 field "name"`).
func (c *Client) putVMConfig(ctx context.Context, node string, vmid int, form url.Values, what string) error {
	// url.PathEscape(node): node is roster-config-controlled, not external
	// input, so this is cheap hardening rather than a real threat model —
	// but an unescaped node name containing '/', '#', '?', or a space
	// would otherwise silently corrupt the request path instead of
	// failing loudly. vmid is already safe (formatted from an int).
	reqURL := fmt.Sprintf("%s/nodes/%s/qemu/%d/config", c.baseURL, url.PathEscape(node), vmid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%s: build request: %w", what, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", c.authHeader)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("%s: read response: %w", what, err)
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("%s: pve returned %s: %s", what, res.Status, strings.TrimSpace(string(body)))
}

// digestConflictErrorSubstring is the text this project EXPECTS a PVE
// config-digest mismatch to include in its error response body —
// based on documented Proxmox digest-parameter behavior, NOT
// independently verified against a live host in this implementation
// session (same empirical-verification gap flagged throughout this
// project: parseTokenSecret, the root-only-fields registry,
// SetVMConfigFieldCAS's own doc comment above). Confirm the real text
// against a live PVE host before relying on IsDigestConflictError in
// production. Until then, failing to recognize a real conflict just
// means the caller gets a normal terminal error instead of an automatic
// retry — a safe failure mode; this can never cause a false positive
// that retries a write that wasn't actually a conflict, since it only
// ever narrows an already-returned error, never manufactures one.
const digestConflictErrorSubstring = "digest"

// IsDigestConflictError reports whether err's message looks like PVE
// rejected a config write because the supplied digest no longer matches
// the server's current config (SetVMConfigFieldCAS's expectDigest didn't
// match) — a real concurrent-modification conflict, distinct from any
// other write failure. See this function's own const for the
// verification caveat.
func IsDigestConflictError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), digestConflictErrorSubstring)
}
