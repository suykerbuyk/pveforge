//go:build harness

// U-CWCV cross-node API-proxy proof (pveforge-nested-pve-test-harness, the §2
// MERGE GATE). This instrument is the authored-but-not-yet-run leg: it is
// compiled only under `-tags harness` and is driven by the Chair against a live
// nested cluster, NOT by `make check`. It proves the ONE fact the fake servers
// cannot (an httptest server answers any /nodes/* path from one process, so it
// passes whether or not real PVE proxies): that a single host-bound *Client's
// GET /nodes/{nodeB}/qemu/{vmid}/config, issued to node A's API, is answered
// with node B's OWN config — not node A's view, and not a proxied wrong node —
// asserted by a MARKER that exists only on B. This proof passed GREEN on the
// nested `pvh` harness 2026-10-30, which is what let the cluster-wide
// shared-storage free (cmd/pveforge/storage.go free-orphans) be enabled; this
// leg stays as the re-runnable evidence.
package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CrossNodeProxyCapture is the result of reading node B's config through node
// A's API.
//
//   - MarkerField is the config field the harness set to a B-UNIQUE value (e.g.
//     a disk slot "scsi0" whose volid names B's VM, or "description"); WantMarker
//     is that value.
//   - GotValue is the field's actual decoded value in the config node A returned.
//   - BoundHostOK is whether this *Client's own base URL host equals the
//     caller-asserted bound host (node A's API endpoint).
//   - Proven is true ONLY when the client was bound to the asserted host AND the
//     named field decoded to exactly WantMarker — i.e. the proxy served B's own
//     config. A substring-anywhere match is deliberately NOT used.
type CrossNodeProxyCapture struct {
	BoundHost   string
	TargetNode  string
	VMID        int
	MarkerField string
	WantMarker  string
	GotValue    string
	BoundHostOK bool
	Proven      bool
}

// CaptureCrossNodeProxy reads /nodes/{targetNode}/qemu/{vmid}/config through
// this client and proves it is node B's OWN config by decoding the config and
// checking that markerField's VALUE equals wantMarker exactly (not a
// substring-anywhere of the raw body, which a volid on the wrong node could
// satisfy). It also asserts this client is actually bound to boundHost (node
// A's API endpoint), since the whole proof is "A's API served B's config": a
// client accidentally pointed straight at B would prove nothing.
//
// Driver contract (the Chair MUST honor it): boundHost is node A's real API host
// (host or host:port, as the roster target's Host); markerField is a config key
// the driver set to a value UNIQUE to the VM on targetNode (B); wantMarker is
// that value. An empty boundHost, targetNode, markerField or wantMarker, or a
// non-positive vmid, is refused.
//
// Outcomes: a transport/HTTP error (non-2xx via rawrequest.go:87-89) is returned
// as an error; a 200 with no digest, or an undecodable body, is ErrUnverifiableRead
// (never a silent "no marker"); a digest-bearing 200 whose markerField value does
// not equal wantMarker, or a bound-host mismatch, is a FAILED proof (Proven
// false, nil error) — meaning the §2 fallback (one host-bound *Client per node
// host) is required before the shared free is enabled.
func (c *Client) CaptureCrossNodeProxy(ctx context.Context, boundHost, targetNode string, vmid int, markerField, wantMarker string) (*CrossNodeProxyCapture, error) {
	if boundHost == "" || targetNode == "" || vmid < 1 || markerField == "" || wantMarker == "" {
		return nil, fmt.Errorf("cross-node proxy proof: boundHost, targetNode, a positive vmid, markerField and wantMarker are all required")
	}

	// Assert this client is bound to node A's API, not pointed straight at B.
	u, perr := url.Parse(c.baseURL)
	if perr != nil {
		return nil, fmt.Errorf("cross-node proxy proof: parse client base URL: %w", perr)
	}
	boundHostOK := u.Host == boundHost || u.Hostname() == boundHost

	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(targetNode), vmid)
	raw, err := c.RawRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("cross-node proxy proof: read %s via %q: %w", path, boundHost, err)
	}

	var cfg map[string]json.RawMessage
	if jerr := json.Unmarshal(raw, &cfg); jerr != nil {
		return nil, fmt.Errorf("cross-node proxy proof: %w: config for vmid %d via %q did not decode: %v", ErrUnverifiableRead, vmid, boundHost, jerr)
	}
	// A real config always carries a digest; a {"data":null}/{} answer is an
	// unverifiable read, never a silently-empty "no marker".
	if _, ok := cfg["digest"]; !ok {
		return nil, fmt.Errorf("cross-node proxy proof: %w: config for vmid %d via %q carries no digest", ErrUnverifiableRead, vmid, boundHost)
	}

	// Decode ONLY the named field and compare its VALUE exactly.
	var gotValue string
	if rawVal, present := cfg[markerField]; present {
		_ = json.Unmarshal(rawVal, &gotValue) // non-string leaves gotValue ""
	}

	return &CrossNodeProxyCapture{
		BoundHost:   boundHost,
		TargetNode:  targetNode,
		VMID:        vmid,
		MarkerField: markerField,
		WantMarker:  wantMarker,
		GotValue:    gotValue,
		BoundHostOK: boundHostOK,
		Proven:      boundHostOK && gotValue == wantMarker,
	}, nil
}
