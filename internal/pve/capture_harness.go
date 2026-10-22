//go:build harness

// Batch A read-only capture instrument (pveforge-nested-pve-test-harness,
// items 66 and 68). This file is compiled ONLY under the `harness` build tag,
// so it is invisible to `go build ./...` and `make test`; it adds no
// production behaviour and changes no existing signature or call site.
//
// It lives in package pve — and nowhere else — because it must reach three
// unexported pieces no accessor exposes: Client.httpClient and
// Client.authHeader (to issue a GET that records the RAW, pre-unwrap wire
// bytes and the negotiated Response.Proto, which `pveforge api get` discards
// when it unwraps the data envelope and re-encodes), Client.baseURL, and
// Client.pc (to drive the exact production decode path the nil-slice guards
// use, so the null-vs-[] observation is the real one, not a re-implementation).
//
// The runnable entry point is a separate `//go:build harness` package main
// tool (cmd/pveforge-harness-capture) that calls these exported methods: a
// non-test binary, where internal/netguard is never installed, so it can dial
// the nested `pvh` cluster. These methods themselves are transport-agnostic
// and are exercised in-package against an httptest loopback server under the
// netguard trip-wire.

package pve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// ListShape is how a PVE list payload decoded into a Go slice: ShapeNull when
// the slice is nil (PVE sent `{"data":null}`), ShapeEmpty when it is a non-nil
// slice of length 0 (`{"data":[]}`), ShapeItems when it holds entries. Item 66
// asks which of the first two a healthy PVE produces for an empty list — a
// `null` would make the landed nil-slice guards (GetVMs, vms.go:53-54;
// FindByTag's cluster.Resources, findbytag.go:60-62) refuse a healthy cluster.
type ListShape string

const (
	ShapeNull  ListShape = "null"
	ShapeEmpty ListShape = "[]"
	ShapeItems ListShape = "items"
)

// classifyVMList is the null-vs-empty discriminator, the first of this
// instrument's two central invariants. A nil slice is ShapeNull; a non-nil
// slice decides on its length. Kept as one small function so the invariant has
// a single line to mutation-test.
func classifyVMList(vms proxmox.VirtualMachines) ListShape {
	if vms == nil {
		return ShapeNull
	}
	if len(vms) == 0 {
		return ShapeEmpty
	}
	return ShapeItems
}

// ErrNotAtGolden is the item-66 golden-precondition refusal: a nested node is
// carrying a guest, so the cluster is not at its golden point and the
// empty-list shape cannot be read from it. The capture refuses rather than
// recording a vacuous answer or resetting anything itself.
var ErrNotAtGolden = errors.New("cluster not at golden — reset required")

// RawCapture is one raw-HTTP GET recorded before any envelope unwrap: the
// negotiated protocol, the status, the response headers, the verbatim body
// bytes, and their sha256 (over exactly those bytes).
type RawCapture struct {
	Proto  string
	Status string
	Header http.Header
	Body   []byte
	SHA256 string
}

// CaptureRawGET issues one GET against the target's pinned client
// (c.httpClient) and records the wire response before pveforge's own code ever
// unwraps it. It sets the token Authorization header EXACTLY as RawRequest does
// (rawrequest.go:74, the value from client.go:124) — without it PVE answers 401
// and the capture would record an auth error, not the shape under test.
//
// path is appended to the client's own baseURL (e.g. "/nodes/pvh-n1/qemu").
// The body is read in full and hashed; the caller owns deciding what the bytes
// mean.
func (c *Client) CaptureRawGET(ctx context.Context, path string) (*RawCapture, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("capture raw GET %q: %w", path, err)
	}
	req.Header.Set("Authorization", c.authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("capture raw GET %q: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("capture raw GET %q: reading body: %w", path, err)
	}
	sum := sha256.Sum256(body)
	return &RawCapture{
		Proto:  resp.Proto,
		Status: resp.Status,
		Header: resp.Header,
		Body:   body,
		SHA256: hex.EncodeToString(sum[:]),
	}, nil
}

// CaptureVMListShape drives the production decode path — c.pc.Get into
// proxmox.VirtualMachines, the very slice type GetVMs decodes (vms.go:49) — and
// reports whether PVE's list payload came back null, empty, or with items, plus
// the decoded length. It deliberately does NOT call GetVMs, which would reject a
// null payload as ErrUnverifiableRead before the shape could be observed.
func (c *Client) CaptureVMListShape(ctx context.Context, node string) (ListShape, int, error) {
	if node == "" {
		return "", 0, fmt.Errorf("capture vm list shape: node is required")
	}
	var vms proxmox.VirtualMachines
	if err := c.pc.Get(ctx, fmt.Sprintf("/nodes/%s/qemu", url.PathEscape(node)), &vms); err != nil {
		return "", 0, fmt.Errorf("capture vm list shape on %q: %w", node, err)
	}
	return classifyVMList(vms), len(vms), nil
}

// GoldenGateEmpty is the item-66 golden precondition, the instrument's second
// central invariant. It reads every nested node's qemu list and requires each
// to be empty (len 0) before any empty-list shape is recorded from the cluster.
// A node carrying a guest (len > 0) REFUSES with ErrNotAtGolden — it is neither
// a vacuous pass nor a self-reset; re-establishing golden is the operator's or
// A-MUT's job, beforehand. The per-node shapes are returned either way, so the
// caller records whether the empties arrived as `[]` or `null`.
func (c *Client) GoldenGateEmpty(ctx context.Context, nodes []string) (map[string]ListShape, error) {
	if len(nodes) == 0 {
		return map[string]ListShape{}, fmt.Errorf("%w: no nested nodes to check — an empty node set is not a golden cluster", ErrNotAtGolden)
	}
	shapes := make(map[string]ListShape, len(nodes))
	for _, node := range nodes {
		shape, count, err := c.CaptureVMListShape(ctx, node)
		if err != nil {
			return shapes, err
		}
		shapes[node] = shape
		if count > 0 {
			return shapes, fmt.Errorf("%w: node %q carries %d guest(s)", ErrNotAtGolden, node, count)
		}
	}
	return shapes, nil
}
