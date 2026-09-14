package discover

import (
	"context"
	"encoding/json"
	"fmt"
)

// PVEObjectSchema is layer 1's entry point: it fetches PVE's static
// API-doc schema tree from client (pve.Client.APIDocTree /
// pve.RoutedClient's pass-through), parses it (ParseAPITree), and
// returns the schema for one literal templated path within it (e.g.
// "/nodes/{node}/qemu/{vmid}/config") — unreshaped, exactly as PVE's own
// apidoc.js describes it. See this package's own doc comment for why
// layer 1 is a passthrough, not a translation, and pve.Client.APIDocTree's
// doc comment for why the tree is fetched whole rather than per-path
// (PVE's HTTP API has no per-path introspection endpoint at all —
// verified live, 2026-09-14).
//
// Kept as a named function (rather than callers reaching for
// pve.Client.APIDocTree/ParseAPITree directly) so internal/discover — not
// internal/pve — is the one place that represents "how do I describe a
// given noun," matching this package's own layer-2 (NVMeDriveSchema)
// convention.
func PVEObjectSchema(ctx context.Context, client Client, path string) (json.RawMessage, error) {
	raw, err := client.APIDocTree(ctx)
	if err != nil {
		return nil, fmt.Errorf("pve object schema %s: %w", path, err)
	}
	tree, err := ParseAPITree(raw)
	if err != nil {
		return nil, fmt.Errorf("pve object schema %s: %w", path, err)
	}
	info, ok := tree.Lookup(path)
	if !ok {
		return nil, fmt.Errorf("pve object schema %s: no such path in PVE's API-doc tree", path)
	}
	return info, nil
}
