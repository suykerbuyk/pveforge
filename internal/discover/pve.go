package discover

import (
	"context"
	"encoding/json"
	"fmt"
)

// PVEObjectSchema is layer 1's entry point: it fetches path's schema from
// client and returns it exactly as PVE returned it (already unwrapped
// from go-proxmox's envelope by Client.OptionsSchema itself) — no
// reshaping into Schema or any other dialect. See this package's own doc
// comment for why layer 1 is a passthrough, not a translation.
//
// Kept as a named function (rather than callers reaching for
// pve.Client.OptionsSchema directly) so internal/discover — not
// internal/pve — is the one place that represents "how do I describe a
// given noun," even though today that's a thin pass-through; a future
// caller (the planned discover CLI) depends on this package's surface,
// not pve's.
func PVEObjectSchema(ctx context.Context, client Client, path string) (json.RawMessage, error) {
	raw, err := client.OptionsSchema(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("pve object schema %s: %w", path, err)
	}
	return raw, nil
}
