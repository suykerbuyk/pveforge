package discover

import (
	"context"
	"encoding/json"
)

// Client is the subset of *pve.Client this package's layer-1 support
// needs: fetching PVE's own static API-doc schema tree. Defined here, not
// as the concrete *pve.Client, so this package's own tests use a
// lightweight in-package fake instead of pve's network test harness —
// *pve.Client satisfies this interface structurally (see
// compat_test.go), and so does *pve.RoutedClient (via its own thin
// pass-through), which is what cmd/pveforge's discover commands actually
// hold.
type Client interface {
	// APIDocTree fetches and returns PVE's own static API-doc schema
	// tree, unwrapped from any transport envelope but otherwise
	// unreshaped — see pve.Client.APIDocTree's own doc comment for the
	// live-verified mechanism (2026-09-14) this replaced the disproved
	// OPTIONS-based design with.
	APIDocTree(ctx context.Context) (json.RawMessage, error)
}
