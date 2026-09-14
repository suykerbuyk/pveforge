package discover

import (
	"context"
	"encoding/json"
)

// Client is the subset of *pve.Client this package's layer-1 support
// needs: the raw OPTIONS fetch. Defined here, not as the concrete
// *pve.Client, so this package's own tests use a lightweight in-package
// fake instead of pve's network test harness — *pve.Client satisfies
// this interface structurally (see compat_test.go).
type Client interface {
	// OptionsSchema issues an OPTIONS request against path and returns
	// PVE's own schema response, unwrapped from go-proxmox's envelope but
	// otherwise unreshaped.
	OptionsSchema(ctx context.Context, path string) (json.RawMessage, error)
}
