package discover

import "github.com/suykerbuyk/pveforge/internal/pve"

// Compile-time proof that *pve.Client actually satisfies Client — the
// entire design (this package takes the Client interface, never the
// concrete *pve.Client) rests on this holding. If Client's method set
// ever drifts from this interface, this fails to compile. A test-only
// dependency on internal/pve.
var _ Client = (*pve.Client)(nil)
