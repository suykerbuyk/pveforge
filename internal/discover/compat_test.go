package discover

import "github.com/suykerbuyk/pveforge/internal/pve"

// Compile-time proof that *pve.Client actually satisfies Client — the
// entire design (this package takes the Client interface, never the
// concrete *pve.Client) rests on this holding. If Client's method set
// ever drifts from this interface, this fails to compile. A test-only
// dependency on internal/pve.
var _ Client = (*pve.Client)(nil)

// Compile-time proof that *pve.RoutedClient also satisfies Client —
// that's the concrete type cmd/pveforge's discover commands actually
// hold (via resolveRoutedClient), not *pve.Client directly, so this
// package's own claim (see client.go's doc comment) that RoutedClient
// satisfies Client structurally needs its own assertion, same pattern as
// internal/device's compat_test.go.
var _ Client = (*pve.RoutedClient)(nil)
