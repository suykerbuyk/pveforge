package device

import "github.com/suykerbuyk/pveforge/internal/pve"

// Compile-time proof that *pve.RoutedClient actually satisfies Client —
// the entire design (resolvers take the Client interface, never the
// concrete *pve.RoutedClient) rests on this holding. If RoutedClient's
// method set ever drifts from this interface, this fails to compile. A
// test-only dependency on internal/pve (not a production one) — device.go
// itself never imports pve.
var _ Client = (*pve.RoutedClient)(nil)
