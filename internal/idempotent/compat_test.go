package idempotent

import "github.com/suykerbuyk/pveforge/internal/pve"

// Compile-time proof that *pve.RoutedClient actually satisfies Client —
// the entire design (Ops take the Client interface, never the concrete
// *pve.RoutedClient) rests on this holding. If RoutedClient's method set
// ever drifts from this interface, this fails to compile. A test-only
// dependency on internal/pve for the interface itself; vmtag.go's own
// production code already imports internal/pve directly for
// pve.IsDigestConflictError, so this file exists only to pin the
// interface-satisfaction claim, not to introduce a new dependency.
var _ Client = (*pve.RoutedClient)(nil)

// Compile-time proof that *pve.RoutedClient also satisfies
// BridgeIsolationClient (bridgeisolation.go) — a larger, separate
// interface from Client above (see bridgeisolation.go's own doc comment
// on why it isn't just Client extended).
var _ BridgeIsolationClient = (*pve.RoutedClient)(nil)

// Compile-time proof that *pve.RoutedClient also satisfies VMCreateClient
// (vmcreate.go) — a third, separate interface from Client and
// BridgeIsolationClient above, for the same "narrow interface per Op"
// reason vmcreate.go's own doc comment gives.
var _ VMCreateClient = (*pve.RoutedClient)(nil)
