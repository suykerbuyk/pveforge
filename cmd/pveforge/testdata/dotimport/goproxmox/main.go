// Command dotimport-goproxmox dot-imports "github.com/suykerbuyk/go-proxmox", one of the four import paths the
// transport boundary guard resolves its targets through, and then references
// a guarded symbol with NO qualifier at all.
//
// A dot-import is the third evasion, and the cheapest: aliasing changes the
// local name, dot-importing REMOVES it, so an ImportPath-qualified target has
// nothing left to match on. sourceguard.NonTestReferences refuses such an
// import LOUDLY rather than silently returning no hits, and this directory is
// how ../../../transportboundary_test.go proves that refusal reaches THIS
// unit's own target list rather than only the one path sourceguard's own
// fixture covers.
//
// One directory per path, deliberately: the walker fails on the FIRST file
// that dot-imports a guarded path, so four probes in one directory would
// leave three of them never exercised.
//
// Never built by ./... — it lives under testdata.
package main

import . "github.com/suykerbuyk/go-proxmox"

// NewClient is proxmox.NewClient with the qualifier stripped off.
var _ = NewClient

func main() {}
