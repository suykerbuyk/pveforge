// Package outer is the Go core of the outer test-harness (U-CORE): a
// behaviour-faithful port of the parts of hack/harness/lib.sh that encode
// pveforge logic — the existing-VM guard, the positive-JSON gone-proof
// trio, the created-VM ledger, the VMID bound and the per-verb field
// allow-list. It is a PARALLEL path to lib.sh (which is untouched); the
// `pveforge harness` cobra verbs drive it, and it is unit-testable without
// cobra or a network.
//
// Every state decision here is made on JSON/typed fields, never on PVE's
// error text, exactly as lib.sh does since the destroy-by-error-text
// removal: a pool-only token is answered 403 (never "does not exist") for a
// VMID outside the pool, so "gone" can only ever be proven positively.
package outer

import (
	"context"
	"encoding/json"
	"net/url"
)

// Harness-wide constants, ported verbatim from lib.sh:128-134. Node is NOT
// here: it is the roster target's node (RoutedClient.Node()), the same value
// lib.sh fixes as HARNESS_NODE for its single harness node.
const (
	DefaultPool = "pveforge-harness" // lib.sh:129 HARNESS_POOL
	DefaultTag  = "pveforge-harness" // lib.sh:130 HARNESS_TAG

	minVMID = 690 // lib.sh:133 HARNESS_VMID_RE='^69[0-9]$'
	maxVMID = 699
)

// Config carries the three run-scoped identities the guard and gone-proof
// read against. Node is the client's roster node (== lib.sh HARNESS_NODE).
type Config struct {
	Pool string
	Node string
	Tag  string
}

// Reader is the subset of *pve.RoutedClient the guard, gone-proof and storage
// layer need: the raw REST passthrough. The guard/gone-proof/storage callers
// use it GET-only; RawUPID issues task-returning writes (POST/DELETE) through
// it too, so the method is the contract, not a GET-only restriction.
// *pve.RoutedClient satisfies it structurally, and the package's own tests
// use an in-package fake, so the core never needs pve's network/TLS harness.
type Reader interface {
	RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error)
}

// ValidVMID reports whether vmid is in the harness range 690–699
// (lib.sh:133). Every harness verb enforces this before any call, the way
// _harness_require_declared (lib.sh:237) refuses an out-of-range VMID.
func ValidVMID(vmid int) bool { return vmid >= minVMID && vmid <= maxVMID }
