package main

import (
	"regexp"
	"strconv"

	"github.com/suykerbuyk/pveforge/internal/lock"
)

// apiObjectKeyPattern is one entry in apiObjectKeyPatterns: a path shape
// this project already models as a lockable object, and how to pull that
// object's lock.ObjectKey.ID out of a matching path.
type apiObjectKeyPattern struct {
	kind string
	re   *regexp.Regexp
}

// apiObjectKeyPatterns is `pveforge-raw-api-escape-hatch`'s own recorded
// key-derivation table (vault task pveforge-raw-api-escape-hatch,
// "Locking design", 2026-09-14) — reusing the EXACT Kind/ID vocabulary
// cmd/pveforge/{vm,node,storage,network}.go's own lock.ObjectKey{...}
// calls already use for the same real object (verified against those
// files directly, not invented independently): a key that doesn't match
// wouldn't actually serialize against them, which would make locking here
// pure theater. Every pattern is fully anchored (^...$ or a `(?:/.*)?$`
// trailing-wildcard, never an open prefix), so none can accidentally
// shadow another — matching order does not affect correctness, only
// which table entry the DevX-facing error names first if a path somehow
// matched more than one (it can't, by construction).
//
// vm/storage/network patterns ignore trailing path segments (a write to
// e.g. /nodes/{node}/qemu/{vmid}/snapshot still mutates THAT VM for
// locking purposes); the node pattern does not — it's exactly
// "/nodes/{node}" or "/nodes/{node}/status", matching the table's own
// documented shape, not a general prefix.
//
// The network pattern captures {node}, not {iface}, and matches BOTH the
// bare collection path (/nodes/{node}/network — the path
// NetworkBridgeEnsure's own commit/PUT and whole-node-revert/DELETE calls
// use, with no trailing iface segment at all) and the per-interface path
// (/nodes/{node}/network/{iface}, plus anything nested further under it,
// same trailing-segment convention as vm/storage above) — one table entry
// covers both shapes, since capturing {node} makes the trailing
// "/{iface}" segment irrelevant to the lock key either way. This mirrors
// internal/idempotent/networkbridge.go's own NetworkLockKey: PVE's staged
// network config (/nodes/{node}/network[...]) is a single shared,
// node-wide staging area, not per-interface, so two concurrent mutations
// against different interfaces on the SAME node must still serialize
// against each other — keying by {iface} instead of {node} would let them
// race. This is a reviewed, load-bearing decision — do not key this
// pattern by {iface}.
var apiObjectKeyPatterns = []apiObjectKeyPattern{
	{kind: "vm", re: regexp.MustCompile(`^/nodes/[^/]+/qemu/(\d+)(?:/.*)?$`)},
	{kind: "storage", re: regexp.MustCompile(`^/nodes/[^/]+/storage/([^/]+)(?:/.*)?$`)},
	{kind: "storage", re: regexp.MustCompile(`^/storage/([^/]+)(?:/.*)?$`)},
	{kind: "network", re: regexp.MustCompile(`^/nodes/([^/]+)/network(?:/[^/]+)?(?:/.*)?$`)},
	{kind: "node", re: regexp.MustCompile(`^/nodes/([^/]+)(?:/status)?$`)},
}

// apiObjectKey derives the lock.ObjectKey a raw path names, if any — see
// apiObjectKeyPatterns' own doc comment for the table and its provenance.
//
// For the "node" pattern specifically, id is the path's own literal
// {node} segment, NOT the routed client's configured node (client.Node())
// — confirmed while implementing, not just assumed (the vault design left
// this as an open item): lock.ObjectKey carries no node field at all
// (only TargetID+Kind+ID — see internal/lock/lock.go), so the path's own
// segment is what correctly distinguishes "this target's view of node X"
// from "this target's view of its own node" whenever a raw path addresses
// a DIFFERENT node than the target's own — which PVE allows and proxies
// transparently (every node's pveproxy can reach every other node via
// "proxyto":"node", confirmed live during pveforge-discover-cli's own
// investigation of /nodes/{node}/qemu/{vmid}/config's schema). Using
// client.Node() instead would wrongly conflate locks for two DIFFERENT
// real node objects whenever they differ — over-serializing unrelated
// work against each other, which is a correctness regression, not a
// safety improvement. A raw escape hatch trusts its caller on path
// correctness (same posture as not validating the {node} segment against
// the target's own routing at all): a genuinely cross-node path is the
// caller's problem, exactly as it already is for every other aspect of
// this command (a bad vmid, a bad storage name, ...).
//
// For the "vm" pattern specifically, the captured digit string is
// round-tripped through strconv.Atoi/strconv.Itoa before becoming the
// key's ID — the exact normalization cmd/pveforge/vm.go's own `get`/`set`
// commands already apply to their own vmid argument
// (`strconv.Atoi(args[1])` ... `strconv.Itoa(vmid)`). Without this, a
// leading-zero path segment (e.g. ".../qemu/0100/config") would capture
// the raw string "0100" while `vm get <target> 0100` locks "100" — two
// DIFFERENT lock.ObjectKeys for the SAME real VM, silently defeating the
// cross-command interop this whole command exists to guarantee
// (confirmed bug, adversarial review, 2026-09-14). The `\d+` capture
// group makes a non-numeric Atoi failure unreachable in practice, but an
// absurdly long digit string could still overflow int; treated as no
// match (falls through to the next pattern, ultimately "no known
// object") rather than either panicking or silently keying on an
// unnormalized string — apiObjectKey's existing (ObjectKey, bool)
// signature has no room for a distinct error case, and "no match" is
// already this function's documented safe default for anything it can't
// confidently resolve.
func apiObjectKey(targetID, path string) (lock.ObjectKey, bool) {
	for _, p := range apiObjectKeyPatterns {
		m := p.re.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		id := m[1]
		if p.kind == "vm" {
			n, err := strconv.Atoi(id)
			if err != nil {
				continue
			}
			id = strconv.Itoa(n)
		}
		return lock.ObjectKey{TargetID: targetID, Kind: p.kind, ID: id}, true
	}
	return lock.ObjectKey{}, false
}
