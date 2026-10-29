package pve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ParseClusterStatusQuorate decodes `pvesh get /cluster/status --output-format
// json` strictly and reports whether this node's pmxcfs view is trustworthy
// enough to even CONSIDER a destructive orphan free.
//
// quorate is corosync's MAJORITY bit ONLY. PVE sets it once the node holds
// corosync quorum, which happens BEFORE pmxcfs's config database (dcdb)
// finishes syncing, and /cluster/status carries no "config index is fresh"
// field. So a node can read quorate=true while its get_vmlist is still stale
// (it just regained quorum, or a sibling's write has not yet replicated).
// quorate is therefore NECESSARY, NOT SUFFICIENT for a destructive free: it
// closes the no-quorum stale-read, never the post-quorate replication window,
// which no API read closes. Every caller of the free (VolumeFreeOrphans and
// its CLI) carries that residual as a documented precondition + warning.
//
// Shape — a bare JSON array (as pvesh --output-format json prints; NOT a
// {"data":…} REST envelope):
//   - exactly one entry with type=="cluster": quorate = (its "quorate" == 1)
//   - NO cluster entry but AT LEAST ONE type=="node" entry: a STANDALONE
//     (non-clustered) node, whose single pmxcfs is locally authoritative with no
//     replication lag -> quorate=true.
//
// Fail-closed as ErrUnverifiableRead on anything a healthy PVE never prints: a
// non-array / null / {"data":…} envelope, trailing data, a null entry, MORE
// than one cluster entry, a cluster entry whose "quorate" flag is absent or not
// a 0/1 integer, OR an array with neither a cluster nor a node entry (a bare []
// or a truncated/garbage body that still exited 0 — a healthy /cluster/status
// always carries at least the local node). The per-entry strictness mirrors
// internal/harness' decodeQuorate; unlike the harness it does NOT refuse a
// missing cluster entry when a node entry proves the node stands alone.
//
// NOT LIVE-VERIFIED: that a CONFIGURED cluster ALWAYS emits the type:"cluster"
// entry (reporting quorate=0 on loss), so a quorum loss can never present as a
// MISSING cluster entry — the one shape that would fall through to the
// standalone quorate=true path and fail OPEN. Confirm on the nested harness,
// same honesty posture as nodeqemu.go's /etc/pve/local note.
func ParseClusterStatusQuorate(b []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var entries []map[string]json.RawMessage
	if err := dec.Decode(&entries); err != nil {
		return false, fmt.Errorf("cluster status: %w: %v", ErrUnverifiableRead, err)
	}
	if entries == nil {
		return false, fmt.Errorf("cluster status: %w: the list is null", ErrUnverifiableRead)
	}
	if _, err := dec.Token(); err != io.EOF {
		return false, fmt.Errorf("cluster status: %w: trailing data after the list", ErrUnverifiableRead)
	}
	clusters := 0
	nodes := 0
	quorate := false
	for i, e := range entries {
		if e == nil {
			return false, fmt.Errorf("cluster status: %w: entry %d is null", ErrUnverifiableRead, i)
		}
		var typ string
		if json.Unmarshal(e["type"], &typ) != nil {
			continue
		}
		if typ == "node" {
			nodes++
			continue
		}
		if typ != "cluster" {
			continue
		}
		clusters++
		q, ok := quorateFlag(e["quorate"])
		if !ok {
			return false, fmt.Errorf("cluster status: %w: the cluster entry's quorate flag is absent or not a 0/1 integer", ErrUnverifiableRead)
		}
		quorate = q
	}
	if clusters > 1 {
		return false, fmt.Errorf("cluster status: %w: %d cluster entries, want at most 1", ErrUnverifiableRead, clusters)
	}
	if clusters == 0 {
		// A STANDALONE node emits no cluster entry but ALWAYS at least one
		// type:"node" entry (itself). Requiring that node entry closes the
		// fail-OPEN a bare [] (a truncated/garbage body that still exited 0)
		// would otherwise cause: no cluster AND no node is not a healthy
		// /cluster/status, so refuse rather than authorize the free.
		if nodes == 0 {
			return false, fmt.Errorf("cluster status: %w: no cluster entry and no node entry — not a healthy /cluster/status reply", ErrUnverifiableRead)
		}
		return true, nil
	}
	return quorate, nil
}

// quorateFlag decodes a strict 0/1 integer quorate flag. Absent, non-numeric,
// fractional, or outside {0,1} -> not ok (the caller refuses). Mirrors
// internal/harness decodeQuorate's int decode.
func quorateFlag(raw json.RawMessage) (value bool, ok bool) {
	if len(raw) == 0 {
		return false, false
	}
	var q int
	if json.Unmarshal(raw, &q) != nil {
		return false, false
	}
	switch q {
	case 0:
		return false, true
	case 1:
		return true, true
	default:
		return false, false
	}
}
