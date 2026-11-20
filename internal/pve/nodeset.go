package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// NodeSet is the cluster's member list as the gone-proof's cross-node scan
// needs it: EVERY configured member, offline ones included, and a statement of
// whether that list can be trusted. The zero value is NOT complete.
//
// There is deliberately no `error` return from ClusterNodes (the in-flight
// determination's idiom): a caller must branch on Complete, and an incomplete
// set carries no names to scan.
type NodeSet struct {
	// Complete is true only when BOTH reads succeeded and the authoritative
	// list is non-empty and names the roster node.
	Complete bool
	// Names is the member set, sorted and de-duplicated, ALWAYS including the
	// roster node. Empty unless Complete.
	Names []string
	// Read and Detail say which read failed and why, when not Complete.
	Read   string
	Detail string
	// Privilege is the missing privilege, set only when the authoritative read
	// answered 403.
	Privilege string
}

const clusterConfigNodesPath = "/cluster/config/nodes"

// ClusterNodes reads the member list for the gone-proof's retry scan.
//
// AUTHORITY: GET /cluster/config/nodes ("Corosync node list", pve-cluster
// API2/ClusterConfig.pm). It reads corosync.conf and returns every CONFIGURED
// member without consulting liveness, so an offline member is listed; it needs
// Sys.Audit on `/`, and a token without it gets 403 — a refusal, never a
// shorter list. GET /nodes (user => all; pve-manager Nodes.pm index) is
// UNIONED in: it also lists every member, but falls back to a one-node list
// when pmxcfs's cluster info is empty, so it is never trusted on its own.
//
// FAIL CLOSED on membership (Chair ruling U5-D2). An EMPTY authoritative list,
// or one that does not name the roster node, is "membership unknown" and the
// set is not Complete. There is NO standalone inference: an empty corosync list
// is what a genuine standalone host answers AND what a masked pmxcfs failure
// can answer (ipcc_get_config reads "no file" for ENOENT, and the errno of a
// failed IPC connect was not established), and the two member reads are
// separate API requests from the nextid read, each refreshing the cluster
// state anew. The price is accepted residual R-STANDALONE: on a non-clustered
// host a retry whose VM is already absent refuses.
func (c *Client) ClusterNodes(ctx context.Context, roster string) NodeSet {
	if roster == "" {
		return NodeSet{Read: "roster node", Detail: "the roster node name is empty"}
	}
	raw, err := c.RawRequest(ctx, http.MethodGet, clusterConfigNodesPath, nil)
	if err != nil {
		ns := NodeSet{Read: "GET " + clusterConfigNodesPath, Detail: oneLine(err.Error())}
		if code, ok := HTTPStatus(err); ok && code == http.StatusForbidden {
			// From the status code only: never echo PVE's body, and a 401 (a bad
			// token) is not a missing privilege.
			ns.Privilege = "Sys.Audit on /"
			ns.Detail = "PVE answered 403: " + ns.Privilege + " is required to read the cluster member list"
		}
		return ns
	}
	authority, why := decodeCorosyncNodes(raw)
	if why != "" {
		return NodeSet{Read: "GET " + clusterConfigNodesPath, Detail: why}
	}
	if len(authority) == 0 {
		return NodeSet{Read: "GET " + clusterConfigNodesPath, Detail: "membership unknown: the corosync node list is empty (a standalone host and a failed cluster-filesystem read answer the same, so no standalone is inferred)"}
	}
	found := false
	for _, n := range authority {
		if n == roster {
			found = true
		}
	}
	if !found {
		return NodeSet{Read: "GET " + clusterConfigNodesPath, Detail: fmt.Sprintf("membership unknown: the corosync node list does not name the roster node %q", roster)}
	}

	listed, err := c.ListNodes(ctx)
	if err != nil {
		return NodeSet{Read: "GET /nodes", Detail: oneLine(err.Error())}
	}
	// An entry with no node name is membership-UNKNOWN, the same class as an
	// undecodable authority entry — never dropped: a member this read could not
	// even name is a member whose task view was never read.
	for _, n := range listed {
		if n == "" {
			return NodeSet{Read: "GET /nodes", Detail: "GET /nodes returned an entry with no node name"}
		}
	}
	seen := map[string]bool{roster: true}
	names := []string{roster}
	for _, n := range append(append([]string(nil), authority...), listed...) {
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}
	sort.Strings(names)
	return NodeSet{Complete: true, Names: names}
}

// decodeCorosyncNodes strictly decodes /cluster/config/nodes: one JSON array,
// no null, no trailing data, every entry an object with a non-empty string
// `node`. why is non-empty on any deviation.
func decodeCorosyncNodes(raw json.RawMessage) (names []string, why string) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var entries []map[string]json.RawMessage
	if err := dec.Decode(&entries); err != nil {
		return nil, "the member list has an unexpected shape: " + oneLine(err.Error())
	}
	if entries == nil {
		return nil, "the member list is null"
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "the member list has trailing data"
	}
	for i, e := range entries {
		if e == nil {
			return nil, fmt.Sprintf("member list entry %d is null", i)
		}
		var n string
		if json.Unmarshal(e["node"], &n) != nil || n == "" {
			return nil, fmt.Sprintf("member list entry %d has no string node name", i)
		}
		names = append(names, n)
	}
	return names, ""
}
