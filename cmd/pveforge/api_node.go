package main

import "regexp"

// apiPathNodePattern captures the {node} segment of any raw path under
// /nodes/{node}. It is deliberately NOT a row of apiObjectKeyPatterns: that
// table's capture group means "this object's lock ID" (a vmid, a storage
// name, and a node for only 2 of its 5 rows), and changing what a capture
// group means there would silently change lock keys.
var apiPathNodePattern = regexp.MustCompile(`^/nodes/([^/]+)(?:/|$)`)

// apiPathNode returns the node a raw `api` path addresses, if it addresses
// one. That node — never client.Node() — is what an `api` verb passes to
// WaitForTask: a raw path may name a different node than the target's own,
// which PVE proxies transparently (see apiObjectKey's doc comment), and the
// path's node is the independent value that makes WaitForTask's own
// UPID-node check mean something.
//
// The path is matched verbatim, exactly as RawRequest sends it and
// apiObjectKey keys it: no query stripping, no ".." cleaning.
func apiPathNode(rawPath string) (string, bool) {
	m := apiPathNodePattern.FindStringSubmatch(rawPath)
	if m == nil {
		return "", false
	}
	return m[1], true
}
