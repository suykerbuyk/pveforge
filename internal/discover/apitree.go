package discover

import (
	"encoding/json"
	"fmt"
)

// apiTreeNode mirrors one node of PVE's static API-doc schema tree (see
// pve.Client.APIDocTree's own doc comment for how that tree is fetched
// and why it's the live-verified, corrected source for this package's
// layer-1 discovery — replacing the disproved OPTIONS-based design).
//
// Only the fields ParseAPITree actually needs are declared. Leaf is
// decoded but otherwise unused: both leaf (1) and non-leaf (0) nodes can
// carry a non-empty Info object (e.g. "/nodes/{node}/qemu" — a listing
// endpoint — is non-leaf but still describes its own GET), so ParseAPITree
// indexes every node with a Path and a non-empty Info, regardless of
// Leaf.
type apiTreeNode struct {
	Path     string                     `json:"path"`
	Info     map[string]json.RawMessage `json:"info"`
	Children []apiTreeNode              `json:"children,omitempty"`
}

// APITree is PVE's API-doc schema tree, flattened to a literal
// TEMPLATED-path lookup (e.g. "/nodes/{node}/qemu/{vmid}/config" —
// apidoc.js already uses placeholder segment names, never a real object
// id, so no runtime path substitution is ever needed: pveforge's
// noun->path grammar indexes straight into this map with a fixed
// string). Each value is that path's "info" object exactly as PVE
// describes it — keyed by HTTP method (GET/PUT/...), unreshaped.
type APITree map[string]json.RawMessage

// ParseAPITree decodes raw (the JSON array pve.Client.APIDocTree already
// extracted from apidoc.js's surrounding JS) into an APITree indexed by
// every node's own literal Path.
func ParseAPITree(raw json.RawMessage) (APITree, error) {
	var nodes []apiTreeNode
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return nil, fmt.Errorf("parse api tree: %w", err)
	}
	tree := make(APITree)
	if err := flattenAPITree(nodes, tree); err != nil {
		return nil, err
	}
	return tree, nil
}

// flattenAPITree walks nodes depth-first, recording each node with a
// non-empty Path and Info into into, keyed by that literal Path.
// Re-marshals n.Info (already decoded once) back to JSON bytes rather
// than re-slicing the original input, so callers get one canonical
// encoding regardless of where in the tree a path was found — the only
// change from PVE's own byte-for-byte text is JSON object key order
// (Go's encoding/json sorts map keys on marshal), which carries no
// meaning in JSON and only ever affects the small, fixed set of HTTP
// method names (GET/PUT/POST/DELETE) at this level.
//
// Errors loudly on a duplicate Path (two nodes anywhere in the tree
// sharing one literal templated path) rather than letting the second
// visit silently overwrite the first — the same "never mask a surprise
// in this unversioned artifact" stance pve.Client.APIDocTree's own doc
// comment commits to. A real duplicate would mean pveforge's own path-keyed
// lookup is ambiguous for that path; better to fail than to silently
// prefer whichever occurrence the tree walk happened to visit second.
func flattenAPITree(nodes []apiTreeNode, into APITree) error {
	for _, n := range nodes {
		if n.Path != "" && len(n.Info) > 0 {
			raw, err := json.Marshal(n.Info)
			if err != nil {
				return fmt.Errorf("parse api tree: re-marshal info for %q: %w", n.Path, err)
			}
			if existing, ok := into[n.Path]; ok {
				return fmt.Errorf("parse api tree: duplicate path %q: first occurrence has info %s, second has %s", n.Path, existing, raw)
			}
			into[n.Path] = raw
		}
		if len(n.Children) > 0 {
			if err := flattenAPITree(n.Children, into); err != nil {
				return err
			}
		}
	}
	return nil
}

// Lookup returns the per-HTTP-method info object for path (e.g.
// "/nodes/{node}/qemu/{vmid}/config"), unreshaped, exactly as PVE's
// apidoc.js describes it — every HTTP method the path supports at once
// (GET's readable fields, PUT's settable fields, etc.), since PVE splits
// those across different parts of one method's own schema (parameters
// vs. returns) in ways that vary node to node; narrowing to a single
// method here would risk silently hiding the more useful half for a
// given noun (observed live: /storage/{storage}'s GET carries no
// returns.properties at all — the real field list lives under PUT's
// parameters instead).
func (t APITree) Lookup(path string) (json.RawMessage, bool) {
	raw, ok := t[path]
	return raw, ok
}
