package discover

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseAPITree_FlattensNestedChildren(t *testing.T) {
	const raw = `[
		{"path":"/nodes","leaf":0,"info":{"GET":{"description":"index"}},"children":[
			{"path":"/nodes/{node}","leaf":0,"info":{"GET":{"description":"node index"}},"children":[
				{"path":"/nodes/{node}/status","leaf":1,"info":{"GET":{"description":"node status"},"POST":{"description":"reboot"}}},
				{"path":"/nodes/{node}/qemu","leaf":0,"info":{"GET":{"description":"list vms"}},"children":[
					{"path":"/nodes/{node}/qemu/{vmid}/config","leaf":1,"info":{"GET":{"description":"vm config"}}}
				]}
			]}
		]}
	]`

	tree, err := ParseAPITree(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseAPITree: %v", err)
	}

	for _, path := range []string{
		"/nodes",
		"/nodes/{node}",
		"/nodes/{node}/status",
		"/nodes/{node}/qemu",
		"/nodes/{node}/qemu/{vmid}/config",
	} {
		if _, ok := tree.Lookup(path); !ok {
			t.Errorf("expected path %q to be present in the flattened tree", path)
		}
	}

	if _, ok := tree.Lookup("/nodes/{node}/does-not-exist"); ok {
		t.Error("expected an absent path to not be found")
	}
}

// TestParseAPITree_IndexesNonLeafNodesWithInfo proves a non-leaf node
// (one with children) is still indexed when it carries its own non-empty
// Info — e.g. "/nodes/{node}/qemu" is a listing endpoint (has children:
// /{vmid}/...) but its own GET describes the list call itself.
func TestParseAPITree_IndexesNonLeafNodesWithInfo(t *testing.T) {
	const raw = `[{"path":"/nodes/{node}/qemu","leaf":0,"info":{"GET":{"description":"list vms"}},"children":[
		{"path":"/nodes/{node}/qemu/{vmid}/config","leaf":1,"info":{"GET":{}}}
	]}]`

	tree, err := ParseAPITree(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseAPITree: %v", err)
	}
	info, ok := tree.Lookup("/nodes/{node}/qemu")
	if !ok {
		t.Fatal("expected the non-leaf listing node to be indexed")
	}
	if !strings.Contains(string(info), "list vms") {
		t.Errorf("expected the non-leaf node's own info, got %s", info)
	}
}

// TestParseAPITree_SkipsNodesWithEmptyInfo proves a node with an empty
// (or absent) Info object doesn't produce a spurious lookup entry — only
// paths PVE actually describes something for should be findable.
func TestParseAPITree_SkipsNodesWithEmptyInfo(t *testing.T) {
	const raw = `[{"path":"/nodes/{node}/qemu","leaf":0,"info":{},"children":[
		{"path":"/nodes/{node}/qemu/{vmid}/config","leaf":1,"info":{"GET":{}}}
	]}]`

	tree, err := ParseAPITree(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseAPITree: %v", err)
	}
	if _, ok := tree.Lookup("/nodes/{node}/qemu"); ok {
		t.Error("expected the empty-info node to not be indexed")
	}
	if _, ok := tree.Lookup("/nodes/{node}/qemu/{vmid}/config"); !ok {
		t.Error("expected the child with real info to still be indexed")
	}
}

func TestParseAPITree_PreservesAllHTTPMethods(t *testing.T) {
	const raw = `[{"path":"/storage/{storage}","leaf":1,"info":{
		"GET":{"description":"read"},
		"PUT":{"description":"update","parameters":{"properties":{"content":{"type":"string"}}}},
		"DELETE":{"description":"remove"}
	}}]`

	tree, err := ParseAPITree(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("ParseAPITree: %v", err)
	}
	info, ok := tree.Lookup("/storage/{storage}")
	if !ok {
		t.Fatal("expected /storage/{storage} to be present")
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(info, &decoded); err != nil {
		t.Fatalf("unmarshal info: %v", err)
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		if _, ok := decoded[method]; !ok {
			t.Errorf("expected method %q to survive flattening", method)
		}
	}
}

// TestParseAPITree_DuplicatePathErrors proves two nodes anywhere in the
// tree sharing one literal templated path (with differing info) errors
// loudly instead of letting the second occurrence silently overwrite the
// first.
func TestParseAPITree_DuplicatePathErrors(t *testing.T) {
	const raw = `[
		{"path":"/nodes","leaf":0,"info":{"GET":{"description":"top-level index"}},"children":[
			{"path":"/nodes/{node}/qemu/{vmid}/config","leaf":1,"info":{"GET":{"description":"first occurrence"}}}
		]},
		{"path":"/other","leaf":0,"info":{"GET":{"description":"unrelated"}},"children":[
			{"path":"/nodes/{node}/qemu/{vmid}/config","leaf":1,"info":{"GET":{"description":"second, conflicting occurrence"}}}
		]}
	]`

	_, err := ParseAPITree(json.RawMessage(raw))
	if err == nil {
		t.Fatal("expected an error for a duplicate path with differing info")
	}
	if !strings.Contains(err.Error(), "duplicate path") {
		t.Errorf("expected the error to say \"duplicate path\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "/nodes/{node}/qemu/{vmid}/config") {
		t.Errorf("expected the error to name the offending path, got: %v", err)
	}
}

func TestParseAPITree_MalformedJSON(t *testing.T) {
	if _, err := ParseAPITree(json.RawMessage(`not json`)); err == nil {
		t.Fatal("expected an error for malformed input")
	}
}

func TestParseAPITree_EmptyArray(t *testing.T) {
	tree, err := ParseAPITree(json.RawMessage(`[]`))
	if err != nil {
		t.Fatalf("ParseAPITree: %v", err)
	}
	if len(tree) != 0 {
		t.Errorf("expected an empty tree, got %d entries", len(tree))
	}
}
