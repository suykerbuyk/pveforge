package discover

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// fakeAPIDocTree builds a minimal but realistically-shaped apidoc.js
// JSON array (already extracted — no surrounding JS wrapper, since that
// extraction step is pve.Client.APIDocTree's job, not this package's)
// with a single path node.
func fakeAPIDocTree(path, infoJSON string) json.RawMessage {
	return json.RawMessage(`[{"path":"` + path + `","leaf":1,"info":` + infoJSON + `}]`)
}

func TestPVEObjectSchema_PassesThroughVerbatim(t *testing.T) {
	const path = "/nodes/qa-pve-01/qemu/100/config"
	const info = `{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}`
	client := &fakeClient{result: fakeAPIDocTree(path, info)}

	got, err := PVEObjectSchema(context.Background(), client, path)
	if err != nil {
		t.Fatalf("PVEObjectSchema: %v", err)
	}

	var got2, want interface{}
	if err := json.Unmarshal(got, &got2); err != nil {
		t.Fatalf("unmarshal returned raw: %v", err)
	}
	if err := json.Unmarshal([]byte(info), &want); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	gotJSON, _ := json.Marshal(got2)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("PVEObjectSchema reshaped the response: got %s, want %s (verbatim)", gotJSON, wantJSON)
	}
	if client.calls != 1 {
		t.Errorf("expected exactly one APIDocTree call, got %d", client.calls)
	}
}

func TestPVEObjectSchema_PropagatesClientError(t *testing.T) {
	client := &fakeClient{err: errors.New("network down")}

	if _, err := PVEObjectSchema(context.Background(), client, "/nodes/qa-pve-01/qemu/100/config"); err == nil {
		t.Fatal("expected an error when the client fails")
	}
}

func TestPVEObjectSchema_PropagatesParseError(t *testing.T) {
	client := &fakeClient{result: json.RawMessage(`not json`)}

	if _, err := PVEObjectSchema(context.Background(), client, "/nodes/qa-pve-01/qemu/100/config"); err == nil {
		t.Fatal("expected an error when the tree fails to parse")
	}
}

func TestPVEObjectSchema_UnknownPath(t *testing.T) {
	client := &fakeClient{result: fakeAPIDocTree("/some/other/path", `{"GET":{}}`)}

	_, err := PVEObjectSchema(context.Background(), client, "/nodes/qa-pve-01/qemu/100/config")
	if err == nil {
		t.Fatal("expected an error for a path absent from the tree")
	}
}
