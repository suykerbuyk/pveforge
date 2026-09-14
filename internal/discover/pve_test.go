package discover

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestPVEObjectSchema_PassesThroughVerbatim(t *testing.T) {
	const raw = `{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}`
	client := &fakeClient{result: json.RawMessage(raw)}

	got, err := PVEObjectSchema(context.Background(), client, "/nodes/qa-pve-01/qemu/100/config")
	if err != nil {
		t.Fatalf("PVEObjectSchema: %v", err)
	}
	if string(got) != raw {
		t.Errorf("PVEObjectSchema reshaped the response: got %s, want %s (verbatim)", got, raw)
	}
	if client.calls != 1 || client.lastPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("expected exactly one OptionsSchema call with the given path, got %d calls, last path %q", client.calls, client.lastPath)
	}
}

func TestPVEObjectSchema_PropagatesClientError(t *testing.T) {
	client := &fakeClient{err: errors.New("network down")}

	if _, err := PVEObjectSchema(context.Background(), client, "/nodes/qa-pve-01/qemu/100/config"); err == nil {
		t.Fatal("expected an error when the client fails")
	}
}
