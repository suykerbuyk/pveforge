package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestOptionsSchema_Success(t *testing.T) {
	const pveSchema = `{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}`
	var gotMethod, gotPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":` + pveSchema + `}`))
	})
	c := testClient(t, srv)

	raw, err := c.OptionsSchema(context.Background(), "/nodes/qa-pve-01/qemu/100/config")
	if err != nil {
		t.Fatalf("OptionsSchema: %v", err)
	}
	if gotMethod != http.MethodOptions {
		t.Errorf("method = %q, want OPTIONS", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("path = %q", gotPath)
	}

	var got, want interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal returned raw: %v", err)
	}
	if err := json.Unmarshal([]byte(pveSchema), &want); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("OptionsSchema returned %s, want the envelope's \"data\" unwrapped to %s", gotJSON, wantJSON)
	}
}

func TestOptionsSchema_RequiresPath(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when path is empty")
	}))

	if _, err := c.OptionsSchema(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty path")
	}
}

func TestOptionsSchema_PropagatesTransportError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := testClient(t, srv)

	if _, err := c.OptionsSchema(context.Background(), "/nodes/qa-pve-01/qemu/100/config"); err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}
