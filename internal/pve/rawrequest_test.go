package pve

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRawRequest_GetSendsParamsAsQueryString(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"uptime":123}}`))
	})
	c := testClient(t, srv)

	raw, err := c.RawRequest(context.Background(), http.MethodGet, "/nodes/qa-pve-01/status", url.Values{"type": {"qemu"}})
	if err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/status" {
		t.Errorf("path = %q", gotPath)
	}
	if gotQuery != "type=qemu" {
		t.Errorf("query = %q, want type=qemu", gotQuery)
	}
	if string(raw) != `{"uptime":123}` {
		t.Errorf("raw = %s, want the unwrapped data object", raw)
	}
}

func TestRawRequest_DeleteSendsParamsAsQueryString(t *testing.T) {
	var gotMethod, gotQuery string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if _, err := c.RawRequest(context.Background(), http.MethodDelete, "/nodes/qa-pve-01/qemu/100/snapshot/foo", url.Values{"force": {"1"}}); err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotQuery != "force=1" {
		t.Errorf("query = %q, want force=1", gotQuery)
	}
}

func TestRawRequest_PostSendsParamsAsFormBody(t *testing.T) {
	var gotMethod, gotContentType string
	var gotForm url.Values
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:12345::task::"}`))
	})
	c := testClient(t, srv)

	raw, err := c.RawRequest(context.Background(), http.MethodPost, "/nodes/qa-pve-01/qemu/100/snapshot", url.Values{"snapname": {"before-upgrade"}})
	if err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if gotForm.Get("snapname") != "before-upgrade" {
		t.Errorf("form snapname = %q, want before-upgrade", gotForm.Get("snapname"))
	}
	if string(raw) != `"UPID:qa-pve-01:12345::task::"` {
		t.Errorf("raw = %s, want the unwrapped data string", raw)
	}
}

func TestRawRequest_PutSendsParamsAsFormBody(t *testing.T) {
	var gotForm url.Values
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if _, err := c.RawRequest(context.Background(), http.MethodPut, "/nodes/qa-pve-01/qemu/100/config", url.Values{"cores": {"4"}}); err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if gotForm.Get("cores") != "4" {
		t.Errorf("form cores = %q, want 4", gotForm.Get("cores"))
	}
}

// TestRawRequest_EmptyBodyIsNull proves a successful write with a
// completely empty response body renders as JSON null rather than a
// parse error — the exact shape several real PVE write endpoints return
// (observed in this project's own test fixtures elsewhere, e.g.
// TestNewVMSetCmd_PositionalPairs_Success's fake server).
func TestRawRequest_EmptyBodyIsNull(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	raw, err := c.RawRequest(context.Background(), http.MethodPut, "/nodes/qa-pve-01/qemu/100/config", nil)
	if err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if string(raw) != "null" {
		t.Errorf("raw = %s, want null", raw)
	}
}

func TestRawRequest_ExplicitDataNullIsNull(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	})
	c := testClient(t, srv)

	raw, err := c.RawRequest(context.Background(), http.MethodGet, "/version", nil)
	if err != nil {
		t.Fatalf("RawRequest: %v", err)
	}
	if string(raw) != "null" {
		t.Errorf("raw = %s, want null", raw)
	}
}

// TestRawRequest_NonOKStatusPreservesBodyVerbatim is the whole reason this
// method bypasses go-proxmox: PVE's own diagnostic text on a 500/501 must
// survive, not be discarded the way go-proxmox's handleResponse would.
func TestRawRequest_NonOKStatusPreservesBodyVerbatim(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  only root can set 'args' config  \n"))
	})
	c := testClient(t, srv)

	_, err := c.RawRequest(context.Background(), http.MethodPut, "/nodes/qa-pve-01/qemu/100/config", url.Values{"args": {"-foo"}})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if got := err.Error(); !strings.Contains(got, "only root can set 'args' config") {
		t.Errorf("expected PVE's verbatim error text in %q", got)
	}
}

func TestRawRequest_MalformedJSONBody(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	c := testClient(t, srv)

	if _, err := c.RawRequest(context.Background(), http.MethodGet, "/version", nil); err == nil {
		t.Fatal("expected an error for a malformed JSON body")
	}
}

func TestRawRequest_RequiresPath(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when path is empty")
	}))
	if _, err := c.RawRequest(context.Background(), http.MethodGet, "", nil); err == nil {
		t.Fatal("expected an error for an empty path")
	}
}

func TestRawRequest_RequiresLeadingSlash(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when path has no leading slash")
	}))
	if _, err := c.RawRequest(context.Background(), http.MethodGet, "nodes/qa-pve-01", nil); err == nil {
		t.Fatal("expected an error for a path with no leading slash")
	}
}

func TestRawRequest_RejectsUnsupportedMethod(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network for an unsupported method")
	}))
	if _, err := c.RawRequest(context.Background(), http.MethodPatch, "/version", nil); err == nil {
		t.Fatal("expected an error for an unsupported HTTP method")
	}
}
