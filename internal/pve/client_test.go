package pve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newFakeAPIServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{
		BaseURLOverride: srv.URL,
		TokenID:         "root@pam!pveforge",
		TokenSecret:     "test-secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClient_RequiresHostOrOverride(t *testing.T) {
	_, err := NewClient(ClientConfig{TokenID: "x", TokenSecret: "y"})
	if err == nil {
		t.Fatal("expected error when neither Host nor BaseURLOverride is set")
	}
}

func TestNewClient_RequiresToken(t *testing.T) {
	_, err := NewClient(ClientConfig{Host: "example.com"})
	if err == nil {
		t.Fatal("expected error when token id/secret are missing")
	}
}

func TestNewClient_DerivesBaseURLFromHostAndPort(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Host:        "qa-pve-01.example.com",
		APIPort:     8443,
		TokenID:     "root@pam!pveforge",
		TokenSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("expected a non-nil client")
	}
}

func TestListNodes_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodes" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"node":"qa-pve-01"},{"node":"qa-pve-02"}]}`))
	})
	c := testClient(t, srv)

	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 2 || nodes[0] != "qa-pve-01" || nodes[1] != "qa-pve-02" {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
}

func TestListNodes_EmptyList(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected empty node list, got: %+v", nodes)
	}
}

func TestListNodes_Forbidden(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := testClient(t, srv)

	_, err := c.ListNodes(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 403 response")
	}
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got: %v", err)
	}
}

func TestListNodes_Unauthorized(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := testClient(t, srv)

	_, err := c.ListNodes(context.Background())
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got: %v", err)
	}
}

func TestListNodes_ServerError(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	c := testClient(t, srv)

	_, err := c.ListNodes(context.Background())
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if errors.Is(err, ErrNotAuthorized) {
		t.Fatal("a 500 should not be reported as ErrNotAuthorized")
	}
}

func TestNewClient_InsecureTLSDoesNotErrorOnConstruction(t *testing.T) {
	c, err := NewClient(ClientConfig{
		Host:        "qa-pve-01.example.com",
		InsecureTLS: true,
		TokenID:     "root@pam!pveforge",
		TokenSecret: "secret",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("expected a non-nil client")
	}
}
