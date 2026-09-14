package pve

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestValidateTokenGrants_Success(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"node":"qa-pve-01"},{"node":"qa-pve-02"}]}`))
	})
	c := testClient(t, srv)

	if err := ValidateTokenGrants(context.Background(), c, "qa-pve-01"); err != nil {
		t.Fatalf("ValidateTokenGrants: %v", err)
	}
}

func TestValidateTokenGrants_EmptyList_ReturnsErrNoGrants(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	c := testClient(t, srv)

	err := ValidateTokenGrants(context.Background(), c, "qa-pve-01")
	if !errors.Is(err, ErrNoGrants) {
		t.Fatalf("expected ErrNoGrants, got: %v", err)
	}
}

func TestValidateTokenGrants_WrongNode_ReturnsErrWrongScope(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"node":"some-other-node"}]}`))
	})
	c := testClient(t, srv)

	err := ValidateTokenGrants(context.Background(), c, "qa-pve-01")
	if !errors.Is(err, ErrWrongScope) {
		t.Fatalf("expected ErrWrongScope, got: %v", err)
	}
}

func TestValidateTokenGrants_TransportFailure_NotConfusedWithNoGrants(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c := testClient(t, srv)

	err := ValidateTokenGrants(context.Background(), c, "qa-pve-01")
	if errors.Is(err, ErrNoGrants) || errors.Is(err, ErrWrongScope) {
		t.Fatalf("a transport/auth failure must not be reported as ErrNoGrants/ErrWrongScope: %v", err)
	}
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got: %v", err)
	}
}
