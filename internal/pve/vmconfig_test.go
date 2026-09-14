package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

func TestSetVMConfigField_Success(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotBody = r.PostForm.Get("args")
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if err := c.SetVMConfigField(context.Background(), "qa-pve-01", 100, "args", "-device foo"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/config" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100/config", gotPath)
	}
	if gotAuth != "PVEAPIToken=root@pam!pveforge=test-secret" {
		t.Errorf("Authorization header = %q", gotAuth)
	}
	if gotBody != "-device foo" {
		t.Errorf("posted field value = %q, want %q", gotBody, "-device foo")
	}
}

// TestSetVMConfigField_500SurfacesBodyVerbatim is the key regression test
// for the whole raw-HTTP-bypass design: go-proxmox's own handleResponse
// discards the response body entirely on 500/501
// (`return errors.New(res.Status)`), which would make it impossible to
// ever see PVE's actual rejection text. This asserts the real, verified
// PVE error string survives byte-for-byte, and that
// sshexec.IsRootOnlyWriteError recognizes the resulting error — proving
// the cross-package wiring this task exists to build.
func TestSetVMConfigField_500SurfacesBodyVerbatim(t *testing.T) {
	const pveMessage = `only root can set 'args' config`
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(pveMessage))
	})
	c := testClient(t, srv)

	err := c.SetVMConfigField(context.Background(), "qa-pve-01", 100, "args", "-device foo")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), pveMessage) {
		t.Fatalf("expected the exact PVE error text to survive verbatim, got: %v", err)
	}
	if !sshexec.IsRootOnlyWriteError(err) {
		t.Fatalf("expected sshexec.IsRootOnlyWriteError to recognize this error: %v", err)
	}
}

func TestSetVMConfigField_400SurfacesBody(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":{"args":"invalid format"}}`))
	})
	c := testClient(t, srv)

	err := c.SetVMConfigField(context.Background(), "qa-pve-01", 100, "args", "bad-value")
	if err == nil {
		t.Fatal("expected an error for a 400 response")
	}
	if !strings.Contains(err.Error(), "invalid format") {
		t.Fatalf("expected the response body to be surfaced, got: %v", err)
	}
}

// TestSetVMConfigField_EscapesNodeInURL guards the cheap hardening item:
// node is roster-config-controlled, not external input, but an unescaped
// node name containing a special character would otherwise silently
// corrupt the request path rather than failing loudly.
func TestSetVMConfigField_EscapesNodeInURL(t *testing.T) {
	var gotEscapedPath string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is net/http's already-decoded form regardless of how
		// the request was encoded on the wire — EscapedPath() is what
		// actually reflects whether pveforge escaped the node name in the
		// request it sent.
		gotEscapedPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if err := c.SetVMConfigField(context.Background(), "weird node/name", 100, "args", "v"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if gotEscapedPath != "/nodes/weird%20node%2Fname/qemu/100/config" {
		t.Fatalf("expected the node name to be escaped on the wire, got escaped path: %q", gotEscapedPath)
	}
}

// TestSetVMConfigFieldCAS_SendsDigestWhenProvided proves the "digest"
// form parameter is only ever added when expectDigest is non-empty
// (SetVMConfigField's own unconditional-write behavior must be
// unaffected by this CAS sibling existing).
func TestSetVMConfigFieldCAS_SendsDigestWhenProvided(t *testing.T) {
	var gotDigest string
	var digestPresent bool
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		_, digestPresent = r.PostForm["digest"]
		if digestPresent {
			gotDigest = r.PostForm.Get("digest")
		}
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if err := c.SetVMConfigFieldCAS(context.Background(), "qa-pve-01", 100, "tags", "prod", "abc123digest"); err != nil {
		t.Fatalf("SetVMConfigFieldCAS: %v", err)
	}
	if !digestPresent || gotDigest != "abc123digest" {
		t.Errorf("expected digest=abc123digest on the wire, got present=%v value=%q", digestPresent, gotDigest)
	}
}

func TestSetVMConfigFieldCAS_OmitsDigestWhenEmpty(t *testing.T) {
	var digestPresent bool
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		_, digestPresent = r.PostForm["digest"]
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if err := c.SetVMConfigFieldCAS(context.Background(), "qa-pve-01", 100, "tags", "prod", ""); err != nil {
		t.Fatalf("SetVMConfigFieldCAS: %v", err)
	}
	if digestPresent {
		t.Error("expected no digest form field when expectDigest is empty")
	}
}

// TestSetVMConfigField_IsCASWithEmptyDigest is the reverse check: the
// plain SetVMConfigField is genuinely just SetVMConfigFieldCAS(..., "")
// under the hood, not a separately-diverging code path.
func TestSetVMConfigField_IsCASWithEmptyDigest(t *testing.T) {
	var digestPresent bool
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		_, digestPresent = r.PostForm["digest"]
		w.WriteHeader(http.StatusOK)
	})
	c := testClient(t, srv)

	if err := c.SetVMConfigField(context.Background(), "qa-pve-01", 100, "tags", "prod"); err != nil {
		t.Fatalf("SetVMConfigField: %v", err)
	}
	if digestPresent {
		t.Error("SetVMConfigField must never send a digest parameter")
	}
}

func TestIsDigestConflictError(t *testing.T) {
	if IsDigestConflictError(nil) {
		t.Error("nil error should never be a digest conflict")
	}
	if !IsDigestConflictError(errors.New("update VM 100: digest mismatch")) {
		t.Error("expected an error mentioning 'digest' to be recognized")
	}
	if !IsDigestConflictError(errors.New("PVE returned 400: Digest verification failed")) {
		t.Error("expected recognition to be case-insensitive")
	}
	if IsDigestConflictError(errors.New("only root can set 'args' config")) {
		t.Error("an unrelated error must not be misrecognized as a digest conflict")
	}
}

func TestSetVMConfigField_RequiresNodeAndField(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node/field validation fails locally")
	}))

	if err := c.SetVMConfigField(context.Background(), "", 100, "args", "v"); err == nil {
		t.Fatal("expected error for empty node")
	}
	if err := c.SetVMConfigField(context.Background(), "qa-pve-01", 100, "", "v"); err == nil {
		t.Fatal("expected error for empty field")
	}
}
