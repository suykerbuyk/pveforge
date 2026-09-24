package pve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// pveforge-rawrequest-typed-status-error: a non-2xx answer is a
// *StatusError carrying the code, the status line and the body as received,
// while its text stays exactly what the substring classifiers read.

// statusBody has surrounding whitespace and an inner line break, so a
// trimmed or re-encoded Body is visible.
const statusBody = " {\"errors\":{\"vmid\":\"why\"}}\nsecond line \n"

// S1: RawRequest's non-2xx answer, for each status a caller cares about, is
// reachable with errors.As through a caller's %w wrap, with the right Code
// and Status and a byte-exact Body; HTTPStatus agrees; the text is the
// historical one, and only 401/403 are ErrNotAuthorized.
func TestStatusError_S1_RawRequest(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 500, 501} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(statusBody))
			})
			_, err := testClient(t, srv).RawRequest(context.Background(), http.MethodGet, "/x", nil)
			err = fmt.Errorf("caller: %w", err)
			var se *StatusError
			if !errors.As(err, &se) {
				t.Fatalf("errors.As(*StatusError) = false for %v", err)
			}
			wantStatus := fmt.Sprintf("%d %s", code, http.StatusText(code))
			if se.Code != code || se.Status != wantStatus || !bytes.Equal(se.Body, []byte(statusBody)) {
				t.Errorf("StatusError{Code %d, Status %q, Body %q}, want {%d, %q, %q}", se.Code, se.Status, se.Body, code, wantStatus, statusBody)
			}
			if got, ok := HTTPStatus(err); !ok || got != code {
				t.Errorf("HTTPStatus = %d, %v; want %d, true", got, ok, code)
			}
			wantText := "raw request: pve returned " + wantStatus + ": {\"errors\":{\"vmid\":\"why\"}}\nsecond line"
			if se.Error() != wantText {
				t.Errorf("text = %q, want exactly %q", se.Error(), wantText)
			}
			if auth := code == 401 || code == 403; errors.Is(err, ErrNotAuthorized) != auth {
				t.Errorf("errors.Is(err, ErrNotAuthorized) = %v, want %v", !auth, auth)
			}
			var pse *proxmox.StatusError
			if errors.As(err, &pse) || errors.Unwrap(se) != nil {
				t.Error("a StatusError must not unwrap, and must not be a *proxmox.StatusError")
			}
		})
	}
}

// S2: the config PUT behind SetVMConfigFieldCAS and DeleteVMConfigFieldCAS
// returns a *StatusError too, its text unchanged — so IsDigestConflictError
// still reads a digest rejection — and a 401 is now ErrNotAuthorized, as
// ErrNotAuthorized's own contract says.
func TestStatusError_S2_ConfigPut(t *testing.T) {
	for name, write := range map[string]func(c *Client) error{
		"set": func(c *Client) error {
			return c.SetVMConfigFieldCAS(context.Background(), "qa-pve-01", 100, "cores", "4", "d1")
		},
		"delete": func(c *Client) error {
			return c.DeleteVMConfigFieldCAS(context.Background(), "qa-pve-01", 100, "description", "d1")
		},
	} {
		what := map[string]string{"set": `set vm 100 field "cores"`, "delete": `delete vm 100 field "description"`}[name]
		for _, tc := range []struct {
			code int
			body string
		}{
			{500, "{\"errors\":{\"digest\":\"detected modified configuration - file changed by another user? Try again.\"}}\n"},
			{401, "no ticket\n"},
		} {
			t.Run(fmt.Sprintf("%s %d", name, tc.code), func(t *testing.T) {
				srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tc.code)
					_, _ = w.Write([]byte(tc.body))
				})
				err := write(testClient(t, srv))
				var se *StatusError
				if !errors.As(err, &se) || se.Code != tc.code || string(se.Body) != tc.body {
					t.Fatalf("err = %#v, want a *StatusError %d with the body as received", err, tc.code)
				}
				want := fmt.Sprintf("%s: pve returned %d %s: %s", what, tc.code, http.StatusText(tc.code), bytes.TrimSpace([]byte(tc.body)))
				if err.Error() != want {
					t.Errorf("text = %q, want exactly %q", err.Error(), want)
				}
				if IsDigestConflictError(err) != (tc.code == 500) {
					t.Errorf("IsDigestConflictError = %v for %d", !(tc.code == 500), tc.code)
				}
				if errors.Is(err, ErrNotAuthorized) != (tc.code == 401) {
					t.Errorf("errors.Is(err, ErrNotAuthorized) wrong for %d", tc.code)
				}
			})
		}
	}
}

// S3: HTTPStatus is false for nil, a transport failure and a non-status
// error, wrapped or not.
func TestStatusError_S3_HTTPStatusFalse(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	c := testClient(t, srv)
	srv.Close() // every request now fails in transport
	_, transport := c.RawRequest(context.Background(), http.MethodGet, "/x", nil)
	if transport == nil {
		t.Fatal("want a transport error")
	}
	for name, err := range map[string]error{
		"nil":       nil,
		"transport": transport,
		"plain":     errors.New("pve returned 500 Internal Server Error: looks like one"),
		"wrapped":   fmt.Errorf("x: %w", ErrUnverifiableRead),
	} {
		if code, ok := HTTPStatus(err); ok || code != 0 {
			t.Errorf("%s: HTTPStatus = %d, %v; want 0, false", name, code, ok)
		}
	}
}
