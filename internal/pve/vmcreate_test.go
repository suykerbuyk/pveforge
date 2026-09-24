package pve

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCreateVM_PostsVMIDAndParamsFormEncoded(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	var gotForm url.Values
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	params := url.Values{"cores": {"4"}, "memory": {"2048"}}
	upid, err := c.CreateVM(context.Background(), "qa-pve-01", 100, params)
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu", gotPath)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if gotForm.Get("vmid") != "100" {
		t.Errorf("form vmid = %q, want 100", gotForm.Get("vmid"))
	}
	if gotForm.Get("cores") != "4" || gotForm.Get("memory") != "2048" {
		t.Errorf("form cores/memory = %q/%q, want 4/2048", gotForm.Get("cores"), gotForm.Get("memory"))
	}
	const wantUPID = "UPID:qa-pve-01:00001234:0000ABCD:5F000000:qmcreate:100:root@pam:"
	if upid != wantUPID {
		t.Errorf("upid = %q, want %q", upid, wantUPID)
	}
}

// TestCreateVM_NilParamsDoesNotPanic covers the boundary case where a
// caller passes a nil url.Values — params.Set on a nil map would panic,
// so CreateVM must allocate before setting vmid.
func TestCreateVM_NilParamsDoesNotPanic(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.PostForm.Get("vmid") != "101" {
			t.Errorf("form vmid = %q, want 101", r.PostForm.Get("vmid"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmcreate:101:root@pam:"}`))
	})
	c := testClient(t, srv)

	if _, err := c.CreateVM(context.Background(), "qa-pve-01", 101, nil); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
}

// TestCreateVM_DoesNotMutateCallerParams proves CreateVM clones params
// before stamping "vmid" onto it — the caller's own map (e.g.
// VMCreate.Apply's op.Params) must come back exactly as it went in, with
// no "vmid" key silently added to it.
func TestCreateVM_DoesNotMutateCallerParams(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:"}`))
	})
	c := testClient(t, srv)

	params := url.Values{"cores": {"4"}}
	if _, err := c.CreateVM(context.Background(), "qa-pve-01", 100, params); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if _, ok := params["vmid"]; ok {
		t.Errorf("caller's params was mutated: got vmid key %v, want untouched", params["vmid"])
	}
	if len(params) != 1 {
		t.Errorf("caller's params gained keys: %v, want only cores", params)
	}
}

func TestCreateVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach the network when node is empty")
	}))
	if _, err := c.CreateVM(context.Background(), "", 100, url.Values{}); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

// TestCreateVM_ServerErrorBodyIsVisible is a real regression test proving
// the RawRequest-based approach puts PVE's text for an HTTP 500/501 in the
// returned error, where go-proxmox's error text is only the status line
// (and through v0.8.2-pveforge.0 handleResponse's
// `return errors.New(res.Status)` never read the body at all) — a design
// reason CreateVM goes through RawRequest rather than go-proxmox's own
// VM-create call. It checks the response BODY text is present in the
// returned error, not just the HTTP status.
func TestCreateVM_ServerErrorBodyIsVisible(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  VM 100 already exists on node 'qa-pve-01'  \n"))
	})
	c := testClient(t, srv)

	_, err := c.CreateVM(context.Background(), "qa-pve-01", 100, url.Values{})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if got := err.Error(); !strings.Contains(got, "VM 100 already exists on node 'qa-pve-01'") {
		t.Errorf("expected PVE's verbatim error body in %q", got)
	}
}

func TestDecodeUPIDScalar_DecodesString(t *testing.T) {
	upid, err := decodeUPIDScalar([]byte(`"UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:"`))
	if err != nil {
		t.Fatalf("decodeUPIDScalar: %v", err)
	}
	if upid != "UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:" {
		t.Errorf("upid = %q", upid)
	}
}

// TestDecodeUPIDScalar_RejectsNonStringResponses proves decodeUPIDScalar
// errors clearly on a non-string JSON response rather than silently
// returning garbage — the whole reason it doesn't reuse
// internal/kvjson.Scalar (see decodeUPIDScalar's own doc comment).
func TestDecodeUPIDScalar_RejectsNonStringResponses(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"number", `12345`},
		{"object", `{"upid":"UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:"}`},
		{"array", `["UPID:qa-pve-01:1:2:3:qmcreate:100:root@pam:"]`},
		{"null", `null`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeUPIDScalar([]byte(c.raw)); err == nil {
				t.Fatalf("expected an error decoding %s as a UPID scalar", c.raw)
			}
		})
	}
}

// TestCreateVM_MalformedUPIDResponseErrors covers the same non-string
// rejection end to end through CreateVM itself, not just
// decodeUPIDScalar in isolation.
func TestCreateVM_MalformedUPIDResponseErrors(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":12345}`))
	})
	c := testClient(t, srv)

	if _, err := c.CreateVM(context.Background(), "qa-pve-01", 100, url.Values{}); err == nil {
		t.Fatal("expected an error for a non-string upid response")
	}
}
