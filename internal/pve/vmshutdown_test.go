package pve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

const testShutdownUPID = "UPID:qa-pve-01:00001236:0000ABCF:5F000002:qmshutdown:100:root@pam:"

// TestShutdownVM_PostsToStatusShutdownWithNoBody is the wire-level
// contract: the right method, the right path (node AND vmid both actually
// on it — a path assertion that doesn't pin the vmid would pass just as
// happily while shutting down VMID+1), and an empty request body, since
// this first cut sends no parameters at all.
func TestShutdownVM_PostsToStatusShutdownWithNoBody(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody string
	var requests int
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"` + testShutdownUPID + `"}`))
	})
	c := testClient(t, srv)

	upid, err := c.ShutdownVM(context.Background(), "qa-pve-01", 100)
	if err != nil {
		t.Fatalf("ShutdownVM: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/nodes/qa-pve-01/qemu/100/status/shutdown" {
		t.Errorf("path = %q, want /nodes/qa-pve-01/qemu/100/status/shutdown", gotPath)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want no query parameters at all", gotQuery)
	}
	if gotBody != "" {
		t.Errorf("body = %q, want an empty body", gotBody)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want exactly 1 (a shutdown is one call, with no follow-up)", requests)
	}
	if upid != testShutdownUPID {
		t.Errorf("upid = %q, want %q", upid, testShutdownUPID)
	}
}

// TestShutdownVM_PathPinsNodeAndVMID proves the node and the vmid the
// caller passed are the ones that actually reach the wire — separately
// from the fixed-fixture test above, so a hardcoded path could never
// satisfy both. This is the class of gap that let an earlier unit's
// destroy tests pass while destroying VMID+1.
func TestShutdownVM_PathPinsNodeAndVMID(t *testing.T) {
	cases := []struct {
		node     string
		vmid     int
		wantPath string
	}{
		{"qa-pve-01", 100, "/nodes/qa-pve-01/qemu/100/status/shutdown"},
		{"qa-pve-01", 101, "/nodes/qa-pve-01/qemu/101/status/shutdown"},
		{"other-node", 100, "/nodes/other-node/qemu/100/status/shutdown"},
		{"node with space", 4242, "/nodes/node with space/qemu/4242/status/shutdown"},
	}
	for _, c := range cases {
		t.Run(c.wantPath, func(t *testing.T) {
			var gotPath string
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":"` + testShutdownUPID + `"}`))
			})
			if _, err := testClient(t, srv).ShutdownVM(context.Background(), c.node, c.vmid); err != nil {
				t.Fatalf("ShutdownVM: %v", err)
			}
			// r.URL.Path is the already-unescaped path, so the space in the
			// last case proves url.PathEscape ran without the assertion
			// having to hardcode its encoding.
			if gotPath != c.wantPath {
				t.Errorf("path = %q, want %q", gotPath, c.wantPath)
			}
		})
	}
}

func TestShutdownVM_RequiresNode(t *testing.T) {
	c := testClient(t, newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not reach the network without a node")
	}))
	if _, err := c.ShutdownVM(context.Background(), "", 100); err == nil {
		t.Fatal("expected an error for an empty node")
	}
}

// TestShutdownVM_PropagatesPVEErrorText is the RawRequest-not-go-proxmox
// justification (hazard D) made observable: PVE answers a shutdown-time
// rejection with HTTP 500, whose body go-proxmox's handleResponse threw
// away through v0.8.2-pveforge.0 and since .1 keeps out of its error text
// (the status line only), so the diagnostic text surviving here is the
// evidence that this primitive does not route through it.
func TestShutdownVM_PropagatesPVEErrorText(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("VM 100 is locked (backup)"))
	})
	c := testClient(t, srv)

	_, err := c.ShutdownVM(context.Background(), "qa-pve-01", 100)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "VM 100 is locked (backup)") {
		t.Errorf("expected PVE's verbatim error text to survive, got: %v", err)
	}
}

// TestShutdownVM_RejectsNonUPIDResponse pins that the UPID decode is the
// strict decodeUPIDScalar (vmcreate.go), not a permissive coercion: a
// response that isn't the documented UPID string must surface as a decode
// failure rather than sailing on to WaitForTask as an empty or
// plausible-looking string.
func TestShutdownVM_RejectsNonUPIDResponse(t *testing.T) {
	for _, body := range []string{`{"data":null}`, `{"data":{"upid":"x"}}`, `{"data":42}`, ``} {
		srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
		upid, err := testClient(t, srv).ShutdownVM(context.Background(), "qa-pve-01", 100)
		if err == nil {
			t.Errorf("body %q: expected an error, got upid %q", body, upid)
		}
	}
}

// TestShutdownVM_MakesExactlyOneRequestOnEveryPath is the BEHAVIOURAL
// no-escalation guard, and the strongest of the three this primitive
// carries: whatever PVE answers, exactly one request may leave this
// process. It does not care how an escalation is spelled, whether the verb
// is assembled at runtime, or which file the helper that sends it lives in
// — a second call is visible on the wire either way.
//
// It exists because review demonstrated the alternative: a hard-stop
// escalation on the ERROR path passed the entire suite. The happy-path test
// above counts requests, but its server always answers 200, so an
// escalation branch that only runs after a rejection never executed there.
// Every row below drives a different failure shape for exactly that reason.
func TestShutdownVM_MakesExactlyOneRequestOnEveryPath(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"success", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":"` + testShutdownUPID + `"}`))
		}},
		{"pve rejects with 500", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("VM 100 is locked (backup)"))
		}},
		{"pve rejects with 501", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = w.Write([]byte("not implemented"))
		}},
		{"not found", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}},
		{"malformed upid body", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"upid":"x"}}`))
		}},
		{"empty body", func(w http.ResponseWriter, r *http.Request) {}},
	}
	// BOTH entry points are driven, not just the low-level one. Review
	// found an escalation placed in RoutedClient.ShutdownVM surviving the
	// entire package suite: this table used to call Client.ShutdownVM only,
	// so the pass-through — the one production actually holds — was a guard
	// root with no behavioural test over it at all. The identical escalation
	// in Client.ShutdownVM was caught; it survived solely by sitting in the
	// function nothing drove.
	entries := []struct {
		name string
		call func(t *testing.T, srv *httptest.Server)
	}{
		{"Client.ShutdownVM", func(t *testing.T, srv *httptest.Server) {
			// Return values deliberately ignored: this test asserts nothing
			// about success or failure, only how many calls reached the
			// network and where they went.
			_, _ = testClient(t, srv).ShutdownVM(context.Background(), "qa-pve-01", 100)
		}},
		{"RoutedClient.ShutdownVM", func(t *testing.T, srv *httptest.Server) {
			tg := &roster.Target{ID: "qa-pve-01", Host: "qa-pve-01.example.com", Node: "qa-pve-01"}
			rc := &RoutedClient{rest: testClient(t, srv), target: tg, passphrase: "roster-pass"}
			_, _ = rc.ShutdownVM(context.Background(), 100)
		}},
	}

	for _, e := range entries {
		for _, c := range cases {
			t.Run(e.name+"/"+c.name, func(t *testing.T) {
				var requests int
				var paths []string
				srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
					requests++
					paths = append(paths, r.Method+" "+r.URL.Path)
					c.handler(w, r)
				})

				e.call(t, srv)

				if requests != 1 {
					t.Errorf("%d requests reached the network (%v), want exactly 1 — "+
						"a graceful shutdown is ONE call, and a second one is how a hard-stop "+
						"escalation would show itself", requests, paths)
				}
				for _, p := range paths {
					if p != "POST /nodes/qa-pve-01/qemu/100/status/shutdown" {
						t.Errorf("request %q went somewhere other than the graceful shutdown endpoint", p)
					}
				}
			})
		}
	}
}

// TestShutdownVM_ExposesNoHardStopPath is the structural half of this
// task's design point: this primitive must never gain a hard-stop
// escalation, as a parameter, a default, or a fallback.
//
// Two legs, and it is worth being clear about what each one reaches:
//
//  1. Reflection pins the SIGNATURE — a force/timeout parameter cannot be
//     added without failing, including as a variadic that would leave every
//     existing call site compiling.
//  2. internal/sourceguard walks the call graph reachable from ShutdownVM
//     across the WHOLE package and scans it for stop/kill/force tokens.
//     This replaces an earlier scan that read this one file's text: review
//     showed a hard-stop helper in a sibling file of package pve defeated
//     that entirely, which is an ordinary thing for a later contributor to
//     write rather than an adversarial trick.
//
// Neither leg defeats deliberate evasion — a verb assembled at runtime, or
// reflection — and neither is claimed to. The behavioural request count
// above is what covers those, by not depending on spelling at all.
func TestShutdownVM_ExposesNoHardStopPath(t *testing.T) {
	// Leg 1 — signature: exactly (context.Context, string, int) -> (string, error).
	m, ok := reflect.TypeOf((*Client)(nil)).MethodByName("ShutdownVM")
	if !ok {
		t.Fatal("Client has no ShutdownVM method")
	}
	ft := m.Type
	// NumIn includes the receiver.
	if got, want := ft.NumIn(), 4; got != want {
		t.Errorf("ShutdownVM takes %d parameters (incl. receiver), want %d — "+
			"a new parameter here is exactly the hard-stop/timeout knob this primitive refuses to expose", got, want)
	}
	if ft.NumIn() == 4 {
		if got := ft.In(2).Kind(); got != reflect.String {
			t.Errorf("ShutdownVM parameter 1 is %v, want string (node)", got)
		}
		if got := ft.In(3).Kind(); got != reflect.Int {
			t.Errorf("ShutdownVM parameter 2 is %v, want int (vmid)", got)
		}
	}
	if got, want := ft.NumOut(), 2; got != want {
		t.Errorf("ShutdownVM returns %d values, want %d (upid, error)", got, want)
	}

	// Leg 2 — package-wide call graph reachable from either ShutdownVM.
	tokens, err := sourceguard.ReachableTokens(".", []string{"Client.ShutdownVM", "RoutedClient.ShutdownVM"})
	if err != nil {
		t.Fatalf("sourceguard: %v", err)
	}
	for _, hit := range sourceguard.FindForbidden(tokens, forbiddenHardStopTokens) {
		t.Errorf("code reachable from ShutdownVM names a hard-stop token — %s; "+
			"this primitive exposes no escalation path of any kind (see ShutdownVM's own doc comment)", hit)
	}
}

// forbiddenHardStopTokens is what may not appear in anything reachable from
// ShutdownVM. Comments are never scanned — sourceguard walks the AST, whose
// function bodies do not carry them — so ShutdownVM's own doc comment is
// free to discuss "force" and "status/stop" at the length the design needs
// without tripping or satisfying this list.
var forbiddenHardStopTokens = []string{
	"status/stop", "StopVM", "forceStop", "force", "skiplock", "hard", "kill", "timeout",
}
