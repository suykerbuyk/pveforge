package pve

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// writeClusterStatusOK answers Client.Cluster(ctx)'s incidental
// GET /cluster/status probe with an empty-but-valid cluster status body —
// none of these tests care about its contents, only that it doesn't error.
func writeClusterStatusOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":[]}`))
}

func writeNextIDData(w http.ResponseWriter, vmid int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":"` + strconv.Itoa(vmid) + `"}`))
}

// vmidTakenBody is the exact PVE-shaped rejection body confirmed against
// go-proxmox v0.8.1's own vendored mock fixture
// (tests/mocks/pve9x/cluster.go) for a taken vmid.
func vmidTakenBody(vmid int) string {
	return `{"errors":{"vmid":"VM ` + strconv.Itoa(vmid) + ` already exists"},"data":null}`
}

func writeVMIDTaken(w http.ResponseWriter, vmid int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(vmidTakenBody(vmid)))
}

func TestNextVMID_NoPinNoExclude_PassesThroughNextID(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cluster/status":
			writeClusterStatusOK(w)
		case "/cluster/nextid":
			if r.URL.Query().Get("vmid") != "" {
				t.Fatalf("expected NextID's raw candidate to be trusted without a vmidFree check, got query %q", r.URL.RawQuery)
			}
			writeNextIDData(w, 105)
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 0)
	if err != nil {
		t.Fatalf("NextVMID: %v", err)
	}
	if got != 105 {
		t.Fatalf("NextVMID = %d, want 105", got)
	}
}

// TestNextVMID_NoPin_SkipsExcludedCandidatesWithoutNetworkCall covers the
// walk-forward loop's locally-claimed-id branch: candidates present in
// exclude are skipped WITHOUT ever calling vmidFree (no network call), only
// the first non-excluded candidate reached is checked against PVE.
func TestNextVMID_NoPin_SkipsExcludedCandidatesWithoutNetworkCall(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cluster/status":
			writeClusterStatusOK(w)
		case "/cluster/nextid":
			vmid := r.URL.Query().Get("vmid")
			switch vmid {
			case "":
				writeNextIDData(w, 100)
			case "102":
				writeNextIDData(w, 102)
			default:
				t.Fatalf("expected only vmid=102 to ever be checked (100 and 101 are locally excluded), got vmid=%q", vmid)
			}
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 0, 100, 101)
	if err != nil {
		t.Fatalf("NextVMID: %v", err)
	}
	if got != 102 {
		t.Fatalf("NextVMID = %d, want 102", got)
	}
}

// TestNextVMID_NoPin_WalksPastCandidateTakenByPVE covers the other
// walk-forward branch: a candidate that clears the exclude filter but is
// genuinely taken per PVE still gets an explicit vmidFree check (and the
// walk keeps advancing past it) rather than being returned on trust.
func TestNextVMID_NoPin_WalksPastCandidateTakenByPVE(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cluster/status":
			writeClusterStatusOK(w)
		case "/cluster/nextid":
			switch r.URL.Query().Get("vmid") {
			case "":
				writeNextIDData(w, 100)
			case "101":
				writeVMIDTaken(w, 101)
			case "102":
				writeNextIDData(w, 102)
			default:
				t.Fatalf("unexpected vmid query: %q", r.URL.RawQuery)
			}
		default:
			http.NotFound(w, r)
		}
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("NextVMID: %v", err)
	}
	if got != 102 {
		t.Fatalf("NextVMID = %d, want 102", got)
	}
}

func TestNextVMID_Pin_Free_ReturnsPin_NextIDNeverCalled(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cluster/nextid" || r.URL.Query().Get("vmid") != "55" {
			t.Fatalf("expected only a vmidFree check for the pin, NextID must never be called; got %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		writeNextIDData(w, 55)
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 55)
	if err != nil {
		t.Fatalf("NextVMID: %v", err)
	}
	if got != 55 {
		t.Fatalf("NextVMID = %d, want 55", got)
	}
}

func TestNextVMID_Pin_Taken_ErrorsNoSubstitution(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cluster/nextid" || r.URL.Query().Get("vmid") != "55" {
			t.Fatalf("expected only a vmidFree check for the pin; got %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		writeVMIDTaken(w, 55)
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 55)
	if err == nil {
		t.Fatalf("expected an error for a taken pin, got vmid %d with no error", got)
	}
	if got != 0 {
		t.Fatalf("expected a zero vmid alongside the error, got %d", got)
	}
}

func TestNextVMID_Pin_AlsoInExclude_ErrorsBeforeAnyNetworkCall(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("pin/exclude contradiction must be rejected before any network call, got request to %s", r.URL.String())
	})
	c := testClient(t, srv)

	got, err := c.NextVMID(context.Background(), 55, 55)
	if err == nil {
		t.Fatalf("expected an error when pin is also in exclude, got vmid %d", got)
	}
}

// TestVMIDFree_TakenTextMatch_CannedRejectionBody exercises vmidFree's
// vmid-specific "already exists" text match directly, against the exact
// PVE-shaped rejection body confirmed by go-proxmox's own vendored mock
// fixture — same spirit as
// TestVMTagEnsure_Apply_WrapsDigestConflictAsErrConflict's canned-text
// test for IsDigestConflictError.
func TestVMIDFree_TakenTextMatch_CannedRejectionBody(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cluster/nextid" || r.URL.Query().Get("vmid") != "200" {
			http.NotFound(w, r)
			return
		}
		writeVMIDTaken(w, 200)
	})
	c := testClient(t, srv)

	free, err := c.vmidFree(context.Background(), 200)
	if err != nil {
		t.Fatalf("vmidFree: expected the taken-vmid text match to classify this as (false, nil), got err: %v", err)
	}
	if free {
		t.Fatal("vmidFree: expected false for a taken vmid")
	}
}

// TestVMIDFree_UnrelatedError_NotMisclassifiedAsTaken proves the vmid
// parameterization actually matters: a genuine transport/API failure that
// happens to mention a DIFFERENT vmid's "already exists" text must not be
// swallowed as "this vmid is taken".
func TestVMIDFree_UnrelatedError_NotMisclassifiedAsTaken(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Rejects vmid 42 with text about a DIFFERENT vmid (201) already
		// existing — a stand-in for an unrelated PVE error that happens to
		// contain the "already exists" phrase for some other resource.
		writeVMIDTaken(w, 201)
	})
	c := testClient(t, srv)

	free, err := c.vmidFree(context.Background(), 42)
	if err == nil {
		t.Fatal("expected the mismatched vmid text to surface as a genuine error, not be classified as taken")
	}
	if free {
		t.Fatal("expected free=false alongside the propagated error")
	}
}

// TestRoutedClient_NextVMID_Forwards is the required integration-style
// test proving NextVMID works end-to-end through RoutedClient's
// pass-through, not just Client.NextVMID in isolation: covers both the
// no-pin/no-exclude passthrough path and the pin-given-and-free path.
func TestRoutedClient_NextVMID_Forwards(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cluster/status":
			writeClusterStatusOK(w)
		case "/cluster/nextid":
			switch r.URL.Query().Get("vmid") {
			case "":
				writeNextIDData(w, 300)
			case "42":
				writeNextIDData(w, 42)
			default:
				t.Fatalf("unexpected vmid query: %q", r.URL.RawQuery)
			}
		default:
			http.NotFound(w, r)
		}
	})
	// Built via NewClient(BaseURLOverride), not NewClientForTarget:
	// NextVMID goes through c.pc.Cluster/c.pc.Get, which use go-proxmox's
	// own internal base URL set at construction time — patching
	// rest.baseURL after the fact (as some other RoutedClient tests do, for
	// the raw-HTTP write path only) would not reach it. See
	// TestRoutedClient_TypedReadForwarding's identical note.
	rest := testClient(t, srv)
	tg := &roster.Target{ID: "qa-pve-01", Host: "qa-pve-01.example.com", Node: "qa-pve-01"}
	rc := &RoutedClient{rest: rest, target: tg, passphrase: "roster-pass"}
	defer rc.Close()

	ctx := context.Background()

	got, err := rc.NextVMID(ctx, 0)
	if err != nil {
		t.Fatalf("NextVMID (no pin): %v", err)
	}
	if got != 300 {
		t.Fatalf("NextVMID (no pin) = %d, want 300", got)
	}

	got, err = rc.NextVMID(ctx, 42)
	if err != nil {
		t.Fatalf("NextVMID (pin): %v", err)
	}
	if got != 42 {
		t.Fatalf("NextVMID (pin) = %d, want 42", got)
	}
}
