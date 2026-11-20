package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// These tests call FreeProof DIRECTLY against servers of their own, and assert
// its STATE. The instrument is shown to move (a Free case and an InUse case in
// the same table) before any "not free" row is believed.

func rawClient(t *testing.T, statusLine, body string) *Client {
	t.Helper()
	return detClient(t, rawStatusServer(t, statusLine, body))
}

// inUseBody is the production 400's body (see pvefake.NextIDInUseBody): the
// sentence is under errors.vmid, not in the reason phrase.
const prodReason = "400 Parameter verification failed."

func TestFreeProof_Table(t *testing.T) {
	const v = 690
	for _, tc := range []struct {
		name   string
		status string
		body   string
		want   VMIDState
		detail string // substring the Detail must carry, "" = none required
	}{
		// the control: the instrument moves in both directions.
		{"free: string echo", "200 OK", `{"data":"690"}`, VMIDFree, ""},
		{"free: number echo", "200 OK", `{"data":690}`, VMIDFree, ""},
		{"in use: production 400, sentence in the BODY", prodReason, pvefake.NextIDInUseBody("690"), VMIDInUse, "already in use"},
		{"in use: master wording", prodReason, pvefake.NextIDInUseMasterBody("690"), VMIDInUse, "already in use"},

		// a 200 that is not an exact echo is NEVER free (S1).
		{"200 echoing another vmid", "200 OK", `{"data":"691"}`, VMIDUnverified, "not with a single scalar"},
		{"200 echoing a longer vmid", "200 OK", `{"data":"6900"}`, VMIDUnverified, ""},
		{"200 echoing a prefix", "200 OK", `{"data":"69"}`, VMIDUnverified, ""},
		{"200 echoing a number for another vmid", "200 OK", `{"data":691}`, VMIDUnverified, ""},
		{"200 empty string", "200 OK", `{"data":""}`, VMIDUnverified, ""},
		{"200 null", "200 OK", `{"data":null}`, VMIDUnverified, ""},
		{"200 array", "200 OK", `{"data":[690]}`, VMIDUnverified, ""},
		{"200 object", "200 OK", `{"data":{"vmid":690}}`, VMIDUnverified, ""},
		{"200 bool", "200 OK", `{"data":true}`, VMIDUnverified, ""},
		{"200 float spelling", "200 OK", `{"data":690.0}`, VMIDUnverified, ""},
		{"200 padded string", "200 OK", `{"data":" 690"}`, VMIDUnverified, ""},
		{"200 not JSON", "200 OK", `not json`, VMIDUnverified, ""},

		// every other error is Unverified: never in use, never free.
		{"400 about ANOTHER vmid", prodReason, pvefake.NextIDInUseBody("691"), VMIDUnverified, ""},
		{"400 about a longer vmid", prodReason, pvefake.NextIDInUseBody("6900"), VMIDUnverified, ""},
		{"500 quoting PVE's sentence", "500 Internal Server Error", pvefake.NextIDInUseBody("690"), VMIDUnverified, ""},
		{"403", "403 Forbidden", `{"data":null}`, VMIDUnverified, ""},
		{"401", "401 Unauthorized", `{"data":null}`, VMIDUnverified, ""},
		{"595", "595 no route to host", `{"data":null}`, VMIDUnverified, ""},

		// master's enforcement rejections are 400s that are NOT "in use" (R-ENFORCE).
		{"400 enforce: below the lower boundary", prodReason, `{"message":"Parameter verification failed.\n","errors":{"vmid":"guest ID 690 is below the lower boundary 1000 of the next-id range\n"}}`, VMIDUnverified, "enforcement"},
		{"400 enforce: not below the upper boundary", prodReason, `{"errors":{"vmid":"guest ID 690 is not below the upper boundary 600 of the next-id range\n"}}`, VMIDUnverified, "enforcement"},
		{"400 enforce: used before", prodReason, `{"errors":{"vmid":"guest ID 690 was used before\n"}}`, VMIDUnverified, "enforcement"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rawClient(t, tc.status, tc.body).FreeProof(context.Background(), v)
			if r.State != tc.want {
				t.Fatalf("state = %d, want %d (detail %q)", r.State, tc.want, r.Detail)
			}
			if tc.want == VMIDFree && r.Detail != "" {
				t.Errorf("a Free result carries detail %q", r.Detail)
			}
			if tc.want != VMIDFree && r.Detail == "" {
				t.Errorf("a non-Free result carries no detail: the refusal would name nothing")
			}
			if tc.detail != "" && !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("detail %q lacks %q", r.Detail, tc.detail)
			}
			if r.Read != "GET /cluster/nextid" {
				t.Errorf("Read = %q", r.Read)
			}
		})
	}
}

// The InUse decision is made from the BODY: a message that does not quote it is
// still classified (the reason phrase is only "Parameter verification failed.").
func TestFreeProof_InUseIsDecidedFromTheBody(t *testing.T) {
	r := rawClient(t, prodReason, pvefake.NextIDInUseBody("690")).FreeProof(context.Background(), 690)
	if r.State != VMIDInUse {
		t.Fatalf("state = %d", r.State)
	}
	// The same body without the sentence is not "in use".
	r = rawClient(t, prodReason, `{"message":"Parameter verification failed.\n","errors":{"vmid":"value does not match"}}`).FreeProof(context.Background(), 690)
	if r.State != VMIDUnverified {
		t.Fatalf("a 400 without the sentence: state = %d, want Unverified", r.State)
	}
}

func TestFreeProof_ZeroValueIsNotFree(t *testing.T) {
	var z FreeResult
	if z.State == VMIDFree || z.State == VMIDInUse {
		t.Fatal("the zero FreeResult must read as unverified")
	}
	if got := (&Client{}).FreeProof(context.Background(), 0); got.State != VMIDUnverified {
		t.Errorf("vmid 0: %d, want Unverified without any request", got.State)
	}
}

// The request carries exactly vmid=N and nothing else, once (E10: a client that
// forgot the vmid would be told "free" by a fake that echoes anything).
func TestFreeProof_SendsExactlyTheVMID(t *testing.T) {
	s := pvefake.NewVMREST(t, detNode)
	s.NextID = map[string]pvefake.NextIDAnswer{
		"690": {Body: `"690"`},
		"691": {Code: 400, Body: pvefake.NextIDInUseBody("691")},
	}
	srv := s.Server()
	defer srv.Close()
	c := detClient(t, srv.URL+"/api2/json")

	if r := c.FreeProof(context.Background(), 690); r.State != VMIDFree {
		t.Fatalf("690: %+v", r)
	}
	if r := c.FreeProof(context.Background(), 691); r.State != VMIDInUse {
		t.Fatalf("691: %+v (the same client, another vmid, answers differently: the instrument moves)", r)
	}
	got := s.Requests()
	want := []string{"GET /api2/json/cluster/nextid ?vmid=690", "GET /api2/json/cluster/nextid ?vmid=691"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("requests = %v, want %v", got, want)
	}
}

// T-vmidfree-contrast (grok F6; the live demonstration of S1 and the A4 killer):
// ONE server, ONE *Client. vmidFree reads a 200 echoing the WRONG vmid as free;
// FreeProof does not. A mutant that routes FreeProof through vmidFree compiles
// and goes red here.
func TestFreeProof_ContrastWithVMIDFree(t *testing.T) {
	c := rawClient(t, "200 OK", `{"data":"691"}`)
	free, err := c.vmidFree(context.Background(), 690)
	if err != nil || !free {
		t.Fatalf("vmidFree(690) against 200 \"691\" = (%v, %v); this test's premise is that it says (true, nil)", free, err)
	}
	if got := c.FreeProof(context.Background(), 690); got.State != VMIDUnverified {
		t.Fatalf("FreeProof(690) against 200 \"691\" = %d, want Unverified", got.State)
	}
}

// scalarEqualsInt, directly, with the shapes a 200 cannot carry through the
// envelope (two values).
func TestScalarEqualsInt(t *testing.T) {
	for raw, want := range map[string]bool{
		`"690"`: true, `690`: true,
		`691`: false, `"691"`: false, `"6900"`: false, `"69"`: false, `""`: false,
		`null`: false, `[690]`: false, `{}`: false, `true`: false, `690.0`: false, `6.9e2`: false,
		"690\n\"691\"": false, `"690" "690"`: false, `690 690`: false, ``: false,
		`" 690"`: false, `"+690"`: false, `"0690"`: false,
	} {
		if got := scalarEqualsInt(json.RawMessage(raw), 690); got != want {
			t.Errorf("scalarEqualsInt(%q, 690) = %v, want %v", raw, got, want)
		}
	}
}

// A transport fault is Unverified AND actually arrived (instrument #7): the
// server dropped the connection, and the connection count proves the client did
// not silently retry its way to an answer.
func TestFreeProof_TransportFaultArrives(t *testing.T) {
	var conns, reqs atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	c := testClient(t, srv)
	r := c.FreeProof(context.Background(), 690)
	if r.State != VMIDUnverified || r.Detail == "" {
		t.Fatalf("transport reset: %+v", r)
	}
	if reqs.Load() < 1 {
		t.Fatal("the fault never arrived: the server saw no request")
	}
	// Assert the CONNECTION count as well as the request count: a transport that
	// silently retried on a fresh connection would hide the fault from the code
	// under test.
	if conns.Load() != reqs.Load() {
		t.Errorf("connections %d != requests %d: a request was retried or reused a connection", conns.Load(), reqs.Load())
	}
}

// A stalled read is bounded by the caller's context, and the deadline actually
// FIRED (the stall is far longer than the budget).
func TestFreeProof_StallIsBoundedByTheContext(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(30 * time.Second):
		case <-r.Context().Done():
		}
	})
	c := testClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := c.FreeProof(ctx, 690)
	if time.Since(start) > 10*time.Second {
		t.Fatal("the read was not bounded by the context")
	}
	if ctx.Err() == nil {
		t.Fatal("the deadline never fired: the stall measured nothing")
	}
	if r.State != VMIDUnverified {
		t.Fatalf("stalled read: state %d, want Unverified", r.State)
	}
}
