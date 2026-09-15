package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// clusterResourcesFixture is a fake /cluster/resources response body
// covering: a single-tag qemu match, a qemu resource whose tag is a
// superstring of the tag under test (must never substring-match), and an
// lxc resource sharing the same tag (must never count toward a match).
const clusterResourcesFixture = `{"data":[
	{"id":"qemu/100","type":"qemu","vmid":100,"node":"qa-pve-01","tags":"qng"},
	{"id":"qemu/101","type":"qemu","vmid":101,"node":"qa-pve-01","tags":"qng-template;other"},
	{"id":"lxc/200","type":"lxc","vmid":200,"node":"qa-pve-01","tags":"qng"}
]}`

func TestFindByTag_SingleMatch(t *testing.T) {
	var gotPath, gotQuery string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(clusterResourcesFixture))
	})
	c := testClient(t, srv)

	res, err := c.FindByTag(context.Background(), "qng")
	if err != nil {
		t.Fatalf("FindByTag: %v", err)
	}
	if res == nil || res.VMID != 100 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if gotPath != "/cluster/resources" {
		t.Fatalf("expected request to /cluster/resources, got %q", gotPath)
	}
	if gotQuery != "type=vm" {
		t.Fatalf("expected query type=vm, got %q", gotQuery)
	}
}

func TestFindByTag_NoMatch(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"tags":"other"}]}`))
	})
	c := testClient(t, srv)

	_, err := c.FindByTag(context.Background(), "qng")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestFindByTag_TwoMatches(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"id":"qemu/100","type":"qemu","vmid":100,"tags":"qng"},
			{"id":"qemu/101","type":"qemu","vmid":101,"tags":"qng"}
		]}`))
	})
	c := testClient(t, srv)

	_, err := c.FindByTag(context.Background(), "qng")
	if !errors.Is(err, ErrAmbiguousTag) {
		t.Fatalf("expected ErrAmbiguousTag, got: %v", err)
	}
	if !strings.Contains(err.Error(), "2 matches") {
		t.Fatalf("expected error message to contain the match count, got: %v", err)
	}
}

// TestFindByTag_ExactElementMatch_NotSubstring proves a resource tagged
// "qng-template;other" never matches a lookup for "qng" — only an exact
// semicolon-delimited element match counts. The fixture's only resource
// carrying anything resembling "qng" as a substring is that qemu/101
// resource and the lxc/200 resource (excluded by type below), so a lookup
// for "qng" must come back as zero matches.
func TestFindByTag_ExactElementMatch_NotSubstring(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"id":"qemu/101","type":"qemu","vmid":101,"tags":"qng-template;other"}
		]}`))
	})
	c := testClient(t, srv)

	_, err := c.FindByTag(context.Background(), "qng")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound (no exact-element match), got: %v", err)
	}
}

// TestFindByTag_ExcludesLXC proves an lxc-type resource sharing the exact
// same tag as a qemu resource is excluded entirely: it must not count
// toward a match, and its presence must not turn a single qemu match into
// an ambiguous one.
func TestFindByTag_ExcludesLXC(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(clusterResourcesFixture))
	})
	c := testClient(t, srv)

	res, err := c.FindByTag(context.Background(), "qng")
	if err != nil {
		t.Fatalf("FindByTag: %v", err)
	}
	if res.VMID != 100 {
		t.Fatalf("expected the qemu resource (vmid 100), got vmid %d", res.VMID)
	}
}

// TestFindByTag_RejectsInvalidTagBeforeTouchingClient mirrors
// TestVMTagEnsure_Apply_RejectsInvalidTagBeforeTouchingClient
// (internal/idempotent/vmtag_test.go): an invalid tag must be rejected
// before any network call reaches the server.
func TestFindByTag_RejectsInvalidTagBeforeTouchingClient(t *testing.T) {
	cases := []struct {
		name string
		tag  string
	}{
		{"empty tag", ""},
		{"tag containing the separator", "foo;bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				t.Error("should not reach the network for an invalid tag")
			})
			c := testClient(t, srv)

			_, err := c.FindByTag(context.Background(), tc.tag)
			if err == nil {
				t.Fatal("expected an error for an invalid tag")
			}
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrAmbiguousTag) {
				t.Fatal("an invalid tag must be a plain validation error, not one of the lookup-result sentinels")
			}
			if calls != 0 {
				t.Errorf("expected zero requests to reach the fake server, got %d", calls)
			}
		})
	}
}

// TestFindByTag_NeverCallsClusterStatus is the regression guard for the
// Cluster.New(c.pc) vs c.pc.Cluster(ctx) fix: the fake server must only
// ever see /cluster/resources requests, never a GET /cluster/status.
func TestFindByTag_NeverCallsClusterStatus(t *testing.T) {
	var seenPaths []string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.Path)
		if r.URL.Path == "/cluster/status" {
			t.Error("must never call GET /cluster/status")
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(clusterResourcesFixture))
	})
	c := testClient(t, srv)

	if _, err := c.FindByTag(context.Background(), "qng"); err != nil {
		t.Fatalf("FindByTag: %v", err)
	}
	if len(seenPaths) != 1 || seenPaths[0] != "/cluster/resources" {
		t.Fatalf("expected exactly one request to /cluster/resources, got: %v", seenPaths)
	}
}
