package pve

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// TestRoutedForwarding_CanAuditAllVMs: the pass-through asks PVE for the
// token's rights at exactly /vms, and reads only VM.Audit held WITH
// propagate as "can see every VM": without propagate, absent, or on some
// other path it is false, and a failed read is an error, never an answer.
func TestRoutedForwarding_CanAuditAllVMs(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   bool
		err    bool
	}{
		"propagated":     {200, `{"/vms":{"VM.Audit":1,"VM.Console":1}}`, true, false},
		"not propagated": {200, `{"/vms":{"VM.Audit":0}}`, false, false},
		"absent":         {200, `{"/vms":{"VM.Console":1}}`, false, false},
		"no rights":      {200, `{"/vms":{}}`, false, false},
		"other path":     {200, `{"/pool/p":{"VM.Audit":1}}`, false, true},
		"read fails":     {500, ``, false, true},
		"404":            {404, ``, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 200 {
					w.WriteHeader(tc.status)
					return
				}
				writeData(w, tc.body)
			})
			got, err := fwdClient(t, srv).CanAuditAllVMs(context.Background())
			if (err != nil) != tc.err || got != tc.want {
				t.Errorf("CanAuditAllVMs = %v, %v; want %v, error %v", got, err, tc.want, tc.err)
			}
			assertRequests(t, rec.got(), "GET /access/permissions?path=%2Fvms")
		})
	}
}

// TestRoutedForwarding_FindByTagFold: the pass-through, and the fold
// itself. PVE matches tags case-insensitively by default, so "FOO" finds a
// VM tagged "Foo", and "Foo" beside "foo" is ambiguous; FindByTag stays
// exact. Still an element match (never a substring) and QEMU only.
func TestRoutedForwarding_FindByTagFold(t *testing.T) {
	srv, rec := newFwdServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeData(w, `[`+
			`{"id":"qemu/4242","type":"qemu","vmid":4242,"tags":"web;Foo"},`+
			`{"id":"qemu/5151","type":"qemu","vmid":5151,"tags":"bar;FOOD"},`+
			`{"id":"qemu/6161","type":"qemu","vmid":6161,"tags":"Dup"},`+
			`{"id":"qemu/6262","type":"qemu","vmid":6262,"tags":"dup"},`+
			`{"id":"lxc/300","type":"lxc","vmid":300,"tags":"foo"}]`)
	})
	rc := fwdClient(t, srv)
	ctx := context.Background()
	for _, tag := range []string{"foo", "FOO", "Foo"} {
		res, err := rc.FindByTagFold(ctx, tag)
		if err != nil || res.VMID != 4242 {
			t.Errorf("FindByTagFold(%q) = %+v, %v; want vmid 4242", tag, res, err)
		}
	}
	if _, err := rc.FindByTagFold(ctx, "dup"); !errors.Is(err, ErrAmbiguousTag) {
		t.Errorf("FindByTagFold(dup): %v, want ErrAmbiguousTag", err)
	}
	if _, err := rc.FindByTag(ctx, "foo"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByTag(foo): %v, want ErrNotFound: FindByTag stays case-sensitive", err)
	}
	const listing = "GET /cluster/resources?type=vm"
	assertRequests(t, rec.got(), listing, listing, listing, listing, listing)
}
