package pve

import (
	"errors"
	"testing"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// TestIsStorageNotFoundError pins the classifier (M1): it is true ONLY for a
// typed PVE answer whose errors.storage entry is exactly "No such storage."
// (case-insensitive, optional trailing period) — never a whole-answer
// substring. Widening the needle in IsStorageNotFoundError (e.g. to "storage")
// turns the non-absence rows red.
func TestIsStorageNotFoundError(t *testing.T) {
	notFoundBody := []byte(`{"data":null,"errors":{"storage":"No such storage."}}`)

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "typed pve.StatusError 400, errors.storage = No such storage.",
			err:  NewStatusError("get storage config", 400, "400 Parameter verification failed.", notFoundBody),
			want: true,
		},
		{
			name: "typed proxmox.StatusError, same body",
			err:  &proxmox.StatusError{StatusCode: 400, Status: "400 Parameter verification failed.", Body: notFoundBody},
			want: true,
		},
		{
			// The CONFIG endpoint GET /storage/{id} shape, observed live on
			// qa-pve-07 2026-10-24: HTTP 500 carrying "storage '<id>' does not
			// exist" in the status line. This is the shape StorageCreate.Read
			// actually hits (go-proxmox c.pc.Get -> *proxmox.StatusError).
			name: "config endpoint 500, message in the status line (proxmox.StatusError)",
			err:  &proxmox.StatusError{StatusCode: 500, Status: "500 storage 'pveforge-harness' does not exist", Body: []byte(`{"data":null}`)},
			want: true,
		},
		{
			// Robustness: same message carried in the BODY instead of the status
			// line (e.g. if a transport erases the reason phrase). pveAnswer
			// concatenates status and body, so the matcher still fires.
			name: "config endpoint 500, message in the body (pve.StatusError)",
			err:  NewStatusError("get storage config", 500, "500 Internal Server Error", []byte(`storage 'pveforge-harness' does not exist`)),
			want: true,
		},
		{
			name: "unrelated 500 'user does not exist' is NOT storage-not-found",
			err:  NewStatusError("some call", 500, "500 user 'ops@pve' does not exist", []byte(`{"data":null}`)),
			want: false,
		},
		{
			name: "untyped error carrying the phrase",
			err:  errors.New("No such storage."),
			want: false,
		},
		{
			name: "typed 500 duplicate (already defined) is not absent",
			err:  NewStatusError("create storage", 500, "500 Internal Server Error", []byte(`storage ID 'x' already defined`)),
			want: false,
		},
		{
			name: "typed 500 whose prose merely contains the phrase, no errors map",
			err:  NewStatusError("create storage", 500, "500 Internal Server Error", []byte(`permission denied: no such storage pool 'tank'`)),
			want: false,
		},
		{
			name: "typed 400 errors.storage says 'no such storage pool', not the bare absence phrase",
			err:  NewStatusError("get storage config", 400, "400 Parameter verification failed.", []byte(`{"errors":{"storage":"No such storage pool 'tank'"}}`)),
			want: false,
		},
		{
			name: "typed 403 privilege denial is ErrNotAuthorized, not storage-not-found",
			err:  NewStatusError("create storage", 403, "403 Forbidden", []byte(`Permission check failed (/storage, Datastore.Allocate)`)),
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsStorageNotFoundError(c.err); got != c.want {
				t.Errorf("IsStorageNotFoundError = %v, want %v", got, c.want)
			}
		})
	}

	// The 403 row must also stay classified as a privilege failure, so a
	// permission error can never take the create's "absent" branch.
	forbidden := NewStatusError("create storage", 403, "403 Forbidden", []byte(`Permission check failed (/storage, Datastore.Allocate)`))
	if !errors.Is(forbidden, ErrNotAuthorized) {
		t.Error("a 403 must satisfy errors.Is(ErrNotAuthorized)")
	}
	if IsStorageNotFoundError(forbidden) {
		t.Error("a 403 must NOT be classified as storage-not-found")
	}
}
