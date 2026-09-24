package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Every reader that loops over a go-proxmox []*T list refuses a null
// element as an unverifiable read, naming its index, where it used to
// nil-dereference (a [null] list panicked ListNodes and FindByTag). A real
// entry before the null proves the guard looks past the first element.
func TestListReaders_NullEntryIsUnverifiable(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, first string
		call        func(*Client) error
	}{
		{"ListNodes", `{"node":"n1","status":"online"}`, func(c *Client) error { _, err := c.ListNodes(ctx); return err }},
		{"GetNodes", `{"node":"n1","status":"online"}`, func(c *Client) error { _, err := c.GetNodes(ctx); return err }},
		{"FindByTag", `{"type":"qemu","vmid":100,"tags":"other"}`, func(c *Client) error { _, err := c.FindByTag(ctx, "x"); return err }},
		{"TagStillClaimed", `{"type":"qemu","vmid":100,"tags":"other"}`, func(c *Client) error { _, err := c.TagStillClaimed(ctx, "x", 0); return err }},
		{"GetVMs", `{"vmid":100,"name":"a"}`, func(c *Client) error { _, err := c.GetVMs(ctx, "qa-pve-01"); return err }},
		{"GetStorages", `{"storage":"local","enabled":1}`, func(c *Client) error { _, err := c.GetStorages(ctx, "qa-pve-01"); return err }},
		{"GetStorageVolumes", `{"volid":"local:iso/a.iso"}`, func(c *Client) error {
			_, err := c.GetStorageVolumes(ctx, "qa-pve-01", "local")
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := `{"data":[` + c.first + `,null]}`
			srv := newFakeAPIServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			cl := testClient(t, srv)
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked: %v", r)
					}
				}()
				err = c.call(cl)
			}()
			if !errors.Is(err, ErrUnverifiableRead) || !strings.Contains(err.Error(), "entry 1 is null") {
				t.Fatalf("err = %v, want an unverifiable read naming entry 1", err)
			}
		})
	}
}

func TestNullEntry(t *testing.T) {
	a, b := 1, 2
	for _, c := range []struct {
		list []*int
		want int
	}{{nil, -1}, {[]*int{}, -1}, {[]*int{&a, &b}, -1}, {[]*int{nil}, 0}, {[]*int{&a, nil, &b}, 1}, {[]*int{&a, &b, nil}, 2}} {
		if got := nullEntry(c.list); got != c.want {
			t.Errorf("nullEntry(%v) = %d, want %d", c.list, got, c.want)
		}
	}
}
