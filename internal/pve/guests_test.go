package pve

import (
	"errors"
	"testing"
)

// ParseClusterGuests decodes root's `pvesh get /cluster/resources --type vm`
// strictly: anything a healthy PVE does not print is an unverifiable read,
// never an empty or partial list.
func TestParseClusterGuests(t *testing.T) {
	good := `[{"id":"qemu/100","type":"qemu","vmid":100,"node":"n1","tags":"web;x"},` +
		`{"id":"lxc/200","type":"lxc","vmid":200,"node":"n1","tags":"db"},` +
		`{"id":"qemu/300","type":"qemu","vmid":300,"node":"n1"}]`
	guests, err := ParseClusterGuests([]byte(good))
	want := []Guest{{"qemu", 100, "web;x"}, {"lxc", 200, "db"}, {"qemu", 300, ""}}
	if err != nil || len(guests) != len(want) {
		t.Fatalf("ParseClusterGuests(good) = %+v, %v", guests, err)
	}
	for i := range want {
		if guests[i] != want[i] {
			t.Errorf("guest %d = %+v, want %+v", i, guests[i], want[i])
		}
	}
	if g, err := ParseClusterGuests([]byte(`[]`)); err != nil || len(g) != 0 {
		t.Errorf("an empty cluster: %+v, %v", g, err)
	}
	for name, bad := range map[string]string{
		"null":              `null`,
		"empty":             ``,
		"not json":          `pvesh: permission denied`,
		"an object":         `{"data":[]}`,
		"trailing data":     `[] []`,
		"a stray ]":         `[]]`,
		"a stray }":         `[{"type":"qemu","vmid":100}]}`,
		"trailing text":     `[] x`,
		"a null entry":      `[null]`,
		"no type":           `[{"vmid":100}]`,
		"a node":            `[{"type":"node","vmid":100}]`,
		"openvz":            `[{"type":"openvz","vmid":100}]`,
		"no vmid":           `[{"type":"qemu"}]`,
		"vmid a string":     `[{"type":"qemu","vmid":"100"}]`,
		"vmid fractional":   `[{"type":"qemu","vmid":100.5}]`,
		"vmid zero":         `[{"type":"qemu","vmid":0}]`,
		"tags not a string": `[{"type":"qemu","vmid":100,"tags":["x"]}]`,
		"tags null":         `[{"type":"qemu","vmid":100,"tags":null}]`,
	} {
		if g, err := ParseClusterGuests([]byte(bad)); !errors.Is(err, ErrUnverifiableRead) {
			t.Errorf("%s: %+v, %v; want ErrUnverifiableRead", name, g, err)
		}
	}
}

// FindGuestByTagFold counts VMs and containers, folds case, matches whole
// elements only, and splits on every separator PVE accepts.
func TestFindGuestByTagFold(t *testing.T) {
	guests := []Guest{
		{"qemu", 100, "web;foo"},
		{"lxc", 200, "Bar"},
		{"qemu", 300, "food;bar-x"},
		{"qemu", 400, "a, b c"},
		{"lxc", 500, "dup"},
		{"qemu", 600, "DUP"},
	}
	for _, c := range []struct {
		tag  string
		want int
	}{{"foo", 100}, {"FOO", 100}, {"bar", 200}, {"BAR", 200}, {"b", 400}, {"c", 400}} {
		g, err := FindGuestByTagFold(guests, c.tag)
		if err != nil || g.VMID != c.want {
			t.Errorf("FindGuestByTagFold(%q) = %+v, %v; want %d", c.tag, g, err, c.want)
		}
	}
	for _, tag := range []string{"fo", "bar-", "x", "web;foo"} {
		if _, err := FindGuestByTagFold(guests, tag); !errors.Is(err, ErrNotFound) {
			t.Errorf("FindGuestByTagFold(%q): %v, want ErrNotFound", tag, err)
		}
	}
	if _, err := FindGuestByTagFold(guests, "dup"); !errors.Is(err, ErrAmbiguousTag) {
		t.Errorf("a container and a VM both carrying dup: %v, want ErrAmbiguousTag", err)
	}
	if _, err := FindGuestByTagFold(guests, ""); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("an empty tag: %v, want a plain refusal", err)
	}
	if (Guest{Type: "lxc"}).Kind() != "ct" || (Guest{Type: "qemu"}).Kind() != "vm" {
		t.Error("Kind: want ct for lxc, vm for qemu")
	}
}
