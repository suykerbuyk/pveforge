package pve

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// This file is UNTAGGED on purpose: the config/snapshot volid reader and its
// parser (firstCommaVolid/allDigits/isDiskShapedKey, configVolids) now gate the
// claimed set on the destroy-time free path, so CI's `go test ./...` (no tags)
// must run their pins. Before the pveforge-claimed-volumes-snapshot-vmstate lift
// the only parser test lived behind //go:build harness and CI never ran it.

// --- parser pins --------------------------------------------------------

func TestFirstCommaVolid(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"local-lvm:vm-905-disk-0,size=32G", "local-lvm:vm-905-disk-0"},
		{"local-lvm:vm-905-state-snap1", "local-lvm:vm-905-state-snap1"},
		{"none", ""},
		{"/dev/sdb", ""},
		{"1", ""}, // a vmstate flag, not a volid
	} {
		if got := firstCommaVolid(tc.in); got != tc.want {
			t.Errorf("firstCommaVolid(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAllDigits(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"0", true}, {"30", true}, {"255", true},
		{"", false}, {"a", false}, {"1a", false}, {"fs0", false},
	} {
		if got := allDigits(tc.in); got != tc.want {
			t.Errorf("allDigits(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestIsDiskShapedKey pins the destroy-path key recognizer completely: all FIVE
// indexed disk families INCLUDED (not merely virtiofs0 excluded — virtio0 must
// be INCLUDED), both scalars, multi-digit indices, and the full SEVEN-family
// exclusion set plus the scsihw/virtiofs0 decoys.
func TestIsDiskShapedKey(t *testing.T) {
	included := []string{
		"ide0", "scsi0", "sata0", "virtio0", "unused0", // all five families
		"scsi30", "unused255", // multi-digit, beyond go-proxmox's explicit range
		"efidisk0", "tpmstate0", // the two scalars
	}
	for _, k := range included {
		if !isDiskShapedKey(k) {
			t.Errorf("isDiskShapedKey(%q) = false, want true (disk-bearing)", k)
		}
	}
	excluded := []string{
		"net0", "numa0", "hostpci0", "serial0", "usb0", "parallel0", "ipconfig0", // the seven
		"scsihw", "virtiofs0", // decoys: a prefix match without a trailing index
		"digest", "lock", "vmstate", "description",
	}
	for _, k := range excluded {
		if isDiskShapedKey(k) {
			t.Errorf("isDiskShapedKey(%q) = true, want false", k)
		}
	}
}

// --- configVolids strict (NEW-2) ----------------------------------------

func snapServer(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if body, ok := routes[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	})
	return testClient(t, srv)
}

// TestConfigVolids_StrictRefusesNonString (mutant 3): a disk-shaped or vmstate
// key present with a non-string value must REFUSE on the strict path, never
// silently drop — a dropped claim is a freed live volume.
func TestConfigVolids_StrictRefusesNonString(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"object slot", `{"data":{"digest":"d","scsi0":{"file":"x"}}}`},
		{"numeric vmstate", `{"data":{"digest":"d","scsi0":"s:vm-1-disk-0","vmstate":123}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := snapServer(t, map[string]string{"/nodes/n1/qemu/1/config": tc.body})
			_, err := c.configVolids(context.Background(), 1, "", "/nodes/n1/qemu/1/config", nil, true)
			if !errors.Is(err, ErrUnverifiableRead) {
				t.Fatalf("strict configVolids did not refuse a non-string key: err=%v", err)
			}
			// strict=false (harness) keeps the lenient skip: the non-string key is
			// dropped, every well-formed disk slot still parsed.
			cr, err := c.configVolids(context.Background(), 1, "", "/nodes/n1/qemu/1/config", nil, false)
			if err != nil {
				t.Fatalf("lenient configVolids errored: %v", err)
			}
			if tc.name == "numeric vmstate" {
				// scsi0 is a well-formed volid and must survive the lenient skip.
				if len(cr.volids) != 1 || cr.volids[0] != "s:vm-1-disk-0" {
					t.Errorf("lenient read dropped a well-formed slot: volids=%v", cr.volids)
				}
				if cr.vmstate != "" {
					t.Errorf("non-string vmstate must not populate cr.vmstate, got %q", cr.vmstate)
				}
			}
		})
	}
}

// --- ClaimedVolumes red-first cases -------------------------------------

// liveOnly builds the routes for a VM with a live config and no real snapshots.
func liveOnly(vmid string, liveConfig string) map[string]string {
	return map[string]string{
		"/nodes/n1/qemu/" + vmid + "/config":   liveConfig,
		"/nodes/n1/qemu/" + vmid + "/snapshot": `{"data":[{"name":"current"}]}`,
	}
}

// case 1 + the headline completeness mutant (6): a volid referenced ONLY by a
// snapshot section is CLAIMED. Mutant (revert to live-config-only parse) reds this.
func TestClaimedVolumes_SnapshotDiskSlotClaimed(t *testing.T) {
	routes := map[string]string{
		"/nodes/n1/qemu/1/config":                `{"data":{"digest":"d","scsi0":"local-lvm:vm-1-disk-0,size=8G"}}`,
		"/nodes/n1/qemu/1/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":0}]}`,
		"/nodes/n1/qemu/1/snapshot/snap1/config": `{"data":{"scsi0":"local-lvm:vm-1-disk-0,size=8G","scsi1":"local-lvm:vm-1-disk-9,size=4G"}}`,
	}
	claimed, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 1)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}
	if !claimed["local-lvm:vm-1-disk-9"] {
		t.Errorf("snapshot-only disk vm-1-disk-9 was not claimed: %v", claimed)
	}
}

// case 2: a snapshot's vmstate volid is CLAIMED (list vmstate:1, section carries it).
func TestClaimedVolumes_SnapshotVmstateClaimed(t *testing.T) {
	routes := map[string]string{
		"/nodes/n1/qemu/2/config":                `{"data":{"digest":"d","scsi0":"local-lvm:vm-2-disk-0,size=8G"}}`,
		"/nodes/n1/qemu/2/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":1}]}`,
		"/nodes/n1/qemu/2/snapshot/snap1/config": `{"data":{"scsi0":"local-lvm:vm-2-disk-0,size=8G","vmstate":"local-lvm:vm-2-state-snap1"}}`,
	}
	claimed, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 2)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}
	if !claimed["local-lvm:vm-2-state-snap1"] {
		t.Errorf("snapshot vmstate volid not claimed: %v", claimed)
	}
}

// mutant 2 / NEW-13: list reports vmstate!=0 but the section carries no vmstate
// volid (missing key, or a non-volid flag) ⇒ REFUSE.
func TestClaimedVolumes_SnapshotVmstateOracleRefuses(t *testing.T) {
	for _, tc := range []struct{ name, section string }{
		{"no vmstate key", `{"data":{"scsi0":"local-lvm:vm-3-disk-0,size=8G"}}`},
		{"non-volid flag", `{"data":{"scsi0":"local-lvm:vm-3-disk-0,size=8G","vmstate":"1"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{
				"/nodes/n1/qemu/3/config":                `{"data":{"digest":"d","scsi0":"local-lvm:vm-3-disk-0,size=8G"}}`,
				"/nodes/n1/qemu/3/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":1}]}`,
				"/nodes/n1/qemu/3/snapshot/snap1/config": tc.section,
			}
			_, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 3)
			if !errors.Is(err, ErrUnverifiableRead) {
				t.Fatalf("expected refusal when list asserts vmstate but section has no volid, got %v", err)
			}
			if !strings.Contains(err.Error(), "3") {
				t.Errorf("error does not name the vmid: %v", err)
			}
		})
	}
}

// mutant 4 / NEW-9: a non-empty metadata-only diskless snapshot (list vmstate:0)
// is ACCEPTED (zero volids); an empty {} section is REFUSED.
func TestClaimedVolumes_SnapshotShapeGuard(t *testing.T) {
	t.Run("diskless metadata-only accepted", func(t *testing.T) {
		routes := map[string]string{
			"/nodes/n1/qemu/4/config":                `{"data":{"digest":"d"}}`,
			"/nodes/n1/qemu/4/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":0}]}`,
			"/nodes/n1/qemu/4/snapshot/snap1/config": `{"data":{"description":"x","parent":"snap0","cores":4,"memory":8192,"name":"snap1"}}`,
		}
		claimed, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 4)
		if err != nil {
			t.Fatalf("a diskless metadata-only snapshot must be accepted, got %v", err)
		}
		if len(claimed) != 0 {
			t.Errorf("expected zero claimed volids, got %v", claimed)
		}
	})
	t.Run("empty object refused", func(t *testing.T) {
		routes := map[string]string{
			"/nodes/n1/qemu/4/config":                `{"data":{"digest":"d"}}`,
			"/nodes/n1/qemu/4/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":0}]}`,
			"/nodes/n1/qemu/4/snapshot/snap1/config": `{"data":{}}`,
		}
		_, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 4)
		if !errors.Is(err, ErrUnverifiableRead) {
			t.Fatalf("an empty {} snapshot config must be refused, got %v", err)
		}
	})
}

// mutant 1 / 3.2: the live hibernated-vmstate backstop across the suspend family.
func TestClaimedVolumes_HibernatedVmstateBackstop(t *testing.T) {
	// suspended + real state volid → CLAIMED.
	t.Run("suspended with state volid claimed", func(t *testing.T) {
		c := snapServer(t, liveOnly("5", `{"data":{"digest":"d","lock":"suspended","scsi0":"local-lvm:vm-5-disk-0","vmstate":"local-lvm:vm-5-state-suspend-0"}}`))
		claimed, err := c.ClaimedVolumes(context.Background(), "n1", 5)
		if err != nil {
			t.Fatalf("ClaimedVolumes: %v", err)
		}
		if !claimed["local-lvm:vm-5-state-suspend-0"] {
			t.Errorf("hibernated resume-state volume not claimed: %v", claimed)
		}
	})
	// BOTH suspend-family lock values, each with a missing/non-volid vmstate → REFUSE.
	for _, lock := range []string{"suspended", "suspending"} {
		for _, vm := range []struct{ name, kv string }{
			{"no vmstate", ""},
			{"flag vmstate", `,"vmstate":"1"`},
		} {
			t.Run(lock+"/"+vm.name, func(t *testing.T) {
				body := `{"data":{"digest":"d","lock":"` + lock + `","scsi0":"local-lvm:vm-6-disk-0"` + vm.kv + `}}`
				c := snapServer(t, liveOnly("6", body))
				_, err := c.ClaimedVolumes(context.Background(), "n1", 6)
				if !errors.Is(err, ErrUnverifiableRead) {
					t.Fatalf("lock %q + no vmstate volid must refuse, got %v", lock, err)
				}
			})
		}
	}
	// A non-suspend lock with no vmstate is a NORMAL VM → ACCEPT (no false-refusal).
	t.Run("non-suspend lock accepted", func(t *testing.T) {
		c := snapServer(t, liveOnly("7", `{"data":{"digest":"d","lock":"backup","scsi0":"local-lvm:vm-7-disk-0"}}`))
		if _, err := c.ClaimedVolumes(context.Background(), "n1", 7); err != nil {
			t.Errorf("a non-suspend lock must not false-refuse, got %v", err)
		}
	})
}

// case 9: a live config with no digest (200 {}) is refused.
func TestClaimedVolumes_LiveConfigNoDigestRefused(t *testing.T) {
	c := snapServer(t, map[string]string{"/nodes/n1/qemu/8/config": `{"data":{"scsi0":"local-lvm:vm-8-disk-0"}}`})
	_, err := c.ClaimedVolumes(context.Background(), "n1", 8)
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("a live config with no digest must be refused, got %v", err)
	}
}

// F3: the live read is pending ∪ current=1. This fake DIFFERS by the current=1
// query: vm-9-disk-pending appears only in the default (pending) view, and
// vm-9-disk-current appears only under ?current=1. Both must be claimed. A
// mutant that discards the current=1 volids (or never issues the second read)
// reds this — which newFakeAPIServer/routeServer cannot catch, as they drop the
// query string from their route key.
func TestClaimedVolumes_PendingUnionCurrent(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/nodes/n1/qemu/9/config":
			if r.URL.Query().Get("current") == "1" {
				_, _ = w.Write([]byte(`{"data":{"digest":"d","scsi0":"local-lvm:vm-9-disk-current,size=8G"}}`))
			} else {
				_, _ = w.Write([]byte(`{"data":{"digest":"d","scsi0":"local-lvm:vm-9-disk-pending,size=8G"}}`))
			}
		case "/nodes/n1/qemu/9/snapshot":
			_, _ = w.Write([]byte(`{"data":[{"name":"current"}]}`))
		default:
			http.NotFound(w, r)
		}
	})
	claimed, err := testClient(t, srv).ClaimedVolumes(context.Background(), "n1", 9)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}
	for _, want := range []string{"local-lvm:vm-9-disk-pending", "local-lvm:vm-9-disk-current"} {
		if !claimed[want] {
			t.Errorf("union of pending ∪ current=1 missing %q: %v", want, claimed)
		}
	}
}

// F4: a disk referenced ONLY by an OLDER snapshot (snap0), absent from the live
// config and from the newer snap1, must be claimed. The "newest-snapshot-only"
// mutant (read only the last/parent-head snapshot) reds this.
func TestClaimedVolumes_DetachedDiskOnlyInOlderSnapshot(t *testing.T) {
	routes := map[string]string{
		"/nodes/n1/qemu/10/config":                `{"data":{"digest":"d","scsi0":"local-lvm:vm-10-disk-0,size=8G"}}`,
		"/nodes/n1/qemu/10/snapshot":              `{"data":[{"name":"current"},{"name":"snap0","vmstate":0},{"name":"snap1","vmstate":0}]}`,
		"/nodes/n1/qemu/10/snapshot/snap0/config": `{"data":{"scsi0":"local-lvm:vm-10-disk-0,size=8G","scsi1":"local-lvm:vm-10-disk-7,size=4G"}}`,
		"/nodes/n1/qemu/10/snapshot/snap1/config": `{"data":{"scsi0":"local-lvm:vm-10-disk-0,size=8G"}}`,
	}
	claimed, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 10)
	if err != nil {
		t.Fatalf("ClaimedVolumes: %v", err)
	}
	if !claimed["local-lvm:vm-10-disk-7"] {
		t.Errorf("disk referenced only by the older snapshot not claimed: %v", claimed)
	}
}

// F5: a non-string value on a SNAPSHOT disk/vmstate key must REFUSE on the
// strict (claimed) path. The continue-instead-of-refuse mutant reds this.
func TestClaimedVolumes_SnapshotNonStringRefused(t *testing.T) {
	for _, tc := range []struct{ name, section string }{
		{"object disk slot", `{"data":{"scsi0":{"file":"x"}}}`},
		{"numeric vmstate", `{"data":{"scsi0":"local-lvm:vm-11-disk-0","vmstate":123}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]string{
				"/nodes/n1/qemu/11/config":                `{"data":{"digest":"d","scsi0":"local-lvm:vm-11-disk-0,size=8G"}}`,
				"/nodes/n1/qemu/11/snapshot":              `{"data":[{"name":"current"},{"name":"snap1","vmstate":0}]}`,
				"/nodes/n1/qemu/11/snapshot/snap1/config": tc.section,
			}
			_, err := snapServer(t, routes).ClaimedVolumes(context.Background(), "n1", 11)
			if !errors.Is(err, ErrUnverifiableRead) {
				t.Fatalf("a non-string snapshot key must refuse on the strict path, got %v", err)
			}
		})
	}
}

// F2: a present-but-non-string lock on the LIVE config must REFUSE (else the
// suspend backstop never sees it and fails open). The swallow mutant reds this.
func TestClaimedVolumes_NonStringLockRefused(t *testing.T) {
	c := snapServer(t, map[string]string{
		"/nodes/n1/qemu/12/config":   `{"data":{"digest":"d","lock":1,"scsi0":"local-lvm:vm-12-disk-0"}}`,
		"/nodes/n1/qemu/12/snapshot": `{"data":[{"name":"current"}]}`,
	})
	_, err := c.ClaimedVolumes(context.Background(), "n1", 12)
	if !errors.Is(err, ErrUnverifiableRead) {
		t.Fatalf("a non-string lock must be refused, got %v", err)
	}
}
