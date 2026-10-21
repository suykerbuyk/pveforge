package outer

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRequireStorage(t *testing.T) {
	for _, ok := range []string{"pveforge-harness", "local-zfs", "a1"} {
		if _, err := RequireStorage(ok); err != nil {
			t.Errorf("RequireStorage(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "X", "a_", "ab*"} {
		if _, err := RequireStorage(bad); err == nil {
			t.Errorf("RequireStorage(%q) = nil, want error", bad)
		}
	}
}

func TestParseStorageStatus_RawDecode(t *testing.T) {
	// Boolean enabled/active must be accepted (proxmox.Storage rejects them).
	st, err := ParseStorageStatus(json.RawMessage(`{"type":"zfspool","enabled":true,"active":true,"content":"images,rootdir","avail":644245094400,"used":0}`))
	if err != nil {
		t.Fatalf("boolean enabled/active: %v", err)
	}
	if !st.Enabled || !st.Active || st.Type != "zfspool" || st.Avail == 0 || !st.HasUsed {
		t.Errorf("parsed = %+v", st)
	}
	// Numeric 1/1 also accepted.
	if st, err := ParseStorageStatus(json.RawMessage(`{"type":"zfspool","enabled":1,"active":1,"content":"images","avail":1}`)); err != nil || !st.Enabled || !st.Active {
		t.Errorf("numeric enabled = %+v err %v", st, err)
	}
	// A FRACTIONAL used is NOT a usable integer (not truncated, as
	// proxmox.Storage would): HasUsed stays false, and BaselineUsed then
	// refuses "no usable 'used'" — matching lib.sh's _harness_used.
	if st, err := ParseStorageStatus(json.RawMessage(`{"type":"zfspool","content":"images","avail":1,"used":1.5}`)); err != nil || st.HasUsed {
		t.Errorf("fractional used: st=%+v err=%v, want parsed with HasUsed=false", st, err)
	} else if _, berr := BaselineUsed(st, "s"); berr == nil {
		t.Errorf("fractional used accepted as a baseline")
	}
	// Missing avail → shape error.
	if _, err := ParseStorageStatus(json.RawMessage(`{"type":"zfspool","content":"images"}`)); err == nil {
		t.Errorf("missing avail accepted")
	}
}

func TestStorageUnsuitable(t *testing.T) {
	ok := StorageStatus{Type: "zfspool", Enabled: true, Active: true, Content: "images,rootdir", Avail: 600 * gib}
	if r := ok.Unsuitable(520); r != "" {
		t.Errorf("suitable storage refused: %q", r)
	}
	cases := []struct {
		name string
		st   StorageStatus
		want string
	}{
		{"not enabled", StorageStatus{Type: "zfspool", Active: true, Content: "images", Avail: 600 * gib}, "not enabled"},
		{"not active", StorageStatus{Type: "zfspool", Enabled: true, Content: "images", Avail: 600 * gib}, "not active"},
		{"no images", StorageStatus{Type: "zfspool", Enabled: true, Active: true, Content: "rootdir,iso", Avail: 600 * gib}, "does not include images"},
		{"imagesx element not substring", StorageStatus{Type: "zfspool", Enabled: true, Active: true, Content: "imagesx", Avail: 600 * gib}, "does not include images"},
		{"lvmthin by name", StorageStatus{Type: "lvmthin", Enabled: true, Active: true, Content: "images", Avail: 600 * gib}, "type lvmthin is not supported"},
		{"dir by name", StorageStatus{Type: "dir", Enabled: true, Active: true, Content: "images", Avail: 600 * gib}, "type dir cannot hold the harness"},
		{"too little space", StorageStatus{Type: "zfspool", Enabled: true, Active: true, Content: "images", Avail: 519 * gib}, "519 GiB free, below HARNESS_PROBE_MIN_FREE_GIB=520"},
	}
	for _, c := range cases {
		if r := c.st.Unsuitable(520); !strings.Contains(r, c.want) {
			t.Errorf("%s: Unsuitable = %q, want containing %q", c.name, r, c.want)
		}
	}
}

func TestBaselineUsed(t *testing.T) {
	if _, err := BaselineUsed(StorageStatus{HasUsed: true, Used: 0}, "s"); err != nil {
		t.Errorf("empty storage refused: %v", err)
	}
	if _, err := BaselineUsed(StorageStatus{HasUsed: true, Used: StorageSlack}, "s"); err != nil {
		t.Errorf("at-slack storage refused: %v", err)
	}
	if _, err := BaselineUsed(StorageStatus{HasUsed: true, Used: StorageSlack + 1}, "s"); err == nil {
		t.Errorf("above-slack storage accepted as a baseline")
	}
	if _, err := BaselineUsed(StorageStatus{HasUsed: false}, "s"); err == nil {
		t.Errorf("no-used storage accepted")
	}
}

// storageFake serves /status and /content for StorageLeftover tests.
type storageFake struct {
	used        string // the `used` JSON token for status (empty = unreadable)
	contentHits int    // how many content reads returned a non-empty array before going empty
	calls       int
}

func (f *storageFake) RawRequest(_ context.Context, _, path string, _ url.Values) (json.RawMessage, error) {
	if strings.HasSuffix(path, "/status") {
		f.calls++
		if f.used == "" {
			return nil, context.DeadlineExceeded // unreadable
		}
		return json.RawMessage(`{"type":"zfspool","content":"images","avail":1,"used":` + f.used + `}`), nil
	}
	if strings.HasSuffix(path, "/content") {
		if f.contentHits > 0 {
			f.contentHits--
			return json.RawMessage(`[{"volid":"s:vm-690-disk-0"}]`), nil
		}
		return json.RawMessage(`[]`), nil
	}
	return json.RawMessage(`null`), nil
}

func TestStorageLeftover(t *testing.T) {
	// B2: the bound/poll are per-call now (no package-global seam). Short bounds
	// keep the "never clears" cases fast.
	const b, p = 30 * time.Millisecond, 5 * time.Millisecond
	// Back at baseline, nothing listed → not a leftover.
	if lo, _ := StorageLeftover(context.Background(), &storageFake{used: "0"}, "n", "s", 0, []int{690}, b, p); lo {
		t.Error("clean storage reported a leftover")
	}
	// used stays above baseline+slack → leftover detected after the bound.
	if lo, reason := StorageLeftover(context.Background(), &storageFake{used: "999999999"}, "n", "s", 0, []int{690}, b, p); !lo || !strings.Contains(reason, "not back within") {
		t.Errorf("high-used not detected: lo=%v reason=%q", lo, reason)
	}
	// A volume still listed → leftover detected.
	if lo, reason := StorageLeftover(context.Background(), &storageFake{used: "0", contentHits: 100}, "n", "s", 0, []int{690}, b, p); !lo || !strings.Contains(reason, "still lists volumes") {
		t.Errorf("listed volume not detected: lo=%v reason=%q", lo, reason)
	}
	// Unreadable status detects NOTHING (never a failure) — PollIsBounded.
	if lo, _ := StorageLeftover(context.Background(), &storageFake{used: ""}, "n", "s", 0, []int{690}, b, p); lo {
		t.Error("unreadable status reported a leftover")
	}
	// bound=0 → one read, no wait (the build's secs=0 case).
	if lo, reason := StorageLeftover(context.Background(), &storageFake{used: "0", contentHits: 100}, "n", "s", 0, []int{690}, 0, p); !lo || !strings.Contains(reason, "still lists volumes") {
		t.Errorf("bound=0 one-read leftover not detected: lo=%v reason=%q", lo, reason)
	}
}
