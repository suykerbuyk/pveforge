package outer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeReader is the in-package fake PVE client the core's tests use instead
// of pve's network/TLS harness. Each field is the UNWRAPPED data a GET of
// that endpoint returns (RawRequest unwraps PVE's {"data":…} envelope), or
// an error to inject. Reads are asserted through it so a re-keyed fake
// cannot silently disable assertions (hazard #13).
type fakeReader struct {
	pool      string
	poolErr   error
	config    string
	configErr error
	nextid    string
	nextidErr error
	task      string
	taskErr   error
}

func (f *fakeReader) RawRequest(_ context.Context, method, path string, _ url.Values) (json.RawMessage, error) {
	switch {
	case method == "GET" && strings.Contains(path, "/pools"):
		return json.RawMessage(f.pool), f.poolErr
	case method == "GET" && strings.HasSuffix(path, "/config"):
		return json.RawMessage(f.config), f.configErr
	case method == "GET" && strings.Contains(path, "/cluster/nextid"):
		return json.RawMessage(f.nextid), f.nextidErr
	case method == "GET" && strings.Contains(path, "/tasks/") && strings.HasSuffix(path, "/status"):
		return json.RawMessage(f.task), f.taskErr
	}
	return nil, fmt.Errorf("fakeReader: unexpected %s %s", method, path)
}

var testCfg = Config{Pool: "pveforge-harness", Node: "qa-pve-02", Tag: "pveforge-harness"}

func validUPID(vmid int) string {
	return fmt.Sprintf("UPID:qa-pve-02:00001234:0000ABCD:5F000000:qmdestroy:%d:root@pam:", vmid)
}

func taskBody(upid, typ, id, node, status, exit string) string {
	return fmt.Sprintf(`{"upid":%q,"type":%q,"id":%q,"node":%q,"status":%q,"exitstatus":%q}`, upid, typ, id, node, status, exit)
}

func TestValidVMID(t *testing.T) {
	for _, v := range []int{690, 695, 699} {
		if !ValidVMID(v) {
			t.Errorf("ValidVMID(%d) = false, want true", v)
		}
	}
	for _, v := range []int{689, 700, 0, 100} {
		if ValidVMID(v) {
			t.Errorf("ValidVMID(%d) = true, want false", v)
		}
	}
}

func TestTagsHave(t *testing.T) {
	tag := "pveforge-harness"
	cases := []struct {
		tags string
		want bool
	}{
		{"pveforge-harness", true},
		{"a;pveforge-harness;b", true},
		{"a,pveforge-harness,b", true},
		{"a pveforge-harness b", true},
		{"a\x00pveforge-harness\x00b", true}, // NUL-delimited
		{"pveforge-harness-extra", false},    // substring, not a part
		{"other", false},
		{"", false},
		{"a\x00other\x00b", false}, // NUL split, tag absent
	}
	for _, c := range cases {
		if got := tagsHave(c.tags, tag); got != c.want {
			t.Errorf("tagsHave(%q) = %v, want %v", c.tags, got, c.want)
		}
	}
}

func TestValidSnapshotNameAndAllowedField(t *testing.T) {
	for _, n := range []string{"s1", "Golden", "a_b-c"} {
		if !ValidSnapshotName(n) {
			t.Errorf("ValidSnapshotName(%q) = false", n)
		}
	}
	for _, n := range []string{"1s", "-s", "s/x", "current ", ""} {
		if ValidSnapshotName(n) {
			t.Errorf("ValidSnapshotName(%q) = true", n)
		}
	}
	for _, ok := range [][2]string{{"snapshot", "vmstate"}, {"shutdown", "forceStop"}, {"destroy", "purge"}, {"destroy", "destroy-unreferenced-disks"}} {
		if !AllowedField(ok[0], ok[1]) {
			t.Errorf("AllowedField(%q,%q) = false", ok[0], ok[1])
		}
	}
	for _, bad := range [][2]string{{"snapshot", "name"}, {"create", "vmid"}, {"stop", "forceStop"}, {"destroy", "config"}} {
		if AllowedField(bad[0], bad[1]) {
			t.Errorf("AllowedField(%q,%q) = true", bad[0], bad[1])
		}
	}
}

func TestScalarEqualsInt(t *testing.T) {
	cases := []struct {
		raw  string
		n    int
		want bool
	}{
		{`690`, 690, true},   // number
		{`"690"`, 690, true}, // string decimal (lib.sh accepts both)
		{`691`, 690, false},
		{`"691"`, 690, false},
		{`"not-690"`, 690, false}, // the S2 danger: any-string must NOT pass
		{`""`, 690, false},
		{`{"x":690}`, 690, false},
		{`[690]`, 690, false},
		// C4: lib.sh:585's `jq -s 'length == 1'` — trailing data is NOT one scalar.
		{"690\n\"691\"", 690, false},
		{"690 \"extra\"", 690, false},
		{"690 691", 690, false},
	}
	for _, c := range cases {
		if got := scalarEqualsInt(json.RawMessage(c.raw), c.n); got != c.want {
			t.Errorf("scalarEqualsInt(%s,%d) = %v, want %v", c.raw, c.n, got, c.want)
		}
	}
}

func TestLedger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "created")
	l := OpenLedger(path)

	// Missing file is "nothing recorded", not an error.
	if has, err := l.Has(690); err != nil || has {
		t.Fatalf("Has on missing = (%v,%v), want (false,nil)", has, err)
	}
	if err := l.Add(690); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(692); err != nil {
		t.Fatal(err)
	}
	if has, _ := l.Has(690); !has {
		t.Error("690 not recorded")
	}
	if has, _ := l.Has(691); has {
		t.Error("691 falsely recorded")
	}
	// Exact whole-line match: 69 must not match 690.
	if has, _ := l.Has(69); has {
		t.Error("69 matched a 690 line (not a whole-line match)")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "690\n692\n" {
		t.Errorf("ledger body = %q", string(b))
	}
}

func TestGuard_PassesAndRefuses(t *testing.T) {
	poolOK := `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-02"}]}]`
	confOK := `{"tags":"pveforge-harness"}`

	// Positive control: every leg passes.
	r := &fakeReader{pool: poolOK, config: confOK}
	if err := Guard(context.Background(), r, testCfg, nil, 690, ModeChange); err != nil {
		t.Fatalf("guard should pass: %v", err)
	}

	cases := []struct {
		name string
		r    *fakeReader
		want string
	}{
		{"not a qemu member", &fakeReader{pool: `[{"poolid":"pveforge-harness","members":[{"type":"lxc","vmid":690,"node":"qa-pve-02"}]}]`, config: confOK}, "not a qemu member"},
		{"wrong node", &fakeReader{pool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-03"}]}]`, config: confOK}, "is on node qa-pve-03"},
		{"missing tag", &fakeReader{pool: poolOK, config: `{"tags":"other"}`}, "does not carry tag"},
		{"string vmid member is not a numeric qemu match", &fakeReader{pool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":"690","node":"qa-pve-02"}]}]`, config: confOK}, "not a qemu member"},
		{"wrong pool shape", &fakeReader{pool: `[]`, config: confOK}, "unexpected shape"},
	}
	for _, c := range cases {
		err := Guard(context.Background(), c.r, testCfg, nil, 690, ModeChange)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}

	// ModeDestroy needs the ledger.
	dir := t.TempDir()
	led := OpenLedger(filepath.Join(dir, "created"))
	if err := Guard(context.Background(), r, testCfg, led, 690, ModeDestroy); err == nil || !strings.Contains(err.Error(), "was not created by this run") {
		t.Errorf("destroy without ledger entry = %v, want created-by-run refusal", err)
	}
	_ = led.Add(690)
	if err := Guard(context.Background(), r, testCfg, led, 690, ModeDestroy); err != nil {
		t.Errorf("destroy with ledger entry should pass: %v", err)
	}
}

func TestDestroyTaskOK_BodyReassert(t *testing.T) {
	upid := validUPID(690)
	// Positive control.
	r := &fakeReader{task: taskBody(upid, "qmdestroy", "690", "qa-pve-02", "stopped", "OK")}
	if err := DestroyTaskOK(context.Background(), r, testCfg, 690, upid); err != nil {
		t.Fatalf("should pass: %v", err)
	}
	// WARNINGS is not OK (a disk the worker could not free).
	r = &fakeReader{task: taskBody(upid, "qmdestroy", "690", "qa-pve-02", "stopped", "WARNINGS: 1")}
	if err := DestroyTaskOK(context.Background(), r, testCfg, 690, upid); err == nil {
		t.Error("WARNINGS task accepted as OK")
	}
	// S1: UPID string parses fine, but the BODY names a different id.
	r = &fakeReader{task: taskBody(upid, "qmdestroy", "691", "qa-pve-02", "stopped", "OK")}
	if err := DestroyTaskOK(context.Background(), r, testCfg, 690, upid); err == nil {
		t.Error("status body with mismatched id accepted")
	}
	// UPID string itself names the wrong type.
	badUPID := "UPID:qa-pve-02:00001234:0000ABCD:5F000000:qmstart:690:root@pam:"
	r = &fakeReader{task: taskBody(badUPID, "qmdestroy", "690", "qa-pve-02", "stopped", "OK")}
	if err := DestroyTaskOK(context.Background(), r, testCfg, 690, badUPID); err == nil {
		t.Error("UPID naming a non-qmdestroy task accepted")
	}
}

func TestVMIDFreeAndVMGone(t *testing.T) {
	upid := validUPID(690)
	okTask := taskBody(upid, "qmdestroy", "690", "qa-pve-02", "stopped", "OK")
	poolAbsent := `[{"poolid":"pveforge-harness","members":[]}]`
	poolStill := `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-02"}]}]`

	// Proven gone.
	r := &fakeReader{task: okTask, nextid: `690`, pool: poolAbsent}
	if err := VMGone(context.Background(), r, testCfg, 690, upid); err != nil {
		t.Fatalf("should be proven gone: %v", err)
	}
	// nextid did not answer exactly N → not free.
	r = &fakeReader{task: okTask, nextid: `691`, pool: poolAbsent}
	if err := VMIDFree(context.Background(), r, 690); err == nil {
		t.Error("nextid 691 accepted as free for 690")
	}
	// Pool still lists it (numeric member) → not gone.
	r = &fakeReader{task: okTask, nextid: `690`, pool: poolStill}
	if err := VMGone(context.Background(), r, testCfg, 690, upid); err == nil {
		t.Error("pool still listing 690 accepted as gone")
	}
	// A member with a STRING vmid "690" must be an unexpected shape (lib.sh:648
	// requires every member numeric), so a would-be alias cannot read as gone.
	poolStringAlias := `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":"690","node":"qa-pve-02"}]}]`
	r = &fakeReader{task: okTask, nextid: `690`, pool: poolStringAlias}
	if err := VMGone(context.Background(), r, testCfg, 690, upid); err == nil || !strings.Contains(err.Error(), "unexpected shape") {
		t.Errorf("string-vmid member = %v, want unexpected shape", err)
	}
	// C3: a null (or any non-number) member vmid must FAIL the proof before the
	// inequality — lib.sh:648's `all(...(.vmid|type)=="number"...)`. A null
	// member read past as "not 690" would report a would-be-leftover as gone.
	poolNullMember := `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":null,"node":"qa-pve-02"}]}]`
	r = &fakeReader{task: okTask, nextid: `690`, pool: poolNullMember}
	if err := VMGone(context.Background(), r, testCfg, 690, upid); err == nil || !strings.Contains(err.Error(), "not a number") {
		t.Errorf("null-vmid member = %v, want 'not a number' refusal", err)
	}
}

// TestGuard_PoolShape pins readPool/Guard's pool-shape legs (C6): each fixture
// must refuse, so reverting the corresponding check ships red.
func TestGuard_PoolShape(t *testing.T) {
	confOK := `{"tags":"pveforge-harness"}`
	member := `{"type":"qemu","vmid":690,"node":"qa-pve-02"}`
	cases := []struct {
		name string
		pool string
		want string
	}{
		{"H: two-element pool array", `[{"poolid":"pveforge-harness","members":[` + member + `]},{"poolid":"x","members":[]}]`, "unexpected shape"},
		{"I: wrong poolid", `[{"poolid":"not-the-pool","members":[` + member + `]}]`, "unexpected shape"},
		{"J: members null", `[{"poolid":"pveforge-harness","members":null}]`, "unexpected shape"},
		{"K: two qemu members, same vmid", `[{"poolid":"pveforge-harness","members":[` + member + `,` + member + `]}]`, "not a qemu member"},
	}
	for _, c := range cases {
		r := &fakeReader{pool: c.pool, config: confOK}
		err := Guard(context.Background(), r, testCfg, nil, 690, ModeChange)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
}
