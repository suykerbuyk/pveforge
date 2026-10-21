package reset

import (
	"encoding/json"
	"strings"
	"testing"
)

// Pure-decoder tests over their inputs (no process-global or shared-path
// state): the two-view snapshot decode, the newest-first cascade ordering, and
// the golden-stamp / read-back predicates — the logic the shell's jq encodes.

func TestParseSnaps_ShapeAndCurrent(t *testing.T) {
	if _, _, err := parseSnaps(json.RawMessage(`{}`)); err == nil {
		t.Error("a non-array snapshot list must be an unexpected shape")
	}
	if _, _, err := parseSnaps(json.RawMessage(`[{"snaptime":5}]`)); err == nil {
		t.Error("an entry without a string name must be an unexpected shape")
	}
	dec, hasCurrent, err := parseSnaps(json.RawMessage(`[{"name":"pvh-golden","snaptime":1000,"vmstate":0},{"name":"current","snaptime":0}]`))
	if err != nil {
		t.Fatal(err)
	}
	if !hasCurrent {
		t.Error("current was not detected")
	}
	if len(dec) != 1 || dec[0].name != "pvh-golden" {
		t.Errorf("decision view = %+v, want only pvh-golden (current removed)", dec)
	}
	if !dec[0].hasTime || dec[0].snaptime != 1000 || !dec[0].diskOnly {
		t.Errorf("decoded entry = %+v", dec[0])
	}
}

func TestParseSnaps_MissingSnaptimeIsNotZero(t *testing.T) {
	// go-proxmox would collapse a missing snaptime to 0; the raw decode must
	// distinguish it so "a snapshot without a time" is caught.
	dec, _, err := parseSnaps(json.RawMessage(`[{"name":"t1"},{"name":"current","snaptime":0}]`))
	if err != nil {
		t.Fatal(err)
	}
	if dec[0].hasTime {
		t.Error("a snapshot with no snaptime read as having a time")
	}
}

func TestParseSnaps_VmstatePresence(t *testing.T) {
	dec, _, _ := parseSnaps(json.RawMessage(`[{"name":"g","snaptime":1,"vmstate":1},{"name":"current","snaptime":0}]`))
	if dec[0].diskOnly {
		t.Error("vmstate:1 must not be disk-only")
	}
	dec, _, _ = parseSnaps(json.RawMessage(`[{"name":"g","snaptime":1},{"name":"current","snaptime":0}]`))
	if !dec[0].diskOnly {
		t.Error("an absent vmstate must be disk-only (// 0)")
	}
	dec, _, _ = parseSnaps(json.RawMessage(`[{"name":"g","snaptime":1,"vmstate":"x"},{"name":"current","snaptime":0}]`))
	if dec[0].diskOnly {
		t.Error("a non-integer vmstate must not be disk-only")
	}
}

func TestNewerThanGolden_Ordering(t *testing.T) {
	d := &Driver{}
	snaps, _, _ := parseSnaps(json.RawMessage(`[{"name":"aa","snaptime":3000},{"name":"pvh-golden","snaptime":1000,"description":"x"},{"name":"zz","snaptime":2000},{"name":"mm","snaptime":2500},{"name":"current","snaptime":0}]`))
	names, err := d.newerThanGolden(690, snaps)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "aa,mm,zz" {
		t.Errorf("newer = %v, want aa,mm,zz (newest first by time, not name)", names)
	}
}

func TestNewerThanGolden_Refusals(t *testing.T) {
	d := &Driver{}
	cases := map[string]string{
		"no golden":          `[{"name":"t1","snaptime":2000},{"name":"current","snaptime":0}]`,
		"two at one time":    `[{"name":"pvh-golden","snaptime":1000},{"name":"t1","snaptime":2000},{"name":"t2","snaptime":2000},{"name":"current","snaptime":0}]`,
		"a missing snaptime": `[{"name":"pvh-golden","snaptime":1000},{"name":"t1"},{"name":"current","snaptime":0}]`,
	}
	for name, raw := range cases {
		snaps, _, err := parseSnaps(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if _, err := d.newerThanGolden(690, snaps); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func TestGoldenStamp(t *testing.T) {
	d := &Driver{}
	good := `[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":"pveforge harness golden point 20260101T000000Z"},{"name":"current","snaptime":0}]`
	snaps, _, _ := parseSnaps(json.RawMessage(good))
	stamp, err := d.goldenStamp(690, snaps)
	if err != nil || stamp != "20260101T000000Z" {
		t.Fatalf("stamp = %q err = %v", stamp, err)
	}
	// One trailing newline is tolerated (TrimSuffix, not TrimRight).
	oneNL := `[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":"pveforge harness golden point 20260101T000000Z\n"},{"name":"current","snaptime":0}]`
	snaps, _, _ = parseSnaps(json.RawMessage(oneNL))
	if _, err := d.goldenStamp(690, snaps); err != nil {
		t.Errorf("one trailing newline must be tolerated: %v", err)
	}
	bad := map[string]string{
		"vmstate 1":      `[{"name":"pvh-golden","snaptime":1000,"vmstate":1,"description":"pveforge harness golden point 20260101T000000Z"},{"name":"current","snaptime":0}]`,
		"no prefix":      `[{"name":"pvh-golden","snaptime":1000,"description":"20260101T000000Z"},{"name":"current","snaptime":0}]`,
		"line after":     `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point 20260101T000000Z\nmore"},{"name":"current","snaptime":0}]`,
		"two newlines":   `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point 20260101T000000Z\n\n"},{"name":"current","snaptime":0}]`,
		"trailing text":  `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point 20260101T000000Z trailing"},{"name":"current","snaptime":0}]`,
		"no description": `[{"name":"pvh-golden","snaptime":1000},{"name":"current","snaptime":0}]`,
	}
	for name, raw := range bad {
		snaps, _, _ := parseSnaps(json.RawMessage(raw))
		if _, err := d.goldenStamp(690, snaps); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func TestGoldenReadsBack(t *testing.T) {
	d := &Driver{stamp: "20260924T120000Z"}
	ok := `[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":"pveforge harness golden point 20260924T120000Z"},{"name":"current","snaptime":0}]`
	snaps, _, _ := parseSnaps(json.RawMessage(ok))
	if !d.goldenReadsBack(snaps) {
		t.Error("a correct disk-only golden with this run's stamp must read back")
	}
	for name, raw := range map[string]string{
		"vmstate 1": `[{"name":"pvh-golden","snaptime":1000,"vmstate":1,"description":"pveforge harness golden point 20260924T120000Z"},{"name":"current","snaptime":0}]`,
		"old stamp": `[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":"pveforge harness golden point 20260101T000000Z"},{"name":"current","snaptime":0}]`,
		// Two trailing newlines must NOT read back: TrimSuffix strips exactly one,
		// so the compare still fails (a TrimRight would wrongly accept it).
		"two newlines": `[{"name":"pvh-golden","snaptime":1000,"vmstate":0,"description":"pveforge harness golden point 20260924T120000Z\n\n"},{"name":"current","snaptime":0}]`,
		"no golden":    `[{"name":"current","snaptime":0}]`,
		"two golden":   `[{"name":"pvh-golden","snaptime":1,"vmstate":0,"description":"pveforge harness golden point 20260924T120000Z"},{"name":"pvh-golden","snaptime":2,"vmstate":0,"description":"pveforge harness golden point 20260924T120000Z"},{"name":"current","snaptime":0}]`,
	} {
		snaps, _, _ := parseSnaps(json.RawMessage(raw))
		if d.goldenReadsBack(snaps) {
			t.Errorf("%s: must not read back", name)
		}
	}
}
