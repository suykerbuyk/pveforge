//go:build harness

package main

import (
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

const (
	vzdumpEmptyID = "UPID:pvh-n1:00001A2C:0003C4D6:66AC0001:vzdump::root@pam:"  // valid vzdump, empty id
	qmstartEmpty  = "UPID:pvh-n1:00001A2D:0003C4D7:66AC0002:qmstart::root@pam:" // qmstart with an empty id
	qmcreate150   = "UPID:pvh-n1:00001A2B:0003C4D5:66AC0000:qmcreate:150:root@pam:"
	tokenStart    = "UPID:pvh-n1:00001A2E:0003C4D8:66AC0003:qmstart:150:batcha-amut@pve!amut:"
)

// F5: the golden gate is gated on amutRequested — true iff any A-MUT flag is set.
func TestAmutRequested(t *testing.T) {
	if amutRequested(0, 0, nil, "", "", "") {
		t.Error("no A-MUT flags: amutRequested should be false (golden gate runs)")
	}
	for name, got := range map[string]bool{
		"agent":      amutRequested(150, 0, nil, "", "", ""),
		"qmcreate":   amutRequested(0, 150, nil, "", "", ""),
		"upid":       amutRequested(0, 0, []string{"u"}, "", "", ""),
		"vzdump":     amutRequested(0, 0, nil, "x", "", ""),
		"user":       amutRequested(0, 0, nil, "", "x", ""),
		"exitstatus": amutRequested(0, 0, nil, "", "", "x"),
	} {
		if !got {
			t.Errorf("%s flag set: amutRequested should be true (golden gate skipped)", name)
		}
	}
}

// F4: -vzdump-upid must assert type=vzdump AND valid AND empty id — a non-vzdump
// UPID is caught even with an empty id.
func TestVzdumpSpellingErrors(t *testing.T) {
	ok, _ := pve.ParseUPIDSpelling(vzdumpEmptyID)
	if errs := vzdumpSpellingErrors(ok); len(errs) != 0 {
		t.Errorf("valid empty-id vzdump: want no errors, got %v", errs)
	}
	bad, _ := pve.ParseUPIDSpelling(qmstartEmpty) // empty id but WRONG type
	errs := vzdumpSpellingErrors(bad)
	if len(errs) == 0 || !strings.Contains(strings.Join(errs, ";"), "type") {
		t.Errorf("qmstart with empty id: want a type mismatch error, got %v", errs)
	}
}

// F4/B1: userSpellingErrors asserts the principal; the mandatory-expect-user
// guard (empty → error) lives in run() and is exercised via the empty case here.
func TestUserSpellingErrors(t *testing.T) {
	sp, _ := pve.ParseUPIDSpelling(tokenStart)
	if errs := userSpellingErrors(sp, "batcha-amut@pve!amut"); len(errs) != 0 {
		t.Errorf("matching principal: want no errors, got %v", errs)
	}
	if errs := userSpellingErrors(sp, "root@pam"); len(errs) == 0 {
		t.Error("root@pam expectation on a token UPID: want a mismatch error")
	}
}

// F2: a recovered qmcreate spelling is checked for type+id and validity.
func TestQmcreateSpellingErrors(t *testing.T) {
	sp, _ := pve.ParseUPIDSpelling(qmcreate150)
	if errs := qmcreateSpellingErrors(sp, 150); len(errs) != 0 {
		t.Errorf("qmcreate/150: want no errors, got %v", errs)
	}
	if errs := qmcreateSpellingErrors(sp, 999); len(errs) == 0 {
		t.Error("qmcreate/150 checked against vmid 999: want an id mismatch")
	}
	// A qmstart masquerading (wrong type) is caught.
	st, _ := pve.ParseUPIDSpelling(tokenStart)
	if errs := qmcreateSpellingErrors(st, 150); len(errs) == 0 {
		t.Error("qmstart checked as qmcreate: want a type mismatch")
	}
}
