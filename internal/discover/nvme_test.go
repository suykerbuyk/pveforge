package discover

import (
	"github.com/suykerbuyk/pveforge/internal/device"
	"regexp"
	"testing"
)

func TestNVMeDriveSchema_Shape(t *testing.T) {
	if NVMeDriveSchema.Type != "object" {
		t.Errorf("Type = %q, want object", NVMeDriveSchema.Type)
	}
	for _, name := range []string{"serial", "backing", "format"} {
		if _, ok := NVMeDriveSchema.Properties[name]; !ok {
			t.Errorf("expected a %q property", name)
		}
	}
	wantRequired := map[string]bool{"serial": true, "backing": true}
	for _, r := range NVMeDriveSchema.Required {
		if !wantRequired[r] {
			t.Errorf("unexpected required field %q", r)
		}
		delete(wantRequired, r)
	}
	if len(wantRequired) != 0 {
		t.Errorf("missing required fields: %v", wantRequired)
	}
	if NVMeDriveSchema.Properties["format"].Optional != true {
		t.Error("expected format to be marked Optional")
	}
	if NVMeDriveSchema.Properties["serial"].Optional {
		t.Error("serial must not be marked Optional (it's required)")
	}
}

// TestNVMeDriveSchema_PatternsAreValidRegexes proves every derived
// pattern actually compiles — a syntax error here would mean
// allowedExtraToPattern produced garbage no caller could use.
func TestNVMeDriveSchema_PatternsAreValidRegexes(t *testing.T) {
	for name, prop := range NVMeDriveSchema.Properties {
		if prop.Pattern == "" {
			continue
		}
		if _, err := regexp.Compile(prop.Pattern); err != nil {
			t.Errorf("property %q: pattern %q does not compile: %v", name, prop.Pattern, err)
		}
	}
}

// TestAllowedExtraToPattern_TrailingHyphenIsLiteral checks the specific
// concern that motivated escaping '-' defensively in allowedExtraToPattern
// (see that function's own doc comment): a naive reading of bracket-
// expression syntax might expect a '-' placed right after "0-9" (as
// NVMeSerialAllowedExtra's leading '-' ends up) to be misread as a SECOND
// range operator reaching back into the already-consumed '9' — i.e.
// "^[A-Za-z0-9-_]+$" parsed as if it covered every character from '9'
// (0x39) through '_' (0x5F). Verified empirically (both here and by hand
// with regexp.MatchString outside this test) that Go's RE2 does NOT do
// this — a range consumes its three tokens as one unit, and the single
// remaining '-' has no second atom available to pair with backward, so
// it's already read as a literal even without escaping. This test proves
// that's still true (and would catch it if a future Go regexp change, or
// a different value of extra, ever made it not true) — not a regression
// test for a bug that was ever actually reproducible; escaping stays in
// allowedExtraToPattern as defense-in-depth, not because this failed
// without it.
func TestAllowedExtraToPattern_TrailingHyphenIsLiteral(t *testing.T) {
	pattern := allowedExtraToPattern("-_")
	re := regexp.MustCompile(pattern)

	valid := []string{"abc", "ABC123", "a-b_c", "a_b-c"}
	for _, s := range valid {
		if !re.MatchString(s) {
			t.Errorf("pattern %q should match %q but didn't", pattern, s)
		}
	}

	// Characters that fall inside the ASCII range '9'..'_' (0x39..0x5F)
	// but are NOT letters, digits, '-', or '_' — what a genuine
	// range-operator misparse would incorrectly accept.
	invalid := []string{":", ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^"}
	for _, s := range invalid {
		if re.MatchString(s) {
			t.Errorf("pattern %q incorrectly matched %q — hyphen range-operator bug", pattern, s)
		}
	}
}

func TestAllowedExtraToPattern_EmptyExtra(t *testing.T) {
	pattern := allowedExtraToPattern("")
	re := regexp.MustCompile(pattern)
	if !re.MatchString("raw") {
		t.Error("expected plain alphanumeric to match")
	}
	if re.MatchString("raw-2") {
		t.Error("expected a hyphen to be rejected when extra is empty")
	}
}

// TestNVMeDriveSchema_BackingIsTheValidatePattern: the backing pattern is
// device.NVMeBackingPattern itself, not a restatement of it, and it refuses
// what Validate refuses: a PVE volid and QEMU protocol syntax. (Agreement
// over the whole input table is internal/device's
// TestNVMeDriveSchema_AgreesWithValidate.)
func TestNVMeDriveSchema_BackingIsTheValidatePattern(t *testing.T) {
	got := NVMeDriveSchema.Properties["backing"].Pattern
	if got != device.NVMeBackingPattern {
		t.Fatalf("backing pattern = %q, want device.NVMeBackingPattern %q", got, device.NVMeBackingPattern)
	}
	re := regexp.MustCompile(got)
	for _, s := range []string{"local-lvm:vm-100-disk-1", "nbd:qa-pve-01:10809", "nbd://qa-pve-01/export"} {
		if re.MatchString(s) {
			t.Errorf("backing pattern %q matched %q", got, s)
		}
	}
	if !re.MatchString("/dev/pve/vm-100-disk-1") {
		t.Errorf("backing pattern %q refused an absolute host path", got)
	}
}

// TestDeviceSchemas_OneEntry is the deliberately brittle guardrail
// described on DeviceSchemas's own doc comment: it must be updated by
// hand — and this test's own expectations widened — the moment a second
// device-semantic resolver gets a hand-authored schema, rather than let a
// new resolver silently go undescribed.
func TestDeviceSchemas_OneEntry(t *testing.T) {
	if len(DeviceSchemas) != 1 {
		t.Fatalf("DeviceSchemas has %d entries, want exactly 1 — if you just added a new resolver's schema, update this test's expectation deliberately", len(DeviceSchemas))
	}
	if _, ok := DeviceSchemas["NVMeDrive"]; !ok {
		t.Error(`expected DeviceSchemas["NVMeDrive"] to be present`)
	}
}
