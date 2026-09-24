package device_test

import (
	"regexp"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/device"
	"github.com/suykerbuyk/pveforge/internal/discover"
)

// TestNVMeDriveSchema_AgreesWithValidate: for every Backing the check must
// decide, the pattern `discover device NVMeDrive` publishes matches exactly
// when NVMeDrive.Validate accepts it, so a caller validating against the
// schema is never told a path is fine that Validate then refuses, or the
// reverse. An external test package, so it can import internal/discover,
// which itself imports internal/device.
func TestNVMeDriveSchema_AgreesWithValidate(t *testing.T) {
	re := regexp.MustCompile(discover.NVMeDriveSchema.Properties["backing"].Pattern)
	if len(device.BackingCasesForTest) == 0 {
		t.Fatal("no backing cases: the test checks nothing")
	}
	for _, c := range device.BackingCasesForTest {
		validated := device.NVMeDrive{Serial: "SN123", Backing: c.Backing}.Validate() == nil
		if matched := re.MatchString(c.Backing); matched != validated || validated != c.OK {
			t.Errorf("backing %q: schema matches %v, Validate accepts %v, want both %v", c.Backing, matched, validated, c.OK)
		}
	}
}
