package roster

import (
	"bufio"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age/armor"
)

// productionScryptWorkFactor is the scrypt work factor (log2 N) that
// EncryptString must write: age's own default, which EncryptString gets by
// never calling SetWorkFactor.
const productionScryptWorkFactor = 18

// TestEncryptString_UsesAgeDefaultWorkFactor guards the production KDF
// parameter. Other packages' tests encrypt their fixtures at a low work
// factor through a _test.go-only fixtureEncrypt helper, to keep the suite
// fast under -race. This test is what proves that weak parameter never
// reaches the ciphertext production writes. It reads the scrypt stanza from
// the age header ("-> scrypt <salt> <logN>") and requires logN to be
// exactly productionScryptWorkFactor, not merely at least some threshold.
func TestEncryptString_UsesAgeDefaultWorkFactor(t *testing.T) {
	armored, err := EncryptString([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	logN, found := scryptWorkFactor(t, armored)
	if !found {
		t.Fatalf("no scrypt stanza in the age header of EncryptString's output:\n%s", armored)
	}
	if logN != productionScryptWorkFactor {
		t.Errorf("EncryptString wrote scrypt work factor %d, want exactly %d (age's default)", logN, productionScryptWorkFactor)
	}
}

// scryptWorkFactor returns the logN argument of the first scrypt stanza in
// armored's age header, and whether one was found at all. The header ends at
// its "---" MAC line; nothing after it is read.
func scryptWorkFactor(t *testing.T, armored string) (int, bool) {
	t.Helper()
	sc := bufio.NewScanner(armor.NewReader(strings.NewReader(armored)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "---") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] != "->" || fields[1] != "scrypt" {
			continue
		}
		logN, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatalf("scrypt stanza %q has a non-numeric work factor: %v", line, err)
		}
		return logN, true
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read age header: %v", err)
	}
	return 0, false
}
