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
// factor, and this package's own writeback and load tests lower it through
// roster.SetScryptWorkFactorForTests. This test is what proves that weak
// parameter never reaches a ciphertext production write. It reads the scrypt
// stanza from the age header ("-> scrypt <salt> <logN>") and requires logN to
// be exactly productionScryptWorkFactor, not merely at least some threshold.
//
// It is a TABLE rather than one call, and the table varies the PASSPHRASE.
// That is the only input that can reach the decision: SetWorkFactor is called
// on the recipient, which is built from the passphrase alone, and age writes
// the scrypt stanza in Wrap before it has seen a byte of plaintext. A
// weakening conditional on the passphrase — its length, its encoding,
// anything — is therefore the only input-dependent weakening that is possible
// here, and one fixed passphrase would let it sit behind a green test. One
// plaintext variation is kept as a cheap cross-check on that reasoning.
//
// Each case costs a full production derivation (~6.3s under -race), so the
// table is kept to the cases that can actually distinguish something.
//
// Mutants G1 (SetWorkFactor(10) unconditionally), G1b (17) and G-default
// (the override defaults to 10) all die here.
func TestEncryptString_UsesAgeDefaultWorkFactor(t *testing.T) {
	if scryptWorkFactorOverride != 0 {
		t.Fatalf("override is %d at the start of this test, not 0 — something "+
			"earlier in the package failed to restore it, and every assertion "+
			"below would be measuring the wrong thing", scryptWorkFactorOverride)
	}
	cases := []struct {
		name       string
		plaintext  []byte
		passphrase string
	}{
		{"ordinary", []byte("secret"), "pw"},
		{"long passphrase", []byte("secret"), strings.Repeat("p", 512)},
		{"non-ascii passphrase", []byte("secret"), "pä§→ 🔑"},
		{"empty plaintext", []byte{}, "pw"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			armored, err := EncryptString(tc.plaintext, tc.passphrase)
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
		})
	}
}

// TestScryptWorkFactorOverride_IsZeroUnlessATestSetsIt pins the production
// configuration itself: the package's default must be "no override", so
// EncryptString behaves exactly as it did before the seam existed. Mutant
// G-default sets the var to 10 at declaration.
func TestScryptWorkFactorOverride_IsZeroUnlessATestSetsIt(t *testing.T) {
	if scryptWorkFactorOverride != 0 {
		t.Fatalf("scryptWorkFactorOverride = %d at rest, want 0 — production would encrypt at a lowered work factor", scryptWorkFactorOverride)
	}
}

// TestSetScryptWorkFactorForTests_RestoresTheProductionFactor is the round
// trip: lower the factor, observe that EncryptString honours it, restore, and
// observe production's 18 again. Mutant G-restore makes restore a no-op.
//
// The t.Cleanup is not redundant with the restore under test. If restore is
// broken, every later test in the package would encrypt at 10 and the failure
// would surface as a confusing cascade somewhere else; forcing the value back
// here keeps the kill attributable to this test.
func TestSetScryptWorkFactorForTests_RestoresTheProductionFactor(t *testing.T) {
	t.Cleanup(func() { scryptWorkFactorOverride = 0 })

	const lowered = 10
	restore := SetScryptWorkFactorForTests(lowered)

	armored, err := EncryptString([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString while lowered: %v", err)
	}
	if logN, found := scryptWorkFactor(t, armored); !found || logN != lowered {
		t.Fatalf("while lowered, EncryptString wrote work factor %d (found=%v), want %d — "+
			"the seam is not doing anything, so the restore assertion below would be vacuous",
			logN, found, lowered)
	}

	restore()

	if scryptWorkFactorOverride != 0 {
		t.Errorf("restore() left the override at %d, want 0", scryptWorkFactorOverride)
	}
	armored, err = EncryptString([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString after restore: %v", err)
	}
	logN, found := scryptWorkFactor(t, armored)
	if !found {
		t.Fatalf("no scrypt stanza after restore:\n%s", armored)
	}
	if logN != productionScryptWorkFactor {
		t.Errorf("after restore, EncryptString wrote work factor %d, want exactly %d", logN, productionScryptWorkFactor)
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
