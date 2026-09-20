// Command weakprobe attempts to weaken the roster KDF from a binary that is
// NOT a test binary. It must never succeed.
//
// It lives under testdata for two reasons, and both matter. The go tool
// ignores testdata when matching ./..., so this never joins a production
// build, is never vetted and never links into the pveforge binary. And
// sourceguard.NonTestReferences skips a testdata directory that is not its
// walk root, so the static guard in kdf_seam_test.go — which forbids the very
// call below in every non-test file — does not fire on this file. That second
// point is not incidental: an unfiltered module walk reports main.go's call
// to SetScryptWorkFactorForTests as a violation, and the guard fails against
// its own fixture. sourceguard's TestNonTestReferences_SkipsNestedTestdataAndTestFiles
// is what keeps the skip from being removed.
//
// Run by TestSeam_WeakProbeIsRejectedOutsideATestBinary via `go run`. If the
// gate is ever deleted, this prints WEAKENED and exits 0, and that test goes
// red.
package main

import (
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func main() {
	restore := roster.SetScryptWorkFactorForTests(10)
	defer restore()
	out, err := roster.EncryptString([]byte("probe"), "probe-passphrase")
	fmt.Printf("WEAKENED: produced %d bytes of ciphertext at a lowered work factor (err=%v)\n", len(out), err)
}
