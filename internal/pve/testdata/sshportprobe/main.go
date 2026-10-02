// Command sshportprobe attempts to redirect RoutedClient's SSH dial from a
// binary that is NOT a test binary. It must never succeed.
//
// It lives under testdata for the same two reasons
// internal/pve/testdata/weakprobe does. The go tool ignores testdata when
// matching ./..., so this never joins a production build, is never vetted and
// never links into the pveforge binary. And sourceguard.NonTestReferences
// skips a testdata directory that is not its walk root, so the static guard
// in sshport_seam_test.go — which forbids the very call below in every
// non-test file — does not fire on this file.
//
// Run by TestSSHPortSeam_ProbeIsRejectedOutsideATestBinary via `go run`. If
// the gate is ever removed, or the exported wrapper ever passes true instead
// of testing.Testing(), this prints REDIRECTED and exits 0, and that test
// goes red. It is the only observer of that wrapper's argument.
package main

import (
	"fmt"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

func main() {
	restore := pve.SetSSHPortForIntegrationTests(2222)
	defer restore()
	fmt.Printf("REDIRECTED: RoutedClient now dials SSH port %d from a non-test binary\n", pve.RoutedSSHPort())
}
