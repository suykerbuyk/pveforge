package harness

import (
	"fmt"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// TestMain arms internal/netguard's loopback trip-wire over both seams, as
// every package whose code can dial does: the guard's own tests never reach
// a real host (they fake the resolver and the clients).
func TestMain(m *testing.M) {
	restoreDial := netguard.Install()
	restoreSSHGuard := sshexec.SetDialGuardForTests(netguard.Guard)
	code := m.Run()
	if err := netguard.Check(); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	restoreSSHGuard()
	restoreDial()
	os.Exit(code)
}
