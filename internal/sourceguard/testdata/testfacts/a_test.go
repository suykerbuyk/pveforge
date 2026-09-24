package testfacts

import (
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
)

func TestPlanted(t *testing.T) {
	t.Parallel()
	seam = 2
	grouped += 1
	os.Stdin = nil
	restore := pve.SetTaskTimingsForTests(0, 0)
	defer restore()
	netguard.ExpectViolation(t)
	// t.Parallel() in a comment is not a call.
	_ = "t.Parallel() in a string is not a call"
	local := 1
	local = 2
	_ = local
}
