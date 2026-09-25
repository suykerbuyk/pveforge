//go:build !linux

package sourceguard

import (
	"os"
	"testing"
)

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	t.Skip("the pseudo-terminal cases run on Linux only")
	return nil, nil
}
