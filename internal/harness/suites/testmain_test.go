//go:build harness

package suites

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/harness"
)

// h is the vetted nested harness every suite uses. A suite gets its clients
// from h.Client, never any other way.
var h *harness.Harness

// TestMain runs the guard before any suite. Any refusal exits non-zero with
// the reason: a harness run never skips, so a run that could not reach the
// nested cluster can never read as a pass.
func TestMain(m *testing.M) {
	var err error
	h, err = harness.Open(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	h.Close()
	os.Exit(code)
}

// TestGuard_EveryTargetIsVetted: every nested node has a vetted client.
func TestGuard_EveryTargetIsVetted(t *testing.T) {
	for _, n := range harness.NodeNames {
		if _, err := h.Client(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}
