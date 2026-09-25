package suites

import (
	"testing"

	"github.com/suykerbuyk/pveforge/internal/harness"
)

// TestAnchor is the untagged import of internal/harness from this package:
// the harness suites themselves build only with -tags harness, so without
// it the module's test-support guard would see no importer at all.
func TestAnchor(t *testing.T) {
	if harness.ClusterName != "pvh" {
		t.Fatalf("harness.ClusterName = %q", harness.ClusterName)
	}
}
