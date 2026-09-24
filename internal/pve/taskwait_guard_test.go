package pve

import (
	"maps"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/lock/lockguard"
)

// TestTaskWaitsUseTheCallersContext: every WaitForTask call in the module
// is given its caller's own context, so the task-warnings reporter the
// command installed (WithTaskWarnings) reaches it. A wait on
// context.Background() would take a warnings success silently. The rule
// and the walk are lockguard's (Scan.TaskWaits).
//
// The sites are pinned per file, so a new wait, or one the walk stopped
// seeing, is a deliberate change here: 11 production waits, plus
// RoutedClient's pass-through to Client.
func TestTaskWaitsUseTheCallersContext(t *testing.T) {
	sc, err := lockguard.ScanModule("../..")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, c := range sc.TaskWaits {
		got[c.Ref.File]++
		if c.Problem != "" {
			t.Errorf("%s:%d: WaitForTask: %s", c.Ref.File, c.Ref.Line, c.Problem)
		}
	}
	want := map[string]int{
		"cmd/pveforge/api.go":                  1,
		"internal/idempotent/networkbridge.go": 1,
		"internal/idempotent/networkfields.go": 1,
		"internal/idempotent/vmclone.go":       1,
		"internal/idempotent/vmcreate.go":      1,
		"internal/idempotent/vmdestroy.go":     2,
		"internal/idempotent/vmshutdown.go":    1,
		"internal/pve/routed.go":               1,
		"internal/pve/snapshot.go":             3,
	}
	if !maps.Equal(got, want) {
		t.Errorf("WaitForTask calls per file = %v\nwant %v", got, want)
	}
}
