package probe

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyStorageRollback pins the probe's STORAGE-measuring classifier
// (operator reversal of P4): nil (the raw rollback task ran OK) → rollback-any;
// an error carrying PVE's "is not most recent snapshot" refusal → latest-only;
// any other error → fail. A mutant that maps any error → latest-only, nil →
// latest-only, or matches the wrong substring goes red here.
func TestClassifyStorageRollback(t *testing.T) {
	if rule, _ := classifyStorageRollback(nil); rule != "rollback-any" {
		t.Errorf("nil → %q, want rollback-any", rule)
	}
	// The real refusal text form (a failed rollback task), as probe.sh sees it.
	refusal := errors.New("task UPID:x failed: can't rollback, 's1' is not most recent snapshot on 'pveforge-harness:vm-690-disk-0'")
	if rule, _ := classifyStorageRollback(refusal); rule != "rollback-latest-only" {
		t.Errorf("not-most-recent refusal → %q, want rollback-latest-only", rule)
	}
	// An unrelated error is NOT latest-only — it is an unrecognised failure.
	rule, reason := classifyStorageRollback(errors.New("task UPID:x failed: some other reason"))
	if rule != "" || reason == "" {
		t.Errorf("unrelated error → (%q,%q), want ('', <cause>)", rule, reason)
	}
}

func TestScreenProbeCreate(t *testing.T) {
	ok := map[string]string{"scsi0": "pveforge-harness:1", "name": "pveforge-probe", "memory": "512", "cores": "1"}
	if err := screenProbeCreate("pveforge-harness", ok); err != nil {
		t.Errorf("valid probe create refused: %v", err)
	}
	cases := []struct {
		name   string
		fields map[string]string
		want   string
	}{
		{"wrong storage", map[string]string{"scsi0": "other-storage:1", "name": "x", "memory": "512", "cores": "1"}, "required storage"},
		{"existing volume not a new alloc", map[string]string{"scsi0": "pveforge-harness:vm-700-disk-0", "name": "x", "memory": "512", "cores": "1"}, "new allocation"},
		{"disallowed field", map[string]string{"scsi0": "pveforge-harness:1", "ide2": "x:cloudinit"}, "not allowed"},
		{"control char", map[string]string{"scsi0": "pveforge-harness:1", "name": "a\nb"}, "control character"},
		{"missing scsi0", map[string]string{"name": "x"}, "needs scsi0"},
	}
	for _, c := range cases {
		if err := screenProbeCreate("pveforge-harness", c.fields); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
}
