package outer

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

// Ledger is this run's record of the VMIDs the harness created — a port of
// lib.sh's HARNESS_CREATED_FILE (lib.sh:199) plus _harness_created
// (lib.sh:449-453). It is one VMID per line, and membership is an exact
// whole-line match (the shell's `grep -qxF`).
//
// S4: this is the Go harness's OWN per-run ledger, independent of the
// shell's. lib.sh holds its path in a per-run variable (a fresh mktemp), not
// a stable shared path, so the two cannot drive one shared ledger; nothing
// here reads or writes the shell's file.
type Ledger struct {
	path string
}

// OpenLedger wraps an existing ledger path (from --created-file /
// HARNESS_CREATED_FILE), so destroy across separate verb invocations can see
// what an earlier `created-mark` recorded. The file need not exist yet; Has
// treats a missing file as "nothing recorded".
func OpenLedger(path string) *Ledger { return &Ledger{path: path} }

// Path is the ledger's file path.
func (l *Ledger) Path() string { return l.path }

// Add records vmid as created by this run (append, newline-terminated),
// mirroring lib.sh:809.
func (l *Ledger) Add(vmid int) error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("record VM %d as created: %w", vmid, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, "%d\n", vmid); err != nil {
		return fmt.Errorf("record VM %d as created: %w", vmid, err)
	}
	return nil
}

// Has reports whether this run created vmid — the exact whole-line match
// _harness_created makes. A missing ledger file is not an error (nothing was
// recorded); any other read error IS an error, never silently "not created"
// (the shell's `rc > 1` die, lib.sh:452), so a destroy can never slip past a
// ledger it merely failed to read.
func (l *Ledger) Has(vmid int) (bool, error) {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read created-VM ledger %s: %w", l.path, err)
	}
	defer func() { _ = f.Close() }()
	want := strconv.Itoa(vmid)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() == want {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("read created-VM ledger %s: %w", l.path, err)
	}
	return false, nil
}
