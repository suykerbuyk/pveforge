package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
)

// The three write logs of the exit-4 contract (contract plan §3.5, AC-W3).
// A refusal fixture never decides "nothing was written" from the exit status
// or from one fake's request log: it reads, after the run,
//
//	(i)   the fake PVE's non-GET request log,
//	(ii)  the root-SSH command log (writes only: reads are legal before a refusal),
//	(iii) a before/after sha256 snapshot of the ROSTER FILE and the temp and
//	      backup siblings the roster package writes,
//
// and asserts the run's own write gate (internal/dispatch) AGREES with them:
// the gate is opened iff some log is non-empty. A primitive or fake that writes
// without opening the gate, or opens it without writing, fails every fixture.
//
// EXCLUDED from (iii), by this explicit list and no other: <roster>.lock,
// <roster>.locks/, harness evidence directories and files, the harness ledger,
// and the probe's harness-state/ file. They are local bookkeeping, not
// mutations (contract plan D17/D18).

// writeEnv wires one fixture's three logs. restWrites and sshWrites are
// functions so a fixture whose fake has no such side (a REST-only verb has no
// SSH) must still say so explicitly with noLog, and the helper asserts every
// log was consulted.
type writeEnv struct {
	roster     string
	restWrites func() []string // fake PVE non-GET requests, "METHOD path"
	sshWrites  func() []string // root-SSH write commands
}

// noLog is the explicit "this fixture has no such side": it always reports an
// empty log, and the helper records that the fixture said so.
func noLog() []string { return nil }

// excludedBookkeeping lists, by name, what the roster snapshot does not count.
func excludedBookkeeping(name string) bool {
	switch {
	case strings.HasSuffix(name, ".lock"), strings.HasSuffix(name, ".locks"):
		return true
	}
	return false
}

// rosterSnapshot is sha256 per file of the roster and its siblings (temp,
// backup), excluding the bookkeeping list above. A file that appears or
// disappears is a difference.
func rosterSnapshot(t *testing.T, rosterPath string) map[string]string {
	t.Helper()
	dir, base := filepath.Split(rosterPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	snap := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || excludedBookkeeping(name) || !strings.HasPrefix(name, strings.TrimSuffix(base, filepath.Ext(base))) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
		sum := sha256.Sum256(b)
		snap[name] = hex.EncodeToString(sum[:])
	}
	if len(snap) == 0 {
		t.Fatalf("vacuous: the roster snapshot of %s holds no file", rosterPath)
	}
	return snap
}

func snapDiff(a, b map[string]string) []string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

// gatedRun is runRootArgs with the run's write gate readable afterwards.
func gatedRun(args ...string) (code int, stdout, stderr string, opened bool) {
	root := newRootCmd()
	root.SetArgs(args)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	ctx, _ := dispatch.With(context.Background())
	root.SetContext(ctx)
	code = runRoot(root, &errOut)
	return code, out.String(), errOut.String(), dispatch.Opened(ctx)
}

// writeObservation is what the three logs and the gate showed for one run.
type writeObservation struct {
	code           int
	stdout, stderr string
	opened         bool
	rest, ssh      []string
	rosterChanged  []string
}

func (o writeObservation) wrote() bool {
	return len(o.rest) > 0 || len(o.ssh) > 0 || len(o.rosterChanged) > 0
}

// observe runs args and reads all three logs and the gate. It FAILS the test
// if the gate disagrees with the logs (opened iff any log is non-empty): that
// is what makes a deleted dispatch.Open observable instead of merely pinned.
func (e writeEnv) observe(t *testing.T, args ...string) writeObservation {
	t.Helper()
	if e.restWrites == nil || e.sshWrites == nil || e.roster == "" {
		t.Fatal("a write fixture must wire all three logs (use noLog for a side the fake does not have)")
	}
	restBefore, sshBefore := len(e.restWrites()), len(e.sshWrites())
	before := rosterSnapshot(t, e.roster)
	code, out, errOut, opened := gatedRun(args...)
	after := rosterSnapshot(t, e.roster)
	o := writeObservation{code: code, stdout: out, stderr: errOut, opened: opened}
	if r := e.restWrites(); len(r) > restBefore {
		o.rest = r[restBefore:]
	}
	if s := e.sshWrites(); len(s) > sshBefore {
		o.ssh = s[sshBefore:]
	}
	o.rosterChanged = snapDiff(before, after)
	if o.wrote() != o.opened {
		t.Fatalf("the write gate disagrees with the logs: gate opened=%v, rest=%q ssh=%q roster changed=%q (exit %d, stderr %q)",
			o.opened, o.rest, o.ssh, o.rosterChanged, code, errOut)
	}
	return o
}

// wantRefusedBeforeAnyWrite: exit 4 with ZERO entries in all three logs and a
// closed gate.
func (o writeObservation) wantRefusedBeforeAnyWrite(t *testing.T) {
	t.Helper()
	if o.code != 4 {
		t.Fatalf("exit %d, want 4 (refused before any write); stdout %q stderr %q", o.code, o.stdout, o.stderr)
	}
	if o.wrote() || o.opened {
		t.Fatalf("exit 4 after a write: rest=%q ssh=%q roster changed=%q gate=%v", o.rest, o.ssh, o.rosterChanged, o.opened)
	}
}

// wantNotRefusedAfterWrite is the POST-WRITE TWIN assertion: the same fixture
// advanced past its first write must exit anything BUT 4, and the write must
// really have happened (so the twin cannot pass because it never wrote).
func (o writeObservation) wantNotRefusedAfterWrite(t *testing.T) {
	t.Helper()
	if !o.wrote() || !o.opened {
		t.Fatalf("vacuous twin: nothing was written (rest=%q ssh=%q roster changed=%q gate=%v, exit %d)", o.rest, o.ssh, o.rosterChanged, o.opened, o.code)
	}
	if o.code == 4 {
		t.Fatalf("exit 4 AFTER a write: rest=%q ssh=%q roster changed=%q; stderr %q", o.rest, o.ssh, o.rosterChanged, o.stderr)
	}
}

// bookkeepingOnlyDoesNotCount is the positive control: creating the lock
// files and an evidence directory beside the roster changes the snapshot not
// at all (the exclusion works), and a real roster edit does (it is not
// excluded too widely).
func TestWriteLogs_BookkeepingIsExcluded_RosterIsNot(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "pveforge.toml")
	if err := os.WriteFile(rp, []byte("# roster\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := rosterSnapshot(t, rp)
	if err := os.WriteFile(rp+".lock", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(rp+".locks", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rp+".locks", "k"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := snapDiff(before, rosterSnapshot(t, rp)); len(d) != 0 {
		t.Fatalf("bookkeeping counted as a roster write: %q", d)
	}
	if err := os.WriteFile(rp, []byte("# roster changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := snapDiff(before, rosterSnapshot(t, rp)); len(d) != 1 || d[0] != "pveforge.toml" {
		t.Fatalf("a roster edit was not seen: %q", d)
	}
	// a temp sibling the roster package leaves is a difference too
	if err := os.WriteFile(filepath.Join(dir, "pveforge.toml.tmp123"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := snapDiff(before, rosterSnapshot(t, rp)); len(d) != 2 {
		t.Fatalf("a temp sibling was not seen: %q", d)
	}
}
