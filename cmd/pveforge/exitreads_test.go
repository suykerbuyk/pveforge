package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// AC-W6 (b): a READ path can never exit 3 or 4. A read failure is not a
// dispatch (3) and not a refusal (4); it is exit 1. Two tables: every safe
// REST read against a server that fails EVERY request, and a root-SSH READ
// that hangs (from a verb that also has root-SSH WRITES).

func TestExitReads_SafeVerbsNeverExit3Or4_WhenEveryRequestFails(t *testing.T) {
	var requests int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, `{"data":null}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	path := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	// `doctor` is excluded on purpose: its exit 4 is a verdict refusal (a privilege
	// not held), documented, and it dispatches nothing.
	cases := map[string][]string{
		"api get":          {"api", "get", "/nodes", "qa-pve-01"},
		"node get":         {"node", "get", "qa-pve-01"},
		"vm get":           {"vm", "get", "qa-pve-01", "100"},
		"vm snapshot list": {"vm", "snapshot", "list", "qa-pve-01", "100"},
		"storage get":      {"storage", "get", "qa-pve-01", "local"},
		"storage orphans":  {"storage", "orphans", "qa-pve-01", "local"},
		"network get":      {"network", "get", "qa-pve-01", "vmbr0"},
		"discover node":    {"discover", "node", "qa-pve-01"},
		"discover vm":      {"discover", "vm", "qa-pve-01"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			before := requests
			full := append(append([]string{args[0]}, argsAfterFirst(args)...), "--roster", path)
			code, _, stderr := runRootArgs(full...)
			if code == 3 || code == 4 {
				t.Fatalf("a read failure exited %d: %q", code, stderr)
			}
			if requests == before {
				t.Fatalf("vacuous: the command made no request (exit %d, stderr %q)", code, stderr)
			}
		})
	}
}

func argsAfterFirst(a []string) []string { return a[1:] }

// A root-SSH READ timeout is exit 1, even from a verb that has root-SSH writes:
// `acl enable-vm-destroy` reads `pveum role list` first. The control: the same
// verb with a hanging WRITE exits 3 (rootdeadlines_test.go's C3 family does the
// same for acl grant).
func TestExitReads_ARootReadTimeoutIsExit1_EvenFromAVerbWithWrites(t *testing.T) {
	lowerRootBounds(t)
	path, fs, started := hangingRoot(t, nil, map[string]string{"pveum acl list": "[]"}, "pveum role list")
	_ = fs
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--yes", "qa-pve-01")
		if code != 1 {
			t.Fatalf("a hung `pveum role list` exited %d, want 1; stderr %q", code, stderr)
		}
		if !strings.Contains(stderr, "timed out") {
			t.Errorf("stderr %q does not say it timed out", stderr)
		}
	})
	select {
	case <-started:
	default:
		t.Fatal("vacuous: the read never started")
	}
}
