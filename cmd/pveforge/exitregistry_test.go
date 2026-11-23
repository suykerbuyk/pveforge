package main

import (
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock/lockguard"
)

// The exit registry (exitstatus.go verbExits) is hand-written; these tests hold
// it to the real command tree (AC-W1) and to the README (AC-W7).

// mutatingTree is every non-safe runnable leaf command of the real tree, by
// path without the root, and the safe ones separately.
func commandTree() (mutating, safe []string) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		if !c.Runnable() || c.HasSubCommands() || cobraBuiltinPaths[c.CommandPath()] {
			return
		}
		path := strings.TrimPrefix(c.CommandPath(), "pveforge ")
		if c.Annotations[mutationAnnotationKey] == mutationSafe {
			safe = append(safe, path)
		} else {
			mutating = append(mutating, path)
		}
	}
	walk(newRootCmd())
	sort.Strings(mutating)
	sort.Strings(safe)
	return
}

func TestExitRegistry_IsTotalOverTheMutatingTree(t *testing.T) {
	tree, _ := commandTree()
	if len(tree) < 36 {
		t.Fatalf("the tree has %d mutating commands, want at least 36: the walk is not seeing the tree", len(tree))
	}
	var keys []string
	for k := range verbExits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, p := range tree {
		if _, ok := verbExits[p]; !ok {
			t.Errorf("mutating command %q has no row in the exit registry", p)
		}
	}
	for _, k := range keys {
		if !slices.Contains(tree, k) {
			t.Errorf("the exit registry has a row for %q, which is not a mutating command", k)
		}
	}
	if !slices.Equal(tree, keys) && !t.Failed() {
		t.Errorf("tree %v != registry %v", tree, keys)
	}
}

func TestExitRegistry_RowsAreWellFormed(t *testing.T) {
	for k, v := range verbExits {
		if len(v.Exits) == 0 {
			t.Errorf("%s: no exits", k)
		}
		for _, e := range v.Exits {
			if e != 3 && e != 4 {
				t.Errorf("%s: exit %d is not 3 or 4", k, e)
			}
		}
		if slices.Contains(v.Exits, 3) && len(v.Waits) == 0 {
			t.Errorf("%s exits 3 with no named wait or dispatch site", k)
		}
		if !slices.Contains(v.Exits, 3) && len(v.Waits) != 0 {
			t.Errorf("%s names waits but does not list exit 3", k)
		}
		if slices.Contains(v.Exits, 4) && len(v.Refusals) == 0 {
			t.Errorf("%s exits 4 with no named refusal boundary", k)
		}
		if v.Gate == "" || v.WriteKind == "" {
			t.Errorf("%s: no gate or write kind", k)
		}
		if v.State != "" && v.State != stateUnobservedDispatch && v.State != stateChildStatus {
			t.Errorf("%s: unknown named state %q", k, v.State)
		}
	}
	// the two named states are in the registry where the plan puts them
	for _, k := range []string{"api post", "api put", "api delete"} {
		if verbExits[k].State != stateUnobservedDispatch {
			t.Errorf("%s lost the named state unobserved_dispatch", k)
		}
	}
	// G5: vm set's row says what is 4 (Validate, lock) and what is 1 (inside the write)
	vs := verbExits["vm set"]
	if !strings.Contains(strings.Join(vs.Refusals, " "), "Validate") || !strings.Contains(vs.Residual, "allow-list and digest refusals raised inside the write are exit 1") {
		t.Errorf("vm set's registry row does not say Validate is 4 and allow-list/digest inside the write is 1: %+v", vs)
	}
	if verbExits["exec"].State != stateChildStatus {
		t.Error("exec lost the named state child_status")
	}
}

// readmeList returns the backticked command paths of the bullet list under a
// heading line prefix in the README's "Which commands exit 3 and 4" section.
func readmeList(t *testing.T, heading string) []string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "### Which commands exit 3 and 4")
	if i < 0 {
		t.Fatal("the README has no 'Which commands exit 3 and 4' section")
	}
	s = s[i:]
	j := strings.Index(s, heading)
	if j < 0 {
		t.Fatalf("no %q list", heading)
	}
	s = s[j+len(heading):]
	re := regexp.MustCompile("^- `([^`]+)`$")
	var out []string
	started := false
	for _, line := range strings.Split(s, "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
			started = true
		} else if started && strings.TrimSpace(line) == "" {
			break
		}
	}
	sort.Strings(out)
	return out
}

func TestExitRegistry_READMEListsAreTheRegistry(t *testing.T) {
	var want3, want4 []string
	for k, v := range verbExits {
		if slices.Contains(v.Exits, 3) {
			want3 = append(want3, k)
		}
		if slices.Contains(v.Exits, 4) {
			want4 = append(want4, k)
		}
	}
	want4 = append(want4, "doctor") // a safe command whose 4 is a verdict refusal
	sort.Strings(want3)
	sort.Strings(want4)
	got3, got4 := readmeList(t, "Commands that can exit 3:"), readmeList(t, "Commands that can exit 4:")
	if len(got3) == 0 || len(got4) == 0 {
		t.Fatalf("vacuous: the README lists hold %d and %d commands", len(got3), len(got4))
	}
	if !slices.Equal(got3, want3) {
		t.Errorf("README exit-3 list != registry\n got  %v\n want %v", got3, want3)
	}
	if !slices.Equal(got4, want4) {
		t.Errorf("README exit-4 list != registry\n got  %v\n want %v", got4, want4)
	}
}

// The README states the invariant and the bookkeeping exclusion list, and the
// two named states and the residual.
func TestExitRegistry_READMEStatesTheContract(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Join(strings.Fields(string(b)), " ")
	for _, w := range []string{
		"exit 4 is decided by whether the run had already sent a change",
		"Local bookkeeping is explicitly NOT a change",
		"`<roster>.lock` and `<roster>.locks/`", "the harness evidence directories and files", "the harness ledger", "`harness-state/`",
		"`unobserved_dispatch`", "`child_status`", "NOT proof that nothing changed", "`vm set` is exit 4 only for its Validate refusals", "an allow-list or digest refusal raised inside the write is exit 1",
	} {
		if !strings.Contains(doc, w) {
			t.Errorf("README lacks %q", w)
		}
	}
	p, err := os.ReadFile("../../docs/prd.md")
	if err != nil {
		t.Fatal(err)
	}
	prd := strings.Join(strings.Fields(string(p)), " ")
	for _, w := range []string{"exit 4 never follows a mutation", "the README's \"Exit status\" table and its two per-command lists are authoritative", "`internal/dispatch`", "`harness-state/`"} {
		if !strings.Contains(prd, w) {
			t.Errorf("PRD lacks %q", w)
		}
	}
	if strings.Contains(prd, "The README holds the table, and `cmd/pveforge/readme_test.go` holds it to the code.") {
		t.Error("the PRD still carries its own copy of the exit-status table (it is a summary now)")
	}
}

// AC-W6 (a): the set of files that wait on a PVE task is the set the registry's
// exit-3 verbs account for. A new wait site (a new file calling WaitForTask)
// fails here until its verbs are named, and every verb named must list exit 3.
// (internal/pve's TestTaskWaitsUseTheCallersContext pins the per-file COUNTS;
// this ties the files to verbs.) A safe verb is never in the table.
var waitSiteVerbs = map[string][]string{
	"cmd/pveforge/api.go":                    {"api post", "api put", "api delete"},
	"cmd/pveforge/harness_vm.go":             {"harness vm destroy", "harness vm stop", "harness vm snapshot create", "harness vm snapshot delete", "harness vm snapshot rollback"},
	"cmd/pveforge/vm_destroy.go":             {"vm destroy"},
	"internal/harness/build/build.go":        {"harness build"},
	"internal/harness/probe/probe.go":        {"harness probe"},
	"internal/harness/reset/reset.go":        {"harness golden", "harness reset"},
	"internal/idempotent/networkbridge.go":   {"network bridge create", "network bridge destroy"},
	"internal/idempotent/networkfields.go":   {"network set"},
	"internal/idempotent/storagecontent.go":  {"storage set-content"},
	"internal/idempotent/storagecreate.go":   {"storage create"},
	"internal/idempotent/storagevolume.go":   {"storage free-orphans"},
	"internal/idempotent/vmclone.go":         {"vm create"},
	"internal/idempotent/vmcreate.go":        {"vm create"},
	"internal/idempotent/vmdestroy.go":       {"vm destroy"},
	"internal/idempotent/vmshutdown.go":      {"harness vm shutdown"},
	"internal/pve/snapshot.go":               {"vm snapshot create", "vm snapshot delete", "vm snapshot rollback"},
	"internal/pve/routed.go":                 nil, // RoutedClient's pass-through to Client: no verb of its own
	"internal/pve/capture_harness_batchc.go": nil, // //go:build harness capture instruments, not a verb
	"internal/pve/capture_harness_rbstop.go": nil,
}

func TestExitRegistry_WaitSitesAreAccountedForByExit3Verbs(t *testing.T) {
	sc, err := lockguard.ScanModule("../..")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]bool{}
	for _, c := range sc.TaskWaits {
		files[c.Ref.File] = true
	}
	if len(files) < 15 {
		t.Fatalf("vacuous: only %d wait files found", len(files))
	}
	for f := range files {
		if _, ok := waitSiteVerbs[f]; !ok {
			t.Errorf("%s waits on a PVE task and no verb accounts for it: add it to waitSiteVerbs with the verbs that reach it (each must list exit 3 in the registry)", f)
		}
	}
	covered := map[string]bool{}
	for f, verbs := range waitSiteVerbs {
		if !files[f] {
			t.Errorf("waitSiteVerbs names %s, which no longer waits on a task", f)
		}
		for _, v := range verbs {
			covered[v] = true
			row, ok := verbExits[v]
			if !ok || !slices.Contains(row.Exits, 3) {
				t.Errorf("%s reaches a task wait (%s) but its registry row does not list exit 3", v, f)
			}
		}
	}
	// every exit-3 verb is reached by a task wait or is a root-SSH-write verb
	for v, row := range verbExits {
		if slices.Contains(row.Exits, 3) && !covered[v] && !strings.Contains(row.WriteKind, "ssh") {
			t.Errorf("%s lists exit 3 but no task-wait site and no root-SSH write accounts for it", v)
		}
	}
}
