package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// findSubcommand is a small test helper: depth-first search for a
// commandSchema node by exact Name, since Subcommands is a nested tree,
// not a flat map.
func findSubcommand(node commandSchema, name string) (commandSchema, bool) {
	if node.Name == name {
		return node, true
	}
	for _, c := range node.Subcommands {
		if found, ok := findSubcommand(c, name); ok {
			return found, true
		}
	}
	return commandSchema{}, false
}

func TestNewSchemaCmd_PrintsValidJSON(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"schema"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var got commandSchema
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput:\n%s", err, out.String())
	}
	if got.Name != "pveforge" {
		t.Errorf("root Name = %q, want %q", got.Name, "pveforge")
	}
}

// TestNewSchemaCmd_KnownCommandMutationLevels proves specific, previously
// classified commands surface the right mutation tier through the real
// annotation mechanism (mutation.go) — not just that *some* string shows
// up, but the *correct* one for a safe, a mutating, and a destructive
// command each.
func TestNewSchemaCmd_KnownCommandMutationLevels(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	schema := buildCommandTreeSchema(root)

	// Path-based lookups, not a bare name search: several distinct
	// commands share a leaf name ("get" under vm/node/storage/network),
	// so disambiguating by parent path is required.
	vmCmd, ok := findRootPath(t, schema, "vm", "get")
	if !ok {
		t.Fatal("vm get not found in schema")
	}
	if vmCmd.Mutation != mutationSafe {
		t.Errorf("vm get mutation = %q, want %q", vmCmd.Mutation, mutationSafe)
	}

	vmSet, ok := findRootPath(t, schema, "vm", "set")
	if !ok {
		t.Fatal("vm set not found in schema")
	}
	if vmSet.Mutation != mutationMutating {
		t.Errorf("vm set mutation = %q, want %q", vmSet.Mutation, mutationMutating)
	}

	bootstrapCmd, ok := findSubcommand(schema, "bootstrap")
	if !ok {
		t.Fatal("bootstrap not found in schema")
	}
	if bootstrapCmd.Mutation != mutationMutating {
		t.Errorf("bootstrap mutation = %q, want %q", bootstrapCmd.Mutation, mutationMutating)
	}

	rosterInit, ok := findRootPath(t, schema, "roster", "init")
	if !ok {
		t.Fatal("roster init not found in schema")
	}
	if rosterInit.Mutation != mutationDestructive {
		t.Errorf("roster init mutation = %q, want %q", rosterInit.Mutation, mutationDestructive)
	}

	rosterValidate, ok := findRootPath(t, schema, "roster", "validate")
	if !ok {
		t.Fatal("roster validate not found in schema")
	}
	if rosterValidate.Mutation != mutationSafe {
		t.Errorf("roster validate mutation = %q, want %q", rosterValidate.Mutation, mutationSafe)
	}

	schemaCmd, ok := findSubcommand(schema, "schema")
	if !ok {
		t.Fatal("schema not found in schema")
	}
	if schemaCmd.Mutation != mutationSafe {
		t.Errorf("schema mutation = %q, want %q", schemaCmd.Mutation, mutationSafe)
	}
}

// findRootPath walks a specific parent/child path (e.g. "vm", "get")
// rather than a bare depth-first name search, since several distinct
// commands share a leaf name ("get" under vm/node/storage/network,
// "config"/"status" under discover's verbs) and a name-only search would
// be ambiguous about which one it found.
func findRootPath(t *testing.T, root commandSchema, path ...string) (commandSchema, bool) {
	t.Helper()
	cur := root
	for _, name := range path {
		next, ok := func() (commandSchema, bool) {
			for _, c := range cur.Subcommands {
				if c.Name == name {
					return c, true
				}
			}
			return commandSchema{}, false
		}()
		if !ok {
			return commandSchema{}, false
		}
		cur = next
	}
	return cur, true
}

// TestNewSchemaCmd_GlobalFlagsNotDuplicated proves --roster and
// -o/--output — registered independently on nearly every leaf command via
// addRosterFlag/addOutputFlag — are hoisted to the root's GlobalFlags
// exactly once each, and do NOT also appear in any individual command's
// own Flags list.
func TestNewSchemaCmd_GlobalFlagsNotDuplicated(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	schema := buildCommandTreeSchema(root)

	rosterCount := 0
	outputCount := 0
	for _, f := range schema.GlobalFlags {
		switch f.Name {
		case "roster":
			rosterCount++
		case "output":
			outputCount++
		}
	}
	if rosterCount != 1 {
		t.Errorf("expected exactly one --roster entry in GlobalFlags, got %d", rosterCount)
	}
	if outputCount != 1 {
		t.Errorf("expected exactly one --output entry in GlobalFlags, got %d", outputCount)
	}

	// Every command that actually registers --roster/--output locally
	// must NOT repeat them in its own Flags — that's the entire point of
	// hoisting them to GlobalFlags in the first place.
	var walk func(node commandSchema)
	walk = func(node commandSchema) {
		for _, f := range node.Flags {
			if f.Name == "roster" || f.Name == "output" {
				t.Errorf("command %q's own Flags still lists global flag %q — should have been hoisted to GlobalFlags only", node.Name, f.Name)
			}
			if f.Name == helpFlagName {
				t.Errorf("command %q's Flags includes the auto-injected --help flag, which should always be excluded", node.Name)
			}
		}
		for _, c := range node.Subcommands {
			walk(c)
		}
	}
	walk(schema)

	vmSet, ok := findRootPath(t, schema, "vm", "set")
	if !ok {
		t.Fatal("vm set not found in schema")
	}
	foundJSON := false
	for _, f := range vmSet.Flags {
		if f.Name == "json" {
			foundJSON = true
		}
	}
	if !foundJSON {
		t.Errorf("vm set's own --json flag should still appear in its local Flags (it isn't global), got %+v", vmSet.Flags)
	}
}

// TestNewSchemaCmd_UnannotatedCobraBuiltinsDoNotCrash proves cobra's own
// auto-added `help` and `completion` commands — never annotated by this
// project's markSafe/markMutating/markDestructive — walk cleanly with an
// empty Mutation rather than panicking or erroring, since buildNodeSchema
// reads cmd.Annotations[mutationAnnotationKey] on every Runnable command
// unconditionally.
func TestNewSchemaCmd_UnannotatedCobraBuiltinsDoNotCrash(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	// Executing (rather than calling buildCommandTreeSchema directly on a
	// freshly-built, never-executed root) is what actually causes cobra to
	// lazily add its own `help` and `completion` commands via
	// InitDefaultHelpCmd/InitDefaultCompletionCmd inside ExecuteC — the
	// same path a real `pveforge schema` invocation goes through.
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"schema"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var schema commandSchema
	if err := json.Unmarshal(out.Bytes(), &schema); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	help, ok := findSubcommand(schema, "help")
	if !ok {
		t.Fatal("expected cobra's auto-added help command in the schema output")
	}
	if help.Mutation != "" {
		t.Errorf("expected help's Mutation to be empty (unannotated), got %q", help.Mutation)
	}

	if completion, ok := findSubcommand(schema, "completion"); ok {
		if completion.Mutation != "" {
			t.Errorf("expected completion's Mutation to be empty (unannotated), got %q", completion.Mutation)
		}
	}
}

func TestNewSchemaCmd_DeterministicOrdering(t *testing.T) {
	root1 := newRootCmd()
	root1.AddCommand(newSchemaCmd())
	root2 := newRootCmd()
	root2.AddCommand(newSchemaCmd())

	s1, err := json.Marshal(buildCommandTreeSchema(root1))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s2, err := json.Marshal(buildCommandTreeSchema(root2))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(s1) != string(s2) {
		t.Error("buildCommandTreeSchema produced non-deterministic output across two independently-built command trees")
	}
}

func TestNewSchemaCmd_NoArgsRejected(t *testing.T) {
	cmd := newSchemaCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"unexpected-arg"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an unexpected positional argument")
	}
}

func TestFlagIdentity_DistinguishesSameNameDifferentUsage(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	a := &cobra.Command{Use: "a", Run: func(*cobra.Command, []string) {}}
	a.Flags().Bool("force", false, "force A")
	b := &cobra.Command{Use: "b", Run: func(*cobra.Command, []string) {}}
	b.Flags().Bool("force", false, "force B")
	root.AddCommand(a, b)

	global := collectGlobalFlags(root)
	if len(global) != 0 {
		t.Errorf("expected --force on a and b to NOT be merged as global (different usage text), got %+v", global)
	}
}

func TestFlagIdentity_MergesSameNameSameUsage(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	a := &cobra.Command{Use: "a", Run: func(*cobra.Command, []string) {}}
	a.Flags().String("roster", "", "shared usage text")
	b := &cobra.Command{Use: "b", Run: func(*cobra.Command, []string) {}}
	b.Flags().String("roster", "", "shared usage text")
	root.AddCommand(a, b)

	global := collectGlobalFlags(root)
	if len(global) != 1 {
		t.Fatalf("expected exactly one global flag, got %d: %+v", len(global), global)
	}

	schema := buildCommandTreeSchema(root)
	nodeA, ok := findSubcommand(schema, "a")
	if !ok {
		t.Fatal("command a not found")
	}
	for _, f := range nodeA.Flags {
		if f.Name == "roster" {
			t.Error("expected --roster to be hoisted out of a's own Flags once it's global")
		}
	}
}

func TestSortedFlagValues_Empty(t *testing.T) {
	if got := sortedFlagValues(map[string]flagSchema{}); got != nil {
		t.Errorf("expected nil for an empty map, got %+v", got)
	}
}

// TestBuildNodeSchema_GroupCommandHasNoMutation uses findRootPath (an
// exact parent/child path), not the ambiguous name-only findSubcommand:
// "vm" also names a leaf command nested under "discover" (discover vm),
// which IS Runnable and annotated safe — a bare depth-first name search
// would find that one first and give a false pass/fail here.
func TestBuildNodeSchema_GroupCommandHasNoMutation(t *testing.T) {
	root := newRootCmd()
	schema := buildCommandTreeSchema(root)

	vmGroup, ok := findRootPath(t, schema, "vm")
	if !ok {
		t.Fatal("vm group command not found")
	}
	if vmGroup.Mutation != "" {
		t.Errorf("expected the non-runnable vm group command to have no Mutation, got %q", vmGroup.Mutation)
	}
}

func TestNewSchemaCmd_OutputContainsExpectedFields(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"schema"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	for _, want := range []string{`"name"`, `"use"`, `"mutation"`, `"globalFlags"`, `"subcommands"`, `"vm"`, `"discover"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected output to contain %s, got:\n%s", want, out.String())
		}
	}
}
