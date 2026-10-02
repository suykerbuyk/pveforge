package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

	// vm snapshot (pveforge-vm-snapshot-cli): list reads, create adds,
	// delete and rollback destroy state that cannot be recovered.
	for leaf, want := range map[string]string{
		"list": mutationSafe, "create": mutationMutating,
		"delete": mutationDestructive, "rollback": mutationDestructive,
	} {
		c, ok := findRootPath(t, schema, "vm", "snapshot", leaf)
		if !ok {
			t.Fatalf("vm snapshot %s not found in schema", leaf)
		}
		if c.Mutation != want {
			t.Errorf("vm snapshot %s mutation = %q, want %q", leaf, c.Mutation, want)
		}
	}

	bootstrapCmd, ok := findSubcommand(schema, "bootstrap")
	if !ok {
		t.Fatal("bootstrap not found in schema")
	}
	if bootstrapCmd.Mutation != mutationDestructive {
		t.Errorf("bootstrap mutation = %q, want %q", bootstrapCmd.Mutation, mutationDestructive)
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

	// exec hands a credential to an arbitrary program: the unbounded blast
	// radius mutation.go names as destructive.
	execCmd, ok := findSubcommand(schema, "exec")
	if !ok {
		t.Fatal("exec not found in schema")
	}
	if execCmd.Mutation != mutationDestructive {
		t.Errorf("exec mutation = %q, want %q", execCmd.Mutation, mutationDestructive)
	}

	// 6a: the Ensures are reversible, routine changes; a grant is
	// destructive (what a widened grant was used for cannot be undone).
	for _, c := range []struct {
		path []string
		want string
	}{
		{[]string{"user", "ensure"}, mutationMutating},
		{[]string{"group", "ensure"}, mutationMutating},
		{[]string{"acl", "grant"}, mutationDestructive},
		{[]string{"access", "inventory"}, mutationSafe},
	} {
		got, ok := findRootPath(t, schema, c.path...)
		if !ok {
			t.Fatalf("%v not found in schema", c.path)
		}
		if got.Mutation != c.want {
			t.Errorf("%v mutation = %q, want %q", c.path, got.Mutation, c.want)
		}
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

// TestNewSchemaCmd_FlagsMatchWhatEachCommandAccepts is the schema's flag
// contract, checked against cobra's own parser for every command in the real
// tree: the flags the schema shows for a command — its own Flags, every
// ancestor's Flags (a group's persistent flags apply to its children), and
// the root's GlobalFlags — are exactly the flags that command accepts. It
// fails on a flag listed as global that some command does not take (the
// --management-bridge / --data / --unsafe-no-lock hoist), on a flag a command
// takes that the schema never shows, and on one name listed twice for one
// command (the doubled --lock-wait).
func TestNewSchemaCmd_FlagsMatchWhatEachCommandAccepts(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	schema := buildCommandTreeSchema(root)

	names := func(fs []flagSchema) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Name)
		}
		return out
	}
	global := names(schema.GlobalFlags)
	checked := 0

	var walk func(cmd *cobra.Command, node commandSchema, inherited []string)
	walk = func(cmd *cobra.Command, node commandSchema, inherited []string) {
		shown := append(append([]string(nil), inherited...), names(node.Flags)...)
		seen := map[string]bool{}
		for _, n := range shown {
			if n == helpFlagName {
				t.Errorf("%q: the schema lists cobra's auto-injected --help", cmd.CommandPath())
			}
			if seen[n] {
				t.Errorf("%q: the schema lists --%s more than once", cmd.CommandPath(), n)
			}
			seen[n] = true
		}
		accepted := map[string]bool{}
		for _, fs := range []*pflag.FlagSet{cmd.LocalFlags(), cmd.InheritedFlags()} {
			fs.VisitAll(func(f *pflag.Flag) {
				if f.Name != helpFlagName {
					accepted[f.Name] = true
				}
			})
		}
		for n := range seen {
			if !accepted[n] {
				t.Errorf("%q: the schema shows --%s, which the command does not accept", cmd.CommandPath(), n)
			}
		}
		for n := range accepted {
			if !seen[n] {
				t.Errorf("%q: the command accepts --%s, which the schema never shows for it", cmd.CommandPath(), n)
			}
		}
		checked++

		for _, c := range cmd.Commands() {
			child, ok := findRootPath(t, node, c.Name())
			if !ok {
				t.Errorf("%q has no schema node", c.CommandPath())
				continue
			}
			walk(c, child, shown)
		}
	}
	walk(root, schema, global)

	// ANTI-VACUITY: the walk has to have reached the whole tree, and the
	// commands that motivated this test must be in it.
	if checked < 50 {
		t.Errorf("checked only %d commands; the tree has 50+", checked)
	}
	for _, path := range [][]string{{"network", "bridge", "create"}, {"api", "post"}, {"vm", "get"}} {
		if _, ok := findRootPath(t, schema, path...); !ok {
			t.Errorf("schema has no %v", path)
		}
	}
}

// TestBuildCommandTreeSchema_GlobalFlagsAreTheRootsPersistentFlags pins the
// rule on a synthetic tree:
//   - a root persistent flag is global and is not repeated on the root's
//     own Flags;
//   - a root flag that is NOT persistent is not global (cobra does not pass
//     it to any child), and stays on the root's own Flags;
//   - a flag two commands each declare — even with identical usage, the old
//     hoisting rule's trigger — stays on each of them;
//   - a command's own flag that shadows the root's persistent one under the
//     same name (with its own usage) stays on that command.
func TestBuildCommandTreeSchema_GlobalFlagsAreTheRootsPersistentFlags(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	root.PersistentFlags().String("everywhere", "", "a real global flag")
	root.Flags().String("rootonly", "", "a root flag no child inherits")
	a := &cobra.Command{Use: "a", Run: func(*cobra.Command, []string) {}}
	a.Flags().String("shared", "", "shared usage text")
	b := &cobra.Command{Use: "b", Run: func(*cobra.Command, []string) {}}
	b.Flags().String("shared", "", "shared usage text")
	c := &cobra.Command{Use: "c", Run: func(*cobra.Command, []string) {}}
	c.Flags().String("everywhere", "", "c's own, shadowing the root's")
	root.AddCommand(a, b, c)

	schema := buildCommandTreeSchema(root)
	if len(schema.GlobalFlags) != 1 || schema.GlobalFlags[0].Name != "everywhere" {
		t.Fatalf("GlobalFlags = %+v, want exactly --everywhere", schema.GlobalFlags)
	}
	if len(schema.Flags) != 1 || schema.Flags[0].Name != "rootonly" {
		t.Errorf("root Flags = %+v, want exactly its own non-persistent --rootonly (and not --everywhere, which GlobalFlags lists)", schema.Flags)
	}
	nodeC, ok := findSubcommand(schema, "c")
	if !ok {
		t.Fatal("command c not found")
	}
	if len(nodeC.Flags) != 1 || nodeC.Flags[0].Usage != "c's own, shadowing the root's" {
		t.Errorf("command c Flags = %+v, want its own --everywhere, which shadows the root's", nodeC.Flags)
	}
	for _, name := range []string{"a", "b"} {
		node, ok := findSubcommand(schema, name)
		if !ok {
			t.Fatalf("command %s not found", name)
		}
		if len(node.Flags) != 1 || node.Flags[0].Name != "shared" {
			t.Errorf("command %s Flags = %+v, want its own --shared", name, node.Flags)
		}
	}
}

// TestNewSchemaCmd_RealTreeHasNoGlobalFlags: pveforge declares no root
// persistent flags, so the schema lists none as global and --roster and
// --output appear on each command that takes them. A root persistent flag
// added later belongs in GlobalFlags; update this test when one is.
func TestNewSchemaCmd_RealTreeHasNoGlobalFlags(t *testing.T) {
	root := newRootCmd()
	root.AddCommand(newSchemaCmd())
	schema := buildCommandTreeSchema(root)
	if len(schema.GlobalFlags) != 0 {
		t.Errorf("GlobalFlags = %+v, want none: newRootCmd declares no persistent flags", schema.GlobalFlags)
	}
	vmGet, ok := findRootPath(t, schema, "vm", "get")
	if !ok {
		t.Fatal("vm get not found")
	}
	got := map[string]bool{}
	for _, f := range vmGet.Flags {
		got[f.Name] = true
	}
	if !got["roster"] || !got["output"] {
		t.Errorf("vm get's Flags = %+v, want --roster and --output on it", vmGet.Flags)
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

func TestSortedFlagValues_Empty(t *testing.T) {
	if got := sortedFlagValues(map[string]flagSchema{}); got != nil {
		t.Errorf("expected nil for an empty map, got %+v", got)
	}
}

// TestBuildNodeSchema_GroupCommandHasNoMutation: a group carries no tier.
// The vm group IS Runnable — refuseUnknownSubcommands gives every group the
// RunE bareGroup, which prints its help to stderr and exits 1 — so
// buildNodeSchema does read its annotation; nothing sets one on a group, and
// the schema reports none. It uses findRootPath (an exact
// parent/child path), not the ambiguous name-only findSubcommand:
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
		t.Errorf("expected the vm group command to have no Mutation, got %q", vmGroup.Mutation)
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

	for _, want := range []string{`"name"`, `"use"`, `"mutation"`, `"flags"`, `"subcommands"`, `"vm"`, `"discover"`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("expected output to contain %s, got:\n%s", want, out.String())
		}
	}
}

// TestSortedFlagValues_SameNameOrderIsDeterministic: sortedFlagValues's
// order is total. Given two entries with one name and different usage,
// which one FlagSet cannot hold today, they still come out in the same order
// every time, not in map-iteration order. Repeated, since a name-only sort
// passes by luck on any single run.
func TestSortedFlagValues_SameNameOrderIsDeterministic(t *testing.T) {
	m := map[string]flagSchema{}
	for _, u := range []string{"usage b", "usage a", "usage c"} {
		m["lock-wait\x00"+u] = flagSchema{Name: "lock-wait", Usage: u}
	}
	m["roster\x00r"] = flagSchema{Name: "roster", Usage: "r"}
	for i := 0; i < 50; i++ {
		var got []string
		for _, f := range sortedFlagValues(m) {
			got = append(got, f.Name+"/"+f.Usage)
		}
		if want := "lock-wait/usage a,lock-wait/usage b,lock-wait/usage c,roster/r"; strings.Join(got, ",") != want {
			t.Fatalf("run %d: order %v, want %s", i, got, want)
		}
	}
}

// cobraBuiltinPaths are the runnable commands cobra adds itself
// (InitDefaultHelpCmd, InitDefaultCompletionCmd). pveforge does not own
// them, so they carry no tier, and the schema reports none for them; a
// caller treats that as unknown (commandSchema's doc).
var cobraBuiltinPaths = map[string]bool{
	"pveforge help":                  true,
	"pveforge completion bash":       true,
	"pveforge completion fish":       true,
	"pveforge completion powershell": true,
	"pveforge completion zsh":        true,
}

// TestEveryRunnableCommandCarriesATier: every runnable leaf command pveforge
// defines is annotated safe, mutating or destructive, so `pveforge schema`
// never reports a pveforge command's tier as unknown. Listing named commands
// (TestNewSchemaCmd_KnownCommandMutationLevels) cannot catch a command that
// was never annotated, which is how roster import-token shipped with none.
func TestEveryRunnableCommandCarriesATier(t *testing.T) {
	root := newRootCmd()
	valid := map[string]bool{mutationSafe: true, mutationMutating: true, mutationDestructive: true}
	checked, builtins := 0, 0

	var walk func(cmd *cobra.Command)
	walk = func(cmd *cobra.Command) {
		for _, c := range cmd.Commands() {
			walk(c)
		}
		// A group (root included) is Runnable only so that running it bare
		// prints its usage and exits 1; it does nothing else, so it has no
		// tier.
		if !cmd.Runnable() || cmd.HasSubCommands() {
			return
		}
		if cobraBuiltinPaths[cmd.CommandPath()] {
			builtins++
			return
		}
		checked++
		if tier := cmd.Annotations[mutationAnnotationKey]; !valid[tier] {
			t.Errorf("%q carries mutation tier %q; mark it with markSafe, markMutating or markDestructive", cmd.CommandPath(), tier)
		}
	}
	walk(root)

	// ANTI-VACUITY: the walk reached the tree, and every exemption names a
	// command that really exists (a stale exemption would hide nothing, but
	// a renamed pveforge command must never inherit one).
	if checked < 35 {
		t.Errorf("checked only %d runnable leaf commands; pveforge has 35", checked)
	}
	if builtins != len(cobraBuiltinPaths) {
		t.Errorf("found %d of the %d cobra built-ins exempted here; the exemption list is stale", builtins, len(cobraBuiltinPaths))
	}
}

// TestRosterImportTokenIsDestructive pins the tier this command was missing:
// --replace discards the roster's only copy of the held token's secret.
func TestRosterImportTokenIsDestructive(t *testing.T) {
	schema := buildCommandTreeSchema(newRootCmd())
	cmd, ok := findRootPath(t, schema, "roster", "import-token")
	if !ok {
		t.Fatal("roster import-token not found in schema")
	}
	if cmd.Mutation != mutationDestructive {
		t.Errorf("roster import-token mutation = %q, want %q", cmd.Mutation, mutationDestructive)
	}
}
