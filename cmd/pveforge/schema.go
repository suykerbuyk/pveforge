package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// newSchemaCmd is PRD §3.5 Layer 3 (pveforge-cli-self-schema): a
// `pveforge schema` command that walks pveforge's own cobra command tree
// and prints it as JSON — name/use/aliases/short/flags/mutation/
// subcommands — so a calling agent can introspect pveforge's own surface
// without parsing --help text or hardcoding per-command knowledge. Idea
// surfaced by reviewing davegallant/pvectl (GPL-3.0 — read for the idea
// only; this command's shape below is reimplemented from scratch against
// pveforge's own command tree, no pvectl code was used).
//
// Purely local: unlike vm/node/storage/network/discover, it never
// resolves a roster or talks to a PVE host, so it takes neither --roster
// nor -o/--output. Output is always JSON — the only shape that makes
// sense for a recursive command tree (kvjson.Render's KV mode is defined
// for a single flat object, not a nested tree with an array field, so
// this deliberately doesn't reuse it).
func newSchemaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schema",
		Short: "Print pveforge's own command tree — names, flags, and mutation levels — as JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := json.MarshalIndent(buildCommandTreeSchema(cmd.Root()), "", "  ")
			if err != nil {
				return fmt.Errorf("schema: marshal: %w", err)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return err
		},
	}
	markSafe(cmd)
	return cmd
}

// flagSchema is one flag's shape in `pveforge schema`'s output.
type flagSchema struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Usage     string `json:"usage"`
	Default   string `json:"default,omitempty"`
}

// commandSchema is one cobra command's shape in `pveforge schema`'s
// output.
//
// Mutation is only ever populated for a Runnable command (see
// markSafe/markMutating/markDestructive in mutation.go), and even then
// only if that command was actually annotated — a Runnable cobra
// built-in this project never annotates (cobra's own auto-added `help`
// and `completion` commands) simply omits the field. A caller MUST treat
// an absent Mutation on a Runnable command as unknown, never assume safe
// by default.
//
// GlobalFlags is only ever populated on the root node — see
// collectGlobalFlags's own doc comment for why a flag ends up there
// instead of in the owning command's own Flags.
type commandSchema struct {
	Name        string          `json:"name"`
	Use         string          `json:"use"`
	Aliases     []string        `json:"aliases,omitempty"`
	Short       string          `json:"short,omitempty"`
	Mutation    string          `json:"mutation,omitempty"`
	Flags       []flagSchema    `json:"flags,omitempty"`
	GlobalFlags []flagSchema    `json:"globalFlags,omitempty"`
	Subcommands []commandSchema `json:"subcommands,omitempty"`
}

// helpFlagName is cobra's own auto-injected --help/-h flag, added to
// every single command in the tree (root included) the first time that
// command's flag set is accessed. It isn't part of pveforge's own
// surface, so schema output excludes it everywhere: including it on every
// one of this tree's dozen-plus nodes would be pure repetitive noise for
// a calling agent, not information.
const helpFlagName = "help"

// globalFlagOccurrenceThreshold is how many distinct commands a flag —
// identified by flagIdentity (name+usage), not name alone — must appear
// on before collectGlobalFlags treats it as global and hoists it to the
// schema's root GlobalFlags instead of repeating it on every owning node.
//
// pveforge has no PersistentFlags declared on the root command itself
// (see main.go): --roster and -o/--output are instead registered
// independently on nearly every leaf command via addRosterFlag/
// addOutputFlag (target.go). So "global" here is inferred from actual
// recurrence across the tree, not read off cobra's own PersistentFlags
// mechanism, which this project doesn't use for these two flags.
const globalFlagOccurrenceThreshold = 2

// buildCommandTreeSchema is `pveforge schema`'s entry point: it computes
// which flags recur often enough across root's tree to be "global"
// (collectGlobalFlags), then walks the tree once more building each
// node's own schema with those flags omitted from its local Flags and
// attached once, at the root, as GlobalFlags.
func buildCommandTreeSchema(root *cobra.Command) commandSchema {
	global := collectGlobalFlags(root)
	schema := buildNodeSchema(root, global)
	schema.GlobalFlags = sortedFlagValues(global)
	return schema
}

// buildNodeSchema recursively builds cmd's own commandSchema and every
// descendant's, sorting Subcommands and Flags by name so the same tree
// always serializes identically — no dependence on cobra's own internal
// command/flag ordering.
func buildNodeSchema(cmd *cobra.Command, global map[string]flagSchema) commandSchema {
	node := commandSchema{
		Name:  cmd.Name(),
		Use:   cmd.Use,
		Short: cmd.Short,
		Flags: localFlagsExcluding(cmd, global),
	}
	if len(cmd.Aliases) > 0 {
		node.Aliases = append([]string(nil), cmd.Aliases...)
	}
	if cmd.Runnable() {
		node.Mutation = cmd.Annotations[mutationAnnotationKey]
	}

	children := cmd.Commands()
	if len(children) > 0 {
		sub := make([]commandSchema, 0, len(children))
		for _, c := range children {
			sub = append(sub, buildNodeSchema(c, global))
		}
		sort.Slice(sub, func(i, j int) bool { return sub[i].Name < sub[j].Name })
		node.Subcommands = sub
	}
	return node
}

// localFlagsExcluding returns cmd's own LocalFlags (never flags it only
// inherited from a parent's PersistentFlags — those show up on the
// ancestor that actually declared them instead), skipping the auto-added
// --help flag and anything collectGlobalFlags already promoted to the
// schema's root.
func localFlagsExcluding(cmd *cobra.Command, global map[string]flagSchema) []flagSchema {
	var flags []flagSchema
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == helpFlagName {
			return
		}
		if _, isGlobal := global[flagIdentity(f)]; isGlobal {
			return
		}
		flags = append(flags, toFlagSchema(f))
	})
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}

// collectGlobalFlags walks root's entire command tree once, tallying
// each flag identity's (flagIdentity) occurrence across distinct
// commands, and returns the ones that meet globalFlagOccurrenceThreshold
// — e.g. --roster (registered separately by addRosterFlag on nearly
// every vm/node/storage/network/discover/bootstrap command, and again as
// a PersistentFlag on the `roster` group command itself) and -o/--output
// (registered by addOutputFlag on every read/discover command). Keyed by
// flagIdentity so buildNodeSchema/localFlagsExcluding can test membership
// cheaply; the returned map's values are only ever read via
// sortedFlagValues for the final, deterministic GlobalFlags list.
func collectGlobalFlags(root *cobra.Command) map[string]flagSchema {
	counts := map[string]int{}
	seen := map[string]flagSchema{}
	walkCommands(root, func(cmd *cobra.Command) {
		cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Name == helpFlagName {
				return
			}
			key := flagIdentity(f)
			counts[key]++
			seen[key] = toFlagSchema(f)
		})
	})

	global := map[string]flagSchema{}
	for key, n := range counts {
		if n >= globalFlagOccurrenceThreshold {
			global[key] = seen[key]
		}
	}
	return global
}

// walkCommands visits cmd and every descendant, depth-first.
func walkCommands(cmd *cobra.Command, visit func(*cobra.Command)) {
	visit(cmd)
	for _, c := range cmd.Commands() {
		walkCommands(c, visit)
	}
}

// flagIdentity is how collectGlobalFlags recognizes "the same flag
// repeated across commands" rather than merely a same-named coincidence:
// name alone isn't enough — roster.go's `roster init --force` and any
// hypothetical future unrelated --force flag elsewhere would collide on
// name alone despite meaning different things, so identity also requires
// identical usage text. In practice, the shared flags in this codebase
// (addRosterFlag/addOutputFlag) already register identical usage text at
// every call site by construction, so this never under-matches them.
func flagIdentity(f *pflag.Flag) string {
	return f.Name + "\x00" + f.Usage
}

func toFlagSchema(f *pflag.Flag) flagSchema {
	return flagSchema{
		Name:      f.Name,
		Shorthand: f.Shorthand,
		Type:      f.Value.Type(),
		Usage:     f.Usage,
		Default:   f.DefValue,
	}
}

func sortedFlagValues(m map[string]flagSchema) []flagSchema {
	if len(m) == 0 {
		return nil
	}
	flags := make([]flagSchema, 0, len(m))
	for _, f := range m {
		flags = append(flags, f)
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}
