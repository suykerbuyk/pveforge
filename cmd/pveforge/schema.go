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
// GlobalFlags is only ever populated on the root node, and holds exactly
// the root command's persistent flags — see globalFlags for why that, and
// nothing inferred, is the rule.
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

// buildCommandTreeSchema is `pveforge schema`'s entry point: it takes the
// root's persistent flags as the global set (globalFlags), then walks the
// tree building each node's own schema with those flags omitted from its
// local Flags and attached once, at the root, as GlobalFlags.
func buildCommandTreeSchema(root *cobra.Command) commandSchema {
	global := globalFlags(root)
	schema := buildNodeSchema(root, global)
	schema.GlobalFlags = sortedFlagValues(global)
	return schema
}

// globalFlags returns the flags every command in root's tree accepts: the
// root's own persistent flags, which cobra itself makes every descendant
// inherit. That is the whole rule, and it is correct by construction —
// a flag is listed as global only if the parser really takes it everywhere.
//
// pveforge declares no root persistent flags today (newRootCmd, main.go), so this is
// empty and the schema omits GlobalFlags: --roster and -o/--output are
// registered per command by addRosterFlag/addOutputFlag (target.go), and so
// they appear in each such command's own Flags. That repetition is the
// price of accuracy. An earlier rule hoisted any flag found on two or more
// commands, which listed --management-bridge, --data and --unsafe-no-lock as
// global though only a few commands take them, and listed --lock-wait twice
// because two of its registrations differ in usage text. A caller reading
// GlobalFlags must be able to pass every flag in it to every command.
//
// A flag a GROUP command declares persistent (the roster group's --roster)
// appears in that group node's Flags and applies to every command under it;
// localFlagsExcluding's doc covers why it is not repeated on each child.
func globalFlags(root *cobra.Command) map[string]flagSchema {
	global := map[string]flagSchema{}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == helpFlagName {
			return
		}
		global[flagIdentity(f)] = toFlagSchema(f)
	})
	return global
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
// --help flag and the root persistent flags globalFlags already lists at the
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

// flagIdentity keys a flag by name and usage text together. The global set
// is the root's persistent flags, and cobra lets a command declare its own
// flag under one of their names, which then shadows the root's for that
// command. Keying by usage as well keeps such a command's own flag in its
// Flags rather than dropping it as the global one.
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
	// Name, then usage. The map holds one FlagSet's flags (the root's
	// persistent ones), whose names are unique, so the usage tie-break never
	// decides anything today; it keeps the order total, so it can never fall
	// to map iteration.
	sort.Slice(flags, func(i, j int) bool {
		if flags[i].Name != flags[j].Name {
			return flags[i].Name < flags[j].Name
		}
		return flags[i].Usage < flags[j].Usage
	})
	return flags
}
