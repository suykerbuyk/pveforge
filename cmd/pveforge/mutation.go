package main

import "github.com/spf13/cobra"

// mutationAnnotationKey is the cobra Command.Annotations key pveforge's
// own mutation tier is recorded under (see markSafe/markMutating/
// markDestructive below and schema.go, which reads it back to build
// `pveforge schema`'s output). A plain string key, not a typed constant
// from some shared enum package: cobra's Annotations field is itself
// just map[string]string, matching the convention cobra's own ecosystem
// already uses for this kind of out-of-band per-command metadata (e.g.
// cobra.Command's BashCompOneRequiredFlag annotation key).
const mutationAnnotationKey = "pveforge/mutation"

// The three mutation tiers a runnable command can carry — see
// docs/prd.md §3.5 Layer 3 and the pveforge-cli-self-schema task this
// implements for the full definitions, surfaced by reviewing
// davegallant/pvectl (GPL-3.0, idea only — this project's own tiers and
// their assignment below are independently reasoned from pveforge's
// actual command list, not copied):
//   - mutationSafe: read-only, never changes state (PVE-side or local).
//   - mutationMutating: changes state, but reversibly and routinely — a
//     normal, expected part of operating pveforge (setting a VM field,
//     bootstrapping a target).
//   - mutationDestructive: a point of no return (irreversible) or an
//     unbounded blast radius (pvectl's own example: a command that hands
//     off to arbitrary execution) — not "changes more state than
//     mutating," but state a caller cannot get back once it's gone.
const (
	mutationSafe        = "safe"
	mutationMutating    = "mutating"
	mutationDestructive = "destructive"
)

// markSafe, markMutating, and markDestructive annotate cmd with its
// mutation tier. Shaped to match addRosterFlag/addOutputFlag in
// target.go: a small, named function a command's own constructor calls
// once, rather than every constructor poking cmd.Annotations directly.
func markSafe(cmd *cobra.Command)        { setMutation(cmd, mutationSafe) }
func markMutating(cmd *cobra.Command)    { setMutation(cmd, mutationMutating) }
func markDestructive(cmd *cobra.Command) { setMutation(cmd, mutationDestructive) }

func setMutation(cmd *cobra.Command, level string) {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[mutationAnnotationKey] = level
}
