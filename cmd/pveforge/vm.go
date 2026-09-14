package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

func newVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Inspect and modify VMs",
	}
	cmd.AddCommand(newVMGetCmd())
	cmd.AddCommand(newVMSetCmd())
	return cmd
}

func newVMGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id> <vmid>",
		Short: "Get a VM's status and config",
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid vmid %q: %w", args[1], err)
		}

		client, err := resolveRoutedClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}
		unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)})
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		vm, err := client.GetVM(cmd.Context(), client.Node(), vmid)
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, vm)
	}
	markSafe(cmd)
	return cmd
}

func newVMSetCmd() *cobra.Command {
	var jsonBody, jsonFile string

	cmd := &cobra.Command{
		Use:   "set <target-id> <vmid> [field=value ...]",
		Short: "Set one or more VM config fields",
		Long: `Set one or more VM config fields, via exactly one of:
  - trailing field=value positional arguments
  - --json '{"field":"value",...}'
  - --json-file path/to/fields.json

Fields are applied in order (positional: as given; JSON: sorted by key).
Applying stops at the first failure — earlier fields in the same
invocation have already been applied and are not rolled back.

The whole batch is applied as one idempotent-mutation-engine cycle
(internal/idempotent.VMFieldsEnsure), serialized against every other
pveforge-managed mutation on this VM for its full duration
(internal/lock.Mutation) — never two concurrent pveforge mutations on the
same VM in flight at once. A field already at its wanted value is left
untouched (no write attempted) and prints no confirmation line; output is
a summary of only the fields that actually changed, printed once the
whole batch resolves rather than streamed as each field applies.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kvArgs := args[2:]

			modes := 0
			if len(kvArgs) > 0 {
				modes++
			}
			if jsonBody != "" {
				modes++
			}
			if jsonFile != "" {
				modes++
			}
			if modes != 1 {
				return fmt.Errorf("specify exactly one of: field=value arguments, --json, or --json-file")
			}

			var pairs []kvjson.Pair
			var err error
			switch {
			case len(kvArgs) > 0:
				pairs, err = kvjson.ParseKVArgs(kvArgs)
			case jsonBody != "":
				pairs, err = kvjson.ParseJSONFields([]byte(jsonBody))
			case jsonFile != "":
				var data []byte
				data, err = os.ReadFile(jsonFile)
				if err != nil {
					return fmt.Errorf("read %s: %w", jsonFile, err)
				}
				pairs, err = kvjson.ParseJSONFields(data)
			}
			if err != nil {
				return err
			}

			vmid, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid vmid %q: %w", args[1], err)
			}

			client, err := resolveRoutedClient(cmd, args[0])
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}

			key := lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)}
			op := &idempotent.VMFieldsEnsure{Client: client, VMID: vmid, Pairs: pairs}

			// Explicit, ahead of Run: idempotent.Run calls Satisfied
			// before Apply, and if the batch already matches current
			// state, Apply — and therefore its own internal Validate()
			// call — never runs at all, silently bypassing the
			// documented "no duplicate field name" contract for an
			// already-satisfied batch (e.g. the same field=value pair
			// given twice, where that value already matches). Never push
			// this into idempotent.Run itself — shared infrastructure
			// VMTagEnsure/BridgeIsolationEnsure also use, out of scope
			// here.
			if err := op.Validate(); err != nil {
				return err
			}

			if _, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false); err != nil {
				return err
			}
			return printAppliedFields(cmd.OutOrStdout(), args[0], op.Applied, pairs)
		},
	}
	addRosterFlag(cmd)
	cmd.Flags().StringVar(&jsonBody, "json", "", "JSON object of field=value pairs (values must be JSON strings)")
	cmd.Flags().StringVar(&jsonFile, "json-file", "", "path to a JSON file of field=value pairs (values must be JSON strings)")
	markMutating(cmd)
	return cmd
}

// printAppliedFields prints one confirmation line per field name in
// applied — VMFieldsEnsure.Applied, populated by Apply itself as it
// writes each field — looking up each one's wanted value from pairs.
// Deliberately does NOT diff idempotent.Result's Before/After: that
// used to be this function's whole approach, but Result.After silently
// falls back to equaling Result.Before whenever idempotent.Run's own
// best-effort post-Apply re-read fails (Run's own documented behavior —
// Changed stays true, the write genuinely succeeded), which made a
// diff-based reconstruction print nothing at all for a real, successful
// write — indistinguishable from a no-op, with no error either. Applied
// is populated directly by the write that happened, not reconstructed
// after the fact from two snapshots that might not disagree even when
// something changed.
//
// applied is already in the order Apply wrote them (a subset of pairs,
// in pairs' own relative order — see Apply), so no separate ordering step
// is needed here.
func printAppliedFields(out io.Writer, targetID string, applied []string, pairs []kvjson.Pair) error {
	wanted := make(map[string]string, len(pairs))
	for _, p := range pairs {
		wanted[p.Field] = p.Value
	}
	for _, field := range applied {
		if _, err := fmt.Fprintf(out, "%s: %s=%s\n", targetID, field, wanted[field]); err != nil {
			return err
		}
	}
	return nil
}
