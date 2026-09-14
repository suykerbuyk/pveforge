package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
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

		vm, err := client.GetVM(cmd.Context(), client.Node(), vmid)
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, vm)
	}
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
invocation have already been applied and are not rolled back.`,
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

			out := cmd.OutOrStdout()
			for i, p := range pairs {
				if err := client.SetVMConfigField(cmd.Context(), vmid, p.Field, p.Value); err != nil {
					return fmt.Errorf("set field %d/%d (%q): %w", i+1, len(pairs), p.Field, err)
				}
				fmt.Fprintf(out, "%s: %s=%s\n", args[0], p.Field, p.Value)
			}
			return nil
		},
	}
	addRosterFlag(cmd)
	cmd.Flags().StringVar(&jsonBody, "json", "", "JSON object of field=value pairs (values must be JSON strings)")
	cmd.Flags().StringVar(&jsonFile, "json-file", "", "path to a JSON file of field=value pairs (values must be JSON strings)")
	return cmd
}
