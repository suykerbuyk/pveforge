package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

func newNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Inspect nodes",
	}
	cmd.AddCommand(newNodeGetCmd())
	return cmd
}

func newNodeGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id>",
		Short: "Get a node's detailed status",
		Args:  cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}

		client, err := resolveRoutedClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		node, err := client.GetNode(cmd.Context(), client.Node())
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, node)
	}
	return cmd
}
