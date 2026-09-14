package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Inspect node-level network interfaces",
	}
	cmd.AddCommand(newNetworkGetCmd())
	return cmd
}

func newNetworkGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id> <iface>",
		Short: "Get one network interface's config",
		Args:  cobra.ExactArgs(2),
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

		nw, err := client.GetNetworkInterface(cmd.Context(), client.Node(), args[1])
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, nw)
	}
	return cmd
}
