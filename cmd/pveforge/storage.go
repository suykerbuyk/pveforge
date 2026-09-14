package main

import (
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

func newStorageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Inspect storage backends",
	}
	cmd.AddCommand(newStorageGetCmd())
	return cmd
}

func newStorageGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id> <storage-name>",
		Short: "Get one storage backend's status",
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

		storage, err := client.GetStorage(cmd.Context(), client.Node(), args[1])
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, storage)
	}
	return cmd
}
