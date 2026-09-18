package main

import (
	"fmt"

	"github.com/spf13/cobra"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

func newStorageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Inspect storage backends",
	}
	cmd.AddCommand(newStorageGetCmd())
	cmd.AddCommand(newStorageOrphansCmd())
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

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}
		unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "storage", ID: args[1]})
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		storage, err := client.GetStorage(cmd.Context(), client.Node(), args[1])
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, storage)
	}
	markSafe(cmd)
	return cmd
}

// newStorageOrphansCmd wires pveforge-storage-orphan-scan's
// Client.OrphanVolumes: with a storage-name given, a single-storage scan
// under that storage's own read lock; without one, GetStorages first,
// skipping any storage reporting Enabled == 0, then a scan (each under its
// own read lock) per remaining storage. A GetStorages failure aborts the
// whole command rather than silently reporting zero storages scanned.
func newStorageOrphansCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "orphans <target-id> [storage-name]",
		Short: "Diff claimed-vs-actual storage volumes for orphans",
		Args:  cobra.RangeArgs(1, 2),
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

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}

		node := client.Node()

		var storageNames []string
		if len(args) == 2 {
			storageNames = []string{args[1]}
		} else {
			storages, err := client.GetStorages(cmd.Context(), node)
			if err != nil {
				return err
			}
			for _, s := range storages {
				if s.Enabled == 0 {
					continue
				}
				storageNames = append(storageNames, s.Name)
			}
		}

		var orphans []*proxmox.StorageContent
		for _, storageName := range storageNames {
			unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "storage", ID: storageName})
			if err != nil {
				return fmt.Errorf("acquire read lock: %w", err)
			}
			found, err := client.OrphanVolumes(cmd.Context(), node, storageName)
			unlockErr := unlock()
			if err != nil {
				return err
			}
			if unlockErr != nil {
				return fmt.Errorf("release read lock: %w", unlockErr)
			}
			orphans = append(orphans, found...)
		}
		if orphans == nil {
			orphans = []*proxmox.StorageContent{}
		}

		// kvjson.Render requires a JSON object at its top level (a bare
		// slice is documented as unsupported — see kvjson.go's own doc
		// comment) — wrap the list under one field rather than passing it
		// directly.
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]interface{}{"orphans": orphans})
	}
	markSafe(cmd)
	return cmd
}
