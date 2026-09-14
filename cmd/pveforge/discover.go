package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/discover"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
)

// newDiscoverCmd is pveforge-discoverability-schema's (PRD §3.5) CLI
// entry point: `vm`/`node`/`storage`/`network` describe PVE's own
// object-model schema (layer 1, internal/discover.PVEObjectSchema,
// proxying PVE's static apidoc.js — see pve.Client.APIDocTree's doc
// comment for why that replaced this task's original OPTIONS-based
// design); `device` describes pveforge's own hand-authored
// device-semantic schemas (layer 2, internal/discover.DeviceSchemas),
// purely locally.
//
// Deliberately does NOT wrap its reads in internal/lock.Read the way
// vm/node/storage/network's own `get` commands do: those lock a specific
// PVE OBJECT (a given vmid, node, storage name, iface) against a
// concurrent mutation of that same object, but discover describes PVE's
// own SCHEMA for a class of object in general — it names no specific
// object instance (the tree is indexed by literal templated paths like
// "/nodes/{node}/qemu/{vmid}/config", never a real vmid), so there is no
// obvious internal/lock.ObjectKey for it to take. Left as an open
// question rather than forcing a key that doesn't actually name anything
// concurrent mutations would collide with.
func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Describe PVE's own object schema (layer 1) or a pveforge device type (layer 2)",
	}
	cmd.AddCommand(newDiscoverVMCmd())
	cmd.AddCommand(newDiscoverNodeCmd())
	cmd.AddCommand(newDiscoverStorageCmd())
	cmd.AddCommand(newDiscoverNetworkCmd())
	cmd.AddCommand(newDiscoverDeviceCmd())
	return cmd
}

// runDiscoverPath resolves target-id's routed client, looks up path in
// PVE's own API-doc schema tree, and renders the result — the shared
// body every layer-1 discover noun (vm/node/storage/network) uses,
// differing only in which literal templated path they pass. path is
// never built from user input (see each noun's own *DiscoverPath
// function): apidoc.js's paths use fixed placeholder segment names like
// "{node}"/"{vmid}", not real object ids, so there is nothing here for a
// caller to supply beyond which fixed path to look up.
func runDiscoverPath(cmd *cobra.Command, targetID, path string, resolveFormat func() (kvjson.Format, error)) error {
	format, err := resolveFormat()
	if err != nil {
		return err
	}

	client, err := resolveRoutedClient(cmd, targetID)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	schema, err := discover.PVEObjectSchema(cmd.Context(), client, path)
	if err != nil {
		return err
	}
	return kvjson.Render(cmd.OutOrStdout(), format, schema)
}

func newDiscoverVMCmd() *cobra.Command {
	var verb string
	cmd := &cobra.Command{
		Use:   "vm <target-id>",
		Short: "Describe a VM's config or status schema, per PVE's own API-doc tree",
		Args:  cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&verb, "verb", "config", `which VM sub-resource to describe: "config" or "status"`)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path, err := vmDiscoverPath(verb)
		if err != nil {
			return err
		}
		return runDiscoverPath(cmd, args[0], path, resolveFormat)
	}
	return cmd
}

func vmDiscoverPath(verb string) (string, error) {
	switch verb {
	case "config":
		return "/nodes/{node}/qemu/{vmid}/config", nil
	case "status":
		return "/nodes/{node}/qemu/{vmid}/status/current", nil
	default:
		return "", fmt.Errorf(`invalid --verb %q: must be "config" or "status"`, verb)
	}
}

func newDiscoverNodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node <target-id>",
		Short: "Describe a node's status schema, per PVE's own API-doc tree",
		Args:  cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Deliberately "/nodes/{node}/status", not the bare "/nodes/{node}"
		// the original plan named: verified live (2026-09-14) that
		// "/nodes/{node}" is only the node's index/listing endpoint (its
		// GET carries no returns.properties at all), while
		// "/nodes/{node}/status" is the endpoint with real status fields —
		// and the one Client.GetNode itself actually calls.
		return runDiscoverPath(cmd, args[0], "/nodes/{node}/status", resolveFormat)
	}
	return cmd
}

func newDiscoverStorageCmd() *cobra.Command {
	var verb string
	cmd := &cobra.Command{
		Use:   "storage <target-id>",
		Short: "Describe a storage backend's config or status schema, per PVE's own API-doc tree",
		Args:  cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&verb, "verb", "config", `which storage sub-resource to describe: "config" (cluster-wide definition, default) or "status" (per-node runtime status)`)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		path, err := storageDiscoverPath(verb)
		if err != nil {
			return err
		}
		return runDiscoverPath(cmd, args[0], path, resolveFormat)
	}
	return cmd
}

// storageDiscoverPath implements the storage path grammar resolved in
// this task's own vault record ("Storage path grammar", 2026-09-14):
// "config" (default) is the cluster-wide storage-definition endpoint
// matching Client.GetStorageConfigPath's intent; "status" is the
// per-node runtime-status endpoint matching Client.GetStorage.
func storageDiscoverPath(verb string) (string, error) {
	switch verb {
	case "config":
		return "/storage/{storage}", nil
	case "status":
		return "/nodes/{node}/storage/{storage}/status", nil
	default:
		return "", fmt.Errorf(`invalid --verb %q: must be "config" or "status"`, verb)
	}
}

func newDiscoverNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network <target-id>",
		Short: "Describe a network interface's schema, per PVE's own API-doc tree",
		Args:  cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runDiscoverPath(cmd, args[0], "/nodes/{node}/network/{iface}", resolveFormat)
	}
	return cmd
}

func newDiscoverDeviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device <type>",
		Short: "Describe a pveforge device-semantic resolver's schema (layer 2, purely local — no target/roster needed)",
		Args:  cobra.ExactArgs(1),
	}
	resolveFormat := addOutputFlag(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		schema, ok := discover.DeviceSchemas[args[0]]
		if !ok {
			return fmt.Errorf("unknown device type %q", args[0])
		}
		return kvjson.Render(cmd.OutOrStdout(), format, schema)
	}
	return cmd
}
