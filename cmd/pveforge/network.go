package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

func newNetworkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Inspect node-level network interfaces",
	}
	cmd.AddCommand(newNetworkGetCmd())
	cmd.AddCommand(newNetworkBridgeCmd())
	cmd.AddCommand(newNetworkSetCmd())
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

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}
		unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "network", ID: client.Node()})
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		nw, err := client.GetNetworkInterface(cmd.Context(), client.Node(), args[1])
		if err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, nw)
	}
	markSafe(cmd)
	return cmd
}

// newNetworkBridgeCmd groups the two-phase stage/commit bridge mutations
// (create/destroy) under `network bridge`, separate from the read-only
// `network get` above.
func newNetworkBridgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Create or destroy a node-level network bridge (two-phase stage/commit)",
	}
	cmd.AddCommand(newNetworkBridgeCreateCmd())
	cmd.AddCommand(newNetworkBridgeDestroyCmd())
	return cmd
}

// wantedFieldsFromKVArgs parses trailing field=value positional args into a
// map suitable for NetworkBridgeEnsure.Wanted, rejecting a duplicate field
// name across the parsed pairs. NetworkBridgeEnsure.Validate itself only
// rejects a literal "iface" key (see its own doc comment), not general
// duplicates, so this is checked here instead, while pairs are still in
// their original ordered []kvjson.Pair form.
func wantedFieldsFromKVArgs(kvArgs []string) (map[string]string, error) {
	pairs, err := kvjson.ParseKVArgs(kvArgs)
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if _, dup := wanted[p.Field]; dup {
			return nil, fmt.Errorf("duplicate field %q given more than once", p.Field)
		}
		wanted[p.Field] = p.Value
	}
	return wanted, nil
}

func newNetworkBridgeCreateCmd() *cobra.Command {
	var managementBridge string

	cmd := &cobra.Command{
		Use:   "create <target-id> <iface> [field=value ...]",
		Short: "Stage and commit a new node-level network bridge",
		Long: `Create a node-level network interface (typically a bridge) via PVE's own
two-phase stage/commit model: the change is staged (POST
/nodes/{node}/network), independently guard-checked, and only then
committed (PUT /nodes/{node}/network), which is the single call that
actually triggers ifupdown2's live reload.

--management-bridge is REQUIRED, with no default (e.g. it is never assumed
to be "vmbr0"): this names the node's own management bridge, which the
guard mechanism reads before and after staging as a canary — if anything
about the management bridge's own pending config changes during the stage
window (PVE's staged network changes are node-wide, not per-interface, so
something else may have staged an unrelated change on this node
concurrently), the commit is refused and the staged changes are reverted
instead of being silently swept in. Guessing a default here would silently
disable that protection on any node where the guess is wrong, which is
worse than having no guard at all while looking like one — so it must be
named explicitly every time.

This command has NO --force override for the guard check: unlike a
digest-based conflict a caller might reasonably force past, a management
bridge whose staged config changed underneath this command means PVE
staged something this command never asked for and knows nothing about —
there is no safe way to force past that, so no bypass is offered.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			wanted, err := wantedFieldsFromKVArgs(args[2:])
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

			key := idempotent.NetworkLockKey(args[0], client.Node())
			op := &idempotent.NetworkBridgeEnsure{
				Client:           client,
				Node:             client.Node(),
				Iface:            args[1],
				ManagementBridge: managementBridge,
				Wanted:           wanted,
			}

			// Explicit, ahead of Run: idempotent.Run calls Satisfied before
			// Apply, and if the bridge already matches the wanted fields,
			// Apply — and therefore its own internal Validate() call —
			// never runs at all, silently bypassing the "no default
			// management bridge"/"no iface key in Wanted" validation for an
			// already-satisfied-but-malformed op. Same reasoning as
			// newVMSetCmd's own explicit Validate() call.
			if err := op.Validate(); err != nil {
				return err
			}

			if _, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: bridge %s created\n", args[0], args[1])
			return nil
		},
	}
	addRosterFlag(cmd)
	cmd.Flags().StringVar(&managementBridge, "management-bridge", "", "the node's own management bridge (e.g. vmbr0) — required, no default; see this command's --help for why")
	if err := cmd.MarkFlagRequired("management-bridge"); err != nil {
		panic(err)
	}
	markMutating(cmd)
	return cmd
}

func newNetworkBridgeDestroyCmd() *cobra.Command {
	var managementBridge string

	cmd := &cobra.Command{
		Use:   "destroy <target-id> <iface>",
		Short: "Stage and commit the removal of a node-level network bridge",
		Long: `Destroy a node-level network interface (typically a bridge) via PVE's own
two-phase stage/commit model: the removal is staged (DELETE
/nodes/{node}/network/{iface}), independently guard-checked, and only then
committed (PUT /nodes/{node}/network), which is the single call that
actually triggers ifupdown2's live reload.

--management-bridge is REQUIRED, with no default, and this command has NO
--force override for the guard check — see "network bridge create --help"
for the full rationale, which applies identically here.

Removing a live bridge can disconnect any VM currently attached to it —
there is no compiler- or PVE-side check for that here, so confirm nothing
depends on iface before running this.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveRoutedClient(cmd, args[0])
			if err != nil {
				return err
			}
			defer func() { _ = client.Close() }()

			rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
			if err != nil {
				return err
			}

			key := idempotent.NetworkLockKey(args[0], client.Node())
			op := &idempotent.NetworkBridgeEnsure{
				Client:           client,
				Node:             client.Node(),
				Iface:            args[1],
				ManagementBridge: managementBridge,
				Wanted:           nil,
			}

			if err := op.Validate(); err != nil {
				return err
			}

			if _, err := idempotent.Run(cmd.Context(), rosterPath, key, op, false); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: bridge %s destroyed\n", args[0], args[1])
			return nil
		},
	}
	addRosterFlag(cmd)
	cmd.Flags().StringVar(&managementBridge, "management-bridge", "", "the node's own management bridge (e.g. vmbr0) — required, no default; see this command's --help for why")
	if err := cmd.MarkFlagRequired("management-bridge"); err != nil {
		panic(err)
	}
	markDestructive(cmd)
	return cmd
}

// newNetworkSetCmd wraps NetworkFieldsEnsure (3b): per-interface field set
// (e.g. mtu, vlan_filtering) on an EXISTING node-level interface, reusing
// 3a's NetworkLockKey (see that function's own doc comment: MTU/vlan set
// and bridge create/destroy on the same node must serialize against each
// other, since PVE's staged network config is node-wide) and the same
// two-phase stage/commit model as "network bridge create/destroy" above.
func newNetworkSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <target-id> <iface> field=value [field=value ...]",
		Short: "Set one or more fields on an existing node-level network interface",
		Long: `Set one or more fields (e.g. mtu, vlan_filtering) on an EXISTING node-level
network interface via PVE's own two-phase stage/commit model: the change is
staged (PUT /nodes/{node}/network/{iface}), a guard proves every OTHER
interface on the node is unchanged (PVE's staged network config is
node-wide, not per-interface — an unrelated concurrent change would
otherwise be silently swept into the same commit), and only then committed
(PUT /nodes/{node}/network), which is the single call that actually
triggers ifupdown2's live reload.

Unlike "network bridge create/destroy", this command has no
--management-bridge flag: the guard here covers EVERY other interface on
the node, not one designated canary.

This command has NO --force override for the guard check, for the same
reason "network bridge create/destroy" doesn't: a mismatch means PVE staged
changes this command never asked for and knows nothing about — there is no
safe way to force past that.`,
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			pairs, err := kvjson.ParseKVArgs(args[2:])
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

			key := idempotent.NetworkLockKey(args[0], client.Node())
			op := &idempotent.NetworkFieldsEnsure{
				Client: client,
				Node:   client.Node(),
				Iface:  args[1],
				Pairs:  pairs,
			}

			// Explicit, ahead of Run: idempotent.Run calls Satisfied before
			// Apply, and if op.Iface already matches every wanted field,
			// Apply — and therefore its own internal Validate() call —
			// never runs at all. Same reasoning as newNetworkBridgeCreateCmd's
			// and newVMSetCmd's own explicit-Validate comment.
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
	markMutating(cmd)
	return cmd
}
