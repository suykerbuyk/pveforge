package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"

	"github.com/spf13/cobra"
	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

func newHarnessVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Harness VM lifecycle verbs (stop, shutdown, destroy, gone, snapshot)",
	}
	cmd.AddCommand(newHarnessVMStopCmd())
	cmd.AddCommand(newHarnessVMShutdownCmd())
	cmd.AddCommand(newHarnessVMDestroyCmd())
	cmd.AddCommand(newHarnessVMGoneCmd())
	cmd.AddCommand(newHarnessVMSnapshotCmd())
	return cmd
}

// harnessVMID parses and bounds-checks a harness VMID argument (690–699,
// lib.sh:133/:237) before any call is made.
func harnessVMID(arg string) (int, error) {
	vmid, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("invalid vmid %q: %w", arg, err)
	}
	if !outer.ValidVMID(vmid) {
		return 0, fmt.Errorf("VMID %d is not one of 690-699", vmid)
	}
	return vmid, nil
}

func harnessVMKey(targetID string, vmid int) lock.ObjectKey {
	return lock.ObjectKey{TargetID: targetID, Kind: "vm", ID: strconv.Itoa(vmid)}
}

// rawUPID issues method against path with params and returns the task UPID
// PVE answers with (the unwrapped scalar is a JSON string). Used by the
// leaf-issued stop/shutdown/destroy requests.
func rawUPID(ctx context.Context, client *pve.RoutedClient, method, path string, params url.Values) (string, error) {
	raw, err := client.RawRequest(ctx, method, path, params)
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(raw, &upid); err != nil {
		return "", fmt.Errorf("%s %s: expected a task UPID, got %s", method, path, string(raw))
	}
	return upid, nil
}

// ---- stop (hard) --------------------------------------------------------

func newHarnessVMStopCmd() *cobra.Command {
	var timeout int
	cmd := &cobra.Command{
		Use:   "stop <target-id> <vmid>",
		Short: "Hard-stop a harness VM",
		Long: `Hard-stop a harness VM (PVE status/stop). Guarded like any change: the VM
must be a tagged qemu member of the harness pool on the harness node.` + "",
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().IntVar(&timeout, "timeout", 0, "seconds PVE waits before forcing the stop (0 = PVE default)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
			return err
		}
		params := url.Values{}
		if timeout > 0 {
			if !outer.AllowedField("stop", "timeout") {
				return fmt.Errorf("stop timeout is not an allowed harness field")
			}
			params.Set("timeout", strconv.Itoa(timeout))
		}
		upid, err := rawUPID(cmd.Context(), client, http.MethodPost, vmSubPath(cfg.Node, vmid, "status/stop"), params)
		if err != nil {
			return fmt.Errorf("stop vm %d: %w", vmid, err)
		}
		if err := harnessWaitForTask(cmd.Context(), client, cfg.Node, upid); err != nil {
			return fmt.Errorf("stop vm %d: %w", vmid, err)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "result": "stopped"})
	}
	markDestructive(cmd)
	return cmd
}

// ---- shutdown (graceful) ------------------------------------------------

func newHarnessVMShutdownCmd() *cobra.Command {
	var (
		timeout   int
		forceStop bool
	)
	cmd := &cobra.Command{
		Use:   "shutdown <target-id> <vmid>",
		Short: "Gracefully shut down a harness VM",
		Long: `Gracefully shut down a harness VM. With neither --timeout nor --force-stop
this drives pveforge's idempotent VMShutdown (a no-op if already stopped,
refuses a paused guest). With either flag it issues PVE's status/shutdown
directly, since the idempotent op cannot express them.`,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().IntVar(&timeout, "timeout", 0, "seconds PVE waits for the guest before giving up (0 = PVE default)")
	cmd.Flags().BoolVar(&forceStop, "force-stop", false, "let PVE hard-stop the VM if the graceful shutdown times out")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)
		key := harnessVMKey(args[0], vmid)

		if timeout == 0 && !forceStop {
			// Plain path: idempotent.Run OWNS lock.Mutation (R2), so the leaf
			// takes no outer lock and the guard runs just before Run.
			if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
				return err
			}
			if _, err := idempotent.Run(cmd.Context(), rosterPath, key, &idempotent.VMShutdown{Client: client, VMID: vmid}, false); err != nil {
				return err
			}
			return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "result": "shutdown"})
		}

		// Leaf-issued shutdown with timeout/forceStop: the leaf owns the lock,
		// held across the guard and the status/shutdown POST (C2/C9).
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, key)
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()
		if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
			return err
		}
		params := url.Values{}
		if timeout > 0 {
			if !outer.AllowedField("shutdown", "timeout") {
				return fmt.Errorf("shutdown timeout is not an allowed harness field")
			}
			params.Set("timeout", strconv.Itoa(timeout))
		}
		if forceStop {
			if !outer.AllowedField("shutdown", "forceStop") {
				return fmt.Errorf("shutdown forceStop is not an allowed harness field")
			}
			params.Set("forceStop", "1")
		}
		upid, err := rawUPID(cmd.Context(), client, http.MethodPost, vmSubPath(cfg.Node, vmid, "status/shutdown"), params)
		if err != nil {
			return fmt.Errorf("shutdown vm %d: %w", vmid, err)
		}
		if err := harnessWaitForTask(cmd.Context(), client, cfg.Node, upid); err != nil {
			return fmt.Errorf("shutdown vm %d: %w", vmid, err)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "result": "shutdown"})
	}
	// C1: --force-stop sends forceStop=1, which PVE escalates to a HARD stop
	// (it can drop unflushed guest state), so the verb is destructive, not
	// merely mutating — the whole command carries the higher tier.
	markDestructive(cmd)
	return cmd
}

// ---- destroy ------------------------------------------------------------

func newHarnessVMDestroyCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "destroy <target-id> <vmid>",
		Short: "Destroy a harness VM and prove it is gone",
		Long: `Destroy a harness VM this run created, purging it and its unreferenced
disks, then prove it is gone from PVE's own JSON (the destroy task ended OK,
the VMID is free cluster-wide, and the pool no longer lists it). Reuses
VMDestroy's fail-closed status-gated stop before the destroy. The VMID must
be listed in this run's created-VM ledger (--created-file or
$HARNESS_CREATED_FILE) — an unconditional gate — and the destroy must be
confirmed with --yes. Exits non-zero if the gone-proof fails.`,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	addCreatedFileFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm this irreversible destroy (required; does NOT bypass the created-by-this-run ledger gate)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		// Guard: created-by-this-run is an UNCONDITIONAL destroy gate
		// (lib.sh:484) — --yes does NOT weaken it (C7). It is an additive
		// non-interactive confirmation, checked only after the full guard
		// (pool/node/tag + created-by-run) has passed.
		if err := outer.Guard(cmd.Context(), client, cfg, harnessLedger(cmd), vmid, outer.ModeDestroy); err != nil {
			return err
		}
		if !yes {
			return fmt.Errorf("vm %d: this irreversible destroy must be confirmed with --yes", vmid)
		}

		// N1: reuse VMDestroy's fail-closed status-gated stop, single-sourced.
		op := &idempotent.VMDestroy{Client: client, VMID: vmid}
		if err := op.StatusGatedStop(cmd.Context()); err != nil {
			return err
		}

		// Leaf-issued final DELETE with BOTH params (F1). Screen them against
		// lib.sh's allow-list; lib sends exactly these two and no caller field.
		for _, k := range []string{"purge", "destroy-unreferenced-disks"} {
			if !outer.AllowedField("destroy", k) {
				return fmt.Errorf("destroy %s is not an allowed harness field", k)
			}
		}
		params := url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}
		upid, err := rawUPID(cmd.Context(), client, http.MethodDelete, vmSubPath(cfg.Node, vmid, ""), params)
		if err != nil {
			return fmt.Errorf("destroy vm %d: %w", vmid, err)
		}
		if err := harnessWaitForTask(cmd.Context(), client, cfg.Node, upid); err != nil {
			return fmt.Errorf("destroy vm %d: %w", vmid, err)
		}

		// Gone-proof: fail the command non-zero if it cannot be proven gone.
		if err := outer.VMGone(cmd.Context(), client, cfg, vmid, upid); err != nil {
			return fmt.Errorf("vm %d: destroy issued but not proven gone: %w", vmid, err)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "result": "destroyed", "proof": "gone"})
	}
	markDestructive(cmd)
	return cmd
}

// ---- gone (standalone proof) --------------------------------------------

func newHarnessVMGoneCmd() *cobra.Command {
	var destroyTask string
	cmd := &cobra.Command{
		Use:   "gone <target-id> <vmid>",
		Short: "Prove a destroyed harness VM is gone",
		Long: `Prove a harness VM is gone without destroying it: given the destroy task's
UPID (--destroy-task), confirm the task ended OK, the VMID is free
cluster-wide, and the pool no longer lists it. Read-only.`,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&destroyTask, "destroy-task", "", "the destroy task's UPID (required)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		upid := parseDestroyTask(destroyTask)
		if upid == "" {
			return fmt.Errorf("--destroy-task is required: the destroy task's UPID")
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Read(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		if err := outer.VMGone(cmd.Context(), client, cfg, vmid, upid); err != nil {
			return fmt.Errorf("vm %d: not proven gone: %w", vmid, err)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "gone": true})
	}
	markSafe(cmd)
	return cmd
}

// parseDestroyTask accepts the UPID bare or as a JSON string (the exact
// value `harness vm destroy` prints), the way lib.sh slurps the destroy's
// answer. Anything else is passed through bare.
func parseDestroyTask(s string) string {
	if len(s) >= 2 && s[0] == '"' {
		var u string
		if err := json.Unmarshal([]byte(s), &u); err == nil {
			return u
		}
	}
	return s
}

// ---- snapshot group -----------------------------------------------------

func newHarnessVMSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Harness VM snapshot verbs (list, create, delete, rollback)",
	}
	cmd.AddCommand(newHarnessVMSnapshotListCmd())
	cmd.AddCommand(newHarnessVMSnapshotCreateCmd())
	cmd.AddCommand(newHarnessVMSnapshotDeleteCmd())
	cmd.AddCommand(newHarnessVMSnapshotRollbackCmd())
	return cmd
}

func newHarnessVMSnapshotListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <target-id> <vmid>",
		Short: "List a harness VM's snapshots, oldest first",
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		unlock, err := lock.Read(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		snaps, err := realSnapshots(cmd.Context(), client, vmid)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(snaps))
		for _, s := range snaps {
			names = append(names, s.Name)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "snapshots": names})
	}
	markSafe(cmd)
	return cmd
}

func newHarnessVMSnapshotCreateCmd() *cobra.Command {
	var (
		vmstate     int
		description string
	)
	cmd := &cobra.Command{
		Use:   "create <target-id> <vmid> <name>",
		Short: "Create a harness VM snapshot (disk-only with --vmstate 0)",
		Long: `Create a harness VM snapshot. --vmstate 1 (default) captures RAM too;
--vmstate 0 is a disk-only snapshot, which the probe and golden paths need
and which pveforge's own vm snapshot create cannot express. The name is
verified present afterward; the names current and pending are refused.`,
		Args: cobra.ExactArgs(3),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().IntVar(&vmstate, "vmstate", 1, "capture RAM state (1) or disk-only (0)")
	cmd.Flags().StringVar(&description, "description", "", "the snapshot's description")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		name := args[2]
		if name == "current" || name == "pending" {
			return fmt.Errorf("snapshot name %q is reserved by PVE", name)
		}
		if !outer.ValidSnapshotName(name) {
			return fmt.Errorf("snapshot name %q is not a valid harness snapshot name", name)
		}
		if vmstate != 0 && vmstate != 1 {
			return fmt.Errorf("--vmstate must be 0 or 1, got %d", vmstate)
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
			return err
		}
		// Leaf-issued create (F2): sends vmstate as a field, unlike
		// pve.CreateSnapshot which forces vmstate=1.
		params := url.Values{}
		params.Set("snapname", name)
		params.Set("vmstate", strconv.Itoa(vmstate))
		if description != "" {
			params.Set("description", description)
		}
		for k := range params {
			if !outer.AllowedField("snapshot", k) {
				return fmt.Errorf("snapshot %s is not an allowed harness field", k)
			}
		}
		upid, err := rawUPID(cmd.Context(), client, http.MethodPost, vmSubPath(cfg.Node, vmid, "snapshot"), params)
		if err != nil {
			return fmt.Errorf("create snapshot %q of vm %d: %w", name, vmid, err)
		}
		if err := harnessWaitForTask(cmd.Context(), client, cfg.Node, upid); err != nil {
			return fmt.Errorf("create snapshot %q of vm %d: %w", name, vmid, err)
		}
		// Verify it exists afterward (lib.sh's post-create check), through a
		// VERIFIABLE list (C5): a swallowed/empty list fails closed.
		snaps, err := listSnapshotsVerifiable(cmd.Context(), client, vmid)
		if err != nil {
			return err
		}
		found := false
		for _, s := range snaps {
			if s.Name == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("create snapshot %q of vm %d: not present after the create task", name, vmid)
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "snapshot": name, "result": "created"})
	}
	markMutating(cmd)
	return cmd
}

func newHarnessVMSnapshotDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <target-id> <vmid> <name>...",
		Short: "Delete harness VM snapshots, newest first",
		Long: `Delete one or more harness VM snapshots. The names are sorted newest-first
in the leaf (CascadeDeleteSnapshots does not reorder), so a chain is deleted
from its leaf back. A name that is not a snapshot is reported absent.`,
		Args: cobra.MinimumNArgs(3),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		names := args[2:]
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
			return err
		}
		// VERIFIABLE list (C5): a swallowed/empty list must fail closed rather
		// than report every name absent and delete nothing (a fail-open).
		snaps, err := listSnapshotsVerifiable(cmd.Context(), client, vmid)
		if err != nil {
			return err
		}
		// Rank oldest→newest (PVE order breaks snaptime ties, as ListSnapshots
		// returns them); newest-first is the reverse — the CascadeOrder.
		rank := map[string]int{}
		for i, s := range snaps {
			rank[s.Name] = i
		}
		var present []string
		absent := []string{}
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] {
				continue
			}
			seen[n] = true
			if _, ok := rank[n]; ok {
				present = append(present, n)
			} else {
				absent = append(absent, n)
			}
		}
		sort.Slice(present, func(i, j int) bool { return rank[present[i]] > rank[present[j]] })

		deleted := []string{}
		if len(present) > 0 {
			d, err := client.CascadeDeleteSnapshots(cmd.Context(), vmid, present)
			if d != nil {
				deleted = d
			}
			if err != nil {
				return fmt.Errorf("delete snapshots of vm %d: %w; deleted so far: %v", vmid, err, deleted)
			}
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "vmid": vmid, "deleted": deleted, "absent": absent})
	}
	markDestructive(cmd)
	return cmd
}

// harnessRollbackResult is the single-sourced snapshot-not-latest contract
// (§4): consumers parse the `reason` field, never the exit code.
type harnessRollbackResult struct {
	Target       string   `json:"target"`
	VMID         int      `json:"vmid"`
	Snapshot     string   `json:"snapshot"`
	Rollback     string   `json:"rollback"`
	Reason       string   `json:"reason,omitempty"`
	Newer        []string `json:"newer,omitempty"`
	CascadeOrder []string `json:"cascade_order,omitempty"`
	Witness      string   `json:"witness,omitempty"`
}

func newHarnessVMSnapshotRollbackCmd() *cobra.Command {
	var witness bool
	cmd := &cobra.Command{
		Use:   "rollback <target-id> <vmid> <name>",
		Short: "Roll a harness VM back to its newest snapshot",
		Long: `Roll a harness VM back to a snapshot. Only the newest snapshot can be rolled
back to: if newer ones exist, pveforge refuses before anything is sent, and
this prints a JSON object with rollback=refused and reason=not-newest (plus
newer and cascade_order). Consumers classify on the reason field, not the
exit code (which stays 1 for any refusal).`,
		Args: cobra.ExactArgs(3),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().BoolVar(&witness, "witness", false, "prove the guest is running after the rollback via the guest agent")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, err := harnessVMID(args[1])
		if err != nil {
			return err
		}
		name := args[2]
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		if err := outer.Guard(cmd.Context(), client, cfg, nil, vmid, outer.ModeChange); err != nil {
			return err
		}
		if err := client.Rollback(cmd.Context(), vmid, name); err != nil {
			// Single classifier (§4): the typed not-latest refusal → the
			// reason contract on stdout; exit stays 1 (return the error).
			var newer *pve.ErrNotNewestSnapshot
			if errors.As(err, &newer) {
				_ = kvjson.Render(cmd.OutOrStdout(), format, harnessRollbackResult{
					Target: args[0], VMID: vmid, Snapshot: name,
					Rollback: "refused", Reason: "not-newest",
					Newer: newer.Newer, CascadeOrder: newer.CascadeOrder(),
				})
				return err
			}
			return err
		}
		res := harnessRollbackResult{Target: args[0], VMID: vmid, Snapshot: name, Rollback: "completed", Witness: "skipped"}
		if witness {
			argv, marker, werr := pve.DefaultRollbackWitnessCommand()
			if werr != nil {
				return werr
			}
			if _, werr := client.RollbackWitness(cmd.Context(), vmid, argv, marker, defaultWitnessTimeout); werr != nil {
				return fmt.Errorf("rollback vm %d completed, but it could not be proven: %w", vmid, werr)
			}
			res.Witness = "verified"
		}
		return kvjson.Render(cmd.OutOrStdout(), format, res)
	}
	markDestructive(cmd)
	return cmd
}

// ---- shared helpers -----------------------------------------------------

// harnessClient resolves the routed client and the roster path together, the
// setup every harness verb needs.
func harnessClient(cmd *cobra.Command, targetID string) (*pve.RoutedClient, string, error) {
	rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
	if err != nil {
		return nil, "", err
	}
	client, err := resolveRoutedClient(cmd, targetID)
	if err != nil {
		return nil, "", err
	}
	return client, rosterPath, nil
}

// harnessWaitForTask polls a PVE task to completion. It exists so the
// WaitForTask call takes the enclosing function's own context.Context
// parameter directly (the task-wait context guard), rather than a
// cmd.Context() expression at each verb's call site.
func harnessWaitForTask(ctx context.Context, client *pve.RoutedClient, node, upid string) error {
	return client.WaitForTask(ctx, node, upid)
}

// vmSubPath builds /nodes/<node>/qemu/<vmid>[/sub] for a raw request.
func vmSubPath(node string, vmid int, sub string) string {
	p := fmt.Sprintf("/nodes/%s/qemu/%d", node, vmid)
	if sub != "" {
		p += "/" + sub
	}
	return p
}

// realSnapshots lists a VM's snapshots oldest-first, dropping PVE's own
// "current" pseudo-entry. Used only by the read-only `snapshot list` display,
// where an empty list is a valid thing to show.
func realSnapshots(ctx context.Context, client *pve.RoutedClient, vmid int) ([]*proxmox.VirtualMachineSnapshot, error) {
	snaps, err := client.ListSnapshots(ctx, vmid)
	if err != nil {
		return nil, err
	}
	var out []*proxmox.VirtualMachineSnapshot
	for _, s := range snaps {
		if s != nil && s.Name != currentPseudoEntry {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Snaptime < out[j].Snaptime })
	return out, nil
}

// listSnapshotsVerifiable is realSnapshots for a read that DECIDES something
// (create's post-verify, delete's absence check). PVE's snapshot list always
// carries the "current" pseudo-entry (snapshot.go), so a list that lacks it
// — an empty [] or a list of nulls that go-proxmox decodes without error —
// is an unverifiable read, NOT "no snapshots". It fails CLOSED (C5): a
// swallowed list must never let a delete report every name absent and exit 0,
// nor let a create's post-verify pass on a list it cannot trust.
func listSnapshotsVerifiable(ctx context.Context, client *pve.RoutedClient, vmid int) ([]*proxmox.VirtualMachineSnapshot, error) {
	snaps, err := client.ListSnapshots(ctx, vmid)
	if err != nil {
		return nil, err
	}
	hasCurrent := false
	var out []*proxmox.VirtualMachineSnapshot
	for _, s := range snaps {
		if s == nil {
			continue
		}
		if s.Name == currentPseudoEntry {
			hasCurrent = true
			continue
		}
		out = append(out, s)
	}
	if !hasCurrent {
		return nil, fmt.Errorf("snapshot list for vm %d is unverifiable: PVE's %q entry is absent (a swallowed or empty list); refusing rather than reading it as 'no snapshots'", vmid, currentPseudoEntry)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Snaptime < out[j].Snaptime })
	return out, nil
}
