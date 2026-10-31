package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

func newStorageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "storage",
		Short: "Inspect and create storage backends",
	}
	cmd.AddCommand(newStorageGetCmd())
	cmd.AddCommand(newStorageOrphansCmd())
	cmd.AddCommand(newStorageCreateCmd())
	cmd.AddCommand(newStorageAllocCmd())
	cmd.AddCommand(newStorageFreeOrphansCmd())
	return cmd
}

// newStorageAllocCmd wires pveforge-storage-volume-tracking's
// idempotent.VolumeAllocEnsure: allocate a convention-named raw volume outside
// qm's own disk schema (POST /nodes/{node}/storage/{storage}/content),
// idempotently. Absent -> allocated; already present -> no-op. The second
// signal compares the volid the POST RETURNED against the storage listing, so
// it is correct for directory storage (volid "<storage>:<vmid>/<name>") as well
// as lvmthin/ZFS ("<storage>:vm-<id>-…"). Non-destructive of any existing data,
// but markDestructive like `storage create` (it writes storage).
func newStorageAllocCmd() *cobra.Command {
	var format string
	var force bool

	cmd := &cobra.Command{
		Use:   "alloc <target-id> <storage> <filename> <size> <vmid> [--format F]",
		Short: "Allocate a convention-named raw volume, idempotently",
		Long: `Allocate a raw volume on a storage by a caller-chosen, deterministic
filename (POST /nodes/{node}/storage/{storage}/content), idempotently — the
"pvesm alloc" half of raw-volume lifecycle, for volumes outside qm's own disk
schema.

The filename is the identity: absent -> allocated; already present with that
name for that vmid -> no-op (nothing changed). The allocate call is synchronous
(no task wait); success is confirmed by a dual signal — the volid the POST
returned is read back from the storage listing.

size is PVE's own size grammar (e.g. 32G), passed through unchanged. --format is
optional (PVE infers it from the storage type when omitted).`,
		Args: cobra.ExactArgs(5),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().StringVar(&format, "format", "", "the volume format (raw, qcow2, ...); optional, PVE infers from the storage type when omitted")
	cmd.Flags().BoolVar(&force, "force", false, "re-run Apply even if the volume already exists (PVE then refuses the duplicate)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		vmid, err := strconv.Atoi(args[4])
		if err != nil || vmid < 1 {
			return fmt.Errorf("storage alloc: vmid %q must be a positive integer", args[4])
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

		op := &idempotent.VolumeAllocEnsure{Client: client, Storage: args[1], Filename: args[2], Size: args[3], VMID: vmid, Format: format}
		// Explicit, ahead of Run, like `storage create`: Run skips Apply (and
		// its internal Validate) on the already-satisfied path.
		if err := op.Validate(); err != nil {
			return err
		}

		key := lock.ObjectKey{TargetID: args[0], Kind: "storage", ID: args[1]}
		res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, force)
		if err != nil {
			return err
		}
		if !res.Changed {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: volume %s already allocated on %s (%s); nothing to do\n", args[0], args[2], args[1], op.Volid())
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: volume %s allocated on %s as %s\n", args[0], args[2], args[1], op.Volid())
		return nil
	}
	markDestructive(cmd)
	return cmd
}

// newStorageFreeOrphansCmd wires pveforge-storage-volume-tracking's DESTRUCTIVE
// idempotent.VolumeFreeOrphans: free every "<storage>:vm-<vmid>-*" volume the
// destructive-safe orphan determination reports unclaimed, after a destroyed
// VM. It is destructive and fail-closed:
//
//   - the claimed set's VM enumeration comes from a ROOT, node-scoped VM list
//     (bootstrap.RootAccess.NodeVMIDs), not the token's silently-short GetVMs —
//     any error reading it REFUSES the free;
//   - before any DELETE it checks the node holds corosync quorum
//     (ClusterStatusQuorate) and REFUSES a non-quorate node (whose pmxcfs view
//     may be stale). Quorum is NECESSARY, NOT SUFFICIENT: a node that just
//     regained quorum, or is receiving a migration, may serve a stale list for
//     a replication window no API read closes — so a warning rides every run
//     (see the stderr notice). Do not run concurrently with a migration
//     targeting this node or just after it rejoined the cluster.
//
// Needs root SSH (the target's stored key, or --no-ssh-key + the PVE password),
// as `vm create --unique-tag` and `user ensure` do, plus the roster token's
// REST view for the per-VM config reads.
func newStorageFreeOrphansCmd() *cobra.Command {
	var noSSHKey bool
	var force bool

	cmd := &cobra.Command{
		Use:   "free-orphans <target-id> <storage> <vmid>",
		Short: "Free orphan volumes matching a destroyed VM's naming convention (DESTRUCTIVE)",
		Args:  cobra.ExactArgs(3),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().BoolVar(&force, "force", false, "re-run Apply even when the determination reports no orphans")
	cmd.Flags().BoolVar(&noSSHKey, "no-ssh-key", false, noSSHKeyAccessUsage)
	cmd.Flags().String("host-key-fingerprint", "", hostKeyFingerprintAccessUsage)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		vmid, err := strconv.Atoi(args[2])
		if err != nil || vmid < 1 {
			return fmt.Errorf("storage free-orphans: vmid %q must be a positive integer", args[2])
		}

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}

		access, t, rc, closeAll, err := openRootAccessAndREST(cmd, args[0], noSSHKey, true)
		if err != nil {
			return err
		}
		defer closeAll()
		if rc == nil {
			return fmt.Errorf("storage free-orphans: target %q holds no API token; the orphan determination needs the token's REST view for the per-VM config reads", args[0])
		}
		// Resolve the keyless password (if any) before the storage lock, so a
		// prompt or slow dial never holds it.
		if err := access.ResolveCredentials(cmd.Context()); err != nil {
			return err
		}

		// A shared storage's content is visible cluster-wide, so a node-scoped
		// claimed set would report a disk a VM on ANOTHER node claims as an
		// orphan and free a live disk. Shared storage therefore needs the
		// cluster-wide claimed set (gated, below); unshared storage keeps the
		// node-scoped path, whose claimed set is already correct.
		stg, err := rc.GetStorage(cmd.Context(), t.Node, args[1])
		if err != nil {
			return fmt.Errorf("storage free-orphans: refusing — could not read storage %q on %q: %w", args[1], t.Node, err)
		}

		op := &idempotent.VolumeFreeOrphans{Client: rc, Scanner: rc, Storage: args[1], VMID: vmid}

		// RULING 3: establish the VM enumeration FIRST, then the quorum gate,
		// both before the lock; refuse on either failure. The gate is a
		// precondition, not a continuous guarantee: a quorum loss AFTER this
		// check is not caught (a volume DELETE is a storage write, vdisk_free,
		// not a pmxcfs write, so a read-only pmxcfs does not fail it).
		if stg.Shared != 0 {
			// Shared storage routes UNCONDITIONALLY through the cluster-wide
			// claimed set (still behind the quorum gate + stale-residual warning
			// below). The U-CWCV §2 merge gate — that this host's API proxy serves
			// another node's OWN config for /nodes/{B}/qemu/{vmid}/config, not a
			// local/wrong-node answer — was proven GREEN and break-tested on the
			// nested `pvh` harness 2026-10-30: node A (pvh-n1) served node B's
			// (pvh-n2) config for a VMID absent on A, carrying a B-unique marker
			// with BoundHostOK, and a wrong marker gave proven:false. See task
			// pveforge-cluster-wide-claimed-volumes Execution status. The former
			// clusterSharedFreeProxyProven refusal gate is therefore removed.
			//
			// Cluster-wide, node-carrying enumeration, QEMU-only and cross-
			// checked against the online-node set (the sound-but-weaker
			// membership check, §4.3). A guest naming a non-online node refuses.
			guests, err := access.ClusterGuests(cmd.Context())
			if err != nil {
				return fmt.Errorf("storage free-orphans: refusing — could not read the cluster guest list for node %q: %w", t.Node, err)
			}
			online, err := access.ClusterStatusOnlineNodes(cmd.Context())
			if err != nil {
				return fmt.Errorf("storage free-orphans: refusing — could not read the cluster's online nodes for node %q: %w", t.Node, err)
			}
			pairs, err := pve.ClusterQemuPairs(guests, online)
			if err != nil {
				return fmt.Errorf("storage free-orphans: refusing — %w", err)
			}
			op.ClusterPairs = pairs
		} else {
			completeVMIDs, err := access.NodeVMIDs(cmd.Context(), t.Node)
			if err != nil {
				return fmt.Errorf("storage free-orphans: refusing — could not read the complete root VM list for node %q: %w", t.Node, err)
			}
			op.CompleteVMIDs = completeVMIDs
		}

		quorate, err := access.ClusterStatusQuorate(cmd.Context())
		if err != nil {
			return fmt.Errorf("storage free-orphans: refusing — could not read cluster quorum for node %q: %w", t.Node, err)
		}
		if !quorate {
			return fmt.Errorf("storage free-orphans: refusing — node %q is not quorate; its VM list may be stale and the free could delete a live VM's disk", t.Node)
		}
		// Residual (rides every free path, now scaled cluster-wide for shared
		// storage): quorum is necessary, not sufficient; the post-quorate pmxcfs
		// replication window — and, on the cluster path, a whole node silently
		// dropped from the enumeration — are NOT closable by any API read, and
		// are deferred to pveforge-cluster-free-stale-shortlist-completeness.
		fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: %s: quorum is a necessary but NOT sufficient freshness check; a node that just regained quorum or is receiving a migration can serve a stale VM list briefly, so do not run free-orphans concurrently with a migration targeting node %q or just after it rejoined the cluster\n",
			args[0], t.Node)

		key := lock.ObjectKey{TargetID: args[0], Kind: "storage", ID: args[1]}
		res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, force)
		if err != nil {
			return err
		}
		if !res.Changed || len(op.Applied) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: no orphan volumes matching vm-%d-* on %s; nothing freed\n", args[0], vmid, args[1])
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: freed %d orphan volume(s) on %s: %s\n", args[0], len(op.Applied), args[1], strings.Join(op.Applied, ", "))
		return nil
	}
	markDestructive(cmd)
	return cmd
}

// newStorageCreateCmd wires pveforge-storage-create-command's
// idempotent.StorageCreate Op: create a cluster-wide storage definition (POST
// /storage), idempotently. Absent -> create; already present and matching ->
// no-op; present with a DIFFERING definition -> refused with a desired-vs-
// actual diff and no POST (a future `storage set` is the deliberate converge).
//
// Type-agnostic: --type <type> plus raw --data key=value passthrough (PVE
// validates, its errors propagate verbatim), mirroring `vm create`'s
// raw/schema-free surface — with one small data-driven per-type required-keys
// guard (v1: a zfspool with no pool= is refused client-side before any POST).
func newStorageCreateCmd() *cobra.Command {
	var storageType string
	var dataPairs []string
	var force bool

	cmd := &cobra.Command{
		Use:   "create <target-id> <name> --type <type> [--data key=value ...]",
		Short: "Create a storage definition, idempotently, refusing a differing one",
		Long: `Create a cluster-wide PVE storage definition (POST /storage), idempotently.

The definition is type-agnostic: --type names the storage type and every
other parameter is a raw --data key=value, passed to PVE unchanged (PVE
validates them and its error text propagates verbatim), exactly like
` + "`vm create`" + `'s raw create fields. One small guard runs client-side
before any POST: a type with a known required key missing is refused early
(v1: --type zfspool needs --data pool=<zpool>, or the storage comes up
inactive).

A storage definition is CLUSTER-WIDE, not node-scoped: it is written to the
cluster's storage.cfg whichever node's API is addressed. Creating one needs
Datastore.Allocate at /storage (datacenter) — a storage pool token with only
Datastore.AllocateSpace cannot create a definition, only allocate volumes
within one.

Idempotent:
  - absent            -> created;
  - present, matching -> no-op (nothing changed);
  - present, differing-> REFUSED, with a desired-vs-actual diff and NO write;
    a future ` + "`storage set`" + ` is the way to converge one deliberately.
--force re-POSTs a present+matching storage instead of no-opping (PVE then
refuses the duplicate), but STILL refuses a differing definition.`,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().StringVar(&storageType, "type", "", "the PVE storage type to create (zfspool, dir, lvmthin, nfs, ...); required")
	cmd.Flags().StringArrayVar(&dataPairs, "data", nil, "a raw PVE create parameter, key=value (repeatable): pool=..., content=..., nodes=...")
	cmd.Flags().BoolVar(&force, "force", false, "re-POST even if the storage already matches (PVE refuses the duplicate); still refuses a differing definition")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if storageType == "" {
			return errors.New("storage create: --type is required")
		}

		params, err := parseDataParams(dataPairs)
		if err != nil {
			return err
		}
		// --type is the authoritative type; a stray --data type= is refused
		// rather than silently fighting the flag.
		if params.Get("type") != "" {
			return errors.New("storage create: set the type with --type, not --data type=")
		}
		params.Set("type", storageType)

		client, err := resolveRoutedClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()

		rosterPath, err := resolveRosterPathFromFlagOrEnv(cmd)
		if err != nil {
			return err
		}

		op := &idempotent.StorageCreate{Client: client, Name: args[1], Params: params}

		// Explicit, ahead of Run, for the same reason `vm create` calls
		// VMCreate.Validate ahead of Run: idempotent.Run skips Apply (and so
		// Apply's own internal Validate) entirely on the already-satisfied
		// path, so the required-keys guard would not run for a storage that
		// already exists. Running it here means a zfspool with no pool= is
		// refused whether or not the storage is already there.
		if err := op.Validate(); err != nil {
			return err
		}

		// The lock key — the same {TargetID, "storage", <name>} key `storage
		// get` and `storage orphans` already use, so a create serializes
		// against reads and other creates of the same storage on this target.
		key := lock.ObjectKey{TargetID: args[0], Kind: "storage", ID: args[1]}

		res, err := idempotent.Run(cmd.Context(), rosterPath, key, op, force)
		if err != nil {
			return err
		}

		if !res.Changed {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: storage %s already exists with the requested definition; nothing to do\n", args[0], args[1])
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "%s: storage %s created\n", args[0], args[1])
		// Advisory, exit 0: the create succeeded but the re-read of the new
		// config could not be made.
		warnNotReread(cmd.ErrOrStderr(), args[0], "storage", args[1], res.AfterErr)
		return nil
	}
	markDestructive(cmd)
	return cmd
}

func newStorageGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <target-id> <storage-name>",
		Short: "Get one storage backend's status",
		Args:  cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
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
	addLockWaitFlag(cmd)
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
