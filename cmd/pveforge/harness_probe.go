package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/harness/probe"
	"github.com/suykerbuyk/pveforge/internal/lock"
)

// pveforge-harness-capability-probe (U-PROBE): `pveforge harness probe
// <target-id> --storage <id> [--static-only]`, the Go port of
// hack/harness/probe.sh. It consumes U-CORE's guard / gone-proof / snapshot
// ops and the exported not-latest classifier; the destructive tier is
// confined to this verb (it creates and destroys VM 690). The outcome is on
// STDOUT (`rollback-rule=<rule> storage=<id>`, or a refusal/failure line);
// every error exits 1.
func newHarnessProbeCmd() *cobra.Command {
	var (
		storage    string
		staticOnly bool
		minFreeGiB int
	)
	cmd := &cobra.Command{
		Use:   "probe <target-id>",
		Short: "Probe an outer storage's capability (creates and destroys VM 690)",
		Long: `Probe an outer storage's capability for the harness, on VM 690, before the
build. The static layer checks the storage is an enabled, active zfspool that
holds images and has room; the empirical layer creates a 1 GiB disk VM,
snapshots it, classifies the storage's rollback rule (rollback-latest-only vs
rollback-any), then destroys 690 and proves it gone. --static-only runs the
static layer alone. The rollback rule is written to
~/.config/pveforge/harness-state/rollback-rule.<id> (a probe output; reset
does not read it).`,
		Args: cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addCreatedFileFlag(cmd)
	addLockWaitFlag(cmd)
	cmd.Flags().StringVar(&storage, "storage", "", "the outer storage id (or $HARNESS_STORAGE)")
	cmd.Flags().BoolVar(&staticOnly, "static-only", false, "run the static layer alone (no VM is created)")
	cmd.Flags().IntVar(&minFreeGiB, "min-free-gib", 0, "minimum free GiB the storage must have (0 = $HARNESS_PROBE_MIN_FREE_GIB, else 520)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if storage == "" {
			storage = os.Getenv("HARNESS_STORAGE")
		}
		min, err := resolveMinFreeGiB(minFreeGiB)
		if err != nil {
			return err
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return fmt.Errorf("cannot determine the home directory for the evidence and rule dirs: %w", err)
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		// The probe holds the VM lock across its whole run (static +
		// empirical + cleanup); the sink lives here, in the command's RunE,
		// per the lock-wait guard, and the driver takes no lock of its own.
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], probe.VMID))
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer func() { _ = unlock() }()

		d := probe.New(client, cfg, harnessLedger(cmd), probe.Params{
			TargetID:   args[0],
			Storage:    storage,
			StaticOnly: staticOnly,
			MinFreeGiB: min,
			RosterPath: rosterPath,
			Home:       home,
			Stdout:     cmd.OutOrStdout(),
		})
		return d.Run(cmd.Context())
	}
	markDestructive(cmd)
	return cmd
}

// resolveMinFreeGiB: the flag if set (>0), else $HARNESS_PROBE_MIN_FREE_GIB,
// else 520 (D10's sizing). A non-whole-number env is a usage error, as
// probe.sh refuses `5e2` (P12 keeps the env as the default, the flag optional).
func resolveMinFreeGiB(flag int) (int, error) {
	if flag > 0 {
		return flag, nil
	}
	if flag < 0 {
		return 0, fmt.Errorf("--min-free-gib must be a non-negative whole number of GiB")
	}
	if env := os.Getenv("HARNESS_PROBE_MIN_FREE_GIB"); env != "" {
		n, err := strconv.Atoi(env)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("HARNESS_PROBE_MIN_FREE_GIB must be whole GiB, got %q", env)
		}
		return n, nil
	}
	return 520, nil
}
