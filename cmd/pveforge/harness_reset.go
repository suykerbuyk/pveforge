package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/harness"
	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/harness/reset"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// pveforge-harness-golden-reset (U-GOLDEN/RESET): `pveforge harness golden` and
// `pveforge harness reset`, the Go port of hack/harness/golden.sh and reset.sh
// over the shared internal/harness/reset driver. golden takes a disk-only
// golden snapshot of 690/691/692; reset rolls them back to it. Both reuse
// U-CORE's guard + screened field allow-list, U-PROBE's static storage layer,
// and the in-process nested acceptance; neither destroys a VM. The command's
// RunE holds the three per-VM locks across the run (the lock-wait sink); the
// driver is lock-free.

// harnessAccept is the acceptance seam. Production awaits the NESTED cluster
// whole through harness.Open/AcceptOnce (never the outer RoutedClient the verbs
// use); a test replaces it so it needs no live nested cluster. It is a
// deadline-taking func (not AcceptOnce, one attempt) so a failing acceptance
// leg returns at once instead of waiting out the real 5m/15m deadline. The
// per-attempt report is a no-op (the final cause is returned, then bounded and
// printed by runRoot); nothing here writes to stderr.
var harnessAccept = func(ctx context.Context, deadline time.Duration, why string) error {
	return harness.Await(ctx, deadline, 30*time.Second, harness.AcceptOnce, func(int, error) {})
}

// resolveResetMinFreeGiB is the golden/reset free-space floor (gr_probe,
// golden-reset.sh:126-128): $HARNESS_RESET_MIN_FREE_GIB else 48 — NOT the
// probe's 520 (resolveMinFreeGiB knows only HARNESS_PROBE_MIN_FREE_GIB). A
// non-whole-number env is a usage error, as probe.sh:64 refuses 5e2.
func resolveResetMinFreeGiB() (int, error) {
	env := os.Getenv("HARNESS_RESET_MIN_FREE_GIB")
	if env == "" {
		return 48, nil
	}
	n, err := strconv.Atoi(env)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("HARNESS_RESET_MIN_FREE_GIB must be whole GiB, got %q", env)
	}
	return n, nil
}

// harnessResetSetup is everything a golden/reset RunE needs except the locks
// (which must be taken inline in the RunE so the lock-wait guard sees the sink
// beside addLockWaitFlag).
type harnessResetSetup struct {
	client     *pve.RoutedClient
	rosterPath string
	cfg        outer.Config
	min        int
	home       string
}

// prepareHarnessReset resolves the client, roster path, config, floor and home
// for a golden/reset run. It takes NO lock.
func prepareHarnessReset(cmd *cobra.Command, targetID string) (*harnessResetSetup, error) {
	min, err := resolveResetMinFreeGiB()
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil, fmt.Errorf("cannot determine the home directory for the evidence dir: %w", err)
	}
	client, rosterPath, err := harnessClient(cmd, targetID)
	if err != nil {
		return nil, err
	}
	return &harnessResetSetup{client: client, rosterPath: rosterPath, cfg: harnessConfig(cmd, client), min: min, home: home}, nil
}

// driver builds the reset driver, wiring the clock and the acceptance seam.
func (s *harnessResetSetup) driver(cmd *cobra.Command, targetID, storage string, replace bool) *reset.Driver {
	return reset.New(s.client, s.cfg, reset.Params{
		TargetID:   targetID,
		Storage:    storage,
		Replace:    replace,
		MinFreeGiB: s.min,
		Home:       s.home,
		Now:        time.Now,
		Accept: func(ctx context.Context, deadline time.Duration, why string) error {
			return harnessAccept(ctx, deadline, why)
		},
	})
}

func newHarnessGoldenCmd() *cobra.Command {
	var (
		storage string
		replace bool
	)
	cmd := &cobra.Command{
		Use:   "golden <target-id>",
		Short: "Take the nested harness's golden point (690-692)",
		Long: `Take a disk-only golden snapshot (pvh-golden) of the nested harness VMs
690, 691 and 692 after a graceful shutdown, then start them and accept the
nested cluster. Never destroys a VM. With --replace-golden every existing
golden is deleted first. The storage is checked by the capability probe's
static layer; the three VMs are locked for the whole run.`,
		Args: cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&storage, "storage", "", "the outer storage id (or $HARNESS_STORAGE)")
	cmd.Flags().BoolVar(&replace, "replace-golden", false, "delete any existing golden first (never a mix of old and new)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		if storage == "" {
			storage = os.Getenv("HARNESS_STORAGE")
		}
		setup, err := prepareHarnessReset(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = setup.client.Close() }()

		// The three per-VM locks, ascending, released on a failed acquire; the
		// sink lives here (beside addLockWaitFlag) so the lock-wait guard sees it.
		var unlocks []func() error
		release := func() {
			for i := len(unlocks) - 1; i >= 0; i-- {
				_ = unlocks[i]()
			}
		}
		for _, vmid := range reset.VMIDs {
			unlock, err := lock.Mutation(cmd.Context(), setup.rosterPath, harnessVMKey(args[0], vmid))
			if err != nil {
				release()
				return fmt.Errorf("acquire lock: %w", err)
			}
			unlocks = append(unlocks, unlock)
		}
		defer release()

		if err := setup.driver(cmd, args[0], storage, replace).Golden(cmd.Context()); err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "storage": storage, "result": "golden point taken"})
	}
	markDestructive(cmd)
	return cmd
}

func newHarnessResetCmd() *cobra.Command {
	var storage string
	cmd := &cobra.Command{
		Use:   "reset <target-id>",
		Short: "Reset the nested harness to its golden point (690-692)",
		Long: `Roll the nested harness VMs 690, 691 and 692 back to their golden point
(pvh-golden): after proving the three goldens are one point, hard-stop each,
delete every snapshot taken after the golden (newest first), roll back to the
golden, start them and accept the nested cluster. Never destroys a VM. The
three VMs are locked for the whole run.`,
		Args: cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&storage, "storage", "", "the outer storage id (or $HARNESS_STORAGE)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		if storage == "" {
			storage = os.Getenv("HARNESS_STORAGE")
		}
		setup, err := prepareHarnessReset(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = setup.client.Close() }()

		var unlocks []func() error
		release := func() {
			for i := len(unlocks) - 1; i >= 0; i-- {
				_ = unlocks[i]()
			}
		}
		for _, vmid := range reset.VMIDs {
			unlock, err := lock.Mutation(cmd.Context(), setup.rosterPath, harnessVMKey(args[0], vmid))
			if err != nil {
				release()
				return fmt.Errorf("acquire lock: %w", err)
			}
			unlocks = append(unlocks, unlock)
		}
		defer release()

		if err := setup.driver(cmd, args[0], storage, false).Reset(cmd.Context()); err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "storage": storage, "result": "reset to " + "pvh-golden"})
	}
	markDestructive(cmd)
	return cmd
}
