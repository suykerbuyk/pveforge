package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/harness/build"
	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// pveforge-harness-build (U-BUILD, the final Go-port unit): `pveforge harness
// build <target-id> --storage <id> [--keep-on-failure] [--repin]`, the Go port
// of hack/harness/build/build.sh + env.sh. It creates the three nested-cluster
// VMs (690/691/692) with the full screened create-field matrix, starts them,
// waits for their installed systems, ejects the node ISOs, and pins the host
// keys. On failure it tears down only this run's recorded VMs. The command's
// RunE holds the three per-VM locks; the internal/harness/build driver is
// lock-free. The destructive tier is confined to this verb.

// The build driver's seams, defaulted to production here and overridden by
// tests (package main is already serial; this keeps internal/harness/build and
// outer parallel-safe). An in-process roster read is the outer-host source — no
// pins subprocess (Findings a/c; D2: hb_pins is not ported).
var (
	buildOuterHost = func(rosterPath, target string) (string, error) {
		r, err := roster.Load(rosterPath)
		if err != nil {
			return "", fmt.Errorf("cannot read %s", rosterPath)
		}
		t := r.Find(target)
		if t == nil {
			return "", fmt.Errorf("%s names no target %s", rosterPath, target)
		}
		if t.Host == "" {
			return "", fmt.Errorf("%s: target %s has no host", rosterPath, target)
		}
		return t.Host, nil
	}
	buildLookupHost = func(host string) ([]string, error) {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, err
		}
		var v4 []string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				v4 = append(v4, a)
			}
		}
		return v4, nil
	}
	buildKeyscan = func(ip string) (string, error) {
		out, err := exec.Command("ssh-keyscan", "-T", "10", "-t", "ed25519", ip).Output()
		if err != nil {
			return "", err
		}
		return string(out), nil
	}
	buildDial = func(ip, port string) bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 5*time.Second)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	buildPollEvery     = 10 * time.Second
	buildPollFor       = 1800 * time.Second
	buildLeftoverBound = 600 * time.Second
	buildLeftoverPoll  = 5 * time.Second
)

func newHarnessBuildCmd() *cobra.Command {
	var (
		storage string
		keep    bool
		repin   bool
	)
	cmd := &cobra.Command{
		Use:   "build <target-id>",
		Short: "Build the nested cluster's three outer VMs (690-692)",
		Long: `Create the three outer VMs of the nested cluster (690 pvh-n1, 691 pvh-n2,
692 pvh-nfs) on the harness node, through pveforge as the pool token, with the
full create-field matrix screened against lib.sh's allow-list. It checks a clean
slate first (nothing created unless all preconditions hold), then creates,
starts, waits for the installed systems, ejects the node ISOs, and pins the host
keys. On any failure it destroys only the VMs this run created (or keeps them
with --keep-on-failure). Site values come from ~/.config/pveforge/harness-build.env.`,
		Args: cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	addHarnessIdentityFlags(cmd)
	addLockWaitFlag(cmd)
	addCreatedFileFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&storage, "storage", "", "the outer storage id (or $HARNESS_STORAGE)")
	cmd.Flags().BoolVar(&keep, "keep-on-failure", false, "on failure, leave this run's VMs for inspection instead of destroying them")
	cmd.Flags().BoolVar(&repin, "repin", false, "replace existing host-key pins for the three addresses (a new build makes new keys)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		if storage == "" {
			storage = os.Getenv("HARNESS_STORAGE")
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return fmt.Errorf("cannot determine the home directory for the evidence dir: %w", err)
		}
		client, rosterPath, err := harnessClient(cmd, args[0])
		if err != nil {
			return err
		}
		defer func() { _ = client.Close() }()
		cfg := harnessConfig(cmd, client)

		// Three per-VM locks, ascending, released on a failed acquire; the sink
		// lives here (beside addLockWaitFlag) so the lock-wait guard sees it.
		var unlocks []func() error
		release := func() {
			for i := len(unlocks) - 1; i >= 0; i-- {
				_ = unlocks[i]()
			}
		}
		for _, vmid := range build.VMIDs {
			unlock, err := lock.Mutation(cmd.Context(), rosterPath, harnessVMKey(args[0], vmid))
			if err != nil {
				release()
				return fmt.Errorf("acquire lock: %w", err)
			}
			unlocks = append(unlocks, unlock)
		}
		defer release()

		d := build.New(client, cfg, harnessLedger(cmd), build.Params{
			TargetID:      args[0],
			Storage:       storage,
			Keep:          keep,
			Repin:         repin,
			Home:          home,
			Now:           time.Now,
			OuterHost:     func() (string, error) { return buildOuterHost(rosterPath, args[0]) },
			LookupHost:    buildLookupHost,
			Keyscan:       buildKeyscan,
			Dial:          buildDial,
			PollEvery:     buildPollEvery,
			PollFor:       buildPollFor,
			LeftoverBound: buildLeftoverBound,
			LeftoverPoll:  buildLeftoverPoll,
		})
		if err := d.Run(cmd.Context()); err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"target": args[0], "storage": storage, "result": "built", "vmids": []int{690, 691, 692}})
	}
	markDestructive(cmd)
	return cmd
}
