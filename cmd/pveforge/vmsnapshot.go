package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// pveforge-vm-snapshot-cli: `vm snapshot list|create|delete|rollback`, over
// internal/pve's snapshot primitives and the rollback witness. Every
// mutation runs under the VM's lock.Mutation, and rollback holds ONE lock
// across the rollback and the witness after it, so another pveforge
// process cannot change the VM in between and have its change "proven".
// The lock serialises pveforge processes only: the web UI and qm take no
// part in it.

// lockNote ends each snapshot command's help.
const lockNote = `

Locking: the VM's pveforge lock is held for the whole command (a shared
read lock for list). It serialises pveforge processes only: a change made
at the same time from PVE's web UI or qm is not held off.`

// errRollbackCompletedWitnessInterrupted marks a rollback that completed
// and whose witness was then interrupted by a signal. Its text already says
// both, so runRoot prints it as it is — never with its generic "may or may
// not have been applied" note, which would contradict it — and still exits
// 128+signum, like its other interrupt exemptions.
var errRollbackCompletedWitnessInterrupted = errors.New("the rollback completed; the witness was interrupted before it could prove it")

// maxWitnessTimeout caps --witness-timeout.
const maxWitnessTimeout = 30 * time.Minute

// defaultWitnessTimeout is the agent-exec default: long enough for a guest
// agent to come back after a rollback that restarts the guest (UNVERIFIED
// against a live host).
const defaultWitnessTimeout = 2 * time.Minute

// witnessExcerptBytes bounds the guest output quoted in a witness warning.
const witnessExcerptBytes = 512

// defaultWitness is the default witness: pve's /bin/echo of a fresh nonce,
// with the nonce as the marker. A seam for tests.
var defaultWitness = pve.DefaultRollbackWitnessCommand

func newVMSnapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "List, create, delete and roll back VM snapshots",
	}
	cmd.AddCommand(newVMSnapshotListCmd())
	cmd.AddCommand(newVMSnapshotCreateCmd())
	cmd.AddCommand(newVMSnapshotDeleteCmd())
	cmd.AddCommand(newVMSnapshotRollbackCmd())
	return cmd
}

// snapshotArgs parses <target-id> <vmid>, and the VM's lock key.
func snapshotArgs(args []string) (vmid int, key lock.ObjectKey, err error) {
	vmid, err = strconv.Atoi(args[1])
	if err != nil {
		return 0, lock.ObjectKey{}, fmt.Errorf("invalid vmid %q: %w", args[1], err)
	}
	return vmid, lock.ObjectKey{TargetID: args[0], Kind: "vm", ID: strconv.Itoa(vmid)}, nil
}

// snapshotView is one real snapshot, as list prints it.
type snapshotView struct {
	Name        string `json:"name"`
	Snaptime    int64  `json:"snaptime"`
	Parent      string `json:"parent,omitempty"`
	Vmstate     int    `json:"vmstate"`
	Description string `json:"description,omitempty"`
}

// currentPseudoEntry is the entry PVE's list carries for the running state.
// It is exactly "current" (a real snapshot named "Current" is kept).
const currentPseudoEntry = "current"

func newVMSnapshotListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <target-id> <vmid>",
		Short: "List a VM's snapshots, oldest first",
		Long: `List a VM's snapshots, oldest first, as one "snapshots" value: each
snapshot's name, snaptime, parent, vmstate and description. PVE's own
"current" entry (the running state) is not a snapshot and is left out.` + lockNote,
		Args: cobra.ExactArgs(2),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, key, err := snapshotArgs(args)
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
		unlock, err := lock.Read(cmd.Context(), rosterPath, key)
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		snaps, err := client.ListSnapshots(cmd.Context(), vmid)
		if err != nil {
			return err
		}
		views := []snapshotView{}
		for _, s := range snaps {
			if s == nil || s.Name == currentPseudoEntry {
				continue
			}
			views = append(views, snapshotView{Name: s.Name, Snaptime: s.Snaptime, Parent: s.Parent, Vmstate: s.Vmstate, Description: s.Description})
		}
		sort.SliceStable(views, func(i, j int) bool { return views[i].Snaptime < views[j].Snaptime })
		return kvjson.Render(cmd.OutOrStdout(), format, map[string]any{"snapshots": views})
	}
	markSafe(cmd)
	return cmd
}

// snapshotResult is create's and rollback's result.
type snapshotResult struct {
	Target   string `json:"target"`
	VMID     int    `json:"vmid"`
	Snapshot string `json:"snapshot"`
	Result   string `json:"result,omitempty"`
	Rollback string `json:"rollback,omitempty"`
	Witness  string `json:"witness,omitempty"`
}

func newVMSnapshotCreateCmd() *cobra.Command {
	var description string
	cmd := &cobra.Command{
		Use:   "create <target-id> <vmid> <name>",
		Short: "Create a snapshot of a VM, with its RAM state",
		Long: `Create a snapshot of a VM, with its RAM state (vmstate), and verify it is in
the snapshot list afterwards. A name that already exists is refused, never
adopted: the same name is not the same snapshot. The names "current" and
"pending", in any case, are PVE's own and are refused before anything is sent.` + lockNote,
		Args: cobra.ExactArgs(3),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&description, "description", "", "the snapshot's description")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, key, err := snapshotArgs(args)
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
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, key)
		if err != nil {
			return fmt.Errorf("acquire lock for %s: %w", key, err)
		}
		defer func() { _ = unlock() }()

		if err := client.CreateSnapshot(cmd.Context(), vmid, args[2], description); err != nil {
			return err
		}
		return kvjson.Render(cmd.OutOrStdout(), format, snapshotResult{Target: args[0], VMID: vmid, Snapshot: args[2], Result: "created"})
	}
	markMutating(cmd)
	return cmd
}

func newVMSnapshotDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <target-id> <vmid> <name>...",
		Short: "Delete one or more of a VM's snapshots, newest first",
		Long: `Delete one or more of a VM's snapshots. The names are deleted newest first,
whatever order they are given in (read from the snapshot list under the
VM's lock), one at a time, each confirmed gone afterwards. A name that is
not a snapshot of the VM is reported as absent, not refused. If a delete
fails, the command stops and says which were already deleted; running the
same command again finishes the job.

To clear the way for a rollback, pass the snapshots vm snapshot rollback
names as newer than its target.` + lockNote,
		Args: cobra.MinimumNArgs(3),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, key, err := snapshotArgs(args)
		if err != nil {
			return err
		}
		names := args[2:]
		for _, n := range names {
			if strings.TrimSpace(n) == "" {
				return fmt.Errorf("delete snapshots of vm %d: a snapshot name is blank", vmid)
			}
			if strings.TrimSpace(n) == currentPseudoEntry {
				return fmt.Errorf("delete snapshots of vm %d: %w", vmid, &pve.ErrReservedSnapshotName{VMID: vmid, Name: n})
			}
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
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, key)
		if err != nil {
			return fmt.Errorf("acquire lock for %s: %w", key, err)
		}
		defer func() { _ = unlock() }()

		snaps, err := client.ListSnapshots(cmd.Context(), vmid)
		if err != nil {
			return err
		}
		// PVE's list, oldest first — its own order breaking a snaptime tie,
		// as NewerSnapshots does — so newest first is this reversed, the
		// order ErrNotNewestSnapshot.CascadeOrder names.
		var listed []*proxmox.VirtualMachineSnapshot
		for _, s := range snaps {
			if s != nil && s.Name != currentPseudoEntry {
				listed = append(listed, s)
			}
		}
		sort.SliceStable(listed, func(i, j int) bool { return listed[i].Snaptime < listed[j].Snaptime })
		rank := map[string]int{}
		for i, s := range listed {
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
		// Newest first: a chain is deleted from its leaf back.
		sort.Slice(present, func(i, j int) bool { return rank[present[i]] > rank[present[j]] })

		deleted := []string{}
		if len(present) > 0 {
			d, err := client.CascadeDeleteSnapshots(cmd.Context(), vmid, present)
			if d != nil {
				deleted = d
			}
			if err != nil {
				return fmt.Errorf("%w; deleted so far: %s; running the same command again is safe", err, kvjson.QuoteValue(strings.Join(deleted, ", ")))
			}
		}
		return kvjson.Render(cmd.OutOrStdout(), format, struct {
			Target  string   `json:"target"`
			VMID    int      `json:"vmid"`
			Deleted []string `json:"deleted"`
			Absent  []string `json:"absent"`
		}{args[0], vmid, deleted, absent})
	}
	markDestructive(cmd)
	return cmd
}

func newVMSnapshotRollbackCmd() *cobra.Command {
	var (
		noWitness      bool
		witnessTimeout time.Duration
		witnessCommand []string
		witnessMarker  string
	)
	cmd := &cobra.Command{
		Use:   "rollback <target-id> <vmid> <name>",
		Short: "Roll a VM back to its newest snapshot, then prove the guest is running",
		Long: `Roll a VM back to a snapshot, then prove the rolled-back guest is running.

Only the NEWEST snapshot can be rolled back to: if newer snapshots exist,
the rollback is refused before anything is sent, and the refusal names them
and the vm snapshot delete command that would discard them. Rollback never
deletes a snapshot itself.

After the rollback, a witness command is run in the guest through the QEMU
guest agent: by default /bin/echo with a fresh random marker, which assumes
a POSIX guest. --witness-command (repeatable: one argument each) and
--witness-marker replace it, for example for a Windows guest. The witness
waits up to --witness-timeout for the agent. --no-witness skips it.

Output: target, vmid, snapshot, rollback=completed and witness=verified (or
witness=skipped). If the witness fails, the command exits 1 and says that
the rollback itself completed but could not be proven.` + lockNote,
		Args: cobra.ExactArgs(3),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().BoolVar(&noWitness, "no-witness", false, "do not run the witness command after the rollback")
	cmd.Flags().DurationVar(&witnessTimeout, "witness-timeout", defaultWitnessTimeout, fmt.Sprintf("how long the witness may wait for the guest agent (at most %s)", maxWitnessTimeout))
	cmd.Flags().StringArrayVar(&witnessCommand, "witness-command", nil, "the witness command to run in the guest, one argument per flag (needs --witness-marker)")
	cmd.Flags().StringVar(&witnessMarker, "witness-marker", "", "text the witness command's output must contain")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		vmid, key, err := snapshotArgs(args)
		if err != nil {
			return err
		}
		name := args[2]
		if witnessTimeout <= 0 || witnessTimeout > maxWitnessTimeout {
			return fmt.Errorf("--witness-timeout %s: must be more than 0 and at most %s", witnessTimeout, maxWitnessTimeout)
		}
		if noWitness && (len(witnessCommand) > 0 || witnessMarker != "") {
			return fmt.Errorf("--no-witness cannot be combined with --witness-command or --witness-marker")
		}
		if len(witnessCommand) > 0 && strings.TrimSpace(witnessMarker) == "" {
			return fmt.Errorf("--witness-command needs a --witness-marker that is not empty or blank: without one, the witness would prove only that some command exited 0")
		}
		if len(witnessCommand) == 0 && witnessMarker != "" {
			return fmt.Errorf("--witness-marker is only for a --witness-command")
		}
		argv, marker := witnessCommand, witnessMarker
		if !noWitness && len(argv) == 0 {
			if argv, marker, err = defaultWitness(); err != nil {
				return err
			}
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
		// ONE hold, across the rollback and the witness.
		unlock, err := lock.Mutation(cmd.Context(), rosterPath, key)
		if err != nil {
			return fmt.Errorf("acquire lock for %s: %w", key, err)
		}
		defer func() { _ = unlock() }()

		if err := client.Rollback(cmd.Context(), vmid, name); err != nil {
			var newer *pve.ErrNotNewestSnapshot
			if errors.As(err, &newer) {
				return fmt.Errorf("%w; to discard them first, run: pveforge vm snapshot delete %s %d %s", err, sshexec.ShellQuote(args[0]), vmid, shellQuoteAll(newer.CascadeOrder()))
			}
			return err
		}

		res := snapshotResult{Target: args[0], VMID: vmid, Snapshot: name, Rollback: "completed", Witness: "skipped"}
		if !noWitness {
			status, err := client.RollbackWitness(cmd.Context(), vmid, argv, marker, witnessTimeout)
			if err != nil {
				return witnessFailure(cmd.ErrOrStderr(), cmd, args[0], vmid, name, status, err)
			}
			res.Witness = "verified"
		}
		return kvjson.Render(cmd.OutOrStdout(), format, res)
	}
	markDestructive(cmd)
	return cmd
}

// witnessFailure is rollback's error once the rollback itself completed and
// the witness did not prove it. A signal is marked
// (errRollbackCompletedWitnessInterrupted) so runRoot prints it as it is. A
// command that ran and failed, or whose output lacks the marker, also shows
// a bounded, quoted excerpt of what the guest printed.
func witnessFailure(errOut io.Writer, cmd *cobra.Command, targetID string, vmid int, name string, status *pve.AgentExecStatus, err error) error {
	// A signal, whenever it landed — during the witness, or after it had
	// already returned its own verdict — is marked, so runRoot never puts its
	// generic "may or may not have been applied" beside "completed".
	var ie interruptError
	if cmd.Context().Err() != nil || errors.As(context.Cause(cmd.Context()), &ie) {
		return fmt.Errorf("rollback vm %d to snapshot %q: %w: %w", vmid, name, errRollbackCompletedWitnessInterrupted, err)
	}
	var we *pve.RollbackWitnessError
	if errors.As(err, &we) && status != nil && (we.Reason == pve.WitnessCommandFailed || we.Reason == pve.WitnessMarkerMissing) {
		fmt.Fprintf(errOut, "warning: %s: vm %d: witness output: %s\n", targetID, vmid, kvjson.QuoteValue(witnessExcerpt(status.OutData)))
	}
	return fmt.Errorf("rollback vm %d to snapshot %q completed, but it could not be proven: %w", vmid, name, err)
}

// witnessExcerpt bounds guest output to witnessExcerptBytes, cut on a rune
// boundary, marking what it left out.
func witnessExcerpt(s string) string {
	if len(s) <= witnessExcerptBytes {
		return s
	}
	cut := witnessExcerptBytes
	// Back off to the start of the rune the bound falls in: at most
	// utf8.UTFMax-1 continuation bytes, so invalid input cannot walk far.
	for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(s[cut]); i++ {
		cut--
	}
	return fmt.Sprintf("%s … [%d bytes elided]", s[:cut], len(s)-cut)
}

// shellQuoteAll shell-quotes each name, space-separated, so a printed
// command can be pasted as it is.
func shellQuoteAll(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = sshexec.ShellQuote(n)
	}
	return strings.Join(q, " ")
}
