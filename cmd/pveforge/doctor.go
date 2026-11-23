package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/kvjson"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// doctorVerb is the one verb v1 knows. A later verb is a row in pve's
// requirement table and a flag here, not a new mechanism.
const doctorVerb = "vm destroy"

// doctorFix is the one remedy doctor prints, and only beside a Sys.Audit row
// that PVE itself refused (a 403). Never for a VM row, never for an unknown or
// unchecked one.
const doctorFixFmt = "pveforge acl enable-vm-destroy %s"

// doctorRow is one requirement's line.
type doctorRow struct {
	Requirement string `json:"requirement"`
	Path        string `json:"path"`
	Verdict     string `json:"verdict"`
	Hint        string `json:"hint,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// doctorReport is what `doctor` renders, through ONE kvjson.Render.
type doctorReport struct {
	Target string      `json:"target"`
	Verb   string      `json:"verb"`
	Node   string      `json:"node"`
	VMID   int         `json:"vmid,omitempty"`
	Result string      `json:"result"` // "ok" only when every row is held
	Rows   []doctorRow `json:"rows"`
	Fix    string      `json:"fix,omitempty"`
}

func (r *doctorReport) bound() {
	for i := range r.Rows {
		for _, p := range []*string{&r.Rows[i].Requirement, &r.Rows[i].Path, &r.Rows[i].Verdict, &r.Rows[i].Hint, &r.Rows[i].Detail} {
			*p = boundErrText(*p)
		}
	}
	for _, p := range []*string{&r.Target, &r.Verb, &r.Node, &r.Result, &r.Fix} {
		*p = boundErrText(*p)
	}
}

func newDoctorCmd() *cobra.Command {
	var vmid string
	cmd := &cobra.Command{
		Use:   "doctor <target-id>",
		Short: "Report which privileges `vm destroy` needs and which the token holds",
		Long: `Report, for ` + "`vm destroy`" + `, each privilege the token needs and whether it holds it.
It changes nothing: the token over REST, GET requests only, no SSH, no write to
the roster.

Each row is held, missing, unknown or not checked. The verdict is what the
verb's own read answers, not the permission tree: Sys.Audit on the node is
GET /nodes/<node>/status (200 held, 403 missing, anything else unknown), and
Sys.Audit on / is the cluster member list the retry reads. The permission tree
is printed beside it as a hint only.

The privileges on a VM (VM.PowerMgmt, VM.Allocate) are checked only when you
name one with --vmid; without it those rows are "not checked".

Exit status: 0 only when every row is held. 4 when any row is missing, unknown
or not checked: nothing was dispatched, so pass --vmid, or grant what is
missing (a missing Sys.Audit row prints ` + "`pveforge acl enable-vm-destroy <target-id>`" + `).
1 is doctor's own failure (roster, passphrase, usage).`,
		Args: cobra.ExactArgs(1),
	}
	addRosterFlag(cmd)
	addLockWaitFlag(cmd)
	resolveFormat := addOutputFlag(cmd)
	cmd.Flags().StringVar(&vmid, "vmid", "", "also check the privileges on this VM (a canonical decimal vmid)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		format, err := resolveFormat()
		if err != nil {
			return err
		}
		id := 0
		if cmd.Flags().Changed("vmid") {
			if id, err = parseDestroyVMID(vmid); err != nil {
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
		rep, err := doctorVerdict(cmd.Context(), client, func() (func() error, error) {
			return lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "node", ID: client.Node()})
		}, args[0], id)
		if err != nil {
			return err
		}
		rerr := kvjson.Render(cmd.OutOrStdout(), format, rep)
		if rep.Result == "ok" {
			return rerr
		}
		return errors.Join(newRefusedError(doctorRefusal(rep)), rerr)
	}
	markSafe(cmd)
	return cmd
}

// doctorVerdict is the ONE place the vm-destroy verdict is computed: the
// node's read lock (taken by readLock, which each locking command builds from
// its own cmd.Context(): the lock-wait guard holds a lock to the function that
// registers --lock-wait), the verb's own reads (RoutedClient.CheckVerb), the report,
// bounded. `doctor` renders it; `acl enable-vm-destroy` runs it after its
// write and renders the same rows. Nothing else in cmd/pveforge may call
// CheckVerb or decide a row (pinned by TestEnableFlow_T7_*).
func doctorVerdict(ctx context.Context, client *pve.RoutedClient, readLock func() (func() error, error), target string, vmid int) (doctorReport, error) {
	unlock, err := readLock()
	if err != nil {
		return doctorReport{}, fmt.Errorf("acquire read lock: %w", err)
	}
	defer func() { _ = unlock() }()
	results, err := client.CheckVerb(ctx, doctorVerb, vmid)
	if err != nil {
		return doctorReport{}, err
	}
	rep := buildDoctorReport(target, client.Node(), vmid, results)
	rep.bound()
	return rep, nil
}

// rowCounts is how many rows are in each state that is not held.
type rowCounts struct{ missing, unknown, unchecked int }

// classifyRows counts the rows that are not held. It is the one place a row's
// verdict word is read, for doctor's refusal and for the enable verb's verdict.
func classifyRows(rep doctorReport) rowCounts {
	var c rowCounts
	for _, r := range rep.Rows {
		switch pve.Verdict(r.Verdict) {
		case pve.VerdictMissing:
			c.missing++
		case pve.VerdictUnknown:
			c.unknown++
		case pve.VerdictNotChecked:
			c.unchecked++
		case pve.VerdictHeld:
		default:
			// A word this function does not know is never "held": fail closed.
			c.unknown++
		}
	}
	return c
}

// auditNotEffectiveRow is the row for a node path where the grant is correct
// but Sys.Audit is still absent (the token's own override row). The verdict
// word lives here, in doctor.go, with the rest of the row vocabulary.
func auditNotEffectiveRow(path string) doctorRow {
	return doctorRow{
		Requirement: "Sys.Audit on " + path, Path: path, Verdict: string(pve.VerdictMissing),
		Detail: "the token's own ACL row on this path overrides the granted role",
	}
}

// decideVerdict is the ONE function that decides whether the enable verb says
// ready, and the ONE writer of the verdict sentence: it returns both, so the
// bool and the sentence cannot disagree (ready == the sentence contains
// "privileges are ready", pinned on every fixture). unread, when non-empty,
// means the check itself did not run (no token client, a failed lock or read):
// that is never ready, and the sentence says the check did not run.
//
// Otherwise ready means no row is missing or unknown; a row not checked only
// because no --vmid was named does not count (those are the VM rows, which the
// verb never touches: its precondition is that the token already holds them).
func decideVerdict(rep doctorReport, vmid int, unread string) (ready bool, line string) {
	if unread != "" {
		return false, fmt.Sprintf("%s privileges are not ready: the check did not run (%s)", doctorVerb, unread)
	}
	c := classifyRows(rep)
	ready = c.missing == 0 && c.unknown == 0 && (c.unchecked == 0 || vmid == 0)
	if ready {
		scope := "scope=node"
		var held, unchecked []string
		for _, r := range rep.Rows {
			switch pve.Verdict(r.Verdict) {
			case pve.VerdictHeld:
				held = append(held, r.Requirement)
			case pve.VerdictNotChecked:
				unchecked = append(unchecked, r.Requirement)
			}
		}
		if vmid > 0 {
			scope = "scope=node+vm"
		}
		line = fmt.Sprintf("%s privileges are ready on %s (%s; held: %s", rep.Verb, rep.Node, scope, strings.Join(held, ", "))
		if len(unchecked) > 0 {
			line += "; not checked: " + strings.Join(unchecked, ", ") + ", pass --vmid N to check them"
		}
		return true, line + ")"
	}
	var parts []string
	for _, w := range []pve.Verdict{pve.VerdictMissing, pve.VerdictUnknown, pve.VerdictNotChecked} {
		var rows []string
		for _, r := range rep.Rows {
			if pve.Verdict(r.Verdict) != w {
				continue
			}
			row := r.Requirement
			if r.Detail != "" {
				row += " (" + r.Detail + ")"
			}
			rows = append(rows, row)
		}
		if len(rows) > 0 {
			parts = append(parts, string(w)+": "+strings.Join(rows, ", "))
		}
	}
	return false, fmt.Sprintf("%s privileges are not ready on %s: %s", rep.Verb, rep.Node, strings.Join(parts, "; "))
}

func buildDoctorReport(target, node string, vmid int, results []pve.RequirementResult) doctorReport {
	rep := doctorReport{Target: target, Verb: doctorVerb, Node: node, VMID: vmid, Result: "ok"}
	for _, r := range results {
		rep.Rows = append(rep.Rows, doctorRow{
			Requirement: r.Privilege + " on " + r.Path, Path: r.Path,
			Verdict: string(r.Verdict), Hint: r.Hint, Detail: r.Detail,
		})
		if r.Verdict != pve.VerdictHeld {
			rep.Result = "refused"
		}
		if r.Verdict == pve.VerdictMissing && r.Privilege == "Sys.Audit" {
			rep.Fix = fmt.Sprintf(doctorFixFmt, target)
		}
	}
	return rep
}

// doctorRefusal is the one-line error behind exit 4: counts only, no PVE text.
func doctorRefusal(rep doctorReport) error {
	c := classifyRows(rep)
	msg := fmt.Sprintf("doctor: %s on target %s: %d missing, %d unknown, %d not checked", rep.Verb, rep.Target, c.missing, c.unknown, c.unchecked)
	if c.unchecked > 0 {
		msg += "; pass --vmid N to check the VM privileges"
	}
	if c.missing > 0 {
		msg += "; grant what is missing"
	}
	return errors.New(msg)
}
