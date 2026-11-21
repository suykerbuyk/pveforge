package main

import (
	"errors"
	"fmt"

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
		unlock, err := lock.Read(cmd.Context(), rosterPath, lock.ObjectKey{TargetID: args[0], Kind: "node", ID: client.Node()})
		if err != nil {
			return fmt.Errorf("acquire read lock: %w", err)
		}
		defer func() { _ = unlock() }()

		results, err := client.CheckVerb(cmd.Context(), doctorVerb, id)
		if err != nil {
			return err
		}
		rep := buildDoctorReport(args[0], client.Node(), id, results)
		rep.bound()
		rerr := kvjson.Render(cmd.OutOrStdout(), format, rep)
		if rep.Result == "ok" {
			return rerr
		}
		return errors.Join(newRefusedError(doctorRefusal(rep)), rerr)
	}
	markSafe(cmd)
	return cmd
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
	var missing, unknown, unchecked int
	for _, r := range rep.Rows {
		switch pve.Verdict(r.Verdict) {
		case pve.VerdictMissing:
			missing++
		case pve.VerdictUnknown:
			unknown++
		case pve.VerdictNotChecked:
			unchecked++
		}
	}
	msg := fmt.Sprintf("doctor: %s on target %s: %d missing, %d unknown, %d not checked", rep.Verb, rep.Target, missing, unknown, unchecked)
	if unchecked > 0 {
		msg += "; pass --vmid N to check the VM privileges"
	}
	if missing > 0 {
		msg += "; grant what is missing"
	}
	return errors.New(msg)
}
