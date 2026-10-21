// Package reset is the Go port of hack/harness/golden.sh + reset.sh and their
// shared library hack/harness/golden-reset.sh (U-GOLDEN/RESET): the outer
// test-harness golden-point capture and the rollback-to-golden reset, the
// third consumer of U-CORE. It CONSUMES U-CORE/U-PROBE (outer.Guard, the
// screened field allow-list, the static storage layer, outer.VMPath/RawUPID)
// and the in-process nested acceptance (internal/harness) rather than
// re-implementing any of them. It is a parallel, additive path; lib.sh, the
// shell scripts and the pinned sourceguard tests are untouched.
//
// It NEVER destroys a VM (golden-reset.sh:5): every write is one of
// status/{shutdown,stop,start}, snapshot, snapshot/<name> (delete via the pve
// cascade) or snapshot/<name>/rollback. The three per-VM locks that serialise
// the run are taken by the command's RunE (the lock-wait guard sink); this
// driver is lock-free and issues every mutation as a direct leaf, never
// idempotent.Run (which owns its own per-VM lock and would deadlock).
package reset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// The harness identities, ported from golden-reset.sh:7-11.
const (
	goldenName = "pvh-golden"                     // GR_GOLDEN
	descPrefix = "pveforge harness golden point " // GR_DESC_PREFIX (trailing space)
)

// VMIDs / stopOrder / startOrder are golden-reset.sh:8-11: 690 pvh-n1,
// 691 pvh-n2, 692 pvh-nfs. Stop the nodes before the storage they mount
// (691,690,692); start the storage first (692,690,691). VMIDs is exported so
// the command can build the per-VM lock keys it holds across the run.
var (
	VMIDs      = [...]int{690, 691, 692}
	stopOrder  = [...]int{691, 690, 692}
	startOrder = [...]int{692, 690, 691}
)

// stampRE is golden-reset.sh / reset.sh:70's run stamp, anchored exactly
// (jq's \A…\z): yyyymmddThhmmssZ, nothing before or after.
var stampRE = mustStampRE()

// Params are the golden/reset verbs' inputs.
type Params struct {
	TargetID   string
	Storage    string
	Replace    bool // golden only: --replace-golden
	MinFreeGiB int  // the reset free-space floor (resolved by the command)
	Home       string

	// Now is the run clock, read ONCE per run (one stamp for all three VMs,
	// reset.sh's "one point"). Tests inject a fixed clock; nil means time.Now.
	Now func() time.Time
	// Accept awaits the nested cluster whole, up to deadline. Production wraps
	// harness.Await(…, AcceptOnce) (dialling the NESTED roster, not the outer
	// RoutedClient the verbs use); tests inject an immediate result so an
	// accept-failure leg need not block to the real 5m/15m deadline.
	Accept func(ctx context.Context, deadline time.Duration, why string) error
}

// Driver runs golden/reset against one routed client. Lock-free (the command
// holds the three per-VM locks).
type Driver struct {
	client *pve.RoutedClient
	cfg    outer.Config
	p      Params

	what        string         // "golden" | "reset" (evidence subdir)
	evid        string         // this run's evidence directory
	stamp       string         // this run's clock stamp (one per run)
	failed      bool           // a gr_fail-style failure already recorded a FAILED line
	goldenState map[int]string // golden only: per-VM old|none|new (gr_on_exit's suffix)
}

// New builds a Driver. cfg.Node must be the client's node.
func New(client *pve.RoutedClient, cfg outer.Config, p Params) *Driver {
	return &Driver{client: client, cfg: cfg, p: p, goldenState: map[int]string{}}
}

// Golden takes the golden point (golden.sh); Reset rolls back to it (reset.sh).
func (d *Driver) Golden(ctx context.Context) error { return d.run(ctx, "golden", d.golden) }
func (d *Driver) Reset(ctx context.Context) error  { return d.run(ctx, "reset", d.reset) }

// run is the shared frame: validate the storage, run the static layer (the
// first PVE call is the storage status, spec harness_reset_test.go:328-331),
// the pre-change roster gate, then open evidence and the flow, writing the
// gr_on_exit FAILED line on a failure.
func (d *Driver) run(ctx context.Context, what string, flow func(context.Context) error) error {
	d.what = what
	if _, err := outer.RequireStorage(d.p.Storage); err != nil {
		return err // usage refusal, before any PVE call or evidence (reset.sh:38)
	}
	if err := d.staticLayer(ctx); err != nil {
		return err // the first PVE call; before evidence (gr_probe, golden-reset.sh:126)
	}
	if err := d.rosterGate(); err != nil {
		return err // pre-change, no PVE call (gr_accept_bin, golden-reset.sh:95-98)
	}
	if err := d.openEvidence(); err != nil {
		return err
	}
	return d.onExit(flow(ctx))
}

// staticLayer reuses U-PROBE's static storage layer (outer.RequireStorage has
// already validated the id). A refusal is wrapped in gr_probe's cause
// ("…static layer refused storage…", golden-reset.sh:129) so the spec's
// inactive-storage and free-space-floor legs (spec :395,:398,:454) match.
func (d *Driver) staticLayer(ctx context.Context) error {
	st, _, err := outer.ReadStorageStatus(ctx, d.client, d.cfg.Node, d.p.Storage)
	if err != nil {
		return fmt.Errorf("the capability probe's static layer refused storage %s: %v", d.p.Storage, err)
	}
	if reason := st.Unsuitable(d.p.MinFreeGiB); reason != "" {
		return fmt.Errorf("the capability probe's static layer refused storage %s: %s", d.p.Storage, reason)
	}
	return nil
}

// rosterGate is gr_accept_bin's pre-change refusal (golden-reset.sh:95-98):
// acceptance needs the nested roster and the outer-roster list named, and
// refuses before any change if either is missing (spec "no nested roster"
// leg, :434). Only presence is checked here; the nested dial is Accept's.
func (d *Driver) rosterGate() error {
	if os.Getenv("PVEFORGE_HARNESS_ROSTER") == "" {
		return errors.New("PVEFORGE_HARNESS_ROSTER must name the nested harness roster: acceptance reads the nested cluster through it")
	}
	if os.Getenv("PVEFORGE_HARNESS_OUTER_ROSTERS") == "" {
		return errors.New("PVEFORGE_HARNESS_OUTER_ROSTERS must list the outer rosters: acceptance refuses any overlap with them")
	}
	return nil
}

// ---- golden (golden.sh) -------------------------------------------------

func (d *Driver) golden(ctx context.Context) error {
	for _, vmid := range VMIDs {
		if err := d.checkVM(ctx, vmid); err != nil {
			return err
		}
		snaps, err := d.readSnapshots(ctx, vmid, "snapshots-before")
		if err != nil {
			return err
		}
		has := hasGolden(snaps)
		if has && !d.p.Replace {
			return d.die(fmt.Sprintf("VM %d already has %s; replacing the golden point needs --replace-golden", vmid, goldenName))
		}
		if has {
			d.goldenState[vmid] = "old"
		} else {
			d.goldenState[vmid] = "none"
		}
	}
	if err := d.accept(ctx, 5*time.Minute, "before the golden point"); err != nil {
		return err
	}
	// Graceful shutdown, nodes before storage, each then read stopped.
	for _, vmid := range stopOrder {
		if err := d.postLeaf(ctx, vmid, "status/shutdown", "shutdown", url.Values{"timeout": {"300"}}); err != nil {
			return d.die(fmt.Sprintf("VM %d: the shutdown failed: %v", vmid, err))
		}
		if err := d.confirmStopped(ctx, vmid); err != nil {
			return err
		}
	}
	// --replace-golden: every old golden deleted, and that recorded, before any
	// new one (golden.sh:73-84).
	if d.p.Replace {
		for _, vmid := range VMIDs {
			snaps, err := d.readSnapshots(ctx, vmid, "")
			if err != nil {
				return err
			}
			if hasGolden(snaps) {
				if err := d.guardChange(ctx, vmid); err != nil {
					return d.die(err.Error())
				}
				// Delete that ONE name (never an empty slice, snapshot.go:683-688).
				if _, err := d.client.CascadeDeleteSnapshots(ctx, vmid, []string{goldenName}); err != nil {
					return d.die(fmt.Sprintf("VM %d: deleting the old %s failed: %v", vmid, goldenName, err))
				}
				d.goldenState[vmid] = "none"
				d.step(fmt.Sprintf("VM %d: the old %s deleted (--replace-golden)", vmid, goldenName))
			}
		}
		d.step("no golden exists on " + vmidList())
	}
	// A disk-only golden of each, read back as one stamped disk-only snapshot.
	for _, vmid := range VMIDs {
		params := url.Values{"snapname": {goldenName}, "vmstate": {"0"}, "description": {descPrefix + d.stamp}}
		if err := d.postLeaf(ctx, vmid, "snapshot", "snapshot", params); err != nil {
			return d.die(fmt.Sprintf("VM %d: taking %s failed: %v", vmid, goldenName, err))
		}
		d.goldenState[vmid] = "new"
		snaps, err := d.readSnapshots(ctx, vmid, "snapshots-after")
		if err != nil {
			return err
		}
		if !d.goldenReadsBack(snaps) {
			return d.fail(fmt.Sprintf("VM %d: %s does not read back as one disk-only snapshot stamped %s", vmid, goldenName, d.stamp))
		}
		d.step(fmt.Sprintf("VM %d: %s taken", vmid, goldenName))
	}
	if err := d.start(ctx); err != nil {
		return err
	}
	if err := d.accept(ctx, 15*time.Minute, "after the golden point"); err != nil {
		return err
	}
	d.step("RESULT golden point taken")
	return nil
}

// ---- reset (reset.sh) ---------------------------------------------------

type vmReset struct {
	newer []string // snapshots strictly newer than golden, newest first
	stamp string   // golden's run stamp
}

func (d *Driver) reset(ctx context.Context) error {
	state := map[int]*vmReset{}
	for _, vmid := range VMIDs {
		if err := d.checkVM(ctx, vmid); err != nil {
			return err
		}
		snaps, err := d.readSnapshots(ctx, vmid, "snapshots-before")
		if err != nil {
			return err
		}
		newer, err := d.newerThanGolden(vmid, snaps)
		if err != nil {
			return err
		}
		stamp, err := d.goldenStamp(vmid, snaps)
		if err != nil {
			return err
		}
		state[vmid] = &vmReset{newer: newer, stamp: stamp}
	}
	// The three goldens must be ONE point (reset.sh:82-86).
	for _, vmid := range VMIDs {
		if state[vmid].stamp != state[VMIDs[0]].stamp {
			return d.die("the goldens are not one point: " + stampList(state))
		}
	}
	d.step("the goldens are one point: stamp " + state[VMIDs[0]].stamp)
	// Hard stop, nodes before storage, each not already stopped; then confirm.
	for _, vmid := range stopOrder {
		st, err := d.status(ctx, vmid)
		if err != nil {
			return err
		}
		if st != "stopped" {
			if err := d.postLeaf(ctx, vmid, "status/stop", "stop", nil); err != nil {
				return d.die(fmt.Sprintf("VM %d: the stop failed: %v", vmid, err))
			}
		}
		if err := d.confirmStopped(ctx, vmid); err != nil {
			return err
		}
	}
	// Cascade (newest first), then the raw rollback leaf (Chair-settled B1:
	// never client.Rollback, which re-classifies newest-only and may send no
	// POST on a reset the shell completes).
	for _, vmid := range VMIDs {
		names := state[vmid].newer
		if len(names) > 0 {
			if err := d.guardChange(ctx, vmid); err != nil {
				return d.die(err.Error())
			}
			if _, err := d.client.CascadeDeleteSnapshots(ctx, vmid, names); err != nil {
				return d.die(fmt.Sprintf("VM %d: deleting its newer snapshots failed: %v", vmid, err))
			}
			for _, n := range names {
				d.step(fmt.Sprintf("VM %d: snapshot %s deleted", vmid, n))
			}
		}
		if err := d.postLeaf(ctx, vmid, "snapshot/"+goldenName+"/rollback", "rollback", nil); err != nil {
			return d.die(fmt.Sprintf("VM %d: the rollback to %s failed: %v", vmid, goldenName, err))
		}
		d.step(fmt.Sprintf("VM %d: rolled back to %s", vmid, goldenName))
	}
	if err := d.start(ctx); err != nil {
		return err
	}
	if err := d.accept(ctx, 15*time.Minute, "after the reset"); err != nil {
		return err
	}
	d.step("RESULT reset to " + goldenName)
	return nil
}

// ---- per-VM checks ------------------------------------------------------

// checkVM is gr_check_vm (golden-reset.sh:159-169): the system disk on the
// required storage, and no lock. A non-string / absent scsi0 or lock reads as
// "" (fail-closed). NOT outer.Guard (that checks pool/node/tag, not scsi0/lock).
func (d *Driver) checkVM(ctx context.Context, vmid int) error {
	raw, err := d.client.RawRequest(ctx, http.MethodGet, outer.VMPath(d.cfg.Node, vmid, "config"), nil)
	if err != nil {
		return d.die(fmt.Sprintf("reading VM %d's config failed: %v", vmid, err))
	}
	d.evidence(fmt.Sprintf("config-%d.json", vmid), raw)
	var conf struct {
		Scsi0 string `json:"scsi0"`
		Lock  string `json:"lock"`
	}
	_ = json.Unmarshal(raw, &conf) // a non-string field → "" (fail-closed)
	store := conf.Scsi0
	if i := strings.IndexByte(store, ':'); i >= 0 {
		store = store[:i]
	}
	if store != d.p.Storage {
		return d.die(fmt.Sprintf("VM %d: its system disk is on '%s', not the required storage %s", vmid, store, d.p.Storage))
	}
	if conf.Lock != "" {
		return d.die(fmt.Sprintf("VM %d holds lock '%s'; lib cannot clear it. Operator ask: qm unlock %d on %s, as root", vmid, conf.Lock, vmid, d.cfg.Node))
	}
	return nil
}

// status is gr_status (golden-reset.sh:138-145): the VM's run state, fail-closed
// on a missing or non-string status.
func (d *Driver) status(ctx context.Context, vmid int) (string, error) {
	raw, err := d.client.RawRequest(ctx, http.MethodGet, outer.VMPath(d.cfg.Node, vmid, "status/current"), nil)
	if err != nil {
		return "", d.die(fmt.Sprintf("reading VM %d's status failed: %v", vmid, err))
	}
	var s struct {
		Status *string `json:"status"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Status == nil || *s.Status == "" {
		return "", d.die(fmt.Sprintf("VM %d: the status answer has an unexpected shape", vmid))
	}
	return *s.Status, nil
}

// confirmStopped is gr_confirm_stopped (golden-reset.sh:173-178): a second
// status read proves it stopped; the task outcome alone does not. A VM still
// running is a gr_fail (not a gr_on_exit "FAILED exit").
func (d *Driver) confirmStopped(ctx context.Context, vmid int) error {
	st, err := d.status(ctx, vmid)
	if err != nil {
		return err
	}
	if st != "stopped" {
		return d.fail(fmt.Sprintf("VM %d is '%s' after its stop reported success", vmid, st))
	}
	d.step(fmt.Sprintf("VM %d: stopped", vmid))
	return nil
}

// ---- leaves -------------------------------------------------------------

// postLeaf is the one task-returning write path (so taskwait_guard counts a
// single WaitForTask site in this file): screen every field against lib.sh's
// allow-list, Guard(ModeChange), raw POST the subpath, wait. sub is always one
// of status/{shutdown,stop,start}, snapshot, snapshot/<name>/rollback — any
// other subpath would be operator-binding.
func (d *Driver) postLeaf(ctx context.Context, vmid int, sub, set string, params url.Values) error {
	for k := range params {
		if !outer.AllowedField(set, k) {
			return fmt.Errorf("%s %s is not an allowed harness field", set, k)
		}
	}
	if err := d.guardChange(ctx, vmid); err != nil {
		return err
	}
	upid, err := outer.RawUPID(ctx, d.client, http.MethodPost, outer.VMPath(d.cfg.Node, vmid, sub), params)
	if err != nil {
		return err
	}
	return d.client.WaitForTask(ctx, d.cfg.Node, upid)
}

// start is gr_start (golden-reset.sh:181-187): start the VMs, storage first.
// There is no status/start leaf in U-CORE; this mirrors the stop leaf.
func (d *Driver) start(ctx context.Context) error {
	for _, vmid := range startOrder {
		if err := d.postLeaf(ctx, vmid, "status/start", "start", nil); err != nil {
			return d.die(fmt.Sprintf("VM %d: the start failed: %v", vmid, err))
		}
		d.step(fmt.Sprintf("VM %d: started", vmid))
	}
	return nil
}

func (d *Driver) guardChange(ctx context.Context, vmid int) error {
	return outer.Guard(ctx, d.client, d.cfg, nil, vmid, outer.ModeChange)
}

// accept runs the injected acceptance; a failure is a gr_fail (gr_accept,
// golden-reset.sh:113-119).
func (d *Driver) accept(ctx context.Context, deadline time.Duration, why string) error {
	if err := d.p.Accept(ctx, deadline, why); err != nil {
		return d.fail(fmt.Sprintf("accept (%s): the nested cluster was not accepted: %v", why, err))
	}
	d.step(fmt.Sprintf("accepted (%s)", why))
	return nil
}

// ---- snapshot decoding (two views) --------------------------------------

// snapEntry is one real (non-"current") snapshot, decoded from RAW JSON so a
// missing snaptime is distinguishable from 0 (go-proxmox would collapse both),
// reproducing gr_snapshots / newer_than_golden / golden_stamp exactly.
type snapEntry struct {
	name     string
	snaptime int64
	hasTime  bool // snaptime present AND an integer JSON number
	diskOnly bool // vmstate absent OR integer 0 (jq's (.vmstate // 0) == 0)
	desc     string
}

// readSnapshots reads the snapshot list and returns the DECISION view
// ("current" removed). It is VERIFIABLE (B2 / C5): "current" must be present,
// else the list is a swallowed/unverifiable read, not "no snapshots". If evFile
// is non-empty the raw list is written to evidence.
func (d *Driver) readSnapshots(ctx context.Context, vmid int, evFile string) ([]snapEntry, error) {
	raw, err := d.client.RawRequest(ctx, http.MethodGet, outer.VMPath(d.cfg.Node, vmid, "snapshot"), nil)
	if err != nil {
		return nil, d.die(fmt.Sprintf("reading VM %d's snapshots failed: %v", vmid, err))
	}
	if evFile != "" {
		d.evidence(fmt.Sprintf("%s-%d.json", evFile, vmid), raw)
	}
	decision, hasCurrent, perr := parseSnaps(raw)
	if perr != nil {
		return nil, d.die(fmt.Sprintf("VM %d: the snapshot list has an unexpected shape", vmid))
	}
	if !hasCurrent {
		return nil, d.die(fmt.Sprintf("VM %d: the snapshot list is unverifiable: PVE's \"current\" entry is absent", vmid))
	}
	return decision, nil
}

// parseSnaps decodes the raw snapshot array (gr_snapshots, golden-reset.sh:147-154):
// every entry needs a string name; "current" is dropped from the decision view
// but its presence is reported for the verifiable check.
func parseSnaps(raw json.RawMessage) (decision []snapEntry, hasCurrent bool, err error) {
	var arr []map[string]json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return nil, false, errors.New("unexpected shape")
	}
	for _, m := range arr {
		var name string
		if json.Unmarshal(m["name"], &name) != nil || name == "" {
			return nil, false, errors.New("unexpected shape")
		}
		if name == "current" {
			hasCurrent = true
			continue
		}
		e := snapEntry{name: name, diskOnly: true}
		if t, ok := m["snaptime"]; ok {
			if i, ok := intJSON(t); ok {
				e.snaptime, e.hasTime = i, true
			}
		}
		if v, ok := m["vmstate"]; ok {
			e.diskOnly = isIntZero(v) // present → must be integer 0
		}
		if dsc, ok := m["description"]; ok {
			var s string
			if json.Unmarshal(dsc, &s) == nil {
				e.desc = s
			}
		}
		decision = append(decision, e)
	}
	return decision, hasCurrent, nil
}

// newerThanGolden is reset.sh:50-60: exactly one golden, a numeric snaptime on
// every real snapshot, no two at the same time; it returns the snapshots
// strictly newer than golden, newest first (by time, never by name). The three
// jq conditions share one cause, so each spec leg's substring matches it.
func (d *Driver) newerThanGolden(vmid int, snaps []snapEntry) ([]string, error) {
	msg := fmt.Sprintf("VM %d: the snapshots need exactly one %s, a time on each, and no two at the same time", vmid, goldenName)
	goldens := 0
	var gt int64
	seen := map[int64]bool{}
	for _, s := range snaps {
		if s.name == goldenName {
			goldens++
			gt = s.snaptime
		}
		if !s.hasTime {
			return nil, d.die(msg)
		}
		if seen[s.snaptime] {
			return nil, d.die(msg)
		}
		seen[s.snaptime] = true
	}
	if goldens != 1 {
		return nil, d.die(msg)
	}
	var newer []snapEntry
	for _, s := range snaps {
		if s.snaptime > gt {
			newer = append(newer, s)
		}
	}
	sort.SliceStable(newer, func(i, j int) bool { return newer[i].snaptime > newer[j].snaptime })
	names := make([]string, 0, len(newer))
	for _, s := range newer {
		names = append(names, s.name)
	}
	return names, nil
}

// goldenStamp is golden_stamp (reset.sh:64-72): the golden must be disk-only
// (vmstate 0) and its description must be the prefix plus a run stamp (one
// trailing newline tolerated, via TrimSuffix — not TrimRight, which would
// strip two and accept a stamp the shell refuses).
func (d *Driver) goldenStamp(vmid int, snaps []snapEntry) (string, error) {
	msg := fmt.Sprintf("VM %d: %s must be disk-only (vmstate 0) and carry golden.sh's run stamp; retake it with golden.sh --replace-golden", vmid, goldenName)
	var g *snapEntry
	for i := range snaps {
		if snaps[i].name == goldenName {
			g = &snaps[i]
		}
	}
	if g == nil || !g.diskOnly {
		return "", d.die(msg)
	}
	desc := strings.TrimSuffix(g.desc, "\n")
	if !strings.HasPrefix(desc, descPrefix) {
		return "", d.die(msg)
	}
	stamp := strings.TrimPrefix(desc, descPrefix)
	if !stampRE.MatchString(stamp) {
		return "", d.die(msg)
	}
	return stamp, nil
}

// goldenReadsBack is golden.sh:91-94: exactly one golden, disk-only, with a
// description equal to the prefix plus THIS run's stamp (one trailing newline
// tolerated).
func (d *Driver) goldenReadsBack(snaps []snapEntry) bool {
	n := 0
	var g *snapEntry
	for i := range snaps {
		if snaps[i].name == goldenName {
			n++
			g = &snaps[i]
		}
	}
	if n != 1 || !g.diskOnly {
		return false
	}
	return strings.TrimSuffix(g.desc, "\n") == descPrefix+d.stamp
}

func hasGolden(snaps []snapEntry) bool {
	for _, s := range snaps {
		if s.name == goldenName {
			return true
		}
	}
	return false
}

// ---- evidence + outcome -------------------------------------------------

// openEvidence makes this run's evidence directory
// ~/.config/pveforge/harness-evidence/<what>/<UTC stamp>, mode 0700, and reads
// the run clock ONCE (golden-reset.sh:36-47).
func (d *Driver) openEvidence() error {
	d.stamp = d.now().UTC().Format("20060102T150405Z")
	root := filepath.Join(d.p.Home, ".config/pveforge/harness-evidence", d.what)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", root, err)
	}
	_ = os.Chmod(root, 0o700)
	d.evid = filepath.Join(root, d.stamp)
	if err := os.Mkdir(d.evid, 0o700); err != nil {
		return fmt.Errorf("cannot create the evidence directory %s (one run per second): %w", d.evid, err)
	}
	return nil
}

func (d *Driver) now() time.Time {
	if d.p.Now != nil {
		return d.p.Now()
	}
	return time.Now()
}

// step records one completed step (gr_step), best-effort.
func (d *Driver) step(line string) { d.appendSteps(line) }

// evidence records name=content (gr_evidence), best-effort.
func (d *Driver) evidence(name string, content []byte) {
	if d.evid == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(d.evid, name), append(bytes.TrimRight(content, "\n"), '\n'), 0o600)
}

func (d *Driver) appendSteps(line string) {
	if d.evid == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(d.evid, "steps"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line + "\n")
}

// die records nothing itself: the gr_on_exit line (FAILED exit) is written by
// onExit when the flow returns this error (the _harness_die path).
func (d *Driver) die(reason string) error { return errors.New(reason) }

// fail is gr_fail (golden-reset.sh:85-90): it records "FAILED <reason>" and
// sets the flag so onExit does not add a second "FAILED exit" line.
func (d *Driver) fail(reason string) error {
	d.failed = true
	d.appendSteps("FAILED " + reason)
	return errors.New(reason)
}

// onExit is gr_on_exit (golden-reset.sh:54-70): on a failure, a _harness_die
// path writes "FAILED exit 1" plus (golden) the golden-state suffix; a gr_fail
// path writes only the suffix (its "FAILED <reason>" line is already there),
// or nothing when there is no suffix (reset).
func (d *Driver) onExit(err error) error {
	if err == nil {
		return nil
	}
	states := d.goldenStateSuffix()
	if !d.failed {
		d.appendSteps("FAILED exit 1" + states)
	} else if states != "" {
		d.appendSteps("FAILED" + states)
	}
	return err
}

// goldenStateSuffix is "; golden state: 690=<s> 691=<s> 692=<s>" for a golden
// run that recorded any state, else "" (reset never records state).
func (d *Driver) goldenStateSuffix() string {
	if len(d.goldenState) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("; golden state:")
	for _, vmid := range VMIDs {
		s := d.goldenState[vmid]
		if s == "" {
			s = "unknown"
		}
		fmt.Fprintf(&b, " %d=%s", vmid, s)
	}
	return b.String()
}

// stampList is reset.sh:84's "690=<s> 691=<s> 692=<s>" (VMID order).
func stampList(state map[int]*vmReset) string {
	parts := make([]string, 0, len(VMIDs))
	for _, vmid := range VMIDs {
		parts = append(parts, fmt.Sprintf("%d=%s", vmid, state[vmid].stamp))
	}
	return strings.Join(parts, " ")
}

func vmidList() string {
	parts := make([]string, 0, len(VMIDs))
	for _, vmid := range VMIDs {
		parts = append(parts, fmt.Sprint(vmid))
	}
	return strings.Join(parts, " ")
}

func mustStampRE() *regexp.Regexp { return regexp.MustCompile(`\A[0-9]{8}T[0-9]{6}Z\z`) }

// intJSON reports a JSON token that is an integer number as an int64 (never a
// quoted string, a float or a bool). It mirrors outer.intJSON's rule so a
// snaptime read here matches the shell's `type == "number"` test for an
// integer epoch second.
func intJSON(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return 0, false
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}

// isIntZero reports whether raw is the integer JSON number 0 (jq's
// (.vmstate // 0) == 0 for a PRESENT vmstate: a 1 or a non-number is not 0).
func isIntZero(raw json.RawMessage) bool {
	i, ok := intJSON(raw)
	return ok && i == 0
}
