// Package probe is the Go port of hack/harness/probe.sh (U-PROBE): the outer
// storage-capability probe, the first consumer of U-CORE. It CONSUMES U-CORE
// (outer.Guard / outer.VMGone / outer.VMIDFree / outer.Ledger, the pve client
// snapshot/destroy ops, and the already-exported *pve.ErrNotNewestSnapshot
// classifier) rather than re-implementing any of them. It is a parallel,
// additive path; lib.sh/probe.sh and the pinned sourceguard tests are
// untouched.
//
// Outcome is classified on STDOUT, never an exit integer (runRoot collapses
// every error to 1): the success line is `rollback-rule=<rule> storage=<id>`;
// a refusal and a failure each print a distinct line and write no rule file.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	proxmox "github.com/suykerbuyk/go-proxmox"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// VMID is the one VMID the probe touches (690), exported so the command can
// build the lock key it holds across the run.
const VMID = vmid

// vmid is the one VMID the probe touches (probe.sh runs only on 690, before
// the build).
const vmid = 690

// Params are the probe verb's inputs.
type Params struct {
	TargetID   string
	Storage    string
	StaticOnly bool
	MinFreeGiB int
	RosterPath string
	Home       string // $HOME, for the evidence and rule-state dirs
	Stdout     io.Writer
	// LeftoverBound/LeftoverPoll bound the post-destroy storage-leftover wait
	// (B2: the per-call bound replaces outer's removed package-global seam). The
	// command sets 180s/5s in production; a test injects a short bound.
	LeftoverBound time.Duration
	LeftoverPoll  time.Duration
}

// Driver runs the probe against one routed client. The command holds the VM
// lock across Run (lockwait guard: the lock.Mutation sink lives in the
// command's RunE, not here), so the driver takes no lock itself.
type Driver struct {
	client   *pve.RoutedClient
	cfg      outer.Config
	p        Params
	evid     string        // this run's evidence directory
	ledger   *outer.Ledger // the created-VM ledger (its own per-run file)
	created  bool          // this run created 690 (ledger has it)
	gone     bool          // 690 proven gone on the main path
	mainUPID string        // the main-path destroy UPID (cleanup fallback)
}

// New builds a Driver. cfg.Node must be the client's node.
func New(client *pve.RoutedClient, cfg outer.Config, ledger *outer.Ledger, p Params) *Driver {
	return &Driver{
		client: client,
		cfg:    cfg,
		p:      p,
		ledger: ledger,
	}
}

// refuseErr marks a storage the probe refuses (unsuitable / not a clean
// pre-build state): its cause goes to stdout and the command exits 1.
type refuseErr struct{ reason string }

func (e *refuseErr) Error() string { return "storage refused: " + e.reason }

func (d *Driver) sayln(s string) { fmt.Fprintln(d.p.Stdout, s) }

// refuse writes the refusal cause to stdout and returns a refuseErr.
func (d *Driver) refuse(reason string) error {
	d.note("REFUSED", "storage "+d.p.Storage+": "+reason)
	d.sayln("probe: refusing storage " + d.p.Storage + ": " + reason)
	return &refuseErr{reason}
}

// fail writes a failure cause to stdout and returns an error.
func (d *Driver) fail(reason string) error {
	d.note("FAILED", reason)
	d.sayln("probe: FAILED: " + reason)
	return fmt.Errorf("probe: %s", reason)
}

// Run executes the probe. Writes the outcome to stdout; returns nil on a
// clean probe, a non-nil error (exit 1) on a refusal or a failure.
func (d *Driver) Run(ctx context.Context) error {
	if _, err := outer.RequireStorage(d.p.Storage); err != nil {
		return err
	}
	if err := d.openEvidence(); err != nil {
		return err
	}

	// ---- static layer ----
	st, raw, err := outer.ReadStorageStatus(ctx, d.client, d.cfg.Node, d.p.Storage)
	if err != nil {
		return d.fail(err.Error())
	}
	d.evidence("storage-status-before.json", string(raw))
	if reason := st.Unsuitable(d.p.MinFreeGiB); reason != "" {
		return d.refuse(reason)
	}
	d.evidence("storage-type", st.Type)
	if d.p.StaticOnly {
		d.evidence("SUMMARY", "static-only: storage "+d.p.Storage+" ("+st.Type+") passed")
		d.sayln("probe: storage " + d.p.Storage + " (" + st.Type + ") passes the static checks")
		return nil
	}

	// ---- empirical pre-create checks (NO outer.Guard: 690 is not a member
	// yet; P7) ----
	baseline, err := d.preCreate(ctx, st)
	if err != nil {
		return err
	}

	// The command holds the VM lock across this whole run (P5: one lock, no
	// nested idempotent.Run). Deferred cleanup on a failure path runs on a
	// FRESH detached context (P3).
	defer d.cleanup()

	rule, err := d.empirical(ctx)
	if err != nil {
		return err
	}

	// Leftover detector (bounded; unreadable = not detected).
	if leftover, reason := outer.StorageLeftover(ctx, d.client, d.cfg.Node, d.p.Storage, baseline, []int{vmid}, d.p.LeftoverBound, d.p.LeftoverPoll); leftover {
		return d.fail("VM " + strconv.Itoa(vmid) + " is destroyed, but the storage shows a leftover: " + reason)
	}

	// The rule file, atomically, only after a complete probe.
	if err := d.writeRule(rule); err != nil {
		return d.fail(err.Error())
	}
	d.evidence("SUMMARY", fmt.Sprintf("storage %s (%s): %s; VM %d created, probed, destroyed and gone", d.p.Storage, st.Type, rule, vmid))
	d.sayln(fmt.Sprintf("rollback-rule=%s storage=%s", rule, d.p.Storage))
	return nil
}

// preCreate ports probe.sh:150-167: 690 absent from the pool, free in the
// cluster, the storage's content empty of 690's volumes, the pool empty, and
// a clean baseline. Returns the baseline `used`.
func (d *Driver) preCreate(ctx context.Context, st outer.StorageStatus) (int64, error) {
	members, err := d.poolMembers(ctx)
	if err != nil {
		return 0, d.fail(err.Error())
	}
	if members.has(vmid) {
		return 0, d.refuse(fmt.Sprintf("VM %d already exists in pool %s: the probe runs only before the build", vmid, d.cfg.Pool))
	}
	if err := outer.VMIDFree(ctx, d.client, vmid); err != nil {
		return 0, d.refuse(fmt.Sprintf("VMID %d is not free in the cluster: %v", vmid, err))
	}
	content, err := d.client.RawRequest(ctx, http.MethodGet, outer.ContentPath(d.cfg.Node, d.p.Storage), url.Values{"vmid": {strconv.Itoa(vmid)}})
	if err != nil {
		return 0, d.fail(fmt.Sprintf("storage %s: the content answer could not be read: %v", d.p.Storage, err))
	}
	var arr []json.RawMessage
	if json.Unmarshal(content, &arr) != nil {
		return 0, d.fail(fmt.Sprintf("storage %s: the content answer has an unexpected shape", d.p.Storage))
	}
	if len(arr) != 0 {
		return 0, d.refuse("it already holds volumes of VM " + strconv.Itoa(vmid) + " (a leftover)")
	}
	if !members.empty() {
		return 0, d.refuse(fmt.Sprintf("pool %s is not empty: the probe runs on an empty harness storage, before the build", d.cfg.Pool))
	}
	baseline, err := outer.BaselineUsed(st, d.p.Storage)
	if err != nil {
		return 0, d.refuse(err.Error())
	}
	return baseline, nil
}

// empirical ports probe.sh:272-316: create 690, snapshot s1/s2 (vmstate=0),
// classify the rollback, cascade, destroy (LEAF), prove gone. Returns the
// rollback rule.
func (d *Driver) empirical(ctx context.Context) (string, error) {
	// Create + tag (screened, probe-only; P5).
	if err := d.createAndTag(ctx); err != nil {
		return "", d.fail(err.Error())
	}
	// From here 690 is a tagged member: change verbs may be guarded.
	for _, name := range []string{"s1", "s2"} {
		if err := d.snapshot(ctx, name); err != nil {
			return "", d.fail(err.Error())
		}
	}
	// Rollback s1 while s2 exists → classify on the STORAGE's response
	// (operator reversal of P4): the probe is the "ask the artifact"
	// mechanism, so it must issue a RAW rollback POST and read what PVE/the
	// storage actually does — NOT client.Rollback, whose client-side
	// NewerSnapshots guard (snapshot.go:611-620) always pre-refuses a
	// non-latest rollback and would only ever report pveforge POLICY
	// (rollback-latest-only). reset.sh issues raw rollback POSTs the same way.
	if err := d.guard(ctx, outer.ModeChange); err != nil {
		return "", d.fail(err.Error())
	}
	rule, failedReason := classifyStorageRollback(d.rawRollback(ctx, "s1"))
	if rule == "" {
		return "", d.fail("the rollback of s1 while s2 exists failed for an unrecognised reason: " + failedReason)
	}
	if rule == "rollback-latest-only" {
		if err := d.refusedRollbackLockCheck(ctx); err != nil {
			return "", err
		}
	}
	d.evidence("rollback-rule", rule)

	// Cascade (success path MAY use CascadeDeleteSnapshots; a failure stops
	// the probe — P11): delete s2, roll back to s1, delete s1.
	if err := d.guard(ctx, outer.ModeChange); err != nil {
		return "", d.fail(err.Error())
	}
	if _, err := d.client.CascadeDeleteSnapshots(ctx, vmid, []string{"s2"}); err != nil {
		return "", d.fail(fmt.Sprintf("cascade: delete s2: %v", err))
	}
	if err := d.rollback(ctx, "s1"); err != nil {
		return "", d.fail(fmt.Sprintf("cascade: rollback to s1: %v", err))
	}
	if _, err := d.client.CascadeDeleteSnapshots(ctx, vmid, []string{"s1"}); err != nil {
		return "", d.fail(fmt.Sprintf("cascade: delete s1: %v", err))
	}

	// Destroy LEAF (P1): StatusGatedStop → raw DELETE both params → VMGone.
	upid, err := d.destroyLeaf(ctx)
	if err != nil {
		return "", d.fail(err.Error())
	}
	d.mainUPID = upid
	d.evidence("destroy.out", upid)
	if err := outer.VMGone(ctx, d.client, d.cfg, vmid, upid); err != nil {
		return "", d.fail(fmt.Sprintf("VM %d is not proven gone after the destroy: %v", vmid, err))
	}
	d.gone = true
	return rule, nil
}

// createAndTag: CreateVM (no tags) → WaitForTask → Ledger.Add → screened
// SetVMConfigField(tags). All under the run's single lock (P5).
func (d *Driver) createAndTag(ctx context.Context) error {
	fields := map[string]string{
		"scsi0":  d.p.Storage + ":1",
		"name":   "pveforge-probe",
		"memory": "512",
		"cores":  "1",
		// pool=<harness pool> is how 690 joins the pool (harness_vm_create
		// lib.sh:12 always stamps it); without it the first Guard(ModeChange)
		// before the snapshot refuses 690 as a non-member (CR1).
		"pool": d.cfg.Pool,
	}
	if err := screenProbeCreate(d.p.Storage, fields); err != nil {
		return err
	}
	params := url.Values{}
	for k, v := range fields {
		params.Set(k, v)
	}
	upid, err := d.client.CreateVM(ctx, vmid, params)
	if err != nil {
		return fmt.Errorf("create VM %d: %w", vmid, err)
	}
	if err := d.client.WaitForTask(ctx, d.cfg.Node, upid); err != nil {
		return fmt.Errorf("create VM %d: %w", vmid, err)
	}
	if d.ledger != nil {
		if err := d.ledger.Add(vmid); err != nil {
			return err
		}
	}
	d.created = true
	if err := d.client.SetVMConfigField(ctx, vmid, "tags", outer.DefaultTag); err != nil {
		return fmt.Errorf("tag VM %d: %w", vmid, err)
	}
	return nil
}

// snapshot issues a disk-only (vmstate=0) snapshot via a screened raw POST
// (the pve CreateSnapshot method forces vmstate=1, so the probe issues this
// itself), guarded ModeChange.
func (d *Driver) snapshot(ctx context.Context, name string) error {
	if err := d.guard(ctx, outer.ModeChange); err != nil {
		return err
	}
	for _, k := range []string{"snapname", "vmstate"} {
		if !outer.AllowedField("snapshot", k) {
			return fmt.Errorf("snapshot %s is not an allowed harness field", k)
		}
	}
	params := url.Values{"snapname": {name}, "vmstate": {"0"}}
	upid, err := d.rawUPID(ctx, http.MethodPost, d.vmPath("snapshot"), params)
	if err != nil {
		return fmt.Errorf("snapshot %s of VM %d: %w", name, vmid, err)
	}
	return d.client.WaitForTask(ctx, d.cfg.Node, upid)
}

// rollback runs client.Rollback — used ONLY for the cascade rollback to s1
// AFTER s2 has been deleted, where s1 is the newest snapshot so pveforge's
// client-side guard does not refuse. This is an ordinary cascade step, not a
// storage measurement.
func (d *Driver) rollback(ctx context.Context, name string) error {
	if err := d.guard(ctx, outer.ModeChange); err != nil {
		return err
	}
	return d.client.Rollback(ctx, vmid, name)
}

// rawRollback issues a RAW rollback POST (PVE's own task), deliberately
// BYPASSING client.Rollback's client-side NewerSnapshots guard, so the
// probe's classification rollback measures what the STORAGE actually does
// with a non-latest rollback (probe.sh:292 / reset.sh do the same). The
// bypass is scoped to VM 690, the disposable probe VM THIS run created and
// destroys — never an operator VM. Returns PVE's error (the refusal task's
// failure, or a synchronous refusal), or nil when the task ran OK.
func (d *Driver) rawRollback(ctx context.Context, name string) error {
	upid, err := d.rawUPID(ctx, http.MethodPost, d.vmPath("snapshot/"+name+"/rollback"), nil)
	if err != nil {
		return err // a synchronous refusal (its text carries PVE's reason)
	}
	return d.client.WaitForTask(ctx, d.cfg.Node, upid) // a task refusal → *pve.TaskFailedError
}

// refusedRollbackLockCheck ports probe.sh:300-304: after a refused rollback,
// a lock PVE may have left (lib cannot clear it) is reported by name.
func (d *Driver) refusedRollbackLockCheck(ctx context.Context) error {
	raw, err := d.client.RawRequest(ctx, http.MethodGet, d.vmPath("config"), nil)
	if err != nil {
		return d.fail(fmt.Sprintf("VM %d: cannot read its config: %v", vmid, err))
	}
	var conf struct {
		Lock string `json:"lock"`
	}
	if json.Unmarshal(raw, &conf) == nil && conf.Lock != "" {
		return d.fail(fmt.Sprintf("VM %d carries lock %q after the refused rollback: clear it as root on %s with 'qm unlock %d'", vmid, conf.Lock, d.cfg.Node, vmid))
	}
	return nil
}

// destroyLeaf reuses U-CORE's destroy leaf: StatusGatedStop → raw DELETE with
// BOTH params → the UPID (caller runs the gone-proof).
func (d *Driver) destroyLeaf(ctx context.Context) (string, error) {
	if err := d.guard(ctx, outer.ModeDestroy); err != nil {
		return "", err
	}
	op := &idempotent.VMDestroy{Client: d.client, VMID: vmid}
	if err := op.StatusGatedStop(ctx); err != nil {
		return "", err
	}
	params := url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}
	upid, err := d.rawUPID(ctx, http.MethodDelete, d.vmPath(""), params)
	if err != nil {
		return "", fmt.Errorf("destroy VM %d: %w", vmid, err)
	}
	if err := d.client.WaitForTask(ctx, d.cfg.Node, upid); err != nil {
		return "", fmt.Errorf("destroy VM %d: %w", vmid, err)
	}
	return upid, nil
}

func (d *Driver) guard(ctx context.Context, mode outer.Mode) error {
	var led *outer.Ledger
	if mode == outer.ModeDestroy {
		led = d.ledger
	}
	return outer.Guard(ctx, d.client, d.cfg, led, vmid, mode)
}

// notMostRecentPhrase is PVE's storage-level refusal of a non-latest
// rollback (probe.sh:296 matches the same substring). It appears in the
// failed rollback task's error text (a qcow2/zfspool-style refusal), or in a
// synchronous refusal body.
const notMostRecentPhrase = "is not most recent snapshot"

// classifyStorageRollback classifies the RAW rollback POST's result on the
// STORAGE's response (operator reversal of P4; probe.sh:294-307):
//   - no error (the task ran OK) → rollback-any
//   - an error whose text carries PVE's "is not most recent snapshot"
//     refusal → rollback-latest-only
//   - any other error → fail ("", cause)
//
// This is the storage's own behaviour, NOT pveforge's client-side policy:
// rollback-any is genuinely reachable here (it was dead under P4, which
// always pre-refused).
func classifyStorageRollback(err error) (rule, failedReason string) {
	if err == nil {
		return "rollback-any", ""
	}
	if strings.Contains(err.Error(), notMostRecentPhrase) {
		return "rollback-latest-only", ""
	}
	return "", err.Error()
}

// ---- helpers ----

func (d *Driver) vmPath(sub string) string {
	p := fmt.Sprintf("/nodes/%s/qemu/%d", d.cfg.Node, vmid)
	if sub != "" {
		p += "/" + sub
	}
	return p
}

func (d *Driver) rawUPID(ctx context.Context, method, path string, params url.Values) (string, error) {
	raw, err := d.client.RawRequest(ctx, method, path, params)
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(raw, &upid); err != nil {
		return "", fmt.Errorf("%s %s: expected a task UPID, got %s", method, path, string(raw))
	}
	return upid, nil
}

type poolMembers struct {
	vmids map[int]bool
	count int
}

func (m poolMembers) has(v int) bool { return m.vmids[v] }
func (m poolMembers) empty() bool    { return m.count == 0 }

func (d *Driver) poolMembers(ctx context.Context) (poolMembers, error) {
	raw, err := d.client.RawRequest(ctx, http.MethodGet, "/pools", url.Values{"poolid": {d.cfg.Pool}})
	if err != nil {
		return poolMembers{}, fmt.Errorf("reading pool %s failed: %w", d.cfg.Pool, err)
	}
	var pools []struct {
		PoolID  string `json:"poolid"`
		Members []struct {
			VMID json.RawMessage `json:"vmid"`
		} `json:"members"`
	}
	if json.Unmarshal(raw, &pools) != nil || len(pools) != 1 || pools[0].PoolID != d.cfg.Pool {
		return poolMembers{}, fmt.Errorf("pool %s: the answer has an unexpected shape", d.cfg.Pool)
	}
	m := poolMembers{vmids: map[int]bool{}, count: len(pools[0].Members)}
	for _, mem := range pools[0].Members {
		// Every member's vmid must be a bare JSON number (lib.sh:648 /
		// outer.VMGone's `(.vmid|type)=="number"`): a JSON string "690" must
		// NOT read as absent nor alias the number 690 (CR3). Refuse the shape.
		i, ok := numericVMID(mem.VMID)
		if !ok {
			return poolMembers{}, fmt.Errorf("pool %s: a member's vmid is not a number (unexpected shape)", d.cfg.Pool)
		}
		m.vmids[i] = true
	}
	return m, nil
}

// numericVMID reports a member's vmid as an int only when its JSON token is a
// bare integer number (never a quoted string, which encoding/json's
// json.Number would otherwise accept). Mirrors outer's unexported rule.
func numericVMID(raw json.RawMessage) (int, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s[0] == '"' {
		return 0, false
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return i, true
}

// screenProbeCreate ports _harness_screen_fields create / _harness_disk_ok
// (lib.sh) for ONLY the four fixed fields the probe sends (P5): scsi0 as a new
// allocation (<storage>:<n>) on the REQUIRED storage, and plain name/memory/
// cores. It does NOT widen outer.AllowedField with U-BUILD's ISO/import-from
// arms.
func screenProbeCreate(storage string, fields map[string]string) error {
	allowed := map[string]bool{"scsi0": true, "name": true, "memory": true, "cores": true, "pool": true}
	for k, v := range fields {
		if !allowed[k] {
			return fmt.Errorf("create field %q is not allowed by the probe", k)
		}
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 }) {
			return fmt.Errorf("create field %q holds a control character", k)
		}
	}
	disk, ok := fields["scsi0"]
	if !ok {
		return fmt.Errorf("probe create needs scsi0")
	}
	// New allocation only: <storage>:<size>, storage == the required one.
	m := diskSpecRE.FindStringSubmatch(disk)
	if m == nil || m[1] != storage {
		return fmt.Errorf("disk scsi0=%q is not a new allocation on the required storage %q", disk, storage)
	}
	return nil
}

var diskSpecRE = regexp.MustCompile(`^([a-z][a-z0-9._-]*):([0-9]+)$`)

// ---- evidence + rule file ----

func (d *Driver) openEvidence() error {
	root := filepath.Join(d.p.Home, ".config/pveforge/harness-evidence/probe")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", root, err)
	}
	_ = os.Chmod(root, 0o700) // mkdir -m does not tighten an existing dir
	d.evid = filepath.Join(root, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Mkdir(d.evid, 0o700); err != nil {
		return fmt.Errorf("cannot create the evidence directory %s: %w", d.evid, err)
	}
	return nil
}

// evidence writes an evidence file; on the SUCCESS path an unwritable
// evidence dir is fatal.
func (d *Driver) evidence(name, content string) {
	_ = os.WriteFile(filepath.Join(d.evid, name), []byte(content+"\n"), 0o600)
}

// note writes evidence best-effort (never changes the outcome) — the failure
// path (P3).
func (d *Driver) note(name, content string) {
	if d.evid == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(d.evid, name), []byte(content+"\n"), 0o600)
}

// writeRule writes the rollback rule to its state file atomically: a temp in
// the same dir, 0600, renamed over the target, then the target is proven a
// REGULAR file (not a symlink — O_NOFOLLOW/Lstat) holding exactly the rule.
// Path/format byte-identical to probe.sh (a probe output; reset does NOT read
// it — reset.sh cascades newest-first then rolls back unconditionally).
func (d *Driver) writeRule(rule string) error {
	state := filepath.Join(d.p.Home, ".config/pveforge/harness-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return fmt.Errorf("cannot create %s", state)
	}
	_ = os.Chmod(state, 0o700)
	target := filepath.Join(state, "rollback-rule."+d.p.Storage)
	tmp, err := os.CreateTemp(state, "rollback-rule.*")
	if err != nil {
		return fmt.Errorf("cannot write the rule")
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.WriteString(rule + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write the rule")
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cannot write the rule")
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write the rule")
	}
	// Refuse to write THROUGH a symlink sitting at the target path.
	if fi, err := os.Lstat(target); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("the rule file %s is a symlink; refusing", target)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("cannot write the rule to %s", target)
	}
	fi, err := os.Lstat(target)
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("the rule file %s is not a regular file after the write", target)
	}
	got, err := os.ReadFile(target)
	if err != nil || strings.TrimRight(string(got), "\n") != rule {
		return fmt.Errorf("the rule file %s does not hold %q after the write", target, rule)
	}
	return nil
}

// ---- cleanup (P3): fresh detached context, ledger-gated, main-path UPID ----

func (d *Driver) cleanup() {
	if d.gone || !d.created {
		// Success, or we never created 690: nothing this run must undo. (If
		// a VM 690 appeared un-ledgered, the pre-create/guard refusal already
		// reported it; cleanup never destroys an un-ledgered VM — P3.)
		return
	}
	// A FRESH detached, bounded context (P3): a signal cancels cmd.Context,
	// so cleanup must not observe it or the destroy+report would no-op.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	d.cleanupTeardown(ctx)
}

// cleanupTeardown takes ctx as its own parameter (so the WaitForTask below is
// passed the enclosing function's context directly — the task-wait guard).
func (d *Driver) cleanupTeardown(ctx context.Context) {
	// Ledger-gated: only this run's created 690 may be destroyed.
	if has, err := d.ledgerHas(vmid); err != nil || !has {
		d.note("LEFTOVER", fmt.Sprintf("VM %d: this run did not record creating it; it is left for an operator", vmid))
		return
	}
	// Delete this run's snapshots ONE BY ONE, newest first, continuing on
	// error (P11 — not CascadeDeleteSnapshots, which stops at the first).
	for _, name := range d.listSnapshotNamesNewestFirst(ctx) {
		_, _ = d.client.CascadeDeleteSnapshots(ctx, vmid, []string{name})
	}
	op := &idempotent.VMDestroy{Client: d.client, VMID: vmid}
	upid := ""
	if err := op.StatusGatedStop(ctx); err == nil {
		if u, err := d.rawUPID(ctx, http.MethodDelete, d.vmPath(""), url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}); err == nil {
			upid = u
			_ = d.client.WaitForTask(ctx, d.cfg.Node, upid)
		}
	}
	// A re-destroy that printed nothing (690 already left the pool): judge by
	// the MAIN-path destroy's UPID (P3, CleanupKeepsTheRealCause).
	if upid == "" {
		upid = d.mainUPID
	}
	if err := outer.VMGone(ctx, d.client, d.cfg, vmid, upid); err != nil {
		d.note("LEFTOVER", fmt.Sprintf("VM %d is not proven gone after cleanup: %v", vmid, err))
	}
}

func (d *Driver) ledgerHas(v int) (bool, error) {
	if d.ledger == nil {
		return false, nil
	}
	return d.ledger.Has(v)
}

func (d *Driver) listSnapshotNamesNewestFirst(ctx context.Context) []string {
	snaps, err := d.client.ListSnapshots(ctx, vmid)
	if err != nil {
		return nil
	}
	var real []*proxmox.VirtualMachineSnapshot
	for _, s := range snaps {
		if s != nil && s.Name != "current" {
			real = append(real, s)
		}
	}
	sort.SliceStable(real, func(i, j int) bool { return real[i].Snaptime > real[j].Snaptime })
	names := make([]string, 0, len(real))
	for _, s := range real {
		names = append(names, s.Name)
	}
	return names
}
