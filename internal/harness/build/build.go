package build

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/suykerbuyk/pveforge/internal/harness/outer"
	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// The three outer VMs (build.sh:5-9, 73-78) and the harness bridge (lib.sh:140).
const (
	vmN1           = 690
	vmN2           = 691
	vmNFS          = 692
	harnessBridges = "vmbr0"
)

var (
	// VMIDs is exported so the command can build the three per-VM lock keys it
	// holds across the run.
	VMIDs     = [...]int{vmN1, vmN2, vmNFS}
	vmName    = map[int]string{vmN1: "pvh-n1", vmN2: "pvh-n2", vmNFS: "pvh-nfs"}
	vmPorts   = map[int][]string{vmN1: {"22", "8006"}, vmN2: {"22", "8006"}, vmNFS: {"22"}}
	pubkeyRE  = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=*( [A-Za-z0-9@._-]+)?$`)
	keyscanRE = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=*$`)
	ipRE      = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)
)

// Params are the build verb's inputs.
type Params struct {
	TargetID string
	Storage  string
	Keep     bool // --keep-on-failure
	Repin    bool // --repin
	Home     string

	Now func() time.Time // the run clock (one stamp per run); nil → time.Now

	// Seams (production defaults wired by the command; tests inject):
	OuterHost  func() (string, error)              // the host the roster names for TargetID (in-process roster read)
	LookupHost func(host string) ([]string, error) // getent ahostsv4 (build.sh:190)
	Keyscan    func(ip string) (string, error)     // ssh-keyscan -t ed25519 (build.sh:444)
	Dial       func(ip, port string) bool          // a bounded TCP connect (build.sh:127)

	// Timings (production defaults wired by the command; tests shorten):
	PollEvery     time.Duration // build.sh:82 POLL_EVERY 10s
	PollFor       time.Duration // build.sh:83 POLL_FOR 1800s
	LeftoverBound time.Duration // cleanup usage wait, build.sh:289 600s
	LeftoverPoll  time.Duration
}

// Driver runs the build against one routed client. Lock-free (the command holds
// the three per-VM locks).
type Driver struct {
	client *pve.RoutedClient
	cfg    outer.Config
	p      Params
	ledger *outer.Ledger

	site  Site
	evid  string
	stamp string

	pubkey    string // the nested SSH public key (preflight), encoded into sshkeys
	knownText string // the existing known_hosts text (preflight)
	knownPath string // ~/.config/pveforge/harness-nested.known_hosts
	baseline  int64  // the storage `used` the preflight recorded (C5: cleanup compares to THIS, not 0)

	created  []int // VMIDs this run created and recorded (newest last)
	creating bool  // past the point where cleanup must tear down
	doneOK   bool
}

// New builds a Driver. cfg.Node must be the client's node.
func New(client *pve.RoutedClient, cfg outer.Config, ledger *outer.Ledger, p Params) *Driver {
	return &Driver{client: client, cfg: cfg, ledger: ledger, p: p}
}

// refuseErr / failErr carry the shell's exit-3 (precondition) / exit-4 (step)
// distinction as a classifiable cause; runRoot collapses both to 1, so the Go
// suite asserts the cause, not the integer.
type refuseErr struct{ reason string }
type failErr struct{ reason string }

func (e *refuseErr) Error() string { return e.reason }
func (e *failErr) Error() string   { return e.reason }

func (d *Driver) now() time.Time {
	if d.p.Now != nil {
		return d.p.Now()
	}
	return time.Now()
}

// Run executes the build. On any failure past the first create, deferred
// cleanup tears down only this run's recorded VMs (or keeps them, --keep).
func (d *Driver) Run(ctx context.Context) (err error) {
	if _, e := outer.RequireStorage(d.p.Storage); e != nil {
		return &refuseErr{e.Error()}
	}
	site, e := LoadSite(filepath.Join(d.p.Home, ".config/pveforge/harness-build.env"))
	if e != nil {
		return &refuseErr{e.Error()}
	}
	d.site = site
	if e := d.openEvidence(); e != nil {
		return &failErr{e.Error()}
	}
	defer func() { d.cleanup(err) }()

	baseline, e := d.preflight(ctx)
	if e != nil {
		return e
	}
	d.baseline = baseline // C5: thread the recorded baseline through to cleanup's leftover check
	d.step("PASS preflight")

	if e := d.createAll(ctx); e != nil {
		return e
	}
	if e := d.startAll(ctx); e != nil {
		return e
	}
	if e := d.waitUp(ctx); e != nil {
		return e
	}
	if e := d.ejectAll(ctx); e != nil {
		return e
	}
	if e := d.pinAll(ctx); e != nil {
		return e
	}
	d.doneOK = true
	d.step(fmt.Sprintf("RESULT built %d %d %d evidence=%s", vmN1, vmN2, vmNFS, d.evid))
	d.writeManifest()
	return nil
}

// ---- preflight (read-only; nothing created unless all of it holds) ----

func (d *Driver) preflight(ctx context.Context) (int64, error) {
	cfgDir := filepath.Join(d.p.Home, ".config/pveforge")
	keyPub := filepath.Join(cfgDir, "harness-nested_ed25519.pub")
	known := filepath.Join(cfgDir, "harness-nested.known_hosts")

	fi, e := os.Lstat(keyPub)
	if e != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return 0, d.refuse("the nested SSH key " + keyPub + ".pub does not exist: run prepare-iso.sh first")
	}
	pubRaw, e := os.ReadFile(keyPub)
	if e != nil {
		return 0, d.refuse("cannot read " + keyPub)
	}
	pub := strings.TrimRight(string(pubRaw), "\n")
	if !pubkeyRE.MatchString(pub) {
		return 0, d.refuse(keyPub + " is not one ssh-ed25519 public key")
	}

	knownText := ""
	if fi, e := os.Lstat(known); e == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return 0, d.refuse(known + " is not a regular file")
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			return 0, d.refuse(fmt.Sprintf("%s has mode %o, want 600", known, perm))
		}
		b, e := os.ReadFile(known)
		if e != nil {
			return 0, d.refuse("cannot read " + known)
		}
		knownText = string(b)
	}
	if !d.p.Repin {
		for _, v := range VMIDs {
			if ipPinned(knownText, d.ip(v)) {
				return 0, d.refuse(fmt.Sprintf("%s already pins a host key for %s (%s); a new build makes new host keys: run with --repin to replace the pins", known, d.ip(v), vmName[v]))
			}
		}
	}

	// None of the three addresses may be the outer host itself.
	outerHost, e := d.p.OuterHost()
	if e != nil {
		return 0, d.refuse(e.Error())
	}
	var outerIPs []string
	if ipRE.MatchString(outerHost) {
		outerIPs = []string{outerHost}
	} else {
		outerIPs, e = d.p.LookupHost(outerHost)
		if e != nil {
			return 0, d.refuse("cannot resolve the outer host " + outerHost)
		}
	}
	d.evidence("outer-host", outerHost+": "+strings.Join(outerIPs, " "))
	for _, v := range VMIDs {
		for _, a := range outerIPs {
			if a == d.ip(v) {
				return 0, d.refuse(fmt.Sprintf("%s's address %s is the outer host %s", vmName[v], d.ip(v), outerHost))
			}
		}
	}
	// Nothing may answer yet at any of the three.
	for _, v := range VMIDs {
		for _, port := range vmPorts[v] {
			if d.p.Dial(d.ip(v), port) {
				return 0, d.refuse(fmt.Sprintf("%s:%s already answers, before %s exists: the address is in use", d.ip(v), port, vmName[v]))
			}
		}
	}

	// Pool empty, none of 690-692 anywhere in the cluster, storage clean.
	members, e := d.poolMembers(ctx)
	if e != nil {
		return 0, &failErr{e.Error()}
	}
	for _, v := range VMIDs {
		if members.has(v) {
			return 0, d.refuse(fmt.Sprintf("VM %d already exists in pool %s: the build runs on a clean slate, and removing an earlier build's VM needs an operator ask", v, d.cfg.Pool))
		}
		if e := outer.VMIDFree(ctx, d.client, v); e != nil {
			return 0, d.refuse(fmt.Sprintf("VMID %d is not free in the cluster: %v", v, e))
		}
		content, e := d.client.RawRequest(ctx, http.MethodGet, outer.ContentPath(d.cfg.Node, d.p.Storage), url.Values{"vmid": {strconv.Itoa(v)}})
		if e != nil {
			return 0, &failErr{fmt.Sprintf("storage %s: the content answer could not be read: %v", d.p.Storage, e)}
		}
		var arr []json.RawMessage
		if json.Unmarshal(content, &arr) != nil {
			return 0, &failErr{fmt.Sprintf("storage %s: the content answer has an unexpected shape", d.p.Storage)}
		}
		if len(arr) != 0 {
			return 0, d.refuse(fmt.Sprintf("storage %s already holds volumes of VM %d (a leftover)", d.p.Storage, v))
		}
	}
	if !members.empty() {
		return 0, d.refuse(fmt.Sprintf("pool %s is not empty: the build runs on an empty harness storage", d.cfg.Pool))
	}
	st, _, e := outer.ReadStorageStatus(ctx, d.client, d.cfg.Node, d.p.Storage)
	if e != nil {
		return 0, &failErr{e.Error()}
	}
	baseline, e := outer.BaselineUsed(st, d.p.Storage)
	if e != nil {
		return 0, d.refuse(e.Error())
	}
	// Both prepared node ISOs and the import image on local.
	isos, e := d.localContent(ctx, "iso")
	if e != nil {
		return 0, &failErr{e.Error()}
	}
	for _, v := range []int{vmN1, vmN2} {
		if !hasVolid(isos, "local:iso/"+vmName[v]+"-auto.iso") {
			return 0, d.refuse("local:iso/" + vmName[v] + "-auto.iso is not on " + d.cfg.Node + ": upload prepare-iso.sh's output first")
		}
	}
	imports, e := d.localContent(ctx, "import")
	if e != nil {
		return 0, &failErr{e.Error()}
	}
	if !hasVolid(imports, "local:import/"+d.site["NFS_IMAGE"]) {
		return 0, d.refuse("local:import/" + d.site["NFS_IMAGE"] + " is not on " + d.cfg.Node + ": upload the Debian 13 genericcloud image first")
	}
	d.pubkey = pub
	d.knownText = knownText
	d.knownPath = known
	return baseline, nil
}

// ---- create ----

func (d *Driver) createParams(v int) map[string]string {
	if v == vmNFS {
		return map[string]string{
			"name": vmName[v], "ostype": "l26", "cpu": "host",
			"cores": d.site["NFS_CORES"], "memory": d.site["NFS_MEMORY_MIB"],
			"bios": "seabios", "scsihw": "virtio-scsi-single",
			"scsi0": d.p.Storage + ":0,import-from=local:import/" + d.site["NFS_IMAGE"],
			"scsi1": d.p.Storage + ":" + d.site["NFS_DATA_GIB"],
			"ide2":  d.p.Storage + ":cloudinit",
			"net0":  "virtio=" + d.mac(v) + ",bridge=vmbr0,firewall=0",
			"boot":  "order=scsi0", "agent": "1",
			"ipconfig0":    "ip=" + d.ip(v) + "/" + d.site["PREFIX"] + ",gw=" + d.site["GATEWAY"],
			"nameserver":   d.site["DNS"],
			"searchdomain": d.site["DOMAIN"],
			"ciuser":       d.site["NFS_USER"],
			"sshkeys":      uriEncode(d.pubkey),
		}
	}
	return map[string]string{
		"name": vmName[v], "ostype": "l26", "cpu": "host",
		"cores": d.site["NODE_CORES"], "memory": d.site["NODE_MEMORY_MIB"],
		"bios": "seabios", "scsihw": "virtio-scsi-single",
		"scsi0": d.p.Storage + ":" + d.site["NODE_DISK_GIB"],
		"ide2":  "local:iso/" + vmName[v] + "-auto.iso,media=cdrom",
		"net0":  "virtio=" + d.mac(v) + ",bridge=vmbr0,firewall=0",
		"boot":  "order=scsi0;ide2",
	}
}

func (d *Driver) createAll(ctx context.Context) error {
	d.creating = true
	for _, v := range VMIDs {
		fields := d.createParams(v)
		// Screen the full matrix (create leg) as a JSON object of strings.
		obj := make(map[string]json.RawMessage, len(fields))
		for k, val := range fields {
			b, _ := json.Marshal(val)
			obj[k] = b
		}
		if e := outer.ScreenCreate(obj, d.p.Storage, harnessBridges); e != nil {
			return &failErr{fmt.Sprintf("VM %d: %v", v, e)}
		}
		// pool is added AFTER the screen (lib.sh:805); tags NOT in the body (D5).
		params := url.Values{"pool": {d.cfg.Pool}}
		for k, val := range fields {
			params.Set(k, val)
		}
		d.evidence(fmt.Sprintf("create-%d.json", v), toJSON(fields, d.cfg.Pool))
		upid, e := d.client.CreateVM(ctx, v, params)
		if e != nil {
			return &failErr{fmt.Sprintf("VM %d: vm create failed: %v", v, e)}
		}
		if e := d.waitTask(ctx, upid); e != nil {
			return &failErr{fmt.Sprintf("VM %d: vm create failed: %v", v, e)}
		}
		if d.ledger != nil {
			if e := d.ledger.Add(v); e != nil {
				return &failErr{e.Error()}
			}
		}
		d.created = append(d.created, v)
		// Tag after create, under the tag-skip guard (ModeTag): a just-created
		// VM has no tag yet.
		if e := outer.Guard(ctx, d.client, d.cfg, nil, v, outer.ModeTag); e != nil {
			return &failErr{fmt.Sprintf("VM %d: tag guard: %v", v, e)}
		}
		if e := d.client.SetVMConfigField(ctx, v, "tags", d.cfg.Tag); e != nil {
			return &failErr{fmt.Sprintf("VM %d: tag failed: %v", v, e)}
		}
		d.step(fmt.Sprintf("PASS create %d %s", v, vmName[v]))
	}
	return nil
}

func (d *Driver) startAll(ctx context.Context) error {
	for _, v := range VMIDs {
		if e := d.postLeaf(ctx, v, "status/start", nil); e != nil {
			return &failErr{fmt.Sprintf("VM %d: start failed: %v", v, e)}
		}
		d.step(fmt.Sprintf("PASS start %d", v))
	}
	return nil
}

// ---- wait for the installed systems (wall-clock bound) ----

func (d *Driver) waitUp(ctx context.Context) error {
	deadline := d.now().Add(d.p.PollFor)
	open := map[string]bool{}
	for i := 0; ; i++ {
		waiting := false
		for _, v := range VMIDs {
			for _, port := range vmPorts[v] {
				key := fmt.Sprintf("%d:%s", v, port)
				if open[key] {
					continue
				}
				if d.p.Dial(d.ip(v), port) {
					open[key] = true
				} else {
					waiting = true
				}
			}
		}
		if !waiting {
			d.step(fmt.Sprintf("PASS up after %d polls", i))
			return nil
		}
		if !d.now().Before(deadline) {
			var missing string
			for _, v := range VMIDs {
				for _, port := range vmPorts[v] {
					if !open[fmt.Sprintf("%d:%s", v, port)] {
						missing += fmt.Sprintf(" %s=%s:%s", vmName[v], d.ip(v), port)
					}
				}
			}
			return d.fail(fmt.Sprintf("after %ds, still closed:%s", int(d.p.PollFor.Seconds()), missing))
		}
		select {
		case <-ctx.Done():
			return d.fail("interrupted while waiting for the systems")
		case <-time.After(d.p.PollEvery):
		}
	}
}

// ---- eject each node's ISO (one two-field PUT config) ----

func (d *Driver) ejectAll(ctx context.Context) error {
	for _, v := range []int{vmN1, vmN2} {
		fields := map[string]string{"ide2": "none,media=cdrom", "boot": "order=scsi0"}
		if e := outer.ScreenConfig(fields, d.p.Storage, harnessBridges, true); e != nil {
			return &failErr{fmt.Sprintf("VM %d: eject screen: %v", v, e)}
		}
		if e := outer.Guard(ctx, d.client, d.cfg, nil, v, outer.ModeChange); e != nil {
			return &failErr{fmt.Sprintf("VM %d: eject guard: %v", v, e)}
		}
		// One synchronous PUT config with both fields (build.sh:437); no task.
		if _, e := d.client.RawRequest(ctx, http.MethodPut, outer.VMPath(d.cfg.Node, v, "config"),
			url.Values{"ide2": {"none,media=cdrom"}, "boot": {"order=scsi0"}}); e != nil {
			return &failErr{fmt.Sprintf("VM %d: eject failed: %v", v, e)}
		}
		d.step(fmt.Sprintf("PASS eject %d", v))
	}
	return nil
}

// ---- pin the host keys (O5) ----

func (d *Driver) pinAll(ctx context.Context) error {
	var pins strings.Builder
	for _, v := range VMIDs {
		scan, e := d.p.Keyscan(d.ip(v))
		if e != nil {
			return d.fail(fmt.Sprintf("ssh-keyscan %s failed: %v", d.ip(v), e))
		}
		d.evidence(fmt.Sprintf("keyscan-%d.txt", v), scan)
		line, n := "", 0
		for _, l := range strings.Split(scan, "\n") {
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			n++
			line = l
		}
		want := d.ip(v) + " "
		if n != 1 || !strings.HasPrefix(line, want) || !keyscanRE.MatchString(strings.TrimPrefix(line, want)) {
			return d.fail(fmt.Sprintf("ssh-keyscan %s did not give exactly one ed25519 host key", d.ip(v)))
		}
		pins.WriteString(line + "\n")
	}
	// Keep every line pinning another address; (re)write the three.
	var kept strings.Builder
	if d.knownText != "" {
		for _, l := range strings.Split(d.knownText, "\n") {
			if l == "" {
				continue
			}
			addr := l
			if i := strings.IndexByte(l, ' '); i >= 0 {
				addr = l[:i]
			}
			if addr == d.ip(vmN1) || addr == d.ip(vmN2) || addr == d.ip(vmNFS) {
				continue
			}
			kept.WriteString(l + "\n")
		}
	}
	want := kept.String() + pins.String()
	if e := writeFileAtomic(d.knownPath, want, 0o600); e != nil {
		return d.fail("cannot write " + d.knownPath)
	}
	got, e := os.ReadFile(d.knownPath)
	if e != nil || string(got) != want {
		return d.fail(d.knownPath + " is not a regular file holding the pins after the write")
	}
	d.evidence("known_hosts", want)
	suffix := ""
	if d.p.Repin {
		suffix = " (repinned)"
	}
	d.step(fmt.Sprintf("PASS pinned %s %s %s%s", d.ip(vmN1), d.ip(vmN2), d.ip(vmNFS), suffix))
	return nil
}

// ---- cleanup (on any exit that is not a complete build) ----

func (d *Driver) cleanup(runErr error) {
	if d.doneOK || !d.creating {
		return
	}
	// mine = the VMs this run recorded in the ledger (the shell's CREATED_FILE
	// grep, build.sh:258-262) — the destroy gate. NOT d.created: the ledger is
	// the source of truth, so a VM that appeared but was not recorded is never
	// destroyed, only reported.
	var mine []int
	for _, v := range VMIDs {
		if has, _ := d.ledgerHas(v); has {
			mine = append(mine, v)
		}
	}
	if d.p.Keep {
		d.appendResult("KEPT " + vmidList(mine))
		d.reportLeftover("kept for inspection (--keep-on-failure)", mine)
		return
	}
	// Fresh detached, bounded context: a signal must not cancel the teardown.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var left []int
	upids := map[int]string{}
	for i := len(mine) - 1; i >= 0; i-- { // newest-first
		v := mine[i]
		op := &idempotent.VMDestroy{Client: d.client, VMID: v}
		if e := op.StatusGatedStop(ctx); e != nil {
			left = append(left, v)
			continue
		}
		u, e := outer.RawUPID(ctx, d.client, http.MethodDelete, outer.VMPath(d.cfg.Node, v, ""),
			url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}})
		if e != nil {
			left = append(left, v)
			continue
		}
		_ = d.waitTask(ctx, u)
		upids[v] = u
	}
	var gone []int
	for v, u := range upids {
		if e := outer.VMGone(ctx, d.client, d.cfg, v, u); e == nil {
			gone = append(gone, v)
		} else {
			left = append(left, v)
		}
	}
	if len(gone) > 0 {
		secs := d.p.LeftoverBound
		if len(left) > 0 {
			secs = 0 // a VM still there holds its volumes: one read, no wait (build.sh:301)
		}
		if lo, _ := outer.StorageLeftover(ctx, d.client, d.cfg.Node, d.p.Storage, d.baseline, gone, secs, d.p.LeftoverPoll); lo {
			left = append(left, gone...)
		} else {
			for _, v := range gone {
				d.appendResult(fmt.Sprintf("DESTROYED %d", v))
			}
		}
	}
	// A VM in the pool this run did NOT record (its create appeared but was not
	// ledgered): named, never destroyed (build.sh:318-323).
	if members, e := d.poolMembers(ctx); e == nil {
		for _, v := range VMIDs {
			if !containsInt(mine, v) && members.has(v) {
				left = append(left, v)
			}
		}
	}
	sort.Ints(left)
	left = dedupInts(left)
	if len(left) > 0 {
		d.reportLeftover("cleanup could not remove all of them, or this run did not record creating them", left)
	} else {
		d.appendResult("CLEANUP " + vmidList(mine) + " destroyed")
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func dedupInts(s []int) []int {
	out := s[:0]
	seen := map[int]bool{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (d *Driver) reportLeftover(head string, vmids []int) {
	if len(vmids) == 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "LEFTOVER: %s\n", head)
	for _, v := range vmids {
		fmt.Fprintf(&b, "  VM %d (%s)\n", v, vmName[v])
	}
	b.WriteString("Removing them needs an operator ask (lib destroys only a VM the same run created).\n")
	fmt.Fprintf(&b, "As root on %s, for each VM above:\n  qm stop <vmid>\n  qm destroy <vmid> --purge\n  pvesm list %s --vmid <vmid>     # must list nothing", d.cfg.Node, d.p.Storage)
	d.note("LEFTOVER", b.String())
	d.appendResult("LEFTOVER " + vmidList(vmids))
}

// ---- leaves / helpers ----

// postLeaf is the one task-returning write path (the single WaitForTask site):
// Guard(ModeChange) → raw POST → waitTask.
func (d *Driver) postLeaf(ctx context.Context, vmid int, sub string, params url.Values) error {
	if e := outer.Guard(ctx, d.client, d.cfg, nil, vmid, outer.ModeChange); e != nil {
		return e
	}
	upid, e := outer.RawUPID(ctx, d.client, http.MethodPost, outer.VMPath(d.cfg.Node, vmid, sub), params)
	if e != nil {
		return e
	}
	return d.waitTask(ctx, upid)
}

// waitTask is the ONLY WaitForTask call site in this package (B6, the stated
// taskwait count of 1); every create/start/destroy wait routes through it.
func (d *Driver) waitTask(ctx context.Context, upid string) error {
	return d.client.WaitForTask(ctx, d.cfg.Node, upid)
}

func (d *Driver) ledgerHas(v int) (bool, error) {
	if d.ledger == nil {
		return false, nil
	}
	return d.ledger.Has(v)
}

func (d *Driver) ip(v int) string {
	return d.site[map[int]string{vmN1: "N1_IP", vmN2: "N2_IP", vmNFS: "NFS_IP"}[v]]
}
func (d *Driver) mac(v int) string {
	return d.site[map[int]string{vmN1: "N1_MAC", vmN2: "N2_MAC", vmNFS: "NFS_MAC"}[v]]
}

type poolMembers struct {
	vmids map[int]bool
	count int
}

func (m poolMembers) has(v int) bool { return m.vmids[v] }
func (m poolMembers) empty() bool    { return m.count == 0 }

func (d *Driver) poolMembers(ctx context.Context) (poolMembers, error) {
	raw, e := d.client.RawRequest(ctx, http.MethodGet, "/pools", url.Values{"poolid": {d.cfg.Pool}})
	if e != nil {
		return poolMembers{}, fmt.Errorf("reading pool %s failed: %w", d.cfg.Pool, e)
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
		s := strings.TrimSpace(string(mem.VMID))
		if s == "" || s[0] == '"' {
			return poolMembers{}, fmt.Errorf("pool %s: a member's vmid is not a number (unexpected shape)", d.cfg.Pool)
		}
		if i, err := strconv.Atoi(s); err == nil {
			m.vmids[i] = true
		}
	}
	return m, nil
}

func (d *Driver) localContent(ctx context.Context, content string) ([]volEntry, error) {
	raw, e := d.client.RawRequest(ctx, http.MethodGet, "/nodes/"+d.cfg.Node+"/storage/local/content", url.Values{"content": {content}})
	if e != nil {
		return nil, fmt.Errorf("storage local: cannot read %s content: %v", content, e)
	}
	var arr []volEntry
	if json.Unmarshal(raw, &arr) != nil {
		return nil, fmt.Errorf("storage local: the %s content answer has an unexpected shape", content)
	}
	return arr, nil
}

type volEntry struct {
	Volid string `json:"volid"`
}

func hasVolid(vols []volEntry, id string) bool {
	for _, v := range vols {
		if v.Volid == id {
			return true
		}
	}
	return false
}

// ---- evidence ----

func (d *Driver) openEvidence() error {
	d.stamp = d.now().UTC().Format("20060102T150405Z")
	root := filepath.Join(d.p.Home, ".config/pveforge/harness-evidence/build")
	if e := os.MkdirAll(root, 0o700); e != nil {
		return fmt.Errorf("cannot create %s: %w", root, e)
	}
	_ = os.Chmod(root, 0o700)
	d.evid = filepath.Join(root, d.stamp)
	if e := os.Mkdir(d.evid, 0o700); e != nil {
		return fmt.Errorf("cannot create the evidence directory %s (never reused): %w", d.evid, e)
	}
	return nil
}

func (d *Driver) step(line string) { d.appendResult(line) }
func (d *Driver) appendResult(line string) {
	if d.evid == "" {
		return
	}
	f, e := os.OpenFile(filepath.Join(d.evid, "result.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if e != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line + "\n")
}

func (d *Driver) evidence(name, content string) {
	if d.evid == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(d.evid, name), []byte(content+"\n"), 0o600)
}

func (d *Driver) note(name, content string) { d.evidence(name, content) }

func (d *Driver) writeManifest() {
	entries, e := os.ReadDir(d.evid)
	if e != nil {
		return
	}
	var b strings.Builder
	for _, en := range entries {
		b.WriteString(en.Name() + "\n")
	}
	_ = os.WriteFile(filepath.Join(d.evid, "MANIFEST.sha256"), []byte(b.String()), 0o600)
}

func (d *Driver) refuse(reason string) error {
	d.appendResult("REFUSED " + reason)
	return &refuseErr{reason}
}
func (d *Driver) fail(reason string) error {
	d.appendResult("FAILED " + reason)
	return &failErr{reason}
}

func vmidList(vmids []int) string {
	if len(vmids) == 0 {
		return "none"
	}
	parts := make([]string, len(vmids))
	for i, v := range vmids {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " ")
}

func ipPinned(text, ip string) bool {
	for _, l := range strings.Split(text, "\n") {
		addr := l
		if i := strings.IndexByte(l, ' '); i >= 0 {
			addr = l[:i]
		}
		if addr == ip {
			return true
		}
	}
	return false
}

// uriEncode reproduces jq's @uri (RFC 3986 percent-encoding, space→%20): every
// byte except the unreserved set A-Za-z0-9-_.~ is %XX. (url.QueryEscape is
// wrong: it emits '+' for space.)
func uriEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func writeFileAtomic(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, e := os.CreateTemp(dir, ".harness-nested.known_hosts.*")
	if e != nil {
		return e
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, e := tmp.WriteString(content); e != nil {
		_ = tmp.Close()
		return e
	}
	if e := tmp.Chmod(mode); e != nil {
		_ = tmp.Close()
		return e
	}
	if e := tmp.Close(); e != nil {
		return e
	}
	if fi, e := os.Lstat(path); e == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing", path)
	}
	return os.Rename(tmpName, path)
}

// toJSON renders the create fields + pool as a stable JSON object (evidence).
func toJSON(fields map[string]string, pool string) string {
	keys := make([]string, 0, len(fields)+1)
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(fields[k])
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteString(`,"pool":`)
	pb, _ := json.Marshal(pool)
	b.Write(pb)
	b.WriteByte('}')
	return b.String()
}
