package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Command-level tests for `harness build` (U-BUILD), driven through runRootArgs
// against a stateful multi-VM fake PVE, with the clock/keyscan/dial/getent/
// outer-host seams injected (no live cluster, no ssh-keyscan, no DNS). Outcomes
// are asserted on the create form, the write log, result.txt and the returned
// cause (exit 2/3/4 collapse through runRoot to 1).

const bNode = "qa-pve-07"

type bfake struct {
	mu sync.Mutex

	statusJSON string         // storage /status override
	pre        map[int]bool   // VMID already in the pool before anything (refusal)
	nextidBusy map[int]bool   // /cluster/nextid says the VMID is in use
	contentPre map[int]string // storage content for a VMID before create (non-empty → leftover)
	noISO      map[int]bool   // a node auto ISO missing
	noImport   bool           // the import image missing
	createFail map[int]bool   // CreateVM returns 500 for a VMID

	statusUsed       string       // storage `used` the status reports (baseline); default "0"
	usedAfterDestroy string       // if set, `used` the status reports once any destroy ran (C5 leftover)
	goneFail         map[int]bool // after destroy, keep the VM in the pool → VMGone fails (C7 gone-proof)
	anyDestroyed     bool

	created    map[int]bool       // VM joined the pool
	tags       map[int]string     // tags set after create
	createForm map[int]url.Values // the create POST's form, per VMID
	started    map[int]bool       // start POST seen (→ its ports answer)
	destroyed  map[int]bool
	writes     []string
}

func (f *bfake) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tags == nil {
		f.tags = map[int]string{}
		f.createForm = map[int]url.Values{}
		f.created = map[int]bool{}
		f.started = map[int]bool{}
		f.destroyed = map[int]bool{}
	}
	data := func(raw string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s}`, raw)
	}
	p, m := r.URL.Path, r.Method
	_ = r.ParseForm()

	switch {
	case m == http.MethodGet && strings.HasSuffix(p, "/storage/pveforge-harness/status"):
		if f.statusJSON != "" {
			data(f.statusJSON)
		} else {
			used := f.statusUsed
			if used == "" {
				used = "0"
			}
			if f.anyDestroyed && f.usedAfterDestroy != "" {
				used = f.usedAfterDestroy
			}
			data(fmt.Sprintf(`{"type":"zfspool","enabled":1,"active":1,"content":"images,rootdir","avail":%d,"used":%s}`, int64(600)<<30, used))
		}
		return
	case m == http.MethodGet && strings.HasSuffix(p, "/storage/local/content"):
		switch r.URL.Query().Get("content") {
		case "iso":
			var vols []string
			for _, v := range []int{690, 691} {
				if f.noISO[v] {
					continue
				}
				vols = append(vols, fmt.Sprintf(`{"volid":"local:iso/%s-auto.iso"}`, map[int]string{690: "pvh-n1", 691: "pvh-n2"}[v]))
			}
			data("[" + strings.Join(vols, ",") + "]")
		case "import":
			if f.noImport {
				data("[]")
			} else {
				data(`[{"volid":"local:import/debian-13-genericcloud-amd64.qcow2"}]`)
			}
		default:
			data("[]")
		}
		return
	case m == http.MethodGet && strings.Contains(p, "/storage/pveforge-harness/content"):
		v := qvmid(r)
		if raw := f.contentPre[v]; raw != "" && !f.created[v] {
			data(raw)
			return
		}
		data("[]")
		return
	case m == http.MethodGet && strings.Contains(p, "/cluster/nextid"):
		v := qvmid(r)
		if f.nextidBusy[v] {
			data(`700`) // answers, but not with v → not free
		} else {
			data(fmt.Sprint(v))
		}
		return
	case m == http.MethodGet && strings.Contains(p, "/pools"):
		var ms []string
		for _, v := range []int{690, 691, 692} {
			if (f.pre[v] || f.created[v]) && !f.destroyed[v] {
				ms = append(ms, fmt.Sprintf(`{"type":"qemu","vmid":%d,"node":%q}`, v, bNode))
			}
		}
		data(`[{"poolid":"pveforge-harness","members":[` + strings.Join(ms, ",") + `]}]`)
		return
	case m == http.MethodGet && strings.Contains(p, "/tasks/") && strings.HasSuffix(p, "/status"):
		// Reconstruct the FULL task body from the UPID in the path: DestroyTaskOK
		// re-asserts upid/type/id/node from the body itself (not just the UPID
		// string), so a minimal body would fail every destroy's gone-proof.
		seg := p[strings.Index(p, "/tasks/")+len("/tasks/") : len(p)-len("/status")]
		upid, _ := url.PathUnescape(seg)
		node, typ, id := "", "", ""
		if parts := strings.Split(upid, ":"); len(parts) >= 7 {
			node, typ, id = parts[1], parts[5], parts[6]
		}
		data(fmt.Sprintf(`{"upid":%q,"type":%q,"id":%q,"node":%q,"status":"stopped","exitstatus":"OK"}`, upid, typ, id, node))
		return
	}

	i := strings.Index(p, "/qemu")
	if i < 0 {
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route "+m+" "+p))
		return
	}
	after := strings.TrimPrefix(p[i:], "/qemu")
	after = strings.TrimPrefix(after, "/")
	parts := strings.SplitN(after, "/", 2)
	vmid := atoiSafe(parts[0])
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	rec := func(tag string) { f.writes = append(f.writes, fmt.Sprintf("%s %d", tag, vmid)) }

	switch {
	case m == http.MethodPost && after == "": // CreateVM (POST /nodes/<n>/qemu)
		vmid = atoiSafe(r.FormValue("vmid"))
		rec("create")
		if f.createFail[vmid] {
			w.WriteHeader(http.StatusInternalServerError)
			data(`null`)
			return
		}
		f.created[vmid] = true
		f.createForm[vmid] = cloneForm(r.Form)
		data(fmt.Sprintf("%q", pUPID("qmcreate", vmid)))
	case m == http.MethodGet && sub == "config":
		data(fmt.Sprintf(`{"tags":%q}`, f.tags[vmid]))
	case m == http.MethodGet && sub == "status/current":
		st := "stopped"
		data(fmt.Sprintf(`{"vmid":%d,"status":%q}`, vmid, st))
	case m == http.MethodPut && sub == "config":
		if t := r.FormValue("tags"); t != "" {
			f.tags[vmid] = t
			rec("tag")
		} else {
			rec("eject")
		}
		data(`null`)
	case m == http.MethodPost && sub == "status/start":
		rec("start")
		f.started[vmid] = true
		data(fmt.Sprintf("%q", pUPID("qmstart", vmid)))
	case m == http.MethodDelete && sub == "": // destroy
		rec("destroy")
		f.anyDestroyed = true
		if f.goneFail[vmid] {
			// The destroy task answers OK but the VM stays in the pool → VMGone fails.
			data(fmt.Sprintf("%q", pUPID("qmdestroy", vmid)))
			return
		}
		f.destroyed[vmid] = true
		f.created[vmid] = false
		data(fmt.Sprintf("%q", pUPID("qmdestroy", vmid)))
	default:
		w.WriteHeader(http.StatusNotFound)
		data(fmt.Sprintf("%q", "no route "+m+" "+sub))
	}
}

func (f *bfake) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}
func (f *bfake) form(vmid int) url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createForm[vmid]
}

func qvmid(r *http.Request) int { return atoiSafe(r.URL.Query().Get("vmid")) }
func atoiSafe(s string) int     { n := 0; fmt.Sscanf(s, "%d", &n); return n }
func cloneForm(in url.Values) url.Values {
	out := url.Values{}
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

const bPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNestedKey pveforge-harness-nested"

var bSiteKeys = map[string]string{
	"DOMAIN": "pvh.example.invalid",
	"N1_IP":  "192.0.2.90", "N2_IP": "192.0.2.91", "NFS_IP": "192.0.2.92",
	"GATEWAY": "192.0.2.1", "DNS": "192.0.2.53", "PREFIX": "24",
	"N1_MAC": "02:00:00:00:00:90", "N2_MAC": "02:00:00:00:00:91", "NFS_MAC": "02:00:00:00:00:92",
	"KEYBOARD": "en-us", "COUNTRY": "us", "TIMEZONE": "UTC", "MAILTO": "root@example.invalid",
	"SOURCE_ISO": "/srv/proxmox-ve.iso", "NFS_IMAGE": "debian-13-genericcloud-amd64.qcow2", "NFS_USER": "pvh",
	"CONTAINER_IMAGE": "debian:13", "PVE_KEYRING_SHA512": strings.Repeat("a", 128),
	"NODE_CORES": "4", "NODE_MEMORY_MIB": "16384", "NODE_DISK_GIB": "128",
	"NFS_CORES": "2", "NFS_MEMORY_MIB": "2048", "NFS_DATA_GIB": "200",
}

func writeSite(t *testing.T, home string, overrides map[string]string, omit string) {
	t.Helper()
	dir := filepath.Join(home, ".config/pveforge")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for k, v := range bSiteKeys {
		if k == omit {
			continue
		}
		if ov, ok := overrides[k]; ok {
			v = ov
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	if err := os.WriteFile(filepath.Join(dir, "harness-build.env"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// The nested SSH key (public half).
	if err := os.WriteFile(filepath.Join(dir, "harness-nested_ed25519.pub"), []byte(bPubKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newBuildTest wires the fake behind a TLS server, a per-test HOME + site file,
// the injected seams, and the universal never-destroy cleanup.
func newBuildTest(t *testing.T, f *bfake) (rosterPath, home string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	home = t.TempDir()
	t.Setenv("HOME", home)
	writeSite(t, home, nil, "")

	// Seams.
	save := struct {
		oh             func(string, string) (string, error)
		lh             func(string) ([]string, error)
		ks             func(string) (string, error)
		dl             func(string, string) bool
		pe, pf, lb, lp time.Duration
	}{buildOuterHost, buildLookupHost, buildKeyscan, buildDial, buildPollEvery, buildPollFor, buildLeftoverBound, buildLeftoverPoll}
	t.Cleanup(func() {
		buildOuterHost, buildLookupHost, buildKeyscan, buildDial = save.oh, save.lh, save.ks, save.dl
		buildPollEvery, buildPollFor, buildLeftoverBound, buildLeftoverPoll = save.pe, save.pf, save.lb, save.lp
	})
	buildOuterHost = func(string, string) (string, error) { return "198.51.100.20", nil } // not a VM address
	buildLookupHost = func(h string) ([]string, error) { return []string{h}, nil }
	buildKeyscan = func(ip string) (string, error) {
		return "# comment\n" + ip + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKey\n", nil
	}
	ipVM := map[string]bool{"192.0.2.90": true, "192.0.2.91": true, "192.0.2.92": true}
	buildDial = func(ip, port string) bool {
		if !ipVM[ip] {
			return false
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		v := map[string]int{"192.0.2.90": 690, "192.0.2.91": 691, "192.0.2.92": 692}[ip]
		return f.started[v] // nothing answers until the VM is started
	}
	buildPollEvery, buildPollFor = time.Millisecond, 2*time.Second
	buildLeftoverBound, buildLeftoverPoll = 20*time.Millisecond, 2*time.Millisecond

	// C6: a live never-destroy check on EVERY scenario — a SUCCESSFUL build
	// (result.txt carries "RESULT built") must destroy NOTHING. Build legitimately
	// destroys in cleanup on failure, so the gate is "success ⇒ zero destroys";
	// failure scenarios' destroys are checked by their own tests + the source
	// guard. The fake records a destroy as "destroy N".
	t.Cleanup(func() {
		if !strings.Contains(buildSteps(t, home), "RESULT built") {
			return // a failed build may destroy in cleanup
		}
		for _, w := range f.writeLog() {
			if strings.HasPrefix(w, "destroy ") {
				t.Errorf("a SUCCESSFUL build issued a destroy (%q): the never-destroy invariant is broken", w)
			}
		}
	})
	return newTestRosterWithTLSTarget(t, srv, "h", bNode), home
}

func TestBuild_Full(t *testing.T) {
	f := &bfake{}
	rosterPath, home := newBuildTest(t, f)
	code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	// The write sequence: create+tag each, start each, eject the two nodes. No destroy.
	want := []string{
		"create 690", "tag 690", "create 691", "tag 691", "create 692", "tag 692",
		"start 690", "start 691", "start 692",
		"eject 690", "eject 691",
	}
	if got := f.writeLog(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// The nfs create carries pool, @uri sshkeys, import-from, and no tags.
	nfs := f.form(692)
	if nfs.Get("pool") != "pveforge-harness" {
		t.Errorf("nfs create pool=%q, want pveforge-harness", nfs.Get("pool"))
	}
	if nfs.Get("tags") != "" {
		t.Errorf("nfs create carried tags=%q (must be set after create, D5)", nfs.Get("tags"))
	}
	if want := "ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIFakeNestedKey%20pveforge-harness-nested"; nfs.Get("sshkeys") != want {
		t.Errorf("nfs sshkeys=%q, want @uri %q", nfs.Get("sshkeys"), want)
	}
	if nfs.Get("scsi0") != "pveforge-harness:0,import-from=local:import/debian-13-genericcloud-amd64.qcow2" {
		t.Errorf("nfs scsi0=%q", nfs.Get("scsi0"))
	}
	node := f.form(690)
	if node.Get("scsi0") != "pveforge-harness:128" || node.Get("net0") != "virtio=02:00:00:00:00:90,bridge=vmbr0,firewall=0" {
		t.Errorf("node 690 create fields wrong: scsi0=%q net0=%q", node.Get("scsi0"), node.Get("net0"))
	}
	// result.txt + known_hosts pinned.
	if s := buildSteps(t, home); !strings.Contains(s, "RESULT built 690 691 692") || !strings.Contains(s, "PASS pinned 192.0.2.90 192.0.2.91 192.0.2.92") {
		t.Errorf("result.txt:\n%s", s)
	}
	assertNoDestroy(t, f.writeLog())
}

func TestBuild_PreflightRefusals(t *testing.T) {
	cases := []struct {
		name string
		f    *bfake
		seam func()
		want string
	}{
		{"VM already in pool", &bfake{pre: map[int]bool{690: true}}, nil, "VM 690 already exists in pool"},
		{"VMID not free", &bfake{nextidBusy: map[int]bool{691: true}}, nil, "VMID 691 is not free in the cluster"},
		{"storage holds a leftover", &bfake{contentPre: map[int]string{692: `[{"volid":"x"}]`}}, nil, "already holds volumes of VM 692"},
		{"missing node ISO", &bfake{noISO: map[int]bool{691: true}}, nil, "local:iso/pvh-n2-auto.iso is not on"},
		{"missing import image", &bfake{noImport: true}, nil, "local:import/debian-13-genericcloud-amd64.qcow2 is not on"},
		{"an address is the outer host", &bfake{}, func() { buildOuterHost = func(string, string) (string, error) { return "192.0.2.92", nil } }, "is the outer host"},
		{"an address already answers", &bfake{}, func() {
			buildDial = func(ip, port string) bool { return ip == "192.0.2.90" && port == "22" }
		}, "already answers"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rosterPath, _ := newBuildTest(t, c.f)
			if c.seam != nil {
				c.seam()
			}
			code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
			if code == 0 {
				t.Fatalf("a refusal exited 0; stderr %q", stderr)
			}
			if !strings.Contains(stderr, c.want) {
				t.Errorf("stderr %q, want %q", stderr, c.want)
			}
			for _, w := range c.f.writeLog() {
				t.Errorf("a preflight refusal issued a write: %q", w)
			}
		})
	}
}

func TestBuild_SiteFileRefusals(t *testing.T) {
	cases := []struct {
		name, want string
		over       map[string]string
		omit       string
	}{
		{"a missing key", "NFS_USER is missing", nil, "NFS_USER"},
		{"NFS_USER is root", "never root", map[string]string{"NFS_USER": "root"}, ""},
		{"a bad IP", "N1_IP=\"999.1.1.1\" is not a valid value", map[string]string{"N1_IP": "999.1.1.1"}, ""},
		{"two addresses collide", "each must be distinct", map[string]string{"N2_IP": "192.0.2.90"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &bfake{}
			rosterPath, home := newBuildTest(t, f)
			writeSite(t, home, c.over, c.omit)
			code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--storage", "pveforge-harness", "h")
			if code == 0 || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d stderr %q, want a refusal containing %q", code, stderr, c.want)
			}
			for _, w := range f.writeLog() {
				t.Errorf("a site-file refusal issued a write: %q", w)
			}
		})
	}
}

func TestBuild_CreateFailsMidwayCleansUp(t *testing.T) {
	f := &bfake{createFail: map[int]bool{691: true}}
	rosterPath, _ := newBuildTest(t, f)
	code, _, _ := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatal("a create failure exited 0")
	}
	// 690 created → destroyed in cleanup; 691's create failed (never recorded) →
	// never destroyed; 692 never reached.
	got := f.writeLog()
	var destroyed []string
	for _, w := range got {
		if strings.HasPrefix(w, "destroy ") {
			destroyed = append(destroyed, w)
		}
	}
	if strings.Join(destroyed, ",") != "destroy 690" {
		t.Errorf("destroys = %v, want only [destroy 690] (ledger-gated; 691 unrecorded, 692 unreached)", destroyed)
	}
}

func TestBuild_KeepOnFailure(t *testing.T) {
	f := &bfake{createFail: map[int]bool{691: true}}
	rosterPath, home := newBuildTest(t, f)
	code, _, _ := runRootArgs("harness", "build", "--keep-on-failure", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatal("a create failure exited 0")
	}
	for _, w := range f.writeLog() {
		if strings.HasPrefix(w, "destroy ") {
			t.Errorf("--keep-on-failure destroyed a VM: %q", w)
		}
	}
	if s := buildSteps(t, home); !strings.Contains(s, "KEPT 690") {
		t.Errorf("result.txt lacks KEPT:\n%s", s)
	}
}

func buildSteps(t *testing.T, home string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(home, ".config/pveforge/harness-evidence/build/*/result.txt"))
	if len(matches) == 0 {
		return ""
	}
	b, _ := os.ReadFile(matches[len(matches)-1])
	return string(b)
}

// C5 + C7/F2: cleanup proves the storage returned to the PREFLIGHT BASELINE, not
// to 0. Baseline is 1 MiB (StorageSlack, passes BaselineUsed); after destroy the
// storage settles to 1.5 MiB (within baseline+slack) with no listed volumes → NO
// leftover → the VMs are DESTROYED. Reverting build.go to pass 0 reports a false
// leftover (1.5 MiB > 0+slack) → RED.
func TestBuild_CleanupProvesGoneAgainstBaseline(t *testing.T) {
	f := &bfake{statusUsed: "1048576", usedAfterDestroy: "1572864"}
	rosterPath, home := newBuildTest(t, f)
	buildKeyscan = func(string) (string, error) { return "", fmt.Errorf("boom") } // fail pinAll → cleanup
	code, _, _ := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatal("a pin failure exited 0")
	}
	s := buildSteps(t, home)
	if strings.Contains(s, "LEFTOVER") {
		t.Errorf("cleanup reported a false leftover against baseline:\n%s", s)
	}
	for _, v := range []int{690, 691, 692} {
		if !strings.Contains(s, fmt.Sprintf("DESTROYED %d", v)) {
			t.Errorf("VM %d not reported DESTROYED:\n%s", v, s)
		}
	}
}

// C7/F2: a destroyed VM that is NOT proven gone (still in the pool) is reported
// LEFTOVER, never DESTROYED. Mutant: trust the destroy task / skip VMGone → 692
// would be DESTROYED → RED.
func TestBuild_CleanupGoneProofFails(t *testing.T) {
	f := &bfake{goneFail: map[int]bool{692: true}}
	rosterPath, home := newBuildTest(t, f)
	buildKeyscan = func(string) (string, error) { return "", fmt.Errorf("boom") }
	code, _, _ := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 {
		t.Fatal("a pin failure exited 0")
	}
	s := buildSteps(t, home)
	if strings.Contains(s, "DESTROYED 692") {
		t.Errorf("VM 692 reported DESTROYED despite not being proven gone:\n%s", s)
	}
	if !strings.Contains(s, "LEFTOVER") || !strings.Contains(s, "692") {
		t.Errorf("VM 692 not reported as a leftover:\n%s", s)
	}
	for _, v := range []int{690, 691} {
		if !strings.Contains(s, fmt.Sprintf("DESTROYED %d", v)) {
			t.Errorf("VM %d (proven gone) not DESTROYED:\n%s", v, s)
		}
	}
}

// C7/F3: the wall-clock poll timeout. Nothing ever answers → waitUp gives up at
// the bound → fail → cleanup. A mutant bounding by iteration count would not
// elapse the clock.
func TestBuild_PollTimeout(t *testing.T) {
	f := &bfake{}
	rosterPath, home := newBuildTest(t, f)
	buildDial = func(string, string) bool { return false } // nothing answers, ever
	buildPollFor, buildPollEvery = 30*time.Millisecond, time.Millisecond
	code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code == 0 || !strings.Contains(stderr, "still closed") {
		t.Fatalf("exit %d stderr %q, want a poll-timeout failure", code, stderr)
	}
	// Cleanup tore down the three created VMs.
	if s := buildSteps(t, home); !strings.Contains(s, "DESTROYED 690") {
		t.Errorf("poll timeout did not clean up:\n%s", s)
	}
}

// C7/F3 (SECURITY): ssh-keyscan must give exactly one ed25519 host key (O5).
func TestBuild_KeyscanRefused(t *testing.T) {
	cases := map[string]func(string) (string, error){
		"two keys": func(ip string) (string, error) {
			return ip + " ssh-ed25519 AAAAoNe\n" + ip + " ssh-ed25519 AAAAtWo\n", nil
		},
		"wrong address": func(string) (string, error) { return "10.0.0.1 ssh-ed25519 AAAAx\n", nil },
		"not ed25519":   func(ip string) (string, error) { return ip + " ssh-rsa AAAArsa\n", nil },
	}
	for name, ks := range cases {
		t.Run(name, func(t *testing.T) {
			f := &bfake{}
			rosterPath, _ := newBuildTest(t, f)
			buildKeyscan = ks
			code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
			if code == 0 || !strings.Contains(stderr, "did not give exactly one ed25519 host key") {
				t.Errorf("exit %d stderr %q, want a keyscan refusal", code, stderr)
			}
		})
	}
}

// C7/F3 (SECURITY): known_hosts keeps every other address's pin, writes the three
// new ones, and is mode 0600.
func TestBuild_KnownHostsPreservedAndPrivate(t *testing.T) {
	f := &bfake{}
	rosterPath, home := newBuildTest(t, f)
	known := filepath.Join(home, ".config/pveforge/harness-nested.known_hosts")
	if err := os.WriteFile(known, []byte("203.0.113.5 ssh-ed25519 AAAAOtherHost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runRootArgs("harness", "build", "--roster", rosterPath, "--created-file", harnessLedgerFile(t), "--storage", "pveforge-harness", "h")
	if code != 0 {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	b, err := os.ReadFile(known)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "203.0.113.5 ssh-ed25519 AAAAOtherHost") {
		t.Errorf("known_hosts dropped the other address's pin:\n%s", got)
	}
	for _, ip := range []string{"192.0.2.90", "192.0.2.91", "192.0.2.92"} {
		if !strings.Contains(got, ip+" ssh-ed25519 ") {
			t.Errorf("known_hosts missing the pin for %s:\n%s", ip, got)
		}
	}
	fi, _ := os.Stat(known)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts mode = %o, want 600", fi.Mode().Perm())
	}
}
