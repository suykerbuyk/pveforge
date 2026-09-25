package sourceguard

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// The harness build's phase A (pveforge-harness-build): prepare-iso.sh, the
// answer template, and build.sh, run offline. build.sh reaches PVE only
// through lib.sh and the sequenced fake pveforge; its TCP poll and host-key
// scan run against stubs. prepare-iso.sh runs against fake openssl,
// ssh-keygen and podman. The site file is the committed example itself, so
// these cases also prove it complete and valid.

const (
	bISO    = "get /nodes/qa-pve-02/storage/local/content content=iso"
	bImport = "get /nodes/qa-pve-02/storage/local/content content=import"

	nestedPub  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNestedKeyFakeNestedKeyFakeNestedKey0 pveforge-harness-nested"
	fakeHash   = "$6$fakesalt$FakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFakeHashFake12"
	nestedPw   = "Nested-Test-Pw-7f3a9c"
	otherPin   = "198.51.100.7 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherHostOtherHost"
	allMembers = `[{"poolid":"pveforge-harness","comment":"","members":[` +
		`{"id":"qemu/690","type":"qemu","vmid":690,"node":"qa-pve-02"},` +
		`{"id":"qemu/691","type":"qemu","vmid":691,"node":"qa-pve-02"},` +
		`{"id":"qemu/692","type":"qemu","vmid":692,"node":"qa-pve-02"}]}]`
)

var buildIPs = map[string]string{"690": "192.0.2.90", "691": "192.0.2.91", "692": "192.0.2.92"}

func bContent(v string) string {
	return "get /nodes/qa-pve-02/storage/pveforge-harness/content vmid=" + v
}
func bConf(v string) string   { return "get /nodes/qa-pve-02/qemu/" + v + "/config" }
func bStatus(v string) string { return "get /nodes/qa-pve-02/qemu/" + v + "/status/current" }
func bStart(v string) string  { return "post /nodes/qa-pve-02/qemu/" + v + "/status/start" }
func hostKey(v string) string {
	return buildIPs[v] + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey" + v
}

// exampleEnv is the committed harness-build.env.example, with each of
// replace's KEY=value lines put in place of that key's.
func exampleEnv(t *testing.T, replace ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(harnessDir, "build", "harness-build.env.example"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for _, r := range replace {
		key, _, _ := strings.Cut(r, "=")
		found := false
		for i, l := range lines {
			if strings.HasPrefix(l, key+"=") {
				lines[i], found = r, true
			}
		}
		if !found {
			t.Fatalf("the example has no %s", key)
		}
	}
	return strings.Join(lines, "\n")
}

func fakeBody(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(harnessDir, "test", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// buildHome is what the operator has before build.sh: the site file and the
// nested key; keyscan answers each address with one host key.
type buildHome struct {
	env     string // the site file ("" = the example as committed)
	noKey   bool
	known   string // an existing known_hosts ("" = none)
	knownM  os.FileMode
	keyscan map[string]string // vmid -> the scan's output, replacing hostKey
	tcp     map[string]string // "ip_port" -> attempts that fail first (default 1: the preflight's), or "never"
	outer   string            // the harness roster's host for qa-pve-02-harness ("" = 198.51.100.20; "-" = none)
	getent  map[string]string // host -> getent ahostsv4's answer
	extra   func(t *testing.T, home string)
}

func (b buildHome) setup(t *testing.T, home string) {
	t.Helper()
	cfg := filepath.Join(home, ".config/pveforge")
	env := b.env
	if env == "" {
		env = exampleEnv(t)
	}
	writeFile(t, filepath.Join(cfg, "harness-build.env"), env, 0o600)
	outer := b.outer
	if outer == "" {
		outer = "198.51.100.20"
	}
	roster := "# test roster\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"192.0.2.91\"\n\n[[targets]]\nnode = \"qa-pve-02\"\nid = \"qa-pve-02-harness\"\n"
	if outer != "-" {
		roster += "host = \"" + outer + "\"\n"
	}
	// Decoys: a sub-table's host is never the target's, whether or not the
	// sub-table has an id of its own.
	roster += "\n[targets.ssh]\nuser = \"root\"\nhost = \"192.0.2.90\"\n\n[targets.token]\nid = \"pveforge-harness@pve!build\"\nhost = \"192.0.2.91\"\n"
	writeFile(t, filepath.Join(cfg, "harness-outer.toml"), roster, 0o600)
	if !b.noKey {
		writeFile(t, filepath.Join(cfg, "harness-nested_ed25519"), "fake private key\n", 0o600)
		writeFile(t, filepath.Join(cfg, "harness-nested_ed25519.pub"), nestedPub+"\n", 0o644)
	}
	if b.known != "" {
		m := b.knownM
		if m == 0 {
			m = 0o600
		}
		writeFile(t, filepath.Join(cfg, "harness-nested.known_hosts"), b.known, m)
	}
	fake := filepath.Join(filepath.Dir(home), "fake")
	for v, ip := range buildIPs {
		out, ok := b.keyscan[v]
		if !ok {
			out = "# " + ip + ":22 SSH-2.0-OpenSSH_10.0\n" + hostKey(v) + "\n"
		}
		writeFile(t, filepath.Join(fake, "keyscan", ip), out, 0o600)
	}
	for k, n := range b.tcp {
		writeFile(t, filepath.Join(fake, "tcp", k), n, 0o600)
	}
	for h, a := range b.getent {
		writeFile(t, filepath.Join(fake, "getent", h), a, 0o600)
	}
	if b.extra != nil {
		b.extra(t, home)
	}
}

// buildWorld: a clean slate on qa-pve-02. The pool is empty at the preflight
// and then lists all three; each VM carries the tag and is running.
func buildWorld(t *testing.T, h buildHome) probeSpec {
	s := probeSpec{
		script: "build/build.sh",
		resp: map[string]string{
			pPool:   allMembers,
			bISO:    `[{"volid":"local:iso/proxmox-ve_9.2-1.iso"},{"volid":"local:iso/pvh-n1-auto.iso"},{"volid":"local:iso/pvh-n2-auto.iso"}]`,
			bImport: `[{"volid":"local:import/debian-13-genericcloud-amd64.qcow2"}]`,
		},
		seq:  map[string]map[int]string{pPool: {1: emptyPool}},
		rc:   map[string]map[int]int{},
		err:  map[string]map[int]string{},
		args: []string{"--storage", "pveforge-harness"},
		stubs: clockStubs(t, map[string]string{
			"timeout":     fakeBody(t, "fake-timeout.sh"),
			"ssh-keyscan": fakeBody(t, "fake-keyscan-hosts.sh"),
			"getent":      "#!/usr/bin/env bash\n[ \"$1\" = ahostsv4 ] && [ -f \"$FAKE_PVEFORGE_DIR/getent/$2\" ] || exit 2\ncat \"$FAKE_PVEFORGE_DIR/getent/$2\"\n",
		}),
		setup: h.setup,
	}
	for v := range buildIPs {
		s.resp[bContent(v)] = `[]`
		s.resp[bConf(v)] = `{"name":"x","tags":"pveforge-harness"}`
		s.resp[bStatus(v)] = `{"status":"running"}`
	}
	return s
}

// clockStubs adds a fake clock to stubs: $FAKE_PVEFORGE_DIR/clock holds the
// seconds elapsed; sleep adds its argument, the TCP fake adds 5 per timed-out
// attempt, and `date +%s` reads it (any other date call is the real date's).
func clockStubs(t *testing.T, stubs map[string]string) map[string]string {
	t.Helper()
	realDate, err := exec.LookPath("date")
	if err != nil {
		t.Fatal(err)
	}
	stubs["date"] = "#!/usr/bin/env bash\nif [ \"$*\" = +%s ]; then\n\tc=0\n\t[ -f \"$FAKE_PVEFORGE_DIR/clock\" ] && c=$(cat \"$FAKE_PVEFORGE_DIR/clock\")\n\techo $((1790000000 + c))\n\texit 0\nfi\nexec " + realDate + " \"$@\"\n"
	stubs["sleep"] = "#!/usr/bin/env bash\necho \"$*\" >>\"$FAKE_PVEFORGE_DIR/sleep.log\"\nc=0\n[ -f \"$FAKE_PVEFORGE_DIR/clock\" ] && c=$(cat \"$FAKE_PVEFORGE_DIR/clock\")\nprintf '%s' $((c + $1)) >\"$FAKE_PVEFORGE_DIR/clock\"\n"
	return stubs
}

// goneAfter makes VM v answer "does not exist" from its status read n on.
func goneAfter(s probeSpec, v string, n int) {
	s.rc[bStatus(v)] = map[int]int{}
	s.err[bStatus(v)] = map[int]string{}
	for i := n; i < n+8; i++ {
		s.rc[bStatus(v)][i] = 1
		s.err[bStatus(v)][i] = "get vm " + v + " status: 500 Internal Server Error: Configuration file 'nodes/qa-pve-02/qemu-server/" + v + ".conf' does not exist"
	}
}

func bCall(verb, sub, data string) string {
	c := "api " + verb + " /nodes/qa-pve-02/qemu/" + sub + " qa-pve-02-harness --roster R -o json"
	if data != "" {
		c += " " + data
	}
	return c
}

const sshkeysURI = "ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5AAAAIFakeNestedKeyFakeNestedKeyFakeNestedKey0%20pveforge-harness-nested"

var (
	bCreate = map[string]string{
		"690": `vm create qa-pve-02-harness 690 --roster R --json {"name":"pvh-n1","ostype":"l26","cpu":"host","cores":"4","memory":"16384","bios":"seabios","scsihw":"virtio-scsi-single","scsi0":"pveforge-harness:128","ide2":"local:iso/pvh-n1-auto.iso,media=cdrom","net0":"virtio=02:00:00:00:00:90,bridge=vmbr0,firewall=0","boot":"order=scsi0;ide2","pool":"pveforge-harness"}`,
		"691": `vm create qa-pve-02-harness 691 --roster R --json {"name":"pvh-n2","ostype":"l26","cpu":"host","cores":"4","memory":"16384","bios":"seabios","scsihw":"virtio-scsi-single","scsi0":"pveforge-harness:128","ide2":"local:iso/pvh-n2-auto.iso,media=cdrom","net0":"virtio=02:00:00:00:00:91,bridge=vmbr0,firewall=0","boot":"order=scsi0;ide2","pool":"pveforge-harness"}`,
		"692": `vm create qa-pve-02-harness 692 --roster R --json {"name":"pvh-nfs","ostype":"l26","cpu":"host","cores":"2","memory":"2048","bios":"seabios","scsihw":"virtio-scsi-single","scsi0":"pveforge-harness:0,import-from=local:import/debian-13-genericcloud-amd64.qcow2","scsi1":"pveforge-harness:200","ide2":"pveforge-harness:cloudinit","net0":"virtio=02:00:00:00:00:92,bridge=vmbr0,firewall=0","boot":"order=scsi0","agent":"1","ipconfig0":"ip=192.0.2.92/24,gw=192.0.2.1","nameserver":"192.0.2.53","searchdomain":"pvh.example.invalid","ciuser":"pvh","sshkeys":"` + sshkeysURI + `","pool":"pveforge-harness"}`,
	}
	bTag    = func(v string) string { return bCall("put", v+"/config", "--data tags=pveforge-harness") }
	bStartC = func(v string) string { return bCall("post", v+"/status/start", "") }
	bStopC  = func(v string) string { return bCall("post", v+"/status/stop", "") }
	bEject  = func(v string) string {
		return bCall("put", v+"/config", "--data ide2=none,media=cdrom --data boot=order=scsi0")
	}
	bDestroy = func(v string) string {
		return bCall("delete", v, "--data purge=1 --data destroy-unreferenced-disks=1")
	}
	bCreated = []string{bCreate["690"], bTag("690"), bCreate["691"], bTag("691"), bCreate["692"], bTag("692"),
		bStartC("690"), bStartC("691"), bStartC("692")}
	bFull = append(append([]string{}, bCreated...), bEject("690"), bEject("691"))
	// bTornDown: cleanup after all three were created and started.
	bTornDown = append(append([]string{}, bCreated...),
		bStopC("692"), bDestroy("692"), bStopC("691"), bDestroy("691"), bStopC("690"), bDestroy("690"))
)

func (r probeResult) known() (string, bool) {
	b, err := os.ReadFile(filepath.Join(r.home, ".config/pveforge/harness-nested.known_hosts"))
	return string(b), err == nil
}

func (r probeResult) buildEvidence(t *testing.T, name string) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/build/*"))
	if len(dirs) != 1 {
		t.Fatalf("build evidence directories = %q, want exactly one", dirs)
	}
	b, err := os.ReadFile(filepath.Join(dirs[0], name))
	if err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	return string(b)
}

func fakeLog(r probeResult, name string) string {
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(r.home), "fake", name))
	return string(b)
}

// B1: a clean build: the three VMs are created, tagged and started, each
// system comes up, the nodes' ISOs are ejected, and the host keys pinned.
func TestBuild_Full(t *testing.T) {
	s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.90_8006": "4", "192.0.2.92_22": "2"}})
	r := runProbe(t, s)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), bFull)
	if r.stdout != "built=690,691,692 storage=pveforge-harness known_hosts="+filepath.Join(r.home, ".config/pveforge/harness-nested.known_hosts")+"\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	if r.sleeps != 3 {
		t.Errorf("slept %d times, want 3 (8006 on pvh-n1 opens on the 4th attempt)", r.sleeps)
	}
	want := hostKey("690") + "\n" + hostKey("691") + "\n" + hostKey("692") + "\n"
	if got, ok := r.known(); !ok || got != want {
		t.Errorf("known_hosts %q, want %q", got, want)
	}
	fi, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.known_hosts"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts mode: %v %v", fi.Mode().Perm(), err)
	}
	// Only the three configured addresses, and only their ports, are probed.
	for _, l := range strings.Split(strings.TrimSpace(fakeLog(r, "tcp.log")), "\n") {
		switch l {
		case "192.0.2.90:22", "192.0.2.90:8006", "192.0.2.91:22", "192.0.2.91:8006", "192.0.2.92:22":
		default:
			t.Errorf("probed %q", l)
		}
	}
	if got := fakeLog(r, "keyscan.log"); got != "-T 10 -t ed25519 192.0.2.90\n-T 10 -t ed25519 192.0.2.91\n-T 10 -t ed25519 192.0.2.92\n" {
		t.Errorf("keyscan calls %q", got)
	}
	res := r.buildEvidence(t, "result.txt")
	for _, w := range []string{"PASS preflight", "PASS create 692 pvh-nfs", "PASS up after 3 polls", "PASS eject 691", "PASS pinned", "RESULT built 690 691 692"} {
		if !strings.Contains(res, w) {
			t.Errorf("result.txt lacks %q:\n%s", w, res)
		}
	}
	r.buildEvidence(t, "MANIFEST.sha256")
	r.buildEvidence(t, "pool-before.json")
}

// B2: the preflight refuses by name, before anything is created.
func TestBuild_PreflightRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		h    buildHome
		edit func(s probeSpec)
		want string
	}{
		"691 exists":     {edit: func(s probeSpec) { s.seq[pPool] = nil }, want: "VM 690 already exists in pool pveforge-harness: the build runs on a clean slate"},
		"a leftover":     {edit: func(s probeSpec) { s.resp[bContent("692")] = oneVolume }, want: "storage pveforge-harness already holds volumes of VM 692"},
		"no n2 ISO":      {edit: func(s probeSpec) { s.resp[bISO] = `[{"volid":"local:iso/pvh-n1-auto.iso"}]` }, want: "local:iso/pvh-n2-auto.iso is not on qa-pve-02"},
		"no n1 ISO":      {edit: func(s probeSpec) { s.resp[bISO] = `[{"volid":"local:iso/pvh-n2-auto.iso"}]` }, want: "local:iso/pvh-n1-auto.iso is not on qa-pve-02"},
		"no image":       {edit: func(s probeSpec) { s.resp[bImport] = `[]` }, want: "local:import/debian-13-genericcloud-amd64.qcow2 is not on qa-pve-02"},
		"no key":         {h: buildHome{noKey: true}, want: "harness-nested_ed25519.pub does not exist: run prepare-iso.sh first"},
		"already pinned": {h: buildHome{known: otherPin + "\n" + hostKey("691") + "\n"}, want: "already pins a host key for 192.0.2.91 (pvh-n2); a new build makes new host keys: run with --repin"},
		"loose pins":     {h: buildHome{known: otherPin + "\n", knownM: 0o644}, want: "has mode 644, want 600"},
		"pins a directory": {h: buildHome{extra: func(t *testing.T, home string) {
			os.MkdirAll(filepath.Join(home, ".config/pveforge/harness-nested.known_hosts"), 0o700)
		}}, want: "harness-nested.known_hosts is not a regular file"},
	} {
		t.Run(name, func(t *testing.T) {
			s := buildWorld(t, tc.h)
			if tc.edit != nil {
				tc.edit(s)
			}
			r := runProbe(t, s)
			if r.code != 3 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 3 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			if w := r.writes(); len(w) != 0 {
				t.Errorf("a refused build sent %q", w)
			}
		})
	}
	// A pin for another address is no reason to refuse.
	if r := runProbe(t, buildWorld(t, buildHome{known: otherPin + "\n"})); r.code != 0 {
		t.Errorf("another address pinned: exit %d\n%s", r.code, r.stderr)
	} else if got, _ := r.known(); got != otherPin+"\n"+hostKey("690")+"\n"+hostKey("691")+"\n"+hostKey("692")+"\n" {
		t.Errorf("known_hosts %q", got)
	}
}

// B3: the site file is read, never sourced, and refused whole when anything
// in it is wrong.
func TestBuild_SiteFile(t *testing.T) {
	for name, tc := range map[string]struct {
		env  func(t *testing.T) string
		mode os.FileMode
		want string
	}{
		"loose mode":         {func(t *testing.T) string { return exampleEnv(t) }, 0o644, "harness-build.env has mode 644, want 600"},
		"a missing key":      {func(t *testing.T) string { return strings.Replace(exampleEnv(t), "NFS_DATA_GIB=200\n", "", 1) }, 0, "NFS_DATA_GIB is missing"},
		"an unknown key":     {func(t *testing.T) string { return exampleEnv(t) + "NFS_DATA_GB=200\n" }, 0, "unknown key NFS_DATA_GB"},
		"a repeated key":     {func(t *testing.T) string { return exampleEnv(t) + "N1_IP=192.0.2.90\n" }, 0, "N1_IP is set twice"},
		"a bad address":      {func(t *testing.T) string { return exampleEnv(t, "N2_IP=192.0.2.256") }, 0, "N2_IP='192.0.2.256' is not a valid value"},
		"a bad octet":        {func(t *testing.T) string { return exampleEnv(t, "GATEWAY=256.0.2.1") }, 0, "GATEWAY='256.0.2.1' is not a valid value"},
		"a vendor MAC":       {func(t *testing.T) string { return exampleEnv(t, "N1_MAC=bc:24:11:00:00:90") }, 0, "N1_MAC='bc:24:11:00:00:90' is not a valid value"},
		"a quoted value":     {func(t *testing.T) string { return exampleEnv(t, `DOMAIN="pvh.example.invalid"`) }, 0, "DOMAIN='\"pvh.example.invalid\"' is not a valid value"},
		"a TOML breakout":    {func(t *testing.T) string { return exampleEnv(t, `TIMEZONE=UTC"`) }, 0, "TIMEZONE='UTC\"' is not a valid value"},
		"code, not a file":   {func(t *testing.T) string { return exampleEnv(t, "DOMAIN=$(touch pwned)") }, 0, "DOMAIN='$(touch pwned)' is not a valid value"},
		"not KEY=value":      {func(t *testing.T) string { return exampleEnv(t) + "export N1_IP\n" }, 0, "not KEY=value"},
		"root on pvh-nfs":    {func(t *testing.T) string { return exampleEnv(t, "NFS_USER=root") }, 0, "NFS_USER='root' is not a valid value"},
		"n2 at n1's address": {func(t *testing.T) string { return exampleEnv(t, "N2_IP=192.0.2.90") }, 0, "N1_IP and N2_IP are both 192.0.2.90: each must be distinct"},
		"nfs at the gateway": {func(t *testing.T) string { return exampleEnv(t, "NFS_IP=192.0.2.1") }, 0, "NFS_IP and GATEWAY are both 192.0.2.1"},
		"n1 at the resolver": {func(t *testing.T) string { return exampleEnv(t, "N1_IP=192.0.2.53") }, 0, "N1_IP and DNS are both 192.0.2.53"},
		"a shared MAC":       {func(t *testing.T) string { return exampleEnv(t, "NFS_MAC=02:00:00:00:00:91") }, 0, "N2_MAC and NFS_MAC are both 02:00:00:00:00:91"},
		"a zero size":        {func(t *testing.T) string { return exampleEnv(t, "NODE_DISK_GIB=0") }, 0, "NODE_DISK_GIB='0' is not a valid value"},
	} {
		t.Run(name, func(t *testing.T) {
			h := buildHome{env: tc.env(t)}
			s := buildWorld(t, h)
			if tc.mode != 0 {
				s.setup = func(t *testing.T, home string) {
					h.setup(t, home)
					os.Chmod(filepath.Join(home, ".config/pveforge/harness-build.env"), tc.mode)
				}
			}
			r := runProbe(t, s)
			if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			if len(r.calls) != 0 {
				t.Errorf("a bad site file reached pveforge: %q", r.calls)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(r.home), "work", "pwned")); err == nil {
				t.Error("the site file was run as code")
			}
		})
	}
	s := buildWorld(t, buildHome{})
	s.setup = func(t *testing.T, home string) {}
	if r := runProbe(t, s); r.code != 2 || !strings.Contains(r.stderr, "harness-build.env does not exist (copy hack/harness/build/harness-build.env.example there") {
		t.Errorf("no site file: exit %d\n%s", r.code, r.stderr)
	}
}

// B4: --repin replaces the three addresses' pins, and keeps every other.
func TestBuild_Repin(t *testing.T) {
	s := buildWorld(t, buildHome{known: "192.0.2.90 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStaleKey\n" + otherPin + "\n" +
		"192.0.2.92 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStaleKey692\n"})
	s.args = append(s.args, "--repin")
	r := runProbe(t, s)
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	if got, _ := r.known(); got != otherPin+"\n"+hostKey("690")+"\n"+hostKey("691")+"\n"+hostKey("692")+"\n" {
		t.Errorf("known_hosts %q", got)
	}
	if !strings.Contains(r.buildEvidence(t, "result.txt"), "(repinned)") {
		t.Error("the repin is not recorded")
	}
}

// B5: a system that never comes up: a named failure after 30 minutes, and
// cleanup stops and destroys this run's three VMs, newest first.
func TestBuild_PollTimeoutCleansUp(t *testing.T) {
	s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.91_8006": "never"}})
	for v := range buildIPs {
		goneAfter(s, v, 2)
	}
	r := runProbe(t, s)
	// A clock, not a count: each round's timed-out attempt (5 s) and sleep
	// (10 s) spend 15 s of the 1800, so 120 sleeps, never 180.
	if r.code != 4 || !strings.Contains(r.stderr, "after 1800s, still closed: pvh-n2=192.0.2.91:8006") || r.sleeps != 120 {
		t.Fatalf("exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), bTornDown)
	if !strings.Contains(r.stderr, "build: cleanup: this run's VM(s) 690 691 692 destroyed") || strings.Contains(r.stderr, "LEFTOVER") {
		t.Errorf("cleanup:\n%s", r.stderr)
	}
	if _, ok := r.known(); ok {
		t.Error("a failed build pinned host keys")
	}
}

// B6: --keep-on-failure leaves this run's VMs, and says so.
func TestBuild_KeepOnFailure(t *testing.T) {
	s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.92_22": "never"}})
	s.args = append(s.args, "--keep-on-failure")
	r := runProbe(t, s)
	if r.code != 4 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), bCreated)
	for _, w := range []string{"--keep-on-failure: leaving VM(s) 690 691 692 for inspection", "LEFTOVER: kept for inspection (--keep-on-failure)", "VM 692 (pvh-nfs): status running", "qm destroy <vmid> --purge"} {
		if !strings.Contains(r.stderr, w) {
			t.Errorf("stderr lacks %q:\n%s", w, r.stderr)
		}
	}
	if !strings.Contains(r.buildEvidence(t, "result.txt"), "KEPT 690 691 692") {
		t.Error("KEPT is not recorded")
	}
}

// B7: a create that fails midway: cleanup destroys only what this run
// created; the VM whose create failed after it appeared is named, never
// touched.
func TestBuild_CreateFailsMidway(t *testing.T) {
	s := buildWorld(t, buildHome{})
	s.rc["vm create 691"] = map[int]int{0: 5}
	s.resp[pPool] = strings.Replace(allMembers, `,{"id":"qemu/692","type":"qemu","vmid":692,"node":"qa-pve-02"}`, "", 1)
	s.resp[bStatus("690")] = `{"status":"stopped"}`
	goneAfter(s, "690", 2)
	r := runProbe(t, s)
	if r.code != 5 {
		t.Fatalf("exit %d, want pveforge's 5\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), []string{bCreate["690"], bTag("690"), bCreate["691"], bDestroy("690")})
	if !strings.Contains(r.stderr, "LEFTOVER: cleanup could not remove all of them, or this run did not record creating them") || !strings.Contains(r.stderr, "VM 691 (pvh-n2)") || strings.Contains(r.stderr, "VM 690 (pvh-n1)") {
		t.Errorf("leftover:\n%s", r.stderr)
	}
}

// B8: cleanup cannot destroy a VM: the report names it and the status stands.
func TestBuild_CleanupFailsReportsLeftover(t *testing.T) {
	s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.90_22": "never"}})
	goneAfter(s, "691", 2)
	goneAfter(s, "692", 2)
	s.rc["delete /nodes/qa-pve-02/qemu/690 purge=1 destroy-unreferenced-disks=1"] = map[int]int{0: 7}
	r := runProbe(t, s)
	if r.code != 4 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	for _, w := range []string{"LEFTOVER:", "VM 690 (pvh-n1): status running", "pvesm list pveforge-harness --vmid <vmid>"} {
		if !strings.Contains(r.stderr, w) {
			t.Errorf("stderr lacks %q:\n%s", w, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "VM 691 (pvh-n2)") {
		t.Errorf("a destroyed VM is reported left:\n%s", r.stderr)
	}
}

// B9: a host-key scan that does not give exactly one ed25519 key for the
// address asked: a failure, nothing pinned, and cleanup.
func TestBuild_KeyscanRefused(t *testing.T) {
	for name, out := range map[string]string{
		"two keys":            hostKey("692") + "\n" + hostKey("692") + "2\n",
		"none":                "",
		"another address":     "192.0.2.99 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey692\n",
		"a regex-dot address": "192x0.2.92 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey692\n",
		"an rsa key":          "192.0.2.92 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ\n",
	} {
		t.Run(name, func(t *testing.T) {
			s := buildWorld(t, buildHome{keyscan: map[string]string{"692": out}})
			for v := range buildIPs {
				goneAfter(s, v, 2)
			}
			r := runProbe(t, s)
			if r.code != 4 || !strings.Contains(r.stderr, "ssh-keyscan 192.0.2.92 did not give exactly one ed25519 host key") {
				t.Fatalf("exit %d\n%s", r.code, r.stderr)
			}
			if _, ok := r.known(); ok {
				t.Error("pinned after a bad scan")
			}
			if !strings.Contains(r.stderr, "destroyed") {
				t.Errorf("no cleanup:\n%s", r.stderr)
			}
		})
	}
}

// B10: Ctrl-C midway: 130, and cleanup.
func TestBuild_SignalCleansUp(t *testing.T) {
	s := buildWorld(t, buildHome{})
	s.kill = map[string]map[int]string{bStart("691"): {1: "INT"}}
	s.resp[bStatus("692")] = `{"status":"stopped"}` // never started
	for v := range buildIPs {
		goneAfter(s, v, 2)
	}
	r := runProbe(t, s)
	if r.code != 130 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), append(append([]string{}, bCreated[:8]...),
		bDestroy("692"), bStopC("691"), bDestroy("691"), bStopC("690"), bDestroy("690")))
}

// B11: the pins land as a regular file holding exactly them, or the build
// fails; the evidence directories are private even when they already exist.
func TestBuild_PinsVerifiedAndPrivate(t *testing.T) {
	s := buildWorld(t, buildHome{})
	s.stubs["mv"] = "#!/usr/bin/env bash\nexit 0\n"
	for v := range buildIPs {
		goneAfter(s, v, 2)
	}
	if r := runProbe(t, s); r.code != 4 || !strings.Contains(r.stderr, "is not a regular file holding the pins after the write") {
		t.Errorf("an mv that writes nothing: exit %d\n%s", r.code, r.stderr)
	}
	s = buildWorld(t, buildHome{extra: func(t *testing.T, home string) {
		p := filepath.Join(home, ".config/pveforge/harness-evidence/build")
		os.MkdirAll(p, 0o700)
		os.Chmod(p, 0o777)
	}})
	r := runProbe(t, s)
	fi, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-evidence/build"))
	if r.code != 0 || err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("exit %d, evidence parent %v %v", r.code, fi.Mode().Perm(), err)
	}
}

// ---- prepare-iso.sh ----

func isoWorld(t *testing.T, pw string, extra func(t *testing.T, home string)) probeSpec {
	return probeSpec{
		script: "build/prepare-iso.sh",
		env:    map[string]string{"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD": pw},
		stubs: map[string]string{
			"podman":     fakeBody(t, "fake-podman.sh"),
			"openssl":    fakeBody(t, "fake-openssl.sh"),
			"ssh-keygen": fakeBody(t, "fake-ssh-keygen.sh"),
		},
		setup: func(t *testing.T, home string) {
			iso := filepath.Join(filepath.Dir(home), "isos", "proxmox-ve_9.2-1.iso")
			writeFile(t, iso, "the installer\n", 0o644)
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-build.env"), exampleEnv(t, "SOURCE_ISO="+iso), 0o600)
			if extra != nil {
				extra(t, home)
			}
		},
	}
}

func isoOut(t *testing.T, r probeResult) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-build/*"))
	if len(dirs) != 1 {
		t.Fatalf("output directories %q", dirs)
	}
	return dirs[0]
}

var kebab = regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`)

// checkKebab: every key is kebab-case, but those naming a udev property (the
// NIC filter) or a MAC (the pinning map), which are PVE's and not ours.
func checkKebab(t *testing.T, m map[string]any, path string) {
	t.Helper()
	for k, v := range m {
		if path != "network.filter" && path != "network.interface-name-pinning.mapping" && !kebab.MatchString(k) {
			t.Errorf("key %s.%s is not kebab-case", path, k)
		}
		if sub, ok := v.(map[string]any); ok {
			checkKebab(t, sub, strings.TrimPrefix(path+"."+k, "."))
		}
	}
}

// I1: the answers are rendered, parse as TOML with kebab-case keys and the
// site's values, hold the hash and never the password; the password reaches
// openssl on stdin only; the ISOs are prepared in the container and their
// hashes printed.
func TestPrepareISO_Full(t *testing.T) {
	r := runProbe(t, isoWorld(t, nestedPw, nil))
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	out := isoOut(t, r)
	var sums strings.Builder
	for i, node := range []string{"pvh-n1", "pvh-n2"} {
		ip := []string{"192.0.2.90", "192.0.2.91"}[i]
		mac := []string{"02:00:00:00:00:90", "02:00:00:00:00:91"}[i]
		b, err := os.ReadFile(filepath.Join(out, node+".toml"))
		if err != nil {
			t.Fatal(err)
		}
		var a map[string]any
		if err := toml.Unmarshal(b, &a); err != nil {
			t.Fatalf("%s: %v\n%s", node, err, b)
		}
		checkKebab(t, a, "")
		g, _ := a["global"].(map[string]any)
		n, _ := a["network"].(map[string]any)
		d, _ := a["disk-setup"].(map[string]any)
		pin, _ := n["interface-name-pinning"].(map[string]any)
		got := fmt.Sprint(g["fqdn"], "|", g["root-password-hashed"], "|", g["root-ssh-keys"], "|", g["reboot-on-error"], "|",
			g["keyboard"], g["country"], g["timezone"], g["mailto"], "|",
			n["source"], n["cidr"], n["gateway"], n["dns"], n["filter"], "|", pin["enabled"], pin["mapping"], "|", d["filesystem"], d["disk-list"])
		want := fmt.Sprint(node+".pvh.example.invalid", "|", fakeHash, "|", []any{nestedPub}, "|", false, "|",
			"en-us", "us", "UTC", "root@pvh.example.invalid", "|",
			"from-answer", ip+"/24", "192.0.2.1", "192.0.2.53", map[string]any{"ID_NET_NAME_MAC": "*" + strings.ReplaceAll(mac, ":", "")}, "|",
			true, map[string]any{mac: "nic0"}, "|", "ext4", []any{"sda"})
		if got != want {
			t.Errorf("%s:\n got  %s\n want %s", node, got, want)
		}
		iso, err := os.ReadFile(filepath.Join(out, node+"-auto.iso"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&sums, "%x  %s-auto.iso\n", sha256.Sum256(iso), node)
		for _, f := range []string{node + ".toml", node + "-auto.iso"} {
			if fi, err := os.Stat(filepath.Join(out, f)); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v %v", f, fi.Mode().Perm(), err)
			}
		}
	}
	if r.stdout != sums.String() {
		t.Errorf("stdout %q, want %q", r.stdout, sums.String())
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("output directory mode %v %v", fi.Mode().Perm(), err)
	}
	// The password: on openssl's stdin, and nowhere else at all.
	if got := fakeLog(r, "openssl.stdin"); got != nestedPw+"\n" {
		t.Errorf("openssl's stdin %q", got)
	}
	if got := fakeLog(r, "openssl.argv"); got != "passwd\n-6\n-stdin\n" {
		t.Errorf("openssl's argv %q", got)
	}
	tmp := filepath.Dir(r.home)
	seen := 0
	filepath.WalkDir(tmp, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || p == filepath.Join(tmp, "fake", "openssl.stdin") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("read %s: %v", p, err)
			return nil
		}
		seen++
		if strings.Contains(string(b), nestedPw) {
			t.Errorf("%s holds the password", p)
		}
		return nil
	})
	if seen < 10 {
		t.Errorf("walked only %d files", seen)
	}
	for _, env := range []string{"openssl.env", "podman.env"} {
		if strings.Contains(fakeLog(r, env), "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD") {
			t.Errorf("%s inherits the password's variable", env)
		}
	}
	if strings.Contains(r.stdout+r.stderr, nestedPw) {
		t.Error("the password was printed")
	}
	// The key is made, once, with no passphrase, as the nested key.
	key := filepath.Join(r.home, ".config/pveforge/harness-nested_ed25519")
	if got := fakeLog(r, "ssh-keygen.argv"); got != "-q\n-t\ned25519\n-N\n\n-C\npveforge-harness-nested\n-f\n"+key+"\n--\n" {
		t.Errorf("ssh-keygen argv %q", got)
	}
	// The container: mounts, values by name, and the steps.
	pod := strings.Split(fakeLog(r, "podman.log"), "\n")
	iso := filepath.Join(tmp, "isos")
	wantArgs := []string{"run", "--rm", "--security-opt", "label=disable", "-v", out + ":/work", "-v", iso + ":/src:ro",
		"-e", "PVE_KEYRING_SHA512=" + strings.Repeat("0", 128), "-e", "SOURCE_ISO_NAME=proxmox-ve_9.2-1.iso", "docker.io/library/debian:trixie", "bash", "-c"}
	if len(pod) < len(wantArgs)+1 || strings.Join(pod[:len(wantArgs)], "\n") != strings.Join(wantArgs, "\n") {
		t.Fatalf("podman argv:\n%s", strings.Join(pod, "\n"))
	}
	script := strings.Join(pod[len(wantArgs):], "\n")
	for _, w := range []string{
		`echo "$PVE_KEYRING_SHA512  $keyring" | sha512sum -c -`,
		"apt-get install -y --no-install-recommends proxmox-auto-install-assistant xorriso",
		`proxmox-auto-install-assistant validate-answer "/work/$n.toml"`,
		`proxmox-auto-install-assistant prepare-iso "/src/$SOURCE_ISO_NAME" --fetch-from iso --answer-file "/work/$n.toml" --output "/work/$n-auto.iso"`,
		`proxmox-auto-install-assistant inspect-iso "/work/$n-auto.iso"`,
		"Components: pve-no-subscription",
	} {
		if !strings.Contains(script, w) {
			t.Errorf("the container script lacks %q", w)
		}
	}
	if strings.Index(script, "sha512sum -c") > strings.Index(script, "proxmox-auto-install-assistant xorriso") {
		t.Error("the keyring is trusted before it is checked")
	}
}

// I2: refused before anything runs: no password, a short or multi-line one,
// arguments, tracing, BASH_ENV; a password the rendered file would hold.
func TestPrepareISO_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		pw       string
		args     []string
		bashArgs []string
		env      map[string]string
		code     int
		want     string
	}{
		"no password":    {"-", nil, nil, nil, 2, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set: run this through 'hack/harness/unlock.sh run --'"},
		"empty":          {"", nil, nil, nil, 2, "is not set"},
		"short":          {"Short-7", nil, nil, nil, 2, "shorter than 8 characters"},
		"two lines":      {"Nested-Test\nPw-7f3a9c", nil, nil, nil, 2, "holds a control character"},
		"arguments":      {nestedPw, []string{"--storage", "x"}, nil, nil, 2, "usage: prepare-iso.sh"},
		"xtrace":         {nestedPw, nil, []string{"-x"}, nil, 2, "xtrace or verbose is on"},
		"verbose":        {nestedPw, nil, []string{"-v"}, nil, 2, "xtrace or verbose is on"},
		"BASH_ENV":       {nestedPw, nil, nil, map[string]string{"BASH_ENV": "/dev/null"}, 2, "BASH_ENV or ENV is set"},
		"in the answers": {"reboot-on-error", nil, nil, nil, 4, "pvh-n1: the rendered answer file holds the plaintext password"},
	} {
		t.Run(name, func(t *testing.T) {
			s := isoWorld(t, tc.pw, nil)
			s.args, s.bashArgs = tc.args, tc.bashArgs
			for k, v := range tc.env {
				s.env[k] = v
			}
			r := runProbe(t, s)
			if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d (want %d), stderr:\n%s\nwant %q", r.code, tc.code, r.stderr, tc.want)
			}
			if tc.pw != "-" && tc.pw != "" && strings.Contains(r.stderr+r.stdout, tc.pw) {
				t.Error("the password was printed")
			}
			if fakeLog(r, "podman.log") != "" {
				t.Error("the container ran")
			}
			if tc.code == 2 && fakeLog(r, "openssl.argv") != "" {
				t.Error("openssl ran")
			}
		})
	}
}

// I3: an existing key is reused, never remade; a loose one is refused.
func TestPrepareISO_ExistingKey(t *testing.T) {
	key := func(mode os.FileMode) func(t *testing.T, home string) {
		return func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519"), "the operator's key\n", mode)
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExisting nested\n", 0o644)
		}
	}
	r := runProbe(t, isoWorld(t, nestedPw, key(0o600)))
	if r.code != 0 || fakeLog(r, "ssh-keygen.argv") != "" {
		t.Fatalf("exit %d, ssh-keygen %q\n%s", r.code, fakeLog(r, "ssh-keygen.argv"), r.stderr)
	}
	b, _ := os.ReadFile(filepath.Join(isoOut(t, r), "pvh-n2.toml"))
	if !strings.Contains(string(b), `root-ssh-keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExisting nested"]`) {
		t.Errorf("the existing key is not root's:\n%s", b)
	}
	if r := runProbe(t, isoWorld(t, nestedPw, key(0o644))); r.code != 4 || !strings.Contains(r.stderr, "harness-nested_ed25519 has mode 644, want 600") {
		t.Errorf("a loose key: exit %d\n%s", r.code, r.stderr)
	}
}

// I4: the container fails: its status, recorded, and nothing printed as
// prepared.
func TestPrepareISO_ContainerFails(t *testing.T) {
	s := isoWorld(t, nestedPw, func(t *testing.T, home string) {
		writeFile(t, filepath.Join(filepath.Dir(home), "fake", "podman.rc"), "7", 0o600)
	})
	r := runProbe(t, s)
	if r.code != 7 || r.stdout != "" || !strings.Contains(r.stderr, "the container exited 7") {
		t.Fatalf("exit %d stdout %q\n%s", r.code, r.stdout, r.stderr)
	}
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/prepare-iso/*/FAILED"))
	if len(dirs) != 1 {
		t.Error("FAILED is not recorded")
	}
}

// I5: what prepare-iso.sh takes from other programs is checked: openssl's
// hash, the key's public half. Its directories are private even when they
// already exist.
func TestPrepareISO_Checks(t *testing.T) {
	for name, tc := range map[string]struct {
		extra func(t *testing.T, home string)
		want  string
	}{
		"not a hash": {func(t *testing.T, home string) {
			writeFile(t, filepath.Join(filepath.Dir(home), "fake", "openssl.out"), "$1$md5$notsha512\n", 0o600)
		}, "openssl passwd did not print one SHA-512 crypt hash"},
		"an rsa key": {func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519"), "k\n", 0o600)
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519.pub"), "ssh-rsa AAAAB3NzaC1yc2E nested\n", 0o644)
		}, "harness-nested_ed25519.pub is not one ssh-ed25519 public key"},
		"a quote in the key": {func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519"), "k\n", 0o600)
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 a\"b\n", 0o644)
		}, "is not one ssh-ed25519 public key"},
	} {
		t.Run(name, func(t *testing.T) {
			r := runProbe(t, isoWorld(t, nestedPw, tc.extra))
			if r.code != 4 || !strings.Contains(r.stderr, tc.want) || fakeLog(r, "podman.log") != "" {
				t.Fatalf("exit %d\n%s", r.code, r.stderr)
			}
		})
	}
	r := runProbe(t, isoWorld(t, nestedPw, func(t *testing.T, home string) {
		for _, d := range []string{"harness-build", "harness-evidence/prepare-iso"} {
			p := filepath.Join(home, ".config/pveforge", d)
			os.MkdirAll(p, 0o700)
			os.Chmod(p, 0o777)
		}
	}))
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	evid, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/prepare-iso/*"))
	for _, p := range append(evid, filepath.Join(r.home, ".config/pveforge/harness-build"), filepath.Join(r.home, ".config/pveforge/harness-evidence/prepare-iso")) {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v %v", p, fi.Mode().Perm(), err)
		}
	}
	if len(evid) != 1 {
		t.Errorf("evidence %q", evid)
	}
}

// B12: a site file that is a symlink is refused, whatever it points at.
func TestBuild_SiteFileSymlink(t *testing.T) {
	h := buildHome{}
	s := buildWorld(t, h)
	s.setup = func(t *testing.T, home string) {
		h.setup(t, home)
		p := filepath.Join(home, ".config/pveforge/harness-build.env")
		real := filepath.Join(filepath.Dir(home), "elsewhere.env")
		if err := os.Rename(p, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, p); err != nil {
			t.Fatal(err)
		}
	}
	if r := runProbe(t, s); r.code != 2 || !strings.Contains(r.stderr, "harness-build.env does not exist") || len(r.calls) != 0 {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
}

// B13: cleanup runs to its end: a Ctrl-C to the process group during it is
// ignored, and a VM is taken as gone only on PVE's "does not exist".
func TestBuild_CleanupRunsToItsEnd(t *testing.T) {
	s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.91_8006": "never"}})
	for v := range buildIPs {
		goneAfter(s, v, 2)
	}
	s.kill = map[string]map[int]string{"post /nodes/qa-pve-02/qemu/692/status/stop": {1: "group:INT"}}
	r := runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, "build: cleanup: this run's VM(s) 690 691 692 destroyed") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), bTornDown)
	s = buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.91_8006": "never"}})
	for v := range buildIPs {
		goneAfter(s, v, 2)
	}
	s.err[bStatus("691")][2] = "get vm 691 status: 500 Internal Server Error: VM 691 exists, but its status could not be read"
	r = runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, "LEFTOVER:") || !strings.Contains(r.stderr, "VM 691 (pvh-n2)") || strings.Contains(r.stderr, "VM 690 (pvh-n1)") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
}

// B14: before anything is created, none of the three addresses is the outer
// host (read from the harness roster, resolved), and none answers yet.
func TestBuild_PreflightAddresses(t *testing.T) {
	for name, tc := range map[string]struct {
		h    buildHome
		want string
	}{
		"in use":               {buildHome{tcp: map[string]string{"192.0.2.92_22": "0"}}, "192.0.2.92:22 already answers, before pvh-nfs exists: the address is in use"},
		"a node's 8006 in use": {buildHome{tcp: map[string]string{"192.0.2.91_8006": "0"}}, "192.0.2.91:8006 already answers, before pvh-n2 exists"},
		"the outer host":       {buildHome{outer: "192.0.2.90"}, "pvh-n1's address 192.0.2.90 is the outer host 192.0.2.90"},
		"the outer host by name": {buildHome{outer: "qa-pve-02.example.invalid", getent: map[string]string{
			"qa-pve-02.example.invalid": "198.51.100.20   STREAM qa-pve-02.example.invalid\n192.0.2.92      STREAM\n"}}, "pvh-nfs's address 192.0.2.92 is the outer host qa-pve-02.example.invalid"},
		"unresolvable": {buildHome{outer: "nowhere.example.invalid"}, "cannot resolve the outer host nowhere.example.invalid"},
		"no host":      {buildHome{outer: "-"}, "names no host for target qa-pve-02-harness"},
	} {
		t.Run(name, func(t *testing.T) {
			r := runProbe(t, buildWorld(t, tc.h))
			if r.code != 3 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 3 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			if w := r.writes(); len(w) != 0 {
				t.Errorf("a refused build sent %q", w)
			}
		})
	}
	// Resolved, and not one of the three: built.
	r := runProbe(t, buildWorld(t, buildHome{outer: "qa-pve-02.example.invalid", getent: map[string]string{
		"qa-pve-02.example.invalid": "198.51.100.20   STREAM qa-pve-02.example.invalid\n"}}))
	if r.code != 0 {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	if got := r.buildEvidence(t, "outer-host"); got != "qa-pve-02.example.invalid: 198.51.100.20\n" {
		t.Errorf("outer-host %q", got)
	}
}

// B15: a second Ctrl-C, TERM or hangup to the whole process group while
// cleanup stops a VM is ignored: cleanup still destroys all three.
func TestBuild_SignalsDuringCleanup(t *testing.T) {
	for _, sig := range []string{"INT", "TERM", "HUP"} {
		t.Run(sig, func(t *testing.T) {
			s := buildWorld(t, buildHome{tcp: map[string]string{"192.0.2.91_8006": "never"}})
			for v := range buildIPs {
				goneAfter(s, v, 2)
			}
			s.kill = map[string]map[int]string{"post /nodes/qa-pve-02/qemu/692/status/stop": {1: "group:" + sig}}
			r := runProbe(t, s)
			if r.code != 4 || !strings.Contains(r.stderr, "build: cleanup: this run's VM(s) 690 691 692 destroyed") {
				t.Fatalf("exit %d\n%s", r.code, r.stderr)
			}
			equalCalls(t, "writes", r.writes(), bTornDown)
		})
	}
}
