package sourceguard

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The harness build's phase B (pveforge-harness-build): cluster.sh, run
// offline against the fake ssh (U2's, extended). Each remote step names its
// own answer key; the tests pin who is reached, how, in what order, and that
// the nested root password travels only on the join's stdin.

const (
	cN1  = "root@192.0.2.90"
	cN2  = "root@192.0.2.91"
	cNFS = "pvh@192.0.2.92"

	n1Fingerprint = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
	n1RootKey     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCn1RootKey root@pvh-n1"
	n2RootKey     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCn2RootKey root@pvh-n2"
	clusterOK     = `[{"type":"cluster","name":"pvh","quorate":1,"nodes":2,"version":3},` +
		`{"type":"node","name":"pvh-n1","online":1,"nodeid":1},{"type":"node","name":"pvh-n2","online":1,"nodeid":2}]`
	pvecmOK   = "Cluster information\n-------------------\nName:             pvh\n\nQuorum information\n------------------\nNodes:            2\nQuorate:          Yes\n\nVotequorum information\n----------------------\nExpected votes:   3\nHighest expected: 3\nTotal votes:      3\nQuorum:           2  \nFlags:            Quorate Qdevice \n"
	exportsOK = "/srv/pvh      \t192.0.2.90(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)\n" +
		"/srv/pvh      \t192.0.2.91(sync,wdelay,hide,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)\n"
)

// clusterSpec: a world in which every step succeeds and the join is seen on
// n1's second look.
type clusterSpec struct {
	resp  map[string]string            // key -> answer, any host
	host  map[string]map[string]string // host -> key -> answer
	rc    map[string]string            // key -> status, any host
	known string                       // the pins ("" = all three)
	pw    string
}

func clusterWorld() clusterSpec {
	return clusterSpec{
		resp: map[string]string{
			"reach": "", "nfs-server": "", "node-packages": "", "cluster-create": "", "cluster-join": "",
			"qdevice-keys": "", "qdevice-known": "", "qdevice-setup": "", "storage": "",
			"cert-info":             `[{"filename":"pve-root-ca.pem","fingerprint":"11:22"},{"filename":"pve-ssl.pem","fingerprint":"` + n1Fingerprint + `"}]`,
			"cluster-status":        strings.Replace(clusterOK, `"online":1,"nodeid":2`, `"online":0,"nodeid":2`, 1),
			"cluster-status.2":      clusterOK,
			"verify-cluster-status": clusterOK,
			"verify-pvecm-status":   pvecmOK,
			"verify-storage-n1":     `{"active":1,"enabled":1,"type":"nfs"}`,
			"verify-storage-n2":     `{"active":1,"enabled":1,"type":"nfs"}`,
			"verify-exports":        exportsOK,
		},
		host: map[string]map[string]string{
			cN1: {"root-key": n1RootKey},
			cN2: {"root-key": n2RootKey},
		},
		rc: map[string]string{},
		pw: nestedPw,
	}
}

func (c clusterSpec) spec(t *testing.T) probeSpec {
	fake, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-ssh.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return probeSpec{
		script: "build/cluster.sh",
		env:    map[string]string{"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD": c.pw},
		// Each ssh round trip costs 10 s on the fake clock.
		stubs: clockStubs(t, map[string]string{
			"ssh": "#!/usr/bin/env bash\nenv >>\"$FAKE_PVEFORGE_DIR/ssh.env\"\nc=0\n[ -f \"$FAKE_PVEFORGE_DIR/clock\" ] && c=$(cat \"$FAKE_PVEFORGE_DIR/clock\")\nprintf '%s' $((c + 10)) >\"$FAKE_PVEFORGE_DIR/clock\"\nFAKE_SSH_DIR=$FAKE_PVEFORGE_DIR/ssh exec bash " + fake + " \"$@\"\n",
		}),
		setup: func(t *testing.T, home string) {
			cfg := filepath.Join(home, ".config/pveforge")
			writeFile(t, filepath.Join(cfg, "harness-build.env"), exampleEnv(t), 0o600)
			writeFile(t, filepath.Join(cfg, "harness-nested_ed25519"), "fake private key\n", 0o600)
			writeFile(t, filepath.Join(cfg, "harness-nested_ed25519.pub"), nestedPub+"\n", 0o644)
			known := c.known
			if known == "" {
				known = hostKey("690") + "\n" + hostKey("691") + "\n" + hostKey("692") + "\n"
			}
			writeFile(t, filepath.Join(cfg, "harness-nested.known_hosts"), known, 0o600)
			ssh := filepath.Join(filepath.Dir(home), "fake", "ssh")
			for _, d := range []string{"calls", "stdin", "host", "resp", "rc"} {
				os.MkdirAll(filepath.Join(ssh, d), 0o700)
			}
			for k, v := range c.resp {
				writeFile(t, filepath.Join(ssh, "resp", k), v, 0o600)
			}
			for k, v := range c.rc {
				writeFile(t, filepath.Join(ssh, "rc", k), v, 0o600)
			}
			for h, m := range c.host {
				for k, v := range m {
					writeFile(t, filepath.Join(ssh, "host", fakeKey(h), "resp", k), v, 0o600)
				}
			}
		},
	}
}

// sshCall is one call the fake ssh saw.
type sshCall struct {
	opts  []string // every argument before the destination
	dest  string
	key   string // the command's "# key:" name
	cmd   string
	stdin string
}

func sshCalls(t *testing.T, r probeResult) []sshCall {
	t.Helper()
	dir := filepath.Join(filepath.Dir(r.home), "fake", "ssh")
	names, _ := filepath.Glob(filepath.Join(dir, "calls", "*"))
	sort.Strings(names)
	var calls []sshCall
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
		if len(args) < 2 {
			t.Fatalf("call %s: %q", n, args)
		}
		c := sshCall{opts: args[:len(args)-2], dest: args[len(args)-2], cmd: args[len(args)-1]}
		first, _, _ := strings.Cut(c.cmd, "\n")
		c.key = strings.TrimPrefix(first, "# key: ")
		in, _ := os.ReadFile(filepath.Join(dir, "stdin", filepath.Base(n)))
		c.stdin = string(in)
		calls = append(calls, c)
	}
	return calls
}

func (r probeResult) clusterEvidence(t *testing.T, name string) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/cluster/*"))
	if len(dirs) != 1 {
		t.Fatalf("cluster evidence directories = %q, want exactly one", dirs)
	}
	b, err := os.ReadFile(filepath.Join(dirs[0], name))
	if err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	return string(b)
}

// clusterSteps is the full run: who is reached, for which step, in order.
var clusterSteps = []string{
	cN1 + " reach", cN2 + " reach", cNFS + " reach",
	cNFS + " nfs-server",
	cN1 + " node-packages", cN2 + " node-packages",
	cN1 + " cluster-create", cN1 + " cert-info", cN2 + " cluster-join",
	cN1 + " cluster-status", cN1 + " cluster-status",
	cN1 + " root-key", cN2 + " root-key",
	cNFS + " qdevice-keys", cN1 + " qdevice-known", cN2 + " qdevice-known", cN1 + " qdevice-setup",
	cN1 + " storage",
	cN1 + " verify-cluster-status", cN1 + " verify-pvecm-status", cN1 + " verify-storage-n1", cN1 + " verify-storage-n2", cNFS + " verify-exports",
}

// remoteScript is the script a call runs: bash's own reading of the command's
// last word, as the remote login shell reads it.
func remoteScript(t *testing.T, c sshCall) string {
	t.Helper()
	body := strings.TrimPrefix(c.cmd, "# key: "+c.key+"\n")
	out, err := exec.Command("bash", "-c", `eval "a=( $1 )"; printf '%s' "${a[-1]}"`, "decode", body).Output()
	if err != nil {
		t.Fatalf("%s %s: cannot decode %q: %v", c.dest, c.key, body, err)
	}
	return string(out)
}

func steps(calls []sshCall) []string {
	var s []string
	for _, c := range calls {
		s = append(s, c.dest+" "+c.key)
	}
	return s
}

// C1: the cluster is formed: every call pinned, the password on the join's
// stdin only, and every check green.
func TestCluster_Full(t *testing.T) {
	s := clusterWorld().spec(t)
	// What the operator's terminal holds must reach no host.
	s.stdin = "operator-typed\n"
	prev := s.setup
	s.setup = func(t *testing.T, home string) {
		prev(t, home)
		p := filepath.Join(home, ".config/pveforge/harness-evidence/cluster")
		os.MkdirAll(p, 0o700)
		os.Chmod(p, 0o777)
	}
	r := runProbe(t, s)
	if r.code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	calls := sshCalls(t, r)
	equalCalls(t, "steps", steps(calls), clusterSteps)
	cfg := filepath.Join(r.home, ".config/pveforge")
	wantOpts := strings.Join([]string{"-F", "/dev/null", "-i", filepath.Join(cfg, "harness-nested_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + filepath.Join(cfg, "harness-nested.known_hosts"), "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=15"}, " ")
	var join sshCall
	for _, c := range calls {
		if got := strings.Join(c.opts, " "); got != wantOpts {
			t.Errorf("%s %s: options %q", c.dest, c.key, got)
		}
		body := strings.TrimPrefix(c.cmd, "# key: "+c.key+"\n")
		wantPre := "bash -euo pipefail -c "
		if c.dest == cNFS {
			wantPre = "sudo -n " + wantPre
		}
		if !strings.HasPrefix(body, wantPre) {
			t.Errorf("%s %s: runs %q", c.dest, c.key, body)
		}
		if c.key == "cluster-join" {
			join = c
		} else if c.stdin != "" {
			t.Errorf("%s %s: stdin %q", c.dest, c.key, c.stdin)
		}
	}
	if join.stdin != nestedPw+"\n" {
		t.Errorf("the join's stdin %q", join.stdin)
	}
	for _, w := range []string{"--hostname 192.0.2.90 --fingerprint " + n1Fingerprint + ` --password "$pw" --link0 192.0.2.91`, "IFS= read -r pw", "pvesh create /cluster/config/join"} {
		if !strings.Contains(remoteScript(t, join), w) {
			t.Errorf("the join lacks %q:\n%s", w, join.cmd)
		}
	}
	// The password: nowhere but the join's stdin.
	tmp := filepath.Dir(r.home)
	filepath.WalkDir(tmp, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasPrefix(p, filepath.Join(tmp, "fake", "ssh", "stdin")+"/") {
			return nil
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), nestedPw) {
			t.Errorf("%s holds the password", p)
		}
		return nil
	})
	if strings.Contains(r.stdout+r.stderr, nestedPw) {
		t.Error("the password was printed")
	}
	byKey := map[string]string{}
	for _, c := range calls {
		byKey[c.dest+" "+c.key] = remoteScript(t, c)
	}
	for step, wants := range map[string][]string{
		cNFS + " nfs-server": {"apt-get install -y --no-install-recommends nfs-kernel-server corosync-qnetd", "dev=/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1",
			`if [ "$rc" = 2 ]; then`, "mkfs.ext4 -q -L pvh-export", "/srv/pvh 192.0.2.90(rw,sync,no_subtree_check,no_root_squash) 192.0.2.91(rw,sync,no_subtree_check,no_root_squash)", "exportfs -ra"},
		cN1 + " node-packages":  {"Components: pve-no-subscription", "apt-get install -y corosync-qdevice", "pve-enterprise.sources"},
		cN1 + " cluster-create": {"pvecm create pvh --link0 192.0.2.90", "cluster_name:"},
		cNFS + " qdevice-keys":  {n1RootKey, n2RootKey, "/root/.ssh/authorized_keys"},
		cN2 + " qdevice-known":  {hostKey("692"), "/root/.ssh/known_hosts"},
		cN1 + " qdevice-setup":  {"pvecm qdevice setup 192.0.2.92", "if pvecm status | grep -q '^Flags:.*Qdevice'; then"},
		cN1 + " storage":        {"if pvesm status --storage pvh-shared >/dev/null 2>&1; then", "pvesm add nfs pvh-shared --server 192.0.2.92 --export /srv/pvh --content images,iso --options vers=4.2"},
	} {
		for _, w := range wants {
			if !strings.Contains(byKey[step], w) {
				t.Errorf("%s lacks %q:\n%s", step, w, byKey[step])
			}
		}
	}
	if r.sleeps != 1 {
		t.Errorf("slept %d times, want 1 (the join is seen on the second look)", r.sleeps)
	}
	res := r.clusterEvidence(t, "result.txt")
	if strings.Contains(res, "RED") || strings.Count(res, "PASS ") != 27 || !strings.Contains(res, "RESULT phase=cluster fail=0") {
		t.Errorf("result.txt:\n%s", res)
	}
	r.clusterEvidence(t, "MANIFEST.sha256")
	r.clusterEvidence(t, "verify-pvecm-status.out")
	if fi, err := os.Stat(filepath.Join(cfg, "harness-evidence/cluster")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("evidence parent mode %v %v", fi.Mode().Perm(), err)
	}
	if env := fakeLog(r, "ssh.env"); env == "" || strings.Contains(env, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD") {
		t.Errorf("ssh's environment (%d bytes) names the password's variable", len(env))
	}
}

// C2: refused before anything is sent.
func TestCluster_Refusals(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(c *clusterSpec, s *probeSpec)
		want string
	}{
		"no password": {func(c *clusterSpec, s *probeSpec) { s.env["PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"] = "-" }, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set"},
		"arguments":   {func(c *clusterSpec, s *probeSpec) { s.args = []string{"--force"} }, "usage: cluster.sh"},
		"two lines": {func(c *clusterSpec, s *probeSpec) {
			s.env["PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"] = "Nested-Test\nPw-7f3a9c"
		}, "the nested root password holds a control character"},
		"xtrace":   {func(c *clusterSpec, s *probeSpec) { s.bashArgs = []string{"-x"} }, "xtrace or verbose is on"},
		"BASH_ENV": {func(c *clusterSpec, s *probeSpec) { s.env["BASH_ENV"] = "/dev/null" }, "BASH_ENV or ENV is set"},
		"no nfs pin": {func(c *clusterSpec, s *probeSpec) { c.known = hostKey("690") + "\n" + hostKey("691") + "\n" },
			"pins no ed25519 host key for 192.0.2.92: run build.sh first"},
		"an rsa pin": {func(c *clusterSpec, s *probeSpec) {
			c.known = hostKey("690") + "\n192.0.2.91 ssh-rsa AAAAB3NzaC1yc2E\n" + hostKey("692") + "\n"
		}, "pins no ed25519 host key for 192.0.2.91"},
		"a loose key": {func(c *clusterSpec, s *probeSpec) {
			prev := s.setup
			s.setup = func(t *testing.T, home string) {
				prev(t, home)
				os.Chmod(filepath.Join(home, ".config/pveforge/harness-nested_ed25519"), 0o644)
			}
		}, "harness-nested_ed25519 has mode 644, want 600"},
		"loose pins": {func(c *clusterSpec, s *probeSpec) {
			prev := s.setup
			s.setup = func(t *testing.T, home string) {
				prev(t, home)
				os.Chmod(filepath.Join(home, ".config/pveforge/harness-nested.known_hosts"), 0o644)
			}
		}, "harness-nested.known_hosts has mode 644, want 600"},
		"the lock held": {func(c *clusterSpec, s *probeSpec) {
			prev := s.setup
			s.setup = func(t *testing.T, home string) {
				prev(t, home)
				holdHarnessLock(t, filepath.Join(home, ".config/pveforge/harness.lock"))
			}
		}, "another harness script holds"},
	} {
		t.Run(name, func(t *testing.T) {
			c := clusterWorld()
			s := c.spec(t)
			tc.edit(&c, &s)
			if c.known != "" {
				prev := s.setup
				known := c.known
				s.setup = func(t *testing.T, home string) {
					prev(t, home)
					writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.known_hosts"), known, 0o600)
				}
			}
			r := runProbe(t, s)
			if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			if calls := sshCalls(t, r); len(calls) != 0 {
				t.Errorf("a refused run reached %q", steps(calls))
			}
			if strings.Contains(r.stderr+r.stdout, nestedPw) {
				t.Error("the password was printed")
			}
		})
	}
}

// C3: a red step ends the run there, recorded; nothing after it is sent.
func TestCluster_RedStepStops(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(c *clusterSpec)
		last string // the last step sent
		want string // in result.txt
	}{
		"nfs-server fails": {func(c *clusterSpec) { c.rc["nfs-server"] = "1" }, cNFS + " nfs-server", "RED step nfs-server (nfs): see nfs-server.out"},
		"a bad fingerprint": {func(c *clusterSpec) { c.resp["cert-info"] = `[{"filename":"pve-ssl.pem","fingerprint":"ab:cd"}]` }, cN1 + " cert-info",
			"RED n1's pve-ssl.pem fingerprint is not one SHA-256 fingerprint"},
		"the join fails":  {func(c *clusterSpec) { c.rc["cluster-join"] = "255" }, cN2 + " cluster-join", "RED step cluster-join (n2): see cluster-join.out"},
		"a bad root key":  {func(c *clusterSpec) { c.host[cN2]["root-key"] = "ssh-rsa AAAA root@pvh-n2\ncommand=\"x\" ssh-rsa BBBB" }, cN2 + " root-key", "RED n2's root key is not one ssh-rsa public key"},
		"qdevice fails":   {func(c *clusterSpec) { c.rc["qdevice-setup"] = "2" }, cN1 + " qdevice-setup", "RED step qdevice-setup (n1)"},
		"storage refused": {func(c *clusterSpec) { c.rc["storage"] = "1" }, cN1 + " storage", "RED step storage (n1)"},
	} {
		t.Run(name, func(t *testing.T) {
			c := clusterWorld()
			tc.edit(&c)
			r := runProbe(t, c.spec(t))
			if r.code != 1 {
				t.Fatalf("exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
			}
			got := steps(sshCalls(t, r))
			if len(got) == 0 || got[len(got)-1] != tc.last {
				t.Errorf("the last step %q, want %q; all: %q", got[len(got)-1], tc.last, got)
			}
			res := r.clusterEvidence(t, "result.txt")
			if !strings.Contains(res, tc.want) || !strings.Contains(res, "RESULT phase=cluster fail=1") {
				t.Errorf("result.txt:\n%s", res)
			}
			r.clusterEvidence(t, "MANIFEST.sha256")
		})
	}
}

// C4: the join is awaited, bounded by the clock: 300 s. Each look is a
// 10 s round trip on the fake clock plus a 5 s sleep, so 20 sleeps, never
// the 60 a count of 300/5 would give.
func TestCluster_JoinWaitBounded(t *testing.T) {
	c := clusterWorld()
	delete(c.resp, "cluster-status.2")
	r := runProbe(t, c.spec(t))
	if r.code != 1 || r.sleeps != 20 || !strings.Contains(r.clusterEvidence(t, "result.txt"), "RED after 300s, n1 does not see two nodes online") {
		t.Fatalf("exit %d sleeps %d\n%s", r.code, r.sleeps, r.stdout)
	}
	if got := steps(sshCalls(t, r)); got[len(got)-1] != cN1+" cluster-status" || len(got) != 9+21 {
		t.Errorf("steps %d, last %q", len(got), got[len(got)-1])
	}
}

// C5: the checks all run, each red one named, and the run is red.
func TestCluster_VerifyReds(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(c *clusterSpec)
		reds []string
	}{
		"no qdevice": {func(c *clusterSpec) {
			c.resp["verify-pvecm-status"] = strings.Replace(strings.Replace(pvecmOK, "Total votes:      3", "Total votes:      2", 1), "Quorate Qdevice", "Quorate", 1)
		}, []string{"RED qdevice: quorate, 3 votes, Qdevice flag"}},
		"two votes": {func(c *clusterSpec) {
			c.resp["verify-pvecm-status"] = strings.Replace(pvecmOK, "Total votes:      3", "Total votes:      2", 1)
		}, []string{"RED qdevice: quorate, 3 votes, Qdevice flag"}},
		"not quorate by pvecm": {func(c *clusterSpec) {
			c.resp["verify-pvecm-status"] = strings.Replace(pvecmOK, "Quorate:          Yes", "Quorate:          No", 1)
		}, []string{"RED qdevice: quorate, 3 votes, Qdevice flag"}},
		"a Qdevice-like flag": {func(c *clusterSpec) {
			c.resp["verify-pvecm-status"] = strings.Replace(pvecmOK, "Quorate Qdevice", "Quorate QdeviceAlive", 1)
		}, []string{"RED qdevice: quorate, 3 votes, Qdevice flag"}},
		"n2 offline": {func(c *clusterSpec) {
			c.resp["verify-cluster-status"] = strings.Replace(clusterOK, `"online":1,"nodeid":2`, `"online":0,"nodeid":2`, 1)
		}, []string{"RED pvh-n1 and pvh-n2 online"}},
		"another cluster": {func(c *clusterSpec) {
			c.resp["verify-cluster-status"] = strings.Replace(clusterOK, `"name":"pvh"`, `"name":"prod"`, 1)
		}, []string{"RED cluster pvh, quorate, 2 nodes"}},
		"not quorate": {func(c *clusterSpec) {
			c.resp["verify-cluster-status"] = strings.Replace(clusterOK, `"quorate":1`, `"quorate":0`, 1)
		}, []string{"RED cluster pvh, quorate, 2 nodes"}},
		"storage inactive on n2": {func(c *clusterSpec) { c.resp["verify-storage-n2"] = `{"active":0}` }, []string{"RED pvh-shared active on pvh-n2"}},
		"exported to the world": {func(c *clusterSpec) {
			c.resp["verify-exports"] = exportsOK + "/srv/pvh      \t*(sync,rw)\n"
		}, []string{"RED /srv/pvh exported to n1 and n2 only"}},
		"exported to n1 only": {func(c *clusterSpec) {
			c.resp["verify-exports"] = strings.SplitAfter(exportsOK, "\n")[0]
		}, []string{"RED /srv/pvh exported to n1 and n2 only"}},
		"a fetch fails": {func(c *clusterSpec) { c.rc["verify-storage-n1"] = "1" }, []string{"RED fetch storage-n1", "RED pvh-shared active on pvh-n1"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := clusterWorld()
			tc.edit(&c)
			r := runProbe(t, c.spec(t))
			res := r.clusterEvidence(t, "result.txt")
			if r.code != 1 || !strings.Contains(res, "RESULT phase=cluster fail=1") {
				t.Fatalf("exit %d\n%s", r.code, res)
			}
			for _, w := range tc.reds {
				if !strings.Contains(res, w) {
					t.Errorf("result.txt lacks %q:\n%s", w, res)
				}
			}
			if n := strings.Count(res, "RED "); n != len(tc.reds) {
				t.Errorf("%d reds, want %d:\n%s", n, len(tc.reds), res)
			}
			// Every check ran: 5 fetches and 6 checks after the 16 steps.
			if n := strings.Count(res, "PASS ") + strings.Count(res, "RED "); n != 27 {
				t.Errorf("%d results, want 27:\n%s", n, res)
			}
		})
	}
}

// PW1 (both scripts that hold the nested root password): code the
// environment slips in, a function inherited as BASH_FUNC_<name>%% or a
// BASH_ENV file that disables a builtin or defines a function and then
// unsets itself, is refused before the password is read, as lib.sh refuses
// it.
func TestPasswordScripts_RefuseInheritedCode(t *testing.T) {
	// The reviewer's spy: printf, the builtin that handles the password.
	spy := `() {  builtin echo "$@" >>captured; builtin printf "$@"; }`
	for _, script := range []string{"prepare-iso", "cluster"} {
		for name, tc := range map[string]struct {
			env     map[string]string
			bashEnv string
			want    string
		}{
			"an inherited printf": {env: map[string]string{"BASH_FUNC_printf%%": spy}, want: "shell functions already defined (inherited from the environment)"},
			"a disabled builtin":  {bashEnv: "enable -n printf\nunset BASH_ENV\n", want: "shell builtins are disabled: enable -n printf"},
			"a BASH_ENV function": {bashEnv: "cat() { builtin echo \"$@\" >>captured; }\nunset BASH_ENV\n", want: "shell functions already defined"},
		} {
			t.Run(script+"/"+name, func(t *testing.T) {
				var s probeSpec
				if script == "cluster" {
					s = clusterWorld().spec(t)
				} else {
					s = isoWorld(t, nestedPw, nil)
				}
				for k, v := range tc.env {
					s.env[k] = v
				}
				if tc.bashEnv != "" {
					prev := s.setup
					body := tc.bashEnv
					s.setup = func(t *testing.T, home string) {
						prev(t, home)
						writeFile(t, filepath.Join(filepath.Dir(home), "work", "benv.sh"), body, 0o600)
					}
					s.env["BASH_ENV"] = "benv.sh"
				}
				r := runProbe(t, s)
				if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
					t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, tc.want, r.stderr)
				}
				if b, err := os.ReadFile(filepath.Join(filepath.Dir(r.home), "work", "captured")); err == nil {
					t.Errorf("the spy ran: %q", b)
				}
				if strings.Contains(r.stdout+r.stderr, nestedPw) {
					t.Error("the password was printed")
				}
				if len(r.calls) != 0 || fakeLog(r, "openssl.argv") != "" || len(sshCalls(t, r)) != 0 {
					t.Error("a refused run ran something")
				}
			})
		}
	}
}
