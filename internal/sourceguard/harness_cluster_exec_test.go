package sourceguard

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cluster.sh's remote scripts, EXECUTED: each is taken from a real run (as
// the remote shell reads it) and run under bash in a sandbox whose PATH holds
// only safe real tools and logging stubs for the system ones (blkid,
// mkfs.ext4, mount, pvecm, ...), so a guard is proved by what the script
// does, not by the text it contains. Absolute paths are rewritten into the
// sandbox; each rewrite must match, so a changed line cannot slip through.

// remoteStubs: each logs its argv to $R/calls.log, one line per call, and
// answers from $R/stub/.
var remoteStubs = map[string]string{
	// blkid -p DEV: status stub/blkid.rc (default 2: no signature).
	// blkid -o value -s TYPE|LABEL DEV: stub/TYPE, stub/LABEL (none: status 2).
	"blkid": `if [ "$1" = -p ]; then exit "$(cat "$R/stub/blkid.rc" 2>/dev/null || echo 2)"; fi
if [ "$1" = -o ] && [ -f "$R/stub/$4" ]; then cat "$R/stub/$4"; exit 0; fi
exit 2`,
	// mkfs.ext4 -q -L LABEL DEV: the device now holds that ext4.
	"mkfs.ext4":  `printf ext4 >"$R/stub/TYPE"; printf '%s' "$3" >"$R/stub/LABEL"; printf 0 >"$R/stub/blkid.rc"`,
	"mountpoint": `[ -f "$R/stub/mounted" ]`,
	"mount":      `: >"$R/stub/mounted"`,
	"exportfs":   `:`,
	"systemctl":  `:`,
	"apt-get":    `:`,
	// pvecm status: stub/pvecm-status; anything else: logged only.
	"pvecm": `if [ "$1" = status ]; then cat "$R/stub/pvecm-status" 2>/dev/null; exit 0; fi`,
	"pvesh": `:`,
	// sleep: a no-op, so the join retry loop's node-side backoff does not actually
	// delay the exec tests (the sandbox PATH otherwise has no sleep).
	"sleep": `:`,
	// pvesm status --storage X: status stub/pvesm.rc (default 1: no such storage).
	"pvesm": `if [ "$1" = status ]; then exit "$(cat "$R/stub/pvesm.rc" 2>/dev/null || echo 1)"; fi`,
}

type remoteRun struct {
	root  string
	code  int
	calls []string
	out   string
}

// newRemoteRoot makes a sandbox: $R, its stubs, and a bin of safe tools.
func newRemoteRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	for _, d := range []string{bin, filepath.Join(root, "stub")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"bash", "cat", "grep", "mkdir", "awk", "mv", "touch", "chmod", "install", "rm", "sort", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range remoteStubs {
		script := "#!" + filepath.Join(bin, "bash") + "\nprintf '%s\\n' \"" + name + " $*\" >>\"$R/calls.log\"\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// runRemote runs script in root's sandbox after rewriting each old path to
// new ("$R" is the sandbox); every rewrite must match at least once.
func runRemote(t *testing.T, root, script string, rewrites [][2]string, stdin string) remoteRun {
	t.Helper()
	for _, rw := range rewrites {
		if !strings.Contains(script, rw[0]) {
			t.Fatalf("the script no longer holds %q:\n%s", rw[0], script)
		}
		script = strings.ReplaceAll(script, rw[0], strings.ReplaceAll(rw[1], "$R", root))
	}
	os.Remove(filepath.Join(root, "calls.log"))
	cmd := exec.Command(filepath.Join(root, "bin", "bash"), "-euo", "pipefail", "-c", script)
	cmd.Env = []string{"PATH=" + filepath.Join(root, "bin"), "HOME=" + root, "R=" + root, "LC_ALL=C"}
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	r := remoteRun{root: root, out: out.String()}
	err := cmd.Run()
	r.out = out.String()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "calls.log")); err == nil {
		r.calls = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	}
	return r
}

func (r remoteRun) called(prefix string) int {
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func stubFile(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "stub", name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// clusterScripts runs cluster.sh once in the green world and returns each
// step's script, by "<dest> <key>".
func clusterScripts(t *testing.T) map[string]string {
	t.Helper()
	r := runProbe(t, clusterWorld().spec(t))
	if r.code != 0 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	m := map[string]string{}
	for _, c := range sshCalls(t, r) {
		m[c.dest+" "+c.key] = remoteScript(t, c)
	}
	return m
}

const scsi1 = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi1"

// X1: the data disk is formatted only when blkid finds it blank; the
// pvh-export filesystem already there is kept (a rerun); anything else on
// it, a filesystem or a partition table, or a blkid failure, is refused and
// never formatted.
func TestCluster_NFSServerScriptExecuted(t *testing.T) {
	script := clusterScripts(t)[cNFS+" nfs-server"]
	rw := [][2]string{
		{`[ -b "$dev" ]`, `[ -f "$dev" ]`}, // a test cannot count on a block device
		{scsi1, "$R/scsi1"},
		{"/etc/fstab", "$R/fstab"},
		{"/etc/exports.d", "$R/exports.d"},
		{"/srv/pvh", "$R/srv/pvh"},
	}
	for name, tc := range map[string]struct {
		rc, typ, label string // blkid -p's status, and what the disk holds
		noDisk         bool
		code           int
		mkfs           int
	}{
		"blank":                 {rc: "2", mkfs: 1},
		"our own filesystem":    {rc: "0", typ: "ext4", label: "pvh-export"},
		"a foreign filesystem":  {rc: "0", typ: "xfs", label: "pvh-export", code: 1},
		"ext4 of another name":  {rc: "0", typ: "ext4", label: "data", code: 1},
		"a GPT partition table": {rc: "0", code: 1},
		"a blkid failure":       {rc: "8", code: 1},
		"no data disk":          {rc: "2", noDisk: true, code: 1},
	} {
		t.Run(name, func(t *testing.T) {
			root := newRemoteRoot(t)
			if !tc.noDisk {
				stubFile(t, root, "../scsi1", "")
			}
			stubFile(t, root, "blkid.rc", tc.rc)
			if tc.typ != "" {
				stubFile(t, root, "TYPE", tc.typ)
				stubFile(t, root, "LABEL", tc.label)
			}
			os.WriteFile(filepath.Join(root, "fstab"), []byte("# fstab\n"), 0o600)
			r := runRemote(t, root, script, rw, "")
			if r.code != tc.code || r.called("mkfs.ext4") != tc.mkfs {
				t.Fatalf("exit %d (want %d), mkfs %d (want %d)\n%s\ncalls: %q", r.code, tc.code, r.called("mkfs.ext4"), tc.mkfs, r.out, r.calls)
			}
			if tc.mkfs == 1 && r.called("mkfs.ext4 -q -L pvh-export "+filepath.Join(root, "scsi1")) != 1 {
				t.Errorf("mkfs calls %q", r.calls)
			}
			if tc.code != 0 {
				if r.called("mount ") != 0 || r.called("exportfs") != 0 {
					t.Errorf("a refused disk was mounted or exported: %q", r.calls)
				}
				return
			}
			exports, _ := os.ReadFile(filepath.Join(root, "exports.d", "pvh.exports"))
			if string(exports) != root+"/srv/pvh 192.0.2.90(rw,sync,no_subtree_check,no_root_squash) 192.0.2.91(rw,sync,no_subtree_check,no_root_squash)\n" {
				t.Errorf("exports %q", exports)
			}
			// A rerun keeps the filesystem and adds nothing twice.
			r = runRemote(t, root, script, rw, "")
			fstab, _ := os.ReadFile(filepath.Join(root, "fstab"))
			if r.code != 0 || r.called("mkfs.ext4") != 0 || strings.Count(string(fstab), "LABEL=pvh-export ") != 1 || r.called("mount ") != 0 {
				t.Errorf("rerun: exit %d, calls %q, fstab %q\n%s", r.code, r.calls, fstab, r.out)
			}
		})
	}
}

// X2: n1 creates pvh and n2 joins only when in no cluster; one already in
// pvh is left as it is; one in any other cluster is refused.
func TestCluster_CreateAndJoinScriptsExecuted(t *testing.T) {
	scripts := clusterScripts(t)
	rw := [][2]string{{"/etc/pve/corosync.conf", "$R/corosync.conf"}}
	for _, step := range []struct {
		key, stdin, call string
	}{
		{cN1 + " cluster-create", "", "pvecm create pvh --link0 192.0.2.90"},
		{cN2 + " cluster-join", nestedPw + "\n", "pvesh create /cluster/config/join --hostname 192.0.2.90 --fingerprint " + n1Fingerprint + " --password " + nestedPw + " --link0 192.0.2.91"},
	} {
		for name, tc := range map[string]struct {
			conf string // "" = in no cluster
			code int
			made int
		}{
			"in no cluster":      {made: 1},
			"in pvh already":     {conf: "totem {\n  cluster_name: pvh\n}\n"},
			"in another cluster": {conf: "totem {\n  cluster_name: prod\n}\n", code: 1},
			"a pvh-like name":    {conf: "totem {\n  cluster_name: pvh2\n}\n", code: 1},
		} {
			t.Run(step.key+"/"+name, func(t *testing.T) {
				root := newRemoteRoot(t)
				if tc.conf != "" {
					os.WriteFile(filepath.Join(root, "corosync.conf"), []byte(tc.conf), 0o600)
				}
				r := runRemote(t, root, scripts[step.key], rw, step.stdin)
				if r.code != tc.code || r.called(step.call) != tc.made || len(r.calls) != tc.made {
					t.Errorf("exit %d (want %d), calls %q\n%s", r.code, tc.code, r.calls, r.out)
				}
			})
		}
	}
}

// X3: the nodes' apt sources: the enterprise and ceph repositories are set
// aside, pve-no-subscription added, then corosync-qdevice installed; a rerun
// changes nothing more.
func TestCluster_NodePackagesScriptExecuted(t *testing.T) {
	script := clusterScripts(t)[cN1+" node-packages"]
	root := newRemoteRoot(t)
	src := filepath.Join(root, "sources")
	os.MkdirAll(src, 0o700)
	for _, f := range []string{"pve-enterprise.sources", "ceph.sources", "debian.sources"} {
		os.WriteFile(filepath.Join(src, f), []byte(f+"\n"), 0o600)
	}
	rw := [][2]string{{"/etc/apt/sources.list.d", "$R/sources"}}
	for run := 1; run <= 2; run++ {
		r := runRemote(t, root, script, rw, "")
		if r.code != 0 || strings.Join(r.calls, "\n") != "apt-get update\napt-get install -y corosync-qdevice" {
			t.Fatalf("run %d: exit %d, calls %q\n%s", run, r.code, r.calls, r.out)
		}
		var names []string
		entries, _ := os.ReadDir(src)
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if strings.Join(names, " ") != "ceph.sources.disabled debian.sources pve-enterprise.sources.disabled pve-no-subscription.sources" {
			t.Errorf("run %d: sources %q", run, names)
		}
	}
	b, _ := os.ReadFile(filepath.Join(src, "pve-no-subscription.sources"))
	if string(b) != "Types: deb\nURIs: http://download.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-no-subscription\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n" {
		t.Errorf("pve-no-subscription.sources %q", b)
	}
}

// X4: the qdevice's preparation and setup, and the storage, each done once:
// a rerun adds no key or pin twice, and a qdevice or storage already there
// is not set up again.
func TestCluster_QdeviceAndStorageScriptsExecuted(t *testing.T) {
	scripts := clusterScripts(t)
	rw := [][2]string{{"/root/.ssh", "$R/rootssh"}}
	root := newRemoteRoot(t)
	for run := 1; run <= 2; run++ {
		if r := runRemote(t, root, scripts[cNFS+" qdevice-keys"], rw, ""); r.code != 0 {
			t.Fatalf("qdevice-keys: exit %d\n%s", r.code, r.out)
		}
		if r := runRemote(t, root, scripts[cN1+" qdevice-known"], rw, ""); r.code != 0 {
			t.Fatalf("qdevice-known: exit %d\n%s", r.code, r.out)
		}
	}
	keys, _ := os.ReadFile(filepath.Join(root, "rootssh", "authorized_keys"))
	known, _ := os.ReadFile(filepath.Join(root, "rootssh", "known_hosts"))
	if string(keys) != n1RootKey+"\n"+n2RootKey+"\n" || string(known) != hostKey("692")+"\n" {
		t.Errorf("authorized_keys %q, known_hosts %q", keys, known)
	}
	for f, mode := range map[string]os.FileMode{"rootssh": 0o700, "rootssh/authorized_keys": 0o600} {
		if fi, err := os.Stat(filepath.Join(root, f)); err != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s mode %v %v", f, fi.Mode().Perm(), err)
		}
	}

	for name, tc := range map[string]struct {
		status string
		setup  int
	}{
		"no qdevice":            {"Flags:            Quorate \n", 1},
		"the qdevice is there":  {"Flags:            Quorate Qdevice \n", 0},
		"a qdevice-like header": {"Qdevice: pending\nFlags:            Quorate \n", 1},
	} {
		t.Run(name, func(t *testing.T) {
			root := newRemoteRoot(t)
			stubFile(t, root, "pvecm-status", tc.status)
			r := runRemote(t, root, scripts[cN1+" qdevice-setup"], nil, "")
			if r.code != 0 || r.called("pvecm qdevice setup 192.0.2.92") != tc.setup {
				t.Errorf("exit %d calls %q\n%s", r.code, r.calls, r.out)
			}
		})
	}
	for name, tc := range map[string]struct {
		rc  string
		add int
	}{"no storage yet": {"1", 1}, "pvh-shared exists": {"0", 0}} {
		t.Run(name, func(t *testing.T) {
			root := newRemoteRoot(t)
			stubFile(t, root, "pvesm.rc", tc.rc)
			r := runRemote(t, root, scripts[cN1+" storage"], nil, "")
			if r.code != 0 || r.called("pvesm add nfs pvh-shared --server 192.0.2.92 --export /srv/pvh --content images,iso --options vers=4.2") != tc.add {
				t.Errorf("exit %d calls %q\n%s", r.code, r.calls, r.out)
			}
		})
	}
}

// X5: the quorum-ready probe (cluster-ready), EXECUTED under stubbed pvecm/pvesh.
// The fake-ssh byte-pin never runs remote scripts, so this is what pins the
// probe's BEHAVIOR: green only when corosync is Quorate AND the API GET
// succeeds. Dropping the "&& pvesh" half or weakening the Quorate grep is caught
// here (see the mutation obligations).
func TestCluster_ReadyProbeScriptExecuted(t *testing.T) {
	script := clusterScripts(t)[cN1+" cluster-ready"]
	if script == "" {
		t.Fatal("no cluster-ready script captured")
	}
	t.Run("quorate and api ok -> exit 0", func(t *testing.T) {
		root := newRemoteRoot(t)
		stubFile(t, root, "pvecm-status", pvecmOK)
		if r := runRemote(t, root, script, nil, ""); r.code != 0 {
			t.Errorf("exit %d, want 0\n%s", r.code, r.out)
		}
	})
	t.Run("not quorate -> nonzero", func(t *testing.T) {
		root := newRemoteRoot(t)
		stubFile(t, root, "pvecm-status", strings.Replace(pvecmOK, "Yes\n\nVotequorum", "No\n\nVotequorum", 1))
		if r := runRemote(t, root, script, nil, ""); r.code == 0 {
			t.Errorf("exit 0 on Quorate: No, want nonzero\n%s", r.out)
		}
	})
	t.Run("pvesh fails -> nonzero", func(t *testing.T) {
		root := newRemoteRoot(t)
		stubFile(t, root, "pvecm-status", pvecmOK)
		// Override the pvesh stub to fail: the API-GET half must gate.
		if err := os.WriteFile(filepath.Join(root, "bin", "pvesh"), []byte("#!"+filepath.Join(root, "bin", "bash")+"\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if r := runRemote(t, root, script, nil, ""); r.code == 0 {
			t.Errorf("exit 0 on pvesh failure, want nonzero\n%s", r.out)
		}
	})
}

// X6: the join RETRY loop, EXECUTED. The fake-ssh byte-pin returns resp verbatim
// and never runs the loop, so this pins the loop's behavior: retry ONLY on a clean
// abort, bounded, no retry once n2 began local setup, and tolerate a non-zero pvesh
// (|| true). in_pvh is neutralized via the X2 rewrite with no file, so the loop is
// reached. The pvesh stub counts calls (one pw line per call in pvesh.pw) and
// records the --password it saw; `sleep` is the no-op remoteStubs entry.
const pveshRetryStub = `c=$(cat "$R/pvesh.n" 2>/dev/null || echo 0); c=$((c + 1)); printf '%s' "$c" >"$R/pvesh.n"
p=""; a=("$@"); i=0; while [ "$i" -lt "${#a[@]}" ]; do [ "${a[$i]}" = --password ] && p="${a[$((i + 1))]}"; i=$((i + 1)); done
printf '%s\n' "$p" >>"$R/pvesh.pw"
case "$(cat "$R/pvesh.mode")" in
abort-then-succeed) if [ "$c" -ge 2 ]; then echo "successfully added node 'pvh-n2' to cluster."; else echo "cluster not ready - no quorum?"; echo "Cluster join aborted!"; fi ;;
always-abort) if [ "$c" -ge 4 ]; then echo "successfully added node 'pvh-n2' to cluster."; else echo "cluster not ready - no quorum?"; echo "Cluster join aborted!"; fi ;;
partial) echo "Join request OK, finishing setup locally"; echo "stopping pve-cluster service"; echo "Cluster join aborted!" ;;
hardfail) echo "pvesh: transport error" >&2; echo "pvesh: transport error"; exit 1 ;;
esac
exit 0
`

func TestCluster_JoinRetryScriptExecuted(t *testing.T) {
	script := clusterScripts(t)[cN2+" cluster-join"]
	if script == "" {
		t.Fatal("no cluster-join script captured")
	}
	// Neutralize in_pvh (the X2 rewrite, with NO file created) so the loop is reached.
	rw := [][2]string{{"/etc/pve/corosync.conf", "$R/corosync.conf"}}
	setup := func(t *testing.T, mode string) string {
		root := newRemoteRoot(t)
		if err := os.WriteFile(filepath.Join(root, "pvesh.mode"), []byte(mode), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "bin", "pvesh"), []byte("#!"+filepath.Join(root, "bin", "bash")+"\n"+pveshRetryStub), 0o700); err != nil {
			t.Fatal(err)
		}
		return root
	}
	pws := func(root string) []string {
		b, _ := os.ReadFile(filepath.Join(root, "pvesh.pw"))
		s := strings.TrimSuffix(string(b), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}

	// sub-1: clean abort then success -> retries once, ends success; stdout carries
	// only the FINAL attempt (no abort line); the password is read once and reused.
	t.Run("abort-then-succeed", func(t *testing.T) {
		root := setup(t, "abort-then-succeed")
		r := runRemote(t, root, script, rw, "testpw123\n")
		if n := len(pws(root)); n != 2 {
			t.Errorf("pvesh called %d, want 2 (retry once then succeed)\n%s", n, r.out)
		}
		if !strings.Contains(r.out, "successfully added node") {
			t.Errorf("stdout lacks the success token:\n%s", r.out)
		}
		if strings.Contains(r.out, "Cluster join aborted!") {
			t.Errorf("stdout contains the abort text (emit-final-only violated):\n%s", r.out)
		}
		if p := pws(root); len(p) != 2 || p[0] != "testpw123" || p[1] != "testpw123" {
			t.Errorf("pvesh passwords %q, want both \"testpw123\" (single-read-pw)", p)
		}
	})

	// sub-2: always a clean abort -> bounded at 3 attempts. The stub self-caps at
	// call 4 (returns success) so a removed bound fails pvesh==3 fast, not by hang.
	t.Run("always-clean-abort", func(t *testing.T) {
		root := setup(t, "always-abort")
		r := runRemote(t, root, script, rw, "testpw123\n")
		if n := len(pws(root)); n != 3 {
			t.Errorf("pvesh called %d, want 3 (bounded)\n%s", n, r.out)
		}
		if !strings.Contains(r.out, "Cluster join aborted!") {
			t.Errorf("stdout lacks the abort text:\n%s", r.out)
		}
	})

	// sub-3: an abort WITH both partial-setup markers -> n2 began local setup, so
	// it must NOT retry (one call), even though an abort marker is present.
	t.Run("abort-with-partial", func(t *testing.T) {
		root := setup(t, "partial")
		r := runRemote(t, root, script, rw, "testpw123\n")
		if n := len(pws(root)); n != 1 {
			t.Errorf("pvesh called %d, want 1 (no retry once local setup began)\n%s", n, r.out)
		}
	})

	// sub-4 (obligation g): a non-zero pvesh with no marker -> || true must let the
	// loop break and the script complete (exit 0), one call, no retry.
	t.Run("non-marker-hard-failure", func(t *testing.T) {
		root := setup(t, "hardfail")
		r := runRemote(t, root, script, rw, "testpw123\n")
		if r.code != 0 {
			t.Errorf("remote script exit %d, want 0 (|| true must tolerate a non-zero pvesh)\n%s", r.code, r.out)
		}
		if n := len(pws(root)); n != 1 {
			t.Errorf("pvesh called %d, want 1\n%s", n, r.out)
		}
	})
}
