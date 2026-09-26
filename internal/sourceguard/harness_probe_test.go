package sourceguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The capability probe (hack/harness/probe.sh, pveforge-harness-capability-
// probe), run offline against the fake with per-call answer sequences. Every
// PVE call goes through lib.sh; these cases pin what the probe sends, what it
// records, what it refuses by name, and what it cleans up and reports when it
// dies midway.

const (
	pStatus   = "get /nodes/qa-pve-02/storage/pveforge-harness/status"
	pContent  = "get /nodes/qa-pve-02/storage/pveforge-harness/content vmid=690"
	pPool     = "get /pools poolid=pveforge-harness"
	pConf     = "get /nodes/qa-pve-02/qemu/690/config"
	pSnaps    = "get /nodes/qa-pve-02/qemu/690/snapshot"
	pGone     = "get /nodes/qa-pve-02/qemu/690/status/current" // never read: a pool token gets 403 for a destroyed VM
	pNextID   = "get /cluster/nextid vmid=690"
	pRollback = "post /nodes/qa-pve-02/qemu/690/snapshot/s1/rollback"
	pSnapS2   = "post /nodes/qa-pve-02/qemu/690/snapshot snapname=s2 vmstate=0"
	pDelS2    = "delete /nodes/qa-pve-02/qemu/690/snapshot/s2"
	pDelS1    = "delete /nodes/qa-pve-02/qemu/690/snapshot/s1"
	pDestroy  = "delete /nodes/qa-pve-02/qemu/690 purge=1 destroy-unreferenced-disks=1"
	upid690   = "UPID:qa-pve-02:000107D0:0FA3B38F:6AB7381B:qmdestroy:690:pveforge-harness@pve!build:"
	pTask     = "get /nodes/qa-pve-02/tasks/" + upid690 + "/status"
	pCreate   = "vm create 690"

	gib600      = int64(600) << 30
	zfsRefusal  = "task UPID:fake failed: can't rollback, 's1' is not most recent snapshot on 'pveforge-harness:vm-690-disk-0'"
	nextIDInUse = "api get /cluster/nextid: pve returned 400 Parameter verification failed: vmid: VM 690 already exists"
	emptyPool   = `[{"poolid":"pveforge-harness","comment":"","members":[]}]`
	poolWith690 = `[{"poolid":"pveforge-harness","comment":"","members":[{"id":"qemu/690","type":"qemu","vmid":690,"node":"qa-pve-02"}]}]`
	oneVolume   = `[{"volid":"pveforge-harness:vm-690-disk-0","vmid":690,"size":1073741824}]`
)

// taskStatus is PVE's status of a destroy task, exitstatus as given.
func taskStatus(upid, node, typ, id, status, exit string) string {
	return fmt.Sprintf(`{"upid":%q,"node":%q,"pid":67536,"pstart":262386575,"starttime":1790000000,"type":%q,"id":%q,"user":"pveforge-harness@pve","tokenid":"build","status":%q,"exitstatus":%q}`, upid, node, typ, id, status, exit)
}

func storageStatus(typ string, avail int64, extra string) string {
	// A quota'd dataset, as pveforge-harness is: used + avail = total.
	return fmt.Sprintf(`{"type":%q,"enabled":1,"active":1,"content":"images,rootdir","avail":%d,"total":%d,"used":%d,"shared":0%s}`, typ, avail, gib600, gib600-avail, extra)
}

// probeSpec is one probe run's fake world: answers by key, and by the n-th
// call of a key.
type probeSpec struct {
	resp map[string]string
	seq  map[string]map[int]string // key -> call number -> stdout
	rc   map[string]map[int]int    // key -> call number (0: every call) -> status
	err  map[string]map[int]string // key -> call number (0: every call) -> stderr
	kill map[string]map[int]string // key -> call number -> signal sent to the probe
	args []string
	env  map[string]string
	// script is the harness script run, relative to hack/harness (default
	// probe.sh); bashArgs go to bash before it.
	script   string
	bashArgs []string
	// setup prepares $HOME before the run; stubs are scripts put first in
	// PATH, by name.
	setup func(t *testing.T, home string)
	stubs map[string]string
	// block is a key whose first call (blockAt, when set) waits until
	// onBlock has returned.
	block   string
	blockAt int
	onBlock func(t *testing.T, b blocked)
	// stdin, when set, is the script's standard input.
	stdin string
	// gone and goneRC answer a key once a VM destroy has succeeded (the
	// fake's .destroyed variants), unless a numbered one answers that call:
	// what PVE shows once a VM is gone.
	gone   map[string]string
	goneRC map[string]int
	// keepInPool: VMIDs the pool still lists after their destroy (the fake
	// drops every other destroyed VM from /pools, as PVE does).
	keepInPool []string
	// destroyLands: VMIDs whose destroy takes effect even when the call
	// exits non-zero (a pveforge wait that failed while PVE's task finished).
	destroyLands []string
	// out is where stdout and stderr go: "" (captured), "pipe" (one pipe,
	// as "2>&1 | head" gives; the test can close its reading end) or "pty"
	// (a terminal; the test can hang it up).
	out string
}

// blocked is a run held at spec.block.
type blocked struct {
	home   string
	hangup func() // closes the reading end of the pipe, or hangs up the pty
}

// zfsWorld: a healthy zfspool; the first rollback is refused as ZFS refuses
// it; the pool lists 690 only between its create and its destroy (the fake
// drops a destroyed VM from it), and /cluster/nextid offers 690; the first poll still shows the
// volume and less free space. status/current has no answer at all: the probe
// must never ask it whether 690 is gone.
func zfsWorld() probeSpec {
	return probeSpec{
		resp: map[string]string{
			pStatus:  storageStatus("zfspool", gib600, ""),
			pContent: `[]`,
			pPool:    poolWith690,
			pConf:    `{"cores":"1","tags":"pveforge-harness"}`,
			pSnaps:   `[{"name":"current"}]`,
			pNextID:  `"690"`,
			pDestroy: `"` + upid690 + `"`,
			pTask:    taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "OK"),
		},
		gone: map[string]string{},
		seq: map[string]map[int]string{
			pPool:    {1: emptyPool},
			pContent: {2: oneVolume},
			pStatus:  {2: storageStatus("zfspool", gib600-(5<<30), "")},
		},
		rc:   map[string]map[int]int{pRollback: {1: 1}},
		err:  map[string]map[int]string{pRollback: {1: zfsRefusal}},
		args: []string{"--storage", "pveforge-harness"},
	}
}

type probeResult struct {
	code           int
	stdout, stderr string
	calls          []string
	home           string
	sleeps         int
}

func (r probeResult) evidenceDir(t *testing.T) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/probe/*"))
	if len(dirs) != 1 {
		t.Fatalf("evidence directories = %q, want exactly one", dirs)
	}
	return dirs[0]
}

func (r probeResult) evidence(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.evidenceDir(t), name))
	if err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	return string(b)
}

func (r probeResult) rule() (string, bool) {
	b, err := os.ReadFile(filepath.Join(r.home, ".config/pveforge/harness-state/rollback-rule.pveforge-harness"))
	return string(b), err == nil
}

func (r probeResult) writes() []string {
	var w []string
	for _, c := range r.calls {
		if isWrite(c) {
			w = append(w, c)
		}
	}
	return w
}

func runProbe(t *testing.T, s probeSpec) probeResult {
	t.Helper()
	script := s.script
	if script == "" {
		script = "probe.sh"
	}
	probe, err := filepath.Abs(filepath.Join(harnessDir, script))
	if err != nil {
		t.Fatal(err)
	}
	fake, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-pveforge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cfg := filepath.Join(home, ".config", "pveforge")
	fakeDir := filepath.Join(tmp, "fake")
	stub := filepath.Join(tmp, "stub")
	work := filepath.Join(tmp, "work")
	for _, d := range []string{cfg, stub, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"resp", "rc", "err", "kill", "block"} {
		if err := os.MkdirAll(filepath.Join(fakeDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg, "harness-outer.toml"), []byte("# test roster\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// sleep and `date +%s` share a fake clock (clockStubs), so a poll bounded
	// by the clock runs at once; each sleep is counted. A spec's own stubs
	// replace them.
	for name, body := range clockStubs(t, map[string]string{}) {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if s.setup != nil {
		s.setup(t, home)
	}
	for name, body := range s.stubs {
		if err := os.WriteFile(filepath.Join(stub, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	put := func(dir, key string, n int, v string) {
		name := fakeKey(key)
		if n > 0 {
			name += fmt.Sprintf(".%d", n)
		}
		if err := os.WriteFile(filepath.Join(fakeDir, dir, name), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range s.resp {
		put("resp", k, 0, v+"\n")
	}
	for k, m := range s.seq {
		for n, v := range m {
			put("resp", k, n, v+"\n")
		}
	}
	for k, m := range s.rc {
		for n, v := range m {
			put("rc", k, n, fmt.Sprint(v))
		}
	}
	for k, m := range s.err {
		for n, v := range m {
			put("err", k, n, v+"\n")
		}
	}
	for k, v := range s.gone {
		if err := os.WriteFile(filepath.Join(fakeDir, "resp", fakeKey(k)+".destroyed"), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range s.keepInPool {
		if err := os.MkdirAll(filepath.Join(fakeDir, "keep-in-pool"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fakeDir, "keep-in-pool", v), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range s.destroyLands {
		if err := os.MkdirAll(filepath.Join(fakeDir, "destroy-lands"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fakeDir, "destroy-lands", v), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range s.goneRC {
		if err := os.WriteFile(filepath.Join(fakeDir, "rc", fakeKey(k)+".destroyed"), []byte(fmt.Sprint(v)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for k, m := range s.kill {
		for n, v := range m {
			put("kill", k, n, v)
		}
	}
	path := stub + ":" + harnessPATH(t)
	for _, tool := range []string{"date", "mv", "chmod"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		path += ":" + filepath.Dir(p)
	}
	env := map[string]string{
		"PATH": path, "HOME": home, "PVEFORGE_BIN": fake,
		"PVEFORGE_ROSTER_PASSPHRASE": "not-a-secret", "FAKE_PVEFORGE_DIR": fakeDir,
	}
	for k, v := range s.env {
		env[k] = v
	}
	var fifo *os.File
	if s.block != "" {
		at := s.blockAt
		if at == 0 {
			at = 1
		}
		put("block", s.block, at, "")
		fp := filepath.Join(fakeDir, "block.fifo")
		if err := syscall.Mkfifo(fp, 0o600); err != nil {
			t.Fatal(err)
		}
		// Held open read-write, so the release line waits in the fifo
		// whenever the fake opens it, and the fake's open never blocks.
		if fifo, err = os.OpenFile(fp, os.O_RDWR, 0); err != nil {
			t.Fatal(err)
		}
		defer fifo.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append(append(append([]string{}, s.bashArgs...), probe), s.args...)...)
	cmd.Dir = work
	cmd.WaitDelay = 5 * time.Second
	// Its own process group: a signal the fake sends to its group never
	// reaches the test.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	for k, v := range env {
		if v != "-" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var out, errOut bytes.Buffer
	var hangup func()
	var afterStart []func()
	switch s.out {
	case "":
		cmd.Stdout, cmd.Stderr = &out, &errOut
	case "pipe":
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = w, w
		var once sync.Once
		done := make(chan struct{})
		go func() {
			defer close(done)
			b := make([]byte, 4096)
			for {
				n, err := r.Read(b)
				errOut.Write(b[:n])
				if err != nil {
					return
				}
			}
		}()
		hangup = func() { once.Do(func() { r.Close(); <-done }) }
		afterStart = append(afterStart, func() { w.Close() })
		defer hangup()
	case "pty":
		master, slave := openPTY(t)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		var once sync.Once
		hangup = func() { once.Do(func() { master.Close() }) }
		afterStart = append(afterStart, func() { slave.Close() })
		defer hangup()
	default:
		t.Fatalf("out %q", s.out)
	}
	if s.stdin != "" {
		cmd.Stdin = strings.NewReader(s.stdin)
	}
	res := probeResult{home: home}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the probe: %v", err)
	}
	for _, f := range afterStart {
		f()
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	if s.block != "" {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
	poll:
		for {
			select {
			case err = <-waited:
				t.Errorf("the probe exited before it reached %q", s.block)
				waited <- err
				break poll
			case <-ctx.Done():
				t.Errorf("the probe never reached %q", s.block)
				break poll
			case <-tick.C:
				if _, err := os.Stat(filepath.Join(fakeDir, "blocked")); err == nil {
					if s.onBlock != nil {
						s.onBlock(t, blocked{home: home, hangup: hangup})
					}
					break poll
				}
			}
		}
		if _, err := fifo.WriteString("go\n"); err != nil {
			t.Fatal(err)
		}
	}
	err = <-waited
	if hangup != nil {
		hangup()
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.code = ee.ExitCode()
	default:
		t.Fatalf("run the probe: %v", err)
	}
	res.stdout, res.stderr = out.String(), errOut.String()
	roster := filepath.Join(cfg, "harness-outer.toml")
	if b, err := os.ReadFile(filepath.Join(fakeDir, "argv.log")); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if l != "" {
				res.calls = append(res.calls, strings.ReplaceAll(l, roster, "R"))
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(fakeDir, "sleep.log")); err == nil {
		res.sleeps = strings.Count(string(b), "\n")
	}
	return res
}

const (
	createCall = `vm create qa-pve-02-harness 690 --roster R --json {"scsi0":"pveforge-harness:1","name":"pveforge-probe","memory":"512","cores":"1","pool":"pveforge-harness"}`
	tagCall    = "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data tags=pveforge-harness"
	snapS1     = "api post /nodes/qa-pve-02/qemu/690/snapshot qa-pve-02-harness --roster R -o json --data snapname=s1 --data vmstate=0"
	snapS2     = "api post /nodes/qa-pve-02/qemu/690/snapshot qa-pve-02-harness --roster R -o json --data snapname=s2 --data vmstate=0"
	rollback   = "api post /nodes/qa-pve-02/qemu/690/snapshot/s1/rollback qa-pve-02-harness --roster R -o json"
	delS2      = "api delete /nodes/qa-pve-02/qemu/690/snapshot/s2 qa-pve-02-harness --roster R -o json"
	delS1      = "api delete /nodes/qa-pve-02/qemu/690/snapshot/s1 qa-pve-02-harness --roster R -o json"
	destroy    = "api delete /nodes/qa-pve-02/qemu/690 qa-pve-02-harness --roster R -o json --data purge=1 --data destroy-unreferenced-disks=1"
)

var fullWrites = []string{createCall, tagCall, snapS1, snapS2, rollback, delS2, rollback, delS1, destroy}

func equalCalls(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\n got:\n  %s\n want:\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// P1: on zfspool the rollback to s1 while s2 exists is refused; the probe
// records that as the storage's rule, cascades, destroys 690, verifies it
// gone, polls until nothing is left, and only then writes the rule.
func TestProbe_ZFSPool(t *testing.T) {
	r := runProbe(t, zfsWorld())
	if r.code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", r.code, r.stderr)
	}
	if r.stdout != "rollback-rule=rollback-latest-only storage=pveforge-harness\n" {
		t.Errorf("stdout %q", r.stdout)
	}
	if rule, ok := r.rule(); !ok || rule != "rollback-latest-only\n" {
		t.Errorf("rule file %q (present %t)", rule, ok)
	}
	equalCalls(t, "writes", r.writes(), fullWrites)
	if r.sleeps != 1 {
		t.Errorf("slept %d times, want 1 (the first poll still shows the volume)", r.sleeps)
	}
	if got := r.evidence(t, "rollback-s1-with-s2.stderr"); !strings.Contains(got, "is not most recent snapshot") {
		t.Errorf("the refusal is not recorded: %q", got)
	}
	for _, f := range []string{"storage-status-before.json", "content-before.json", "storage-type", "rollback-rule", "gone.stderr", "poll.log", "storage-status-after.json", "SUMMARY"} {
		r.evidence(t, f)
	}
	// The answers the proof decided on, recorded as read.
	gone := r.evidence(t, "gone.log")
	for _, want := range []string{"task " + upid690 + ": " + taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "OK"), `nextid vmid=690: "690"`, "pool pveforge-harness: " + emptyPool} {
		if !strings.Contains(gone, want) {
			t.Errorf("gone.log lacks %q:\n%s", want, gone)
		}
	}
	if got := r.evidence(t, "nextid.log"); got != `nextid vmid=690: "690"`+"\n" {
		t.Errorf("nextid.log %q", got)
	}
	if got := r.evidence(t, "accounts.txt"); !strings.Contains(got, ": thick (evidence only)") {
		t.Errorf("accounts.txt %q", got)
	}
	fi, err := os.Stat(r.evidenceDir(t))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("evidence directory mode %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	fi, err = os.Stat(filepath.Join(r.home, ".config/pveforge/harness-state/rollback-rule.pveforge-harness"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("rule file mode: %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "--unsafe-no-lock") {
			t.Errorf("a call bypasses the lock: %s", c)
		}
		if strings.Contains(c, "/qemu/690/status/current") {
			t.Errorf("690's status was read: a pool token gets 403 for a destroyed VM, so its answer proves nothing: %s", c)
		}
	}
	if !slices.Contains(r.calls, "api get /cluster/nextid qa-pve-02-harness --roster R -o json --data vmid=690") {
		t.Errorf("690 was never proven free by /cluster/nextid: %q", r.calls)
	}
}

// P2: a storage on which the rollback to s1 while s2 exists succeeds: rule
// rollback-any, and the cascade still runs. (No zfspool does; lvmthin, which
// would, is refused before this. The branch stays covered.)
func TestProbe_RollbackAny(t *testing.T) {
	s := zfsWorld()
	s.rc = map[string]map[int]int{}
	s.err = map[string]map[int]string{}
	r := runProbe(t, s)
	if r.code != 0 || r.stdout != "rollback-rule=rollback-any storage=pveforge-harness\n" {
		t.Fatalf("exit %d stdout %q stderr:\n%s", r.code, r.stdout, r.stderr)
	}
	if rule, _ := r.rule(); rule != "rollback-any\n" {
		t.Errorf("rule file %q", rule)
	}
	equalCalls(t, "writes", r.writes(), fullWrites)
}

// P3: the static layer refuses by name, before any change.
func TestProbe_StaticRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		status string
		env    map[string]string
		code   int
		want   string
	}{
		"not enabled":           {strings.Replace(storageStatus("zfspool", gib600, ""), `"enabled":1`, `"enabled":0`, 1), nil, 3, "it is not enabled"},
		"not active":            {strings.Replace(storageStatus("zfspool", gib600, ""), `"active":1`, `"active":0`, 1), nil, 3, "it is not active on qa-pve-02"},
		"no images":             {strings.Replace(storageStatus("zfspool", gib600, ""), `"images,rootdir"`, `"rootdir,iso"`, 1), nil, 3, "does not include images"},
		"images only as prefix": {strings.Replace(storageStatus("zfspool", gib600, ""), `"images,rootdir"`, `"imagesx"`, 1), nil, 3, "does not include images"},
		"a dir storage":         {storageStatus("dir", gib600, ""), nil, 3, "type dir cannot hold the harness: it needs zfspool"},
		"an lvmthin storage":    {storageStatus("lvmthin", gib600, ""), nil, 3, "type lvmthin is not supported: the harness is proven on zfspool only"},
		"an nfs storage":        {storageStatus("nfs", gib600, ""), nil, 3, "type nfs cannot hold the harness"},
		"too little space":      {storageStatus("zfspool", 519<<30, ""), nil, 3, "519 GiB free, below HARNESS_PROBE_MIN_FREE_GIB=520"},
		"a raised threshold":    {storageStatus("zfspool", gib600, ""), map[string]string{"HARNESS_PROBE_MIN_FREE_GIB": "601"}, 3, "below HARNESS_PROBE_MIN_FREE_GIB=601"},
		"a bad threshold":       {storageStatus("zfspool", gib600, ""), map[string]string{"HARNESS_PROBE_MIN_FREE_GIB": "5e2"}, 2, "must be whole GiB"},
		"a null status":         {`null`, nil, 1, "unexpected shape"},
		"no avail":              {`{"type":"zfspool","enabled":1,"active":1,"content":"images"}`, nil, 1, "unexpected shape"},
	} {
		t.Run(name, func(t *testing.T) {
			s := zfsWorld()
			s.resp[pStatus] = tc.status
			s.seq[pStatus] = nil
			s.env = tc.env
			r := runProbe(t, s)
			if r.code != tc.code || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d (want %d), stderr:\n%s\nwant %q", r.code, tc.code, r.stderr, tc.want)
			}
			if w := r.writes(); len(w) != 0 {
				t.Errorf("a refused storage was changed: %q", w)
			}
			if _, ok := r.rule(); ok {
				t.Errorf("a refused probe wrote the rule")
			}
		})
	}
	// The minimum is exactly 520 GiB.
	s := zfsWorld()
	// (A storage smaller than its quota: 520 GiB free, and empty.)
	s.resp[pStatus] = storageStatus("zfspool", 520<<30, `,"used":0`)
	s.seq[pStatus] = map[int]string{2: storageStatus("zfspool", 515<<30, "")}
	if r := runProbe(t, s); r.code != 0 {
		t.Errorf("exactly 520 GiB free: exit %d\n%s", r.code, r.stderr)
	}
	// No storage: lib's own refusal, nothing sent.
	s = zfsWorld()
	s.args = nil
	if r := runProbe(t, s); r.code != 2 || !strings.Contains(r.stderr, "the outer storage is required") || len(r.calls) != 0 {
		t.Errorf("no storage: exit %d calls %q\n%s", r.code, r.calls, r.stderr)
	}
}

// P4: --static-only reads the storage status and nothing else.
func TestProbe_StaticOnly(t *testing.T) {
	s := zfsWorld()
	s.args = append(s.args, "--static-only")
	r := runProbe(t, s)
	if r.code != 0 || !strings.Contains(r.stdout, "passes the static checks") {
		t.Fatalf("exit %d stdout %q\n%s", r.code, r.stdout, r.stderr)
	}
	equalCalls(t, "calls", r.calls, []string{"api get /nodes/qa-pve-02/storage/pveforge-harness/status qa-pve-02-harness --roster R -o json"})
	if _, ok := r.rule(); ok {
		t.Error("--static-only wrote the rule")
	}
}

// P5: 690 already in the pool, or volumes of 690 already on the storage: the
// probe runs only before the build, and refuses before any change.
func TestProbe_690MustNotExist(t *testing.T) {
	s := zfsWorld()
	s.seq[pPool] = nil
	r := runProbe(t, s)
	if r.code != 3 || !strings.Contains(r.stderr, "VM 690 already exists in pool pveforge-harness") || len(r.writes()) != 0 {
		t.Errorf("690 in the pool: exit %d writes %q\n%s", r.code, r.writes(), r.stderr)
	}
	s = zfsWorld()
	s.seq[pContent] = map[int]string{1: oneVolume}
	r = runProbe(t, s)
	if r.code != 3 || !strings.Contains(r.stderr, "already holds volumes of VM 690") || len(r.writes()) != 0 {
		t.Errorf("a leftover volume: exit %d writes %q\n%s", r.code, r.writes(), r.stderr)
	}
	// Not an empty harness storage: another VM in the pool, or used above
	// the empty dataset's 1 MiB (an orphan the token cannot list, or a free
	// still in progress): refused before anything, naming the figure.
	s = zfsWorld()
	s.seq[pPool] = map[int]string{1: strings.Replace(poolWith690, `"vmid":690`, `"vmid":691`, 1)}
	r = runProbe(t, s)
	if r.code != 3 || !strings.Contains(r.stderr, "pool pveforge-harness is not empty") || len(r.writes()) != 0 {
		t.Errorf("another VM in the pool: exit %d writes %q\n%s", r.code, r.writes(), r.stderr)
	}
	s = zfsWorld()
	s.resp[pStatus] = storageStatus("zfspool", gib600-(1<<20)-1, "")
	s.seq[pStatus] = nil
	r = runProbe(t, s)
	if r.code != 3 || !strings.Contains(r.stderr, "storage pveforge-harness is not empty: its used is 1048577 bytes") || len(r.writes()) != 0 {
		t.Errorf("used above 1 MiB: exit %d writes %q\n%s", r.code, r.writes(), r.stderr)
	}
	// 690 held anywhere in the cluster, outside the pool the token sees.
	for name, edit := range map[string]func(s *probeSpec){
		"nextid 400":   func(s *probeSpec) { s.rc[pNextID] = map[int]int{0: 1}; s.err[pNextID] = map[int]string{0: nextIDInUse} },
		"another VMID": func(s *probeSpec) { s.resp[pNextID] = `"691"` },
	} {
		s = zfsWorld()
		edit(&s)
		r = runProbe(t, s)
		if r.code != 3 || !strings.Contains(r.stderr, "refusing storage pveforge-harness: VMID 690 is not free in the cluster") || len(r.writes()) != 0 {
			t.Errorf("%s: exit %d writes %q\n%s", name, r.code, r.writes(), r.stderr)
		}
	}
}

// cleanupWorld: a world in which cleanup finds s1 and s2 and destroys 690.
func cleanupWorld() probeSpec {
	s := zfsWorld()
	s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100},{"name":"s2","snaptime":200}]`
	delete(s.seq, pContent) // the volumes go as soon as 690 is destroyed
	return s
}

// stillThere keeps 690 in the cluster after the destroy: /cluster/nextid
// refuses it (400), as PVE does for a VMID in use.
func stillThere(s probeSpec) {
	// Free at the preflight's read (call 1), in use at every later one.
	s.rc[pNextID] = map[int]int{}
	s.err[pNextID] = map[int]string{}
	for n := 2; n < 8; n++ {
		s.rc[pNextID][n] = 1
		s.err[pNextID][n] = nextIDInUse
	}
}

// notProven is cleanup's report for a 690 that stillThere keeps.
const notProven = "LEFTOVER: VM 690 is not proven gone after cleanup: /cluster/nextid did not answer 200 for VMID 690"

// P6: an unrecognised rollback error aborts; cleanup deletes the snapshots
// newest first and destroys 690; no rule is written.
func TestProbe_UnexpectedRollbackErrorCleansUp(t *testing.T) {
	s := cleanupWorld()
	s.err[pRollback] = map[int]string{1: "task UPID:fake failed: storage is busy"}
	r := runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, "failed for an unrecognised reason") {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), []string{createCall, tagCall, snapS1, snapS2, rollback, delS2, delS1, destroy})
	if !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("cleanup not reported:\n%s", r.stderr)
	}
	if _, ok := r.rule(); ok {
		t.Error("a failed probe wrote the rule")
	}
}

// P7: a lock left by the refused rollback is named, with the operator's
// command, and cleanup's leftover report lists what remains.
func TestProbe_LockAfterRefusal(t *testing.T) {
	s := cleanupWorld()
	s.resp[pConf] = `{"cores":"1","tags":"pveforge-harness","lock":"rollback"}`
	s.rc[pDelS2] = map[int]int{0: 1}
	s.rc[pDelS1] = map[int]int{0: 1}
	s.rc[pDestroy] = map[int]int{0: 1}
	s.err[pDestroy] = map[int]string{0: "VM is locked (rollback)"}
	stillThere(s)
	r := runProbe(t, s)
	if r.code != 4 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{"carries lock 'rollback' after the refused rollback", "qm unlock 690", notProven,
		"lock:      rollback", "snapshots: s1 s2", "qm destroy 690 --purge"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	r.evidence(t, "LEFTOVER")
}

// P8: the probe dies midway (a failed snapshot): pveforge's status is kept,
// and cleanup removes what was made.
func TestProbe_DiesMidwayCleansUp(t *testing.T) {
	s := cleanupWorld()
	s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
	s.rc[pSnapS2] = map[int]int{0: 5}
	r := runProbe(t, s)
	if r.code != 5 {
		t.Fatalf("exit %d, want pveforge's 5\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), []string{createCall, tagCall, snapS1, snapS2, delS1, destroy})
	if !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("cleanup not reported:\n%s", r.stderr)
	}
}

// P9: cleanup itself fails: the leftover report says exactly what is left,
// with the commands, and the original status stands.
func TestProbe_CleanupFailsReportsLeftover(t *testing.T) {
	s := cleanupWorld()
	s.rc[pSnapS2] = map[int]int{0: 5}
	s.rc[pDestroy] = map[int]int{0: 7}
	stillThere(s)
	s.resp[pContent] = oneVolume
	s.seq[pContent] = map[int]string{1: `[]`}
	r := runProbe(t, s)
	if r.code != 5 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	for _, want := range []string{notProven, "volumes:   pveforge-harness:vm-690-disk-0", "Removing it needs an operator ask", "pvesm list pveforge-harness --vmid 690"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
}

// P10: a create that failed, though 690 appeared: this run did not record it,
// so nothing is destroyed and the leftover is named.
func TestProbe_CreateFailedButVMAppeared(t *testing.T) {
	s := zfsWorld()
	s.rc[pCreate] = map[int]int{0: 1}
	r := runProbe(t, s)
	if r.code != 1 {
		t.Fatalf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), []string{createCall})
	if !strings.Contains(r.stderr, "this run did not record creating it") || !strings.Contains(r.stderr, "qm destroy 690 --purge") {
		t.Errorf("leftover not named:\n%s", r.stderr)
	}
}

// P11: after the destroy is proven, lib's wait on the storage (bounded by
// the clock, 180 s at 5 s) can only DETECT a leftover: a volume still listed,
// or the usage still above its baseline when the wait ends. A status it
// cannot read detects nothing, and the probe completes on the task's proof.
// How the storage accounted the disk (thick or thin) is evidence, never a
// gate.
func TestProbe_PollIsBounded(t *testing.T) {
	const leftover = "VM 690 is destroyed, but the storage shows a leftover: "
	s := zfsWorld()
	s.resp[pContent] = oneVolume
	s.seq[pContent] = map[int]string{1: `[]`}
	r := runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, leftover+"storage pveforge-harness still lists volumes of VM(s) 690 (after 180s)") || r.sleeps != 36 {
		t.Errorf("volumes never go: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	if _, ok := r.rule(); ok {
		t.Error("a probe that detected a leftover wrote the rule")
	}
	// The bound is the clock's, not a count of sleeps: a slow sleep ends it
	// sooner.
	s = zfsWorld()
	s.resp[pContent] = oneVolume
	s.seq[pContent] = map[int]string{1: `[]`}
	s.stubs = map[string]string{"sleep": "#!/usr/bin/env bash\necho \"$*\" >>\"$FAKE_PVEFORGE_DIR/sleep.log\"\nc=0\n[ -f \"$FAKE_PVEFORGE_DIR/clock\" ] && c=$(cat \"$FAKE_PVEFORGE_DIR/clock\")\nprintf '%s' $((c + 60)) >\"$FAKE_PVEFORGE_DIR/clock\"\n"}
	if r := runProbe(t, s); r.code != 4 || !strings.Contains(r.stderr, "(after 180s)") || r.sleeps != 3 {
		t.Errorf("a slow clock: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	// A hidden leftover: nothing listed, but the usage 2 MiB high at the end.
	s = zfsWorld()
	delete(s.seq, pContent)
	s.seq[pStatus] = map[int]string{2: storageStatus("zfspool", gib600-(5<<30), "")}
	for n := 3; n < 60; n++ {
		s.seq[pStatus][n] = storageStatus("zfspool", gib600-(2<<20), "")
	}
	if r := runProbe(t, s); r.code != 4 || !strings.Contains(r.stderr, leftover+"storage pveforge-harness's used is 2097152, not back within 1 MiB of its baseline 0 (after 180s)") {
		t.Errorf("usage 2 MiB high: exit %d\n%s", r.code, r.stderr)
	}
	s = zfsWorld()
	delete(s.seq, pContent)
	s.seq[pStatus] = map[int]string{2: storageStatus("zfspool", gib600-(5<<30), ""), 3: storageStatus("zfspool", gib600-(1<<20), "")}
	if r := runProbe(t, s); r.code != 0 || r.sleeps != 0 {
		t.Errorf("usage exactly 1 MiB high is within the slack: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	// A status the wait cannot read, or with no usable used, detects
	// nothing: the task's proof stands, and the log says so.
	for name, edit := range map[string]func(s *probeSpec){
		"unreadable": func(s *probeSpec) {
			s.rc[pStatus] = map[int]int{}
			for n := 3; n < 60; n++ {
				s.rc[pStatus][n] = 1
			}
		},
		"no used": func(s *probeSpec) {
			for n := 3; n < 60; n++ {
				s.seq[pStatus][n] = `{"type":"zfspool","avail":1}`
			}
		},
		"a string used": func(s *probeSpec) {
			for n := 3; n < 60; n++ {
				s.seq[pStatus][n] = `{"type":"zfspool","used":"0"}`
			}
		},
	} {
		s = zfsWorld()
		delete(s.seq, pContent)
		edit(&s)
		r := runProbe(t, s)
		if r.code != 0 || r.sleeps != 36 || !strings.Contains(r.evidence(t, "poll.log"), "the status could not be read (after 180s): nothing detected, nothing proven") {
			t.Errorf("%s: exit %d sleeps %d\n%s", name, r.code, r.sleeps, r.stderr)
		}
	}
	// Accounting is evidence: thick (the whole disk in used at once), or thin
	// (pveforge-harness is 'sparse 1': 96544 bytes for the live 1 GiB zvol),
	// and the probe completes either way.
	for name, c := range map[string]struct {
		base, after int64
		want        string
	}{
		"thick":                  {0, 5 << 30, "baseline 0 after-create 5368709120 delta 5368709120: thick (evidence only)"},
		"thin, as measured live": {165504, 262048, "baseline 165504 after-create 262048 delta 96544: thin (evidence only)"},
		// 1 GiB less 512 KiB over a 1 MiB baseline is short of thick, though
		// it would pass over an absolute zero.
		"short over a 1 MiB baseline": {1 << 20, (1 << 30) - (512 << 10), "baseline 1048576 after-create 1073217536 delta 1072168960: thin (evidence only)"},
	} {
		s = zfsWorld()
		delete(s.seq, pContent)
		s.resp[pStatus] = storageStatus("zfspool", gib600-c.base, "")
		s.seq[pStatus] = map[int]string{2: storageStatus("zfspool", gib600-c.after, "")}
		r := runProbe(t, s)
		if got := r.evidence(t, "accounts.txt"); r.code != 0 || got != c.want+"\n" {
			t.Errorf("%s: exit %d accounts.txt %q, want %q\n%s", name, r.code, got, c.want, r.stderr)
		}
	}
}

// P12: 690 is gone only on a positive proof: /cluster/nextid answers 200
// with exactly 690, and the pool no longer lists it. Anything else, whatever
// its text, is a named failure and no rule is written.
func TestProbe_VerifyGone(t *testing.T) {
	const notGone = "VM 690 is not proven gone after the destroy: "
	const taskNotOK = "the destroy task " + upid690 + " is not a stopped qmdestroy of VM 690 on qa-pve-02 with exitstatus OK"
	upidFor := func(old, new string) string { return strings.Replace(upid690, old, new, 1) }
	printed := func(u string) string {
		return "the destroy of VM 690 printed " + u + ", which is not a qmdestroy task for VM 690 on qa-pve-02"
	}
	for name, c := range map[string]struct {
		edit func(s *probeSpec)
		want string
	}{
		"nextid 400": {func(s *probeSpec) {
			s.goneRC = map[string]int{pNextID: 1}
			s.err[pNextID] = map[int]string{0: nextIDInUse}
		}, "/cluster/nextid did not answer 200"},
		"nextid fails saying does not exist": {func(s *probeSpec) {
			s.goneRC = map[string]int{pNextID: 1}
			s.err[pNextID] = map[int]string{0: "Configuration file 'nodes/qa-pve-02/qemu-server/690.conf' does not exist"}
		}, "/cluster/nextid did not answer 200"},
		"another VMID":        {func(s *probeSpec) { s.gone[pNextID] = `"691"` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"a longer VMID":       {func(s *probeSpec) { s.gone[pNextID] = `"6900"` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"a prefix":            {func(s *probeSpec) { s.gone[pNextID] = `"69"` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"null":                {func(s *probeSpec) { s.gone[pNextID] = `null` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"an array":            {func(s *probeSpec) { s.gone[pNextID] = `["690"]` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"two values":          {func(s *probeSpec) { s.gone[pNextID] = "\"690\"\n\"690\"" }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"not JSON":            {func(s *probeSpec) { s.gone[pNextID] = `690 free` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"still in the pool":   {func(s *probeSpec) { s.keepInPool = []string{"690"} }, "pool pveforge-harness still lists VM 690"},
		"the pool unreadable": {func(s *probeSpec) { s.goneRC = map[string]int{pPool: 1} }, "reading pool pveforge-harness failed"},
		"the pool lists 690 as a string": {func(s *probeSpec) {
			s.gone[pPool] = `[{"poolid":"pveforge-harness","members":[{"id":"qemu/690","type":"qemu","vmid":"690","node":"qa-pve-02"}]}]`
		}, "pool pveforge-harness still lists VM 690, or its answer has an unexpected shape"},
		"another pool's answer": {func(s *probeSpec) { s.gone[pPool] = `[{"poolid":"other","members":[]}]` }, "pool pveforge-harness still lists VM 690, or its answer has an unexpected shape"},
		"an empty answer":       {func(s *probeSpec) { s.gone[pPool] = `[]` }, "pool pveforge-harness still lists VM 690, or its answer has an unexpected shape"},
		// The destroy's own task: exactly this task, stopped, exitstatus OK.
		"task WARNINGS": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "WARNINGS: 1")
		}, taskNotOK},
		"task OK with space": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "OK ")
		}, taskNotOK},
		"task ok lowercase": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "ok")
		}, taskNotOK},
		"task running": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "running", "OK")
		}, taskNotOK},
		"task no exitstatus": {func(s *probeSpec) {
			s.resp[pTask] = strings.Replace(taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "OK"), `,"exitstatus":"OK"`, "", 1)
		}, taskNotOK},
		"task unreadable": {func(s *probeSpec) { s.rc[pTask] = map[int]int{0: 1} }, "the status of the destroy task " + upid690 + " could not be read"},
		"another task's upid": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(strings.Replace(upid690, "6AB7381B", "6AB7381C", 1), "qa-pve-02", "qmdestroy", "690", "stopped", "OK")
		}, taskNotOK},
		"another task's type": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmstart", "690", "stopped", "OK")
		}, taskNotOK},
		"another task's id": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "691", "stopped", "OK")
		}, taskNotOK},
		"another task's node": {func(s *probeSpec) {
			s.resp[pTask] = taskStatus(upid690, "qa-pve-01", "qmdestroy", "690", "stopped", "OK")
		}, taskNotOK},
		"the destroy printed no UPID": {func(s *probeSpec) { s.resp[pDestroy] = `null` }, "the destroy of VM 690 printed no task UPID"},
		"a UPID for another VM": {func(s *probeSpec) {
			s.resp[pDestroy] = `"` + strings.Replace(upid690, ":690:", ":691:", 1) + `"`
		}, printed(upidFor(":690:", ":691:"))},
		"a UPID of another type": {func(s *probeSpec) {
			s.resp[pDestroy] = `"` + strings.Replace(upid690, "qmdestroy", "qmstop", 1) + `"`
		}, printed(upidFor("qmdestroy", "qmstop"))},
		"a UPID on another node": {func(s *probeSpec) {
			s.resp[pDestroy] = `"` + strings.Replace(upid690, "qa-pve-02", "qa-pve-01", 1) + `"`
		}, printed(upidFor("qa-pve-02", "qa-pve-01"))},
	} {
		t.Run(name, func(t *testing.T) {
			s := zfsWorld()
			c.edit(&s)
			r := runProbe(t, s)
			if r.code != 4 || !strings.Contains(r.stderr, notGone+c.want) {
				t.Errorf("exit %d, want 4 and %q:\n%s", r.code, notGone+c.want, r.stderr)
			}
			if _, ok := r.rule(); ok {
				t.Error("a probe that could not prove 690 gone wrote the rule")
			}
		})
	}
	// PVE's integer form is 690 too.
	s := zfsWorld()
	s.resp[pNextID] = `690`
	if r := runProbe(t, s); r.code != 0 {
		t.Errorf("nextid 690 as a number: exit %d\n%s", r.code, r.stderr)
	}
}

// P13: a signal mid-run: the probe exits 143 and cleanup still runs.
func TestProbe_SignalCleansUp(t *testing.T) {
	s := cleanupWorld()
	s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
	s.kill = map[string]map[int]string{pSnapS2: {1: "TERM"}}
	r := runProbe(t, s)
	if r.code != 143 {
		t.Fatalf("exit %d, want 143\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("cleanup did not run on the signal:\n%s", r.stderr)
	}
	if _, ok := r.rule(); ok {
		t.Error("an interrupted probe wrote the rule")
	}
}

// P14: after cleanup's destroy the volumes linger (ZFS frees
// asynchronously): cleanup waits, bounded by the clock, and names a leftover
// only when it detects one; the destroy task is the proof.
func TestProbe_CleanupWaitsForVolumes(t *testing.T) {
	const leftover = "LEFTOVER: VM 690 is destroyed, but the storage shows a leftover: "
	dies := func() probeSpec {
		s := cleanupWorld()
		s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
		s.rc[pSnapS2] = map[int]int{0: 5}
		return s
	}
	s := dies()
	s.seq[pContent] = map[int]string{2: oneVolume, 3: oneVolume}
	r := runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, "cleanup: VM 690 destroyed: its destroy task ended OK") || strings.Contains(r.stderr, "LEFTOVER") || r.sleeps != 2 {
		t.Errorf("exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	// A hidden leftover: the token is not shown a destroyed VM's volume, so
	// the listing is empty, but the usage never comes back.
	s = dies()
	s.gone[pStatus] = storageStatus("zfspool", gib600-(1<<30), "")
	r = runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, leftover+"storage pveforge-harness's used is 1073741824, not back within 1 MiB of its baseline 0 (after 180s)") || r.sleeps != 36 {
		t.Errorf("a hidden leftover: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	// A listed volume is a leftover even when the usage has come back.
	s = dies()
	s.resp[pContent] = oneVolume
	s.seq[pContent] = map[int]string{1: `[]`}
	r = runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, leftover+"storage pveforge-harness still lists volumes of VM(s) 690 (after 180s)") || r.sleeps != 36 {
		t.Errorf("volumes never go: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
	// A sleep that fails ends the wait there, and what was last seen is
	// reported; cleanup still reports.
	s = dies()
	s.seq[pContent] = map[int]string{2: oneVolume, 3: oneVolume}
	s.stubs = map[string]string{"sleep": "#!/usr/bin/env bash\necho \"$*\" >>\"$FAKE_PVEFORGE_DIR/sleep.log\"\nexit 1\n"}
	r = runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, leftover+"storage pveforge-harness still lists volumes of VM(s) 690 (sleep failed)") || r.sleeps != 1 {
		t.Errorf("a failing sleep: exit %d sleeps %d\n%s", r.code, r.sleeps, r.stderr)
	}
}

// P15: Ctrl-C and a hangup mid-run: exit 130 and 129, and cleanup still runs.
func TestProbe_IntAndHupCleanUp(t *testing.T) {
	for sig, code := range map[string]int{"INT": 130, "HUP": 129} {
		t.Run(sig, func(t *testing.T) {
			s := cleanupWorld()
			s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
			s.kill = map[string]map[int]string{pSnapS2: {1: sig}}
			r := runProbe(t, s)
			if r.code != code {
				t.Fatalf("exit %d, want %d\n%s", r.code, code, r.stderr)
			}
			equalCalls(t, "writes", r.writes(), []string{createCall, tagCall, snapS1, snapS2, delS1, destroy})
			if !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
				t.Errorf("cleanup did not run on %s:\n%s", sig, r.stderr)
			}
		})
	}
}

// dieAtS2 is cleanupWorld with s2's snapshot failing (pveforge's status 5)
// and held there until the test has acted.
func dieAtS2() probeSpec {
	s := cleanupWorld()
	s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
	s.rc[pSnapS2] = map[int]int{0: 5}
	s.block = pSnapS2
	return s
}

var dieAtS2Writes = []string{createCall, tagCall, snapS1, snapS2, delS1, destroy}

// P16: a terminal hung up after 690 exists (a closed ssh session): the probe
// gets its HUP, and cleanup, whose every write to the terminal now fails,
// still destroys 690 and records what it did.
func TestProbe_TerminalHangupCleansUp(t *testing.T) {
	s := dieAtS2()
	s.rc[pSnapS2] = nil // the snapshot succeeds; the hangup ends the run
	s.out = "pty"
	s.onBlock = func(t *testing.T, b blocked) { b.hangup() }
	r := runProbe(t, s)
	if r.code != 129 {
		t.Fatalf("exit %d, want 129", r.code)
	}
	equalCalls(t, "writes", r.writes(), []string{createCall, tagCall, snapS1, snapS2, delS1, destroy})
	if got := r.evidence(t, "CLEANUP"); !strings.Contains(got, "VM 690 destroyed") {
		t.Errorf("CLEANUP %q", got)
	}
}

// P17: stdout and stderr into a pipe whose reader has gone ("probe.sh 2>&1 |
// head -c 600"): cleanup's own writes cannot stop it.
func TestProbe_BrokenPipeCleansUp(t *testing.T) {
	s := dieAtS2()
	s.out = "pipe"
	s.onBlock = func(t *testing.T, b blocked) { b.hangup() }
	r := runProbe(t, s)
	// lib's own message about pveforge's failure is the first write to the
	// dead pipe: SIGPIPE's 141, and cleanup.
	if r.code != 141 {
		t.Fatalf("exit %d, want 141", r.code)
	}
	equalCalls(t, "writes", r.writes(), dieAtS2Writes)
	if got := r.evidence(t, "CLEANUP"); !strings.Contains(got, "VM 690 destroyed") {
		t.Errorf("CLEANUP %q", got)
	}
	// And when cleanup cannot remove 690, the report is still recorded.
	s = dieAtS2()
	s.out = "pipe"
	s.onBlock = func(t *testing.T, b blocked) { b.hangup() }
	stillThere(s)
	r = runProbe(t, s)
	if got := r.evidence(t, "LEFTOVER"); !strings.Contains(got, notProven) || !strings.Contains(got, "qm destroy 690 --purge") {
		t.Errorf("exit %d, LEFTOVER %q", r.code, got)
	}
}

// P18: a second Ctrl-C to the whole process group while cleanup deletes a
// snapshot: cleanup ignores it, still sends the destroy, and reports.
func TestProbe_CtrlCDuringCleanup(t *testing.T) {
	s := cleanupWorld()
	s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
	s.rc[pSnapS2] = map[int]int{0: 5}
	s.kill = map[string]map[int]string{pDelS1: {1: "group:INT"}}
	r := runProbe(t, s)
	if r.code != 5 {
		t.Fatalf("exit %d, want pveforge's 5\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), dieAtS2Writes)
	if !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("cleanup did not finish:\n%s", r.stderr)
	}
	// The same, with 690 left: the report is made.
	s.kill = map[string]map[int]string{pDelS1: {1: "group:INT"}, pDestroy: {1: "group:TERM"}}
	stillThere(s)
	r = runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, notProven) {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), dieAtS2Writes)
}

// P19: the evidence directory turns unwritable before cleanup: every cleanup
// step still runs, the report still reaches stderr, and pveforge's status
// stands.
func TestProbe_UnwritableEvidenceDuringCleanup(t *testing.T) {
	lock := func(t *testing.T, b blocked) {
		dirs, _ := filepath.Glob(filepath.Join(b.home, ".config/pveforge/harness-evidence/probe/*"))
		for _, d := range dirs {
			if err := os.Chmod(d, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(d, 0o700) })
		}
		if len(dirs) != 1 {
			t.Fatalf("evidence directories %q", dirs)
		}
	}
	s := dieAtS2()
	s.onBlock = lock
	r := runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), dieAtS2Writes)
	s = dieAtS2()
	s.onBlock = lock
	stillThere(s)
	r = runProbe(t, s)
	if r.code != 5 || !strings.Contains(r.stderr, notProven) || !strings.Contains(r.stderr, "qm destroy 690 --purge") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	equalCalls(t, "writes", r.writes(), dieAtS2Writes)
	// A failure found by the probe itself keeps its status too.
	// (690 is not proven gone after the destroy.)
	s = cleanupWorld()
	s.block = pNextID
	s.blockAt = 2 // the proof after the destroy; call 1 is the preflight's
	s.onBlock = lock
	stillThere(s)
	r = runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, "probe: VM 690 is not proven gone after the destroy") || !strings.Contains(r.stderr, "LEFTOVER: VM 690 is not proven gone after cleanup: ") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	// A refusal into an unwritable evidence directory keeps its status too.
	s = zfsWorld()
	s.seq[pPool] = nil
	s.block = pPool
	s.onBlock = lock
	if r := runProbe(t, s); r.code != 3 || !strings.Contains(r.stderr, "VM 690 already exists in pool") {
		t.Errorf("refusal: exit %d\n%s", r.code, r.stderr)
	}
}

// P20: the state and evidence directories are private even when they
// already exist with a looser mode.
func TestProbe_PrivateDirectories(t *testing.T) {
	state := func(home string) string { return filepath.Join(home, ".config/pveforge/harness-state") }
	evid := func(home string) string { return filepath.Join(home, ".config/pveforge/harness-evidence/probe") }
	mode := func(t *testing.T, p string) os.FileMode {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}
	r := runProbe(t, zfsWorld())
	if r.code != 0 || mode(t, state(r.home)) != 0o700 || mode(t, evid(r.home)) != 0o700 {
		t.Errorf("fresh: exit %d state %v evidence %v\n%s", r.code, mode(t, state(r.home)), mode(t, evid(r.home)), r.stderr)
	}
	s := zfsWorld()
	s.setup = func(t *testing.T, home string) {
		for _, d := range []string{state(home), evid(home)} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d, 0o777); err != nil {
				t.Fatal(err)
			}
		}
	}
	r = runProbe(t, s)
	if r.code != 0 || mode(t, state(r.home)) != 0o700 || mode(t, evid(r.home)) != 0o700 {
		t.Errorf("pre-existing 0777: exit %d state %v evidence %v\n%s", r.code, mode(t, state(r.home)), mode(t, evid(r.home)), r.stderr)
	}
}

// P21: the rule is written only when it lands as a regular file holding
// it: a directory at the rule's path, or an mv that claims success and
// writes nothing, is a failure, not a probe that exits 0.
func TestProbe_RuleWriteVerified(t *testing.T) {
	s := zfsWorld()
	s.setup = func(t *testing.T, home string) {
		if err := os.MkdirAll(filepath.Join(home, ".config/pveforge/harness-state/rollback-rule.pveforge-harness"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := runProbe(t, s)
	if r.code != 4 || !strings.Contains(r.stderr, "cannot write the rule") || strings.Contains(r.stdout, "rollback-rule=") {
		t.Errorf("a directory at the rule's path: exit %d stdout %q\n%s", r.code, r.stdout, r.stderr)
	}
	for name, mv := range map[string]string{
		"an mv that writes nothing": "exit 0",
		// mv -f -T -- tmp rule: the rule's path becomes a symlink to a
		// file that does hold the rule.
		"a symlink at the rule's path": `exec ln -sfn -- "$4" "$5"`,
	} {
		s = zfsWorld()
		s.stubs = map[string]string{"mv": "#!/usr/bin/env bash\n" + mv + "\n"}
		r = runProbe(t, s)
		if r.code != 4 || !strings.Contains(r.stderr, "is not a regular file holding 'rollback-latest-only'") || strings.Contains(r.stdout, "rollback-rule=") {
			t.Errorf("%s: exit %d stdout %q\n%s", name, r.code, r.stdout, r.stderr)
		}
	}
}

// P22: cleanup takes 690 as gone only on a positive proof: an error that
// says "does not exist", another VMID, or a pool that still lists it is a
// leftover, never "destroyed".
func TestProbe_CleanupGoneNeedsPositiveProof(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(s *probeSpec)
		want string
	}{
		"does-not-exist text": {func(s *probeSpec) {
			s.goneRC = map[string]int{pNextID: 1}
			s.err[pNextID] = map[int]string{0: "Configuration file 'nodes/qa-pve-02/qemu-server/690.conf' does not exist"}
		}, "/cluster/nextid did not answer 200 for VMID 690"},
		"another VMID":      {func(s *probeSpec) { s.gone[pNextID] = `"691"` }, "/cluster/nextid answered 200 for VMID 690, but not with 690"},
		"still in the pool": {func(s *probeSpec) { s.keepInPool = []string{"690"} }, "pool pveforge-harness still lists VM 690"},
	} {
		t.Run(name, func(t *testing.T) {
			s := cleanupWorld()
			s.resp[pSnaps] = `[{"name":"current"},{"name":"s1","snaptime":100}]`
			s.rc[pSnapS2] = map[int]int{0: 5}
			c.edit(&s)
			r := runProbe(t, s)
			if r.code != 5 || !strings.Contains(r.stderr, "LEFTOVER: VM 690 is not proven gone after cleanup: "+c.want) || strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
				t.Errorf("exit %d\n%s", r.code, r.stderr)
			}
		})
	}
}

// P22b: a destroy whose pveforge call fails with nothing on stdout (a wait
// that failed or timed out) is never proven gone, even when nextid and the
// pool both say gone: only the task shows whether PVE freed the disks.
func TestProbe_DestroyWithoutAnswerIsNotProven(t *testing.T) {
	s := zfsWorld()
	s.rc[pDestroy] = map[int]int{0: 1}
	s.resp[pDestroy] = ""
	s.destroyLands = []string{"690"}
	r := runProbe(t, s)
	if r.code != 1 || !strings.Contains(r.stderr, "LEFTOVER: VM 690 is not proven gone after cleanup: the destroy of VM 690 printed no task UPID") ||
		strings.Contains(r.stderr, "cleanup: VM 690 destroyed") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	if _, ok := r.rule(); ok {
		t.Error("an unproven destroy wrote the rule")
	}
}

// P22c: the main destroy ended in WARNINGS, and cleanup's re-destroy is
// refused (690 left the pool): the report keeps the real cause, the task.
func TestProbe_CleanupKeepsTheRealCause(t *testing.T) {
	s := zfsWorld()
	s.resp[pTask] = taskStatus(upid690, "qa-pve-02", "qmdestroy", "690", "stopped", "WARNINGS: 1")
	r := runProbe(t, s)
	want := "LEFTOVER: VM 690 is not proven gone after cleanup: the destroy task " + upid690 + " is not a stopped qmdestroy of VM 690 on qa-pve-02 with exitstatus OK"
	if r.code != 4 || !strings.Contains(r.stderr, want) || strings.Contains(r.stderr, "printed no task UPID") {
		t.Errorf("exit %d, want %q\n%s", r.code, want, r.stderr)
	}
}

// P23: a create that failed and left nothing: no leftover is reported.
func TestProbe_CreateFailedNothingAppeared(t *testing.T) {
	s := zfsWorld()
	s.rc[pCreate] = map[int]int{0: 1}
	s.seq[pPool] = map[int]string{1: emptyPool, 2: emptyPool}
	r := runProbe(t, s)
	if r.code != 1 || strings.Contains(r.stderr, "LEFTOVER") {
		t.Errorf("exit %d\n%s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(r.evidenceDir(t), "LEFTOVER")); err == nil {
		t.Error("a LEFTOVER was recorded")
	}
	equalCalls(t, "writes", r.writes(), []string{createCall})
}
