package sourceguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// golden.sh and reset.sh (pveforge-harness-golden-reset) run offline here,
// against U1's sequenced fake pveforge (the capability probe's static layer
// included, as its own process) and a fake acceptance command that logs its
// arguments and exits as told.

const (
	grStatus = "get /nodes/qa-pve-02/storage/pveforge-harness/status"
	grPool   = "get /pools poolid=pveforge-harness"
	grMember = `{"type":"qemu","vmid":%d,"node":"qa-pve-02"}`
	// grStamp is the run stamp every run here reads from its fixed clock;
	// grOld is an earlier golden.sh run's.
	grStamp = "20260924T120000Z"
	grOld   = "20260101T000000Z"
	grDesc  = "pveforge harness golden point "
)

// grGolden is a snapshot list entry for pvh-golden stamped stamp (JSON).
func grGolden(snaptime int, stamp string, extra string) string {
	return fmt.Sprintf(`{"name":"pvh-golden","snaptime":%d,"description":"%s%s"%s}`, snaptime, grDesc, stamp, extra)
}

func grKey(verb string, vmid int, sub string) string {
	k := fmt.Sprintf("%s /nodes/qa-pve-02/qemu/%d", verb, vmid)
	if sub != "" {
		k += "/" + sub
	}
	return k
}

// grSpec is one run's fake world.
type grSpec struct {
	resp      map[string]string
	seq       map[string]map[int]string // key -> call number -> stdout
	rc        map[string]map[int]int    // key -> call number (0: every call) -> status
	acceptRC  map[int]int               // acceptance call number -> status
	args      []string
	env       map[string]string
	noAccept  bool // HARNESS_ACCEPT_BIN unset
	noRosters bool // the nested and outer harness rosters unset
}

type grResult struct {
	code         int
	stderr       string
	calls        []string
	accepts      []string
	steps        string
	evidenceRoot string
}

// writes are the calls that change something, in order.
func (r grResult) writes() []string {
	var w []string
	for _, c := range r.calls {
		if isWrite(c) {
			w = append(w, c)
		}
	}
	return w
}

// grWorld: 690-692 built, tagged, pool members on qa-pve-02, each running
// and stopping when told, each with pvh-golden (t=1000, all three stamped
// grOld), an older snapshot (t=500) and two later ones (t=2000, t=3000).
func grWorld() grSpec {
	var members []string
	for _, v := range []int{690, 691, 692} {
		members = append(members, fmt.Sprintf(grMember, v))
	}
	s := grSpec{
		resp: map[string]string{
			grStatus: `{"type":"zfspool","enabled":1,"active":1,"content":"images","avail":107374182400,"total":644245094400,"used":0}`,
			grPool:   `[{"poolid":"pveforge-harness","members":[` + strings.Join(members, ",") + `]}]`,
		},
		seq:  map[string]map[int]string{},
		rc:   map[string]map[int]int{},
		args: []string{"--storage", "pveforge-harness"},
	}
	for _, v := range []int{690, 691, 692} {
		s.resp[grKey("get", v, "config")] = fmt.Sprintf(`{"scsi0":"pveforge-harness:vm-%d-disk-0,size=128G","tags":"pveforge-harness","cores":"8"}`, v)
		s.resp[grKey("get", v, "snapshot")] = `[{"name":"early","snaptime":500},` + grGolden(1000, grOld, `,"parent":"early"`) + `,{"name":"t1","snaptime":2000,"parent":"pvh-golden"},{"name":"t2","snaptime":3000,"parent":"t1"},{"name":"current","parent":"t2","running":1}]`
		s.resp[grKey("get", v, "status/current")] = `{"status":"stopped"}`
		s.seq[grKey("get", v, "status/current")] = map[int]string{1: `{"status":"running"}`}
	}
	return s
}

func runGR(t *testing.T, script string, s grSpec) grResult {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(harnessDir, script))
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
	work := filepath.Join(tmp, "work")
	for _, d := range []string{cfg, work, filepath.Join(fakeDir, "resp"), filepath.Join(fakeDir, "rc")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, v string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(v), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(cfg, "harness-outer.toml"), "# test roster\n", 0o600)
	put := func(dir, key string, n int, v string) {
		name := fakeKey(key)
		if n > 0 {
			name += fmt.Sprintf(".%d", n)
		}
		write(filepath.Join(fakeDir, dir, name), v, 0o600)
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
	accept := filepath.Join(tmp, "fake-accept")
	write(accept, `#!/usr/bin/env bash
n=1; [ -f "$FAKE_PVEFORGE_DIR/accept.n" ] && n=$(( $(cat "$FAKE_PVEFORGE_DIR/accept.n") + 1 ))
echo "$n" >"$FAKE_PVEFORGE_DIR/accept.n"
echo "$*" >>"$FAKE_PVEFORGE_DIR/accept.log"
rc=0; [ -f "$FAKE_PVEFORGE_DIR/accept.rc.$n" ] && rc=$(cat "$FAKE_PVEFORGE_DIR/accept.rc.$n")
exit "$rc"
`, 0o700)
	for n, rc := range s.acceptRC {
		write(filepath.Join(fakeDir, fmt.Sprintf("accept.rc.%d", n)), fmt.Sprint(rc), 0o600)
	}
	// A fixed clock for the run stamp, first on PATH; every other use of date
	// is the real one.
	realDate, err := exec.LookPath("date")
	if err != nil {
		t.Fatal(err)
	}
	clock := filepath.Join(tmp, "clock")
	if err := os.MkdirAll(clock, 0o700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(clock, "date"), `#!/usr/bin/env bash
if [ "$*" = "-u +%Y%m%dT%H%M%SZ" ]; then echo `+grStamp+`; exit 0; fi
exec `+realDate+` "$@"
`, 0o700)
	pathVar := clock + ":" + harnessPATH(t)
	for _, tool := range []string{"mv", "chmod", "sleep", "go", "dirname"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		pathVar += ":" + filepath.Dir(p)
	}
	env := map[string]string{
		"PATH": pathVar, "HOME": home, "PVEFORGE_BIN": fake, "FAKE_PVEFORGE_DIR": fakeDir,
		"PVEFORGE_ROSTER_PASSPHRASE":     "not-a-secret",
		"PVEFORGE_HARNESS_ROSTER":        filepath.Join(cfg, "harness-nested.toml"),
		"PVEFORGE_HARNESS_OUTER_ROSTERS": filepath.Join(cfg, "harness-outer.toml"),
		"HARNESS_ACCEPT_BIN":             accept,
	}
	if s.noAccept {
		delete(env, "HARNESS_ACCEPT_BIN")
	}
	if s.noRosters {
		delete(env, "PVEFORGE_HARNESS_ROSTER")
		delete(env, "PVEFORGE_HARNESS_OUTER_ROSTERS")
	}
	for k, v := range s.env {
		env[k] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append([]string{path}, s.args...)...)
	cmd.Dir = work
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var errOut bytes.Buffer
	cmd.Stdout = &errOut
	cmd.Stderr = &errOut
	err = cmd.Run()
	r := grResult{stderr: errOut.String(), evidenceRoot: filepath.Join(cfg, "harness-evidence")}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
	}
	read := func(p string) []string {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var out []string
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	r.calls = read(filepath.Join(fakeDir, "argv.log"))
	r.accepts = read(filepath.Join(fakeDir, "accept.log"))
	what := strings.TrimSuffix(script, ".sh")
	if ms, _ := filepath.Glob(filepath.Join(r.evidenceRoot, what, "*", "steps")); len(ms) == 1 {
		b, _ := os.ReadFile(ms[0])
		r.steps = string(b)
	}
	return r
}

func vmWrite(verb string, vmid int, sub string, fields ...string) string {
	c := fmt.Sprintf("api %s /nodes/qa-pve-02/qemu/%d", verb, vmid)
	if sub != "" {
		c += "/" + sub
	}
	c += " qa-pve-02-harness --roster R -o json"
	for _, f := range fields {
		c += " --data " + f
	}
	return c
}

func grExpect(t *testing.T, r grResult, code int, writes []string, accepts []string, errText string) {
	t.Helper()
	if r.code != code {
		t.Errorf("exit %d, want %d\n%s", r.code, code, r.stderr)
	}
	got := make([]string, 0, len(r.writes()))
	for _, w := range r.writes() {
		got = append(got, regexp.MustCompile(`--roster \S+`).ReplaceAllString(w, "--roster R"))
	}
	if strings.Join(got, "\n") != strings.Join(writes, "\n") {
		t.Errorf("writes:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(writes, "\n  "))
	}
	if accepts != nil && strings.Join(r.accepts, "\n") != strings.Join(accepts, "\n") {
		t.Errorf("acceptance calls %q, want %q", r.accepts, accepts)
	}
	if r.code == 0 && (r.steps == "" || strings.Contains(r.steps, "FAILED")) {
		t.Errorf("a passing run's evidence is missing or records a failure:\n%s", r.steps)
	}
	if errText != "" && !strings.Contains(r.stderr, errText) {
		t.Errorf("output does not contain %q:\n%s", errText, r.stderr)
	}
	for _, w := range r.writes() {
		if regexp.MustCompile(`^api delete /nodes/qa-pve-02/qemu/\d+ `).MatchString(w) {
			t.Errorf("a VM was destroyed: %s", w)
		}
	}
}

// resetWrites is the full reset: stops (nodes first), each VM's cascade
// newest first (t2, t1) then its rollback, starts (storage first).
func resetWrites(stopped ...int) []string {
	return resetWritesCascade([]string{"t2", "t1"}, stopped...)
}

// resetWritesCascade is the reset deleting cascade, in order, from each VM.
func resetWritesCascade(cascade []string, stopped ...int) []string {
	skip := map[int]bool{}
	for _, v := range stopped {
		skip[v] = true
	}
	var w []string
	for _, v := range []int{691, 690, 692} {
		if !skip[v] {
			w = append(w, vmWrite("post", v, "status/stop"))
		}
	}
	for _, v := range []int{690, 691, 692} {
		for _, snap := range cascade {
			w = append(w, vmWrite("delete", v, "snapshot/"+snap))
		}
		w = append(w, vmWrite("post", v, "snapshot/pvh-golden/rollback"))
	}
	for _, v := range []int{692, 690, 691} {
		w = append(w, vmWrite("post", v, "status/start"))
	}
	return w
}

func TestReset_TheFullReset(t *testing.T) {
	r := runGR(t, "reset.sh", grWorld())
	grExpect(t, r, 0, resetWrites(), []string{"-deadline 15m"}, "")
	if !strings.Contains(r.steps, "the goldens are one point: stamp "+grOld) || !strings.Contains(r.steps, "RESULT reset to pvh-golden") {
		t.Errorf("evidence steps:\n%s", r.steps)
	}
	// The probe's static layer ran first, as its own process: the storage
	// status is the very first read.
	if len(r.calls) == 0 || r.calls[0] != "api get /nodes/qa-pve-02/storage/pveforge-harness/status qa-pve-02-harness --roster "+regexp.MustCompile(`--roster (\S+)`).FindStringSubmatch(r.calls[0])[1]+" -o json" {
		t.Errorf("first call %q, want the probe's storage status read", r.calls)
	}
}

func TestReset_AnAlreadyStoppedVMIsNotStoppedAgain(t *testing.T) {
	s := grWorld()
	delete(s.seq, grKey("get", 690, "status/current"))
	r := runGR(t, "reset.sh", s)
	grExpect(t, r, 0, resetWrites(690), nil, "")
}

// The commonest reset: nothing was snapshotted since the golden point, so
// there is no cascade, only the stops, rollbacks and starts.
func TestReset_NothingNewerThanTheGolden(t *testing.T) {
	s := grWorld()
	for _, v := range []int{690, 691, 692} {
		s.resp[grKey("get", v, "snapshot")] = `[{"name":"early","snaptime":500},` + grGolden(1000, grOld, `,"parent":"early"`) + `,{"name":"current","parent":"pvh-golden","running":1}]`
	}
	// A description can read back with a trailing newline; the stamp is the same.
	s.resp[grKey("get", 691, "snapshot")] = `[` + grGolden(1000, grOld+`\n`, "") + `,{"name":"current"}]`
	r := runGR(t, "reset.sh", s)
	grExpect(t, r, 0, resetWritesCascade(nil), []string{"-deadline 15m"}, "")
	if strings.Contains(r.steps, "deleted") {
		t.Errorf("the evidence records a delete:\n%s", r.steps)
	}
}

// The cascade is by time, never by name: here the names sort opposite to
// the times, and the newest (aa, t=3000) goes first.
func TestReset_TheCascadeIsByTimeNotName(t *testing.T) {
	s := grWorld()
	for _, v := range []int{690, 691, 692} {
		s.resp[grKey("get", v, "snapshot")] = `[{"name":"aa","snaptime":3000,"parent":"mm"},` + grGolden(1000, grOld, "") + `,{"name":"zz","snaptime":2000,"parent":"pvh-golden"},{"name":"mm","snaptime":2500,"parent":"zz"},{"name":"current","parent":"aa"}]`
	}
	r := runGR(t, "reset.sh", s)
	grExpect(t, r, 0, resetWritesCascade([]string{"aa", "mm", "zz"}), []string{"-deadline 15m"}, "")
}

func TestReset_RefusedBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*grSpec)
		code   int
		want   string
	}{
		{"no golden", func(s *grSpec) {
			s.resp[grKey("get", 691, "snapshot")] = `[{"name":"t1","snaptime":2000},{"name":"current"}]`
		}, 2, "exactly one pvh-golden"},
		{"two snapshots at one time", func(s *grSpec) {
			s.resp[grKey("get", 692, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000},{"name":"t1","snaptime":2000},{"name":"t2","snaptime":2000},{"name":"current"}]`
		}, 2, "no two at the same time"},
		{"a snapshot without a time", func(s *grSpec) {
			s.resp[grKey("get", 690, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000},{"name":"t1"},{"name":"current"}]`
		}, 2, "a time on each"},
		{"a snapshot list of the wrong shape", func(s *grSpec) {
			s.resp[grKey("get", 690, "snapshot")] = `{}`
		}, 1, "unexpected shape"},
		{"system disk on another storage", func(s *grSpec) {
			s.resp[grKey("get", 691, "config")] = `{"scsi0":"local-lvm:vm-691-disk-0","tags":"pveforge-harness"}`
		}, 2, "not the required storage"},
		{"a lock", func(s *grSpec) {
			s.resp[grKey("get", 692, "config")] = `{"scsi0":"pveforge-harness:vm-692-disk-0","tags":"pveforge-harness","lock":"rollback"}`
		}, 2, "qm unlock 692"},
		{"the probe refuses the storage", func(s *grSpec) {
			s.resp[grStatus] = `{"type":"zfspool","enabled":1,"active":0,"content":"images","avail":107374182400}`
		}, 3, "static layer refused"},
		{"the reset's free-space floor", func(s *grSpec) {
			s.resp[grStatus] = `{"type":"zfspool","enabled":1,"active":1,"content":"images","avail":10737418240}`
		}, 3, "static layer refused"},
		{"goldens of two points", func(s *grSpec) {
			s.resp[grKey("get", 692, "snapshot")] = `[` + grGolden(1000, "20260102T000000Z", "") + `,{"name":"current"}]`
		}, 2, "the goldens are not one point: 690=" + grOld + " 691=" + grOld + " 692=20260102T000000Z"},
		{"a golden taken with its memory", func(s *grSpec) {
			s.resp[grKey("get", 691, "snapshot")] = `[` + grGolden(1000, grOld, `,"vmstate":1`) + `,{"name":"current"}]`
		}, 2, "must be disk-only (vmstate 0)"},
		{"a golden with no stamp", func(s *grSpec) {
			s.resp[grKey("get", 690, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point"},{"name":"current"}]`
		}, 2, "carry golden.sh's run stamp"},
		{"a golden with no description", func(s *grSpec) {
			s.resp[grKey("get", 690, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000},{"name":"current"}]`
		}, 2, "carry golden.sh's run stamp"},
		{"no golden stamped", func(s *grSpec) {
			for _, v := range []int{690, 691, 692} {
				s.resp[grKey("get", v, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000,"description":"pveforge harness golden point"},{"name":"current"}]`
			}
		}, 2, "carry golden.sh's run stamp"},
		{"a bare stamp without golden.sh's prefix", func(s *grSpec) {
			for _, v := range []int{690, 691, 692} {
				s.resp[grKey("get", v, "snapshot")] = `[{"name":"pvh-golden","snaptime":1000,"description":"` + grOld + `"},{"name":"current"}]`
			}
		}, 2, "carry golden.sh's run stamp"},
		{"a stamp with a line after it", func(s *grSpec) {
			for _, v := range []int{690, 691, 692} {
				s.resp[grKey("get", v, "snapshot")] = `[` + grGolden(1000, grOld+`\nmore`, "") + `,{"name":"current"}]`
			}
		}, 2, "carry golden.sh's run stamp"},
		{"a stamp with two trailing newlines", func(s *grSpec) {
			for _, v := range []int{690, 691, 692} {
				s.resp[grKey("get", v, "snapshot")] = `[` + grGolden(1000, grOld+`\n\n`, "") + `,{"name":"current"}]`
			}
		}, 2, "carry golden.sh's run stamp"},
		{"a golden whose stamp is not a stamp", func(s *grSpec) {
			s.resp[grKey("get", 690, "snapshot")] = `[` + grGolden(1000, "20260101T000000Z trailing", "") + `,{"name":"current"}]`
		}, 2, "carry golden.sh's run stamp"},
		{"no nested roster", func(s *grSpec) { s.noRosters = true }, 2, "PVEFORGE_HARNESS_ROSTER"},
		{"no storage", func(s *grSpec) { s.args = nil }, 2, "there is no default"},
		{"an unknown argument", func(s *grSpec) { s.args = append(s.args, "--force") }, 2, "unknown argument"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := grWorld()
			c.mutate(&s)
			r := runGR(t, "reset.sh", s)
			grExpect(t, r, c.code, nil, []string{}, c.want)
		})
	}
}

// The reset's free-space floor is its own, not the pre-build 520 GiB: 100
// GiB free passes (grWorld), 10 GiB does not (above).
func TestReset_ThePreBuildFloorIsNotApplied(t *testing.T) {
	s := grWorld()
	s.env = map[string]string{"HARNESS_RESET_MIN_FREE_GIB": "200"}
	r := runGR(t, "reset.sh", s)
	grExpect(t, r, 3, nil, []string{}, "below HARNESS_PROBE_MIN_FREE_GIB=200")
}

func TestReset_StopsWhereItFails(t *testing.T) {
	t.Run("a stop that leaves the VM running", func(t *testing.T) {
		s := grWorld()
		s.seq[grKey("get", 690, "status/current")] = map[int]string{1: `{"status":"running"}`, 2: `{"status":"running"}`}
		r := runGR(t, "reset.sh", s)
		grExpect(t, r, 1, []string{vmWrite("post", 691, "status/stop"), vmWrite("post", 690, "status/stop")}, []string{}, "'running' after its stop reported success")
	})
	t.Run("a failed rollback", func(t *testing.T) {
		s := grWorld()
		s.rc[grKey("post", 691, "snapshot/pvh-golden/rollback")] = map[int]int{0: 1}
		r := runGR(t, "reset.sh", s)
		w := resetWrites()
		// Everything up to and including 691's rollback; no 692 cascade, no start.
		grExpect(t, r, 1, w[:3+6], []string{}, "")
		if !strings.Contains(r.steps, "VM 690: rolled back to pvh-golden") || strings.Contains(r.steps, "VM 691: rolled back") || !strings.HasSuffix(r.steps, "FAILED exit 1\n") {
			t.Errorf("the evidence does not say how far it got:\n%s", r.steps)
		}
	})
	t.Run("acceptance fails", func(t *testing.T) {
		s := grWorld()
		s.acceptRC = map[int]int{1: 1}
		r := runGR(t, "reset.sh", s)
		grExpect(t, r, 1, resetWrites(), []string{"-deadline 15m"}, "was not accepted")
		if !strings.Contains(r.steps, "FAILED accept") || strings.Contains(r.steps, "FAILED exit") {
			t.Errorf("the evidence does not record the failure once:\n%s", r.steps)
		}
	})
	t.Run("acceptance's own exit status passes through", func(t *testing.T) {
		s := grWorld()
		s.acceptRC = map[int]int{1: 143}
		r := runGR(t, "reset.sh", s)
		grExpect(t, r, 143, resetWrites(), []string{"-deadline 15m"}, "(exit 143)")
	})
	t.Run("a failed start", func(t *testing.T) {
		s := grWorld()
		s.rc[grKey("post", 690, "status/start")] = map[int]int{0: 1}
		r := runGR(t, "reset.sh", s)
		w := resetWrites()
		grExpect(t, r, 1, w[:len(w)-1], []string{}, "")
		if !strings.HasSuffix(r.steps, "FAILED exit 1\n") {
			t.Errorf("the evidence does not end in the failure:\n%s", r.steps)
		}
	})
}

// goldenWorld: 690-692 running, no pvh-golden yet; each snapshot read after
// the snapshot is taken shows it.
func goldenWorld() grSpec {
	s := grWorld()
	for _, v := range []int{690, 691, 692} {
		// golden reads a VM's status only after its shutdown.
		delete(s.seq, grKey("get", v, "status/current"))
		s.resp[grKey("get", v, "snapshot")] = `[{"name":"current","running":1}]`
		s.seq[grKey("get", v, "snapshot")] = map[int]string{2: `[` + grGolden(1000, grStamp, "") + `,{"name":"current"}]`}
	}
	// A description can read back with a trailing newline.
	s.seq[grKey("get", 692, "snapshot")][2] = `[` + grGolden(1000, grStamp+`\n`, "") + `,{"name":"current"}]`
	return s
}

// goldenWrites is the golden point: shutdowns (nodes first), with replace
// every old golden deleted, then every new one taken, then starts.
func goldenWrites(replace bool) []string {
	var w []string
	for _, v := range []int{691, 690, 692} {
		w = append(w, vmWrite("post", v, "status/shutdown", "timeout=300"))
	}
	if replace {
		for _, v := range []int{690, 691, 692} {
			w = append(w, vmWrite("delete", v, "snapshot/pvh-golden"))
		}
	}
	for _, v := range []int{690, 691, 692} {
		w = append(w, vmWrite("post", v, "snapshot", "snapname=pvh-golden", "vmstate=0", "description="+grDesc+grStamp))
	}
	for _, v := range []int{692, 690, 691} {
		w = append(w, vmWrite("post", v, "status/start"))
	}
	return w
}

func TestGolden_TheGoldenPoint(t *testing.T) {
	r := runGR(t, "golden.sh", goldenWorld())
	grExpect(t, r, 0, goldenWrites(false), []string{"-deadline 5m", "-deadline 15m"}, "")
	if !strings.Contains(r.steps, "RESULT golden point taken") || strings.Contains(r.steps, "no golden exists") {
		t.Errorf("evidence steps:\n%s", r.steps)
	}
}

func TestGolden_AnExistingGolden(t *testing.T) {
	s := grWorld() // every VM already has pvh-golden
	r := runGR(t, "golden.sh", s)
	grExpect(t, r, 2, nil, []string{}, "needs --replace-golden")

	s = grWorld()
	s.args = append(s.args, "--replace-golden")
	for _, v := range []int{690, 691, 692} {
		delete(s.seq, grKey("get", v, "status/current")) // read only after the shutdown
		// before: golden present; at the replace: golden present; read back: the new one.
		s.seq[grKey("get", v, "snapshot")] = map[int]string{3: `[` + grGolden(4000, grStamp, "") + `,{"name":"current"}]`}
	}
	r = runGR(t, "golden.sh", s)
	grExpect(t, r, 0, goldenWrites(true), []string{"-deadline 5m", "-deadline 15m"}, "")
	// Every old golden is gone, and that recorded, before any new one.
	gone := strings.Index(r.steps, "no golden exists on 690 691 692")
	if gone < 0 || gone < strings.LastIndex(r.steps, "old pvh-golden deleted") || gone > strings.Index(r.steps, "VM 690: pvh-golden taken") {
		t.Errorf("evidence steps:\n%s", r.steps)
	}
}

// A replace that fails part-way stops there, and the evidence names each
// VM's golden: old, none or new.
func TestGolden_AReplaceThatFails(t *testing.T) {
	replaceWorld := func() grSpec {
		s := grWorld()
		s.args = append(s.args, "--replace-golden")
		for _, v := range []int{690, 691, 692} {
			delete(s.seq, grKey("get", v, "status/current"))
			s.seq[grKey("get", v, "snapshot")] = map[int]string{3: `[` + grGolden(4000, grStamp, "") + `,{"name":"current"}]`}
		}
		return s
	}
	t.Run("the second old golden's delete", func(t *testing.T) {
		s := replaceWorld()
		s.rc[grKey("delete", 691, "snapshot/pvh-golden")] = map[int]int{0: 1}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(true)[:5], []string{"-deadline 5m"}, "golden state: 690=none 691=old 692=old")
		if !strings.HasSuffix(r.steps, "FAILED exit 1; golden state: 690=none 691=old 692=old\n") || strings.Contains(r.steps, "no golden exists") {
			t.Errorf("evidence steps:\n%s", r.steps)
		}
	})
	t.Run("the second new golden", func(t *testing.T) {
		s := replaceWorld()
		s.rc[grKey("post", 691, "snapshot")+" snapname=pvh-golden vmstate=0 description="+grDesc+grStamp] = map[int]int{0: 1}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(true)[:8], []string{"-deadline 5m"}, "golden state: 690=new 691=none 692=none")
		if !strings.Contains(r.steps, "no golden exists on 690 691 692") || !strings.HasSuffix(r.steps, "FAILED exit 1; golden state: 690=new 691=none 692=none\n") {
			t.Errorf("evidence steps:\n%s", r.steps)
		}
	})
	t.Run("a new golden that does not read back", func(t *testing.T) {
		s := replaceWorld()
		s.seq[grKey("get", 690, "snapshot")] = map[int]string{3: `[{"name":"current"}]`}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(true)[:7], []string{"-deadline 5m"}, "does not read back")
		if !strings.HasSuffix(r.steps, "FAILED; golden state: 690=new 691=none 692=none\n") {
			t.Errorf("evidence steps:\n%s", r.steps)
		}
	})
}

func TestGolden_NeverOfABrokenCluster(t *testing.T) {
	s := goldenWorld()
	s.acceptRC = map[int]int{1: 1}
	r := runGR(t, "golden.sh", s)
	grExpect(t, r, 1, nil, []string{"-deadline 5m"}, "before the golden point")

	s = goldenWorld()
	s.acceptRC = map[int]int{1: 130}
	r = runGR(t, "golden.sh", s)
	grExpect(t, r, 130, nil, []string{"-deadline 5m"}, "(exit 130)")
}

func TestGolden_StopsWhereItFails(t *testing.T) {
	t.Run("a shutdown that leaves the VM running", func(t *testing.T) {
		s := goldenWorld()
		s.seq[grKey("get", 691, "status/current")] = map[int]string{1: `{"status":"running"}`}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(false)[:1], []string{"-deadline 5m"}, "'running' after its stop reported success")
	})
	t.Run("a golden that does not read back", func(t *testing.T) {
		s := goldenWorld()
		s.seq[grKey("get", 690, "snapshot")] = map[int]string{2: `[{"name":"current"}]`}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(false)[:4], []string{"-deadline 5m"}, "does not read back")
	})
	t.Run("a golden taken with its memory", func(t *testing.T) {
		s := goldenWorld()
		s.seq[grKey("get", 690, "snapshot")] = map[int]string{2: `[` + grGolden(1000, grStamp, `,"vmstate":1`) + `,{"name":"current"}]`}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(false)[:4], []string{"-deadline 5m"}, "does not read back")
	})
	t.Run("a golden without this run's stamp", func(t *testing.T) {
		s := goldenWorld()
		s.seq[grKey("get", 690, "snapshot")] = map[int]string{2: `[` + grGolden(1000, grOld, "") + `,{"name":"current"}]`}
		r := runGR(t, "golden.sh", s)
		grExpect(t, r, 1, goldenWrites(false)[:4], []string{"-deadline 5m"}, "does not read back as one disk-only snapshot stamped "+grStamp)
	})
}

// Neither script can destroy a VM: they name no destroy, and every run above
// checks its writes for one.
func TestGoldenReset_NeverDestroy(t *testing.T) {
	for _, f := range []string{"golden.sh", "reset.sh", "golden-reset.sh"} {
		b, err := os.ReadFile(filepath.Join(harnessDir, f))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("harness_vm_destroy")) || bytes.Contains(b, []byte("api delete")) {
			t.Errorf("%s names a destroy", f)
		}
	}
}
