package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/nodump"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// `pveforge exec` is tested through the whole CLI: the test binary is
// re-executed as pveforge (cliChildEnv, realMain), and pveforge execve's the
// test binary again as its command, the exec probe, which records what it
// was given. The probe's record goes to a file of its own, so pveforge's
// stdout and stderr are exactly what the test captures.

// execProbeArg and dumpableProbeArg, as the first argument, make this test
// binary a probe (TestMain dispatches on them).
const (
	execProbeArg     = "__pveforge_exec_probe__"
	dumpableProbeArg = "__pveforge_dumpable_probe__"
)

// execProbeRecord is what the exec probe saw of itself.
type execProbeRecord struct {
	Env     []string
	Cmdline []byte // /proc/self/cmdline, or the argv joined by NULs off Linux
}

// runExecProbe records itself into args[0], then ends as args[1] says:
// "exit:N" exits N, "signal:N" kills itself with signal N. Any further
// arguments are recorded but ignored, so a secret appended to argv is
// caught by X3's own check rather than by the probe refusing to run.
func runExecProbe(args []string) int {
	if len(args) < 2 {
		return 97
	}
	cmdline, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		cmdline = []byte(strings.Join(os.Args, "\x00") + "\x00")
	}
	b, err := json.Marshal(execProbeRecord{Env: os.Environ(), Cmdline: cmdline})
	if err != nil || os.WriteFile(args[0], b, 0o600) != nil {
		return 98
	}
	how, n, _ := strings.Cut(args[1], ":")
	code, err := strconv.Atoi(n)
	if err != nil {
		return 99
	}
	if how == "signal" {
		_ = syscall.Kill(os.Getpid(), syscall.Signal(code))
		select {}
	}
	return code
}

// runDumpableProbe runs the production nodump.Set and prints the flag
// the kernel then reports for this process.
func runDumpableProbe() int {
	if err := nodump.Set(); err != nil {
		fmt.Println("error:", err)
		return 1
	}
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		fmt.Println("error:", errno)
		return 1
	}
	fmt.Println("dumpable:", r)
	return 0
}

const (
	// execSecret mixes cases and never runs four digits together, so no
	// 4-byte window of it can turn up by chance in a temp path or a PID.
	execSecret     = "Zq9X-vJw3-KpYh-1Vb8-NmUg-4Tr6-QxWz"
	execSSHKey     = "SSH-PRIVATE-KEY-MATERIAL-5b1f0c7e"
	execPassphrase = "exec-test-passphrase"
	execTokenID    = "ops@pve!ci"
)

// execFixture is one run's roster and directories.
type execFixture struct {
	rosterDir, roster, tmpDir, probeDir, record, covDir string
}

// newExecFixture writes a roster holding:
//   - qa-exp: exportable, with a token and an SSH key;
//   - qa-noexp: a token and an SSH key, not exportable;
//   - qa-notoken: exportable, with no token.
func newExecFixture(t *testing.T) execFixture {
	t.Helper()
	enc := func(s string) string {
		a, err := fixtureEncrypt([]byte(s), execPassphrase)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	target := func(id, export string, auth bool) string {
		s := fmt.Sprintf("[[targets]]\nid = %q\nhost = \"%s.example.com\"\nnode = %q\n", id, id, id)
		if export != "" {
			s += fmt.Sprintf("export = %q\n", export)
		}
		if auth {
			s += fmt.Sprintf("\n[targets.token]\nid = %q\nsecret_enc = '''\n%s'''\n", execTokenID, enc(execSecret))
			s += fmt.Sprintf("\n[targets.ssh]\nuser = \"root\"\npublic_key = \"ssh-ed25519 AAAA\"\nhost_key_fingerprint = \"SHA256:x\"\nprivate_key_enc = '''\n%s'''\n", enc(execSSHKey))
		}
		return s + "\n"
	}
	f := execFixture{rosterDir: t.TempDir(), tmpDir: t.TempDir(), probeDir: t.TempDir()}
	f.roster = filepath.Join(f.rosterDir, "pveforge.toml")
	f.record = filepath.Join(f.probeDir, "record.json")
	f.covDir = filepath.Join(f.probeDir, "cover")
	if err := os.Mkdir(f.covDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := target("qa-exp", roster.ExportToken, true) + target("qa-noexp", "", true) + target("qa-notoken", roster.ExportToken, false)
	if err := os.WriteFile(f.roster, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := roster.Load(f.roster); err != nil {
		t.Fatalf("fixture roster does not load: %v", err)
	}
	return f
}

// execRun is one pveforge run's outcome.
type execRun struct {
	state          *os.ProcessState
	stdout, stderr string
	env            []string // what pveforge was started with
	record         *execProbeRecord
}

// runExec runs `pveforge <args>` in a child with a fixed environment:
// PATH=path, TMPDIR, both secret variables, and one passthrough variable.
func (f execFixture) runExec(t *testing.T, path string, extraEnv []string, args ...string) execRun {
	t.Helper()
	spec, err := json.Marshal(cliChildSpec{Args: args})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append([]string{
		"PATH=" + path,
		"TMPDIR=" + f.tmpDir,
		"PVEFORGE_ROSTER=" + f.roster,
		roster.PassphraseEnvVar + "=" + execPassphrase,
		pvePasswordEnvVar + "=pam-password-must-not-pass",
		"PVEFORGE_EXEC_TEST_PASSTHROUGH=kept",
		// Under -cover the probe, an instrumented binary, would otherwise
		// print a GOCOVERDIR warning on the stderr X2 checks.
		"GOCOVERDIR=" + f.covDir,
		cliChildEnv + "=" + string(spec),
	}, extraEnv...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("run pveforge: %v", err)
	}
	r := execRun{state: cmd.ProcessState, stdout: out.String(), stderr: errOut.String(), env: cmd.Env}
	if b, err := os.ReadFile(f.record); err == nil {
		r.record = &execProbeRecord{}
		if err := json.Unmarshal(b, r.record); err != nil {
			t.Fatalf("probe record: %v", err)
		}
	}
	return r
}

// probeArgs is `exec <target> -- <this binary as the probe> <record> <how>`.
func (f execFixture) probeArgs(target, how string) []string {
	return []string{"exec", target, "--", os.Args[0], execProbeArg, f.record, how}
}

// secretWindows reports each 4-byte window of secret found in s.
func secretWindows(s, secret string) []string {
	var found []string
	for i := 0; i+4 <= len(secret); i++ {
		if w := secret[i : i+4]; strings.Contains(s, w) && !slices.Contains(found, w) {
			found = append(found, w)
		}
	}
	return found
}

func wantAuditLine() string {
	return fmt.Sprintf("notice: exec: handing token %s of qa-exp to %s\n", execTokenID, filepath.Base(os.Args[0]))
}

// X1: the command's environment is pveforge's, minus both secret
// variables and any PVEFORGE_PVE_AUTHORIZATION it already had, plus exactly
// the one PVEFORGE_PVE_AUTHORIZATION — no other addition, so nothing else
// (the SSH key) can ride along under any name.
func TestExec_X1_EnvironmentGainsExactlyTheHeader(t *testing.T) {
	f := newExecFixture(t)
	r := f.runExec(t, "/nonexistent", []string{authorizationEnvVar + "=stale"}, f.probeArgs("qa-exp", "exit:0")...)
	if r.record == nil {
		t.Fatalf("the command never ran: exit %d, stderr %q", r.state.ExitCode(), r.stderr)
	}
	var want []string
	for _, kv := range r.env {
		k, _, _ := strings.Cut(kv, "=")
		if k != roster.PassphraseEnvVar && k != pvePasswordEnvVar && k != authorizationEnvVar {
			want = append(want, kv)
		}
	}
	want = append(want, authorizationEnvVar+"=PVEAPIToken="+execTokenID+"="+execSecret)
	got := slices.Clone(r.record.Env)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("command environment =\n%q\nwant\n%q", got, want)
	}
	for _, kv := range r.record.Env {
		if w := secretWindows(kv, execSSHKey); len(w) > 0 {
			t.Errorf("the SSH key reached the environment: %q", w)
		}
	}
}

// X2: pveforge prints nothing on stdout and exactly the audit line on
// stderr, and no part of the secret reaches either.
func TestExec_X2_OnlyTheAuditLineIsPrinted(t *testing.T) {
	f := newExecFixture(t)
	r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "exit:0")...)
	if r.record == nil {
		t.Fatalf("the command never ran: stderr %q", r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want empty", r.stdout)
	}
	if r.stderr != wantAuditLine() {
		t.Errorf("stderr = %q, want %q", r.stderr, wantAuditLine())
	}
	if w := secretWindows(r.stdout+r.stderr, execSecret); len(w) > 0 {
		t.Errorf("secret fragments %q printed", w)
	}
}

// X3: the secret is nowhere in the command's argv.
func TestExec_X3_SecretNotInArgv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/self/cmdline")
	}
	f := newExecFixture(t)
	r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "exit:0")...)
	if r.record == nil {
		t.Fatalf("the command never ran: stderr %q", r.stderr)
	}
	if !bytes.Contains(r.record.Cmdline, []byte(execProbeArg)) {
		t.Fatalf("cmdline %q is not the probe's: the check proves nothing", r.record.Cmdline)
	}
	if w := secretWindows(string(r.record.Cmdline), execSecret); len(w) > 0 {
		t.Errorf("secret fragments %q in argv %q", w, r.record.Cmdline)
	}
}

// refused asserts a run that must fail before the command starts.
func refused(t *testing.T, r execRun, stderrHas string) {
	t.Helper()
	if code := r.state.ExitCode(); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if r.record != nil {
		t.Error("the command ran")
	}
	if r.stdout != "" {
		t.Errorf("stdout = %q, want empty", r.stdout)
	}
	if !strings.Contains(r.stderr, stderrHas) {
		t.Errorf("stderr = %q, want it to name %q", r.stderr, stderrHas)
	}
	if strings.Contains(r.stderr, "notice: exec:") {
		t.Errorf("stderr = %q: the audit line was printed for a refused run", r.stderr)
	}
	if w := secretWindows(r.stdout+r.stderr, execSecret); len(w) > 0 {
		t.Errorf("secret fragments %q printed", w)
	}
}

// X4: a wrong passphrase is refused, naming the variable; the command never
// starts.
func TestExec_X4_WrongPassphrase(t *testing.T) {
	f := newExecFixture(t)
	r := f.runExec(t, "/nonexistent", []string{roster.PassphraseEnvVar + "=wrong"}, f.probeArgs("qa-exp", "exit:0")...)
	refused(t, r, roster.PassphraseEnvVar)
}

// X5: a target with no token, or no such target, is refused.
func TestExec_X5_NoTokenOrUnknownTarget(t *testing.T) {
	f := newExecFixture(t)
	t.Run("no token", func(t *testing.T) {
		refused(t, f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-notoken", "exit:0")...), "holds no API token")
	})
	t.Run("unknown target", func(t *testing.T) {
		refused(t, f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-nope", "exit:0")...), "not found in roster")
	})
}

// X10: a target the roster does not mark export = "token" is refused, even
// though it holds a token and the passphrase opens it.
func TestExec_X10_TargetNotMarkedExportable(t *testing.T) {
	f := newExecFixture(t)
	refused(t, f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-noexp", "exit:0")...), `is not marked export = "token"`)
}

// dirState is every entry under dir with its size, mode and mtime.
func dirState(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, fmt.Sprintf("%s %d %v %d", p, info.Size(), info.Mode(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// X6: nothing is written: the roster's directory (the roster itself and any
// lock directory) and $TMPDIR are exactly as they were.
func TestExec_X6_NothingWritten(t *testing.T) {
	f := newExecFixture(t)
	beforeRoster, beforeTmp := dirState(t, f.rosterDir), dirState(t, f.tmpDir)
	rosterBytes, err := os.ReadFile(f.roster)
	if err != nil {
		t.Fatal(err)
	}
	r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "exit:0")...)
	if r.record == nil {
		t.Fatalf("the command never ran: stderr %q", r.stderr)
	}
	if got := dirState(t, f.rosterDir); !slices.Equal(got, beforeRoster) {
		t.Errorf("roster directory changed:\n%q\nwas\n%q", got, beforeRoster)
	}
	if got := dirState(t, f.tmpDir); !slices.Equal(got, beforeTmp) {
		t.Errorf("TMPDIR changed:\n%q\nwas\n%q", got, beforeTmp)
	}
	if after, _ := os.ReadFile(f.roster); !bytes.Equal(after, rosterBytes) {
		t.Error("the roster's bytes changed")
	}
}

// X7: the command's exit status is the run's: pveforge is replaced, so
// neither a status nor a death by signal passes through pveforge.
func TestExec_X7_ExitStatusIsTheCommands(t *testing.T) {
	f := newExecFixture(t)
	for _, code := range []int{0, 3} {
		r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "exit:"+strconv.Itoa(code))...)
		if r.record == nil || r.state.ExitCode() != code {
			t.Errorf("command exit %d: run exit %d (ran: %v), stderr %q", code, r.state.ExitCode(), r.record != nil, r.stderr)
		}
	}
	r := f.runExec(t, "/nonexistent", nil, f.probeArgs("qa-exp", "signal:"+strconv.Itoa(int(syscall.SIGTERM)))...)
	ws, ok := r.state.Sys().(syscall.WaitStatus)
	if r.record == nil || !ok || !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("command killed by SIGTERM: run status %v (ran: %v)", r.state, r.record != nil)
	}
}

// X8: a missing --, an empty command or a command not in PATH is refused
// before anything is exec'd.
func TestExec_X8_BadCommandLine(t *testing.T) {
	f := newExecFixture(t)
	emptyPath := t.TempDir()
	// The command, where there is one, is the exec probe: a mutant that
	// ran it anyway is caught by its record, and never loops re-running this
	// binary as pveforge (cliChildEnv passes through).
	probe := []string{os.Args[0], execProbeArg, f.record, "exit:0"}
	with := func(head ...string) []string { return append(head, probe...) }
	cases := []struct {
		name string
		args []string
		has  string
	}{
		{"no --", with("exec", "qa-exp"), "then --"},
		{"-- before the target", with("exec", "--", "qa-exp"), "then --"},
		{"two args before --", with("exec", "qa-exp", "extra", "--"), "then --"},
		{"nothing after --", []string{"exec", "qa-exp", "--"}, "no command after --"},
		{"an empty command", []string{"exec", "qa-exp", "--", ""}, "no command after --"},
		{"not in PATH", []string{"exec", "qa-exp", "--", "pveforge-exec-no-such-command"}, "executable file not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused(t, f.runExec(t, emptyPath, nil, tc.args...), tc.has)
		})
	}
}

// X9: the process is made non-dumpable before the secret is decrypted,
// and the decrypt comes before the exec. The order is recorded through the
// seams; TestExec_X9_SetNotDumpableClearsTheFlag checks that the real
// nodump.Set does what it says.
func TestExec_X9_NotDumpableBeforeDecrypt(t *testing.T) {
	f := newExecFixture(t)
	t.Setenv(roster.PassphraseEnvVar, execPassphrase)
	var calls []string
	var gotPath string
	var gotArgv, gotEnv []string
	origHarden, origDecrypt, origExecve := execHarden, execDecrypt, execve
	t.Cleanup(func() { execHarden, execDecrypt, execve = origHarden, origDecrypt, origExecve })
	execHarden = func() error { calls = append(calls, "harden"); return nil }
	execDecrypt = func(tg *roster.Target, pass string) ([]byte, error) {
		calls = append(calls, "decrypt")
		return origDecrypt(tg, pass)
	}
	execve = func(path string, argv, env []string) error {
		calls = append(calls, "execve")
		gotPath, gotArgv, gotEnv = path, argv, env
		return nil
	}
	// The command is the exec probe, never a bare re-run of this binary:
	// a mutant that runs it for real (fork+wait) must not start this whole
	// suite again, recursively.
	argv := []string{os.Args[0], execProbeArg, f.record, "exit:0"}
	code, stdout, stderr := runRootArgs(append([]string{"exec", "qa-exp", "--roster", f.roster, "--"}, argv...)...)
	if code != 0 || stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := []string{"harden", "decrypt", "execve"}; !slices.Equal(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	if gotPath != os.Args[0] || !slices.Equal(gotArgv, argv) {
		t.Errorf("execve(%q, %q), want the command and its argv as given", gotPath, gotArgv)
	}
	if !slices.Contains(gotEnv, authorizationEnvVar+"=PVEAPIToken="+execTokenID+"="+execSecret) {
		t.Error("execve's environment lacks the header")
	}
}

func TestExec_X9_SetNotDumpableClearsTheFlag(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("PR_SET_DUMPABLE is Linux-only")
	}
	out, err := exec.Command(os.Args[0], dumpableProbeArg).CombinedOutput()
	if err != nil || string(out) != "dumpable: 0\n" {
		t.Errorf("probe: %q, %v; want dumpable: 0", out, err)
	}
	// Anti-vacuity: a process that did not call it is dumpable.
	r, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if r != 1 {
		t.Errorf("this test process reports dumpable %d; the probe's 0 proves nothing", r)
	}
}

// TestAuthorizationValue refuses what would break the documented curl
// config line or a header, and never quotes the secret.
func TestAuthorizationValue(t *testing.T) {
	if got, err := authorizationValue("u@pve!t", []byte("abc-123")); err != nil || got != "PVEAPIToken=u@pve!t=abc-123" {
		t.Errorf("= %q, %v", got, err)
	}
	for _, bad := range []string{"", "a b", "a\"b", "a\\b", "a\nb", "a\x00b", "a\x7fb",
		"Zq9X-vJw3 KpYh-1Vb8", "Zq9X-vJw3\"KpYh-1Vb8", "Zq9X-vJw3\nKpYh-1Vb8"} {
		if _, err := authorizationValue("u@pve!t", []byte(bad)); err == nil {
			t.Errorf("secret %q accepted", bad)
		} else if bad != "" {
			// Nor any encoding of it: raw, quoted, hex, or base64.
			for _, enc := range []string{bad, fmt.Sprintf("%q", bad), hex.EncodeToString([]byte(bad)), fmt.Sprintf("% x", bad),
				base64.StdEncoding.EncodeToString([]byte(bad)), base64.RawStdEncoding.EncodeToString([]byte(bad)),
				base64.URLEncoding.EncodeToString([]byte(bad)), base64.RawURLEncoding.EncodeToString([]byte(bad))} {
				if strings.Contains(err.Error(), enc) {
					t.Errorf("error %q carries the secret as %q", err, enc)
				}
			}
		}
		if _, err := authorizationValue(bad, []byte("s")); err == nil {
			t.Errorf("token id %q accepted", bad)
		}
	}
}

// TestExec_SeamDefaults pins the seams' production values: a test that
// swaps a seam proves the command calls it, not that the command, as
// shipped, calls the real thing. execHarden replaced by a no-op, say,
// would otherwise pass every other test.
func TestExec_SeamDefaults(t *testing.T) {
	ptr := func(f any) uintptr { return reflect.ValueOf(f).Pointer() }
	if ptr(execHarden) != ptr(nodump.Set) {
		t.Error("execHarden is not nodump.Set")
	}
	if ptr(execDecrypt) != ptr((*roster.Target).TokenSecret) {
		t.Error("execDecrypt is not (*roster.Target).TokenSecret")
	}
	if ptr(execve) != ptr(syscall.Exec) {
		t.Error("execve is not syscall.Exec")
	}
	// Anti-vacuity: the comparison tells functions apart.
	if ptr(nodump.Set) == ptr(func() error { return nil }) {
		t.Fatal("reflect cannot tell nodump.Set from a no-op: the checks prove nothing")
	}
}

// X11: an execve that fails is reported plainly after the audit line, so the
// notice never reads as a hand-over that happened: exit 1, and the error
// says the token was not handed over.
func TestExec_X11_FailedExecveIsReported(t *testing.T) {
	f := newExecFixture(t)
	t.Setenv(roster.PassphraseEnvVar, execPassphrase)
	orig := execve
	t.Cleanup(func() { execve = orig })
	execve = func(string, []string, []string) error { return syscall.EACCES }
	argv := []string{os.Args[0], execProbeArg, f.record, "exit:0"}
	code, stdout, stderr := runRootArgs(append([]string{"exec", "qa-exp", "--roster", f.roster, "--"}, argv...)...)
	want := wantAuditLine() + fmt.Sprintf("exec: execve %s failed, so the token was not handed over: %s\n", os.Args[0], syscall.EACCES)
	if code != 1 || stdout != "" || stderr != want {
		t.Errorf("exit %d, stdout %q, stderr %q\nwant exit 1, stderr %q", code, stdout, stderr, want)
	}
	if w := secretWindows(stderr, execSecret); len(w) > 0 {
		t.Errorf("secret fragments %q printed", w)
	}
}
