package sourceguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The harness scripts under hack/harness are shell, which nothing else in
// this repo checks. These tests are their guard: every script parses, none
// uses a construct that hides a failure, and lib.sh, the base every harness
// script sources, refuses what it must, run offline against
// hack/harness/test/fake-pveforge.sh.

const harnessDir = "../../hack/harness"

// hackDir is the root of the SCRIPT SCAN below, and of nothing else.
//
// harnessDir stays what it is: it is not a walk root but the base of 26 path
// joins across this package (lib.sh, README.md, test/fake-*.sh, build/env.sh,
// the .env.example files, evidence.sh, stage14-destructive-proof.sh, and
// filepath.Join(harnessDir, "..", "..") in harness_nested_test.go, which
// reaches the repository root). Repointing it at hack/ would break every one
// of them, and would climb to the repository's PARENT in that last case.
//
// Only TestHarnessScripts_ParseAndHideNoFailure's walk moves here, because it
// joins nothing and is the scan that runs `bash -n` and the failure-hiding
// checks, so it is where a new script outside hack/harness has to be covered.
// harnessReadmeScripts' walk stays on harnessDir: its caller has already read
// filepath.Join(harnessDir, "README.md"), and the README's script map has no
// reason to see hack/gate/.
const hackDir = "../../hack"

var (
	// local x=$(...) takes local's status, never the command's.
	localSubst = regexp.MustCompile(`(?m)^\s*local\s+[A-Za-z_][A-Za-z0-9_]*=\$\(`)
	// A status piped into tail is tail's.
	tailPipe = regexp.MustCompile(`\|\s*tail\b`)
)

func TestHarnessScripts_ParseAndHideNoFailure(t *testing.T) {
	var scripts []string
	err := filepath.WalkDir(hackDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".sh") {
			scripts = append(scripts, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the walk found the scripts it must.
	have := strings.Join(scripts, "\n")
	for _, want := range []string{"hack/harness/lib.sh", "hack/harness/test/fake-pveforge.sh", "hack/gate/clean-export.sh"} {
		if !strings.Contains(have, want) {
			t.Fatalf("%s not found under %s; found:\n%s", want, hackDir, have)
		}
	}
	for _, s := range scripts {
		if out, err := exec.Command("bash", "-n", s).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", s, err, out)
		}
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if loc := localSubst.FindIndex(b); loc != nil {
			t.Errorf("%s: %q: local hides the command's exit status; declare, then assign", s, b[loc[0]:loc[1]])
		}
		if loc := tailPipe.FindIndex(b); loc != nil {
			t.Errorf("%s: %q: a pipe into tail reports tail's status", s, b[loc[0]:loc[1]])
		}
	}
	lib, err := os.ReadFile(filepath.Join(harnessDir, "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(lib, []byte("--unsafe-no-lock")) {
		t.Error("lib.sh names --unsafe-no-lock: every harness write goes through a locked pveforge path")
	}
}

// The harness README tells the operator and the implementors to run its
// scripts as commands, most through `unlock.sh run -- <script>`, which execs
// the script directly: one committed without its executable bit fails there
// with "permission denied" (prepare-iso.sh did, on its first live run). So
// every script the README runs is mode 100755 in the git index, which is what
// a clone checks out; a chmod on one workstation's disk proves nothing.

// harnessReadmeCommand is a script path in a command position of a code span:
// a span's first word when the span has arguments, or the word after "--".
var harnessReadmeCommand = regexp.MustCompile("`([^`]*)`")

// harnessReadmeScripts is every script hack/harness/README.md runs as a
// command, as a path relative to the repository root. A bare name (unlock.sh,
// build.sh) is the one script of that name under hack/harness.
func harnessReadmeScripts(t *testing.T) []string {
	t.Helper()
	readme, err := os.ReadFile(filepath.Join(harnessDir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	byBase := map[string][]string{}
	err = filepath.WalkDir(harnessDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".sh") {
			rel := filepath.ToSlash(strings.TrimPrefix(p, "../../"))
			byBase[filepath.Base(p)] = append(byBase[filepath.Base(p)], rel)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range harnessReadmeCommand.FindAllStringSubmatch(string(readme), -1) {
		words := strings.Fields(m[1])
		var cmds []string
		if len(words) > 1 {
			cmds = append(cmds, words[0])
		}
		for i, w := range words[:max(len(words)-1, 0)] {
			if w == "--" {
				cmds = append(cmds, words[i+1])
			}
		}
		for _, c := range cmds {
			if !strings.HasSuffix(c, ".sh") {
				continue
			}
			path := c
			if !strings.Contains(c, "/") {
				if len(byBase[c]) != 1 {
					t.Fatalf("the harness README runs %s, which names %d scripts under hack/harness: %q", c, len(byBase[c]), byBase[c])
				}
				path = byBase[c][0]
			}
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	return out
}

// gitIndexModes is `git ls-files -s`'s mode for each path, read in the
// repository at root; ok is false when root is not the top of a git work
// tree (an exported tree, as a gate runs on), whose files then carry the
// modes the index gave them (git archive keeps the executable bit).
func gitIndexModes(t *testing.T, root string, paths []string) (modes map[string]string, ok bool) {
	t.Helper()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	top, err := exec.Command("git", "-C", abs, "rev-parse", "--show-toplevel").Output()
	if err != nil || filepath.Clean(strings.TrimSpace(string(top))) != abs {
		return nil, false
	}
	out, err := exec.Command("git", append([]string{"-C", abs, "ls-files", "-s", "--"}, paths...)...).Output()
	if err != nil {
		t.Fatalf("git ls-files -s: %v", err)
	}
	modes = map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// <mode> <object> <stage>\t<path>
		meta, path, found := strings.Cut(line, "\t")
		if f := strings.Fields(meta); found && len(f) == 3 {
			modes[path] = f[0]
		}
	}
	return modes, true
}

func TestHarnessReadme_ScriptsItRunsAreExecutable(t *testing.T) {
	scripts := harnessReadmeScripts(t)
	// Anti-vacuity: the README's steps run eight scripts (unlock.sh, the
	// probe, prepare-iso, build, cluster, nested, golden and reset); a
	// parser that found fewer would check too little.
	if len(scripts) != 8 {
		t.Fatalf("found %d scripts the harness README runs, want 8: %q", len(scripts), scripts)
	}
	modes, inGit := gitIndexModes(t, "../..", scripts)
	for _, s := range scripts {
		if inGit {
			if modes[s] != "100755" {
				t.Errorf("%s: mode %q in the git index, want 100755: the harness README runs it as a command (git update-index --chmod=+x %s)", s, modes[s], s)
			}
			continue
		}
		fi, err := os.Stat(filepath.Join("../..", s))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o111 != 0o111 {
			t.Errorf("%s: mode %v, want executable: the harness README runs it as a command", s, fi.Mode().Perm())
		}
	}
}

// harnessCase is one offline run of a driver script that sources lib.sh.
type harnessCase struct {
	name string
	pre  string // lines before `source lib.sh`
	body string // lines after it
	// env is added to the base environment; a value "-" removes the key.
	env        map[string]string
	bashEnv    string // when set, written to a file BASH_ENV names
	bashArgs   []string
	resp       map[string]string // fake answers by key, over harnessWorld
	rc         map[string]int    // fake exit statuses by key
	roster     string            // "missing", "0644", "env-link", "cwd-link"; "" = a 0600 roster
	outerEnv   string            // "missing", a KEY=value body; "" = the committed example
	plantFiles map[string]string // extra files (name->body) written mode 0600 into ~/.config/pveforge
	sourced    bool              // run the driver by sourcing it from another script
	holdLock   bool
	// pathWithout, when set, runs the case with a PATH of links to every
	// tool but this one.
	pathWithout string
	// skipUnlessLocale skips the case, saying so, where this locale is not
	// installed: what it tests does not arise without it.
	skipUnlessLocale string
	// relTool ("go" or "git") plants an executable of that name in the case's
	// working directory and puts "." first on PATH, so `type -P` answers a
	// relative path.
	relTool string
	// The fakes' answers (hack/harness/test/fake-go.sh, fake-git.sh): the whole
	// `go version -m` output / the HEAD git prints, and their exit statuses.
	// "" and 0 are the defaults: a clean build at HEAD.
	goOut, gitHead string
	goRC, gitRC    int
	// quietGo switches the real go's telemetry off in the case's HOME: it writes
	// counters there from a detached process, which races the TempDir cleanup.
	quietGo bool
	// cdLib runs the case with the harness directory as its working directory.
	cdLib bool

	// wantNoState: after the run, nothing of the harness's own exists under
	// ~/.config/pveforge: no harness.lock, no harness-runs. A refusal before the
	// lock leaves none.
	wantNoState bool
	// wantGoCalled: go.log is exactly one line, `version -m -- $PVEFORGE_BIN`.
	wantGoCalled bool
	// wantGitLog is git.log's exact content, "-" for "git was never run" ("" is
	// not checked). The checkout is the repository root lib.sh lives in.
	wantGitLog string

	wantCode   int
	wantErr    string   // stderr must contain it
	wantNotErr string   // stderr must not contain it
	wantCalls  []string // the exact argv log, roster path as R; nil: not checked
	wantLast   string   // the last call, roster path as R
	noMutation bool     // the argv log holds no write
}

const (
	stdInit  = "harness_init\nharness_declare_vmids 690\n"
	stdInitS = stdInit + "harness_require_storage pveforge-harness\n"
	keyPool  = "get /pools poolid=pveforge-harness"
	keyConf  = "get /nodes/qa-pve-07/qemu/690/config"
)

// harnessWorld is the fake's default answers: VM 690 in the pool on
// qa-pve-07, carrying the tag.
var harnessWorld = map[string]string{
	keyPool: `[{"poolid":"pveforge-harness","comment":"","members":[{"id":"qemu/690","type":"qemu","vmid":690,"node":"qa-pve-07"}]}]`,
	keyConf: `{"cores":"1","tags":"pveforge-harness"}`,
}

func fakeKey(k string) string {
	return regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(k, "_")
}

// harnessPATH is the PATH a case runs with: only the directories of the tools
// lib.sh and the fake use.
func harnessPATH(t *testing.T) string {
	t.Helper()
	seen := map[string]bool{}
	var dirs []string
	for _, tool := range []string{"bash", "jq", "flock", "stat", "sha256sum", "tr", "cat", "grep", "mktemp", "mkdir"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s is required to test the harness scripts: %v", tool, err)
		}
		if d := filepath.Dir(p); !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return harnessFakeToolDir(t) + ":" + strings.Join(dirs, ":")
}

// harnessFakeToolDir is a directory of links named go and git to the offline
// fakes (hack/harness/test/fake-go.sh, fake-git.sh), which lib.sh's
// binary-provenance check runs instead of the real tools: every offline case's
// PVEFORGE_BIN is a bash script, which real `go version -m` cannot read, and a
// `make gate` export has no .git. With no answer files the fakes report a
// clean build at the same revision as HEAD.
func harnessFakeToolDir(t *testing.T, skip ...string) string {
	t.Helper()
	dir := t.TempDir()
	for tool, fake := range map[string]string{"go": "fake-go.sh", "git": "fake-git.sh"} {
		if slicesContains(skip, tool) {
			continue
		}
		abs, err := filepath.Abs(filepath.Join(harnessDir, "test", fake))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(abs, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func slicesContains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func runHarnessCase(t *testing.T, c harnessCase) (code int, stderr string, calls []string) {
	t.Helper()
	lib, err := filepath.Abs(filepath.Join(harnessDir, "lib.sh"))
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
	for _, d := range []string{cfg, filepath.Join(fakeDir, "resp"), filepath.Join(fakeDir, "rc"), work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	roster := filepath.Join(cfg, outerRosterName)
	env := map[string]string{
		"PATH":                       harnessPATH(t),
		"HOME":                       home,
		"PVEFORGE_BIN":               fake,
		"PVEFORGE_ROSTER_PASSPHRASE": "not-a-secret",
		"FAKE_PVEFORGE_DIR":          fakeDir,
		"HARNESS_LIB":                lib,
	}
	// The OUTER-identity site file read_outer_identity reads. "" = the committed
	// example; "missing" = do not write it; anything else = that body verbatim
	// (the invariant tests drive a bad key / a different node this way).
	switch c.outerEnv {
	case "missing":
	case "":
		if err := os.WriteFile(filepath.Join(cfg, "harness-outer.env"), []byte(exampleOuterEnv(t)), 0o600); err != nil {
			t.Fatal(err)
		}
	default:
		if err := os.WriteFile(filepath.Join(cfg, "harness-outer.env"), []byte(c.outerEnv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.quietGo {
		tel := filepath.Join(home, ".config", "go", "telemetry")
		if err := os.MkdirAll(tel, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tel, "mode"), []byte("off"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range c.plantFiles {
		if err := os.WriteFile(filepath.Join(cfg, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.roster != "missing" {
		mode := os.FileMode(0o600)
		if c.roster == "0644" {
			mode = 0o644
		}
		if err := os.WriteFile(roster, []byte("# test roster\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(roster, mode); err != nil {
			t.Fatal(err)
		}
	}
	switch c.roster {
	case "env-link": // a different spelling of the same file
		link := filepath.Join(tmp, "elsewhere.toml")
		if err := os.Symlink(roster, link); err != nil {
			t.Fatal(err)
		}
		env["PVEFORGE_ROSTER"] = link
	case "cwd-link":
		if err := os.Symlink(roster, filepath.Join(work, "pveforge.toml")); err != nil {
			t.Fatal(err)
		}
	}
	answers := map[string]string{}
	for k, v := range harnessWorld {
		answers[k] = v
	}
	for k, v := range c.resp {
		answers[k] = v
	}
	for k, v := range answers {
		if v == "-" {
			continue
		}
		if err := os.WriteFile(filepath.Join(fakeDir, "resp", fakeKey(k)), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range c.rc {
		if err := os.WriteFile(filepath.Join(fakeDir, "rc", fakeKey(k)), []byte(fmt.Sprint(v)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.bashEnv != "" {
		f := filepath.Join(tmp, "bash_env.sh")
		if err := os.WriteFile(f, []byte(c.bashEnv), 0o600); err != nil {
			t.Fatal(err)
		}
		env["BASH_ENV"] = f
	}
	for k, v := range c.env {
		if v == "@lib" { // an existing file that is not executable
			v = lib
		}
		env[k] = v
	}
	if c.pathWithout != "" {
		links := filepath.Join(tmp, "pathbin")
		if err := os.Mkdir(links, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"jq", "flock", "stat", "sha256sum", "tr", "cat", "grep", "mktemp", "mkdir", "sleep", "date", "bash"} {
			if tool == c.pathWithout {
				continue
			}
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p, filepath.Join(links, tool)); err != nil {
				t.Fatal(err)
			}
		}
		env["PATH"] = harnessFakeToolDir(t, c.pathWithout) + ":" + links
	}
	if c.relTool != "" {
		// `type -P <tool>` finds an executable of that name in the case's cwd
		// through the relative PATH entry ".", and answers ./<tool>.
		body := "#!/bin/sh\necho REL-" + c.relTool + "-RAN >&2\nexit 97\n"
		if err := os.WriteFile(filepath.Join(work, c.relTool), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		env["PATH"] = ".:" + env["PATH"]
	}
	if c.gitHead == "-" { // git exits 0 and prints nothing
		if err := os.WriteFile(filepath.Join(fakeDir, "git.head"), []byte("\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"go.out": c.goOut, "git.head": c.gitHead} {
		if body != "" && !(name == "git.head" && body == "-") {
			if err := os.WriteFile(filepath.Join(fakeDir, name), []byte(body+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, rc := range map[string]int{"go.rc": c.goRC, "git.rc": c.gitRC} {
		if rc != 0 {
			if err := os.WriteFile(filepath.Join(fakeDir, name), []byte(fmt.Sprint(rc)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	script := filepath.Join(tmp, "case.sh")
	src := "#!/usr/bin/env bash\n" + c.pre + "source \"$HARNESS_LIB\"\n" + c.body
	if err := os.WriteFile(script, []byte(src), 0o700); err != nil {
		t.Fatal(err)
	}
	run := script
	if c.sourced {
		run = filepath.Join(tmp, "outer.sh")
		if err := os.WriteFile(run, []byte("#!/usr/bin/env bash\nsource "+script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if c.holdLock {
		holdHarnessLock(t, filepath.Join(cfg, "harness.lock"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", append(append([]string(nil), c.bashArgs...), run)...)
	cmd.Dir = work
	if c.cdLib {
		cmd.Dir = filepath.Dir(lib)
	}
	for k, v := range env {
		if v != "-" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("run %s: %v", c.name, err)
	}
	if b, err := os.ReadFile(filepath.Join(fakeDir, "argv.log")); err == nil {
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if l != "" {
				calls = append(calls, strings.ReplaceAll(l, roster, "R"))
			}
		}
	}
	cfgDir := cfg
	if c.wantNoState {
		for _, n := range []string{"harness.lock", "harness-runs"} {
			if _, err := os.Lstat(filepath.Join(cfgDir, n)); err == nil {
				t.Errorf("%s exists after a refusal: the check must run before the lock and any state", n)
			}
		}
	}
	if c.wantGoCalled {
		b, _ := os.ReadFile(filepath.Join(fakeDir, "go.log"))
		if want := "version -m -- " + fake + "\n"; string(b) != want {
			t.Errorf("go.log = %q, want %q", b, want)
		}
	}
	if c.wantGitLog != "" {
		b, err := os.ReadFile(filepath.Join(fakeDir, "git.log"))
		switch {
		case c.wantGitLog == "-":
			if err == nil {
				t.Errorf("git ran, but must not have: %q", b)
			}
		default:
			root, rerr := filepath.Abs(filepath.Join(harnessDir, "..", ".."))
			if rerr != nil {
				t.Fatal(rerr)
			}
			if real, rerr := filepath.EvalSymlinks(root); rerr == nil {
				root = real
			}
			if want := strings.ReplaceAll(c.wantGitLog, "ROOT", root) + "\n"; string(b) != want {
				t.Errorf("git.log = %q, want %q", b, want)
			}
		}
	}
	return code, errOut.String(), calls
}

// holdHarnessLock holds lockFile from another process until the test ends.
func holdHarnessLock(t *testing.T, lockFile string) {
	t.Helper()
	holder := exec.Command("flock", lockFile, "sleep", "60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if exec.Command("flock", "-n", lockFile, "true").Run() != nil {
			return
		}
	}
	t.Fatal("the lock holder never took the harness lock")
}

func isWrite(call string) bool {
	for _, p := range []string{"api put ", "api post ", "api delete ", "vm create "} {
		if strings.HasPrefix(call, p) {
			return true
		}
	}
	return false
}

func refused(name, body string, code int, errText string) harnessCase {
	return harnessCase{name: name, body: body, wantCode: code, wantErr: errText, noMutation: true}
}

func harnessCases() []harnessCase {
	const post = "harness_vm_post 690 status/stop\necho REACHED >&2\n"
	cases := []harnessCase{
		// Shell hygiene: each refused before anything is defined or sent.
		{name: "xtrace", bashArgs: []string{"-x"}, body: stdInit, wantCode: 2, wantErr: "include xtrace", wantCalls: []string{}},
		{name: "verbose", bashArgs: []string{"-v"}, body: stdInit, wantCode: 2, wantErr: "include xtrace", wantCalls: []string{}},
		{name: "allexport", bashArgs: []string{"-a"}, body: stdInit, wantCode: 2, wantErr: "include xtrace", wantCalls: []string{}},
		{name: "SHELLOPTS xtrace", env: map[string]string{"SHELLOPTS": "xtrace"}, body: stdInit, wantCode: 2, wantErr: "include xtrace", wantCalls: []string{}},
		{name: "BASH_XTRACEFD", env: map[string]string{"BASH_XTRACEFD": "2"}, body: stdInit, wantCode: 2, wantErr: "BASH_XTRACEFD", wantCalls: []string{}},
		{name: "BASH_ENV", bashEnv: ":\n", body: stdInit, wantCode: 2, wantErr: "BASH_ENV or ENV", wantCalls: []string{}},
		{name: "ENV", env: map[string]string{"ENV": "/dev/null"}, body: stdInit, wantCode: 2, wantErr: "BASH_ENV or ENV", wantCalls: []string{}},
		{name: "exported function", env: map[string]string{"BASH_FUNC_jq%%": "() { :; }"}, body: stdInit, wantCode: 2, wantErr: "functions already defined", wantCalls: []string{}},
		{name: "function before lib", pre: "f() { :; }\n", body: stdInit, wantCode: 2, wantErr: "functions already defined", wantCalls: []string{}},
		{name: "driver sourced", sourced: true, body: stdInit, wantCode: 2, wantErr: "must be executed, not sourced", wantCalls: []string{}},
		{name: "functrace", bashArgs: []string{"-T"}, body: stdInit, wantCode: 2, wantErr: "functrace or errtrace", wantCalls: []string{}},
		{name: "errtrace", bashArgs: []string{"-E"}, body: stdInit, wantCode: 2, wantErr: "functrace or errtrace", wantCalls: []string{}},
		// A BASH_ENV file that unsets itself gets past the BASH_ENV check. Its
		// functrace is refused; its alias and IFS do not survive lib.sh; and
		// its DEBUG trap, which lib.sh cannot clear, never sees lib's own
		// commands (bash runs it in a function only under functrace).
		{name: "functrace from a self-unsetting BASH_ENV", bashEnv: "set -T\nunset BASH_ENV\n", body: stdInit, wantCode: 2, wantErr: "functrace or errtrace", wantCalls: []string{}},
		{name: "a self-unsetting BASH_ENV's trap never sees lib's commands", bashEnv: "trap 'echo \"TRAP:$BASH_COMMAND\" >&2' DEBUG\nunset BASH_ENV\n", body: stdInit + "harness_get /cluster/resources >/dev/null\n",
			resp: map[string]string{"get /cluster/resources": "[]"}, wantErr: "TRAP:harness_init", wantNotErr: "TRAP:_harness_api"},
		{name: "alias from a self-unsetting BASH_ENV", bashEnv: "shopt -s expand_aliases\nalias true='echo ALIASED >&2'\nunset BASH_ENV\n", body: "true\n", wantNotErr: "ALIASED"},
		{name: "IFS from a self-unsetting BASH_ENV", bashEnv: "IFS=:\nunset BASH_ENV\n", body: "v='a b'\nset -- $v\n[ \"$#\" = 2 ] || { echo \"IFS NOT RESET\" >&2; exit 7; }\n", wantNotErr: "IFS NOT RESET"},
		// The options lib.sh sets for the script.
		{name: "errexit", body: "false\necho REACHED >&2\n", wantCode: 1, wantNotErr: "REACHED"},
		{name: "nounset", body: "echo \"$HARNESS_NO_SUCH_VAR\"\necho REACHED >&2\n", wantCode: 1, wantNotErr: "REACHED"},
		{name: "pipefail", body: "false | cat\necho REACHED >&2\n", wantCode: 1, wantNotErr: "REACHED"},
		{name: "inherit_errexit", body: "v=$(false; echo ok)\necho \"REACHED $v\" >&2\n", wantCode: 1, wantNotErr: "REACHED"},

		// A disabled builtin would make every refusal a no-op.
		{name: "disabled builtin exit", bashEnv: "enable -n exit\nunset BASH_ENV\n", body: stdInit, wantCode: 2, wantErr: "builtins are disabled", wantCalls: []string{}},
		{name: "disabled builtin enable", bashEnv: "enable -n enable\nunset BASH_ENV\n", body: stdInit, wantCode: 2, wantErr: "builtins are disabled", wantCalls: []string{}},

		// The environment.
		{name: "PVEFORGE_BIN relative", env: map[string]string{"PVEFORGE_BIN": "fake-pveforge.sh"}, body: stdInit, wantCode: 2, wantErr: "absolute path", wantCalls: []string{}},
		{name: "PVEFORGE_BIN missing", env: map[string]string{"PVEFORGE_BIN": "/nonexistent/pveforge"}, body: stdInit, wantCode: 2, wantErr: "is not a file", wantCalls: []string{}},
		{name: "PVEFORGE_BIN not executable", env: map[string]string{"PVEFORGE_BIN": "@lib"}, body: stdInit, wantCode: 2, wantErr: "is not executable", wantCalls: []string{}},
		{name: "PVEFORGE_BIN unset", env: map[string]string{"PVEFORGE_BIN": "-"}, body: stdInit, wantCode: 2, wantErr: "absolute path", wantCalls: []string{}},
		{name: "passphrase unset", env: map[string]string{"PVEFORGE_ROSTER_PASSPHRASE": "-"}, body: stdInit, wantCode: 2, wantErr: "PVEFORGE_ROSTER_PASSPHRASE must be set", wantCalls: []string{}},
		{name: "passphrase empty", env: map[string]string{"PVEFORGE_ROSTER_PASSPHRASE": ""}, body: stdInit, wantCode: 2, wantErr: "PVEFORGE_ROSTER_PASSPHRASE must be set", wantCalls: []string{}},
		{name: "PVE password set", env: map[string]string{"PVEFORGE_PVE_PASSWORD": ""}, body: stdInit, wantCode: 2, wantErr: "PVEFORGE_PVE_PASSWORD is set", wantCalls: []string{}},
		{name: "roster missing", roster: "missing", body: stdInit, wantCode: 2, wantErr: "does not exist", wantCalls: []string{}},
		{name: "roster mode 0644", roster: "0644", body: stdInit, wantCode: 2, wantErr: "has mode 644", wantCalls: []string{}},
		{name: "PVEFORGE_ROSTER is the harness roster", roster: "env-link", body: stdInit, wantCode: 2, wantErr: "PVEFORGE_ROSTER names the harness roster", wantCalls: []string{}},
		{name: "./pveforge.toml is the harness roster", roster: "cwd-link", body: stdInit, wantCode: 2, wantErr: "./pveforge.toml is the harness roster", wantCalls: []string{}},
		{name: "lock held", holdLock: true, body: stdInit, wantCode: 2, wantErr: "another harness script holds", wantCalls: []string{}},
		{name: "lock wait not a number", env: map[string]string{"HARNESS_LOCK_WAIT": "soon"}, body: stdInit, wantCode: 2, wantErr: "whole seconds", wantCalls: []string{}},
		{name: "init twice", body: "harness_init\nharness_init\n", wantCode: 2, wantErr: "ran twice", wantCalls: []string{}},
		{name: "read before init", body: "harness_get /cluster/resources\n", wantCode: 2, wantErr: "harness_init has not run", wantCalls: []string{}},
		{name: "declare before init", body: "harness_declare_vmids 690\n", wantCode: 2, wantErr: "harness_init has not run", wantCalls: []string{}},
		{name: "storage before init", body: "harness_require_storage pveforge-harness\n", wantCode: 2, wantErr: "harness_init has not run", wantCalls: []string{}},

		// Storage.
		refused("storage missing", "harness_init\nharness_require_storage ''\n", 2, "there is no default"),
		refused("storage not an id", "harness_init\nharness_require_storage Local\n", 2, "not a PVE storage id"),
		refused("storage twice", "harness_init\nharness_require_storage pveforge-harness\nharness_require_storage local-lvm\n", 2, "ran twice"),
		{name: "storage ok", body: "harness_init\nharness_require_storage pveforge-harness\n[ \"$HARNESS_STORAGE\" = pveforge-harness ]\n", wantErr: " sha256 ", wantCalls: []string{}},
		{name: "a default roster never reaches pveforge", env: map[string]string{"PVEFORGE_ROSTER": "/nonexistent/pveforge.toml"}, resp: map[string]string{"get /cluster/resources": "[]"},
			body: "harness_init\nharness_get /cluster/resources >/dev/null\n", wantCalls: []string{"api get /cluster/resources qa-pve-07-harness --roster R -o json"}},

		// VMIDs: 690-699 matched as a string.
		{name: "declare 690 and 699", body: "harness_init\nharness_declare_vmids 690 699\n", wantCalls: []string{}},
		refused("declare 689", "harness_init\nharness_declare_vmids 689\n", 2, "is not one of 690-699"),
		refused("declare 700", "harness_init\nharness_declare_vmids 700\n", 2, "is not one of 690-699"),
		refused("declare 0690", "harness_init\nharness_declare_vmids 0690\n", 2, "is not one of 690-699"),
		refused("declare a huge number", "harness_init\nharness_declare_vmids 690000000000000000000000000\n", 2, "is not one of 690-699"),
		refused("declare -690", "harness_init\nharness_declare_vmids -690\n", 2, "is not one of 690-699"),
		{name: "ceiling not taken from the environment", env: map[string]string{"HARNESS_VMID_RE": "^[0-9]+$"}, body: "harness_init\nharness_declare_vmids 700\n", wantCode: 2, wantErr: "is not one of 690-699", noMutation: true},
		refused("declare a non-number", "harness_init\nharness_declare_vmids 69x\n", 2, "is not one of 690-699"),
		refused("declare nothing", "harness_init\nharness_declare_vmids\n", 2, "at least one VMID"),
		refused("declare twice", "harness_init\nharness_declare_vmids 690\nharness_declare_vmids 691\n", 2, "ran twice"),
		{name: "a read of a VM with no subpath", body: stdInit + "harness_vm_get 690\n", wantCode: 2, wantErr: "needs at least 2 arguments", wantCalls: []string{}},
		{name: "read an undeclared VM", body: stdInit + "harness_vm_get 691 config\n", wantCode: 2, wantErr: "VMID 691 was not declared", wantCalls: []string{}},
		refused("change an undeclared VM", stdInit+"harness_vm_post 691 status/stop\n", 2, "VMID 691 was not declared"),
		refused("change VM 0690", stdInit+"harness_vm_post 0690 status/stop\n", 2, "is not one of 690-699"),
		refused("create an undeclared VM", stdInit+"harness_vm_create 691 '{}'\n", 2, "VMID 691 was not declared"),

		// lib's state and functions cannot be changed by accident.
		{name: "a lib function cannot be redefined", body: stdInit + "_harness_guard_existing() { :; }\n" + post, wantCode: 1, wantErr: "readonly function", wantNotErr: "REACHED", noMutation: true},
		{name: "the declared set cannot be written after declare", body: stdInit + "HARNESS_DECLARED[691]=1\nharness_vm_post 691 status/stop\n", wantCode: 1, wantErr: "readonly variable", noMutation: true},
		refused("the declared set written before declare", "harness_init\nHARNESS_DECLARED[691]=1\nharness_declare_vmids 690\n", 2, "the declared set was written before it"),
		refused("the declared set written instead of declare", "harness_init\nHARNESS_DECLARED[690]=1\nharness_vm_post 690 status/stop\n", 2, "harness_declare_vmids has not run"),
		{name: "HARNESS_INITIALIZED written instead of init", body: "HARNESS_INITIALIZED=1\nharness_get /cluster/resources\n", wantCode: 2, wantErr: "harness_init has not run", wantCalls: []string{}},
		refused("HARNESS_STORAGE written instead of require", stdInit+"HARNESS_STORAGE=pveforge-harness\n"+`harness_vm_create 690 '{"scsi0":"pveforge-harness:1"}'`+"\n", 2, "on the required storage"),
		{name: "PVEFORGE_BIN cannot be changed after init", body: stdInit + "PVEFORGE_BIN=/bin/true\n", wantCode: 1, wantErr: "readonly variable", wantCalls: []string{}},
		{name: "the created-VM record cannot be repointed", body: stdInit + "HARNESS_CREATED_FILE=/tmp/x\n", wantCode: 1, wantErr: "readonly variable", wantCalls: []string{}},

		// Pool, node and tag, before any change.
		{name: "not a pool member", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[]}]`}, body: stdInit + post, wantCode: 2, wantErr: "not a qemu member of pool", wantNotErr: "REACHED", noMutation: true},
		{name: "a container is not a qemu member", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"lxc","vmid":690,"node":"qa-pve-07"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "not a qemu member of pool", noMutation: true},
		{name: "member on another node", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-01"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "on node qa-pve-01", noMutation: true},
		{name: "vmid as a string is not a match", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":"690","node":"qa-pve-07"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "not a qemu member of pool", noMutation: true},
		{name: "pool answer an object", resp: map[string]string{keyPool: `{}`}, body: stdInit + post, wantCode: 1, wantErr: "unexpected shape", noMutation: true},
		{name: "pool answer two pools", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[]},{"poolid":"pveforge-harness","members":[]}]`}, body: stdInit + post, wantCode: 1, wantErr: "unexpected shape", noMutation: true},
		{name: "pool answer without members", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness"}]`}, body: stdInit + post, wantCode: 1, wantErr: "unexpected shape", noMutation: true},
		{name: "untagged", resp: map[string]string{keyConf: `{"cores":"1"}`}, body: stdInit + post, wantCode: 2, wantErr: "does not carry tag", noMutation: true},
		{name: "a longer tag is not the tag", resp: map[string]string{keyConf: `{"tags":"pveforge-harness-old;x"}`}, body: stdInit + post, wantCode: 2, wantErr: "does not carry tag", noMutation: true},
		{name: "the tag matches case and all", resp: map[string]string{keyConf: `{"tags":"PVEForge-Harness"}`}, body: stdInit + post, wantCode: 2, wantErr: "does not carry tag", noMutation: true},
		{name: "an unreadable created-VM record stops a destroy", body: stdInit + `harness_vm_create 690 '{"cores":"1"}'` + "\nchmod 000 \"$HARNESS_CREATED_FILE\"\nharness_vm_destroy 690\n",
			wantCode: 2, wantErr: "cannot read"},
		refused("destroy a VM this run did not create", stdInit+"harness_vm_destroy 690\n", 2, "was not created by this run"),
		{name: "delete on an untagged VM", resp: map[string]string{keyConf: `{"cores":"1"}`}, body: stdInit + "harness_vm_delete 690 snapshot/s1\n", wantCode: 2, wantErr: "does not carry tag", noMutation: true},
		{name: "read path with a space", body: "harness_init\nharness_get '/cluster/resources x'\n", wantCode: 2, wantErr: "not an API path", wantCalls: []string{}},

		// Create.
		refused("create params name vmid", stdInit+`harness_vm_create 690 '{"vmid":"691"}'`+"\n", 2, "field vmid is not allowed"),
		refused("create params name pool", stdInit+`harness_vm_create 690 '{"pool":"other"}'`+"\n", 2, "field pool is not allowed"),
		refused("create params name tags", stdInit+`harness_vm_create 690 '{"tags":"x"}'`+"\n", 2, "field tags is not allowed"),
		refused("create params put a disk elsewhere", stdInitS+`harness_vm_create 690 '{"scsi0":"local-lvm:8"}'`+"\n", 2, "on the required storage"),
		refused("create params not strings", stdInit+`harness_vm_create 690 '{"cores":1}'`+"\n", 2, "single-line strings"),
		refused("create params with a line break", stdInit+`harness_vm_create 690 '{"description":"a\nb"}'`+"\n", 2, "single-line strings"),
		refused("create params not an object", stdInit+`harness_vm_create 690 '["cores"]'`+"\n", 2, "single-line strings"),
		{name: "create fails", rc: map[string]int{"vm create 690": 1}, body: stdInit + `harness_vm_create 690 '{"cores":"1"}'` + "\necho REACHED >&2\n", wantCode: 1, wantNotErr: "REACHED",
			wantCalls: []string{`vm create qa-pve-07-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`}},
		// A failed create is never recorded: a subshell that failed to create
		// leaves nothing this run may destroy.
		{name: "a failed create is never recorded", rc: map[string]int{"vm create 690": 1}, body: stdInit + `( harness_vm_create 690 '{"cores":"1"}' ) || true` + "\nharness_vm_destroy 690\n", wantCode: 2, wantErr: "was not created by this run",
			wantCalls: []string{`vm create qa-pve-07-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`, "api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness"}},

		// A failure inside $(...) aborts, and pveforge's own status reaches
		// the caller.
		{name: "a failed read aborts before the write", rc: map[string]int{keyPool: 1}, body: stdInit + post, wantCode: 1, wantNotErr: "REACHED",
			wantCalls: []string{"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness"}},
		{name: "a signal status passes through", rc: map[string]int{"post /nodes/qa-pve-07/qemu/690/status/stop": 130}, body: stdInit + post, wantCode: 130, wantNotErr: "REACHED"},

		// Positive control: every guard passes when it should, and the exact
		// calls go out, the create through `vm create` and never an unlocked
		// api write.
		{name: "create, snapshot, roll back, delete the snapshot, destroy", body: stdInitS +
			`harness_vm_create 690 '{"cores":"1","scsi0":"pveforge-harness:1"}'` + "\n" +
			"harness_vm_post 690 snapshot snapname=s1 vmstate=0\n" +
			"harness_vm_post 690 snapshot/s1/rollback\n" +
			"harness_vm_delete 690 snapshot/s1\n" +
			"harness_vm_destroy 690\n" +
			"harness_vm_get 690 status/current >/dev/null\n",
			resp:    map[string]string{"get /nodes/qa-pve-07/qemu/690/status/current": `{"status":"stopped"}`},
			wantErr: "harness: delete /nodes/qa-pve-07/qemu/690 purge=1 destroy-unreferenced-disks=1",
			wantCalls: []string{
				`vm create qa-pve-07-harness 690 --roster R --json {"cores":"1","scsi0":"pveforge-harness:1","pool":"pveforge-harness"}`,
				"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
				"api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data tags=pveforge-harness",
				"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json",
				"api post /nodes/qa-pve-07/qemu/690/snapshot qa-pve-07-harness --roster R -o json --data snapname=s1 --data vmstate=0",
				"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json",
				"api post /nodes/qa-pve-07/qemu/690/snapshot/s1/rollback qa-pve-07-harness --roster R -o json",
				"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json",
				"api delete /nodes/qa-pve-07/qemu/690/snapshot/s1 qa-pve-07-harness --roster R -o json",
				"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json",
				"api delete /nodes/qa-pve-07/qemu/690 qa-pve-07-harness --roster R -o json --data purge=1 --data destroy-unreferenced-disks=1",
				"api get /nodes/qa-pve-07/qemu/690/status/current qa-pve-07-harness --roster R -o json",
			}},
	}
	cases = append(cases, tagSeparatorCases()...)
	cases = append(cases, endpointCases()...)
	cases = append(cases, fieldCases()...)
	return append(cases, ifNotCases()...)
}

// guardReads are the reads a change of VM 690 makes before it writes.
var guardReads = []string{
	"api get /pools qa-pve-07-harness --roster R -o json --data poolid=pveforge-harness",
	"api get /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json",
}

// PVE splits a tag list (PVE::ParseUtils::split_list, pve-common) on NUL
// when it holds one, else on commas, semicolons and whitespace.
func tagSeparatorCases() []harnessCase {
	var cs []harnessCase
	for name, tags := range map[string]string{"comma": `a,pveforge-harness`, "semicolon": `a;pveforge-harness`, "space": `a pveforge-harness`, "tab": `a\tpveforge-harness`, "newline": `a\npveforge-harness`, "NUL": `a\u0000pveforge-harness`, "alone": `pveforge-harness`} {
		cs = append(cs, harnessCase{name: "tag list split on " + name, resp: map[string]string{keyConf: `{"tags":"` + tags + `"}`}, body: stdInit + "harness_vm_post 690 status/stop\n",
			wantCalls: append(append([]string(nil), guardReads...), "api post /nodes/qa-pve-07/qemu/690/status/stop qa-pve-07-harness --roster R -o json")})
	}
	return cs
}

// Only the named endpoints may change a VM; every other one is refused
// before anything is read or sent.
func endpointCases() []harnessCase {
	var cs []harnessCase
	for _, call := range []string{
		"harness_vm_post 690 clone newid=500",
		"harness_vm_post 690 migrate",
		"harness_vm_post 690 move_disk disk=scsi0",
		"harness_vm_put 690 resize disk=scsi0 size=+1G",
		"harness_vm_post 690 template",
		"harness_vm_post 690 status/reset",
		"harness_vm_post 690 status/suspend",
		"harness_vm_post 690 agent/exec command=true",
		"harness_vm_post 690 config cores=2",
		"harness_vm_put 690 snapshot",
		"harness_vm_delete 690 config",
		"harness_vm_delete 690 ''",
		"harness_vm_post 690 ../691/status/stop",
		"harness_vm_post 690 snapshot/s1/rollback/x",
		"harness_vm_post 690 snapshot/a/b/rollback",
		"harness_vm_post 690 snapshot/1bad/rollback",
		"harness_vm_delete 690 snapshot/1bad",
	} {
		cs = append(cs, harnessCase{name: "endpoint refused: " + call, body: stdInit + call + "\n", wantCode: 2, wantErr: "is not an allowed harness change", wantCalls: []string{}})
	}
	for _, c := range []struct{ call, want string }{
		{"harness_vm_put 690 config cores=2", "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data cores=2"},
		{"harness_vm_post 690 snapshot snapname=s1", "api post /nodes/qa-pve-07/qemu/690/snapshot qa-pve-07-harness --roster R -o json --data snapname=s1"},
		{"harness_vm_post 690 snapshot/pvh-golden/rollback", "api post /nodes/qa-pve-07/qemu/690/snapshot/pvh-golden/rollback qa-pve-07-harness --roster R -o json"},
		{"harness_vm_post 690 status/start", "api post /nodes/qa-pve-07/qemu/690/status/start qa-pve-07-harness --roster R -o json"},
		{"harness_vm_post 690 status/stop", "api post /nodes/qa-pve-07/qemu/690/status/stop qa-pve-07-harness --roster R -o json"},
		{"harness_vm_post 690 status/shutdown", "api post /nodes/qa-pve-07/qemu/690/status/shutdown qa-pve-07-harness --roster R -o json"},
		{"harness_vm_delete 690 snapshot/s1", "api delete /nodes/qa-pve-07/qemu/690/snapshot/s1 qa-pve-07-harness --roster R -o json"},
	} {
		cs = append(cs, harnessCase{name: "endpoint allowed: " + c.call, body: stdInit + c.call + "\n", wantCalls: append(append([]string(nil), guardReads...), c.want)})
	}
	return cs
}

// Fields are an allow-list per endpoint: nothing names another VM, pool, node
// or storage, the tag, a hook or a snippet; a disk may be set only on a VM
// this run created, and only on the required storage; no field holds a
// control character.
func fieldCases() []harnessCase {
	const create = `harness_vm_create 690 '{"cores":"1"}'` + "\n"
	put := func(kv string) string {
		return "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data " + kv
	}
	var cs []harnessCase
	for _, kv := range []string{
		"vmid=691", "newid=500", "pool=other", "target=qa-pve-01", "migratedfrom=qa-pve-01", "storage=local-lvm", "tags=x",
		"vmstatestorage=local-lvm", "cicustom=user=local-lvm:snippets/x.yaml", "hookscript=local:snippets/x.pl", "template=1", "lock=backup",
		"args=-no-reboot", "description=x", "onboot=1", "hostpci0=0000:01:00.0", "usb0=host=1234:5678",
		"delete=tags", "'delete=cores;tags'", "'delete=cores tags'", "delete=hookscript", "delete=delete",
		"sata0=pveforge-harness:8", "virtio0=pveforge-harness:8", "efidisk0=pveforge-harness:1", "tpmstate0=pveforge-harness:1", "unused0=pveforge-harness:vm-690-disk-1",
		"Cores=2", "=2", "cores",
	} {
		cs = append(cs, harnessCase{name: "field refused: " + kv, body: stdInitS + "harness_vm_put 690 config " + kv + "\n", wantCode: 2, wantErr: "harness", wantCalls: []string{}})
	}
	// On a VM this run created: every disk still has to be on the required
	// storage, and the two exceptions are exact.
	for _, kv := range []string{
		"scsi1=local-lvm:8", "ide0=cdrom", "scsi1=/dev/sdb", "ide2=local:iso/pve.iso", "ide2=local-lvm:iso/pve.iso,media=cdrom",
		"ide2=local:iso/../images/x.iso,media=cdrom", "ide2=local:iso/sub/x.iso,media=cdrom",
		"scsi0=pveforge-harness:0,import-from=local-lvm:vm-1-disk-0", "scsi0=pveforge-harness:0,import-from=local:iso/x.iso",
		"scsi0=pveforge-harness:0,import-from=local:import/../x.qcow2", "scsi0=none,import-from=local:import/x.qcow2",
		"scsi0=file=local-lvm:8", "scsi0=pveforge-harness:8,file=local-lvm:9",
		"sata0=pveforge-harness:8", "virtio0=pveforge-harness:8", "efidisk0=pveforge-harness:1",
		// An existing volume, another VM's disk say, is never taken: only a new
		// allocation or the cloud-init drive.
		"scsi1=pveforge-harness:vm-100-disk-0", "scsi1=pveforge-harness:base-900-disk-0/vm-690-disk-1", "scsi1=pveforge-harness:8.5",
		"scsi1=pveforge-harness:", "ide2=pveforge-harness:vm-690-cloudinit",
		// Options: never another volume, and every option is key=value.
		"ide3=none,/dev/sdc", "scsi1=pveforge-harness:8,volume=local-lvm:vm-1-disk-0", "scsi1=pveforge-harness:8,volume=x",
		"scsi1=pveforge-harness:8,x=local-lvm:vm-100-disk-0", "scsi1=pveforge-harness:8,,cache=none",
	} {
		want := "on the required storage"
		if !strings.HasPrefix(kv, "scsi") && !strings.HasPrefix(kv, "ide") {
			want = "is not allowed here"
		}
		cs = append(cs, harnessCase{name: "disk refused on a created VM: " + kv, body: stdInitS + create + "harness_vm_put 690 config " + kv + "\n", wantCode: 2, wantErr: want,
			wantLast: "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data tags=pveforge-harness"})
	}
	for _, kv := range []string{"scsi1=pveforge-harness:8", "scsi1=pveforge-harness:8,cache=writeback,discard=on", "ide2=local:iso/pve.iso,media=cdrom", "ide2=pveforge-harness:cloudinit", "ide2=none,media=cdrom",
		"scsi0=pveforge-harness:0,import-from=local:import/debian-13.qcow2", "delete=ide2"} {
		cs = append(cs, harnessCase{name: "disk allowed on a created VM: " + kv, body: stdInitS + create + "harness_vm_put 690 config " + kv + "\n", wantLast: put(kv)})
		cs = append(cs, harnessCase{name: "disk refused on a VM this run did not create: " + kv, body: stdInitS + "harness_vm_put 690 config " + kv + "\n", wantCode: 2, wantErr: "only on a VM this run created", wantCalls: []string{}})
	}
	for _, kv := range []string{"boot=order=scsi0", "delete=cores", "net0=virtio,bridge=vmbr0", "ipconfig0=ip=10.20.247.92/21,gw=10.20.240.1", "name=pvh-nfs", "machine=q35"} {
		cs = append(cs, harnessCase{name: "field allowed: " + kv, body: stdInitS + "harness_vm_put 690 config " + kv + "\n", wantCalls: append(append([]string(nil), guardReads...), put(kv))})
	}
	// A NIC names exactly one bridge, and only vmbr0.
	for _, kv := range []string{"net0=virtio,bridge=vmbr1", "net0=virtio", "net0=virtio,bridge=vmbr0,bridge=vmbr1", "net0=virtio,bridge=vmbr0,bridge=vmbr0", "net1=e1000,bridge=vmbr00"} {
		cs = append(cs, harnessCase{name: "NIC refused: " + kv, body: stdInitS + "harness_vm_put 690 config " + kv + "\n", wantCode: 2, wantErr: "exactly one bridge", wantCalls: []string{}})
	}
	for _, kv := range []string{"net0=virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=0", "delete=net1"} {
		cs = append(cs, harnessCase{name: "NIC allowed: " + kv, body: stdInitS + "harness_vm_put 690 config " + kv + "\n", wantCalls: append(append([]string(nil), guardReads...), put(kv))})
	}
	cs = append(cs, harnessCase{name: "create params refused: a NIC on vmbr2", body: stdInitS + `harness_vm_create 690 '{"net0":"virtio,bridge=vmbr2"}'` + "\n", wantCode: 2, wantErr: "exactly one bridge", wantCalls: []string{}})
	cs = append(cs, harnessCase{name: "create params refused: another VM's disk", body: stdInitS + `harness_vm_create 690 '{"scsi0":"pveforge-harness:vm-100-disk-0"}'` + "\n", wantCode: 2, wantErr: "new allocation", wantCalls: []string{}})
	// delete= items are never glob-expanded against the current directory.
	cs = append(cs, harnessCase{name: "a delete item is not a glob", body: stdInitS + "touch name\nharness_vm_put 690 config 'delete=n*e'\n", wantCode: 2, wantErr: "delete of field n*e is not allowed", wantCalls: []string{}})
	// A relative PATH entry is refused, not resolved relative to wherever the
	// script stands later.
	cs = append(cs, harnessCase{name: "a tool found through a relative PATH entry", pre: "mkdir tbin\nln -s \"$(command -v jq)\" tbin/jq\nPATH=tbin:$PATH\n", body: stdInit, wantCode: 2, wantErr: "not an absolute path", wantCalls: []string{}})
	cs = append(cs, harnessCase{name: "a disk refused without a required storage", body: stdInit + `harness_vm_create 690 '{"scsi0":"pveforge-harness:8"}'` + "\n", wantCode: 2, wantErr: "on the required storage", wantCalls: []string{}})
	// The same allow-list screens create's params.
	for _, p := range []string{`{"hookscript":"local:snippets/x.pl"}`, `{"cicustom":"user=local:snippets/x"}`, `{"vmstatestorage":"local-lvm"}`, `{"template":"1"}`, `{"scsi0":"local-lvm:8"}`} {
		cs = append(cs, harnessCase{name: "create params refused: " + p, body: stdInitS + "harness_vm_create 690 '" + p + "'\n", wantCode: 2, wantErr: "harness", wantCalls: []string{}})
	}
	// Other endpoints take only their own fields.
	for _, c := range []struct{ call, want string }{
		{"harness_vm_post 690 snapshot snapname=s1 vmstatestorage=local-lvm", ""},
		{"harness_vm_post 690 snapshot/s1/rollback start=1", "api post /nodes/qa-pve-07/qemu/690/snapshot/s1/rollback qa-pve-07-harness --roster R -o json --data start=1"},
		{"harness_vm_post 690 status/stop timeout=30", "api post /nodes/qa-pve-07/qemu/690/status/stop qa-pve-07-harness --roster R -o json --data timeout=30"},
		{"harness_vm_post 690 status/stop skiplock=1", ""},
		{"harness_vm_post 690 status/shutdown forceStop=1", "api post /nodes/qa-pve-07/qemu/690/status/shutdown qa-pve-07-harness --roster R -o json --data forceStop=1"},
		{"harness_vm_post 690 status/start timeout=60 migratedfrom=qa-pve-01", ""},
		{"harness_vm_delete 690 snapshot/s1 force=1", ""},
	} {
		if c.want == "" {
			cs = append(cs, harnessCase{name: "endpoint field refused: " + c.call, body: stdInit + c.call + "\n", wantCode: 2, wantErr: "is not allowed here", wantCalls: []string{}})
		} else {
			cs = append(cs, harnessCase{name: "endpoint field allowed: " + c.call, body: stdInit + c.call + "\n", wantCalls: append(append([]string(nil), guardReads...), c.want)})
		}
	}
	// A destroy takes no fields: lib itself sends purge=1 and
	// destroy-unreferenced-disks=1, so PVE's worker frees every disk and a
	// failure shows in its task's exit status.
	for _, f := range []string{"skiplock=1", "purge=1", "destroy-unreferenced-disks=0"} {
		cs = append(cs, harnessCase{name: "destroy field refused: " + f, body: stdInit + create + "harness_vm_destroy 690 " + f + "\n", wantCode: 2, wantErr: "harness_vm_destroy takes only a VMID",
			wantLast: "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data tags=pveforge-harness"})
	}
	// NEW-1: no control character in any field name or value, a newline least
	// of all: it would start a second line of disk options.
	for name, body := range map[string]string{
		"newline in a disk value":               `harness_vm_put 690 config $'scsi0=pveforge-harness:0\n,import-from=local-lvm:vm-100-disk-0'`,
		"carriage return":                       `harness_vm_put 690 config $'name=a\rb'`,
		"tab":                                   `harness_vm_put 690 config $'name=a\tb'`,
		"DEL":                                   `harness_vm_put 690 config $'name=a\x7fb'`,
		"SOH":                                   `harness_vm_put 690 config $'name=a\x01b'`,
		"newline in a field name":               `harness_vm_put 690 config $'na\nme=a'`,
		"newline in a snapshot":                 `harness_vm_post 690 snapshot $'snapname=s1\nvmstate=1'`,
		"newline in create":                     `harness_vm_create 690 '{"name":"a\nb"}'`,
		"newline in a create key":               `harness_vm_create 690 '{"na\nme":"a"}'`,
		"DEL in create":                         `harness_vm_create 690 '{"name":"a\u007fb"}'`,
		"a newline making two fields in create": `harness_vm_create 691 '{"name":"a\nmemory=1"}'`,
		"newline in a read path":                `harness_get $'/cluster/resources\n'`,
		"SOH in a read path":                    `harness_get $'/cluster/\x01resources'`,
		"newline in a read field":               `harness_get /cluster/resources $'type=vm\nx=1'`,
	} {
		cs = append(cs, harnessCase{name: "control character refused: " + name, body: stdInitS + create + body + "\n", wantCode: 2, wantErr: "harness",
			wantLast: "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data tags=pveforge-harness"})
	}
	// Tags: ASCII whitespace separates, NBSP and the other Unicode spaces do
	// not; NUL, when present, is the only separator.
	for name, tags := range map[string]string{"NBSP": `a pveforge-harness`, "NEL": `a\u0085pveforge-harness`, "EM SPACE": `a pveforge-harness`, "NUL splits alone": `pveforge-harness,x\u0000y`} {
		cs = append(cs, harnessCase{name: "tag list does not split on " + name, resp: map[string]string{keyConf: `{"tags":"` + tags + `"}`}, body: stdInit + "harness_vm_post 690 status/stop\n", wantCode: 2, wantErr: "does not carry tag", noMutation: true})
	}
	cs = append(cs, harnessCase{name: "tag list split on vertical tab", resp: map[string]string{keyConf: `{"tags":"a\u000bpveforge-harness"}`}, body: stdInit + "harness_vm_post 690 status/stop\n",
		wantCalls: append(append([]string(nil), guardReads...), "api post /nodes/qa-pve-07/qemu/690/status/stop qa-pve-07-harness --roster R -o json")})
	// The C locale: under en_US.UTF-8, bash's [0-9] matches ².
	cs = append(cs, harnessCase{name: "a superscript digit is not a VMID digit", skipUnlessLocale: "en_US.UTF-8", env: map[string]string{"LC_ALL": "en_US.UTF-8"}, body: "harness_init\nharness_declare_vmids 69²\n", wantCode: 2, wantErr: "is not one of 690-699", wantCalls: []string{}})
	// Tools are found once, when lib is sourced.
	cs = append(cs, harnessCase{name: "a tool missing at source time", pathWithout: "jq", body: stdInit, wantCode: 2, wantErr: "jq is not on PATH", wantCalls: []string{}})
	cs = append(cs, harnessCase{name: "a PATH changed after sourcing finds a wrong jq and grep", body: stdInitS + "mkdir \"$HOME/wrong\"\nfor t in jq grep; do printf '#!/bin/sh\\nexit 99\\n' >\"$HOME/wrong/$t\"; chmod +x \"$HOME/wrong/$t\"; done\nPATH=$HOME/wrong:$PATH\nharness_vm_create 690 '{\"cores\":\"1\"}'\nharness_vm_put 690 config scsi1=pveforge-harness:8\n",
		wantLast: "api put /nodes/qa-pve-07/qemu/690/config qa-pve-07-harness --roster R -o json --data scsi1=pveforge-harness:8"})
	return cs
}

// Every lib function stops the script on failure even when called from an
// `if !`, which turns set -e off inside the function.
func ifNotCases() []harnessCase {
	const created = `harness_vm_create 690 '{"cores":"1"}'` + "\n"
	var cs []harnessCase
	for _, c := range []struct {
		name, pre, call string
		resp            map[string]string
		rc              map[string]int
		env             map[string]string
		roster          string
		code            int
	}{
		{name: "harness_init", call: "harness_init", roster: "missing", code: 2},
		{name: "harness_declare_vmids", pre: "harness_init\n", call: "harness_declare_vmids 700", code: 2},
		{name: "harness_require_storage", pre: "harness_init\n", call: "harness_require_storage Local", code: 2},
		{name: "harness_get", pre: stdInit, call: "harness_get /cluster/resources", resp: map[string]string{"get /cluster/resources": "[]"}, rc: map[string]int{"get /cluster/resources": 1}, code: 1},
		{name: "harness_vm_get", pre: stdInit, call: "harness_vm_get 690 config", rc: map[string]int{keyConf: 1}, code: 1},
		{name: "harness_vm_put", pre: stdInit, call: "harness_vm_put 690 config cores=2", rc: map[string]int{"put /nodes/qa-pve-07/qemu/690/config cores=2": 1}, code: 1},
		{name: "harness_vm_post", pre: stdInit, call: "harness_vm_post 690 status/stop", rc: map[string]int{"post /nodes/qa-pve-07/qemu/690/status/stop": 1}, code: 1},
		{name: "harness_vm_delete", pre: stdInit, call: "harness_vm_delete 690 snapshot/s1", rc: map[string]int{"delete /nodes/qa-pve-07/qemu/690/snapshot/s1": 1}, code: 1},
		{name: "harness_vm_destroy", pre: stdInit + created, call: "harness_vm_destroy 690", rc: map[string]int{"delete /nodes/qa-pve-07/qemu/690 purge=1 destroy-unreferenced-disks=1": 1}, code: 1},
		{name: "harness_vm_create", pre: stdInit, call: `harness_vm_create 690 '{"cores":"1"}'`, rc: map[string]int{"vm create 690": 1}, code: 1},
		{name: "a guard's pool read", pre: stdInit, call: "harness_vm_post 690 status/stop", rc: map[string]int{keyPool: 1}, code: 1},
		{name: "a guard's config read", pre: stdInit, call: "harness_vm_post 690 status/stop", rc: map[string]int{keyConf: 1}, code: 1},
	} {
		cs = append(cs, harnessCase{name: "if ! " + c.name, resp: c.resp, rc: c.rc, env: c.env, roster: c.roster, wantCode: c.code, wantNotErr: "CONTINUED",
			body: c.pre + "if ! " + c.call + "; then echo CONTINUED >&2; fi\necho CONTINUED >&2\n"})
	}
	// The reviewer's case: a failed create must not be followed by the tag
	// write or the destroy, in either form a script might write it.
	for name, body := range map[string]string{
		"create fails under if !": `if ! harness_vm_create 690 '{"cores":"1"}'; then echo SCRIPT-CONTINUED >&2; fi` + "\nharness_vm_destroy 690\n",
		"create fails under ||":   `harness_vm_create 690 '{"cores":"1"}' || echo SCRIPT-CONTINUED >&2` + "\nharness_vm_destroy 690\n",
	} {
		cs = append(cs, harnessCase{name: name, rc: map[string]int{"vm create 690": 1}, body: stdInit + body, wantCode: 1, wantNotErr: "SCRIPT-CONTINUED",
			wantCalls: []string{`vm create qa-pve-07-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`}})
	}
	return cs
}

// outerInvariantCases pins read_outer_identity's guarantees from a lib driver
// (one of the three (b) contexts; verify-root.sh and stage14 are the other two,
// in their own tests — a lib-only test would lie-green the two scripts):
//   - (a) the outer identity is readonly the instant it validates;
//   - (b) a bad/missing key refuses with exit 2 and ZERO pveforge calls, before
//     the lock and any request (missing/unknown key, inverted/non-decade/
//     oversized VMID band, an FQDN not under the node);
//   - (R2) an exported HARNESS_* never wins over the file's value;
//   - (c) the roster is host-keyed with NO un-keyed fallback (an old un-keyed
//     harness-outer.toml is planted, so a fallback would wrongly succeed).
func outerInvariantCases(t *testing.T) []harnessCase {
	t.Helper()
	good := exampleOuterEnv(t)
	drop := func(key string) string {
		var keep []string
		for _, l := range strings.Split(good, "\n") {
			if !strings.HasPrefix(l, key+"=") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	return []harnessCase{
		// (a) readonly after validation: a bug reassigning the identity dies,
		// and no write goes out after it.
		{name: "outer identity readonly after the reader", body: stdInit + "HARNESS_NODE=evil\nharness_vm_post 690 status/stop\necho REACHED >&2\n",
			wantCode: 1, wantErr: "readonly variable", wantNotErr: "REACHED", wantCalls: []string{}},
		{name: "outer VMID_RE readonly after the reader", body: stdInit + "HARNESS_VMID_RE='^[0-9]+$'\nharness_declare_vmids 700\n",
			wantCode: 1, wantErr: "readonly variable", wantCalls: []string{}},
		// (b) refuse before any network, exit 2, zero calls.
		{name: "outer env missing", outerEnv: "missing", body: stdInit, wantCode: 2, wantErr: "harness-outer.env does not exist", wantCalls: []string{}},
		{name: "outer OUTER_NODE missing", outerEnv: drop("OUTER_NODE"), body: stdInit, wantCode: 2, wantErr: "OUTER_NODE is missing", wantCalls: []string{}},
		{name: "outer unknown key", outerEnv: good + "\nOUTER_BOGUS=x\n", body: stdInit, wantCode: 2, wantErr: "unknown key OUTER_BOGUS", wantCalls: []string{}},
		{name: "outer repeated key", outerEnv: good + "\nOUTER_TAG=again\n", body: stdInit, wantCode: 2, wantErr: "OUTER_TAG is set twice", wantCalls: []string{}},
		{name: "outer VMID band inverted", outerEnv: exampleOuterEnv(t, "VMID_LOW=700", "VMID_HIGH=699"), body: stdInit, wantCode: 2, wantErr: "must be VMID_LOW + 9", wantCalls: []string{}},
		{name: "outer VMID band not a decade", outerEnv: exampleOuterEnv(t, "VMID_LOW=695", "VMID_HIGH=704"), body: stdInit, wantCode: 2, wantErr: "not decade-aligned", wantCalls: []string{}},
		{name: "outer VMID oversized", outerEnv: exampleOuterEnv(t, "VMID_LOW=6900000000", "VMID_HIGH=6900000009"), body: stdInit, wantCode: 2, wantErr: "is not a valid value", wantCalls: []string{}},
		{name: "outer FQDN not under node", outerEnv: exampleOuterEnv(t, "OUTER_FQDN=other.lab.quantum.com"), body: stdInit, wantCode: 2, wantErr: "does not begin with OUTER_NODE", wantCalls: []string{}},
		// (R2) the environment never wins over the file.
		{name: "exported HARNESS_TARGET does not win", env: map[string]string{"HARNESS_TARGET": "evil"}, resp: map[string]string{"get /cluster/resources": "[]"},
			body: stdInit + "harness_get /cluster/resources >/dev/null\n", wantCalls: []string{"api get /cluster/resources qa-pve-07-harness --roster R -o json"}},
		{name: "exported HARNESS_NODE does not win", env: map[string]string{"HARNESS_NODE": "evil"}, resp: map[string]string{"get /nodes/qa-pve-07/version": "{}"},
			body: stdInit + "harness_get \"/nodes/$HARNESS_NODE/version\" >/dev/null\n", wantCalls: []string{"api get /nodes/qa-pve-07/version qa-pve-07-harness --roster R -o json"}},
		// (R7) layer 1 — the per-key pattern rejects '.' in the values that become
		// path/regex segments, so a '.' cannot reach the D5 ownership regex.
		{name: "outer OUTER_POOL rejects a dot", outerEnv: exampleOuterEnv(t, "OUTER_POOL=a.b"), body: stdInit, wantCode: 2, wantErr: "OUTER_POOL='a.b' is not a valid value", wantCalls: []string{}},
		{name: "outer OUTER_TARGET rejects a dot", outerEnv: exampleOuterEnv(t, "OUTER_TARGET=a.b"), body: stdInit, wantCode: 2, wantErr: "OUTER_TARGET='a.b' is not a valid value", wantCalls: []string{}},
		// (R7) layer 2 — d5_ere_escape makes a metacharacter literal, so even a
		// value the pattern DOES allow (a storage id may contain '.') cannot
		// inject a regex wildcard into the ownership test: /storage/axb must NOT
		// match storage/a.b. (OUTER_STORAGE=a.b is a legal storage id.)
		{name: "D5 ownership regex escapes a dot", outerEnv: exampleOuterEnv(t, "OUTER_STORAGE=a.b"),
			body: "source \"$(dirname \"$HARNESS_LIB\")/d5/evidence.sh\"\n" +
				"[ \"$(d5_ere_escape 'a.b')\" = 'a\\.b' ] || { echo \"BAD-ESCAPE $(d5_ere_escape 'a.b')\" >&2; exit 1; }\n" +
				"re=\"^/(storage/$(d5_ere_escape \"$D5_STORAGE\"))(\\$|/)\"\n" +
				"[[ /storage/a.b =~ $re ]] || { echo R7-NOMATCH >&2; exit 1; }\n" +
				"if [[ /storage/axb =~ $re ]]; then echo R7-LEAK >&2; exit 1; fi\n" +
				"echo R7-OK >&2\n",
			wantErr: "R7-OK", wantNotErr: "R7-LEAK", wantCalls: []string{}},
		// (R6) the VMID band retargets the match regex, so every script's
		// harness_declare_vmids (built from the band) follows it: with a 700
		// band, 700-702 are declarable and the old 690 decade is refused. This
		// backstops the destructive VMID lists in golden-reset/probe/build/
		// stage14/verify-token, which all go through this match site.
		{name: "outer band retargets the VMID regex", outerEnv: exampleOuterEnv(t, "VMID_LOW=700", "VMID_HIGH=709"),
			body: "harness_init\nharness_declare_vmids 700 701 702\n[ \"$HARNESS_VMID_RE\" = '^70[0-9]$' ] || { echo BAD-RE >&2; exit 1; }\n", wantCalls: []string{}},
		{name: "outer band refuses the old decade", outerEnv: exampleOuterEnv(t, "VMID_LOW=700", "VMID_HIGH=709"),
			body: "harness_init\nharness_declare_vmids 690\n", wantCode: 2, wantErr: "is not one of 700-709", wantCalls: []string{}},
		// (c) host-keyed roster, NO un-keyed fallback. OUTER_NODE=qa-pve-08 makes
		// harness_init look for harness-qa-pve-08-outer.toml (absent); we plant
		// the OLD un-keyed harness-outer.toml so a silent fallback would succeed
		// and this would NOT refuse.
		{name: "roster is host-keyed with no fallback", outerEnv: exampleOuterEnv(t, "OUTER_NODE=qa-pve-08", "OUTER_FQDN=qa-pve-08.lab.quantum.com"),
			plantFiles: map[string]string{"harness-outer.toml": "# planted un-keyed roster\n"},
			body:       stdInit, wantCode: 2, wantErr: "harness-qa-pve-08-outer.toml does not exist", wantCalls: []string{}},
		// (c2) the refusal's GUIDANCE. Same setup as (c): node qa-pve-08, the
		// un-keyed harness-outer.toml planted. One substring per row, so a
		// failure names the clause that went missing. "never read" is a LITERAL
		// part of the refusal-message contract (the statement that the un-keyed
		// file is never read / is not a fallback); the behavioural no-fallback
		// property is pinned by (c) above, not by this text.
		{name: "roster refusal names OUTER_NODE keying", outerEnv: exampleOuterEnv(t, "OUTER_NODE=qa-pve-08", "OUTER_FQDN=qa-pve-08.lab.quantum.com"),
			plantFiles: map[string]string{"harness-outer.toml": "# planted un-keyed roster\n"},
			body:       stdInit, wantCode: 2, wantErr: "OUTER_NODE=qa-pve-08", wantCalls: []string{}},
		{name: "roster refusal names the un-keyed file", outerEnv: exampleOuterEnv(t, "OUTER_NODE=qa-pve-08", "OUTER_FQDN=qa-pve-08.lab.quantum.com"),
			plantFiles: map[string]string{"harness-outer.toml": "# planted un-keyed roster\n"},
			// NOT a substring of the keyed path harness-qa-pve-08-outer.toml.
			body: stdInit, wantCode: 2, wantErr: "the un-keyed harness-outer.toml", wantCalls: []string{}},
		{name: "roster refusal names the pre-b21c9c2 change", outerEnv: exampleOuterEnv(t, "OUTER_NODE=qa-pve-08", "OUTER_FQDN=qa-pve-08.lab.quantum.com"),
			plantFiles: map[string]string{"harness-outer.toml": "# planted un-keyed roster\n"},
			// "Before b21c9c2", not bare "b21c9c2": the refusal echoes $HOME, which
			// is t.TempDir() and embeds THIS case's name, so a bare sha would be
			// satisfied by the path alone (measured: mutant M4 survived).
			body: stdInit, wantCode: 2, wantErr: "Before b21c9c2", wantCalls: []string{}},
		{name: "roster refusal states the un-keyed file is never read", outerEnv: exampleOuterEnv(t, "OUTER_NODE=qa-pve-08", "OUTER_FQDN=qa-pve-08.lab.quantum.com"),
			plantFiles: map[string]string{"harness-outer.toml": "# planted un-keyed roster\n"},
			body:       stdInit, wantCode: 2, wantErr: "never read", wantCalls: []string{}},
		// (c3) the other direction: a roster that EXISTS with the wrong mode is
		// refused for its mode, and carries none of the migration guidance.
		{name: "roster mode refusal carries no migration guidance", roster: "0644", body: stdInit, wantCode: 2,
			wantErr: "has mode 644, want 600", wantNotErr: "OUTER_NODE=", wantCalls: []string{}},
	}
}

func TestHarnessLib_Offline(t *testing.T) {
	cases := append(harnessCases(), outerInvariantCases(t)...)
	prov := provenanceCases()
	cases = append(cases, prov...)
	// Anti-vacuity: the positive control and the refusals are all here. The
	// floor is the count with the provenance rows in (deleting rows makes a
	// suite greener, lessons #4), and the provenance rows hold their own.
	if len(cases) < 318 {
		t.Fatalf("%d harness cases, want at least 318", len(cases))
	}
	if len(prov) < 32 {
		t.Fatalf("%d provenance cases, want at least 32", len(prov))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.skipUnlessLocale != "" {
				out, err := exec.Command("locale", "-a").Output()
				want := strings.ToLower(strings.ReplaceAll(c.skipUnlessLocale, "-", ""))
				if err != nil || !strings.Contains(strings.ToLower(strings.ReplaceAll(string(out), "-", "")), want) {
					t.Skipf("locale %s is not installed here, so what this case tests cannot arise", c.skipUnlessLocale)
				}
			}
			code, stderr, calls := runHarnessCase(t, c)
			if code != c.wantCode {
				t.Errorf("exit %d, want %d\nstderr:\n%s", code, c.wantCode, stderr)
			}
			if c.wantErr != "" && !strings.Contains(stderr, c.wantErr) {
				t.Errorf("stderr does not contain %q:\n%s", c.wantErr, stderr)
			}
			if c.wantNotErr != "" && strings.Contains(stderr, c.wantNotErr) {
				t.Errorf("stderr contains %q:\n%s", c.wantNotErr, stderr)
			}
			if c.wantLast != "" && (len(calls) == 0 || calls[len(calls)-1] != c.wantLast) {
				t.Errorf("last call %q, want %q", calls, c.wantLast)
			}
			if c.wantCalls != nil && strings.Join(calls, "\n") != strings.Join(c.wantCalls, "\n") {
				t.Errorf("calls:\n  %s\nwant:\n  %s", strings.Join(calls, "\n  "), strings.Join(c.wantCalls, "\n  "))
			}
			for _, call := range calls {
				if c.noMutation && isWrite(call) {
					t.Errorf("a write went out on a refused run: %s", call)
				}
				if strings.Contains(call, "--unsafe-no-lock") {
					t.Errorf("an unlocked write went out: %s", call)
				}
			}
		})
	}
}

// fakeBuildInfo is `go version -m` output for a binary, in the shape the real
// tool prints (tab-indented, "build" lines).
func fakeBuildInfo(lines ...string) string {
	out := "/bin/pveforge: go1.27.4\n\tpath\tgithub.com/suykerbuyk/pveforge/cmd/pveforge"
	for _, l := range lines {
		out += "\n\tbuild\t" + l
	}
	return out
}

const (
	provRevA = "1111111111111111111111111111111111111111" // fake go's default build, and fake git's default HEAD
	provRevB = "2222222222222222222222222222222222222222"
)

// provenanceCases pin harness_init's binary-provenance check
// (_harness_check_binary_provenance) against the fake go and git. Every
// refusal is exit 2, with ZERO pveforge calls and none of the harness's state
// (no lock, no created-VM record): the check runs before either. The real
// toolchain's side of the same contract is TestHarnessLib_ProvenanceReal.
func provenanceCases() []harnessCase {
	refuse := func(name, goOut string, rc int, want string) harnessCase {
		return harnessCase{name: "provenance refuses " + name, goOut: goOut, goRC: rc, body: "harness_init\n", wantCode: 2, wantErr: want,
			wantCalls: []string{}, wantNoState: true, wantGoCalled: true, wantGitLog: ""}
	}
	clean := fakeBuildInfo("vcs=git", "vcs.revision="+provRevA, "vcs.modified=false")
	return []harnessCase{
		refuse("a build from a modified tree", fakeBuildInfo("vcs=git", "vcs.revision="+provRevA, "vcs.modified=true"), 0, "was built from a modified tree"),
		refuse("a build with no VCS info", fakeBuildInfo("-buildvcs=false"), 0, "carries no VCS build info"),
		refuse("a go that cannot read the binary", clean, 1, "cannot read build info"),
		refuse("a vcs.modified that is neither true nor false", fakeBuildInfo("vcs=git", "vcs.revision="+provRevA, "vcs.modified=maybe"), 0, "neither true nor false"),
		refuse("a doubled vcs.modified", fakeBuildInfo("vcs.revision="+provRevA, "vcs.modified=false", "vcs.modified=false"), 0, "ambiguous VCS build info (1 vcs.revision and 2 vcs.modified"),
		refuse("a vcs.revision with no vcs.modified", fakeBuildInfo("vcs.revision="+provRevA), 0, "ambiguous VCS build info (1 vcs.revision and 0 vcs.modified"),
		refuse("a vcs.modified with no vcs.revision", fakeBuildInfo("vcs.modified=false"), 0, "ambiguous VCS build info (0 vcs.revision and 1 vcs.modified"),
		refuse("a 39-digit revision", fakeBuildInfo("vcs.revision="+provRevA[:39], "vcs.modified=false"), 0, "not a 40-digit commit id"),
		// A dirty binary is refused whether or not the revision is HEAD's.
		{name: "provenance refuses a modified tree whose revision is not HEAD", gitHead: provRevB, goOut: fakeBuildInfo("vcs.revision="+provRevA, "vcs.modified=true"),
			body: "harness_init\n", wantCode: 2, wantErr: "was built from a modified tree", wantNoState: true, wantCalls: []string{}},
		// go is looked up when harness_init runs, so it refuses THERE, with the
		// check's own text (not a source-time "go is not on PATH").
		{name: "provenance refuses when go is missing", pathWithout: "go", body: "harness_init\n", wantCode: 2, wantErr: "the harness cannot read the build info of", wantNoState: true, wantCalls: []string{}},
		{name: "provenance refuses a go found through a relative PATH entry", relTool: "go", body: "harness_init\n", wantCode: 2, wantErr: "which is not an absolute path: the harness will not run a go",
			wantNotErr: "REL-go-RAN", wantNoState: true, wantCalls: []string{}},
		// A script that sources lib.sh and never calls harness_init needs
		// neither go nor git (stage14-like consumers).
		{name: "sourcing lib.sh needs no go", pathWithout: "go", body: "echo SOURCED >&2\n", wantErr: "SOURCED", wantCalls: []string{}},
		{name: "sourcing lib.sh needs no git", pathWithout: "git", body: "echo SOURCED >&2\n", wantErr: "SOURCED", wantCalls: []string{}},
		// D1: `source lib.sh` from its own directory, set -e already active.
		{name: "bare lib.sh sourced from its own directory under set -e", cdLib: true, env: map[string]string{"HARNESS_LIB": "lib.sh"}, pre: "set -e\n",
			body:      "if [ \"$HARNESS_REPO_ROOT\" = \"$(cd ../.. && pwd -P)\" ]; then echo ROOT-OK >&2; else echo \"ROOT-BAD $HARNESS_REPO_ROOT\" >&2; fi\n",
			wantErr:   "ROOT-OK",
			wantCalls: []string{}},
		// Clean at HEAD: no refusal, no WARN, and the comparison RAN (git was
		// asked, of the checkout holding lib.sh, for HEAD).
		{name: "provenance passes a clean build at HEAD", body: "harness_init\n", wantErr: "rev 111111111111;", wantNotErr: "WARN", wantCalls: []string{},
			wantGoCalled: true, wantGitLog: "-C ROOT rev-parse HEAD"},
		// Stale: a clean build of another commit warns and runs.
		{name: "provenance warns, not refuses, a clean build that is not HEAD", gitHead: provRevB, body: "harness_init\necho PROCEEDED >&2\n",
			wantErr: "built from 111111111111, but HEAD of the harness checkout is 222222222222", wantNotErr: "cannot determine HEAD", wantCalls: []string{},
			wantGoCalled: true, wantGitLog: "-C ROOT rev-parse HEAD"},
		{name: "provenance proceeds past a stale warning", gitHead: provRevB, body: "harness_init\necho PROCEEDED >&2\n", wantErr: "PROCEEDED", wantCalls: []string{}},
		// Unknown HEAD warns and runs; F1: a failing git must not end the script.
		{name: "provenance warns and runs when git fails", gitRC: 128, body: "harness_init\necho PROCEEDED >&2\n", wantErr: "cannot determine HEAD", wantNotErr: "but HEAD of the harness checkout is",
			wantCalls: []string{}, wantGitLog: "-C ROOT rev-parse HEAD"},
		{name: "provenance reaches the end after a failing git", gitRC: 128, body: "harness_init\necho PROCEEDED >&2\n", wantErr: "PROCEEDED", wantCalls: []string{}},
		{name: "provenance warns and runs when git is missing", pathWithout: "git", body: "harness_init\necho PROCEEDED >&2\n", wantErr: "cannot determine HEAD", wantNotErr: "but HEAD of the harness checkout is",
			wantCalls: []string{}, wantGitLog: "-"},
		{name: "provenance reaches the end with git missing", pathWithout: "git", body: "harness_init\necho PROCEEDED >&2\n", wantErr: "PROCEEDED", wantCalls: []string{}},
		{name: "provenance does not run a git found through a relative PATH entry", relTool: "git", body: "harness_init\necho PROCEEDED >&2\n",
			wantErr: "git resolves to ./git, which is not an absolute path", wantNotErr: "REL-git-RAN", wantCalls: []string{}, wantGitLog: "-"},
		{name: "provenance warns under a conditional caller", gitRC: 128, body: "harness_init || echo CONTINUED >&2\n", wantErr: "cannot determine HEAD", wantNotErr: "but HEAD of the harness checkout is", wantCalls: []string{}},
		// The check CALLED DIRECTLY, without harness_init around it, so a mutant
		// in the check cannot hide behind init's other work.
		{name: "provenance check direct: modified tree refused", goOut: fakeBuildInfo("vcs.revision="+provRevA, "vcs.modified=true"), body: "_harness_check_binary_provenance \"$PVEFORGE_BIN\"\necho PROCEEDED >&2\n",
			wantCode: 2, wantErr: "was built from a modified tree", wantNotErr: "PROCEEDED", wantCalls: []string{}, wantGitLog: "-"},
		{name: "provenance check direct: no VCS info refused", goOut: fakeBuildInfo("-buildvcs=false"), body: "_harness_check_binary_provenance \"$PVEFORGE_BIN\"\necho PROCEEDED >&2\n",
			wantCode: 2, wantErr: "carries no VCS build info", wantNotErr: "PROCEEDED", wantCalls: []string{}, wantGitLog: "-"},
		{name: "provenance check direct: stale warns and returns", gitHead: provRevB, body: "_harness_check_binary_provenance \"$PVEFORGE_BIN\"\necho PROCEEDED >&2\n",
			wantErr: "but HEAD of the harness checkout is 222222222222", wantCalls: []string{}},
		{name: "provenance check direct: a failing git warns and returns", gitRC: 128, body: "_harness_check_binary_provenance \"$PVEFORGE_BIN\"\necho PROCEEDED >&2\n",
			wantErr: "PROCEEDED", wantCalls: []string{}, wantGitLog: "-C ROOT rev-parse HEAD"},
		// What git prints is HEAD only if it is a 40-digit commit id.
		{name: "provenance: a git that prints non-hex is an unknown HEAD", gitHead: provRevB + "; echo X", body: "harness_init\necho PROCEEDED >&2\n",
			wantErr: "cannot determine HEAD", wantNotErr: "but HEAD of the harness checkout is", wantCalls: []string{}, wantGitLog: "-C ROOT rev-parse HEAD"},
		{name: "provenance: a git that exits 0 and prints nothing is an unknown HEAD", gitHead: "-", body: "harness_init\necho PROCEEDED >&2\n",
			wantErr: "cannot determine HEAD", wantNotErr: "but HEAD of the harness checkout is", wantCalls: []string{}, wantGitLog: "-C ROOT rev-parse HEAD"},
		// Only the BUILD lines count: a dependency line that spells vcs.modified=true is not the build's.
		{name: "provenance reads only build lines, not a dep line naming vcs.modified=true", goOut: clean + "\n\tdep\texample.com/vcs.modified=true\tv1.0.0\n\tdep\texample.com/vcs.revision=" + provRevB + "\tv1.0.0",
			body: "harness_init\necho PROCEEDED >&2\n", wantErr: "PROCEEDED", wantNotErr: "WARN", wantCalls: []string{}, wantGoCalled: true},
		// A binary and HEAD that agree on the first 12 digits are still different commits.
		{name: "provenance warns on revisions sharing their first 12 digits", gitHead: provRevA[:12] + provRevB[:28], body: "harness_init\necho PROCEEDED >&2\n",
			wantErr: "but HEAD of the harness checkout is " + provRevA[:12], wantCalls: []string{}, wantGitLog: "-C ROOT rev-parse HEAD"},
		// A refusal ends the script even under `if !` (set -e is off inside).
		{name: "provenance refusal under if !", goOut: fakeBuildInfo("vcs.revision="+provRevA, "vcs.modified=true"), wantCode: 2, wantNotErr: "CONTINUED", wantNoState: true,
			body: "if ! harness_init; then echo CONTINUED >&2; fi\necho CONTINUED >&2\n", wantCalls: []string{}},
	}
}

// TestHarnessLib_ProvenanceReal runs the REAL harness_init, with the real go
// and git, against binaries the real go built: what the fake rows cannot show,
// that real `go version -m` says what the check reads. Each row builds a tiny
// module in its own temp repository, and copies lib.sh to
// <repo>/hack/harness/lib.sh so that repository is the checkout lib.sh calls
// HEAD (it climbs two directories from its own file).
func TestHarnessLib_ProvenanceReal(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go is not installed here: %v", err)
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("git is not installed here: %v", err)
	}
	libSrc, err := filepath.Abs(filepath.Join(harnessDir, "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	libBody, err := os.ReadFile(libSrc)
	if err != nil {
		t.Fatal(err)
	}
	fakePveforge, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-pveforge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// The case's base PATH minus the fakes' directory (its first element), plus
	// the real go and git.
	basePATH := strings.SplitN(harnessPATH(t), ":", 2)[1]
	realPATH := basePATH + ":" + filepath.Dir(goBin) + ":" + filepath.Dir(gitBin)

	gitEnv := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	run := func(t *testing.T, dir string, env []string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git := func(t *testing.T, repo string, args ...string) string {
		t.Helper()
		return run(t, repo, gitEnv, "git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	}
	// The build env is the caller's with every Go setting that could change the
	// result forced: an inherited GOFLAGS=-buildvcs=false or GOWORK would turn a
	// clean row red for the wrong reason.
	buildEnv := append(append([]string(nil), gitEnv...), "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// repo makes a committed repository holding the module and lib.sh.
	repo := func(t *testing.T) string {
		t.Helper()
		r := t.TempDir()
		write(t, filepath.Join(r, "go.mod"), "module provtest\n\ngo 1.21\n")
		write(t, filepath.Join(r, "main.go"), "package main\n\nfunc main() {}\n")
		write(t, filepath.Join(r, "hack", "harness", "lib.sh"), string(libBody))
		git(t, r, "init", "-q")
		git(t, r, "add", "-A")
		git(t, r, "commit", "-q", "-m", "c1")
		return r
	}
	build := func(t *testing.T, r string, extra ...string) string {
		t.Helper()
		out := filepath.Join(t.TempDir(), "pveforge")
		run(t, r, buildEnv, "go", append(append([]string{"build"}, extra...), "-o", out, ".")...)
		return out
	}
	// harness runs the real harness_init; refused says whether the row must
	// leave no lock and no run record (runHarnessCase asserts it).
	harness := func(t *testing.T, lib, bin string, refused bool) (int, string) {
		t.Helper()
		code, stderr, _ := runHarnessCase(t, harnessCase{name: t.Name(), env: map[string]string{"PATH": realPATH, "PVEFORGE_BIN": bin, "HARNESS_LIB": lib},
			body: "harness_init\necho PROCEEDED >&2\n", wantNoState: refused, quietGo: true})
		return code, stderr
	}
	short := func(s string) string { return s[:12] }

	t.Run("clean build at HEAD proceeds with no warning", func(t *testing.T) {
		r := repo(t)
		bin := build(t, r)
		head := git(t, r, "rev-parse", "HEAD")
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), bin, false)
		if code != 0 || !strings.Contains(stderr, "PROCEEDED") || strings.Contains(stderr, "WARN") || !strings.Contains(stderr, "rev "+short(head)) {
			t.Errorf("exit %d, want a clean proceed naming rev %s:\n%s", code, short(head), stderr)
		}
	})
	t.Run("a clean build of an older commit warns and proceeds", func(t *testing.T) {
		r := repo(t)
		bin := build(t, r)
		old := git(t, r, "rev-parse", "HEAD")
		write(t, filepath.Join(r, "main.go"), "package main\n\nfunc main() { _ = 1 }\n")
		git(t, r, "commit", "-q", "-a", "-m", "c2")
		head := git(t, r, "rev-parse", "HEAD")
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), bin, false)
		want := "built from " + short(old) + ", but HEAD of the harness checkout is " + short(head)
		if code != 0 || !strings.Contains(stderr, "PROCEEDED") || !strings.Contains(stderr, want) {
			t.Errorf("exit %d, want a proceed with %q:\n%s", code, want, stderr)
		}
	})
	t.Run("an untracked file makes the build dirty and it is refused", func(t *testing.T) {
		r := repo(t)
		write(t, filepath.Join(r, "untracked.txt"), "x\n")
		bin := build(t, r)
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), bin, true)
		if code != 2 || !strings.Contains(stderr, "was built from a modified tree") || strings.Contains(stderr, "PROCEEDED") {
			t.Errorf("exit %d, want a modified-tree refusal:\n%s", code, stderr)
		}
	})
	t.Run("a tracked edit makes the build dirty and it is refused", func(t *testing.T) {
		r := repo(t)
		write(t, filepath.Join(r, "main.go"), "package main\n\nfunc main() { _ = 2 }\n")
		bin := build(t, r)
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), bin, true)
		if code != 2 || !strings.Contains(stderr, "was built from a modified tree") {
			t.Errorf("exit %d, want a modified-tree refusal:\n%s", code, stderr)
		}
	})
	t.Run("-buildvcs=false leaves no VCS info and is refused", func(t *testing.T) {
		r := repo(t)
		bin := build(t, r, "-buildvcs=false")
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), bin, true)
		if code != 2 || !strings.Contains(stderr, "carries no VCS build info") || strings.Contains(stderr, "modified tree") {
			t.Errorf("exit %d, want the no-VCS-info refusal:\n%s", code, stderr)
		}
	})
	t.Run("a checkout that is not a repository warns and proceeds", func(t *testing.T) {
		r := repo(t)
		bin := build(t, r)
		lib := filepath.Join(t.TempDir(), "hack", "harness", "lib.sh")
		write(t, lib, string(libBody))
		code, stderr := harness(t, lib, bin, false)
		if code != 0 || !strings.Contains(stderr, "PROCEEDED") || !strings.Contains(stderr, "cannot determine HEAD") {
			t.Errorf("exit %d, want a proceed with an unknown-HEAD warning:\n%s", code, stderr)
		}
	})
	t.Run("a bash script is not a Go binary and is refused", func(t *testing.T) {
		r := repo(t)
		code, stderr := harness(t, filepath.Join(r, "hack", "harness", "lib.sh"), fakePveforge, true)
		if code != 2 || !strings.Contains(stderr, "cannot read build info") {
			t.Errorf("exit %d, want the unreadable-build-info refusal:\n%s", code, stderr)
		}
	})
}

// D1: lib.sh finds the checkout it lives in at source time, and where that
// fails (here, the climb from a bare `lib.sh` crosses a directory with no
// search permission) the root is EMPTY and the source goes on, under set -e,
// rather than aborting: an unknown HEAD is only a warning.
func TestHarnessLib_RepoRootUnreachableDoesNotAbortSource(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the climb cannot be made to fail")
	}
	lib, err := filepath.Abs(filepath.Join(harnessDir, "lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "p")
	child := filepath.Join(parent, "c")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "lib.sh"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	script := filepath.Join(tmp, "case.sh")
	src := "#!/usr/bin/env bash\ncd \"$C\"\nchmod 600 \"$P\"\nset -e\nsource lib.sh\necho \"ROOT=[${HARNESS_REPO_ROOT}]\" >&2\necho REACHED >&2\n"
	if err := os.WriteFile(script, []byte(src), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Env = []string{"PATH=" + harnessPATH(t), "HOME=" + tmp, "C=" + child, "P=" + parent}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("source aborted: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "ROOT=[]") || !strings.Contains(stderr.String(), "REACHED") {
		t.Errorf("want an empty root and the script reaching its end:\n%s", stderr.String())
	}
}
