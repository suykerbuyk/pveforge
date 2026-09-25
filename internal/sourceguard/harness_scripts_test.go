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

var (
	// local x=$(...) takes local's status, never the command's.
	localSubst = regexp.MustCompile(`(?m)^\s*local\s+[A-Za-z_][A-Za-z0-9_]*=\$\(`)
	// A status piped into tail is tail's.
	tailPipe = regexp.MustCompile(`\|\s*tail\b`)
)

func TestHarnessScripts_ParseAndHideNoFailure(t *testing.T) {
	var scripts []string
	err := filepath.WalkDir(harnessDir, func(p string, d fs.DirEntry, err error) error {
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
	for _, want := range []string{"hack/harness/lib.sh", "hack/harness/test/fake-pveforge.sh"} {
		if !strings.Contains(have, want) {
			t.Fatalf("%s not found under %s; found:\n%s", want, harnessDir, have)
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

// harnessCase is one offline run of a driver script that sources lib.sh.
type harnessCase struct {
	name string
	pre  string // lines before `source lib.sh`
	body string // lines after it
	// env is added to the base environment; a value "-" removes the key.
	env      map[string]string
	bashEnv  string // when set, written to a file BASH_ENV names
	bashArgs []string
	resp     map[string]string // fake answers by key, over harnessWorld
	rc       map[string]int    // fake exit statuses by key
	roster   string            // "missing", "0644", "env-link", "cwd-link"; "" = a 0600 roster
	sourced  bool              // run the driver by sourcing it from another script
	holdLock bool
	// pathWithout, when set, runs the case with a PATH of links to every
	// tool but this one.
	pathWithout string
	// skipUnlessLocale skips the case, saying so, where this locale is not
	// installed: what it tests does not arise without it.
	skipUnlessLocale string

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
	keyConf  = "get /nodes/qa-pve-02/qemu/690/config"
)

// harnessWorld is the fake's default answers: VM 690 in the pool on
// qa-pve-02, carrying the tag.
var harnessWorld = map[string]string{
	keyPool: `[{"poolid":"pveforge-harness","comment":"","members":[{"id":"qemu/690","type":"qemu","vmid":690,"node":"qa-pve-02"}]}]`,
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
	return strings.Join(dirs, ":")
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
	roster := filepath.Join(cfg, "harness-outer.toml")
	env := map[string]string{
		"PATH":                       harnessPATH(t),
		"HOME":                       home,
		"PVEFORGE_BIN":               fake,
		"PVEFORGE_ROSTER_PASSPHRASE": "not-a-secret",
		"FAKE_PVEFORGE_DIR":          fakeDir,
		"HARNESS_LIB":                lib,
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
		for _, tool := range []string{"jq", "flock", "stat", "sha256sum", "tr", "cat", "grep", "mktemp", "mkdir"} {
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
		env["PATH"] = links
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
			body: "harness_init\nharness_get /cluster/resources >/dev/null\n", wantCalls: []string{"api get /cluster/resources qa-pve-02-harness --roster R -o json"}},

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
		{name: "a container is not a qemu member", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"lxc","vmid":690,"node":"qa-pve-02"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "not a qemu member of pool", noMutation: true},
		{name: "member on another node", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-01"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "on node qa-pve-01", noMutation: true},
		{name: "vmid as a string is not a match", resp: map[string]string{keyPool: `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":"690","node":"qa-pve-02"}]}]`}, body: stdInit + post, wantCode: 2, wantErr: "not a qemu member of pool", noMutation: true},
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
			wantCalls: []string{`vm create qa-pve-02-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`}},
		// A failed create is never recorded: a subshell that failed to create
		// leaves nothing this run may destroy.
		{name: "a failed create is never recorded", rc: map[string]int{"vm create 690": 1}, body: stdInit + `( harness_vm_create 690 '{"cores":"1"}' ) || true` + "\nharness_vm_destroy 690\n", wantCode: 2, wantErr: "was not created by this run",
			wantCalls: []string{`vm create qa-pve-02-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`, "api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness"}},

		// A failure inside $(...) aborts, and pveforge's own status reaches
		// the caller.
		{name: "a failed read aborts before the write", rc: map[string]int{keyPool: 1}, body: stdInit + post, wantCode: 1, wantNotErr: "REACHED",
			wantCalls: []string{"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness"}},
		{name: "a signal status passes through", rc: map[string]int{"post /nodes/qa-pve-02/qemu/690/status/stop": 130}, body: stdInit + post, wantCode: 130, wantNotErr: "REACHED"},

		// Positive control: every guard passes when it should, and the exact
		// calls go out, the create through `vm create` and never an unlocked
		// api write.
		{name: "create, snapshot, roll back, delete the snapshot, destroy", body: stdInitS +
			`harness_vm_create 690 '{"cores":"1","scsi0":"pveforge-harness:1"}'` + "\n" +
			"harness_vm_post 690 snapshot snapname=s1 vmstate=0\n" +
			"harness_vm_post 690 snapshot/s1/rollback\n" +
			"harness_vm_delete 690 snapshot/s1\n" +
			"harness_vm_destroy 690 purge=1\n" +
			"harness_vm_get 690 status/current >/dev/null\n",
			resp:    map[string]string{"get /nodes/qa-pve-02/qemu/690/status/current": `{"status":"stopped"}`},
			wantErr: "harness: delete /nodes/qa-pve-02/qemu/690 purge=1",
			wantCalls: []string{
				`vm create qa-pve-02-harness 690 --roster R --json {"cores":"1","scsi0":"pveforge-harness:1","pool":"pveforge-harness"}`,
				"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
				"api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data tags=pveforge-harness",
				"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json",
				"api post /nodes/qa-pve-02/qemu/690/snapshot qa-pve-02-harness --roster R -o json --data snapname=s1 --data vmstate=0",
				"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json",
				"api post /nodes/qa-pve-02/qemu/690/snapshot/s1/rollback qa-pve-02-harness --roster R -o json",
				"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json",
				"api delete /nodes/qa-pve-02/qemu/690/snapshot/s1 qa-pve-02-harness --roster R -o json",
				"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
				"api get /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json",
				"api delete /nodes/qa-pve-02/qemu/690 qa-pve-02-harness --roster R -o json --data purge=1",
				"api get /nodes/qa-pve-02/qemu/690/status/current qa-pve-02-harness --roster R -o json",
			}},
	}
	cases = append(cases, tagSeparatorCases()...)
	cases = append(cases, endpointCases()...)
	cases = append(cases, fieldCases()...)
	return append(cases, ifNotCases()...)
}

// guardReads are the reads a change of VM 690 makes before it writes.
var guardReads = []string{
	"api get /pools qa-pve-02-harness --roster R -o json --data poolid=pveforge-harness",
	"api get /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json",
}

// PVE splits a tag list (PVE::ParseUtils::split_list, pve-common) on NUL
// when it holds one, else on commas, semicolons and whitespace.
func tagSeparatorCases() []harnessCase {
	var cs []harnessCase
	for name, tags := range map[string]string{"comma": `a,pveforge-harness`, "semicolon": `a;pveforge-harness`, "space": `a pveforge-harness`, "tab": `a\tpveforge-harness`, "newline": `a\npveforge-harness`, "NUL": `a\u0000pveforge-harness`, "alone": `pveforge-harness`} {
		cs = append(cs, harnessCase{name: "tag list split on " + name, resp: map[string]string{keyConf: `{"tags":"` + tags + `"}`}, body: stdInit + "harness_vm_post 690 status/stop\n",
			wantCalls: append(append([]string(nil), guardReads...), "api post /nodes/qa-pve-02/qemu/690/status/stop qa-pve-02-harness --roster R -o json")})
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
		{"harness_vm_put 690 config cores=2", "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data cores=2"},
		{"harness_vm_post 690 snapshot snapname=s1", "api post /nodes/qa-pve-02/qemu/690/snapshot qa-pve-02-harness --roster R -o json --data snapname=s1"},
		{"harness_vm_post 690 snapshot/pvh-golden/rollback", "api post /nodes/qa-pve-02/qemu/690/snapshot/pvh-golden/rollback qa-pve-02-harness --roster R -o json"},
		{"harness_vm_post 690 status/start", "api post /nodes/qa-pve-02/qemu/690/status/start qa-pve-02-harness --roster R -o json"},
		{"harness_vm_post 690 status/stop", "api post /nodes/qa-pve-02/qemu/690/status/stop qa-pve-02-harness --roster R -o json"},
		{"harness_vm_post 690 status/shutdown", "api post /nodes/qa-pve-02/qemu/690/status/shutdown qa-pve-02-harness --roster R -o json"},
		{"harness_vm_delete 690 snapshot/s1", "api delete /nodes/qa-pve-02/qemu/690/snapshot/s1 qa-pve-02-harness --roster R -o json"},
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
		return "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data " + kv
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
			wantLast: "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data tags=pveforge-harness"})
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
		{"harness_vm_post 690 snapshot/s1/rollback start=1", "api post /nodes/qa-pve-02/qemu/690/snapshot/s1/rollback qa-pve-02-harness --roster R -o json --data start=1"},
		{"harness_vm_post 690 status/stop timeout=30", "api post /nodes/qa-pve-02/qemu/690/status/stop qa-pve-02-harness --roster R -o json --data timeout=30"},
		{"harness_vm_post 690 status/stop skiplock=1", ""},
		{"harness_vm_post 690 status/shutdown forceStop=1", "api post /nodes/qa-pve-02/qemu/690/status/shutdown qa-pve-02-harness --roster R -o json --data forceStop=1"},
		{"harness_vm_post 690 status/start timeout=60 migratedfrom=qa-pve-01", ""},
		{"harness_vm_delete 690 snapshot/s1 force=1", ""},
	} {
		if c.want == "" {
			cs = append(cs, harnessCase{name: "endpoint field refused: " + c.call, body: stdInit + c.call + "\n", wantCode: 2, wantErr: "is not allowed here", wantCalls: []string{}})
		} else {
			cs = append(cs, harnessCase{name: "endpoint field allowed: " + c.call, body: stdInit + c.call + "\n", wantCalls: append(append([]string(nil), guardReads...), c.want)})
		}
	}
	cs = append(cs, harnessCase{name: "destroy field refused: skiplock", body: stdInit + create + "harness_vm_destroy 690 skiplock=1\n", wantCode: 2, wantErr: "is not allowed here",
		wantLast: "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data tags=pveforge-harness"})
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
			wantLast: "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data tags=pveforge-harness"})
	}
	// Tags: ASCII whitespace separates, NBSP and the other Unicode spaces do
	// not; NUL, when present, is the only separator.
	for name, tags := range map[string]string{"NBSP": `a pveforge-harness`, "NEL": `a\u0085pveforge-harness`, "EM SPACE": `a pveforge-harness`, "NUL splits alone": `pveforge-harness,x\u0000y`} {
		cs = append(cs, harnessCase{name: "tag list does not split on " + name, resp: map[string]string{keyConf: `{"tags":"` + tags + `"}`}, body: stdInit + "harness_vm_post 690 status/stop\n", wantCode: 2, wantErr: "does not carry tag", noMutation: true})
	}
	cs = append(cs, harnessCase{name: "tag list split on vertical tab", resp: map[string]string{keyConf: `{"tags":"a\u000bpveforge-harness"}`}, body: stdInit + "harness_vm_post 690 status/stop\n",
		wantCalls: append(append([]string(nil), guardReads...), "api post /nodes/qa-pve-02/qemu/690/status/stop qa-pve-02-harness --roster R -o json")})
	// The C locale: under en_US.UTF-8, bash's [0-9] matches ².
	cs = append(cs, harnessCase{name: "a superscript digit is not a VMID digit", skipUnlessLocale: "en_US.UTF-8", env: map[string]string{"LC_ALL": "en_US.UTF-8"}, body: "harness_init\nharness_declare_vmids 69²\n", wantCode: 2, wantErr: "is not one of 690-699", wantCalls: []string{}})
	// Tools are found once, when lib is sourced.
	cs = append(cs, harnessCase{name: "a tool missing at source time", pathWithout: "jq", body: stdInit, wantCode: 2, wantErr: "jq is not on PATH", wantCalls: []string{}})
	cs = append(cs, harnessCase{name: "a PATH changed after sourcing finds a wrong jq and grep", body: stdInitS + "mkdir \"$HOME/wrong\"\nfor t in jq grep; do printf '#!/bin/sh\\nexit 99\\n' >\"$HOME/wrong/$t\"; chmod +x \"$HOME/wrong/$t\"; done\nPATH=$HOME/wrong:$PATH\nharness_vm_create 690 '{\"cores\":\"1\"}'\nharness_vm_put 690 config scsi1=pveforge-harness:8\n",
		wantLast: "api put /nodes/qa-pve-02/qemu/690/config qa-pve-02-harness --roster R -o json --data scsi1=pveforge-harness:8"})
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
		{name: "harness_vm_put", pre: stdInit, call: "harness_vm_put 690 config cores=2", rc: map[string]int{"put /nodes/qa-pve-02/qemu/690/config cores=2": 1}, code: 1},
		{name: "harness_vm_post", pre: stdInit, call: "harness_vm_post 690 status/stop", rc: map[string]int{"post /nodes/qa-pve-02/qemu/690/status/stop": 1}, code: 1},
		{name: "harness_vm_delete", pre: stdInit, call: "harness_vm_delete 690 snapshot/s1", rc: map[string]int{"delete /nodes/qa-pve-02/qemu/690/snapshot/s1": 1}, code: 1},
		{name: "harness_vm_destroy", pre: stdInit + created, call: "harness_vm_destroy 690", rc: map[string]int{"delete /nodes/qa-pve-02/qemu/690": 1}, code: 1},
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
			wantCalls: []string{`vm create qa-pve-02-harness 690 --roster R --json {"cores":"1","pool":"pveforge-harness"}`}})
	}
	return cs
}

func TestHarnessLib_Offline(t *testing.T) {
	cases := harnessCases()
	// Anti-vacuity: the positive control and the refusals are all here.
	if len(cases) < 150 {
		t.Fatalf("%d harness cases, want at least 150", len(cases))
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
