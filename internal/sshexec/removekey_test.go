package sshexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The removal program, executed with sh (dash on PVE and on Debian's
// runners) against a temp HOME whose ~/.ssh/authorized_keys is a symlink
// into a separate "priv" directory, as PVE's is to
// /etc/pve/priv/authorized_keys, with a TMPDIR of its own. PATH shims
// inject the faults. Unless a test says otherwise, every fault leaves the
// target byte for byte as it was, the symlink intact, and nothing in the
// priv directory but the target, and nothing in TMPDIR.

const (
	ourLine   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurKeyOurKeyOurKeyOurKeyOurKeyOurKeyOurK pveforge@t"
	otherSame = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyAnotherKeyAnotherKeyAnotherKey pveforge@t"
	operator  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQOperatorKey root@admin"
)

// keyWorld is one test's temp HOME, priv directory and TMPDIR.
type keyWorld struct {
	home, priv, target, tmp string
}

// newKeyWorld builds a world whose authorized_keys holds body, reached
// through an absolute symlink.
func newKeyWorld(t *testing.T, body string) *keyWorld {
	t.Helper()
	w := &keyWorld{home: t.TempDir(), priv: filepath.Join(t.TempDir(), "priv"), tmp: t.TempDir()}
	w.target = filepath.Join(w.priv, "authorized_keys")
	if err := os.MkdirAll(w.priv, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(w.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(w.target, filepath.Join(w.home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	return w
}

func linesBody(lines ...string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// cmdFor is the command that runs script with shell under w, with shims
// prepended to PATH.
func (w *keyWorld) cmdFor(shell, script, shims string) *exec.Cmd {
	cmd := exec.Command(shell, "-c", script)
	path := os.Getenv("PATH")
	if shims != "" {
		path = shims + ":" + path
	}
	cmd.Env = []string{"HOME=" + w.home, "PATH=" + path, "TMPDIR=" + w.tmp}
	return cmd
}

// run runs script with shell and returns stdout and the exit status.
func (w *keyWorld) run(t *testing.T, shell, script, shims string) (string, int) {
	t.Helper()
	out, err := w.cmdFor(shell, script, shims).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func (w *keyWorld) body(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(w.target)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (w *keyWorld) inode(t *testing.T) uint64 {
	t.Helper()
	fi, err := os.Stat(w.target)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func (w *keyWorld) assertSymlink(t *testing.T) {
	t.Helper()
	got, err := os.Readlink(filepath.Join(w.home, ".ssh", "authorized_keys"))
	if err != nil || got != w.target {
		t.Errorf("~/.ssh/authorized_keys is no longer the symlink to %s (readlink %q, %v): the cluster's shared file would be unshared", w.target, got, err)
	}
}

// assertNoLeftovers: nothing but the target in the priv directory, and
// nothing in TMPDIR.
func (w *keyWorld) assertNoLeftovers(t *testing.T) {
	t.Helper()
	for dir, allowed := range map[string]string{w.priv: "authorized_keys", w.tmp: ""} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != allowed {
				t.Errorf("left behind in %s: %s", dir, e.Name())
			}
		}
	}
}

// shimDir writes executable shims (name -> sh body) into a new directory.
func shimDir(t *testing.T, shims map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range shims {
		if err := os.WriteFile(filepath.Join(d, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// requireShIsDash skips a row labelled dash when this host's sh is not
// dash (PVE's /bin/sh is), rather than run another shell under that label.
func requireShIsDash(t *testing.T) {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on this host: %v", err)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Skipf("cannot resolve %s: %v", p, err)
	}
	if filepath.Base(real) != "dash" {
		t.Skipf("sh is %s, not dash: this row stands for PVE's /bin/sh (dash)", real)
	}
}

func realTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s not found: %v", name, err)
	}
	return p
}

func mustScript(t *testing.T, line string) string {
	t.Helper()
	s, err := RemoveAuthorizedKeyScript(line)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustManual(t *testing.T, line string) string {
	t.Helper()
	s, err := ManualKeyRemovalCommand(line)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// both runs a check on the automatic script, under dash AND bash (sshexec
// hands a command to sshd, which runs it with root's login shell: /bin/bash
// on PVE), and on the manual command, pasted into bash as an operator would.
func both(t *testing.T, line string, check func(t *testing.T, shell, script string)) {
	t.Run("automatic/sh", func(t *testing.T) {
		requireShIsDash(t)
		check(t, "sh", mustScript(t, line))
	})
	t.Run("automatic/bash", func(t *testing.T) { check(t, "bash", mustScript(t, line)) })
	t.Run("manual", func(t *testing.T) { check(t, "bash", mustManual(t, line)) })
}

// Test 1: only our exact line goes. An option-prefixed line holding our
// key, a same-comment line with another key, and our key with more text
// all stay. The target is replaced by a rename (its inode changes), the
// rename's source was created beside it (the mv shim records it), and the
// symlink stays a symlink.
func TestRemoveKey_RemovesExactlyOurLine(t *testing.T) {
	keep := []string{operator, otherSame, `from="10.0.0.1" ` + ourLine, ourLine + " extra"}
	both(t, ourLine, func(t *testing.T, shell, script string) {
		w := newKeyWorld(t, linesBody(keep[0], keep[1], ourLine, keep[2], keep[3]))
		log := filepath.Join(t.TempDir(), "mv.log")
		shims := shimDir(t, map[string]string{"mv": `printf '%s\n' "$@" > ` + log + "\nexec " + realTool(t, "mv") + ` "$@"`})
		before := w.inode(t)
		out, code := w.run(t, shell, script, shims)
		if code != 0 || strings.TrimSpace(out) != "removed" {
			t.Fatalf("exit %d, out %q", code, out)
		}
		if got, want := w.body(t), linesBody(keep...); got != want {
			t.Errorf("file after:\n%s\nwant:\n%s", got, want)
		}
		if w.inode(t) == before {
			t.Error("the target's inode is unchanged: it was rewritten in place, not replaced by a rename")
		}
		args, _ := os.ReadFile(log)
		f := strings.Fields(string(args))
		if len(f) < 2 || filepath.Dir(f[len(f)-2]) != w.priv || f[len(f)-1] != w.target {
			t.Errorf("mv %q: want a source beside the target in %s, renamed onto %s", f, w.priv, w.target)
		}
		w.assertSymlink(t)
		w.assertNoLeftovers(t)
	})
	// The only line: the file ends empty, still the symlink's target.
	w := newKeyWorld(t, linesBody(ourLine))
	if out, code := w.run(t, "sh", mustScript(t, ourLine), ""); code != 0 || strings.TrimSpace(out) != "removed" {
		t.Fatalf("only line: exit %d, out %q", code, out)
	}
	if got := w.body(t); got != "" {
		t.Errorf("only line: file after %q, want empty", got)
	}
	w.assertSymlink(t)
	w.assertNoLeftovers(t)
}

// Test 2: a regular file (no symlink) and a relative symlink are removed
// from correctly: readlink -f resolves both (plain readlink fails on the
// first, and returns a path relative to the link for the second).
func TestRemoveKey_RegularFileAndRelativeSymlink(t *testing.T) {
	both(t, ourLine, func(t *testing.T, shell, script string) {
		t.Run("regular file", func(t *testing.T) {
			w := newKeyWorld(t, "")
			link := filepath.Join(w.home, ".ssh", "authorized_keys")
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(link, []byte(linesBody(operator, ourLine)), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, code := w.run(t, shell, script, ""); code != 0 || strings.TrimSpace(out) != "removed" {
				t.Fatalf("exit %d, out %q", code, out)
			}
			if got, _ := os.ReadFile(link); string(got) != linesBody(operator) {
				t.Errorf("file after %q", got)
			}
			if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
				t.Errorf("no longer a regular file: %v %v", fi, err)
			}
		})
		t.Run("relative symlink", func(t *testing.T) {
			w := newKeyWorld(t, linesBody(operator, ourLine))
			link := filepath.Join(w.home, ".ssh", "authorized_keys")
			rel, err := filepath.Rel(filepath.Dir(link), w.target)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(rel, link); err != nil {
				t.Fatal(err)
			}
			if out, code := w.run(t, shell, script, ""); code != 0 || strings.TrimSpace(out) != "removed" {
				t.Fatalf("exit %d, out %q", code, out)
			}
			if got := w.body(t); got != linesBody(operator) {
				t.Errorf("file after %q", got)
			}
			if got, _ := os.Readlink(link); got != rel {
				t.Errorf("the relative symlink became %q", got)
			}
			w.assertNoLeftovers(t)
		})
	})
}

// Test 3: the exit codes, from the real program: 3 for "found 0" and
// "found 2" (and for a line present only as a prefix, with another
// comment, or indented), 4 when the file changes before the cmp. Nothing is
// written, and nothing is left in TMPDIR: the EXIT trap ran.
func TestRemoveKey_ExitCodes(t *testing.T) {
	both(t, ourLine, func(t *testing.T, shell, script string) {
		for name, tc := range map[string]struct {
			lines []string
			found string
		}{
			"absent":          {[]string{operator, otherSame}, "found 0"},
			"twice":           {[]string{ourLine, operator, ourLine}, "found 2"},
			"only a prefix":   {[]string{ourLine + "x"}, "found 0"},
			"another comment": {[]string{strings.TrimSuffix(ourLine, "pveforge@t") + "pveforge@u"}, "found 0"},
			"leading space":   {[]string{" " + ourLine}, "found 0"},
		} {
			t.Run(name, func(t *testing.T) {
				w := newKeyWorld(t, linesBody(tc.lines...))
				before := w.body(t)
				out, code := w.run(t, shell, script, "")
				if code != RemoveKeyExitNotExactlyOne || strings.TrimSpace(out) != tc.found {
					t.Errorf("exit %d, out %q; want %d and %q", code, out, RemoveKeyExitNotExactlyOne, tc.found)
				}
				if w.body(t) != before {
					t.Error("the file changed")
				}
				w.assertSymlink(t)
				w.assertNoLeftovers(t)
			})
		}
		t.Run("changed before the cmp", func(t *testing.T) {
			w := newKeyWorld(t, linesBody(operator, ourLine))
			newcomer := "ssh-ed25519 AAAANewcomer pveforge@other"
			shims := shimDir(t, map[string]string{"cmp": "echo '" + newcomer + "' >> " + w.target + "\nexec " + realTool(t, "cmp") + ` "$@"`})
			out, code := w.run(t, shell, script, shims)
			if code != RemoveKeyExitChanged || strings.TrimSpace(out) != "changed" {
				t.Fatalf("exit %d, out %q; want %d", code, out, RemoveKeyExitChanged)
			}
			if got, want := w.body(t), linesBody(operator, ourLine, newcomer); got != want {
				t.Errorf("file after:\n%s\nwant it untouched but for the newcomer:\n%s", got, want)
			}
			w.assertSymlink(t)
			w.assertNoLeftovers(t)
		})
	})
}

// Test 4: mktemp faults. A shim that fails ONLY the sibling template
// (*.tmp.*) while a plain mktemp works is pmxcfs with quorum lost; one that
// fails the snapshot's mktemp is a full or unwritable TMPDIR. Both leave
// the target as it was.
func TestRemoveKey_MktempFaults(t *testing.T) {
	mk := realTool(t, "mktemp")
	for name, body := range map[string]string{
		"the sibling mktemp fails":  `case "$*" in *.tmp.*) echo "mktemp: Read-only file system" >&2; exit 1;; esac` + "\nexec " + mk + ` "$@"`,
		"the snapshot mktemp fails": `case "$*" in *.tmp.*) exec ` + mk + ` "$@";; esac` + "\necho 'mktemp: No space left on device' >&2; exit 1",
	} {
		t.Run(name, func(t *testing.T) {
			both(t, ourLine, func(t *testing.T, shell, script string) {
				w := newKeyWorld(t, linesBody(operator, ourLine))
				before := w.body(t)
				if out, code := w.run(t, shell, script, shimDir(t, map[string]string{"mktemp": body})); code == 0 {
					t.Fatalf("exit 0, out %q: want a failure", out)
				}
				if w.body(t) != before {
					t.Error("the target changed")
				}
				w.assertSymlink(t)
				w.assertNoLeftovers(t)
			})
		})
	}
}

// Test 5: the write fails (grep exits 2 after a partial write), and the
// rename fails. The target is as it was, and the partial file is gone.
func TestRemoveKey_WriteAndRenameFaults(t *testing.T) {
	for name, shims := range map[string]map[string]string{
		"the write fails":  {"grep": `case "$1" in -vxF) printf 'ssh-rsa NO'; exit 2;; esac` + "\nexec " + realTool(t, "grep") + ` "$@"`},
		"the rename fails": {"mv": `echo "mv: cannot move: Input/output error" >&2; exit 1`},
	} {
		t.Run(name, func(t *testing.T) {
			both(t, ourLine, func(t *testing.T, shell, script string) {
				w := newKeyWorld(t, linesBody(operator, ourLine))
				before := w.body(t)
				if out, code := w.run(t, shell, script, shimDir(t, shims)); code == 0 {
					t.Fatalf("exit 0, out %q: want a failure", out)
				}
				if w.body(t) != before {
					t.Error("the target changed")
				}
				w.assertSymlink(t)
				w.assertNoLeftovers(t)
			})
		})
	}
}

// Test 7: the manual command, built for a line whose comment holds a
// quote, a command substitution, backticks, a double quote, a backslash
// and a semicolon, pasted into bash as an operator would: it removes
// exactly that line, and nothing in the comment runs.
func TestManualKeyRemovalCommand_HostileComment(t *testing.T) {
	marks := t.TempDir()
	hostile := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostileHostileHostileHostileHostileHost pveforge@t it's $(touch " + marks + "/MARK) `touch " + marks + "/MARK2` \"q\" \\ ; x"
	w := newKeyWorld(t, linesBody(operator, hostile, otherSame))
	cmd := mustManual(t, hostile)
	if strings.ContainsAny(cmd, "\r\n") {
		t.Fatalf("the manual command spans lines: %q", cmd)
	}
	if out, code := w.run(t, "bash", cmd, ""); code != 0 || strings.TrimSpace(out) != "removed" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	if got, want := w.body(t), linesBody(operator, otherSame); got != want {
		t.Errorf("file after:\n%s\nwant:\n%s", got, want)
	}
	if entries, _ := os.ReadDir(marks); len(entries) != 0 {
		t.Errorf("the comment ran: %v", entries)
	}
	w.assertSymlink(t)
	w.assertNoLeftovers(t)
}

// Test 14: a line no whole-line match can mean exactly is refused before
// any program is built.
func TestRemoveKey_RefusesALineThatIsNotOneLine(t *testing.T) {
	for _, line := range []string{"", "   ", ourLine + "\n" + operator, ourLine + "\r", "\n"} {
		if s, err := RemoveAuthorizedKeyScript(line); !errors.Is(err, ErrInvalidKeyLine) || s != "" {
			t.Errorf("RemoveAuthorizedKeyScript(%q) = %q, %v; want ErrInvalidKeyLine", line, s, err)
		}
		if s, err := ManualKeyRemovalCommand(line); !errors.Is(err, ErrInvalidKeyLine) || s != "" {
			t.Errorf("ManualKeyRemovalCommand(%q) = %q, %v; want ErrInvalidKeyLine", line, s, err)
		}
	}
}

// The program is simple commands only, so its "; " join is the same
// program, and the changed-meanwhile cmp is the command immediately before
// the rename (the accepted window is two commands wide, never wider).
func TestRemoveKey_ProgramShape(t *testing.T) {
	cmds := removeKeyCommands(ourLine)
	for _, c := range cmds {
		for _, kw := range []string{"if", "then", "fi", "#"} {
			if f := strings.Fields(c); len(f) > 0 && f[0] == kw {
				t.Errorf("command %q starts with %q: a \"; \" join would not be the same program", c, kw)
			}
		}
		if strings.Contains(c, "sed ") {
			t.Errorf("command %q uses sed", c)
		}
	}
	at := func(prefix string) int {
		for i, c := range cmds {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		return -1
	}
	if c, m := at("cmp -s "), at("mv -f -- "); c < 0 || m != c+1 {
		t.Errorf("cmp is command %d and mv %d: the cmp must be the command immediately before the rename", c, m)
	}
	if s := mustScript(t, ourLine); s != strings.Join(cmds, "\n")+"\n" {
		t.Error("RemoveAuthorizedKeyScript is not the program joined by newlines")
	}
	if m := mustManual(t, ourLine); m != "sh -c "+ShellQuote(strings.Join(cmds, "; ")) {
		t.Error("ManualKeyRemovalCommand is not sh -c and the quoted \"; \" join of the program")
	}
}
