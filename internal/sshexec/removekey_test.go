package sshexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ourLine   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOurKeyOurKeyOurKeyOurKeyOurKeyOurKeyOurK pveforge@t"
	otherSame = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyAnotherKeyAnotherKeyAnotherKey pveforge@t"
	operator  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQOperatorKey root@admin"
)

// keyHome builds a HOME whose ~/.ssh/authorized_keys is a symlink to a file
// elsewhere, as PVE's is to /etc/pve/priv/authorized_keys, holding lines.
// It returns HOME and the symlink's target.
func keyHome(t *testing.T, lines ...string) (home, target string) {
	t.Helper()
	home = t.TempDir()
	priv := filepath.Join(t.TempDir(), "priv")
	if err := os.MkdirAll(priv, 0o700); err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(priv, "authorized_keys")
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
		t.Fatal(err)
	}
	return home, target
}

// runScript runs script with sh under home, with extraPath prepended to
// PATH, and returns stdout and the exit status.
func runScript(t *testing.T, home, extraPath, script string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	path := os.Getenv("PATH")
	if extraPath != "" {
		path = extraPath + ":" + path
	}
	cmd.Env = []string{"HOME=" + home, "PATH=" + path}
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func assertSymlink(t *testing.T, home, target string) {
	t.Helper()
	got, err := os.Readlink(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil || got != target {
		t.Errorf("~/.ssh/authorized_keys is no longer the symlink to %s (readlink %q, %v): the cluster's shared file would be unshared", target, got, err)
	}
}

// TestRemoveAuthorizedKeyScript_RemovesExactlyOurLine: the whole line, and
// only it; a key with the same comment and the operator's key stay; the
// symlink stays a symlink and its target is what changed.
func TestRemoveAuthorizedKeyScript_RemovesExactlyOurLine(t *testing.T) {
	home, target := keyHome(t, operator, otherSame, ourLine, operator+" # dup")
	out, code := runScript(t, home, "", RemoveAuthorizedKeyScript(ourLine))
	if code != 0 || strings.TrimSpace(out) != "removed" {
		t.Fatalf("exit %d, out %q", code, out)
	}
	got, _ := os.ReadFile(target)
	if want := operator + "\n" + otherSame + "\n" + operator + " # dup\n"; string(got) != want {
		t.Errorf("file after:\n%s\nwant:\n%s", got, want)
	}
	assertSymlink(t, home, target)

	// The only line: the file ends empty, still a symlink.
	home, target = keyHome(t, ourLine)
	if out, code := runScript(t, home, "", RemoveAuthorizedKeyScript(ourLine)); code != 0 || strings.TrimSpace(out) != "removed" {
		t.Fatalf("only line: exit %d, out %q", code, out)
	}
	if got, _ := os.ReadFile(target); len(got) != 0 {
		t.Errorf("only line: file after %q, want empty", got)
	}
	assertSymlink(t, home, target)
}

// TestRemoveAuthorizedKeyScript_RefusesUnlessExactlyOnce: absent, twice, or
// present only as a prefix or with another comment: nothing is written.
func TestRemoveAuthorizedKeyScript_RefusesUnlessExactlyOnce(t *testing.T) {
	for name, lines := range map[string][]string{
		"absent":          {operator, otherSame},
		"twice":           {ourLine, operator, ourLine},
		"only a prefix":   {ourLine + "x"},
		"another comment": {strings.TrimSuffix(ourLine, "pveforge@t") + "pveforge@u"},
		"leading space":   {" " + ourLine},
	} {
		home, target := keyHome(t, lines...)
		before, _ := os.ReadFile(target)
		out, code := runScript(t, home, "", RemoveAuthorizedKeyScript(ourLine))
		if code != RemoveKeyExitNotExactlyOne || !strings.HasPrefix(out, "found ") {
			t.Errorf("%s: exit %d, out %q; want %d and the count", name, code, out, RemoveKeyExitNotExactlyOne)
		}
		if after, _ := os.ReadFile(target); string(after) != string(before) {
			t.Errorf("%s: the file changed", name)
		}
		assertSymlink(t, home, target)
	}
}

// TestRemoveAuthorizedKeyScript_KeepsAKeyAppendedMeanwhile: a line another
// process appends while the script reads is not dropped: the script sees
// the file changed and writes nothing.
func TestRemoveAuthorizedKeyScript_KeepsAKeyAppendedMeanwhile(t *testing.T) {
	home, target := keyHome(t, operator, ourLine)
	shim := t.TempDir()
	cmpPath, err := exec.LookPath("cmp")
	if err != nil {
		t.Skip("no cmp on this host")
	}
	// A cmp that first lets "another process" append a key.
	script := "#!/bin/sh\necho 'ssh-ed25519 AAAANewcomer pveforge@other' >> " + target + "\nexec " + cmpPath + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shim, "cmp"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, home, shim, RemoveAuthorizedKeyScript(ourLine))
	if code != RemoveKeyExitChanged || strings.TrimSpace(out) != "changed" {
		t.Fatalf("exit %d, out %q; want %d", code, out, RemoveKeyExitChanged)
	}
	got, _ := os.ReadFile(target)
	if want := operator + "\n" + ourLine + "\nssh-ed25519 AAAANewcomer pveforge@other\n"; string(got) != want {
		t.Errorf("file after:\n%s\nwant it untouched but for the newcomer:\n%s", got, want)
	}
}

// TestRemoveAuthorizedKeyScript_NeverReplacesTheFile: the script writes
// through the path (cat >) and never moves or edits it in place with sed.
func TestRemoveAuthorizedKeyScript_NeverReplacesTheFile(t *testing.T) {
	s := RemoveAuthorizedKeyScript(ourLine)
	for _, bad := range []string{"sed ", "mv ", "ln ", "install ", "cp "} {
		if strings.Contains(s, bad) {
			t.Errorf("the script uses %q, which would replace the symlink:\n%s", bad, s)
		}
	}
	if !strings.Contains(s, `cat "$out" > "$f"`) {
		t.Errorf("the script does not write through the path:\n%s", s)
	}
}

// TestManualKeyRemovalCommand: the operator's command removes exactly the
// line, keeps the symlink, and keeps every other line.
func TestManualKeyRemovalCommand(t *testing.T) {
	home, target := keyHome(t, operator, ourLine, otherSame)
	if out, code := runScript(t, home, "", ManualKeyRemovalCommand(ourLine)); code != 0 {
		t.Fatalf("exit %d, out %q", code, out)
	}
	got, _ := os.ReadFile(target)
	if want := operator + "\n" + otherSame + "\n"; string(got) != want {
		t.Errorf("file after:\n%s\nwant:\n%s", got, want)
	}
	assertSymlink(t, home, target)
}
