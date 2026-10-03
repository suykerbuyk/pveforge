package bootstrap

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

func genLine(t *testing.T, comment string) string {
	t.Helper()
	kp, err := sshexec.GenerateEd25519Keypair(comment)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(kp.AuthorizedKeyLine)
}

// TestKeyReport: held means the same key (its blob), whatever options or
// comment the line carries, so an option-prefixed held key is held, with no
// remove_command (test 12, H1); a same-comment key with another blob is a
// stray, with the command for the file's own bytes; a stray whose line
// holds a carriage return (a CRLF file) gets no command, and says why;
// keys that are not pveforge's, lines that do not parse, comments and
// blanks are never listed; a key two rosters hold names both.
func TestKeyReport(t *testing.T) {
	held, stray, crlf := genLine(t, "pveforge@a"), genLine(t, "pveforge@a"), genLine(t, "pveforge@c")
	other := genLine(t, "root@admin")
	notOurs := genLine(t, "xpveforge@a")
	withOptions := `from="10.0.0.1",no-pty ` + held
	r1 := &roster.Roster{Targets: []roster.Target{{ID: "a", SSH: &roster.SSHAuth{PublicKey: held + "\n"}}, {ID: "b"}}}
	r2 := &roster.Roster{Targets: []roster.Target{{ID: "a2", SSH: &roster.SSHAuth{PublicKey: held}}}}
	lines := []string{"", "# comment", other, notOurs, "not a key pveforge@a", withOptions, stray, crlf + "\r", "   "}
	got := KeyReport(lines, []RosterKeys{RosterKeysOf("r1.toml", r1), RosterKeysOf("r2.toml", r2)})
	if len(got) != 3 {
		t.Fatalf("listed %d keys, want 3: %+v", len(got), got)
	}
	if k := got[0]; k.Stray || strings.Join(k.HeldBy, ",") != "r1.toml:a,r2.toml:a2" || k.RemoveCommand != "" {
		t.Errorf("the held key, on a line with options: %+v; want it held, with no remove_command", k)
	}
	want, err := sshexec.ManualKeyRemovalCommand(stray)
	if err != nil {
		t.Fatal(err)
	}
	if k := got[1]; !k.Stray || len(k.HeldBy) != 0 || k.RemoveCommand != want || k.RemoveCommandWithheld != "" {
		t.Errorf("the stray: %+v; want the command for the file's own bytes", k)
	}
	if k := got[2]; !k.Stray || k.RemoveCommand != "" || !strings.Contains(k.RemoveCommandWithheld, "carriage return") {
		t.Errorf("the CRLF stray: %+v; want no command, and the reason", k)
	}
	if got := KeyReport(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("no lines: %#v, want an empty, non-nil list", got)
	}
}

// Test 10 (SF3): the read command, executed with sh. A missing file reads
// as empty (exit 0); a dangling symlink (pmxcfs down) and an unreadable
// file are errors (non-zero exit), never "no keys".
func TestAuthorizedKeysReadCmd(t *testing.T) {
	run := func(t *testing.T, home string) (string, int) {
		t.Helper()
		cmd := exec.Command("sh", "-c", AuthorizedKeysReadCmd)
		cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
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
	sshDir := func(t *testing.T) (string, string) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		return home, filepath.Join(home, ".ssh", "authorized_keys")
	}
	t.Run("a readable file", func(t *testing.T) {
		home, f := sshDir(t)
		if err := os.WriteFile(f, []byte("k1\nk2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, home); code != 0 || out != "k1\nk2\n" {
			t.Errorf("exit %d, out %q", code, out)
		}
	})
	t.Run("a missing file", func(t *testing.T) {
		home, _ := sshDir(t)
		if out, code := run(t, home); code != 0 || out != "" {
			t.Errorf("exit %d, out %q; want 0 and nothing", code, out)
		}
	})
	t.Run("a dangling symlink", func(t *testing.T) {
		home, f := sshDir(t)
		if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), f); err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, home); code == 0 {
			t.Errorf("exit 0, out %q: a dangling symlink read as no keys", out)
		}
	})
	t.Run("an unreadable file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file")
		}
		home, f := sshDir(t)
		if err := os.WriteFile(f, []byte("k\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, home); code == 0 {
			t.Errorf("exit 0, out %q: an unreadable file read as no keys", out)
		}
	})
}
