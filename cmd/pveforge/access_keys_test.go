package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// genKey is a real authorized_keys line with comment.
func genKey(t *testing.T, comment string) string {
	t.Helper()
	kp, err := sshexec.GenerateEd25519Keypair(comment)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(kp.AuthorizedKeyLine)
}

// sshTargetBlock is a roster target holding public key line.
func sshTargetBlock(t *testing.T, id, line string) string {
	t.Helper()
	enc, err := fixtureEncrypt([]byte("k"), rosterPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("\n[[targets]]\nid = %q\nhost = \"h\"\nnode = \"n\"\n\n[targets.ssh]\nuser = \"root\"\npublic_key = %q\nhost_key_fingerprint = \"SHA256:%s\"\nprivate_key_enc = '''\n%s'''\n", id, line, strings.Repeat("A", 43), enc)
}

// keysResult is access keys' JSON.
type keysResult struct {
	Target         string   `json:"target"`
	RostersChecked []string `json:"rosters_checked"`
	Strays         int      `json:"strays"`
	Keys           []struct {
		Comment       string   `json:"comment"`
		Fingerprint   string   `json:"fingerprint"`
		HeldBy        []string `json:"held_by"`
		Stray         bool     `json:"stray"`
		RemoveCommand string   `json:"remove_command"`
	} `json:"keys"`
}

// TestAccessKeys_ReportsStraysReadOnly: root's authorized_keys is read once
// and nothing else runs; the roster's own key is held, a key with the same
// comment is a stray with its exact removal command, a colleague's key is a
// stray until its roster is checked with --also-roster, and a key without
// a pveforge@ comment is never listed.
func TestAccessKeys_ReportsStraysReadOnly(t *testing.T) {
	var file string
	path, fs, rf := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
		if cmd == bootstrap.AuthorizedKeysReadCmd {
			return file, "", 0
		}
		return "", "unexpected", 1
	})
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fixtureKey := strings.TrimSpace(r.Find("qa-pve-01").SSH.PublicKey) // comment "test": not pveforge's
	held, strayKey, colleagueKey := genKey(t, "pveforge@qa-pve-02"), genKey(t, "pveforge@qa-pve-02"), genKey(t, "pveforge@qa-pve-02")
	operatorKey := genKey(t, "root@admin")
	file = strings.Join([]string{"# managed by pmxcfs", operatorKey, fixtureKey, held, strayKey, colleagueKey, ""}, "\n")

	// The main roster also holds qa-pve-02 with key held.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sshTargetBlock(t, "qa-pve-02", held)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	// The colleague's roster holds colleagueKey.
	colleague := filepath.Join(t.TempDir(), "colleague.toml")
	if err := os.WriteFile(colleague, []byte(sshTargetBlock(t, "qa-pve-02", colleagueKey)), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) keysResult {
		t.Helper()
		args := append([]string{"access", "keys", "--roster", path, "qa-pve-01", "-o", "json"}, extra...)
		code, stdout, stderr := runRootArgs(args...)
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		var got keysResult
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("%v: %s", err, stdout)
		}
		return got
	}

	got := run()
	if got.Target != "qa-pve-01" || len(got.RostersChecked) != 1 || got.RostersChecked[0] != path || got.Strays != 2 || len(got.Keys) != 3 {
		t.Fatalf("result %+v", got)
	}
	if k := got.Keys[0]; k.Stray || len(k.HeldBy) != 1 || k.HeldBy[0] != path+":qa-pve-02" || k.RemoveCommand != "" {
		t.Errorf("the roster's key: %+v, want held by %s:qa-pve-02 with no removal command", k, path)
	}
	wantRemove, err := sshexec.ManualKeyRemovalCommand(strayKey)
	if err != nil {
		t.Fatal(err)
	}
	if k := got.Keys[1]; !k.Stray || len(k.HeldBy) != 0 || k.RemoveCommand != wantRemove || k.Comment != "pveforge@qa-pve-02" || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Errorf("the stray: %+v", k)
	}
	if k := got.Keys[2]; !k.Stray {
		t.Errorf("the colleague's key, its roster unchecked: %+v, want a stray", k)
	}
	for _, k := range got.Keys {
		if k.Comment != "pveforge@qa-pve-02" {
			t.Errorf("a key that is not pveforge's was listed: %+v", k)
		}
	}

	got = run("--also-roster", colleague)
	if got.Strays != 1 || len(got.RostersChecked) != 2 || got.RostersChecked[1] != colleague {
		t.Fatalf("with --also-roster: %+v", got)
	}
	if k := got.Keys[2]; k.Stray || len(k.HeldBy) != 1 || k.HeldBy[0] != colleague+":qa-pve-02" {
		t.Errorf("the colleague's key with its roster checked: %+v", k)
	}

	// Test 11 (SF4): exactly the read command, not merely one that begins
	// like it: anything appended to it (a sed -i, say) would run as root.
	for _, c := range fs.Commands() {
		if c != bootstrap.AuthorizedKeysReadCmd {
			t.Errorf("root ran %q, want exactly %q: the report must only read", c, bootstrap.AuthorizedKeysReadCmd)
		}
	}
	if len(fs.Commands()) != 2 {
		t.Errorf("root ran %d commands over two reports, want 2 reads", len(fs.Commands()))
	}
	if len(rf.got()) != 0 {
		t.Errorf("the token was asked: %q", rf.got())
	}
}

// TestAccessKeys_ReadFailureIsAnError: a read that fails (the read command
// exits non-zero for a dangling symlink, pmxcfs down, or an unreadable
// file: TestAuthorizedKeysReadCmd) is an error, never an empty report that
// would look like "no strays".
func TestAccessKeys_ReadFailureIsAnError(t *testing.T) {
	path, _, _ := accessSetupExec(t, nil, func(string) (string, string, int) { return "", "permission denied", 1 })
	code, stdout, stderr := runRootArgs("access", "keys", "--roster", path, "qa-pve-01")
	if code == 0 || stdout != "" || !strings.Contains(stderr, "authorized_keys") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
