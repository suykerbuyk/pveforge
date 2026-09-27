package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/netguard"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// rekeyCLIRoster writes a roster at dir/name holding one target with a
// token sealed under "old", and returns its path.
func rekeyCLIRoster(t *testing.T, name string) string {
	t.Helper()
	enc, err := fixtureEncrypt([]byte("tok"), "old")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	body := fmt.Sprintf("[[targets]]\nid = \"a\"\nhost = \"192.0.2.1\"\nnode = \"a\"\n\n[targets.token]\nid = \"ops@pve!ci\"\nsecret_enc = '''\n%s'''\n", enc)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// withRekeyPrompts answers rekey's two prompts and counts the new-passphrase
// reads.
func withRekeyPrompts(t *testing.T, old, next string) *int {
	t.Helper()
	origOld, origNew := rekeyOldPassphrase, rekeyNewPassphrase
	t.Cleanup(func() { rekeyOldPassphrase, rekeyNewPassphrase = origOld, origNew })
	calls := 0
	rekeyOldPassphrase = func(context.Context) (string, error) { return old, nil }
	rekeyNewPassphrase = func(context.Context) (string, error) { calls++; return next, nil }
	return &calls
}

func rosterTokenEnc(t *testing.T, path string) string {
	t.Helper()
	r, err := roster.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return r.Find("a").Token.SecretEnc
}

// TestRosterRekey_RekeysTheNamedRoster: the command rekeys the roster
// --roster names (the flag is wired), prints the count, and contacts
// nothing: no dial of any kind is observed while it runs. The control
// proves the dial recorder is armed and counting in this process.
func TestRosterRekey_RekeysTheNamedRoster(t *testing.T) {
	path := rekeyCLIRoster(t, "r.toml")
	calls := withRekeyPrompts(t, "old", "new")

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	before, _, _ := netguard.Stats()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	armed, _, _ := netguard.Stats()
	if armed != before+1 {
		t.Fatalf("control: a dial moved the recorder from %d to %d, want +1: it is not counting", before, armed)
	}

	code, stdout, stderr := runRootArgs("roster", "rekey", "--roster", path)
	after, _, _ := netguard.Stats()
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if after != armed {
		t.Errorf("rekey dialed %d time(s): it must contact nothing", after-armed)
	}
	if want := path + ": rekeyed 1 secret(s) of 1 target(s)\n"; stdout != want {
		t.Errorf("stdout %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr %q, want none for a roster not named like a harness roster", stderr)
	}
	if *calls != 1 {
		t.Errorf("new passphrase read %d times, want 1", *calls)
	}
	if p, err := roster.DecryptString(rosterTokenEnc(t, path), "new"); err != nil || string(p) != "tok" {
		t.Errorf("after rekey the new passphrase opens %q, %v", p, err)
	}
}

// TestRosterRekey_RefusesBeforeTheNewPrompt: a wrong current passphrase, or
// a roster with nothing to rekey, is refused before the new passphrase is
// asked for, and the file is unchanged.
func TestRosterRekey_RefusesBeforeTheNewPrompt(t *testing.T) {
	path := rekeyCLIRoster(t, "r.toml")
	before, _ := os.ReadFile(path)
	calls := withRekeyPrompts(t, "wrong", "new")
	code, _, stderr := runRootArgs("roster", "rekey", "--roster", path)
	if code == 0 || !strings.Contains(stderr, "wrong roster passphrase") {
		t.Errorf("wrong passphrase: exit %d, stderr %q", code, stderr)
	}
	if *calls != 0 {
		t.Errorf("the new passphrase was asked for %d times after a wrong current one", *calls)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("a refused rekey changed the roster")
	}

	empty := filepath.Join(t.TempDir(), "e.toml")
	if err := os.WriteFile(empty, []byte("[[targets]]\nid = \"c\"\nhost = \"h\"\nnode = \"n\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls = withRekeyPrompts(t, "old", "new")
	code, _, stderr = runRootArgs("roster", "rekey", "--roster", empty)
	if code == 0 || !strings.Contains(stderr, roster.ErrNothingToRekey.Error()) || *calls != 0 {
		t.Errorf("nothing to rekey: exit %d, stderr %q, new prompts %d", code, stderr, *calls)
	}
}

// TestRosterRekey_NewPassphraseErrorWritesNothing: a failed new-passphrase
// entry (no terminal, or two entries that differ) writes nothing.
func TestRosterRekey_NewPassphraseErrorWritesNothing(t *testing.T) {
	path := rekeyCLIRoster(t, "r.toml")
	before, _ := os.ReadFile(path)
	withRekeyPrompts(t, "old", "new")
	rekeyNewPassphrase = func(context.Context) (string, error) { return "", roster.ErrPassphraseMismatch }
	code, _, stderr := runRootArgs("roster", "rekey", "--roster", path)
	if code == 0 || !strings.Contains(stderr, "differ") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the roster changed")
	}
}

// TestRosterRekey_RemindsToSealAHarnessRoster: a roster named like a harness
// roster gets the one-line reminder to reseal secrets.age.
func TestRosterRekey_RemindsToSealAHarnessRoster(t *testing.T) {
	path := rekeyCLIRoster(t, "harness-outer.toml")
	withRekeyPrompts(t, "old", "new")
	code, _, stderr := runRootArgs("roster", "rekey", "--roster", path)
	if code != 0 || !strings.Contains(stderr, "hack/harness/unlock.sh seal") {
		t.Errorf("exit %d, stderr %q; want the seal reminder", code, stderr)
	}
}

// TestRosterRekey_UsesTheRealPromptsByDefault: the seams default to the
// roster package's prompts, so the new passphrase is terminal-only in the
// shipped command.
func TestRosterRekey_UsesTheRealPromptsByDefault(t *testing.T) {
	path := rekeyCLIRoster(t, "r.toml")
	t.Setenv(roster.PassphraseEnvVar, "old")
	code, _, stderr := runRootArgs("roster", "rekey", "--roster", path)
	if code == 0 || !strings.Contains(stderr, roster.ErrNewPassphraseNeedsTerminal.Error()) {
		t.Errorf("without a terminal: exit %d, stderr %q; want the terminal-only refusal", code, stderr)
	}
}

// TestBootstrap_ConfirmsAFirstPassphrase: bootstrap, which may seal a
// roster's first secret, resolves its passphrase with the confirming
// prompt, and actually calls it with the roster it was given.
func TestBootstrap_ConfirmsAFirstPassphrase(t *testing.T) {
	if reflect.ValueOf(bootstrapPassphrase).Pointer() != reflect.ValueOf(roster.ResolvePassphraseForWriteContext).Pointer() {
		t.Fatal("bootstrap does not resolve its passphrase with roster.ResolvePassphraseForWriteContext")
	}
	orig := bootstrapPassphrase
	t.Cleanup(func() { bootstrapPassphrase = orig })
	var gotPath string
	bootstrapPassphrase = func(_ context.Context, path string) (string, error) {
		gotPath = path
		return "", roster.ErrPassphraseMismatch
	}
	path := filepath.Join(t.TempDir(), "r.toml")
	code, _, stderr := runRootArgs("bootstrap", "t", "--roster", path, "--grant", "/:PVEAuditor")
	if code == 0 || !strings.Contains(stderr, "differ") || gotPath != path {
		t.Errorf("exit %d, stderr %q, resolver saw %q; want the mismatch refused for %s", code, stderr, gotPath, path)
	}
}
