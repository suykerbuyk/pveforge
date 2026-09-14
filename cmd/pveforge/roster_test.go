package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func TestResolveRosterPath_PositionalArgWins(t *testing.T) {
	cmd := newRosterInitCmd()
	if err := cmd.Flags().Set("force", "false"); err != nil {
		t.Fatalf("set force flag: %v", err)
	}
	// newRosterInitCmd itself has no --roster flag (that's on the parent
	// `roster` command); resolveRosterPath only needs the flag to exist
	// when there's no positional arg, so this exercises the positional-arg
	// short-circuit path directly.
	got, err := resolveRosterPath(cmd, []string{"/explicit/path.toml"})
	if err != nil {
		t.Fatalf("resolveRosterPath: %v", err)
	}
	if got != "/explicit/path.toml" {
		t.Fatalf("got %q, want %q", got, "/explicit/path.toml")
	}
}

func TestResolveRosterPath_FallsBackToFlagOrEnv(t *testing.T) {
	cmd := newRosterCmd()
	// The --roster flag is registered as a PersistentFlag on this command;
	// cobra only merges persistent flags into Flags() during
	// ParseFlags/Execute, which a direct call to resolveRosterPath (as
	// opposed to going through cmd.Execute()) skips.
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	t.Setenv("PVEFORGE_ROSTER", "/env/roster.toml")
	got, err := resolveRosterPath(cmd, nil)
	if err != nil {
		t.Fatalf("resolveRosterPath: %v", err)
	}
	if got != "/env/roster.toml" {
		t.Fatalf("got %q, want %q", got, "/env/roster.toml")
	}
}

func TestRosterInitAndValidate_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")

	initCmd := newRosterInitCmd()
	initCmd.SetArgs([]string{path})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("roster init: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected roster file to be created: %v", err)
	}

	validateCmd := newRosterValidateCmd()
	validateCmd.SetArgs([]string{path})
	if err := validateCmd.Execute(); err != nil {
		t.Fatalf("roster validate: %v", err)
	}
}

func TestRosterInit_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte("stale contents"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	cmd := newRosterInitCmd()
	cmd.SetArgs([]string{path, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("roster init --force: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != rosterTemplate {
		t.Fatal("expected --force to overwrite the stale file with the template")
	}
}

func TestRosterValidate_ReportsPerTargetAuthStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")

	tokenArmored, err := roster.EncryptString([]byte("tok-secret"), "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	sshArmored, err := roster.EncryptString([]byte("ssh-key"), "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	fixture := `[[targets]]
id   = "pending-target"
host = "pending.example.com"
node = "pending"

[[targets]]
id   = "token-only-target"
host = "token-only.example.com"
node = "token-only"

  [targets.token]
  id         = "root@pam!pveforge"
  secret_enc = '''
` + tokenArmored + `'''

[[targets]]
id   = "ssh-only-target"
host = "ssh-only.example.com"
node = "ssh-only"

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA..."
  private_key_enc = '''
` + sshArmored + `'''

[[targets]]
id   = "fully-bootstrapped-target"
host = "full.example.com"
node = "full"

  [targets.token]
  id         = "root@pam!pveforge"
  secret_enc = '''
` + tokenArmored + `'''

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA..."
  private_key_enc = '''
` + sshArmored + `'''
`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cmd := newRosterValidateCmd()
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("roster validate: %v", err)
	}
}

func TestRosterInit_StatFailureOtherThanNotExist(t *testing.T) {
	// A path with a non-directory component in the middle makes os.Stat
	// fail with something other than "not exist" (ENOTDIR), exercising
	// the `!os.IsNotExist(err)` branch distinctly from the ordinary
	// already-exists and does-not-exist-yet cases.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	badPath := filepath.Join(filePath, "roster.toml")

	cmd := newRosterInitCmd()
	cmd.SetArgs([]string{badPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a path with a non-directory parent component")
	}
}

func TestRosterInit_RefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	cmd := newRosterInitCmd()
	cmd.SetArgs([]string{path})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when roster already exists and --force is not set")
	}
}
