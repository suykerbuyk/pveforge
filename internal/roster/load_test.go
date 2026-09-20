package roster

import (
	"os"
	"path/filepath"
	"testing"
)

const fixtureBasic = `# comment above the array
[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

[[targets]]
id   = "qa-pve-02"
host = "qa-pve-02.example.com"
node = "qa-pve-02"
`

// fixtureWithAuth builds a roster document whose secret_enc is real
// age-armored ciphertext (not a plaintext placeholder) — validate() now
// rejects anything that isn't actually armored, so tests must give it a
// realistic value.
func fixtureWithAuth(t *testing.T) string {
	t.Helper()
	armored, err := EncryptString([]byte("fixture-secret"), "fixture-passphrase")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	return `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = '''
` + armored + `'''
`
}

func TestLoad_Basic(t *testing.T) {
	withTestWorkFactor(t)
	r, err := Decode([]byte(fixtureBasic))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(r.Targets))
	}
	if r.Targets[0].ID != "qa-pve-01" || r.Targets[1].ID != "qa-pve-02" {
		t.Fatalf("unexpected ids: %+v", r.Targets)
	}
	if r.Targets[0].Token != nil || r.Targets[0].SSH != nil {
		t.Fatalf("expected no auth configured yet: %+v", r.Targets[0])
	}
}

func TestLoad_WithAuth(t *testing.T) {
	withTestWorkFactor(t)
	r, err := Decode([]byte(fixtureWithAuth(t)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tg := r.Find("qa-pve-01")
	if tg == nil {
		t.Fatal("target not found")
	}
	if tg.Token == nil {
		t.Fatal("expected token auth")
	}
	if tg.Token.ID != "pveforge@pve!automation" {
		t.Fatalf("unexpected token id: %q", tg.Token.ID)
	}
	plaintext, err := DecryptString(tg.Token.SecretEnc, "fixture-passphrase")
	if err != nil {
		t.Fatalf("decrypt fixture secret: %v", err)
	}
	if string(plaintext) != "fixture-secret" {
		t.Fatalf("unexpected decrypted secret: %q", plaintext)
	}
}

func TestLoad_RejectsNonArmoredSecret(t *testing.T) {
	withTestWorkFactor(t)
	cases := []string{
		`[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = "plaintext-placeholder"
`,
		`[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA..."
  private_key_enc = "not-actually-encrypted"
`,
	}
	for i, doc := range cases {
		if _, err := Decode([]byte(doc)); err == nil {
			t.Fatalf("case %d: expected error for non-armored secret", i)
		}
	}
}

func TestLoad_DuplicateID(t *testing.T) {
	withTestWorkFactor(t)
	doc := `[[targets]]
id = "a"
host = "h"
node = "n"

[[targets]]
id = "a"
host = "h2"
node = "n2"
`
	if _, err := Decode([]byte(doc)); err == nil {
		t.Fatal("expected error for duplicate id")
	}
}

func TestLoad_FromFile(t *testing.T) {
	withTestWorkFactor(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(fixtureBasic), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(r.Targets))
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	withTestWorkFactor(t)
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	withTestWorkFactor(t)
	cases := []string{
		`[[targets]]
host = "h"
node = "n"
`,
		`[[targets]]
id = "a"
node = "n"
`,
		`[[targets]]
id = "a"
host = "h"
`,
	}
	for i, doc := range cases {
		if _, err := Decode([]byte(doc)); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}
