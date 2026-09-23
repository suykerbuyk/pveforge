package roster

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
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

// lineUnsafeTargetIDs covers every trigger class kvjson.LineUnsafe has: a
// C0 line break and other C0/DEL/C1 controls (U+0085 is NEL), U+2028,
// leading or trailing whitespace (ASCII and not), and a leading quote.
var lineUnsafeTargetIDs = []string{
	"qa\nwarning: forged", "qa\r", "qa\x00", "qa\t", "qa\x7f", "qa\u0085", "qa\u2028",
	" qa", "qa ", "\u00a0qa", `"qa`,
}

// lineSafeTargetIDs must stay accepted: the check refuses what could forge
// a line, not every unusual id.
var lineSafeTargetIDs = []string{"qa-pve-01", "qa pve", "qa=1", "null", `qa"x`}

// tomlBasicString encodes s as a TOML basic string, escaping every
// control character (which TOML forbids raw) as \uXXXX.
func tomlBasicString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// A roster holding a target id that could forge an output line is refused
// at load, naming the id quoted; the ids that are merely unusual load.
func TestDecode_RejectsLineUnsafeTargetID(t *testing.T) {
	withTestWorkFactor(t)
	doc := func(id string) []byte {
		return []byte("[[targets]]\nid = " + tomlBasicString(id) + "\nhost = \"h\"\nnode = \"n\"\n")
	}
	for _, id := range lineUnsafeTargetIDs {
		_, err := Decode(doc(id))
		if err == nil {
			t.Errorf("id %q: Decode accepted a line-unsafe target id", id)
			continue
		}
		if want := fmt.Sprintf("target #0: target id %q", id); !strings.Contains(err.Error(), want) {
			t.Errorf("id %q: error = %q, want it to contain %q", id, err, want)
		}
	}
	for _, id := range lineSafeTargetIDs {
		r, err := Decode(doc(id))
		if err != nil {
			t.Errorf("id %q: Decode: %v", id, err)
			continue
		}
		if r.Find(id) == nil {
			t.Errorf("id %q: decoded, but Find does not return it", id)
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
