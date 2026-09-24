package roster

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// fixtureTwoTargets deliberately carries a leading comment, mixed spacing,
// and a blank line between blocks so tests can prove the splicer leaves
// everything outside the touched target's block byte-for-byte identical.
const fixtureTwoTargets = `# roster — hand-edited, do not reformat
[[targets]]
id   = "qa-pve-01"   # first host, added by hand
host = "qa-pve-01.example.com"
node = "qa-pve-01"

# a deliberately weird comment before the second block
[[targets]]
id = "qa-pve-02"
host = "qa-pve-02.example.com"
node = "qa-pve-02"
`

func writeTempRoster(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// sampleArmored returns real age-armored ciphertext for use in fixtures.
// validate() rejects anything that doesn't look armored, so test fixtures
// can no longer use arbitrary placeholder text for secret_enc /
// private_key_enc — this is the shared way to get a realistic value.
func sampleArmored(t *testing.T, plaintext, passphrase string) string {
	t.Helper()
	armored, err := EncryptString([]byte(plaintext), passphrase)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	return armored
}

func TestWriteTokenAuth_FirstBootstrap_PreservesOtherTarget(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)

	secondBlockStart := strings.Index(fixtureTwoTargets, "# a deliberately weird comment")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantPrefix := fixtureTwoTargets[:secondBlockStart]

	err := WriteTokenAuth(path, "qa-pve-02", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("tok-secret-value"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}

	// Everything up to and including target #1's block, the blank line, and
	// the comment before target #2 must be byte-for-byte untouched.
	if !strings.HasPrefix(string(got), wantPrefix) {
		t.Fatalf("prefix before target #2 was altered.\nwant prefix:\n%s\ngot file:\n%s", wantPrefix, got)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	a := r.Find("qa-pve-01")
	if a == nil {
		t.Fatal("target qa-pve-01 disappeared")
	}
	if a.Token != nil || a.SSH != nil {
		t.Fatalf("target qa-pve-01 should still have no auth: %+v", a)
	}
	b := r.Find("qa-pve-02")
	if b == nil || b.Token == nil {
		t.Fatalf("target qa-pve-02 missing token auth: %+v", b)
	}
	if b.Token.ID != "pveforge@pve!automation" {
		t.Fatalf("unexpected token id: %q", b.Token.ID)
	}
	plaintext, err := DecryptString(b.Token.SecretEnc, "test-passphrase")
	if err != nil {
		t.Fatalf("decrypt written secret: %v", err)
	}
	if string(plaintext) != "tok-secret-value" {
		t.Fatalf("got secret %q, want %q", plaintext, "tok-secret-value")
	}
}

func TestWriteTokenAuth_Rotation_ReplacesOnlySecretValue(t *testing.T) {
	withTestWorkFactor(t)
	oldArmored := sampleArmored(t, "old-secret", "test-passphrase")
	fixture := `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = '''
` + oldArmored + `'''
  # a trailing comment inside the subtable, must survive
`
	path := writeTempRoster(t, fixture)

	idLine := "id         = \"pveforge@pve!automation\"\n"
	idLineStart := strings.Index(fixture, idLine)
	trailingComment := "  # a trailing comment inside the subtable, must survive\n"
	if idLineStart < 0 || !strings.Contains(fixture, trailingComment) {
		t.Fatal("fixture anchors not found")
	}
	wantPrefix := fixture[:idLineStart+len(idLine)]
	wantSuffix := trailingComment

	err := WriteTokenAuth(path, "qa-pve-01", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("new-secret"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteTokenAuth (rotation): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	gotStr := string(got)

	if !strings.HasPrefix(gotStr, wantPrefix) {
		t.Fatalf("prefix through the id line was altered.\nwant prefix:\n%q\ngot:\n%q", wantPrefix, gotStr)
	}
	if !strings.HasSuffix(strings.TrimRight(gotStr, "\n")+"\n", wantSuffix) && !strings.Contains(gotStr, wantSuffix) {
		t.Fatalf("trailing comment did not survive rotation.\ngot:\n%s", gotStr)
	}
	if strings.Contains(gotStr, oldArmored) {
		t.Fatal("old secret value was not replaced")
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	plaintext, err := DecryptString(tg.Token.SecretEnc, "test-passphrase")
	if err != nil {
		t.Fatalf("decrypt rotated secret: %v", err)
	}
	if string(plaintext) != "new-secret" {
		t.Fatalf("got %q, want %q", plaintext, "new-secret")
	}
}

func TestWriteSSHAuth_CoexistsWithToken(t *testing.T) {
	withTestWorkFactor(t)
	tokenArmored := sampleArmored(t, "token-secret", "test-passphrase")
	fixture := `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = '''
` + tokenArmored + `'''
`
	path := writeTempRoster(t, fixture)

	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... pveforge@qa-pve-01",
		PrivateKeyPlaintext: []byte("ssh-priv-key-material"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(got), tokenArmored) {
		t.Fatal("existing token subtable was disturbed by adding ssh auth")
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg.Token == nil {
		t.Fatal("token auth lost")
	}
	// Value-exact, not just "still present": the token's id and secret_enc
	// must be byte-identical to what was there before ssh auth was added.
	if tg.Token.ID != "pveforge@pve!automation" || tg.Token.SecretEnc != tokenArmored {
		t.Fatalf("token auth changed while writing ssh auth: %+v", tg.Token)
	}
	if tg.SSH == nil || tg.SSH.User != "root" || tg.SSH.PublicKey != "ssh-ed25519 AAAA... pveforge@qa-pve-01" {
		t.Fatalf("ssh auth not written correctly: %+v", tg.SSH)
	}
	plaintext, err := DecryptString(tg.SSH.PrivateKeyEnc, "test-passphrase")
	if err != nil {
		t.Fatalf("decrypt ssh key: %v", err)
	}
	if string(plaintext) != "ssh-priv-key-material" {
		t.Fatalf("got %q, want %q", plaintext, "ssh-priv-key-material")
	}
}

// TestWriteTokenAuth_PreservesExistingSSHValue is the complementary
// direction: writing TOKEN auth onto a target that already has SSH auth
// must leave the SSH subtable value-identical, not merely "still present".
// This specifically exercises verifyOnlyIntendedChange's check of the
// auth subtable NOT being written for the target that IS being changed —
// a bug there would previously only be caught if it also corrupted some
// OTHER target, not a sibling subtable on the same target.
func TestWriteTokenAuth_PreservesExistingSSHValue(t *testing.T) {
	withTestWorkFactor(t)
	sshArmored := sampleArmored(t, "ssh-priv-key-original", "test-passphrase")
	fixture := `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA... pveforge@qa-pve-01"
  private_key_enc = '''
` + sshArmored + `'''
`
	path := writeTempRoster(t, fixture)

	err := WriteTokenAuth(path, "qa-pve-01", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("new-token-secret"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(got), sshArmored) {
		t.Fatal("existing ssh subtable was disturbed by adding token auth")
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg.SSH == nil {
		t.Fatal("ssh auth lost")
	}
	// Value-exact comparison against the original, per the review's
	// requirement — not just "SSH != nil".
	if tg.SSH.User != "root" ||
		tg.SSH.PublicKey != "ssh-ed25519 AAAA... pveforge@qa-pve-01" ||
		tg.SSH.PrivateKeyEnc != sshArmored {
		t.Fatalf("ssh auth changed while writing token auth: %+v", tg.SSH)
	}
	if tg.Token == nil {
		t.Fatal("token auth was not written")
	}
}

func TestWriteTokenAuth_UnknownTarget(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteTokenAuth(path, "does-not-exist", TokenWrite{
		TokenID:         "x",
		SecretPlaintext: []byte("y"),
	}, NewPassphrase("pw"))
	if err == nil {
		t.Fatal("expected error for unknown target id")
	}
}

func TestWriteTokenAuth_TargetMissingID(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
host = "h1"
node = "n1"
`
	path := writeTempRoster(t, fixture)
	err := WriteTokenAuth(path, "anything", TokenWrite{
		TokenID:         "x",
		SecretPlaintext: []byte("y"),
	}, NewPassphrase("pw"))
	if err == nil {
		t.Fatal("expected error for target block missing id")
	}
}

func TestQuoteTOMLBasicString_Escapes(t *testing.T) {
	withTestWorkFactor(t)
	cases := map[string]string{
		`plain`:            `"plain"`,
		`with "quote"`:     `"with \"quote\""`,
		`back\slash`:       `"back\\slash"`,
		"tab\tnewline\n":   `"tab\tnewline\n"`,
		"carriage\rreturn": `"carriage\rreturn"`,
	}
	for in, want := range cases {
		if got := quoteTOMLBasicString(in); got != want {
			t.Errorf("quoteTOMLBasicString(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every string quoteTOMLBasicString renders must be a valid TOML basic
// string that go-toml decodes back to the input: each control rune TOML
// forbids raw (U+0000-U+001F, U+007F) — tab included, though it is legal
// raw — alone and embedded, plus runes that are legal raw and must pass
// through unchanged (C1 U+0085, U+2028, non-ASCII), quote and backslash.
func TestQuoteTOMLBasicString_RoundTripsEveryControlRune(t *testing.T) {
	withTestWorkFactor(t)
	var inputs []string
	for r := rune(0); r < 0x20; r++ {
		inputs = append(inputs, string(r), "a"+string(r)+"b")
	}
	inputs = append(inputs, "\x7f", "a\x7fb", "\u0085", "\u2028", "\u2029", "é", "日本", `"`, `\`, `\u0041`, "mixed\x00\b\f\x1b[0m\x7f\u2028\"\\end")
	for _, in := range inputs {
		q := quoteTOMLBasicString(in)
		var v struct {
			V string `toml:"v"`
		}
		if err := toml.Unmarshal([]byte("v = "+q+"\n"), &v); err != nil {
			t.Errorf("quoteTOMLBasicString(%q) = %q: not valid TOML: %v", in, q, err)
			continue
		}
		if v.V != in {
			t.Errorf("quoteTOMLBasicString(%q) = %q: decodes to %q", in, q, v.V)
		}
	}
}

func TestWriteSSHAuth_QuotesSpecialCharsInPublicKey(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           `ssh-ed25519 AAAA... comment "with quotes"`,
		PrivateKeyPlaintext: []byte("k"),
	}, NewPassphrase("pw"))
	if err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg.SSH == nil || tg.SSH.PublicKey != `ssh-ed25519 AAAA... comment "with quotes"` {
		t.Fatalf("public key round-trip mismatch: %+v", tg.SSH)
	}
}

// TestWriteTokenAuth_FirstTarget_PreservesLaterTargetBytes is the mirror
// image of TestWriteTokenAuth_FirstBootstrap_PreservesOtherTarget: that
// test writes to the LAST target and checks the PREFIX; this one writes to
// the FIRST target and checks that the LATER target's exact bytes (not
// just "still parses correctly") are unchanged, including its own
// preceding comment. qa-pve-02 is fixtureTwoTargets' last target, so
// nothing is ever inserted after it — its block must appear as an exact,
// untouched suffix of the resulting file.
func TestWriteTokenAuth_FirstTarget_PreservesLaterTargetBytes(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)

	secondBlockStart := strings.Index(fixtureTwoTargets, "# a deliberately weird comment")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantSuffix := fixtureTwoTargets[secondBlockStart:]

	err := WriteTokenAuth(path, "qa-pve-01", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("tok-secret-value"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.HasSuffix(string(got), wantSuffix) {
		t.Fatalf("target #2's block (and its preceding comment) was altered.\nwant suffix:\n%q\ngot file:\n%q", wantSuffix, got)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	b := r.Find("qa-pve-02")
	if b == nil || b.Token != nil || b.SSH != nil {
		t.Fatalf("target qa-pve-02 should be completely untouched: %+v", b)
	}
}

// TestWriteTokenAuth_ExactIDMatch_DoesNotAffectPrefixTarget guards
// specifically against a regression where target lookup matches by
// prefix/substring instead of exact string equality: "pve-1" is a prefix
// of "pve-10", so writing to "pve-1" must never touch "pve-10"'s bytes.
func TestWriteTokenAuth_ExactIDMatch_DoesNotAffectPrefixTarget(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id   = "pve-1"
host = "pve-1.example.com"
node = "pve-1"

# pve-10's own block, must be untouched by a write to pve-1
[[targets]]
id   = "pve-10"
host = "pve-10.example.com"
node = "pve-10"
`
	path := writeTempRoster(t, fixture)

	secondBlockStart := strings.Index(fixture, "# pve-10's own block")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantSuffix := fixture[secondBlockStart:]

	err := WriteTokenAuth(path, "pve-1", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("tok-secret-value"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteTokenAuth: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.HasSuffix(string(got), wantSuffix) {
		t.Fatalf("pve-10's block was altered by a write to pve-1.\nwant suffix:\n%q\ngot file:\n%q", wantSuffix, got)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	if tg := r.Find("pve-10"); tg == nil || tg.Token != nil {
		t.Fatalf("pve-10 should have no token auth: %+v", tg)
	}
	if tg := r.Find("pve-1"); tg == nil || tg.Token == nil {
		t.Fatalf("pve-1 should have token auth: %+v", tg)
	}
}

func TestWriteSSHAuth_WritesHostKeyFingerprint(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... pveforge@qa-pve-01",
		HostKeyFingerprint:  "SHA256:abcdefg1234567890",
		PrivateKeyPlaintext: []byte("ssh-priv-key-material"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteSSHAuth: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg.SSH == nil || tg.SSH.HostKeyFingerprint != "SHA256:abcdefg1234567890" {
		t.Fatalf("host key fingerprint not written correctly: %+v", tg.SSH)
	}
}

func TestWriteSSHAuth_RotationPreservesHostKeyFingerprint(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... old",
		HostKeyFingerprint:  "SHA256:original-fingerprint",
		PrivateKeyPlaintext: []byte("old-key"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteSSHAuth (initial): %v", err)
	}

	err = WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... new",
		HostKeyFingerprint:  "SHA256:rotated-fingerprint",
		PrivateKeyPlaintext: []byte("new-key"),
	}, NewPassphrase("test-passphrase"))
	if err != nil {
		t.Fatalf("WriteSSHAuth (rotation): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg.SSH == nil || tg.SSH.HostKeyFingerprint != "SHA256:rotated-fingerprint" {
		t.Fatalf("host key fingerprint not updated on rotation: %+v", tg.SSH)
	}
	if strings.Contains(string(got), "original-fingerprint") {
		t.Fatal("old host key fingerprint was not replaced")
	}
}

func TestAppendTarget_NewRoster(t *testing.T) {
	withTestWorkFactor(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.toml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty roster: %v", err)
	}

	err := AppendTarget(path, Target{
		ID:   "qa-pve-01",
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
	})
	if err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(r.Targets))
	}
	tg := r.Find("qa-pve-01")
	if tg == nil || tg.Host != "qa-pve-01.example.com" || tg.Node != "qa-pve-01" {
		t.Fatalf("unexpected target: %+v", tg)
	}
	if tg.Token != nil || tg.SSH != nil {
		t.Fatalf("freshly appended target should have no auth: %+v", tg)
	}
}

func TestAppendTarget_PreservesExistingTargets(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)

	err := AppendTarget(path, Target{
		ID:      "qa-pve-03",
		Host:    "qa-pve-03.example.com",
		Node:    "qa-pve-03",
		APIPort: 8007,
	})
	if err != nil {
		t.Fatalf("AppendTarget: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.HasPrefix(string(got), fixtureTwoTargets) {
		t.Fatalf("existing roster bytes were altered.\nwant prefix:\n%s\ngot:\n%s", fixtureTwoTargets, got)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	if len(r.Targets) != 3 {
		t.Fatalf("want 3 targets, got %d", len(r.Targets))
	}
	a := r.Find("qa-pve-01")
	if a == nil || a.Token != nil || a.SSH != nil {
		t.Fatalf("qa-pve-01 should be untouched: %+v", a)
	}
	b := r.Find("qa-pve-02")
	if b == nil || b.Token != nil || b.SSH != nil {
		t.Fatalf("qa-pve-02 should be untouched: %+v", b)
	}
	c := r.Find("qa-pve-03")
	if c == nil || c.Host != "qa-pve-03.example.com" || c.APIPort != 8007 {
		t.Fatalf("qa-pve-03 not appended correctly: %+v", c)
	}
}

func TestAppendTarget_DuplicateID(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := AppendTarget(path, Target{
		ID:   "qa-pve-01",
		Host: "duplicate.example.com",
		Node: "dup",
	})
	if err == nil {
		t.Fatal("expected error for duplicate target id")
	}
}

// AppendTarget refuses a line-unsafe id itself, before taking the roster
// lock: the file is untouched, no lock file is ever created, and the error
// names the id rather than surfacing as Decode's "safety check failed" on
// the composed result. A line-safe id still appends and loads back.
func TestAppendTarget_RejectsLineUnsafeTargetID(t *testing.T) {
	withTestWorkFactor(t)
	for _, id := range lineUnsafeTargetIDs {
		path := writeTempRoster(t, fixtureTwoTargets)
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		err = AppendTarget(path, Target{ID: id, Host: "h", Node: "n"})
		if err == nil {
			t.Errorf("id %q: AppendTarget accepted a line-unsafe target id", id)
			continue
		}
		if want := fmt.Sprintf("append target: target id %q", id); !strings.Contains(err.Error(), want) {
			t.Errorf("id %q: error = %q, want it to contain %q", id, err, want)
		}
		if _, statErr := os.Stat(path + ".lock"); !os.IsNotExist(statErr) {
			t.Errorf("id %q: roster lock file exists (stat err %v): the id was checked after the lock, not before", id, statErr)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("id %q: roster changed", id)
		}
	}
	for _, id := range lineSafeTargetIDs {
		if id == "qa-pve-01" {
			continue // already in fixtureTwoTargets
		}
		path := writeTempRoster(t, fixtureTwoTargets)
		if err := AppendTarget(path, Target{ID: id, Host: "h", Node: "n"}); err != nil {
			t.Errorf("id %q: AppendTarget: %v", id, err)
			continue
		}
		if r, err := Load(path); err != nil || r.Find(id) == nil {
			t.Errorf("id %q: appended but did not load back (err %v)", id, err)
		}
	}
}

func TestAppendTarget_MissingRequiredFields(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	cases := []Target{
		{Host: "h", Node: "n"},
		{ID: "x", Node: "n"},
		{ID: "x", Host: "h"},
	}
	for i, tg := range cases {
		if err := AppendTarget(path, tg); err == nil {
			t.Fatalf("case %d: expected error for missing required field: %+v", i, tg)
		}
	}
}

func TestAppendTarget_RejectsAuthSubtables(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := AppendTarget(path, Target{
		ID:    "qa-pve-03",
		Host:  "qa-pve-03.example.com",
		Node:  "qa-pve-03",
		Token: &TokenAuth{ID: "x", SecretEnc: "y"},
	})
	if err == nil {
		t.Fatal("expected error when appending a target that already carries auth subtables")
	}
}

// --- UpdateTargetFields ---------------------------------------------

func TestUpdateTargetFields_AddsInsecureTLSToTargetWithoutIt(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	a := r.Find("qa-pve-01")
	if a == nil || !a.InsecureTLS {
		t.Fatalf("expected insecure_tls=true on qa-pve-01, got %+v", a)
	}
	if a.Host != "qa-pve-01.example.com" || a.Node != "qa-pve-01" {
		t.Fatalf("host/node should be unchanged: %+v", a)
	}
	if !strings.Contains(string(got), "insecure_tls = true") {
		t.Fatalf("expected a bare (unquoted) insecure_tls = true line, got:\n%s", got)
	}
	// api_port was never set and stays at its zero value: must not gain a
	// spurious "api_port = 0" line.
	if strings.Contains(string(got), "api_port") {
		t.Fatalf("expected no api_port line to be added, got:\n%s", got)
	}

	b := r.Find("qa-pve-02")
	if b == nil || b.InsecureTLS {
		t.Fatalf("qa-pve-02 must be untouched: %+v", b)
	}
}

func TestUpdateTargetFields_UpdatesExistingValue(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"
api_port = 8006
insecure_tls = false
`
	path := writeTempRoster(t, fixture)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		APIPort:     8006,
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(got), "insecure_tls = true") {
		t.Fatalf("expected insecure_tls updated to true in place, got:\n%s", got)
	}
	if strings.Count(string(got), "insecure_tls") != 1 {
		t.Fatalf("expected exactly one insecure_tls line (updated in place, not duplicated), got:\n%s", got)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	a := r.Find("qa-pve-01")
	if a == nil || !a.InsecureTLS || a.APIPort != 8006 {
		t.Fatalf("unexpected target after update: %+v", a)
	}
}

func TestUpdateTargetFields_ClearsToExplicitFalse(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"
insecure_tls = true
`
	path := writeTempRoster(t, fixture)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host: "qa-pve-01.example.com",
		Node: "qa-pve-01",
		// InsecureTLS left at false: wants to clear the previously-set value.
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.Contains(string(got), "insecure_tls = false") {
		t.Fatalf("expected insecure_tls rewritten to explicit false, got:\n%s", got)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	if a := r.Find("qa-pve-01"); a == nil || a.InsecureTLS {
		t.Fatalf("expected insecure_tls=false after update, got %+v", a)
	}
}

// TestUpdateTargetFields_NoOp_FileUntouched proves the documented no-op
// contract at the strongest level available: not just "resulting bytes
// happen to be identical" but that no write (rename) ever occurred at
// all, by comparing the file's mtime before and after — an atomicWrite
// always renames a fresh temp file into place, which always advances
// mtime, even when the new content is byte-identical to the old.
func TestUpdateTargetFields_NoOp_FileUntouched(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"
api_port = 8006
insecure_tls = true
`
	path := writeTempRoster(t, fixture)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}
	statBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}

	err = UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		APIPort:     8006,
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	statAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}

	if string(before) != string(after) {
		t.Fatalf("expected byte-identical file, before:\n%s\nafter:\n%s", before, after)
	}
	if !statBefore.ModTime().Equal(statAfter.ModTime()) {
		t.Errorf("expected mtime unchanged (no rename/write occurred) for a true no-op, before=%v after=%v", statBefore.ModTime(), statAfter.ModTime())
	}
}

func TestUpdateTargetFields_UnknownTarget(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := UpdateTargetFields(path, "does-not-exist", TargetMeta{Host: "h", Node: "n"})
	if err == nil {
		t.Fatal("expected error for unknown target id")
	}
}

func TestUpdateTargetFields_DuplicateTargetID(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id = "dup"
host = "h1"
node = "n1"

[[targets]]
id = "dup"
host = "h2"
node = "n2"
`
	path := writeTempRoster(t, fixture)
	err := UpdateTargetFields(path, "dup", TargetMeta{Host: "h1", Node: "n1", InsecureTLS: true})
	if err == nil {
		t.Fatal("expected error for ambiguous duplicate target id")
	}
}

// TestUpdateTargetFields_PreservesOtherTarget mirrors
// TestWriteTokenAuth_FirstBootstrap_PreservesOtherTarget: writing to
// qa-pve-01 must leave qa-pve-02's own block (and the comment preceding
// it) byte-for-byte untouched.
func TestUpdateTargetFields_PreservesOtherTarget(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)

	secondBlockStart := strings.Index(fixtureTwoTargets, "# a deliberately weird comment")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantSuffix := fixtureTwoTargets[secondBlockStart:]

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !strings.HasSuffix(string(got), wantSuffix) {
		t.Fatalf("target #2's block was altered.\nwant suffix:\n%q\ngot file:\n%q", wantSuffix, got)
	}
}

// TestUpdateTargetFields_PreservesAuthSubtables is the
// verifyOnlyIntendedChange-style protection this task called for,
// adapted to verifyOnlyTargetFieldsChanged: a target with BOTH token and
// ssh auth already persisted must keep both value-identical (not just
// "still present") after its top-level fields are updated, and the new
// field must be inserted BEFORE the first subtable, not after it.
func TestUpdateTargetFields_PreservesAuthSubtables(t *testing.T) {
	withTestWorkFactor(t)
	tokenArmored := sampleArmored(t, "token-secret", "test-passphrase")
	sshArmored := sampleArmored(t, "ssh-priv-key", "test-passphrase")
	fixture := `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = '''
` + tokenArmored + `'''

  [targets.ssh]
  user            = "root"
  public_key      = "ssh-ed25519 AAAA..."
  private_key_enc = '''
` + sshArmored + `'''
`
	path := writeTempRoster(t, fixture)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	gotStr := string(got)

	// The new field must land BEFORE the first subtable header, not after.
	insecureIdx := strings.Index(gotStr, "insecure_tls")
	tokenHeaderIdx := strings.Index(gotStr, "[targets.token]")
	if insecureIdx < 0 || tokenHeaderIdx < 0 || insecureIdx > tokenHeaderIdx {
		t.Fatalf("expected insecure_tls to be inserted before [targets.token], got:\n%s", gotStr)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg == nil || !tg.InsecureTLS {
		t.Fatalf("insecure_tls not updated: %+v", tg)
	}
	if tg.Token == nil || tg.Token.ID != "pveforge@pve!automation" || tg.Token.SecretEnc != tokenArmored {
		t.Fatalf("token auth changed while updating top-level fields: %+v", tg.Token)
	}
	if tg.SSH == nil || tg.SSH.User != "root" || tg.SSH.PrivateKeyEnc != sshArmored {
		t.Fatalf("ssh auth changed while updating top-level fields: %+v", tg.SSH)
	}
}

// TestUpdateTargetFields_BlankLineBeforeExistingSubtablePreserved proves the
// findTargetBlocks ownEnd fix: appending a new top-level field to a target
// that already has a subtable must not strand the pre-existing blank line
// before the new field — the new field belongs adjacent to the target's
// other own fields, and the blank line stays where it was, immediately
// before the subtable header.
func TestUpdateTargetFields_BlankLineBeforeExistingSubtablePreserved(t *testing.T) {
	withTestWorkFactor(t)
	tokenArmored := sampleArmored(t, "token-secret", "test-passphrase")
	fixture := `[[targets]]
id   = "qa-pve-01"
host = "qa-pve-01.example.com"
node = "qa-pve-01"

  [targets.token]
  id         = "pveforge@pve!automation"
  secret_enc = '''
` + tokenArmored + `'''
`
	path := writeTempRoster(t, fixture)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{
		Host:        "qa-pve-01.example.com",
		Node:        "qa-pve-01",
		InsecureTLS: true,
	})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	gotStr := string(got)

	// No blank line between the existing own fields and the newly appended
	// one, and exactly one blank line between the new field and the
	// subtable header that follows it.
	const want = "node = \"qa-pve-01\"\ninsecure_tls = true\n\n  [targets.token]\n"
	if !strings.Contains(gotStr, want) {
		t.Fatalf("expected %q in result, got:\n%s", want, gotStr)
	}

	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	tg := r.Find("qa-pve-01")
	if tg == nil || !tg.InsecureTLS {
		t.Fatalf("insecure_tls not updated: %+v", tg)
	}
	if tg.Token == nil || tg.Token.ID != "pveforge@pve!automation" || tg.Token.SecretEnc != tokenArmored {
		t.Fatalf("token auth changed while updating top-level fields: %+v", tg.Token)
	}
}

// TestUpdateTargetFields_TrailingNewlineGuard proves the append-branch's
// own "insert a leading newline if the insertion point isn't already at a
// clean line boundary" guard — mirroring applySubtableSplice's identical
// guard for its own append case — by using a fixture whose last line has
// no trailing newline at all.
func TestUpdateTargetFields_TrailingNewlineGuard(t *testing.T) {
	withTestWorkFactor(t)
	fixture := "[[targets]]\nid = \"qa-pve-01\"\nhost = \"h\"\nnode = \"n\""
	path := writeTempRoster(t, fixture)

	err := UpdateTargetFields(path, "qa-pve-01", TargetMeta{Host: "h", Node: "n", InsecureTLS: true})
	if err != nil {
		t.Fatalf("UpdateTargetFields: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if strings.Contains(string(got), "ninsecure_tls") {
		t.Fatalf("missing newline before appended field, got:\n%q", got)
	}
	r, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode result: %v\n---\n%s", err, got)
	}
	if tg := r.Find("qa-pve-01"); tg == nil || !tg.InsecureTLS {
		t.Fatalf("insecure_tls not applied: %+v", tg)
	}
}

func TestWriteTokenAuth_DuplicateTargetID(t *testing.T) {
	withTestWorkFactor(t)
	const fixture = `[[targets]]
id = "dup"
host = "h1"
node = "n1"

[[targets]]
id = "dup"
host = "h2"
node = "n2"
`
	path := writeTempRoster(t, fixture)
	err := WriteTokenAuth(path, "dup", TokenWrite{
		TokenID:         "x",
		SecretPlaintext: []byte("y"),
	}, NewPassphrase("pw"))
	if err == nil {
		t.Fatal("expected error for ambiguous duplicate target id")
	}
}
