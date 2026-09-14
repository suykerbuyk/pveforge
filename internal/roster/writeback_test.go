package roster

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	path := writeTempRoster(t, fixtureTwoTargets)

	secondBlockStart := strings.Index(fixtureTwoTargets, "# a deliberately weird comment")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantPrefix := fixtureTwoTargets[:secondBlockStart]

	err := WriteTokenAuth(path, "qa-pve-02", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("tok-secret-value"),
	}, "test-passphrase")
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
	}, "test-passphrase")
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
	}, "test-passphrase")
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
	}, "test-passphrase")
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
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteTokenAuth(path, "does-not-exist", TokenWrite{
		TokenID:         "x",
		SecretPlaintext: []byte("y"),
	}, "pw")
	if err == nil {
		t.Fatal("expected error for unknown target id")
	}
}

func TestWriteTokenAuth_TargetMissingID(t *testing.T) {
	const fixture = `[[targets]]
host = "h1"
node = "n1"
`
	path := writeTempRoster(t, fixture)
	err := WriteTokenAuth(path, "anything", TokenWrite{
		TokenID:         "x",
		SecretPlaintext: []byte("y"),
	}, "pw")
	if err == nil {
		t.Fatal("expected error for target block missing id")
	}
}

func TestQuoteTOMLBasicString_Escapes(t *testing.T) {
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

func TestWriteSSHAuth_QuotesSpecialCharsInPublicKey(t *testing.T) {
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           `ssh-ed25519 AAAA... comment "with quotes"`,
		PrivateKeyPlaintext: []byte("k"),
	}, "pw")
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
	path := writeTempRoster(t, fixtureTwoTargets)

	secondBlockStart := strings.Index(fixtureTwoTargets, "# a deliberately weird comment")
	if secondBlockStart < 0 {
		t.Fatal("fixture anchor not found")
	}
	wantSuffix := fixtureTwoTargets[secondBlockStart:]

	err := WriteTokenAuth(path, "qa-pve-01", TokenWrite{
		TokenID:         "pveforge@pve!automation",
		SecretPlaintext: []byte("tok-secret-value"),
	}, "test-passphrase")
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
	}, "test-passphrase")
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
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... pveforge@qa-pve-01",
		HostKeyFingerprint:  "SHA256:abcdefg1234567890",
		PrivateKeyPlaintext: []byte("ssh-priv-key-material"),
	}, "test-passphrase")
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
	path := writeTempRoster(t, fixtureTwoTargets)
	err := WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... old",
		HostKeyFingerprint:  "SHA256:original-fingerprint",
		PrivateKeyPlaintext: []byte("old-key"),
	}, "test-passphrase")
	if err != nil {
		t.Fatalf("WriteSSHAuth (initial): %v", err)
	}

	err = WriteSSHAuth(path, "qa-pve-01", SSHWrite{
		User:                "root",
		PublicKey:           "ssh-ed25519 AAAA... new",
		HostKeyFingerprint:  "SHA256:rotated-fingerprint",
		PrivateKeyPlaintext: []byte("new-key"),
	}, "test-passphrase")
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

func TestAppendTarget_MissingRequiredFields(t *testing.T) {
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

func TestWriteTokenAuth_DuplicateTargetID(t *testing.T) {
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
	}, "pw")
	if err == nil {
		t.Fatal("expected error for ambiguous duplicate target id")
	}
}
