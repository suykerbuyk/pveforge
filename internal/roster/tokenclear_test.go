package roster

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureTokenAndSSH has target qa-pve-01 carrying both auth subtables, and
// a second target that must never be touched.
func fixtureTokenAndSSH(t *testing.T) string {
	t.Helper()
	return "# roster\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\n\n" +
		"[targets.ssh]\nuser = \"root\"\npublic_key = \"ssh-ed25519 AAAA x\"\nhost_key_fingerprint = \"SHA256:abc\"\nprivate_key_enc = '''\n" +
		sampleArmored(t, "key", "p") + "'''\n\n" +
		"[targets.token]\nid = \"root@pam!pveforge\"\nsecret_enc = '''\n" + sampleArmored(t, "tok", "p") + "'''\n\n" +
		"# second\n[[targets]]\nid = \"qa-pve-02\"\nhost = \"h2\"\nnode = \"qa-pve-02\"\n"
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func copyRoster(t *testing.T, path string) string {
	t.Helper()
	return writeTempRoster(t, string(readFile(t, path)))
}

// CT1: only the target's [targets.token] subtable goes; its SSH subtable
// and every other target decode identically.
func TestClearTokenAuth_RemovesOnlyTheTargetsTokenSubtable(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTokenAndSSH(t))
	before, err := Decode(readFile(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if err := ClearTokenAuth(path, "qa-pve-01"); err != nil {
		t.Fatalf("ClearTokenAuth: %v", err)
	}
	got := readFile(t, path)
	after, err := Decode(got)
	if err != nil {
		t.Fatalf("decode after clear: %v\n%s", err, got)
	}
	t1, t1b := after.Find("qa-pve-01"), before.Find("qa-pve-01")
	if t1.Token != nil {
		t.Fatalf("token still present after clear: %+v", t1.Token)
	}
	if !sshAuthEqual(t1.SSH, t1b.SSH) {
		t.Fatalf("ssh auth changed by a token clear")
	}
	if !targetDeepEqual(*after.Find("qa-pve-02"), *before.Find("qa-pve-02")) {
		t.Fatalf("the other target changed")
	}
	if strings.Contains(string(got), "[targets.token]") || strings.Contains(string(got), "root@pam!pveforge") {
		t.Fatalf("token text left behind:\n%s", got)
	}
}

// CT1b: a clear exactly undoes WriteTokenAuth's append, byte for byte, so
// clear-then-write lands the same bytes as a write on the original roster.
func TestClearTokenAuth_UndoesAnAppendExactly(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	orig := readFile(t, path)
	if err := WriteTokenAuth(path, "qa-pve-01", TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("s")}, "p"); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(readFile(t, path), orig) {
		t.Fatal("the write did not change the roster (test would be vacuous)")
	}
	if err := ClearTokenAuth(path, "qa-pve-01"); err != nil {
		t.Fatalf("ClearTokenAuth: %v", err)
	}
	if got := readFile(t, path); !bytes.Equal(got, orig) {
		t.Fatalf("write-then-clear did not restore the original bytes.\nwant:\n%q\ngot:\n%q", orig, got)
	}
}

// CT2: a target without a token is a no-op and leaves the file byte-identical.
func TestClearTokenAuth_NoTokenIsANoOp(t *testing.T) {
	path := writeTempRoster(t, fixtureTwoTargets)
	if err := ClearTokenAuth(path, "qa-pve-01"); err != nil {
		t.Fatalf("ClearTokenAuth: %v", err)
	}
	if got := readFile(t, path); string(got) != fixtureTwoTargets {
		t.Fatalf("file changed:\n%s", got)
	}
}

// fixtureInlineToken defines the token as an inline table rather than a
// [targets.token] header: the splicer cannot see it as a subtable, so a
// clear would silently leave it and an append would duplicate the key.
// Both guards must refuse.
const fixtureInlineToken = "[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\ntoken = { id = \"root@pam!x\", secret_enc = \"-----BEGIN AGE ENCRYPTED FILE-----\\nAAAA\\n-----END AGE ENCRYPTED FILE-----\\n\" }\n"

// CT3: the guard refuses a clear that would not actually remove the token,
// and the file is untouched.
func TestClearTokenAuth_GuardRefusesATokenItCannotRemove(t *testing.T) {
	path := writeTempRoster(t, fixtureInlineToken)
	err := ClearTokenAuth(path, "qa-pve-01")
	if err == nil || !strings.Contains(err.Error(), "safety check failed") {
		t.Fatalf("want a safety-check refusal, got %v", err)
	}
	if got := readFile(t, path); string(got) != fixtureInlineToken {
		t.Fatalf("file changed on a refused clear:\n%s", got)
	}
}

// CT4: a duplicated target block (the ambiguity findUniqueTargetBlock
// refuses) is an error, and the file is byte-identical.
func TestClearTokenAuth_DuplicateTargetBlockRefused(t *testing.T) {
	withTestWorkFactor(t)
	dup := fixtureTokenAndSSH(t) + "\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\n"
	path := writeTempRoster(t, dup)
	if err := ClearTokenAuth(path, "qa-pve-01"); err == nil {
		t.Fatal("want an error for a duplicated target block")
	}
	if got := readFile(t, path); string(got) != dup {
		t.Fatal("file changed on a refused clear")
	}
}

// CT5: a healthy roster passes and is byte-identical afterwards; a
// duplicated block and a guard-violating layout both fail.
func TestDryRunTokenWrite_HealthyPassesWritesNothingAndBadLayoutsFail(t *testing.T) {
	withTestWorkFactor(t)
	content := fixtureTokenAndSSH(t)
	path := writeTempRoster(t, content)
	if err := DryRunTokenWrite(path, "qa-pve-01"); err != nil {
		t.Fatalf("healthy roster: %v", err)
	}
	if got := readFile(t, path); string(got) != content {
		t.Fatal("the dry run changed the roster")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "dryrun") {
			t.Fatalf("probe file left behind: %s", e.Name())
		}
	}

	dup := writeTempRoster(t, content+"\n[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\n")
	if err := DryRunTokenWrite(dup, "qa-pve-01"); err == nil {
		t.Fatal("duplicated block: want an error")
	}
	inline := writeTempRoster(t, fixtureInlineToken)
	if err := DryRunTokenWrite(inline, "qa-pve-01"); err == nil {
		t.Fatal("inline token table: want an error")
	}
}

// fixtureNoTrailingNewline has the token subtable last, and the target
// block (so the file) ending after a comment line with NO trailing
// newline: the case where the append path's leading-newline logic runs
// only after a clear.
func fixtureNoTrailingNewline(t *testing.T) string {
	t.Helper()
	return "[[targets]]\nid = \"qa-pve-01\"\nhost = \"h1\"\nnode = \"qa-pve-01\"\n\n" +
		"[targets.token]\nid = \"root@pam!old\"\nsecret_enc = '''\n" + sampleArmored(t, "tok", "p") + "'''\n# trailing comment, no newline"
}

// CT5b: each rehearsal's composed bytes equal what the REAL writers produce
// on a copy of the file: ClearTokenAuth, then the same splice core
// WriteTokenAuth uses (spliceSubtable) with the same placeholder fields.
// WriteTokenAuth itself cannot be compared byte for byte (it encrypts with a
// fresh random age key each call), so a real WriteTokenAuth is compared
// structurally, for both sequences: identical outside the secret_enc
// literal.
func TestDryRunTokenWrite_RehearsalsMatchTheRealWriters(t *testing.T) {
	withTestWorkFactor(t)
	for name, content := range map[string]string{
		"no trailing newline": fixtureNoTrailingNewline(t),
		"token and ssh":       fixtureTokenAndSSH(t),
		"no token yet":        fixtureTwoTargets,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTempRoster(t, content)
			composed := map[string][]byte{}
			dryRunCompose = func(stage string, b []byte) { composed[stage] = append([]byte(nil), b...) }
			defer func() { dryRunCompose = nil }()
			if err := DryRunTokenWrite(path, "qa-pve-01"); err != nil {
				t.Fatalf("DryRunTokenWrite: %v", err)
			}

			alone := copyRoster(t, path)
			if err := spliceSubtable(alone, "qa-pve-01", "token", dryRunPlaceholderFields()); err != nil {
				t.Fatalf("real write-alone: %v", err)
			}
			if got := readFile(t, alone); !bytes.Equal(got, composed["write-alone"]) {
				t.Fatalf("write-alone rehearsal differs from the real writer.\nrehearsed:\n%q\nreal:\n%q", composed["write-alone"], got)
			}

			ctw := copyRoster(t, path)
			if err := ClearTokenAuth(ctw, "qa-pve-01"); err != nil {
				t.Fatalf("real clear: %v", err)
			}
			if err := spliceSubtable(ctw, "qa-pve-01", "token", dryRunPlaceholderFields()); err != nil {
				t.Fatalf("real write after clear: %v", err)
			}
			if got := readFile(t, ctw); !bytes.Equal(got, composed["clear-then-write"]) {
				t.Fatalf("clear-then-write rehearsal differs from the real writers.\nrehearsed:\n%q\nreal:\n%q", composed["clear-then-write"], got)
			}

			// The real WriteTokenAuth alone, on an uncleared copy: identical
			// to the write-alone rehearsal outside the secret_enc literal.
			realAlone := copyRoster(t, path)
			if err := WriteTokenAuth(realAlone, "qa-pve-01", TokenWrite{TokenID: dryRunPlaceholderTokenID, SecretPlaintext: []byte("s")}, "p"); err != nil {
				t.Fatal(err)
			}
			aRealPre, aRealPost := splitAtSecretLiteral(t, string(readFile(t, realAlone)))
			aRehPre, aRehPost := splitAtSecretLiteral(t, string(composed["write-alone"]))
			if aRealPre != aRehPre || aRealPost != aRehPost {
				t.Fatalf("the real WriteTokenAuth differs from the write-alone rehearsal outside secret_enc.\nreal:\n%q%q\nrehearsed:\n%q%q", aRealPre, aRealPost, aRehPre, aRehPost)
			}

			// The real WriteTokenAuth, after a real clear: identical to the
			// rehearsal outside the secret_enc literal.
			realPath := copyRoster(t, path)
			if err := ClearTokenAuth(realPath, "qa-pve-01"); err != nil {
				t.Fatal(err)
			}
			if err := WriteTokenAuth(realPath, "qa-pve-01", TokenWrite{TokenID: dryRunPlaceholderTokenID, SecretPlaintext: []byte("s")}, "p"); err != nil {
				t.Fatal(err)
			}
			rp, rs := splitAtSecretLiteral(t, string(readFile(t, realPath)))
			cp, cs := splitAtSecretLiteral(t, string(composed["clear-then-write"]))
			if rp != cp || rs != cs {
				t.Fatalf("the real WriteTokenAuth differs from the rehearsal outside secret_enc.\nreal:\n%q%q\nrehearsed:\n%q%q", rp, rs, cp, cs)
			}
		})
	}
}

// splitAtSecretLiteral returns the text before the token's secret_enc
// literal opens, and the text after it closes.
func splitAtSecretLiteral(t *testing.T, s string) (string, string) {
	t.Helper()
	open := strings.LastIndex(s, "secret_enc = '''\n")
	if open < 0 {
		t.Fatalf("no secret_enc literal in:\n%s", s)
	}
	body := open + len("secret_enc = '''\n")
	end := strings.Index(s[body:], "'''")
	if end < 0 {
		t.Fatalf("unterminated secret_enc literal")
	}
	return s[:body], s[body+end:]
}

// CT5c: an unwritable roster directory fails the dry run (the CreateTemp
// probe). Root ignores mode bits, so this cannot hold under uid 0;
// bootstrap's R6g-b covers the probe's wiring for every uid.
func TestDryRunTokenWrite_UnwritableDirectoryFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory mode bits; R6g-b (internal/bootstrap) is the uid-independent coverage")
	}
	path := writeTempRoster(t, fixtureTwoTargets)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	err := DryRunTokenWrite(path, "qa-pve-01")
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("want a not-writable error, got %v", err)
	}
}

// CT5d: both rehearsals run on every call, in order.
func TestDryRunTokenWrite_RunsBothRehearsalsInOrder(t *testing.T) {
	path := writeTempRoster(t, fixtureTwoTargets)
	var stages []string
	dryRunCompose = func(stage string, _ []byte) { stages = append(stages, stage) }
	defer func() { dryRunCompose = nil }()
	if err := DryRunTokenWrite(path, "qa-pve-01"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stages, ",") != "write-alone,clear-then-write" {
		t.Fatalf("rehearsals = %v, want [write-alone clear-then-write]", stages)
	}
}

// The placeholder has a real age armor's framing and line profile, so the
// rehearsal renders through the same multi-line literal path.
func TestDryRunPlaceholder_HasArmorShape(t *testing.T) {
	withTestWorkFactor(t)
	realLines := strings.Split(strings.TrimSuffix(sampleArmored(t, "a token secret of typical length", "p"), "\n"), "\n")
	phLines := strings.Split(strings.TrimSuffix(dryRunPlaceholderSecretEnc, "\n"), "\n")
	if phLines[0] != realLines[0] || phLines[len(phLines)-1] != realLines[len(realLines)-1] {
		t.Fatalf("armor framing differs: placeholder %q..%q, real %q..%q", phLines[0], phLines[len(phLines)-1], realLines[0], realLines[len(realLines)-1])
	}
	for i, l := range phLines[1 : len(phLines)-2] {
		if len(l) != 64 {
			t.Fatalf("placeholder body line %d is %d columns, want 64", i+1, len(l))
		}
	}
	if last := phLines[len(phLines)-2]; len(last) == 0 || len(last) > 64 {
		t.Fatalf("placeholder last body line has %d columns", len(last))
	}
	if strings.Contains(dryRunPlaceholderSecretEnc, "'''") {
		t.Fatal("placeholder contains ''' and would break the literal render")
	}
}
