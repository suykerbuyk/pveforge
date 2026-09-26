package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

const testTLSPin = "sha256//AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="

func writeValidateRoster(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const mixedPinRoster = `[[targets]]
id = "pinned"
host = "h1"
node = "n1"
insecure_tls = true

[targets.tls]
spki_sha256 = "` + testTLSPin + `"

[[targets]]
id = "unpinned"
host = "h2"
node = "n2"
insecure_tls = true

[[targets]]
id = "ca-verified"
host = "h3"
node = "n3"
`

func TestRosterValidate_ListsPinsAndChangesNothingElse(t *testing.T) {
	rp := writeValidateRoster(t, mixedPinRoster)
	code, out, stderr := runRootArgs("roster", "validate", rp)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := rp + ": valid, 3 target(s)\n" +
		"  - pinned (h1, node=n1): bootstrap pending, tls pinned\n" +
		"  - unpinned (h2, node=n2): bootstrap pending\n" +
		"  - ca-verified (h3, node=n3): bootstrap pending\n"
	if out != want {
		t.Fatalf("stdout =\n%s\nwant\n%s", out, want)
	}
}

func TestRosterValidate_RequireTLSPins(t *testing.T) {
	rp := writeValidateRoster(t, mixedPinRoster)
	code, out, stderr := runRootArgs("roster", "validate", "--require-tls-pins", rp)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (stdout %q, stderr %q)", code, out, stderr)
	}
	if !strings.Contains(stderr, `1 insecure_tls target(s) hold no [targets.tls] pin: "unpinned"`) {
		t.Fatalf("stderr %q does not name exactly the unpinned insecure_tls target", stderr)
	}
	// Inverted from T1a (which had no pin-tls): it names the command that
	// pins each, and nothing that would re-pin one.
	if !strings.Contains(stderr, "pveforge roster pin-tls <target>") {
		t.Errorf("stderr %q does not name roster pin-tls", stderr)
	}
	for _, not := range []string{`"pinned"`, "ca-verified", "--repin", "--reprovisioned"} {
		// The CA-verified target is exempt (N6).
		if strings.Contains(stderr, not) {
			t.Errorf("stderr %q contains %q", stderr, not)
		}
	}
	if !strings.HasPrefix(out, rp+": valid, 3 target(s)\n") {
		t.Errorf("the listing is not printed first: %q", out)
	}

	all := writeValidateRoster(t, strings.Replace(mixedPinRoster, "id = \"unpinned\"\nhost = \"h2\"\nnode = \"n2\"\ninsecure_tls = true\n",
		"id = \"unpinned\"\nhost = \"h2\"\nnode = \"n2\"\ninsecure_tls = true\n\n[targets.tls]\nspki_sha256 = \""+testTLSPin+"\"\n", 1))
	if code, _, stderr := runRootArgs("roster", "validate", "--require-tls-pins", all); code != 0 {
		t.Fatalf("every insecure_tls target pinned: exit %d, stderr %q", code, stderr)
	}
	// Without the flag the same roster is valid: nothing requires a pin yet.
	if code, _, stderr := runRootArgs("roster", "validate", rp); code != 0 {
		t.Fatalf("without --require-tls-pins: exit %d, stderr %q", code, stderr)
	}
}

// Each id is quoted, so ids are told apart however they are spelled (an id
// may hold a comma or a space).
func TestRosterValidate_RequireTLSPins_QuotesEachID(t *testing.T) {
	rp := writeValidateRoster(t, `[[targets]]
id = "a, b"
host = "h1"
node = "n1"
insecure_tls = true

[[targets]]
id = "c"
host = "h2"
node = "n2"
insecure_tls = true
`)
	code, _, stderr := runRootArgs("roster", "validate", "--require-tls-pins", rp)
	if code != 1 || !strings.Contains(stderr, `2 insecure_tls target(s) hold no [targets.tls] pin: "a, b", "c"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestRosterValidate_RefusesAMalformedPin(t *testing.T) {
	rp := writeValidateRoster(t, strings.Replace(mixedPinRoster, testTLSPin, "sha256//short", 1))
	code, _, stderr := runRootArgs("roster", "validate", rp)
	if code == 0 || !strings.Contains(stderr, "not a TLS pin") {
		t.Fatalf("exit %d, stderr %q; want a refusal naming the malformed pin", code, stderr)
	}
}

// T2: validate shows how each stored SSH pin was vouched for.
func TestRosterValidate_ShowsTheHostKeySource(t *testing.T) {
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	rp := writeValidateRoster(t, "[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n")
	if err := roster.WriteSSHAuth(rp, "a", roster.SSHWrite{User: "root", PublicKey: "k", HostKeyFingerprint: "SHA256:x", PrivateKeyPlaintext: []byte("k"), HostKeySource: "ssh-tofu"}, roster.NewPassphrase("p")); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runRootArgs("roster", "validate", rp)
	if code != 0 || !strings.Contains(out, "  - a (h, node=n): ssh configured, ssh host key ssh-tofu\n") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
}
