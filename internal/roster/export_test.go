package roster

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// The export opt-in (Target.Export) is read and validated at load, and
// written by nothing but a hand edit: AppendTarget refuses it, and every
// writer's safety check refuses a write that would change it on any target.

const fixtureExport = `[[targets]]
id = "qa-exp"
host = "qa-exp.example.com"
node = "qa-exp"
export = "token"

[[targets]]
id = "qa-other"
host = "qa-other.example.com"
node = "qa-other"
export = "token"
`

func TestDecode_Export(t *testing.T) {
	cases := []struct {
		name, line, want string
		wantErr          bool
	}{
		{"absent", "", "", false},
		{"token", `export = "token"`, ExportToken, false},
		{"ssh is refused", `export = "ssh"`, "", true},
		{"empty string loads as absent", `export = ""`, "", false},
		{"case matters", `export = "Token"`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Decode([]byte("[[targets]]\nid = \"a\"\nhost = \"h\"\nnode = \"n\"\n" + tc.line + "\n"))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), `the only value is "token"`) {
					t.Fatalf("Decode = %v, want the export refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := r.Targets[0].Export; got != tc.want {
				t.Errorf("Export = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAppendTarget_RefusesExport(t *testing.T) {
	withTestWorkFactor(t)
	path := writeTempRoster(t, fixtureTwoTargets)
	err := AppendTarget(path, Target{ID: "qa-pve-03", Host: "h", Node: "n", Export: ExportToken})
	if err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("AppendTarget = %v, want a refusal", err)
	}
	if got, _ := os.ReadFile(path); string(got) != fixtureTwoTargets {
		t.Errorf("roster changed:\n%s", got)
	}
}

// TestWriters_PreserveExport: the token and SSH writers and the field
// updater leave every target's export as the operator set it.
func TestWriters_PreserveExport(t *testing.T) {
	withTestWorkFactor(t)
	writers := map[string]func(path string) error{
		"WriteTokenAuth": func(path string) error {
			return WriteTokenAuth(path, "qa-exp", TokenWrite{TokenID: "ops@pve!ci", SecretPlaintext: []byte("s")}, NewPassphrase("pw"))
		},
		"WriteSSHAuth": func(path string) error {
			return WriteSSHAuth(path, "qa-exp", SSHWrite{User: "root", PublicKey: "ssh-ed25519 AAAA", PrivateKeyPlaintext: []byte("k")}, NewPassphrase("pw"))
		},
		"UpdateTargetFields": func(path string) error {
			return UpdateTargetFields(path, "qa-exp", TargetMeta{Host: "new.example.com", Node: "qa-exp"})
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			path := writeTempRoster(t, fixtureExport)
			if err := write(path); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			r, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"qa-exp", "qa-other"} {
				if got := r.Find(id).Export; got != ExportToken {
					t.Errorf("%s: export = %q after %s, want %q", id, got, name, ExportToken)
				}
			}
		})
	}
}

// TestSafetyChecks_RefuseAnExportChange: each writer's safety net refuses a
// spliced result in which export changed, on the target being written and
// on any other.
func TestSafetyChecks_RefuseAnExportChange(t *testing.T) {
	withTestWorkFactor(t)
	dropOn := func(id string) []byte {
		i := strings.Index(fixtureExport, `id = "`+id+`"`)
		j := i + strings.Index(fixtureExport[i:], "export = \"token\"\n")
		return []byte(fixtureExport[:j] + fixtureExport[j+len("export = \"token\"\n"):])
	}
	old := []byte(fixtureExport)
	cases := map[string]error{
		"subtable write, own target":   verifyOnlyIntendedChange(old, dropOn("qa-exp"), "qa-exp", "token"),
		"subtable write, other target": verifyOnlyIntendedChange(old, dropOn("qa-other"), "qa-exp", "token"),
		"field update, own target":     verifyOnlyTargetFieldsChanged(old, dropOn("qa-exp"), "qa-exp"),
		"field update, other target":   verifyOnlyTargetFieldsChanged(old, dropOn("qa-other"), "qa-exp"),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: an export change passed the safety check", name)
		}
	}
	// Anti-vacuity: the dropped line really was the only difference.
	if bytes.Equal(dropOn("qa-exp"), old) || len(dropOn("qa-exp")) != len(old)-len("export = \"token\"\n") {
		t.Fatal("the fixture edit did not drop exactly one export line")
	}
	appended := append(append([]byte{}, old...), "\n[[targets]]\nid = \"qa-new\"\nhost = \"h\"\nnode = \"n\"\nexport = \"token\"\n"...)
	if err := verifyAppendOnly(old, appended, "qa-new"); err == nil {
		t.Error("append check: an appended target carrying export passed")
	}
	plain := append(append([]byte{}, old...), "\n[[targets]]\nid = \"qa-new\"\nhost = \"h\"\nnode = \"n\"\n"...)
	if err := verifyAppendOnly(old, plain, "qa-new"); err != nil {
		t.Fatalf("append check: a clean append failed: %v", err)
	}
	if err := verifyAppendOnly(dropOn("qa-other"), plain, "qa-new"); err == nil {
		t.Error("append check: an existing target whose export changed passed")
	}
}

func TestTarget_TokenSecret(t *testing.T) {
	withTestWorkFactor(t)
	// The SSH key is sealed under another passphrase, so a TokenSecret that
	// also decrypted it would fail here: it must never touch it.
	tgt := &Target{
		ID:    "qa-exp",
		Token: &TokenAuth{ID: "ops@pve!ci", SecretEnc: sampleArmored(t, "the-secret", "pw")},
		SSH:   &SSHAuth{User: "root", PrivateKeyEnc: sampleArmored(t, "ssh-key", "not-pw")},
	}
	got, err := tgt.TokenSecret("pw")
	if err != nil || string(got) != "the-secret" {
		t.Fatalf("TokenSecret = %q, %v", got, err)
	}
	_, err = tgt.TokenSecret("wrong")
	if !errors.Is(err, ErrWrongPassphrase) || !strings.Contains(err.Error(), PassphraseEnvVar) {
		t.Errorf("wrong passphrase: %v, want ErrWrongPassphrase naming %s", err, PassphraseEnvVar)
	}
	if _, err := (&Target{ID: "bare"}).TokenSecret("pw"); err == nil {
		t.Error("a target with no token returned a secret")
	}
}
