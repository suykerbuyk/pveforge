package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The two mismatch wordings (the T2 review): a stored pin's offers the
// reprovision; an expected (operator-given) key's says to check the value
// against the console, and never calls it "the roster's". Both label the
// presented key and point to the console, and neither puts it after a flag.
func TestHostKeyMismatchWording(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	presented := ssh.FingerprintSHA256(key)
	const want = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	stored, _ := PinnedHostKeyCallback(want)
	given, _ := ExpectedHostKeyCallback(want)
	sm := stored("h", nil, key).Error()
	gm := given("h", nil, key).Error()
	for name, m := range map[string]string{"stored": sm, "given": gm} {
		if !strings.Contains(m, "Do NOT pin the presented key") || !strings.Contains(m, ConsoleHostKeyCommand) {
			t.Errorf("%s: lacks the do-not-pin label or the console pointer: %s", name, m)
		}
		if i := strings.Index(m, "--host-key-fingerprint"); i >= 0 && strings.Contains(m[i:], presented) {
			t.Errorf("%s: the presented key follows --host-key-fingerprint: %s", name, m)
		}
	}
	if !strings.Contains(sm, "the roster pins "+want) || !strings.Contains(sm, "--reprovisioned") {
		t.Errorf("stored: %s", sm)
	}
	if strings.Contains(gm, "the roster pins") || strings.Contains(gm, "--reprovisioned") || !strings.Contains(gm, "expected "+want) {
		t.Errorf("given: %s", gm)
	}
}
