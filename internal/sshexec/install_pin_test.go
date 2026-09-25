package sshexec

import (
	"context"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// A pinned install: the host key is checked before authentication, so a
// host presenting another key is refused before the password is sent; the
// right pin connects and is what the result reports.
func TestInstallPubkeyViaPassword_Pinned(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "correct-horse")
	fs.HandleExec(func(string) (string, string, int) { return "added\n", "", 0 })
	fs.Start()
	ctx := context.Background()
	wrong := "SHA256:" + strings.Repeat("A", 43)
	if _, err := InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "correct-horse", "ssh-ed25519 AAAAtest testkey", wrong); err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("a wrong pin: %v; want a host key mismatch", err)
	}
	if n := fs.PasswordAttempts(); n != 0 {
		t.Fatalf("the password was sent %d times to a host whose key did not match", n)
	}
	res, err := InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "correct-horse", "ssh-ed25519 AAAAtest testkey", fs.HostKeyFingerprint())
	if err != nil || res.HostKeyFingerprint != fs.HostKeyFingerprint() {
		t.Fatalf("the right pin: %+v, %v", res, err)
	}
	if fs.PasswordAttempts() != 1 {
		t.Errorf("password attempts %d, want 1", fs.PasswordAttempts())
	}
}

func TestCheckFingerprint(t *testing.T) {
	good := "SHA256:" + strings.Repeat("a", 42) + "Z"
	if err := CheckFingerprint(good); err != nil {
		t.Errorf("%q: %v", good, err)
	}
	for _, bad := range []string{
		"", "SHA256:abc", "sha256:" + strings.Repeat("a", 43), "SHA256:" + strings.Repeat("a", 42) + "=",
		"SHA256:" + strings.Repeat("a", 44), "MD5:12:34:56", " " + good, good + "\n",
		"256 " + good + " root@host (ED25519)", "SHA256:" + strings.Repeat("a", 42) + "-",
	} {
		if err := CheckFingerprint(bad); err == nil || !strings.Contains(err.Error(), "as ssh-keygen -l -E sha256 prints it") {
			t.Errorf("%q: %v; want refused", bad, err)
		}
	}
}
