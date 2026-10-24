package sshexec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// An install that failed before its script ran on the node (a malformed
// pin, a host key that is not the pin, a refused password) matches
// ErrNoCommandSent: no key can have been appended, and bootstrap says
// nothing of one. An install whose script ran and failed does not match it:
// whether the key was appended is unknown, and bootstrap reports the key
// with the manual removal command (T2k U1).
func TestInstallPubkeyViaPassword_NothingSentIsTold(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "correct-horse")
	fs.HandleExec(func(string) (string, string, int) { return "", "Read-only file system", 1 })
	fs.Start()
	ctx := context.Background()
	line := "ssh-ed25519 AAAAtest testkey"
	for name, tc := range map[string]struct {
		password, pin string
	}{
		"a malformed pin":    {"correct-horse", "not-a-fingerprint"},
		"another host key":   {"correct-horse", "SHA256:" + strings.Repeat("A", 43)},
		"a refused password": {"wrong", fs.HostKeyFingerprint()},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := InstallPubkeyViaPassword(ctx, fs.Addr(), "root", tc.password, line, tc.pin)
			if err == nil || !errors.Is(err, ErrNoCommandSent) {
				t.Fatalf("err = %v; want it to match ErrNoCommandSent", err)
			}
		})
	}
	_, err := InstallPubkeyViaPassword(ctx, fs.Addr(), "root", "correct-horse", line, fs.HostKeyFingerprint())
	if err == nil || errors.Is(err, ErrNoCommandSent) || !strings.Contains(err.Error(), "exited 1") {
		t.Fatalf("a script that ran and failed: err = %v; want its exit, not ErrNoCommandSent", err)
	}
}
