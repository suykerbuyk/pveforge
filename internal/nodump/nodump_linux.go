//go:build linux

// Package nodump clears a process's dumpable flag before it holds a
// decrypted secret. The platform split lives here, in a package of its own,
// so cmd/pveforge keeps one file set that its source guards type-check
// whole.
package nodump

import (
	"fmt"
	"syscall"
)

// Set clears the process's dumpable flag: no core dump, and no ptrace
// attach or /proc/<pid>/environ and mem read by another process of the same
// user, for the rest of the process's life. execve resets it for the
// program exec'd, which is the point: only this process, while it holds the
// decrypted secret, is covered.
func Set() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", errno)
	}
	return nil
}
