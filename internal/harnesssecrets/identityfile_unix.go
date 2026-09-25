//go:build unix

package harnesssecrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openRegular opens path for reading without following a symlink and
// without blocking (a FIFO or a device would otherwise block the open
// itself), then checks the OPENED file with fstat, so nothing can be
// swapped in between: it must be a regular file. Every file this tool reads
// — the identity, secrets.age and recipients.txt — goes through it, so a
// committed symlink to /proc/self/environ (git stores symlinks) is refused
// before a byte is read.
func openRegular(path string) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("%s is a symlink; it must be the file itself", path)
		}
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	return f, fi, nil
}

// readIdentityFile reads an identity file through openRegular, and also
// requires it to be owned by the effective user with no group or other
// permission bits.
func readIdentityFile(path string) ([]byte, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("has mode %#o; it must give group and others nothing (chmod 600)", perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != geteuid() {
		return nil, errors.New("is not owned by the current user")
	}
	return readAll(f)
}
