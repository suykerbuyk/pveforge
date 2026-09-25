//go:build !unix

package harnesssecrets

import (
	"errors"
	"io/fs"
	"os"
)

// The harness runs on Linux only; elsewhere no file can be opened without
// following a symlink, so every file is refused.
func openRegular(string) (*os.File, fs.FileInfo, error) {
	return nil, nil, errors.New("the harness secrets tool runs on unix only")
}

func readIdentityFile(string) ([]byte, error) {
	return nil, errors.New("identity files are supported on unix only")
}
