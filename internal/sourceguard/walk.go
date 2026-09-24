package sourceguard

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// walkNonTest calls fn for every file under root that is part of the
// module's non-test source, with its slash-separated path relative to root:
// every file except a Go test file (_test.go), in every directory except
// those skippedDirNames names (testdata, .git, vendor) — unless that
// directory is root itself, so a fixture under testdata can still be walked
// by passing it as root.
//
// It is the ONE definition of "production source" in this package:
// NonTestReferences (which parses the .go files it is handed) and
// DirectiveEvasions (which reads every file as bytes) both walk through it,
// so the two can never disagree about which files they cover. It passes
// files of every extension; each caller picks what it reads.
func walkNonTest(root string, fn func(path, rel string) error) error {
	root = filepath.Clean(root)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skippedDirNames[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		return fn(path, filepath.ToSlash(rel))
	})
}
