package sourceguard

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// walkNonTest calls fn for every file under root that is part of the
// module's non-test source, with its slash-separated path relative to root:
// every file except a Go test file (_test.go), in every directory except
//
//   - those skippedDirNames names (testdata, .git, vendor), at any depth;
//   - a NESTED MODULE: a directory other than root that holds its own go.mod
//     file, and that sits under a top-level dot-directory of root (a unit
//     worktree, .wt/<unit>, is exactly this). Such a tree is a separate
//     module: the main module cannot import it without a replace directive
//     (refused by the module guard) or a go.work (GOWORK=off in every gate
//     command), so none of it is compiled into the binary. Walking it from
//     a main checkout made every module-root guard RED on another unit's
//     copy of the same sources.
//
// — unless that directory is root itself, so a fixture under testdata (or a
// worktree) can still be walked by passing it as root.
//
// What it deliberately does NOT skip, because each is compilable source
// (go build imports a dot-named package directory, and a directory holding a
// .git FILE, a submodule, is still part of the module): a dot-named directory
// in general — the top-level .build included: it is ignored agent scratch,
// but a `.build/evil` package imported by cmd/pveforge builds, so skipping it
// would hide that package and any //go:linkname in it from every guard — a
// directory named .wt with no go.mod of its own, a directory named build, and
// a directory with a .git file. A nested go.mod that is NOT
// under a top-level dot-directory is an ERROR, not a skip: an in-tree nested
// module is somewhere source could hide from every guard if the replace or
// go.work rules ever loosened, so it must be looked at, not silently passed.
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
			if path == root {
				return nil
			}
			if skippedDirNames[d.Name()] {
				return filepath.SkipDir
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			rel = filepath.ToSlash(rel)
			if st, serr := os.Lstat(filepath.Join(path, "go.mod")); serr == nil && st.Mode().IsRegular() {
				if top, _, _ := strings.Cut(rel, "/"); strings.HasPrefix(top, ".") {
					return filepath.SkipDir
				}
				return fmt.Errorf("sourceguard: %s holds its own go.mod, a nested module that is not under a top-level dot-directory (a worktree such as .wt/<unit>) — a guard will not skip it silently; move it, remove it, or walk it as its own Root", rel)
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
