package sourceguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The landing gate, hack/gate/clean-export.sh, is this package's subject here.
//
// Why these tests run the SCRIPT and never re-implement its recipe: the gate's
// job is to go red when the script is wrong. A Go copy of
// read-tree/add/write-tree would pin git's behaviour, not ours, and would stay
// green if someone deleted read-tree from the script or pointed its
// git archive at git write-tree. That is this project's own recurring failure
// -- the check and the thing checked being the same object -- with the sign
// flipped, so every test below execs the real file through its --export-only
// seam, which does everything except run `make`.
//
// The negative control is TestCleanExport_BareWriteTreeMutantIsKilled: it
// substitutes the documented-but-false `git archive $(git write-tree)` form
// into a copy of the script and requires the script's own refusal to fire. A
// control never observed failing has not been shown to work.

const cleanExportScript = "../../hack/gate/clean-export.sh"

// the two refusals the tests below distinguish between, by their message.
const (
	refuseExportsHEAD = "the exported tree IS HEAD's tree"
	refuseDivergence  = "something is staged and the worktree does not match it"
	refuseOmission    = "the worktree and the export disagree on"
)

// gitEnv is a parent environment with every inherited git override removed --
// GIT_INDEX_FILE above all, which is exactly what this gate juggles -- and a
// fixed identity, so a developer's or CI's global config cannot change what
// these fixtures measure.
func gitEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "GIT_INDEX_FILE="),
			strings.HasPrefix(kv, "GIT_DIR="),
			strings.HasPrefix(kv, "GIT_WORK_TREE="),
			strings.HasPrefix(kv, "GIT_CONFIG_GLOBAL="),
			strings.HasPrefix(kv, "GIT_CONFIG_SYSTEM="):
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=gate", "GIT_AUTHOR_EMAIL=gate@invalid",
		"GIT_COMMITTER_NAME=gate", "GIT_COMMITTER_EMAIL=gate@invalid",
	)
}

// git runs one git command in dir and fails the test on a non-zero status.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fixture is a throwaway repository with ONE commit. Its only top-level entry
// is "internal", which the script's literal top-level allowlist already
// contains -- a fixture that added a name of its own would be refused by the
// allowlist and would say nothing about the refusal under test.
//
// It returns the repository and an export directory that is a SIBLING of it:
// an export directory inside the work tree would be swept in by git add -A.
func fixture(t *testing.T) (repo, export string) {
	t.Helper()
	root := t.TempDir()
	repo = filepath.Join(root, "repo")
	export = filepath.Join(root, "export")
	for _, d := range []string{filepath.Join(repo, "internal"), export} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git(t, repo, "init", "-q", "-b", "main")
	write(t, repo, "internal/a.txt", "committed\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base")
	return repo, export
}

func write(t *testing.T, repo, rel, content string) {
	t.Helper()
	p := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeExec writes a file that must keep tabs verbatim (a Makefile).
func writeExec(t *testing.T, repo, rel, content string) {
	t.Helper()
	write(t, repo, rel, content)
}

// goFixture is fixture() plus the smallest real Go module, so the script's
// full mode -- which runs `go list ./...` and `make` inside the export -- has
// something to run. No dependencies, so it resolves offline.
func goFixture(t *testing.T) (repo, export string) {
	t.Helper()
	repo, export = fixture(t)
	write(t, repo, "go.mod", "module fixture\n\ngo 1.22\n")
	write(t, repo, "internal/x/x.go", "package x\n\n// F exists so the package is not empty.\nfunc F() int { return 1 }\n")
	write(t, repo, "internal/x/x_test.go", "package x\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"no\")\n\t}\n}\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "go module")
	return repo, export
}

// runGateFull runs the script in its DEFAULT mode, which builds the export
// and then runs the suites inside it.
func runGateFull(t *testing.T, script, repo, export string) (int, string) {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(abs)
	cmd.Dir = repo
	cmd.Env = append(gitEnv(), "TMPDIR="+export)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running %s: %v\n%s", abs, err, out)
		}
	}
	return code, string(out)
}

func append1(t *testing.T, repo, rel, content string) {
	t.Helper()
	p := filepath.Join(repo, filepath.FromSlash(rel))
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// runGate execs the real script (or a copy of it) in --export-only mode and
// returns its exit status and combined output. The script is run as a command,
// not through `bash`, so a copy committed without its executable bit fails
// here rather than in production.
func runGate(t *testing.T, script, repo, export string) (int, string) {
	t.Helper()
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(abs, "--export-only", export)
	cmd.Dir = repo
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running %s: %v\n%s", abs, err, out)
		}
	}
	return code, string(out)
}

func asExitError(err error, dst **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*dst = ee
	}
	return ok
}

func treeOf(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "clean-export: TREE="); ok {
			return rest
		}
	}
	t.Fatalf("the gate printed no TREE line:\n%s", out)
	return ""
}

// TestCleanExport_CatchesAnUnstagedChange is the positive half of the control:
// the production script, on a worktree whose change was never staged, must
// export a tree that CARRIES the change and is not HEAD's.
func TestCleanExport_CatchesAnUnstagedChange(t *testing.T) {
	repo, export := fixture(t)
	append1(t, repo, "internal/a.txt", "unstaged modification\n")
	write(t, repo, "internal/b.txt", "brand new, never staged\n")

	code, out := runGate(t, cleanExportScript, repo, export)
	if code != 0 {
		t.Fatalf("the gate refused an ordinary unstaged worktree (exit %d); this is the case the gate exists for:\n%s", code, out)
	}
	tree := treeOf(t, out)
	if head := git(t, repo, "rev-parse", "HEAD^{tree}"); tree == head {
		t.Errorf("the exported tree is HEAD's tree %s: the gate is running on HEAD, not on the change", head)
	}
	b, err := os.ReadFile(filepath.Join(export, "internal", "b.txt"))
	if err != nil {
		t.Errorf("the new file is absent from the export: %v", err)
	} else if !strings.Contains(string(b), "brand new") {
		t.Errorf("internal/b.txt in the export is %q", b)
	}
	a, err := os.ReadFile(filepath.Join(export, "internal", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(a), "unstaged modification") {
		t.Errorf("the export does not carry the unstaged modification: %q", a)
	}
}

// TestCleanExport_BareWriteTreeMutantIsKilled is the negative control.
//
// It replaces the script's one throwaway-index block with the documented
// `git write-tree` form -- the defect this unit closes -- and requires the
// script's OWN refusal to fire. The assertion is the non-zero exit, not a tree
// hash: on a dirty worktree the bare form produces HEAD's tree and step 4a
// refuses BEFORE printing anything, so a hash assertion could never be
// observed. The mutant keeps step 4a; a copy with the refusal removed would be
// a script the production path does not run.
func TestCleanExport_BareWriteTreeMutantIsKilled(t *testing.T) {
	src, err := os.ReadFile(cleanExportScript)
	if err != nil {
		t.Fatal(err)
	}
	mutant, err := mutateToBareWriteTree(string(src))
	if err != nil {
		t.Fatalf("%v -- the markers the mutation keys on are gone from %s; restore them or this control is vacuous", err, cleanExportScript)
	}
	if mutant == string(src) {
		t.Fatal("the mutation changed nothing")
	}
	if !strings.Contains(mutant, refuseExportsHEAD) {
		t.Fatal("the mutant lost step 4a's refusal; it would not be the production script")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "clean-export-mutant.sh")
	if err := os.WriteFile(path, []byte(mutant), 0o755); err != nil {
		t.Fatal(err)
	}
	// A mutant that does not parse is not a killed mutant.
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("the mutant does not parse, so it proves nothing: %v\n%s", err, out)
	}

	repo, export := fixture(t)
	append1(t, repo, "internal/a.txt", "unstaged modification\n")
	write(t, repo, "internal/b.txt", "brand new, never staged\n")

	code, out := runGate(t, path, repo, export)
	if code == 0 {
		t.Fatalf("the bare git write-tree form PASSED the gate (exit 0): the refusal does not fire and the whole gate is vacuous\n%s", out)
	}
	if !strings.Contains(out, refuseExportsHEAD) {
		t.Errorf("the mutant was refused (exit %d) but not by step 4a; the gate may be failing for an unrelated reason:\n%s", code, out)
	}
	if strings.Contains(out, "clean-export: TREE=") {
		t.Errorf("the mutant printed a TREE line; the refusal is supposed to come first:\n%s", out)
	}
}

// mutateToBareWriteTree replaces the single marked throwaway-index block --
// the one recipe, which both of the script's modes call -- with the bare form.
func mutateToBareWriteTree(src string) (string, error) {
	const (
		begin = ">>> THROWAWAY-INDEX TREE"
		end   = "<<< THROWAWAY-INDEX TREE <<<"
	)
	i := strings.Index(src, begin)
	if i < 0 {
		return "", fmt.Errorf("begin marker %q not found", begin)
	}
	j := strings.Index(src, end)
	if j < 0 || j < i {
		return "", fmt.Errorf("end marker %q not found after the begin marker", end)
	}
	// widen to whole lines
	start := strings.LastIndex(src[:i], "\n") + 1
	stop := strings.Index(src[j:], "\n")
	if stop < 0 {
		return "", fmt.Errorf("the end marker is not on a line of its own")
	}
	stop += j + 1
	return src[:start] + "\tTREE=$(git write-tree)\n" + src[stop:], nil
}

// TestCleanExport_RefusesDivergence walks every row of the plan's divergence
// matrix.
//
// The three "proceed" rows are not padding: unstaged-only and untracked-only
// are what killed the first predicate (`TREE != git write-tree`, which refuses
// every worktree an implementor forbidden to stage will ever have), and
// intent-to-add is what killed the second (`index tree != HEAD tree`, which is
// blind to git add -N because git write-tree skips the entry). A table without
// all three cannot fail for the reasons this predicate was designed around.
func TestCleanExport_RefusesDivergence(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, repo string)
		refuse  bool
		wantMsg string
	}{
		{name: "clean", setup: func(*testing.T, string) {}},
		{name: "unstaged-only", setup: func(t *testing.T, r string) {
			append1(t, r, "internal/a.txt", "mod\n")
		}},
		{name: "untracked-only", setup: func(t *testing.T, r string) {
			write(t, r, "internal/new.txt", "new\n")
		}},
		{name: "staged-only", setup: func(t *testing.T, r string) {
			append1(t, r, "internal/a.txt", "mod\n")
			git(t, r, "add", "internal/a.txt")
		}},
		{name: "staged-plus-untracked", refuse: true, wantMsg: refuseDivergence, setup: func(t *testing.T, r string) {
			append1(t, r, "internal/a.txt", "mod\n")
			git(t, r, "add", "internal/a.txt")
			write(t, r, "internal/new.txt", "new\n")
		}},
		{name: "intent-to-add", refuse: true, wantMsg: refuseDivergence, setup: func(t *testing.T, r string) {
			write(t, r, "internal/intent.txt", "intent\n")
			git(t, r, "add", "-N", "internal/intent.txt")
		}},
		{name: "staged-then-modified", refuse: true, wantMsg: refuseDivergence, setup: func(t *testing.T, r string) {
			append1(t, r, "internal/a.txt", "staged\n")
			git(t, r, "add", "internal/a.txt")
			append1(t, r, "internal/a.txt", "and more\n")
		}},
		{name: "index-delete-worktree-restored", refuse: true, wantMsg: refuseExportsHEAD, setup: func(t *testing.T, r string) {
			git(t, r, "rm", "-q", "--cached", "internal/a.txt")
			write(t, r, "internal/a.txt", "committed\n")
		}},
		{name: "staged-plus-intent-to-add", refuse: true, wantMsg: refuseDivergence, setup: func(t *testing.T, r string) {
			append1(t, r, "internal/a.txt", "mod\n")
			git(t, r, "add", "internal/a.txt")
			write(t, r, "internal/intent.txt", "intent\n")
			git(t, r, "add", "-N", "internal/intent.txt")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, export := fixture(t)
			tc.setup(t, repo)
			code, out := runGate(t, cleanExportScript, repo, export)
			switch {
			case tc.refuse && code == 0:
				t.Errorf("the gate PROCEEDED on %s; the export is not the tree git commit would produce:\n%s", tc.name, out)
			case tc.refuse && !strings.Contains(out, tc.wantMsg):
				t.Errorf("the gate refused %s (exit %d) but not with %q:\n%s", tc.name, code, tc.wantMsg, out)
			case !tc.refuse && code != 0:
				t.Errorf("the gate REFUSED %s (exit %d), which must pass:\n%s", tc.name, code, out)
			}
		})
	}
}

// TestCleanExport_RefusesATreeMissingAWorktreeChange is the BLOCKING case
// from the code review, reproduced as a standing test.
//
// `git add -A` can exit 0 and silently omit a path. Under a sparse checkout
// it omits everything outside the cone. A SINGLE out-of-cone edit leaves the
// tree equal to HEAD and step 4a catches it -- which is why the single-edit
// form proves nothing about this defect. The COMPOUND case below is the one
// that got through: one in-cone edit is captured, so the tree differs from
// HEAD and 4a is silent, and nothing is staged, so 4b is silent too. The gate
// used to exit 0 on it, having certified a tree the worktree does not match.
func TestCleanExport_RefusesATreeMissingAWorktreeChange(t *testing.T) {
	repo, export := fixture(t)
	// Two top-level-allowlisted directories so a cone can exclude one.
	write(t, repo, "cmd/in.txt", "committed\n")
	write(t, repo, "internal/out.txt", "committed\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "two dirs")

	git(t, repo, "sparse-checkout", "init", "--cone")
	git(t, repo, "sparse-checkout", "set", "cmd")
	// Anti-vacuity: the out-of-cone file must really be gone from disk, or
	// `git add -A` has nothing to omit. (A `git ls-files -v` field count is
	// NOT a sparseness test -- a non-sparse repo returns fields too, so such
	// a check can never fire. Removed for that reason.)
	if _, err := os.Stat(filepath.Join(repo, "internal", "out.txt")); err == nil {
		t.Fatal("internal/out.txt is still on disk; the cone did not take effect")
	}
	append1(t, repo, "cmd/in.txt", "IN-CONE-EDIT\n")         // captured
	write(t, repo, "internal/out.txt", "OUT-OF-CONE-EDIT\n") // omitted by add -A

	// Both older refusals must be silent here, or the test is passing for
	// the wrong reason and would survive deleting the new check.
	if out := git(t, repo, "diff-index", "--cached", "--name-only", "HEAD"); out != "" {
		t.Fatalf("something is staged (%q); 4b would fire and this would not test 3b", out)
	}

	code, out := runGate(t, cleanExportScript, repo, export)
	if code == 0 {
		t.Fatalf("the gate PASSED on a tree that does not carry internal/out.txt:\n%s", out)
	}
	if !strings.Contains(out, "internal/out.txt") {
		t.Errorf("the gate refused (exit %d) without naming the omitted path:\n%s", code, out)
	}
	if !strings.Contains(out, refuseOmission) {
		t.Errorf("the gate refused (exit %d) but not by the step-3b fidelity check:\n%s", code, out)
	}
}

// TestCleanExport_SingleOutOfConeEditIsCaughtByTheFidelityCheck pins WHICH
// refusal fires on the single-edit sparse case, not merely that one does.
//
// It used to assert only `code != 0`, and its comment claimed it covered step
// 4a. Both refusals apply here -- the tree does equal HEAD, which is 4a's
// precondition -- but step 3b runs first, so the test would have stayed green
// with 4a deleted outright while claiming to be 4a's guard. A test that
// cannot fail for the reason it states is the thing this unit exists to
// remove, so it now asserts the step-3b message and says so.
//
// 4a is not left unguarded: TestCleanExport_BareWriteTreeMutantIsKilled
// asserts 4a's message directly, and the index-delete-worktree-restored row
// of TestCleanExport_RefusesDivergence reaches it by another route.
func TestCleanExport_SingleOutOfConeEditIsCaughtByTheFidelityCheck(t *testing.T) {
	repo, export := fixture(t)
	write(t, repo, "cmd/in.txt", "committed\n")
	write(t, repo, "internal/out.txt", "committed\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "two dirs")
	git(t, repo, "sparse-checkout", "init", "--cone")
	git(t, repo, "sparse-checkout", "set", "cmd")
	write(t, repo, "internal/out.txt", "OUT-OF-CONE-EDIT\n")

	code, out := runGate(t, cleanExportScript, repo, export)
	if code == 0 {
		t.Fatalf("the gate PASSED on a single out-of-cone edit:\n%s", out)
	}
	if !strings.Contains(out, refuseOmission) {
		t.Errorf("the gate refused (exit %d) but not by step 3b; if 4a caught it instead, 3b has stopped covering the single-edit case:\n%s", code, out)
	}
}

// TestCleanExport_CommittedSymlinkPasses is the negative control the
// file-count assertion never had.
//
// `git ls-tree -r` counts a symlink (mode 120000); `find -type f` does not.
// A tree with any committed symlink therefore false-redded a COMPLETE export,
// and the message blamed a .gitattributes export-ignore that did not exist.
func TestCleanExport_CommittedSymlinkPasses(t *testing.T) {
	repo, export := fixture(t)
	if err := os.Symlink("a.txt", filepath.Join(repo, "internal", "link.txt")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "symlink")
	// Anti-vacuity: the symlink must really be a 120000 entry, or this test
	// passes for a reason unrelated to symlinks.
	if mode := strings.Fields(git(t, repo, "ls-tree", "HEAD", "internal/link.txt"))[0]; mode != "120000" {
		t.Fatalf("internal/link.txt is mode %s, want 120000", mode)
	}
	write(t, repo, "internal/b.txt", "an ordinary unstaged change\n")

	code, out := runGate(t, cleanExportScript, repo, export)
	if code != 0 {
		t.Fatalf("the gate refused an export containing a committed symlink (exit %d):\n%s", code, out)
	}
	// The property is that the two counts AGREE, and that the symlink is one
	// of them -- not a hard-coded total that would drift with the fixture.
	m := regexp.MustCompile(`entries=(\d+) \(tree lists (\d+)\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the gate printed no entry count:\n%s", out)
	}
	if m[1] != m[2] {
		t.Errorf("extracted %s entries but the tree lists %s: the symlink is not being counted on both sides", m[1], m[2])
	}
	if n, _ := strconv.Atoi(m[1]); n < 3 {
		t.Errorf("the export holds only %s entries; the fixture has a.txt, link.txt and b.txt", m[1])
	}
}

// TestCleanExport_AwkwardFilenamesPass is the control for the entry count.
//
// The count has now false-redded a COMPLETE export twice, each time because
// one side was not counting entries: a committed symlink is a tree entry that
// `find -type f` does not match, and a committed filename containing a
// LITERAL NEWLINE is one entry that line-counting splits into two (measured:
// NUL 2, `find | wc -l` 3). Both sides count NUL-delimited entries now, which
// also covers spaces. This fixture carries all three shapes at once.
func TestCleanExport_AwkwardFilenamesPass(t *testing.T) {
	repo, export := fixture(t)
	write(t, repo, "internal/has\nnewline.txt", "newline in the name\n")
	write(t, repo, "internal/has space.txt", "space in the name\n")
	if err := os.Symlink("a.txt", filepath.Join(repo, "internal", "link.txt")); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "awkward names")
	// Anti-vacuity: all three really are committed, as the shapes claimed.
	tree := git(t, repo, "ls-tree", "-r", "HEAD")
	for _, want := range []string{"newline", "has space.txt", "120000"} {
		if !strings.Contains(tree, want) {
			t.Fatalf("the fixture does not carry %q; ls-tree -r HEAD:\n%s", want, tree)
		}
	}
	write(t, repo, "internal/b.txt", "an ordinary unstaged change\n")

	code, out := runGate(t, cleanExportScript, repo, export)
	if code != 0 {
		t.Fatalf("the gate refused a COMPLETE export of awkward filenames (exit %d):\n%s", code, out)
	}
	m := regexp.MustCompile(`entries=(\d+) \(tree lists (\d+)\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("the gate printed no entry count:\n%s", out)
	}
	if m[1] != m[2] {
		t.Errorf("extracted %s entries but the tree lists %s: a name shape is still being miscounted", m[1], m[2])
	}
	if n, _ := strconv.Atoi(m[1]); n != 5 {
		t.Errorf("the export holds %s entries, want 5 (a.txt, newline, space, link, b.txt)", m[1])
	}
}

// TestCleanExport_DroppedPathStillRefuses is the POSITIVE control for the
// entry count: the previous round fixed two false reds on it, and a fix that
// made it stop firing altogether would look exactly as green. A subdirectory
// .gitattributes with export-ignore makes `git archive` drop a path from a
// tree it was given, which is precisely what this assertion is for. (A ROOT
// .gitattributes cannot reach it -- the top-level allowlist refuses that name
// first -- so the fixture puts it in a subdirectory.)
func TestCleanExport_DroppedPathStillRefuses(t *testing.T) {
	repo, export := fixture(t)
	write(t, repo, "internal/drop.txt", "this will be export-ignored\n")
	write(t, repo, "internal/.gitattributes", "drop.txt export-ignore\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "export-ignore")
	write(t, repo, "internal/b.txt", "an ordinary unstaged change\n")

	code, out := runGate(t, cleanExportScript, repo, export)
	if code == 0 {
		t.Fatalf("the gate PASSED on an export missing internal/drop.txt:\n%s", out)
	}
	if !strings.Contains(out, "git archive dropped paths") {
		t.Errorf("the gate refused (exit %d) but not by the entry-count assertion:\n%s", code, out)
	}
}

// TestCleanExport_MalformedPackageCountRefuses pins the skip detector against
// failing open.
//
// `[ "$okn" -ne "$listed" ]` with a multi-line $listed writes "integer
// expression expected" to stderr and takes the else branch: the comparison
// silently stops asserting and the gate reports green. run_counted is called
// with `|| rc=$?`, so errexit is off inside it and nothing catches the
// fall-through. This fixture makes `make test-harness` print two packages=N
// lines and requires a refusal.
func TestCleanExport_MalformedPackageCountRefuses(t *testing.T) {
	// An all-digit value is not enough: one past INTMAX makes `[ -ne ]` ERROR
	// rather than compare, the `if` takes the else branch, and the check
	// PASSES. Measured: okn=1 against 40 nines -> "integer expression
	// expected", then PASS. errexit is off inside run_counted, so nothing
	// catches it. Both shapes are pinned here.
	huge := strings.Repeat("9", 40)
	cases := []struct {
		name, emit, want string
	}{
		{
			name: "two packages lines",
			emit: "\t@echo \"test-harness: packages=2\"\n\t@echo \"test-harness: packages=1\"\n",
			want: "packages=N lines, want exactly 1",
		},
		{
			name: "a count past INTMAX",
			emit: "\t@echo \"test-harness: packages=" + huge + "\"\n",
			want: "digits long",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, export := goFixture(t)
			writeExec(t, repo, "Makefile", "check:\n\t@echo \"ok  \tfixture/internal/x\t0.01s\"\n\ntest-harness:\n"+tc.emit+"\t@echo \"ok  \tfixture/internal/x\t0.01s\"\n")
			git(t, repo, "add", "-A")
			git(t, repo, "commit", "-q", "-m", "fixture")
			write(t, repo, "internal/x/extra.txt", "an unstaged change so the tree is not HEAD\n")

			// Full mode: --export-only never reaches run_counted.
			code, out := runGateFull(t, cleanExportScript, repo, export)
			if code == 0 {
				t.Fatalf("the gate PASSED with an unusable package count:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the gate refused (exit %d) but not for %q:\n%s", code, tc.want, out)
			}
		})
	}
}

// TestCleanExport_LeavesTheIndexAlone: the whole point of the throwaway index
// is that the repository's own index is untouched, so an implementor who is
// forbidden to stage can run the gate.
func TestCleanExport_LeavesTheIndexAlone(t *testing.T) {
	repo, export := fixture(t)
	append1(t, repo, "internal/a.txt", "mod\n")
	write(t, repo, "internal/b.txt", "new\n")

	before := git(t, repo, "status", "--porcelain")
	beforeIdx := git(t, repo, "write-tree")
	if code, out := runGate(t, cleanExportScript, repo, export); code != 0 {
		t.Fatalf("the gate exited %d:\n%s", code, out)
	}
	if after := git(t, repo, "status", "--porcelain"); after != before {
		t.Errorf("git status changed across the gate:\nbefore %q\nafter  %q", before, after)
	}
	if after := git(t, repo, "write-tree"); after != beforeIdx {
		t.Errorf("the repository index changed across the gate: %s -> %s", beforeIdx, after)
	}
	cmd := exec.Command("git", "diff", "--cached", "--quiet")
	cmd.Dir = repo
	cmd.Env = gitEnv()
	if err := cmd.Run(); err != nil {
		t.Errorf("the gate staged something: git diff --cached --quiet says %v", err)
	}
}

// TestCleanExport_ArtefactDirsAreIgnored: .build and .wt were un-ignored, so
// git add -A swept the chair's scratch (519 files when measured) and any unit
// worktree (as a gitlink) into every export. The ignore rules are the
// prevention; the script's top-level allowlist is the separate observer.
func TestCleanExport_ArtefactDirsAreIgnored(t *testing.T) {
	b, err := os.ReadFile("../../.gitignore")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for _, want := range []string{"/.build/", "/.wt/"} {
		found := false
		for _, l := range lines {
			if strings.TrimSpace(l) == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not in .gitignore: git add -A will sweep it into every clean export", want)
		}
	}
}

// TestMakefile_GateAndHarnessTargets pins the two new targets and, just as
// importantly, pins that `check` did NOT gain test-harness: CI runs `make
// check`, and docs/prd.md and README.md both say that is the whole contract.
// Changing it is the operator's decision, so a silent fold-in must go red.
func TestMakefile_GateAndHarnessTargets(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	var checkLine string
	targets := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(l, ":")
		if !ok || strings.ContainsAny(name, " \t#") || name == "" {
			continue
		}
		targets[name] = true
		if name == "check" {
			checkLine = strings.TrimSpace(rest)
		}
	}
	for _, want := range []string{"gate", "test-harness"} {
		if !targets[want] {
			t.Errorf("the Makefile has no %q target", want)
		}
	}
	prereqs, _, _ := strings.Cut(checkLine, "##")
	if got := strings.Fields(prereqs); len(got) != 2 || got[0] != "lint" || got[1] != "test" {
		t.Errorf("check's prerequisites are %v, want [lint test]: CI runs `make check`, and docs/prd.md and README.md say that is everything it runs; adding to it is the operator's call", got)
	}
}
