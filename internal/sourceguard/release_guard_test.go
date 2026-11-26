package sourceguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The RELEASE tests (contract plan Groups V, B, R; unit U-B). They run the real
// release scripts and the real toolchain in THROWAWAY git repositories made from
// the module's own files: a tag is created only there, never in the repository
// under test, and nothing is pushed.
//
// Every refusal test has a twin that succeeds on the same fixture (instruments
// #7, #15), the artifact is the one the script SHIPPED (#18: a check must run
// against the object under test), and each script run is judged by its own exit
// status and its own last line, never a wrapper's (#5, #19).

const gitDate = "2026-11-23T12:00:00Z"

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// copyModule copies the module's files (never .git, .wt, .build, bin, dist) into a
// new directory and returns it.
func copyModule(t *testing.T, dst string) {
	t.Helper()
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		switch top {
		case ".git", ".wt", ".build", "bin", "dist":
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, _ := d.Info()
		return os.WriteFile(target, b, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

func baseEnv() []string {
	env := os.Environ()
	out := env[:0:0]
	for _, e := range env {
		k := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			k = e[:i]
		}
		switch k {
		case "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "GOPROXY", "CGO_ENABLED", "GOOS", "GOARCH", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE":
			continue
		}
		out = append(out, e)
	}
	// GOPROXY=off is NOT used: it makes the toolchain stamp a stale pseudo-version on a
	// commit built before and tagged since (see hack/release/release.sh)
	return append(out, "GOTOOLCHAIN=local", "GOPROXY=file:///nonexistent-pveforge-release", "GOWORK=off", "GOFLAGS=")
}

func relGitEnv() []string {
	return append(baseEnv(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE="+gitDate, "GIT_COMMITTER_DATE="+gitDate)
}

func run(t *testing.T, dir string, env []string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("%s %v: %v", name, args, err)
		}
	}
	return out.String(), code
}

func mustRun(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	out, code := run(t, dir, env, name, args...)
	if code != 0 {
		t.Fatalf("%s %v exit %d:\n%s", name, args, code, out)
	}
	return out
}

// newRepo makes a throwaway repository of the module with ONE commit, at a fixed
// date. tag, when not empty, is an annotated tag on it.
func newRepo(t *testing.T, tag string) string {
	t.Helper()
	dir := t.TempDir()
	copyModule(t, dir)
	mustRun(t, dir, relGitEnv(), "git", "init", "-q", ".")
	mustRun(t, dir, relGitEnv(), "git", "add", "-A")
	mustRun(t, dir, relGitEnv(), "git", "commit", "-q", "-m", "snapshot")
	if tag != "" {
		mustRun(t, dir, relGitEnv(), "git", "tag", "-a", tag, "-m", "throwaway test tag")
	}
	return dir
}

func headOf(t *testing.T, dir string) string {
	return strings.TrimSpace(mustRun(t, dir, relGitEnv(), "git", "rev-parse", "HEAD"))
}

// release runs hack/release/release.sh in repo and returns its output and exit
// status.
func release(t *testing.T, repo string, args ...string) (string, int) {
	t.Helper()
	return run(t, repo, baseEnv(), filepath.Join(repo, "hack/release/release.sh"), args...)
}

func kvOf(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha(b)
}

// untar reads a .tar.gz into a map of name -> content (regular files) and the
// ordered names.
func untar(t *testing.T, p string) (map[string][]byte, []string) {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			files[h.Name] = b
		}
	}
	return files, names
}

// ---- shared tagged release (built once; several tests read it) --------------

type sharedResult struct {
	dist, repo, err string
}

// sharedDir is deterministic per process, so the cleanup test can remove it
// without a package variable assigned from a test (the no-parallel guard).
func sharedDir() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("pveforge-release-shared-%d", os.Getpid()))
}

// sharedReleaseOnce builds v0.1.0 once from a throwaway repo (sync.OnceValue: no
// package variable is assigned from a test).
var sharedReleaseOnce = sync.OnceValue(func() sharedResult {
	d := sharedDir()
	res := sharedResult{repo: filepath.Join(d, "repo"), dist: filepath.Join(d, "dist")}
	if err := os.MkdirAll(res.repo, 0o755); err != nil {
		res.err = err.Error()
		return res
	}
	root, _ := filepath.Abs("../..")
	if out, err := exec.Command("sh", "-c", "tar -c --exclude=./.git --exclude=./.wt --exclude=./.build --exclude=./bin --exclude=./dist -C "+root+" . | tar -x -C "+res.repo).CombinedOutput(); err != nil {
		res.err = "copy: " + string(out)
		return res
	}
	for _, a := range [][]string{{"init", "-q", "."}, {"add", "-A"}, {"commit", "-q", "-m", "snapshot"}, {"tag", "-a", "v0.1.0", "-m", "throwaway test tag"}} {
		c := exec.Command("git", a...)
		c.Dir, c.Env = res.repo, relGitEnv()
		if out, err := c.CombinedOutput(); err != nil {
			res.err = fmt.Sprintf("git %v: %s", a, out)
			return res
		}
	}
	c := exec.Command(filepath.Join(res.repo, "hack/release/release.sh"), "--out", res.dist)
	c.Dir, c.Env = res.repo, baseEnv()
	if out, err := c.CombinedOutput(); err != nil {
		res.err = "release.sh: " + err.Error() + "\n" + string(out)
	}
	return res
})

// sharedRelease returns the dist directory and repo of the shared v0.1.0 release.
func sharedRelease(t *testing.T) (dist, repo string) {
	t.Helper()
	r := sharedReleaseOnce()
	if r.err != "" {
		t.Fatalf("the shared release failed: %s", r.err)
	}
	return r.dist, r.repo
}

func TestRelease_ZZ_Cleanup(t *testing.T) {
	_ = os.RemoveAll(sharedDir())
}

// ---- AC-V6 / AC-R4: pins -----------------------------------------------------

// The build information is read in exactly one non-test file.
func TestRelease_BuildInfoIsReadInOnePlace(t *testing.T) {
	files, _ := typedModule(t)
	sites := map[string]int{}
	for _, tf := range files {
		ast.Inspect(tf.file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if fn, ok := tf.info.Uses[id].(*types.Func); ok && fn.FullName() == "runtime/debug.ReadBuildInfo" {
				sites[tf.rel]++
			}
			return true
		})
	}
	if len(sites) != 1 || sites["cmd/pveforge/version.go"] != 1 {
		t.Fatalf("runtime/debug.ReadBuildInfo is referenced from %v, want exactly cmd/pveforge/version.go once (AC-V6: the version and the schema's contract block share one function)", sites)
	}
}

// makeRecipes returns the recipe lines of every Makefile target whose name starts
// with "release", with make's own $(...) references replaced by MAKEVAR (they are not
// shell) and the recipe prefixes (@ - +) removed.
func makeRecipes(mk string) map[string][]string {
	out := map[string][]string{}
	target := ""
	for _, line := range strings.Split(mk, "\n") {
		if m := regexp.MustCompile(`^(release[A-Za-z-]*):`).FindStringSubmatch(line); m != nil {
			target = m[1]
			continue
		}
		if strings.HasPrefix(line, "\t") && target != "" {
			l := strings.TrimLeft(line, "\t @-+")
			for {
				i := strings.Index(l, "$(")
				if i < 0 {
					break
				}
				depth, j := 1, i+2
				for j < len(l) && depth > 0 {
					if l[j] == '(' {
						depth++
					} else if l[j] == ')' {
						depth--
					}
					j++
				}
				l = l[:i] + "MAKEVAR" + l[j:]
			}
			out[target] = append(out[target], l)
			continue
		}
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			target = ""
		}
	}
	return out
}

// The script and Makefile pin is an ALLOW-LIST of the commands the release process may
// run (release_shell_test.go), not a deny-list of spellings: a push built from a
// variable, an eval, a bash -c, a command substitution, a trap handler or a find -exec is
// judged like any command.
func TestRelease_ScriptsNeverTagPushOrPublish(t *testing.T) {
	root := moduleRoot(t)
	scripts, _ := filepath.Glob(filepath.Join(root, "hack/release/*.sh"))
	if len(scripts) < 3 {
		t.Fatalf("found %d release scripts, want release.sh, verify.sh and licenses.sh", len(scripts))
	}
	// NON-VACUITY: every plant must be refused (the reviewers' plants first)
	plants := map[string]string{
		"grok: a push built from a variable":  "cmd=git\n\"$cmd\" push origin v0.1.0\n",
		"a literal push":                      "git push origin v0.1.0\n",
		"a literal tag":                       "git -C \"$ROOT\" tag v0.1.0\n",
		"an annotated tag":                    "git tag -a v1 -m x\n",
		"curl":                                "curl -T f https://x\n",
		"gh":                                  "gh release create v0.1.0\n",
		"eval":                                "eval \"git push\"\n",
		"bash -c":                             "bash -c 'git push'\n",
		"sh -c":                               "sh -c \"git push\"\n",
		"a command substitution as the verb":  "$(echo git) push\n",
		"a push inside a substitution":        "x=$(git push 2>&1)\n",
		"a push inside a quoted substitution": "echo \"$(git push)\"\n",
		"a push in a trap string":             "trap 'git push' EXIT\n",
		"a push in an if condition":           "if git push; then :; fi\n",
		"a push after env":                    "env GIT_X=1 git push\n",
		"a push under find -exec":             "find . -exec git push {} +\n",
		"a push inside a case arm":            "case \"$x\" in\na) git push ;;\nesac\n",
		"a push in a pipeline":                "true | git push\n",
		"a push behind &&":                    "[ -f x ] && git push\n",
		"a commit":                            "git commit -am x\n",
		"go run":                              "go run ./cmd/pveforge\n",
		"an unknown program":                  "rsync -a dist host:\n",
		"a backtick substitution":             "x=`git push`\n",
		"command git push":                    "command git push origin HEAD\n",
		"command -p git tag":                  "command -p git tag v1\n",
		"command -v with extra words":         "command -v git push\n",
		"exec git push":                       "exec git push\n",
		"xargs git push":                      "xargs git push\n",
		"nice git push":                       "nice git push\n",
		"nohup git push":                      "nohup git push &\n",
		"timeout git push":                    "timeout 5 git push\n",
		"time git push":                       "time git push\n",
		"builtin git push":                    "builtin git push\n",
		"awk system()":                        "awk 'BEGIN { system(\"git push origin HEAD\") }'\n",
		"awk print piped to a command":        "awk '{ print | \"git push\" }'\n",
		"awk command piped into getline":      "awk 'BEGIN { \"git push\" | getline x }'\n",
		"awk getline from a file":             "awk 'BEGIN { getline x < f }'\n",
		"awk program from a file":             "awk -f prog.awk\n",
		"sed e command":                       "sed -n '1e git push'\n",
		"sed e command at the last line":      "sed -e '$e git push'\n",
		"sed s with the e flag":               "sed 's/a/b/e'\n",
		"sed w file":                          "sed 'w /tmp/x'\n",
		"sed s with the w flag":               "sed 's/a/b/w /tmp/x'\n",
		"sed script from a file":              "sed -f s.sed\n",
		"a variable command in a function":    "f() {\n  \"$GIT\" push\n}\nf\n",
	}
	for name, src := range plants {
		if bad := releaseScriptPolicy.check(src); len(bad) == 0 {
			t.Errorf("the pin does not catch the plant %q:\n%s", name, src)
		}
	}
	// delegating prefixes are refused AS delegation (not merely as unknown programs), and
	// `command` as running another command
	for _, name := range []string{"exec git push", "xargs git push", "nice git push", "nohup git push", "timeout git push", "builtin git push"} {
		if bad := strings.Join(releaseScriptPolicy.check(plants[name]), "\n"); !strings.Contains(bad, "delegation") {
			t.Errorf("%q is not refused as delegation: %s", name, bad)
		}
	}
	for _, name := range []string{"command git push", "command -p git tag", "command -v with extra words"} {
		if bad := strings.Join(releaseScriptPolicy.check(plants[name]), "\n"); !strings.Contains(bad, "only `command -v") {
			t.Errorf("%q is not refused by the command -v rule: %s", name, bad)
		}
	}
	for _, name := range []string{"awk system()", "awk print piped to a command", "awk command piped into getline", "awk getline from a file", "awk program from a file"} {
		if bad := strings.Join(releaseScriptPolicy.check(plants[name]), "\n"); !strings.Contains(bad, "awk") {
			t.Errorf("%q is not refused by the awk rule: %s", name, bad)
		}
	}
	for _, name := range []string{"sed e command", "sed e command at the last line", "sed s with the e flag", "sed w file", "sed s with the w flag", "sed script from a file"} {
		if bad := strings.Join(releaseScriptPolicy.check(plants[name]), "\n"); !strings.Contains(bad, "sed") {
			t.Errorf("%q is not refused by the sed rule: %s", name, bad)
		}
	}
	// the variable-built command is refused AS an indirect invocation (not merely as an
	// unknown program name): the expansion rule is what names it
	if bad := releaseScriptPolicy.check(plants["grok: a push built from a variable"]); len(bad) == 0 || !strings.Contains(strings.Join(bad, "\n"), "indirect invocation") {
		t.Errorf("the variable-built push is not refused as an indirect invocation: %v", bad)
	}
	controls := map[string]string{
		"a listing tag":         "git -C \"$ROOT\" tag --points-at HEAD\n",
		"a listing tag (-l)":    "git tag -l 'v*'\n",
		"a comment":             "# git push is never run\n",
		"a quoted message":      "die \"nothing was tagged, pushed or published\"\n",
		"the shipped binary":    "\"$STAGE/pveforge\" version\n",
		"env then go build":     "env \"${BUILD_ENV[@]}\" go build -trimpath -o x ./cmd/pveforge\n",
		"a function and a call": "f() {\n  echo hi\n}\nf\n",
		"command -v":            "command -v go\n",
		"awk with -F and -v":    "awk -F= -v k=\"$1\" '$1 == k { sub(/^[^=]*=/, \"\"); print; exit }'\n",
		"awk sum":               "awk '{ print $1 \" \" $2 }'\n",
		"sed s with a | delim":  "sed 's|^\\./||'\n",
		"sed -e s":              "sed -e 's/^[[:space:]]*[-*][[:space:]]*//'\n",
		"sed -n print":          "sed -n '2p'\n",
		"a case statement":      "case \"$1\" in\n--a) shift ;;\n*) exit 2 ;;\nesac\n",
	}
	for name, src := range controls {
		if bad := releaseScriptPolicy.check("die() { :; }\n" + src); len(bad) != 0 {
			t.Errorf("the pin refuses the allowed %q: %v", name, bad)
		}
	}
	// the shipped scripts
	for _, s := range scripts {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range releaseScriptPolicy.check(string(b)) {
			t.Errorf("%s: %s", filepath.Base(s), bad)
		}
	}
	// the Makefile's release targets FAIL the test on any violation (they used to be logged)
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	recipes := makeRecipes(string(mk))
	for _, want := range []string{"release", "release-candidate", "release-verify", "release-check"} {
		if len(recipes[want]) == 0 {
			t.Fatalf("the Makefile has no recipe for %s: the pin is not seeing the release targets (found %v)", want, recipes)
		}
	}
	// a planted Makefile recipe must be refused
	for _, plant := range []string{"git push origin HEAD", "git tag v1", "hack/release/release.sh && git push", "curl -T f x"} {
		if bad := makefileReleasePolicy.check(plant + "\n"); len(bad) == 0 {
			t.Errorf("the Makefile pin does not catch %q", plant)
		}
	}
	for target, lines := range recipes {
		for _, l := range lines {
			for _, bad := range makefileReleasePolicy.check(l + "\n") {
				t.Errorf("Makefile target %s: %s (in %q)", target, bad, l)
			}
		}
	}
}

// ---- AC-V1..V4 end to end -----------------------------------------------------

func buildPveforge(t *testing.T, dir, out string, extra []string, env ...string) {
	t.Helper()
	args := append([]string{"build"}, extra...)
	args = append(args, "-o", out, "./cmd/pveforge")
	e := append(baseEnv(), env...)
	if o, code := run(t, dir, e, "go", args...); code != 0 {
		t.Fatalf("go %v in %s exit %d:\n%s", args, dir, code, o)
	}
}

func versionOf(t *testing.T, bin string) map[string]string {
	t.Helper()
	out, code := run(t, "", baseEnv(), bin, "version")
	if code != 0 {
		t.Fatalf("%s version exit %d: %s", bin, code, out)
	}
	return kvOf(out)
}

func vcsLines(t *testing.T, bin string) int {
	out := mustRun(t, "", baseEnv(), "go", "version", "-m", bin)
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "build\tvcs") {
			n++
		}
	}
	return n
}

func TestRelease_VersionEndToEnd(t *testing.T) {
	static := []string{"-trimpath"}
	repo := newRepo(t, "v0.1.0")
	bin := filepath.Join(t.TempDir(), "pveforge")
	rev := strings.TrimSpace(mustRun(t, repo, relGitEnv(), "git", "rev-parse", "v0.1.0^{commit}"))

	// clean tag: release=true, and the commit IS the tag's commit (a version string
	// alone cannot tell a tag on HEAD from a replace onto a tagged tree)
	buildPveforge(t, repo, bin, static, "CGO_ENABLED=0")
	v := versionOf(t, bin)
	if v["release"] != "true" || v["version"] != "v0.1.0" || v["dirty"] != "false" || v["stamped"] != "true" || v["commit"] != rev || v["static"] != "true" || v["commit_time"] != gitDate {
		t.Fatalf("clean tag: %v (want release=true version=v0.1.0 dirty=false commit=%s commit_time=%s)", v, rev, gitDate)
	}
	// untagged HEAD: a pseudo-version, not a release
	mustRun(t, repo, relGitEnv(), "git", "tag", "-d", "v0.1.0")
	buildPveforge(t, repo, bin, static, "CGO_ENABLED=0")
	v = versionOf(t, bin)
	if v["release"] != "false" || !strings.HasPrefix(v["version"], "v0.0.0-") || v["dirty"] != "false" {
		t.Fatalf("untagged: %v", v)
	}
	// a release candidate tag: prerelease=true, release=false
	mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0-rc.1", "-m", "rc")
	buildPveforge(t, repo, bin, static, "CGO_ENABLED=0")
	v = versionOf(t, bin)
	if v["release"] != "false" || v["prerelease"] != "true" || v["version"] != "v0.1.0-rc.1" {
		t.Fatalf("rc tag: %v", v)
	}
	mustRun(t, repo, relGitEnv(), "git", "tag", "-d", "v0.1.0-rc.1")
	mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0", "-m", "again")
	// tagged and dirty by ONE untracked file: dirty=true, release=false
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildPveforge(t, repo, bin, static, "CGO_ENABLED=0")
	v = versionOf(t, bin)
	if v["release"] != "false" || v["dirty"] != "true" || !strings.HasSuffix(v["version"], "+dirty") {
		t.Fatalf("tagged + untracked file: %v", v)
	}
	_ = os.Remove(filepath.Join(repo, "untracked.txt"))
	// a git-archive export: no VCS at all, so no dirty verdict
	export := t.TempDir()
	mustRun(t, repo, relGitEnv(), "sh", "-c", "git archive HEAD | tar -x -C "+export)
	buildPveforge(t, export, bin, static, "CGO_ENABLED=0")
	if n := vcsLines(t, bin); n != 0 {
		t.Fatalf("the export build carries %d vcs lines: the fixture is not an unstamped build", n)
	}
	v = versionOf(t, bin)
	if v["stamped"] != "false" || v["release"] != "false" {
		t.Fatalf("export: %v", v)
	}
	if _, has := v["dirty"]; has {
		t.Fatalf("an unstamped build printed dirty=%s: it must not guess", v["dirty"])
	}
	// -buildvcs=false on the clean tagged tree: also unstamped
	buildPveforge(t, repo, bin, []string{"-trimpath", "-buildvcs=false"}, "CGO_ENABLED=0")
	v = versionOf(t, bin)
	if v["stamped"] != "false" || v["release"] != "false" {
		t.Fatalf("-buildvcs=false: %v", v)
	}
}

// A go.mod replace of a dependency onto a local copy: the toolchain stamps the
// version of the tagged tree, but the build is not that tag's source.
func TestRelease_ReplaceIsNotARelease(t *testing.T) {
	repo := newRepo(t, "v0.1.0")
	mod := strings.TrimSpace(mustRun(t, repo, baseEnv(), "go", "list", "-m", "-f", "{{.Dir}}", "github.com/gofrs/flock"))
	if mod == "" {
		t.Fatal("cannot find the flock module in the cache")
	}
	copyDir := filepath.Join(repo, "internal", "flockcopy")
	if err := os.MkdirAll(copyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustRun(t, repo, baseEnv(), "sh", "-c", "cp -r "+mod+"/. "+copyDir+" && chmod -R u+w "+copyDir)
	gm := filepath.Join(repo, "go.mod")
	b, _ := os.ReadFile(gm)
	if err := os.WriteFile(gm, append(b, []byte("\nreplace github.com/gofrs/flock => ./internal/flockcopy\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, repo, relGitEnv(), "git", "add", "-A")
	mustRun(t, repo, relGitEnv(), "git", "commit", "-q", "-m", "replace")
	mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.1", "-m", "tagged with a replace")
	bin := filepath.Join(t.TempDir(), "pveforge")
	buildPveforge(t, repo, bin, []string{"-trimpath", "-mod=mod"}, "CGO_ENABLED=0")
	v := versionOf(t, bin)
	if v["version"] != "v0.1.1" || v["dirty"] != "false" || v["stamped"] != "true" {
		t.Fatalf("fixture: the replaced build is not a clean tagged build: %v", v)
	}
	if v["release"] != "false" {
		t.Fatalf("a build with a replace says release=%s: %v", v["release"], v)
	}
}

// ---- AC-B1/B3: static, reproducible -------------------------------------------

func isStatic(t *testing.T, p string) (interp bool, needed []string) {
	t.Helper()
	f, err := elf.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, pr := range f.Progs {
		if pr.Type == elf.PT_INTERP {
			interp = true
		}
	}
	needed, _ = f.ImportedLibraries()
	return
}

func TestRelease_BinaryIsStatic_WithADynamicControl(t *testing.T) {
	dist, _ := sharedRelease(t)
	files, _ := untar(t, filepath.Join(dist, "pveforge-v0.1.0-linux-amd64.tar.gz"))
	bin := filepath.Join(t.TempDir(), "pveforge")
	if err := os.WriteFile(bin, files["pveforge-v0.1.0-linux-amd64/pveforge"], 0o755); err != nil {
		t.Fatal(err)
	}
	interp, needed := isStatic(t, bin)
	if interp || len(needed) != 0 {
		t.Fatalf("the shipped binary is not static: interpreter %v, needs %v", interp, needed)
	}
	// the control: the default build of the same tree IS dynamic (so "no NEEDED" can fail)
	repo := newRepo(t, "")
	dyn := filepath.Join(t.TempDir(), "dyn")
	buildPveforge(t, repo, dyn, nil)
	if interp, needed := isStatic(t, dyn); !interp || len(needed) == 0 {
		t.Fatalf("the control (a default build) is not dynamic (interpreter %v, needs %v): the static check cannot fail", interp, needed)
	}
}

// AC-S3b: the static binary's resolver reads /etc/hosts. This tests Go's own
// resolver as the static build embeds it; it does NOT show that nsswitch, mDNS or
// NIS are skipped (the documented difference is stated, not measured).
func TestRelease_StaticResolverReadsEtcHosts(t *testing.T) {
	dir := t.TempDir()
	prog := "package main\nimport (\"fmt\"; \"net\"; \"os\")\nfunc main() { a, err := net.LookupHost(\"localhost\"); if err != nil || len(a) == 0 { fmt.Println(\"FAIL\", err); os.Exit(1) }; fmt.Println(\"OK\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module resolvertest\n\ngo 1.27.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "r")
	mustRun(t, dir, append(baseEnv(), "CGO_ENABLED=0"), "go", "build", "-o", bin, ".")
	if interp, _ := isStatic(t, bin); interp {
		t.Fatal("the resolver fixture is not static")
	}
	if out, code := run(t, dir, baseEnv(), bin); code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("the static resolver could not resolve localhost: %s", out)
	}
}

func TestRelease_TwoBuildsOfOneTagAreByteIdentical(t *testing.T) {
	dist1, _ := sharedRelease(t)
	repo2 := newRepo(t, "v0.1.0") // a DIFFERENT directory, the same tree, the same fixed commit date
	dist2 := filepath.Join(t.TempDir(), "dist")
	if out, code := release(t, repo2, "--out", dist2); code != 0 {
		t.Fatalf("second release: exit %d\n%s", code, out)
	}
	names := []string{"pveforge-v0.1.0-linux-amd64.tar.gz", "pveforge-v0.1.0-source.tar.gz", "schema-v0.1.0.json", "SHA256SUMS"}
	for _, n := range names {
		if a, b := fileSHA(t, filepath.Join(dist1, n)), fileSHA(t, filepath.Join(dist2, n)); a != b {
			t.Errorf("%s differs between two builds of one tag: %s vs %s", n, a, b)
		}
	}
	// non-vacuity: the same comparison WITHOUT -trimpath must differ (two different
	// source directories), else "identical" could not fail
	r1, r2 := newRepo(t, "v0.1.0"), newRepo(t, "v0.1.0")
	b1, b2 := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	buildPveforge(t, r1, b1, nil, "CGO_ENABLED=0")
	buildPveforge(t, r2, b2, nil, "CGO_ENABLED=0")
	if fileSHA(t, b1) == fileSHA(t, b2) {
		t.Fatalf("two builds without -trimpath from different directories are identical: the reproducibility comparison cannot fail")
	}
	// the control the other way: -trimpath builds from those same two directories ARE identical
	t1, t2 := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	buildPveforge(t, r1, t1, []string{"-trimpath"}, "CGO_ENABLED=0")
	buildPveforge(t, r2, t2, []string{"-trimpath"}, "CGO_ENABLED=0")
	if fileSHA(t, t1) != fileSHA(t, t2) {
		t.Fatalf("two -trimpath builds from different directories differ")
	}
}

// ---- AC-R1/R2/R5: the bundle ----------------------------------------------------

var noticeRowRE = regexp.MustCompile("(?m)^\\| `([^`]+)` \\| (v[^ ]+) \\| (.*) \\|$")

func noticeModules(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "THIRD-PARTY-NOTICES.md"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range noticeRowRE.FindAllStringSubmatch(string(b), -1) {
		if strings.Contains(m[3], "Windows only") {
			continue
		}
		out = append(out, m[1]+"@"+m[2])
	}
	sort.Strings(out)
	return out
}

func TestRelease_BundleIsCompleteAndExact(t *testing.T) {
	dist, repo := sharedRelease(t)
	files, names := untar(t, filepath.Join(dist, "pveforge-v0.1.0-linux-amd64.tar.gz"))
	top := "pveforge-v0.1.0-linux-amd64/"
	for _, f := range []string{"pveforge", "LICENSE", "THIRD-PARTY-NOTICES.md", "CHANGES.md", "schema.json", "BUILDINFO.txt", "licenses/go/LICENSE"} {
		if len(files[top+f]) == 0 {
			t.Errorf("the archive lacks (or has an empty) %s", f)
		}
	}
	// the module set is EXACTLY the notices table's rows for linux (15), not a floor
	want := noticeModules(t)
	if len(want) != 15 {
		t.Fatalf("the notices table has %d linux rows: the fixture assumption (15) changed; update the exactness check deliberately", len(want))
	}
	var have []string
	seen := map[string]bool{}
	for _, n := range names {
		rest := strings.TrimPrefix(n, top+"licenses/")
		if rest == n || strings.HasPrefix(rest, "go/") {
			continue
		}
		// <module path>@<version>/<file>; a module path has slashes: split at the @version
		if i := strings.Index(rest, "@"); i >= 0 {
			j := strings.Index(rest[i:], "/")
			if j > 0 {
				k := rest[:i+j]
				if !seen[k] {
					seen[k] = true
					have = append(have, k)
				}
			}
		}
	}
	sort.Strings(have)
	if strings.Join(have, ",") != strings.Join(want, ",") {
		t.Fatalf("bundled modules differ from the notices table:\n bundled %v\n table   %v", have, want)
	}
	// every module has non-empty licence text, equal to the module cache's file
	for _, m := range have {
		var lic int
		for n, b := range files {
			if strings.HasPrefix(n, top+"licenses/"+m+"/") && len(b) > 0 {
				lic++
			}
		}
		if lic == 0 {
			t.Errorf("%s has no licence text", m)
		}
	}
	// go-proxmox's NOTICE ships, and equals the module cache's file (a NOTICE of ANY module is copied)
	var goproxmox string
	for _, m := range have {
		if strings.HasPrefix(m, "github.com/suykerbuyk/go-proxmox@") {
			goproxmox = m
		}
	}
	if len(files[top+"licenses/"+goproxmox+"/NOTICE"]) == 0 {
		t.Errorf("go-proxmox's NOTICE is not in the bundle (%s)", goproxmox)
	}
	// Go's licence is the toolchain's file
	goroot := strings.TrimSpace(mustRun(t, repo, baseEnv(), "go", "env", "GOROOT"))
	gl, err := os.ReadFile(filepath.Join(goroot, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gl, files[top+"licenses/go/LICENSE"]) {
		t.Errorf("licenses/go/LICENSE is not GOROOT's LICENSE")
	}
	// schema.json in the archive is the binary's own (AC-R2): run the shipped binary
	bin := filepath.Join(t.TempDir(), "pveforge")
	if err := os.WriteFile(bin, files[top+"pveforge"], 0o755); err != nil {
		t.Fatal(err)
	}
	sch, code := run(t, "", baseEnv(), bin, "schema")
	if code != 0 || sch != string(files[top+"schema.json"]) {
		t.Fatalf("schema.json in the archive is not the shipped binary's output (exit %d)", code)
	}
	if string(files[top+"schema.json"]) == "" || fileSHA(t, filepath.Join(dist, "schema-v0.1.0.json")) != sha(files[top+"schema.json"]) {
		t.Errorf("the standalone schema differs from the archive's")
	}
	// BUILDINFO.txt is the toolchain's record of the same binary
	bi := string(files[top+"BUILDINFO.txt"])
	for _, w := range []string{"CGO_ENABLED=0", "-trimpath=true", "vcs.revision=", "vcs.modified=false"} {
		if !strings.Contains(bi, w) {
			t.Errorf("BUILDINFO.txt lacks %q", w)
		}
	}
}

func TestRelease_ChecksumsVerify_AndAFlippedByteFails(t *testing.T) {
	dist, repo := sharedRelease(t)
	verify := func(d string) (string, int) {
		return run(t, repo, baseEnv(), filepath.Join(repo, "hack/release/verify.sh"), d)
	}
	if out, code := verify(dist); code != 0 || !strings.Contains(out, "verify: PASSED") {
		t.Fatalf("verify.sh on the real release: exit %d\n%s", code, out)
	}
	// the control: a flipped byte in the archive must fail
	bad := t.TempDir()
	for _, n := range []string{"pveforge-v0.1.0-linux-amd64.tar.gz", "pveforge-v0.1.0-source.tar.gz", "schema-v0.1.0.json", "SHA256SUMS"} {
		b, _ := os.ReadFile(filepath.Join(dist, n))
		if n == "pveforge-v0.1.0-linux-amd64.tar.gz" {
			b[len(b)/2] ^= 0xff
		}
		if err := os.WriteFile(filepath.Join(bad, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := verify(bad); code == 0 {
		t.Fatalf("verify.sh passed an archive with a flipped byte:\n%s", out)
	}
	// a file that rides along unlisted fails
	extra := t.TempDir()
	for _, n := range []string{"pveforge-v0.1.0-linux-amd64.tar.gz", "pveforge-v0.1.0-source.tar.gz", "schema-v0.1.0.json", "SHA256SUMS"} {
		b, _ := os.ReadFile(filepath.Join(dist, n))
		_ = os.WriteFile(filepath.Join(extra, n), b, 0o644)
	}
	_ = os.WriteFile(filepath.Join(extra, "extra.bin"), []byte("x"), 0o644)
	if out, code := verify(extra); code == 0 {
		t.Fatalf("verify.sh passed a directory with an unlisted file:\n%s", out)
	}
}

// ---- licences.sh with a fixture module set (AC-R1 vacuity controls) -------------

func TestRelease_LicensesScriptHandlesEveryNameAndRefusesAMissingOne(t *testing.T) {
	root := moduleRoot(t)
	tmp := t.TempDir()
	mk := func(name string, files map[string]string) string {
		d := filepath.Join(tmp, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for f, c := range files {
			if err := os.WriteFile(filepath.Join(d, f), []byte(c), 0o444); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	list := func(lines ...string) string {
		p := filepath.Join(tmp, fmt.Sprintf("list-%d", len(lines)))
		_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
		return p
	}
	a := mk("a", map[string]string{"LICENSE": "A", "main.go": "x"})
	b := mk("b", map[string]string{"LICENSE.md": "B md"})
	c := mk("c", map[string]string{"COPYING-GPL": "C", "NOTICE": "notice c"})
	d := mk("d", map[string]string{"License": "D", "notice.txt": "notice d"})
	e := mk("e", map[string]string{"README": "no licence here"})
	script := filepath.Join(root, "hack/release/licenses.sh")
	out1 := filepath.Join(tmp, "out1")
	if o, code := run(t, "", baseEnv(), script, list("m/a v1 "+a, "m/b v1 "+b, "m/c v1 "+c, "m/d v1 "+d), out1); code != 0 {
		t.Fatalf("licenses.sh exit %d: %s", code, o)
	}
	for _, want := range []string{"m/a@v1/LICENSE", "m/b@v1/LICENSE.md", "m/c@v1/COPYING-GPL", "m/c@v1/NOTICE", "m/d@v1/License", "m/d@v1/notice.txt"} {
		if _, err := os.Stat(filepath.Join(out1, want)); err != nil {
			t.Errorf("not bundled: %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(out1, "m/a@v1/main.go")); err == nil {
		t.Errorf("a non-licence file was bundled")
	}
	// the refusal: a module with no licence file (the twin is the run above)
	out2 := filepath.Join(tmp, "out2")
	if o, code := run(t, "", baseEnv(), script, list("m/a v1 "+a, "m/e v1 "+e), out2); code == 0 || !strings.Contains(o, "no licence file") {
		t.Fatalf("a module without a licence was not refused (exit %d): %s", code, o)
	}
	// an empty module list is refused (a derivation that found nothing is broken)
	empty := filepath.Join(tmp, "empty")
	_ = os.WriteFile(empty, nil, 0o644)
	if o, code := run(t, "", baseEnv(), script, empty, filepath.Join(tmp, "out3")); code == 0 {
		t.Fatalf("an empty module list was accepted: %s", o)
	}
}

// ---- AC-B4/R3: refusals, each with the succeeding twin ----------------------------

func TestRelease_Refusals(t *testing.T) {
	refused := func(t *testing.T, repo string, wantSub string, args ...string) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "dist")
		a := append([]string{"--out", out}, args...)
		o, code := release(t, repo, a...)
		if code == 0 || !strings.Contains(o, "REFUSED") || !strings.Contains(o, wantSub) {
			t.Fatalf("expected a refusal containing %q, got exit %d:\n%s", wantSub, code, o)
		}
		if ents, err := os.ReadDir(out); err == nil && len(ents) != 0 {
			t.Fatalf("a refused release left artifacts in %s: %v", out, ents)
		}
	}
	t.Run("dirty tree (an untracked file)", func(t *testing.T) {
		repo := newRepo(t, "v0.1.0")
		_ = os.WriteFile(filepath.Join(repo, "stray.txt"), []byte("x"), 0o644)
		refused(t, repo, "not clean")
	})
	t.Run("untagged HEAD needs --candidate, and a candidate succeeds", func(t *testing.T) {
		repo := newRepo(t, "")
		refused(t, repo, "not exactly a release tag")
		out := filepath.Join(t.TempDir(), "dist")
		o, code := release(t, repo, "--candidate", "--changes-for", "v0.1.0", "--out", out)
		if code != 0 || !strings.Contains(o, "the candidate") || !strings.Contains(o, "PASSED") {
			t.Fatalf("the candidate twin failed (exit %d):\n%s", code, o)
		}
		files, _ := untar(t, filepath.Join(out, fileGlob(t, out, "-linux-amd64.tar.gz")))
		var bin []byte
		for n, b := range files {
			if strings.HasSuffix(n, "/pveforge") {
				bin = b
			}
		}
		p := filepath.Join(t.TempDir(), "pveforge")
		_ = os.WriteFile(p, bin, 0o755)
		if v := versionOf(t, p); v["release"] != "false" {
			t.Fatalf("a candidate says release=%s", v["release"])
		}
	})
	for _, bad := range []string{"v0.1.0-beta.1", "v0.1.0-alpha.1", "v0.1.0-rc", "v0.1.0-rc.1.2"} {
		t.Run("tag shape "+bad, func(t *testing.T) {
			repo := newRepo(t, bad)
			refused(t, repo, "not a valid release tag")
		})
	}
	t.Run("a release candidate tag is accepted", func(t *testing.T) {
		repo := newRepo(t, "v0.1.0-rc.1")
		// the CHANGES section is for the tag: add it
		changes := filepath.Join(repo, "CHANGES.md")
		b, _ := os.ReadFile(changes)
		// the `## v0.1.0` heading is found by a line-anchored regexp, whatever its suffix (a date,
		// a note), and its absence FAILS: a literal Replace would silently no-op on a changed heading
		headingRE := regexp.MustCompile(`(?m)^## v0\.1\.0\b.*$`)
		loc := headingRE.FindIndex(b)
		if loc == nil {
			t.Fatalf("CHANGES.md has no `## v0.1.0` heading line: the fixture cannot add the rc section before it")
		}
		rcSection := "## v0.1.0-rc.1\n\n### Breaking\n\n- none\n\n### Added\n\n- none\n\n### Fixed\n\n- none\n\n### Contract\n\n- none\n\n"
		edited := string(b[:loc[0]]) + rcSection + string(b[loc[0]:])
		if edited == string(b) || !strings.Contains(edited, "## v0.1.0-rc.1\n") {
			t.Fatalf("the rc section was not added to CHANGES.md")
		}
		if err := os.WriteFile(changes, []byte(edited), 0o644); err != nil {
			t.Fatal(err)
		}
		mustRun(t, repo, relGitEnv(), "git", "add", "-A")
		mustRun(t, repo, relGitEnv(), "git", "commit", "-q", "-m", "changes")
		mustRun(t, repo, relGitEnv(), "git", "tag", "-d", "v0.1.0-rc.1")
		mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0-rc.1", "-m", "rc")
		out := filepath.Join(t.TempDir(), "dist")
		o, code := release(t, repo, "--out", out)
		if code != 0 {
			t.Fatalf("the rc tag was refused: exit %d\n%s", code, o)
		}
		files, _ := untar(t, filepath.Join(out, fileGlob(t, out, "-linux-amd64.tar.gz")))
		p := filepath.Join(t.TempDir(), "pveforge")
		for n, b := range files {
			if strings.HasSuffix(n, "/pveforge") {
				_ = os.WriteFile(p, b, 0o755)
			}
		}
		if v := versionOf(t, p); v["prerelease"] != "true" || v["release"] != "false" || v["version"] != "v0.1.0-rc.1" {
			t.Fatalf("rc binary: %v", v)
		}
	})
	t.Run("HEAD is past the tag", func(t *testing.T) {
		repo := newRepo(t, "v0.1.0")
		_ = os.WriteFile(filepath.Join(repo, "later.txt"), []byte("x"), 0o644)
		mustRun(t, repo, relGitEnv(), "git", "add", "-A")
		mustRun(t, repo, relGitEnv(), "git", "commit", "-q", "-m", "later")
		refused(t, repo, "not exactly a release tag")
	})
	t.Run("an output directory that is not empty", func(t *testing.T) {
		repo := newRepo(t, "v0.1.0")
		out := t.TempDir()
		_ = os.WriteFile(filepath.Join(out, "old"), []byte("x"), 0o644)
		o, code := release(t, repo, "--out", out)
		if code == 0 || !strings.Contains(o, "is not empty") {
			t.Fatalf("a non-empty output directory was accepted (exit %d): %s", code, o)
		}
	})
	t.Run("a toolchain other than go.mod's", func(t *testing.T) {
		repo := newRepo(t, "")
		gm := filepath.Join(repo, "go.mod")
		b, _ := os.ReadFile(gm)
		_ = os.WriteFile(gm, []byte(strings.Replace(string(b), "\ngo 1.27.4\n", "\ngo 1.27.4\n\ntoolchain go1.27.3\n", 1)), 0o644)
		mustRun(t, repo, relGitEnv(), "git", "add", "-A")
		mustRun(t, repo, relGitEnv(), "git", "commit", "-q", "-m", "toolchain")
		mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0", "-m", "t")
		refused(t, repo, "toolchain")
	})
	t.Run("CHANGES has no section for the tag", func(t *testing.T) {
		repo := newRepo(t, "")
		mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.9.9", "-m", "t")
		refused(t, repo, "CHANGES.md has no '## v0.9.9' section")
	})
	t.Run("CHANGES says Breaking none while the schema diff is breaking, and an honest CHANGES passes", func(t *testing.T) {
		repo := newRepo(t, "")
		writeChanges := func(breaking string) {
			c := "# Changes\n\n## v0.1.0\n\n### Breaking\n\n" + breaking + "\n\n### Added\n\n- none\n\n### Fixed\n\n- none\n\n### Contract\n\n- none\n"
			if err := os.WriteFile(filepath.Join(repo, "CHANGES.md"), []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
			mustRun(t, repo, relGitEnv(), "git", "add", "-A")
			mustRun(t, repo, relGitEnv(), "git", "commit", "-q", "-m", "changes")
		}
		retag := func() {
			run(t, repo, relGitEnv(), "git", "tag", "-d", "v0.1.0")
			mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0", "-m", "t")
		}
		// the previous schema: this tree's real one plus a verb this tree does not have,
		// so the diff (previous -> this) finds a REMOVED verb: breaking
		bin := filepath.Join(t.TempDir(), "pveforge")
		buildPveforge(t, repo, bin, []string{"-trimpath"}, "CGO_ENABLED=0")
		sch := mustRun(t, repo, baseEnv(), bin, "schema")
		prev := strings.Replace(sch, `"subcommands": [`, `"subcommands": [
    {"name": "zzremoved", "use": "zzremoved", "mutation": "safe"},`, 1)
		pf := filepath.Join(t.TempDir(), "prev.json")
		if err := os.WriteFile(pf, []byte(prev), 0o644); err != nil {
			t.Fatal(err)
		}
		writeChanges("- none")
		retag()
		refused(t, repo, "BREAKING change and CHANGES.md says Breaking: none", "--previous-schema", pf)
		// the twin: CHANGES admits the break
		writeChanges("- the zzremoved verb was removed (test)")
		retag()
		out := filepath.Join(t.TempDir(), "dist")
		if o, code := release(t, repo, "--previous-schema", pf, "--out", out); code != 0 {
			t.Fatalf("an honest CHANGES was refused (exit %d):\n%s", code, o)
		}
		// and the control for the diff itself: against the schema of the same tree there is no breaking verdict
		same := filepath.Join(t.TempDir(), "same.json")
		_ = os.WriteFile(same, []byte(sch), 0o644)
		writeChanges("- none")
		retag()
		out2 := filepath.Join(t.TempDir(), "dist")
		if o, code := release(t, repo, "--previous-schema", same, "--out", out2); code != 0 {
			t.Fatalf("Breaking: none against an identical schema was refused (exit %d):\n%s", code, o)
		}
	})
}

func fileGlob(t *testing.T, dir, suffix string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), suffix) {
			return e.Name()
		}
	}
	t.Fatalf("no *%s in %s", suffix, dir)
	return ""
}

// The measured hazard behind GOPROXY=file:///nonexistent (release.sh): a candidate
// is built from an untagged commit, the operator tags that commit, and the release
// built next must say v0.1.0 and release=true. With GOPROXY=off the toolchain
// stamped the earlier pseudo-version on the tagged commit.
func TestRelease_CandidateThenTagStampsTheTag(t *testing.T) {
	repo := newRepo(t, "")
	out1 := filepath.Join(t.TempDir(), "cand")
	if o, code := release(t, repo, "--candidate", "--changes-for", "v0.1.0", "--out", out1); code != 0 {
		t.Fatalf("candidate: exit %d\n%s", code, o)
	}
	mustRun(t, repo, relGitEnv(), "git", "tag", "-a", "v0.1.0", "-m", "tag the candidate's commit")
	out2 := filepath.Join(t.TempDir(), "rel")
	o, code := release(t, repo, "--out", out2)
	if code != 0 || !strings.Contains(o, "the release v0.1.0 PASSED") {
		t.Fatalf("the release after a candidate of the same commit: exit %d\n%s", code, o)
	}
	files, _ := untar(t, filepath.Join(out2, "pveforge-v0.1.0-linux-amd64.tar.gz"))
	p := filepath.Join(t.TempDir(), "pveforge")
	_ = os.WriteFile(p, files["pveforge-v0.1.0-linux-amd64/pveforge"], 0o755)
	if v := versionOf(t, p); v["release"] != "true" || v["version"] != "v0.1.0" {
		t.Fatalf("the release built after a candidate says %v", v)
	}
}
