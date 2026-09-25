package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// These tests drive the real binary (and hack/harness/unlock.sh) with
// throwaway keys, and prove from outside the process that a secret reaches
// the child's environment and nothing else: not its argv
// (/proc/<pid>/cmdline), and not the disk (every directory the helper could
// write to, scanned byte for byte).

// childVar makes this test binary act as the child `run` execs.
const childVar = "PVEFORGE_HARNESS_TEST_CHILD"

var helperBin string

func TestMain(m *testing.M) {
	switch os.Getenv(childVar) {
	case "report":
		// Ready; wait for the test to look at /proc; then report the
		// secret's hash and exit 7, which `run` must pass through.
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		sum := sha256.Sum256([]byte(os.Getenv("PVEFORGE_ROSTER_PASSPHRASE")))
		fmt.Println("pass-sha=" + hex.EncodeToString(sum[:]))
		os.Exit(7)
	case "leak":
		// The scanner's control: a child that DOES write the secret.
		_ = os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "leak.txt"), []byte(os.Getenv("PVEFORGE_ROSTER_PASSPHRASE")), 0o600)
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "harness-secrets-bin-")
	if err != nil {
		panic(err)
	}
	helperBin = filepath.Join(dir, "pveforge-harness-secrets")
	if out, err := exec.Command("go", "build", "-o", helperBin, ".").CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build the helper: %v\n%s", err, out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// sentinel is a fresh, unguessable secret value per test.
func sentinel(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sentinel-" + hex.EncodeToString(b)
}

// world is one test's filesystem: every directory the helper and its child
// could write to lives under root.
type world struct {
	root, harness, home, tmp, cache string
	identity                        string
}

func newWorld(t *testing.T) world {
	t.Helper()
	root := t.TempDir()
	w := world{root: root, harness: filepath.Join(root, "harness"), home: filepath.Join(root, "home"), tmp: filepath.Join(root, "tmp"), cache: filepath.Join(root, "cache")}
	for _, d := range []string{w.harness, w.home, w.tmp, w.cache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	w.identity = id.String()
	if err := os.WriteFile(filepath.Join(w.harness, "recipients.txt"), []byte(id.Recipient().String()+" # operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return w
}

// env is the helper's whole environment: nothing inherited but PATH.
func (w world) env(extra ...string) []string {
	return append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + w.home, "TMPDIR=" + w.tmp, "XDG_CACHE_HOME=" + w.cache}, extra...)
}

// scan returns the files under root holding needle.
func scan(t *testing.T, root, needle string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err == nil && bytes.Contains(b, []byte(needle)) {
			hits = append(hits, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func procFile(t *testing.T, pid int, name string) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seal runs `seal` with the plaintext on stdin, and checks the running
// process's argv while it waits for that stdin.
func seal(t *testing.T, w world, plain string, secret string) {
	t.Helper()
	cmd := exec.Command(helperBin, "--dir", w.harness, "seal")
	cmd.Env = w.env()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(procFile(t, cmd.Process.Pid, "cmdline"), secret) {
		t.Errorf("seal's argv carries the secret")
	}
	_, _ = io.WriteString(stdin, plain)
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("seal: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), secret) {
		t.Errorf("seal printed the secret: %q", out.String())
	}
}

func testBin(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun_TheSecretReachesTheChildEnvironmentOnly(t *testing.T) {
	w := newWorld(t)
	secret := sentinel(t)
	seal(t, w, "PVEFORGE_ROSTER_PASSPHRASE="+secret+"\n", secret)
	if hits := scan(t, w.root, secret); len(hits) != 0 {
		t.Fatalf("after seal, the secret is on disk in %q", hits)
	}

	child := testBin(t)
	cmd := exec.Command(helperBin, "--dir", w.harness, "run", "--", child)
	cmd.Env = w.env("PVEFORGE_HARNESS_AGE_IDENTITY="+w.identity, childVar+"=report")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(stdout)
	if line, _ := rd.ReadString('\n'); line != "ready\n" {
		t.Fatalf("the child did not start: %q, stderr %q", line, stderr.String())
	}
	pid := cmd.Process.Pid
	// The helper exec'd the child in place: the same pid now shows the
	// child's argv, with no secret in it.
	cmdline := procFile(t, pid, "cmdline")
	if cmdline != child+"\x00" {
		t.Errorf("/proc/%d/cmdline = %q, want the child's argv alone (%q): the helper did not exec in place", pid, cmdline, child)
	}
	if strings.Contains(cmdline, secret) {
		t.Errorf("the secret is in /proc/%d/cmdline", pid)
	}
	// The environment is the transport: the secret is there (the positive
	// control), the identity is not.
	environ := procFile(t, pid, "environ")
	if !strings.Contains(environ, "\x00PVEFORGE_ROSTER_PASSPHRASE="+secret+"\x00") && !strings.HasPrefix(environ, "PVEFORGE_ROSTER_PASSPHRASE="+secret+"\x00") {
		t.Errorf("the secret is not in the child's environment")
	}
	if strings.Contains(environ, "PVEFORGE_HARNESS_AGE_IDENTITY") || strings.Contains(environ, "AGE-SECRET-KEY") {
		t.Errorf("the identity reached the child's environment")
	}
	_ = stdin.Close()
	rest, _ := io.ReadAll(rd)
	err = cmd.Wait()
	sum := sha256.Sum256([]byte(secret))
	if want := "pass-sha=" + hex.EncodeToString(sum[:]) + "\n"; string(rest) != want {
		t.Errorf("child reported %q, want %q", rest, want)
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 7 {
		t.Errorf("exit = %v, want the child's own 7", err)
	}
	if strings.Contains(stderr.String(), secret) {
		t.Errorf("stderr carries the secret")
	}
	if hits := scan(t, w.root, secret); len(hits) != 0 {
		t.Errorf("after run, the secret is on disk in %q", hits)
	}

	// Anti-vacuity: the scanner finds a secret a child does write.
	leak := exec.Command(helperBin, "--dir", w.harness, "run", child)
	leak.Env = w.env("PVEFORGE_HARNESS_AGE_IDENTITY="+w.identity, childVar+"=leak")
	if out, err := leak.CombinedOutput(); err != nil {
		t.Fatalf("leak control: %v\n%s", err, out)
	}
	if hits := scan(t, w.root, secret); len(hits) != 1 || filepath.Base(hits[0]) != "leak.txt" {
		t.Errorf("the scanner missed the control's leak: %q", hits)
	}
}

// moduleCopy copies what unlock.sh needs to build the helper into a fresh
// tree: go.mod, go.sum, the helper's two packages and hack/harness.
func moduleCopy(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("..", "..")
	copyFile := func(rel string, perm os.FileMode) {
		b, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dst, filepath.Dir(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, rel), b, perm); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("go.mod", 0o644)
	copyFile("go.sum", 0o644)
	copyFile("hack/harness/unlock.sh", 0o755)
	copyFile("cmd/pveforge-harness-secrets/main.go", 0o644)
	entries, err := os.ReadDir(filepath.Join(src, "internal/harnesssecrets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			copyFile("internal/harnesssecrets/"+e.Name(), 0o644)
		}
	}
	return dst
}

func goEnv(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// unlock.sh end to end: it builds the helper and execs it, so the command's
// own exit status comes back (`go run` would turn it into 1), and the
// secret reaches the command.
func TestUnlockSh(t *testing.T) {
	root := moduleCopy(t)
	w := newWorld(t)
	harness := filepath.Join(root, "hack", "harness")
	if err := os.Rename(filepath.Join(w.harness, "recipients.txt"), filepath.Join(harness, "recipients.txt")); err != nil {
		t.Fatal(err)
	}
	env := w.env("GOMODCACHE="+goEnv(t, "GOMODCACHE"), "GOCACHE="+goEnv(t, "GOCACHE"), "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOWORK=off", "GOTOOLCHAIN=local")
	unlock := filepath.Join(harness, "unlock.sh")
	secret := sentinel(t)

	seal := exec.Command(unlock, "seal")
	seal.Env = env
	seal.Stdin = strings.NewReader("PVEFORGE_ROSTER_PASSPHRASE=" + secret + "\n")
	if out, err := seal.CombinedOutput(); err != nil {
		t.Fatalf("unlock.sh seal: %v\n%s", err, out)
	}

	run := exec.Command(unlock, "run", "--", "sh", "-c", `[ "$PVEFORGE_ROSTER_PASSPHRASE" = "$WANT" ] && [ -z "${PVEFORGE_HARNESS_AGE_IDENTITY+set}" ] && exit 7; exit 3`)
	run.Env = append(env, "PVEFORGE_HARNESS_AGE_IDENTITY="+w.identity, "WANT="+secret)
	out, err := run.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 7 {
		t.Errorf("unlock.sh run: %v (want exit 7: the secret present, the identity gone, the status passed through)\n%s", err, out)
	}

	status := exec.Command(unlock, "status")
	status.Env = append(env, "PVEFORGE_HARNESS_AGE_IDENTITY="+w.identity)
	out, err = status.CombinedOutput()
	if err != nil || string(out) != "recipients: 1 (operator)\nnames: PVEFORGE_ROSTER_PASSPHRASE\n" {
		t.Errorf("unlock.sh status: %v %q", err, out)
	}
	if hits := scan(t, root, secret); len(hits) != 0 {
		t.Errorf("the secret is on disk in %q", hits)
	}
	if hits := scan(t, w.root, secret); len(hits) != 0 {
		t.Errorf("the secret is on disk in %q", hits)
	}
}
