package sourceguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stage14 reaches the outer API with NO harness_init: it sources lib.sh only
// for read_outer_identity, which it calls as its second statement (before arg
// parsing and before any apiget/ssh/unlock.sh). These tests are the stage14 leg
// of the (b) invariant — a lib-only or verify-root-only test would lie-green
// this third caller. The marker is the "Stage 14 destructive proof" banner,
// which is logged only AFTER arg validation and evidence setup, i.e. well after
// the reader: a bad outer site file must never reach it, and must make zero
// ssh/pveforge calls.
const stage14Banner = "Stage 14 destructive proof"

// stage14World sets up a HOME + PATH + a full set of required env so that, with
// a VALID outer env, execution gets PAST the reader and the arg checks into the
// body (reaching the banner). outerEnv "" = the committed example; "missing" =
// none; anything else = that body. It returns (combinedOutput, exitCode, sshLog,
// pveforgeLog).
func runStage14(t *testing.T, outerEnv string, args ...string) (string, int, string, string) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join(harnessDir, "stage14-destructive-proof.sh"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	cfg := filepath.Join(home, ".config", "pveforge")
	logDir := filepath.Join(tmp, "log")
	binDir := filepath.Join(tmp, "bin")
	for _, d := range []string{cfg, logDir, binDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	switch outerEnv {
	case "missing":
	case "":
		writeFile(t, filepath.Join(cfg, "harness-outer.env"), exampleOuterEnv(t), 0o600)
	default:
		writeFile(t, filepath.Join(cfg, "harness-outer.env"), outerEnv, 0o600)
	}
	// Logging fakes: if execution ever reaches the body, these record it.
	sshLog := filepath.Join(logDir, "ssh")
	pveforgeLog := filepath.Join(logDir, "pveforge")
	writeFile(t, filepath.Join(binDir, "ssh"), "#!/bin/sh\necho \"$@\" >>"+sshLog+"\nexit 0\n", 0o700)
	pveforge := filepath.Join(tmp, "fake-pveforge")
	writeFile(t, pveforge, "#!/bin/sh\necho \"$@\" >>"+pveforgeLog+"\nexit 0\n", 0o700)
	accept := filepath.Join(tmp, "fake-accept")
	writeFile(t, accept, "#!/bin/sh\nexit 0\n", 0o700)
	// Other required inputs (dummy): enough that a run which PASSES the reader
	// gets through arg validation into the body.
	roster := filepath.Join(cfg, "nested.toml")
	outerRosters := filepath.Join(cfg, outerRosterName)
	ageFile := filepath.Join(cfg, "age.key")
	for _, p := range []string{roster, outerRosters, ageFile} {
		writeFile(t, p, "# dummy\n", 0o600)
	}

	// A PATH holding bash and every tool lib.sh / stage14 resolve, plus binDir
	// for the fake ssh.
	seen := map[string]bool{}
	var dirs []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	add(binDir)
	for _, tool := range []string{"bash", "jq", "grep", "flock", "sha256sum", "stat", "mktemp", "mkdir", "sleep", "date", "tee", "seq", "readlink", "dirname", "timeout", "cat", "tr"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s is required to test stage14: %v", tool, err)
		}
		add(filepath.Dir(p))
	}

	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = []string{
		"PATH=" + strings.Join(dirs, ":"),
		"HOME=" + home,
		"PVEFORGE_BIN=" + pveforge,
		"HARNESS_ACCEPT_BIN=" + accept,
		"PVEFORGE_HARNESS_ROSTER=" + roster,
		"PVEFORGE_HARNESS_OUTER_ROSTERS=" + outerRosters,
		"PVEFORGE_HARNESS_AGE_IDENTITY_FILE=" + ageFile,
		"PVEFORGE_ROSTER_PASSPHRASE=not-a-secret",
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run stage14: %v", err)
	}
	readLog := func(p string) string {
		b, _ := os.ReadFile(p)
		return strings.TrimSpace(string(b))
	}
	return string(out), code, readLog(sshLog), readLog(pveforgeLog)
}

func TestStage14_OuterIdentityRefusesBeforeAnyNetwork(t *testing.T) {
	good := exampleOuterEnv(t)
	// Control: a VALID outer env passes the reader, so execution reaches the
	// arg checks that come AFTER it. An unknown argument is refused there,
	// before any network — proving the reader is not spuriously blocking a good
	// env, and that a good env alone does NOT enter the body. (--storage is no
	// longer a usable control: with no flag it now defaults to the site file's
	// OUTER_STORAGE, so a valid env + no --storage would enter the body.)
	out, code, sshLog, _ := runStage14(t, good, "--bogus")
	if code != 2 || !strings.Contains(out, "unknown argument") {
		t.Fatalf("control: a valid outer env did not pass the reader into arg validation (exit %d):\n%s", code, out)
	}
	if strings.Contains(out, stage14Banner) {
		t.Fatalf("control reached the body on an unknown argument:\n%s", out)
	}
	if sshLog != "" {
		t.Fatalf("control made ssh calls before arg validation:\n%s", sshLog)
	}

	for _, tc := range []struct{ name, outerEnv, wantErr string }{
		{"env missing", "missing", "harness-outer.env does not exist"},
		{"unknown key", good + "\nOUTER_BOGUS=x\n", "unknown key OUTER_BOGUS"},
		{"OUTER_NODE missing", strings.Replace(good, "OUTER_NODE=qa-pve-07\n", "", 1), "OUTER_NODE is missing"},
		{"VMID band inverted", exampleOuterEnv(t, "VMID_LOW=700", "VMID_HIGH=699"), "must be VMID_LOW + 9"},
		{"VMID oversized", exampleOuterEnv(t, "VMID_LOW=6900000000", "VMID_HIGH=6900000009"), "is not a valid value"},
		{"FQDN not under node", exampleOuterEnv(t, "OUTER_FQDN=other.lab.quantum.com"), "does not begin with OUTER_NODE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Full args: a deferred/removed reader would then proceed past arg
			// validation into the body (reaching the banner / a network call),
			// which these assertions catch.
			out, code, sshLog, pveforgeLog := runStage14(t, tc.outerEnv, "--storage", "pveforge-harness", "--iters", "1")
			if code != 2 {
				t.Errorf("exit %d, want 2 (refuse before any network)\n%s", code, out)
			}
			if !strings.Contains(out, tc.wantErr) {
				t.Errorf("output lacks %q:\n%s", tc.wantErr, out)
			}
			if strings.Contains(out, stage14Banner) {
				t.Errorf("stage14 reached the body on a bad outer env (refuse-before-network broken):\n%s", out)
			}
			if sshLog != "" {
				t.Errorf("stage14 made ssh calls on a bad outer env:\n%s", sshLog)
			}
			if pveforgeLog != "" {
				t.Errorf("stage14 made pveforge calls on a bad outer env:\n%s", pveforgeLog)
			}
		})
	}
}
