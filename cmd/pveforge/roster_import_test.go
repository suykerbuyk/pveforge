package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// importCase is one `pveforge roster import-token` run's fixtures: a roster
// file, a scripted validator, the secret on a counted stdin pipe, and a
// transport seam that counts constructions. An import holds no transport:
// bootstrap's remove path needs one, so a transport constructed at all
// means the import reached for it.
type importCase struct {
	rosterPath string
	v          *recordingValidator
	transports int
	stdinReads int
}

type recordingValidator struct {
	cfgs []bootstrap.APIConfig
	errs []error
}

func (r *recordingValidator) ValidateTokenGrants(_ context.Context, cfg bootstrap.APIConfig, _ []bootstrap.Grant) error {
	r.cfgs = append(r.cfgs, cfg)
	if i := len(r.cfgs) - 1; i < len(r.errs) {
		return r.errs[i]
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n *int
}

func (c countingReader) Read(p []byte) (int, error) {
	*c.n++
	return c.r.Read(p)
}

// newImportCase installs the seams for one test. stdin supplies input; the
// validator answers with errs (nil once they run out).
func newImportCase(t *testing.T, errs ...error) *importCase {
	t.Helper()
	c := &importCase{v: &recordingValidator{errs: errs}}
	// An import really encrypts the secret; at the production work factor
	// that costs seconds per write. The test-only seam lowers it, restoring
	// the value captured on entry.
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	c.rosterPath = filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(c.rosterPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVEFORGE_ROSTER", c.rosterPath)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	origT, origV, origIn, origTTY := newBootstrapTransport, newBootstrapValidator, importStdin, importStdinIsTerminal
	newBootstrapTransport = func() bootstrap.SSHTransport { c.transports++; return &fakeBootstrapTransport{} }
	newBootstrapValidator = func() bootstrap.APIValidator { return c.v }
	importStdinIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		newBootstrapTransport, newBootstrapValidator, importStdin, importStdinIsTerminal = origT, origV, origIn, origTTY
	})
	return c
}

// run runs `pveforge roster import-token qa-imp …args` with input on stdin.
func (c *importCase) run(input string, args ...string) (int, string, string) {
	importStdin = func() io.Reader { return countingReader{strings.NewReader(input), &c.stdinReads} }
	return runRootArgs(append([]string{"roster", "import-token", "qa-imp"}, args...)...)
}

func (c *importCase) rosterBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(c.rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// requireNoRemovePath is the no-remove rule: an import never constructs a
// transport, so bootstrap's remove path (pveum user token remove, over SSH)
// is out of its reach.
func (c *importCase) requireNoRemovePath(t *testing.T) {
	t.Helper()
	if c.transports != 0 {
		t.Errorf("an import constructed %d SSH transport(s): it must never reach bootstrap's remove path", c.transports)
	}
}

var importArgs = []string{"--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser", "--host", "h.example", "--node", "n1"}

const importSecret = "s3cr3t-UNIQUE-4242"

// I1: a piped secret is validated as the token, then persisted; the roster
// it leaves is readable by the existing commands.
func TestRosterImportToken_I1_ImportsAValidatedToken(t *testing.T) {
	c := newImportCase(t)
	code, stdout, stderr := c.run(importSecret+"\n", importArgs...)
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"target=qa-imp", "token_id=ops@pve!ci", "token_outcome=imported", "validation=verified"} {
		if !strings.Contains(stdout, want+"\n") {
			t.Errorf("stdout %q lacks %q", stdout, want)
		}
	}
	if len(c.v.cfgs) != 1 || c.v.cfgs[0].TokenSecret != importSecret || c.v.cfgs[0].TokenID != "ops@pve!ci" {
		t.Fatalf("validated with %+v", c.v.cfgs)
	}
	r, err := roster.Load(c.rosterPath)
	if err != nil {
		t.Fatal(err)
	}
	tg := r.Find("qa-imp")
	if tg == nil || tg.Token == nil || tg.Token.ID != "ops@pve!ci" || tg.Host != "h.example" || tg.Node != "n1" {
		t.Fatalf("roster target = %+v", tg)
	}
	secret, err := roster.DecryptString(tg.Token.SecretEnc, rosterPassphrase)
	if err != nil || string(secret) != importSecret {
		t.Errorf("stored secret = %q, %v; want exactly the piped secret, trailing newline stripped", secret, err)
	}
	if code, _, stderr := runRootArgs("roster", "validate", c.rosterPath); code != 0 {
		t.Errorf("roster validate after import: exit %d, %q", code, stderr)
	}
	c.requireNoRemovePath(t)
}

// I2: a terminal stdin, or a secret that cannot be one, is refused; nothing
// is validated or written.
func TestRosterImportToken_I2_RefusesATerminalAndBadSecrets(t *testing.T) {
	t.Run("terminal", func(t *testing.T) {
		c := newImportCase(t)
		importStdinIsTerminal = func() bool { return true }
		before := c.rosterBytes(t)
		code, _, stderr := c.run(importSecret, importArgs...)
		if code != 1 || !strings.Contains(stderr, "is a terminal") {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if c.stdinReads != 0 || len(c.v.cfgs) != 0 || !bytes.Equal(before, c.rosterBytes(t)) {
			t.Errorf("stdin reads %d, validations %d, roster changed %v", c.stdinReads, len(c.v.cfgs), !bytes.Equal(before, c.rosterBytes(t)))
		}
	})
	for name, input := range map[string]string{
		"empty":            "",
		"only a newline":   "\n",
		"inner whitespace": "s3cr3t with space\n",
		"a tab":            "s3cr3t\twith-tab",
		"two lines":        "s3cr3t\nsecond\n",
		"too long":         strings.Repeat("x", bootstrap.MaxImportedSecretLen+1),
	} {
		t.Run(name, func(t *testing.T) {
			c := newImportCase(t)
			before := c.rosterBytes(t)
			code, _, stderr := c.run(input, importArgs...)
			if code != 1 || !strings.Contains(stderr, "invalid token secret") {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if len(c.v.cfgs) != 0 || !bytes.Equal(before, c.rosterBytes(t)) {
				t.Errorf("validations %d, roster changed %v", len(c.v.cfgs), !bytes.Equal(before, c.rosterBytes(t)))
			}
			if trimmed := strings.TrimSpace(input); len(trimmed) > 3 && len(trimmed) < 100 && strings.Contains(stderr, trimmed) {
				t.Errorf("stderr %q echoes the secret", stderr)
			}
		})
	}
}

// I3: no --grant is refused before stdin is read.
func TestRosterImportToken_I3_RequiresAGrantBeforeReadingTheSecret(t *testing.T) {
	c := newImportCase(t)
	code, _, stderr := c.run(importSecret, "--token-id", "ops@pve!ci", "--host", "h.example", "--node", "n1")
	if code != 1 || !strings.Contains(stderr, "--grant") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if c.stdinReads != 0 || len(c.v.cfgs) != 0 {
		t.Errorf("stdin reads %d, validations %d; want neither", c.stdinReads, len(c.v.cfgs))
	}
}

// I4: every validation failure — verdict or not — writes nothing and
// removes nothing: no transport is ever constructed.
func TestRosterImportToken_I4_FailureWritesNothingAndRemovesNothing(t *testing.T) {
	for name, errs := range map[string][]error{
		"verdict: scope too wide":               {bootstrap.ErrScopeTooWide},
		"retried verdict: wrong scope":          {bootstrap.ErrWrongScope, bootstrap.ErrWrongScope, bootstrap.ErrWrongScope},
		"non-verdict: unverifiable permissions": {io.ErrUnexpectedEOF},
	} {
		t.Run(name, func(t *testing.T) {
			c := newImportCase(t, errs...)
			before := c.rosterBytes(t)
			code, stdout, stderr := c.run(importSecret+"\n", importArgs...)
			if code != 1 {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if !strings.Contains(stdout, "token_outcome=not_imported\n") {
				t.Errorf("stdout %q, want token_outcome=not_imported", stdout)
			}
			if strings.Contains(stderr, "was persisted") {
				t.Errorf("stderr %q claims a persisted token", stderr)
			}
			if !bytes.Equal(before, c.rosterBytes(t)) {
				t.Error("the roster changed")
			}
			c.requireNoRemovePath(t)
		})
	}
}

// I5: the secret appears nowhere but encrypted in the roster: not in stdout,
// stderr, the error line, the roster's plaintext, or the process's args;
// and it has no flag and no environment fallback.
func TestRosterImportToken_I5_TheSecretNeverLeaks(t *testing.T) {
	for name, errs := range map[string][]error{"success": nil, "verdict": {bootstrap.ErrScopeTooWide}} {
		t.Run(name, func(t *testing.T) {
			c := newImportCase(t, errs...)
			_, stdout, stderr := c.run(importSecret+"\n", importArgs...)
			for where, s := range map[string]string{"stdout": stdout, "stderr": stderr, "roster": string(c.rosterBytes(t)), "args": strings.Join(os.Args, " ")} {
				if strings.Contains(s, importSecret) {
					t.Errorf("%s contains the secret", where)
				}
			}
		})
	}
	// RI2: a validator error that ECHOES the secret (PVE or a proxy echoing
	// the Authorization header) must not bring it to stderr.
	for name, echo := range map[string]error{
		"echoing verdict":     fmt.Errorf("%w: pve returned 400: Authorization: PVEAPIToken=ops@pve!ci=%s", bootstrap.ErrScopeTooWide, importSecret),
		"echoing non-verdict": fmt.Errorf("proxy returned 502: Authorization: PVEAPIToken=ops@pve!ci=%s", importSecret),
	} {
		t.Run(name, func(t *testing.T) {
			c := newImportCase(t, echo)
			code, stdout, stderr := c.run(importSecret+"\n", importArgs...)
			if code != 1 {
				t.Fatalf("exit %d", code)
			}
			if strings.Contains(stdout, importSecret) || strings.Contains(stderr, importSecret) {
				t.Errorf("the secret reached the output: stdout %q stderr %q", stdout, stderr)
			}
			if !strings.Contains(stderr, "<redacted>") {
				t.Errorf("stderr %q: want the echoed secret shown as <redacted>", stderr)
			}
		})
	}
	t.Run("no flag names a secret", func(t *testing.T) {
		cmd := newRosterImportTokenCmd()
		for _, f := range []string{"secret", "token-secret", "password"} {
			if cmd.Flags().Lookup(f) != nil {
				t.Errorf("import-token has a --%s flag: the secret comes from stdin only", f)
			}
		}
	})
	t.Run("no environment fallback", func(t *testing.T) {
		c := newImportCase(t)
		t.Setenv("PVEFORGE_TOKEN_SECRET", importSecret)
		t.Setenv("PVEFORGE_IMPORT_SECRET", importSecret)
		code, _, stderr := c.run("", importArgs...)
		if code != 1 || !strings.Contains(stderr, "invalid token secret") || len(c.v.cfgs) != 0 {
			t.Fatalf("empty stdin with a secret in the environment: exit %d, stderr %q, validations %d; want the empty stdin refused", code, stderr, len(c.v.cfgs))
		}
	})
}

// I6: a different held token is refused without --replace; with it, the
// new token is written and the old one reported still live, not revoked.
func TestRosterImportToken_I6_ReplaceOrphansNeverRevokes(t *testing.T) {
	c := newImportCase(t)
	if code, _, stderr := c.run(importSecret+"\n", importArgs...); code != 0 {
		t.Fatalf("first import: %q", stderr)
	}
	before := c.rosterBytes(t)
	other := []string{"--token-id", "ops@pve!ci2", "--grant", "/vms/100:PVEVMUser"}

	code, _, stderr := c.run("s3cr3t-other-0002\n", other...)
	if code != 1 || !strings.Contains(stderr, "already holds a different token") || !bytes.Equal(before, c.rosterBytes(t)) {
		t.Fatalf("without --replace: exit %d, stderr %q, roster changed %v", code, stderr, !bytes.Equal(before, c.rosterBytes(t)))
	}

	code, stdout, stderr := c.run("s3cr3t-other-0002\n", append(other, "--replace")...)
	if code != 0 || !strings.Contains(stdout, "orphaned_token=ops@pve!ci\n") {
		t.Fatalf("with --replace: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := "warning: token ops@pve!ci is still live on PVE with its grants but is no longer held by this roster\n"; stderr != want {
		t.Errorf("stderr = %q, want exactly %q", stderr, want)
	}
	c.requireNoRemovePath(t)
}

// I7: importing the token already held is a no-op.
func TestRosterImportToken_I7_SameTokenIsAlreadyHeld(t *testing.T) {
	c := newImportCase(t)
	if code, _, stderr := c.run(importSecret+"\n", importArgs...); code != 0 {
		t.Fatalf("first import: %q", stderr)
	}
	before := c.rosterBytes(t)
	code, stdout, stderr := c.run(importSecret+"\n", "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser")
	if code != 0 || !strings.Contains(stdout, "token_outcome=already_held\n") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !bytes.Equal(before, c.rosterBytes(t)) {
		t.Error("already_held rewrote the roster")
	}
}

// I8: the import takes bootstrap's own per-target lock, bounded by
// --lock-wait; while another run holds it, nothing is validated or written.
func TestRosterImportToken_I8_HonoursTheBootstrapLock(t *testing.T) {
	c := newImportCase(t)
	unlock, err := lock.Mutation(context.Background(), c.rosterPath, lock.ObjectKey{TargetID: "qa-imp", Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	before := c.rosterBytes(t)
	start := time.Now()
	code, _, stderr := c.run(importSecret+"\n", append(importArgs, "--lock-wait", "150ms")...)
	if code != 1 || !strings.Contains(stderr, "timed out waiting for the lock") || !strings.Contains(stderr, "qa-imp/bootstrap/token") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if time.Since(start) > 2*time.Second || len(c.v.cfgs) != 0 || !bytes.Equal(before, c.rosterBytes(t)) {
		t.Errorf("took %v, validations %d, roster changed %v", time.Since(start), len(c.v.cfgs), !bytes.Equal(before, c.rosterBytes(t)))
	}
}

// I9: a target id the roster would refuse is refused before stdin is read.
func TestRosterImportToken_I9_LineUnsafeTargetRefusedFirst(t *testing.T) {
	c := newImportCase(t)
	importStdin = func() io.Reader { return countingReader{strings.NewReader(importSecret), &c.stdinReads} }
	code, _, stderr := runRootArgs(append([]string{"roster", "import-token", "qa\nimp"}, importArgs...)...)
	if code != 1 || !strings.Contains(stderr, `target id "qa\nimp"`) || c.stdinReads != 0 {
		t.Fatalf("exit %d, stderr %q, stdin reads %d", code, stderr, c.stdinReads)
	}
}

// I10: an imported target holds a token and no SSH key, so a later plain
// bootstrap is refused as keyless, in words that name the import.
func TestRosterImportToken_I10_PlainBootstrapOfAnImportedTargetIsRefused(t *testing.T) {
	c := newImportCase(t)
	if code, _, stderr := c.run(importSecret+"\n", importArgs...); code != 0 {
		t.Fatalf("import: %q", stderr)
	}
	t.Setenv(pvePasswordEnvVar, "test-pve-pass")
	tr := &fakeBootstrapTransport{}
	newBootstrapTransport = func() bootstrap.SSHTransport { return tr }
	// The imported token's own owner and name, so bootstrap's identity check
	// (which runs first) passes and the keyless one is what answers.
	code, _, stderr := runRootArgs("bootstrap", "qa-imp", "--token-owner", "ops@pve", "--token-id", "ci", "--grant", "/vms/100:PVEVMUser")
	if code != 1 || !strings.Contains(stderr, "its token was imported") || !strings.Contains(stderr, "--no-ssh-key") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if tr.calls != 0 {
		t.Errorf("the refused bootstrap dialed SSH %d time(s)", tr.calls)
	}
}
