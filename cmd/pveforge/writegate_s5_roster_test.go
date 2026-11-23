package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// roster init / rekey / import-token / pin-tls and exec: local verbs. Their
// writes are roster writes (the third log); REST and SSH are said to be absent
// with noLog.

func localEnv(rosterPath string) writeEnv {
	return writeEnv{roster: rosterPath, restWrites: noLog, sshWrites: noLog}
}

func TestS5RosterInit_ExistingFileWithoutForceIs4_ForceTwinWrites(t *testing.T) {
	rp := filepath.Join(t.TempDir(), "pveforge.toml")
	if err := os.WriteFile(rp, []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := localEnv(rp)
	e.observe(t, "roster", "init", rp).wantRefusedBeforeAnyWrite(t)
	if b, _ := os.ReadFile(rp); string(b) != "# mine\n" {
		t.Fatalf("the refused init changed the file: %q", b)
	}
	// twin: past the write (with --force) the run is a success that WROTE, and is not a refusal
	o := e.observe(t, "roster", "init", "--force", rp)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 0 {
		t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
	}
}

func TestS5RosterRekey_WrongPassphraseIs4_RekeyTwinWrites(t *testing.T) {
	rp := rekeyCLIRoster(t, "pveforge.toml")
	e := localEnv(rp)
	withRekeyPrompts(t, "not-the-old-one", "new")
	e.observe(t, "roster", "rekey", "--roster", rp).wantRefusedBeforeAnyWrite(t)
	withRekeyPrompts(t, "old", "new")
	o := e.observe(t, "roster", "rekey", "--roster", rp)
	o.wantNotRefusedAfterWrite(t)
	if o.code != 0 {
		t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
	}
}

const s5ImpSeed = "[[targets]]\nid = \"qa-imp\"\nhost = \"h.example\"\nnode = \"n1\"\n"

func s5ImportRun(t *testing.T, e writeEnv, secret string, args ...string) writeObservation {
	t.Helper()
	importStdin = func() io.Reader { return strings.NewReader(secret) }
	return e.observe(t, append([]string{"roster", "import-token", "qa-imp"}, args...)...)
}

func newS5ImportEnv(t *testing.T, seed string, errs ...error) (writeEnv, *s5Validator) {
	t.Helper()
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	rp := filepath.Join(t.TempDir(), "pveforge.toml")
	if err := os.WriteFile(rp, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PVEFORGE_ROSTER", rp)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	v := &s5Validator{errs: errs}
	origT, origV, origIn, origTTY := newBootstrapTransport, newBootstrapValidator, importStdin, importStdinIsTerminal
	newBootstrapTransport = func() bootstrap.SSHTransport { return &fakeBootstrapTransport{} }
	newBootstrapValidator = func() bootstrap.APIValidator { return v }
	importStdinIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		newBootstrapTransport, newBootstrapValidator, importStdin, importStdinIsTerminal = origT, origV, origIn, origTTY
	})
	return localEnv(rp), v
}

// import-token: the refusals are 4 while the roster is untouched; the write is
// the roster's, and with a pre-existing target and no pin the ONLY roster write
// is writeTokenAuthFn's (F-A): its dispatch.Open is what makes the gate agree
// with the roster snapshot here.
func TestS5ImportToken_RefusalsAre4_TheTokenWriteIsAGatedRosterWrite(t *testing.T) {
	good := []string{"--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser"}
	t.Run("a verdict (scope too wide) before the first roster write: 4", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, s5ImpSeed, bootstrap.ErrScopeTooWide)
		s5ImportRun(t, e, importSecret+"\n", good...).wantRefusedBeforeAnyWrite(t)
	})
	t.Run("an unpinned insecure_tls target: 4, before the secret is read", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, strings.Replace(s5ImpSeed, "node = \"n1\"", "node = \"n1\"\ninsecure_tls = true", 1))
		s5ImportRun(t, e, importSecret+"\n", good...).wantRefusedBeforeAnyWrite(t)
	})
	t.Run("a validation READ that fails (not a verdict): 1, nothing written", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, s5ImpSeed, errors.New("proxy 502"))
		o := s5ImportRun(t, e, importSecret+"\n", good...)
		if o.code != 1 || o.wrote() {
			t.Fatalf("exit %d, rest=%q ssh=%q roster=%q; want 1 and no write", o.code, o.rest, o.ssh, o.rosterChanged)
		}
	})
	t.Run("the token write itself (F-A): exit 0, the roster changed AND the gate opened", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, s5ImpSeed)
		o := s5ImportRun(t, e, importSecret+"\n", good...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 || len(o.rosterChanged) != 1 {
			t.Fatalf("exit %d, roster changed %q, stderr %q", o.code, o.rosterChanged, o.stderr)
		}
	})
	t.Run("a new target: the target append, the pin and the token are each gated roster writes", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, "")
		o := s5ImportRun(t, e, importSecret+"\n", append(good, "--host", "h.example", "--node", "n1")...)
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
}

const s5PinSeed = "[[targets]]\nid = \"qa-imp\"\nhost = \"h.example\"\nnode = \"n1\"\n"

// pin-tls: refusals are 4 before the pin write; the pin write is a gated
// roster write.
func TestS5PinTLS_RefusalsAre4_TheWriteIsGated(t *testing.T) {
	cert := s5CertPEM(t, "pin")
	pin := s5PinOf(t, cert)
	other := s5PinOf(t, s5CertPEM(t, "other"))
	t.Run("a CA-verified target without --expect: 4", func(t *testing.T) {
		e, _ := newS5ImportEnv(t, s5PinSeed)
		e.observe(t, "roster", "pin-tls", "qa-imp").wantRefusedBeforeAnyWrite(t)
	})
	t.Run("the address serves another key than --expect: 4", func(t *testing.T) {
		e, v := newS5ImportEnv(t, s5PinSeed)
		v.served = other
		o := e.observe(t, "roster", "pin-tls", "qa-imp", "--expect", string(pin))
		o.wantRefusedBeforeAnyWrite(t)
		if !strings.Contains(o.stderr, bootstrap.ErrTLSPinMismatch.Error()) {
			t.Fatalf("not the mismatch refusal: %q", o.stderr)
		}
	})
	t.Run("a served-key READ failure is not a refusal: 1, nothing written", func(t *testing.T) {
		e, v := newS5ImportEnv(t, s5PinSeed)
		v.servedErr = errors.New("dial: connection refused")
		o := e.observe(t, "roster", "pin-tls", "qa-imp", "--expect", string(pin))
		if o.code != 1 || o.wrote() {
			t.Fatalf("exit %d, wrote %v; want 1 and nothing written", o.code, o.wrote())
		}
	})
	t.Run("the pin write: 0, the roster changed, the gate opened; and a different stored pin is then refused with the roster untouched", func(t *testing.T) {
		e, v := newS5ImportEnv(t, s5PinSeed)
		v.served = pin
		o := e.observe(t, "roster", "pin-tls", "qa-imp", "--expect", string(pin))
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
		v.served = other
		o = e.observe(t, "roster", "pin-tls", "qa-imp", "--expect", string(other))
		o.wantRefusedBeforeAnyWrite(t) // ErrTLSPinDiffers: refused, gate closed in THIS run
	})
}
