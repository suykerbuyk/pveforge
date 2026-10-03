package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// errPromptStop is what a recording prompt returns when told to stop the
// run there.
var errPromptStop = errors.New("recording prompt: stop here")

// promptLog records every secret a command asked for, in order.
type promptLog struct{ calls []string }

// recordPrompts replaces every secret prompt (bootstrap's passphrase
// resolver, the other commands' passphrase prompt, the PVE password) and
// import-token's secret read with recorders. Every call is logged; the one named stopAt returns
// errPromptStop, the others a valid value, so a prompt reached out of
// order is visible in the log whatever the run does next.
//
// MUST STAY SERIAL: it swaps package-level seams.
func recordPrompts(t *testing.T, stopAt string) *promptLog {
	t.Helper()
	l := &promptLog{}
	origP, origW, origB := promptRosterPassphrase, promptPVEPassword, bootstrapPassphrase
	origIn, origTerm := importStdin, importStdinIsTerminal
	t.Cleanup(func() {
		promptRosterPassphrase, promptPVEPassword, bootstrapPassphrase = origP, origW, origB
		importStdin, importStdinIsTerminal = origIn, origTerm
	})
	record := func(name, value string) (string, error) {
		l.calls = append(l.calls, name)
		if name == stopAt {
			return "", errPromptStop
		}
		return value, nil
	}
	promptRosterPassphrase = func(context.Context) (string, error) { return record("passphrase", rosterPassphrase) }
	bootstrapPassphrase = func(context.Context, string) (string, error) { return record("passphrase", rosterPassphrase) }
	promptPVEPassword = func(context.Context) (string, error) { return record("password", "pw") }
	importStdinIsTerminal = func() bool { return false }
	importStdin = func() io.Reader {
		return readerFunc(func(p []byte) (int, error) {
			if _, err := record("secret", ""); err != nil {
				return 0, err
			}
			return 0, io.EOF
		})
	}
	return l
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

const earlyFP = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

// earlyRoster holds one target per mode, each with a token so the
// passphrase proves: ins (insecure_tls, no pins), keyed (insecure_tls, SSH
// pin), ca (CA-verified) and ins-pinned (insecure_tls, TLS pin, no SSH).
func earlyRoster(t *testing.T) string {
	t.Helper()
	t.Cleanup(roster.SetScryptWorkFactorForTests(10))
	rp := filepath.Join(t.TempDir(), "roster.toml")
	if err := os.WriteFile(rp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pass := roster.NewPassphrase(rosterPassphrase)
	for _, tg := range []roster.Target{
		{ID: "ins", Host: "h1", Node: "n1", InsecureTLS: true},
		{ID: "keyed", Host: "h2", Node: "n2", InsecureTLS: true},
		{ID: "ca", Host: "h3", Node: "n3"},
		{ID: "ins-pinned", Host: "h4", Node: "n4", InsecureTLS: true},
	} {
		if err := roster.AppendTarget(rp, tg); err != nil {
			t.Fatal(err)
		}
		if err := roster.WriteTokenAuth(rp, tg.ID, roster.TokenWrite{TokenID: "root@pam!pveforge", SecretPlaintext: []byte("s")}, pass); err != nil {
			t.Fatal(err)
		}
	}
	kp, err := sshexec.GenerateEd25519Keypair("keyed")
	if err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteSSHAuth(rp, "keyed", roster.SSHWrite{User: "root", PublicKey: kp.AuthorizedKeyLine, HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PrivateKeyPlaintext: kp.PrivateKeyPEM}, pass); err != nil {
		t.Fatal(err)
	}
	if err := roster.WriteTLSPin(rp, "ins-pinned", "", testTLSPin, tlspin.SourceExpect, pass); err != nil {
		t.Fatal(err)
	}
	return rp
}

type earlyRow struct {
	name string
	args []string
	want string
}

func runEarlyRows(t *testing.T, rows []earlyRow) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			l := recordPrompts(t, "")
			code, _, stderr := runRootArgs(row.args...)
			if code == 0 || !strings.Contains(stderr, row.want) {
				t.Fatalf("exit %d, stderr %q; want the refusal %q", code, stderr, row.want)
			}
			if len(l.calls) != 0 {
				t.Fatalf("refused only after asking for %q: %q", l.calls, stderr)
			}
		})
	}
}

// Every bootstrap refusal that needs no secret comes before ANY prompt:
// neither the roster passphrase nor the PVE password is asked for.
func TestBootstrap_RefusalsNeedingNoSecretPromptForNothing(t *testing.T) {
	rp := earlyRoster(t)
	b := func(args ...string) []string {
		return append([]string{"bootstrap", args[0], "--roster", rp, "--grant", "/:PVEVMAdmin::1"}, args[1:]...)
	}
	runEarlyRows(t, []earlyRow{
		{"B′, insecure_tls from the flag", b("new", "--host", "h", "--node", "n", "--insecure-tls"), bootstrap.ErrHostKeyFingerprintRequired.Error()},
		{"B′, insecure_tls from the roster only", b("ins"), bootstrap.ErrHostKeyFingerprintRequired.Error()},
		{"--ssh-tofu with a fingerprint", b("ins", "--ssh-tofu", "--host-key-fingerprint", earlyFP), "contradict each other"},
		{"--ssh-tofu on a CA-verified target", b("ca", "--ssh-tofu"), "applies only to an insecure_tls target"},
		{"--ssh-tofu against a stored SSH pin", b("keyed", "--ssh-tofu"), "holds a pinned SSH host key"},
		{"--reprovisioned with --ssh-tofu", b("keyed", "--reprovisioned", "--ssh-tofu"), "does not apply with --reprovisioned"},
		{"--reprovisioned without a fingerprint", b("keyed", "--reprovisioned"), bootstrap.ErrReprovisionNeedsFingerprint.Error()},
		{"--reprovisioned with nothing to replace", b("ins", "--reprovisioned", "--host-key-fingerprint", earlyFP), bootstrap.ErrNothingToReprovision.Error()},
		{"a new target without --host", b("new", "--node", "n"), "host is required"},
		{"a login that is not @pam", b("ca", "--pve-user", "ops@pve"), "only @pam realm users"},
		{"an owner PVE would not accept, defaulted from the login", b("ca", "--pve-user", "a:b@pam"), bootstrap.ErrInvalidTokenOwner.Error()},
		{"an empty --token-id", b("ca", "--token-id", ""), "token id is required"},
		{"--no-ssh-key on a keyed target, no fingerprint (B′)", b("keyed", "--no-ssh-key"), bootstrap.ErrHostKeyFingerprintRequired.Error()},
		{"--no-ssh-key on a target holding an SSH key", b("keyed", "--no-ssh-key", "--host-key-fingerprint", earlyFP), bootstrap.ErrKeylessWithPersistedSSH.Error()},
		{"a keyless target without --no-ssh-key", b("ins-pinned", "--host-key-fingerprint", earlyFP), bootstrap.ErrKeylessTargetNeedsFlag.Error()},
		{"a held token another principal owns", b("ca", "--pve-user", "ops@pam"), bootstrap.ErrTokenOwnerMismatch.Error()},
		{"a fingerprint that is not the stored pin", b("keyed", "--host-key-fingerprint", earlyFP), "is not the host key this target is pinned to"},
		{"a roster that does not exist", []string{"bootstrap", "new", "--roster", filepath.Join(t.TempDir(), "none.toml"), "--grant", "/:PVEVMAdmin::1", "--host", "h", "--node", "n"}, "create it first"},
	})
}

// import-token's TLS refusals come before the passphrase and the secret.
func TestImportToken_RefusalsNeedingNoSecretPromptForNothing(t *testing.T) {
	rp := earlyRoster(t)
	imp := func(args ...string) []string {
		return append([]string{"roster", "import-token", args[0], "--roster", rp, "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser"}, args[1:]...)
	}
	runEarlyRows(t, []earlyRow{
		{"unpinned, insecure_tls from the flag", imp("new", "--host", "h", "--node", "n", "--insecure-tls"), pve.ErrTLSPinRequired.Error()},
		{"unpinned, insecure_tls from the roster only", imp("ins"), pve.ErrTLSPinRequired.Error()},
		{"--expect differs from the stored pin", imp("ins-pinned", "--expect", "sha256//"+strings.Repeat("B", 43)+"="), bootstrap.ErrTLSPinDiffers.Error()},
		{"a new target without --host", imp("new", "--node", "n"), "--host and --node are required"},
		{"a roster that does not exist", []string{"roster", "import-token", "new", "--roster", filepath.Join(t.TempDir(), "none.toml"), "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser", "--host", "h", "--node", "n"}, "create it first"},
	})
}

// A roster whose directory cannot take the write is refused before any
// prompt, by bootstrap and import-token alike, for a target the roster
// holds (roster.DryRunTokenWrite) and a new one (roster.ProbeRosterDir).
func TestRefusalsNeedingNoSecret_UnwritableRosterPromptsForNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory, so the refusal cannot arise")
	}
	rp := earlyRoster(t)
	dir := filepath.Dir(rp)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	runEarlyRows(t, []earlyRow{
		{"bootstrap", []string{"bootstrap", "keyed", "--roster", rp, "--grant", "/:PVEVMAdmin::1"}, "not writable"},
		{"import-token", []string{"roster", "import-token", "ins-pinned", "--roster", rp, "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser"}, "not writable"},
		{"bootstrap, a new target", []string{"bootstrap", "new", "--roster", rp, "--grant", "/:PVEVMAdmin::1", "--host", "h", "--node", "n"}, "not writable"},
		{"import-token, a new target", []string{"roster", "import-token", "new", "--roster", rp, "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser", "--host", "h", "--node", "n"}, "not writable"},
	})
}

// The pre-check refuses nothing it should let through: each of these runs
// is one a refusal row sits next to, and it must reach the first prompt.
func TestBootstrap_PreCheckPassesWhatItMustNotRefuse(t *testing.T) {
	rp := earlyRoster(t)
	b := func(args ...string) []string {
		return append([]string{"bootstrap", args[0], "--roster", rp, "--grant", "/:PVEVMAdmin::1"}, args[1:]...)
	}
	for _, row := range []struct {
		name string
		args []string
	}{
		{"a deliberate --token-owner change", b("ca", "--no-ssh-key", "--token-owner", "alice@pve")},
		{"a --host-key-fingerprint equal to the stored pin", b("keyed", "--host-key-fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		{"--reprovisioned with a new fingerprint", b("keyed", "--reprovisioned", "--host-key-fingerprint", earlyFP)},
		{"a new target", b("new", "--host", "h", "--node", "n")},
	} {
		t.Run(row.name, func(t *testing.T) {
			l := recordPrompts(t, "passphrase")
			code, _, stderr := runRootArgs(row.args...)
			if code == 0 || !strings.Contains(stderr, errPromptStop.Error()) {
				t.Fatalf("exit %d, stderr %q; want the run stopped at the passphrase recorder", code, stderr)
			}
			if !slices.Equal(l.calls, []string{"passphrase"}) {
				t.Fatalf("prompts %q, want [passphrase]", l.calls)
			}
		})
	}
}

// The roster named by PVEFORGE_ROSTER, not --roster, is the one each
// pre-check reads: its fields alone decide these refusals.
func TestRefusalsNeedingNoSecret_ReadTheEnvironmentsRoster(t *testing.T) {
	rp := earlyRoster(t)
	t.Setenv("PVEFORGE_ROSTER", rp)
	runEarlyRows(t, []earlyRow{
		{"bootstrap, B′ from the roster only", []string{"bootstrap", "ins", "--grant", "/:PVEVMAdmin::1"}, bootstrap.ErrHostKeyFingerprintRequired.Error()},
		{"import-token, unpinned from the roster only", []string{"roster", "import-token", "ins", "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser"}, pve.ErrTLSPinRequired.Error()},
		{"pin-tls, a CA-verified target without --expect", []string{"roster", "pin-tls", "ca"}, "pinned only explicitly"},
	})
}

// pin-tls's mode refusals come before the passphrase.
func TestPinTLS_RefusalsNeedingNoSecretPromptForNothing(t *testing.T) {
	rp := earlyRoster(t)
	pin := func(args ...string) []string {
		return append([]string{"roster", "pin-tls", args[0], "--roster", rp}, args[1:]...)
	}
	other := "sha256//" + strings.Repeat("B", 43) + "="
	runEarlyRows(t, []earlyRow{
		{"a CA-verified target without --expect", pin("ca"), "pinned only explicitly"},
		{"--repin on a CA-verified target", pin("ca", "--expect", other, "--repin"), "--repin needs an insecure_tls target"},
		{"--expect on a target with SSH auth", pin("keyed", "--expect", other), "drop --expect"},
		{"--repin without SSH auth", pin("ins", "--repin"), "--repin needs SSH auth"},
		{"no SSH auth and no --expect", pin("ins"), "no SSH auth to capture its key over"},
		{"a target the roster lacks", pin("nope", "--expect", other), "no such target"},
	})
}

// Anti-vacuity: a run no refusal stops asks through the recorders, each
// exactly once and in order. Without this, a command that bypassed a seam
// (asking through the real prompt) would leave every zero-call assertion
// above green.
func TestPromptRecorders_AreTheSeamsTheCommandsUse(t *testing.T) {
	rp := earlyRoster(t)
	for _, tc := range []struct {
		name, stopAt string
		args         []string
		want         []string
	}{
		{"bootstrap", "password", []string{"bootstrap", "keyed", "--roster", rp, "--grant", "/:PVEVMAdmin::1"}, []string{"passphrase", "password"}},
		// The held token's owner, named outright: the login differs, so an
		// owner the pre-check did not see would default to it and refuse.
		{"bootstrap, the held token's owner named", "password", []string{"bootstrap", "keyed", "--roster", rp, "--grant", "/:PVEVMAdmin::1", "--pve-user", "ops@pam", "--token-owner", "root@pam"}, []string{"passphrase", "password"}},
		{"import-token", "secret", []string{"roster", "import-token", "ins-pinned", "--roster", rp, "--token-id", "ops@pve!ci", "--grant", "/vms/100:PVEVMUser"}, []string{"passphrase", "secret"}},
		{"pin-tls", "passphrase", []string{"roster", "pin-tls", "keyed", "--roster", rp}, []string{"passphrase"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := recordPrompts(t, tc.stopAt)
			code, _, stderr := runRootArgs(tc.args...)
			if code == 0 || !strings.Contains(stderr, errPromptStop.Error()) {
				t.Fatalf("exit %d, stderr %q; want the run stopped at the %s recorder", code, stderr, tc.stopAt)
			}
			if !slices.Equal(l.calls, tc.want) {
				t.Fatalf("prompts %q, want %q", l.calls, tc.want)
			}
		})
	}
}
