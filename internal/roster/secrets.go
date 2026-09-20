package roster

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/term"
)

// scryptWorkFactorOverride, when non-zero, is the scrypt work factor (log2 N)
// EncryptString writes instead of age's own default. Zero means "leave age's
// default alone", which is exactly what EncryptString did before this seam
// existed, by never calling SetWorkFactor at all — so production behaviour is
// unchanged by construction, not merely by intent.
//
// WHY THIS EXISTS. age's default work factor is 18, which costs about 0.8s
// per derivation on this project's reference host and about 6.3s under the
// race detector. internal/bootstrap's tests perform 79 derivations and
// internal/roster's 35, which between them set `make test`'s wall clock.
// Neither package can be fixed by a _test.go fixture, because more than half
// of those derivations happen inside production code under test. Only a
// production-side seam reaches them.
//
// WHY THAT IS SAFE. Four layers, and each has a mutant in
// internal/roster/kdf_seam_test.go and kdf_guard_test.go that must kill it:
// the runtime gate below; a module-wide static guard that forbids every name
// involved outside this one file; kdf_guard_test.go pinning EncryptString's
// output at exactly 18 over a table of inputs; and the blast radius, which is
// ciphertext a test writes into its own t.TempDir() and nothing else.
//
// WHAT THOSE FOUR LAYERS DO NOT COVER. They are not exhaustive, and the gap
// below was MEASURED rather than reasoned about — a guarantee stated without
// its limit is worth less than no guarantee, because the next reader budgets
// against it.
//
// What they do buy: no ORDINARY Go reference to this variable, to
// SetScryptWorkFactorForTests, or to setScryptWorkFactor survives in a
// non-test file. The static guard walks every non-test file in the module
// and matches bare identifiers and qualified selectors, resolving the
// qualifier through each file's own imports — so renaming the import, or
// reaching the var from a second file in this package, is caught. That was
// attacked across seven vectors during review; six were blocked.
//
// What they do not buy: a deliberate //go:linkname defeats all four. A
// non-test file anywhere else in the module that imports unsafe and writes
//
//	//go:linkname knob github.com/suykerbuyk/pveforge/internal/roster.scryptWorkFactorOverride
//	var knob int
//
// can then assign knob and lower the work factor in a binary built by
// `go build`. Measured: go build rc=0, the resulting binary emits scrypt
// logN 10, and TestSeam_NoProductionReferences, go vet and make lint are all
// rc=0. The runtime gate never fires because neither setter is ever called;
// the static guard never fires because the directive is a COMMENT, which no
// AST walk sees, and `import _ "unsafe"` binds no identifier to match on.
//
// Two things bound that, and both were executed rather than assumed:
//
//   - Naming the local alias scryptWorkFactorOverride IS caught. The guard
//     matches the alias declaration itself as a bare identifier, so the lazy
//     form of this evasion fails and the working one has to rename the alias
//     on purpose.
//   - kdf_guard_test.go still catches it whenever the offending file lands in
//     a package that internal/roster's own test binary links, because that
//     guard observes the process it runs in: it reports
//     "scryptWorkFactorOverride = 10 at rest, want 0". The escape therefore
//     needs BOTH a renamed alias AND a package outside that test binary, such
//     as a cmd/.
//
// This is not closeable by an AST-based guard, and it is a general property
// of every source guard in this repo rather than anything specific to this
// seam — but this seam is what creates the target, since before it there was
// no variable to link against, so the caveat belongs with the guarantee.
// pveforge-golinkname-defeats-source-guards owns the text-scan instrument
// that would close it.
var scryptWorkFactorOverride = 0

// SetScryptWorkFactorForTests lowers the scrypt work factor EncryptString
// writes, process-wide, restoring the previous value via the returned func
// (call it, typically via t.Cleanup or a TestMain, once the test is done).
//
// It PANICS unless called from a binary built by `go test`, so the seam is
// inert in a shipped pveforge no matter who calls it.
// internal/roster/testdata/weakprobe is a non-test `package main` that calls
// it, and TestSeam_WeakProbeIsRejectedOutsideATestBinary runs that probe with
// `go run` and requires it to die — because a gate nobody has watched refuse
// has not been shown to refuse.
//
// Production code must never call this. That is not left to convention:
// TestSeam_NoProductionReferences forbids this name, setScryptWorkFactor,
// scryptWorkFactorOverride, any SetWorkFactor selector and
// age.NewScryptRecipient in every non-test file in the module except this
// one.
//
// Not safe for two test packages to use concurrently — it mutates
// process-wide state with no locking, matching pve.SetSSHPortForIntegrationTests
// (routed.go:29-49), whose caveat and shape this deliberately copies. Each
// package's tests run in their own process, so the hazard is only ever
// intra-package: TestNoParallelTests in this package and in internal/bootstrap
// pins that neither uses t.Parallel.
//
// COST OF THE testing IMPORT, measured rather than asserted, because
// "production code imports testing" is the kind of thing a later reader
// reverts on reflex: the pveforge binary grows 10,860 bytes, from 18,526,958
// to 18,537,818 (0.06%). It adds testing and runtime/trace to the binary's
// dependency graph; flag and regexp were already there. No test.* flags
// appear in `pveforge --help`, and the binary contains no "test.v" string,
// because testing.Init is never called outside a test binary.
func SetScryptWorkFactorForTests(logN int) (restore func()) {
	return setScryptWorkFactor(logN, testing.Testing())
}

// setScryptWorkFactor holds the whole decision, with the "am I in a test
// binary" answer PASSED IN rather than read, for one reason: the refusal
// branch is then reachable from an ordinary in-process test, so it is covered
// by the suite rather than only by a subprocess whose coverage the profile
// never sees. A gate weakened to make coverage green is not a gate, and a
// gate with no coverage at all is not one either.
//
// The subprocess probe still earns its place: it is the only thing that
// proves testing.Testing() really is false in a non-test binary, which no
// in-process test can show.
func setScryptWorkFactor(logN int, inTestBinary bool) (restore func()) {
	if !inTestBinary {
		panic("roster: SetScryptWorkFactorForTests called outside a test binary")
	}
	// age.SetWorkFactor panics outside [1,30] with a message that names
	// neither this function nor the caller; 0 would silently mean "no
	// override" given the sentinel above; and anything above 20 is slower
	// than production, which no test wants. 18 stays legal so a test can
	// pin production's own value explicitly.
	if logN < 1 || logN > 20 {
		panic(fmt.Sprintf("roster: SetScryptWorkFactorForTests: logN %d out of range [1,20]", logN))
	}
	orig := scryptWorkFactorOverride
	scryptWorkFactorOverride = logN
	return func() { scryptWorkFactorOverride = orig }
}

// EncryptString encrypts plaintext with a scrypt (passphrase-based) age
// recipient and returns ASCII-armored ciphertext, suitable for embedding
// verbatim as a TOML multi-line literal string value.
func EncryptString(plaintext []byte, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("build scrypt recipient: %w", err)
	}
	// The only SetWorkFactor call in non-test code in this module, and the
	// static guard in kdf_seam_test.go pins that. Guarded by != 0 rather
	// than by a bool so the zero value IS the production configuration:
	// dropping the condition calls SetWorkFactor(0), which age refuses.
	if scryptWorkFactorOverride != 0 {
		recipient.SetWorkFactor(scryptWorkFactorOverride)
	}

	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return "", fmt.Errorf("start age encryption: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", fmt.Errorf("write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalize age stream: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", fmt.Errorf("finalize armor: %w", err)
	}
	return buf.String(), nil
}

// DecryptString reverses EncryptString.
func DecryptString(armored string, passphrase string) ([]byte, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("build scrypt identity: %w", err)
	}
	ar := armor.NewReader(strings.NewReader(armored))
	r, err := age.Decrypt(ar, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted plaintext: %w", err)
	}
	return out, nil
}

// ResolvePassphrase reads the roster's master passphrase from
// PVEFORGE_ROSTER_PASSPHRASE, falling back to an interactive terminal
// prompt. It errors rather than hanging when neither is available, so
// pveforge stays safe to invoke from scripts, cron, and CI.
func ResolvePassphrase() (string, error) {
	if v, ok := os.LookupEnv(PassphraseEnvVar); ok && v != "" {
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no roster passphrase available: set %s or run interactively", PassphraseEnvVar)
	}
	fmt.Fprint(os.Stderr, "Roster passphrase: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty passphrase")
	}
	return string(b), nil
}

// ResolvedTarget is a short-lived, in-memory view of a Target with its
// secrets decrypted. It is never serialized back to disk — only the
// splice-writer (writeback.go) writes to the roster file, and only with
// freshly produced ciphertext.
type ResolvedTarget struct {
	Target
	TokenSecret   []byte
	SSHPrivateKey []byte
}

// Resolve decrypts t's secrets using passphrase.
func (t *Target) Resolve(passphrase string) (*ResolvedTarget, error) {
	rt := &ResolvedTarget{Target: *t}
	if t.Token != nil {
		pt, err := DecryptString(t.Token.SecretEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt token secret for %q: %w", t.ID, err)
		}
		rt.TokenSecret = pt
	}
	if t.SSH != nil {
		pt, err := DecryptString(t.SSH.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt ssh private key for %q: %w", t.ID, err)
		}
		rt.SSHPrivateKey = pt
	}
	return rt, nil
}
