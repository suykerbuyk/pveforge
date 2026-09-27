package roster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/gofrs/flock"
)

// rekeyRoster writes a roster with a comment and a TLS pin that must
// survive a rekey byte for byte: target a holds an SSH key and a token,
// b a token, c nothing. Every secret is sealed under pass, unless odd names
// a "target/sub" sealed under "other" instead. It returns the path and the
// plaintext of each secret, keyed "target/key".
func rekeyRoster(t *testing.T, pass string, odd ...string) (string, map[string]string) {
	t.Helper()
	withTestWorkFactor(t)
	plain := map[string]string{}
	seal := func(id, sub, key string) string {
		p := pass
		for _, o := range odd {
			if o == id+"/"+sub {
				p = "other"
			}
		}
		text := "plain-" + id + "-" + sub
		plain[id+"/"+key] = text
		return sampleArmored(t, text, p)
	}
	var b strings.Builder
	b.WriteString("# a comment the rekey must keep\n\n")
	fmt.Fprintf(&b, "[[targets]]\nid = \"a\"\nhost = \"h-a\"\nnode = \"n-a\"\ninsecure_tls = true\n\n")
	fmt.Fprintf(&b, "[targets.ssh]\nuser = \"root\"\npublic_key = \"ssh-ed25519 AAAA pveforge@a\"\nhost_key_fingerprint = \"SHA256:%s\"\nprivate_key_enc = '''\n%s'''\nhost_key_source = \"ssh-verified\"\n\n", strings.Repeat("A", 43), seal("a", "ssh", "private_key_enc"))
	fmt.Fprintf(&b, "[targets.token]\nid = \"root@pam!t\"\nsecret_enc = '''\n%s'''\n\n", seal("a", "token", "secret_enc"))
	fmt.Fprintf(&b, "[targets.tls]\nspki_sha256 = \"sha256//%s=\"\nsource = \"ssh-verified\"\n\n", strings.Repeat("B", 43))
	fmt.Fprintf(&b, "[[targets]]\nid = \"b\"\nhost = \"h-b\"\nnode = \"n-b\"\n\n[targets.token]\nid = \"ops@pve!ci\"\nsecret_enc = '''\n%s'''\n\n", seal("b", "token", "secret_enc"))
	b.WriteString("[[targets]]\nid = \"c\"\nhost = \"h-c\"\nnode = \"n-c\"\n")
	return writeTempRoster(t, b.String()), plain
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rosterSecrets is each secret's ciphertext in the roster at path, keyed
// "target/key".
func rosterSecrets(t *testing.T, path string) map[string]string {
	t.Helper()
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, tg := range r.Targets {
		if tg.SSH != nil && tg.SSH.PrivateKeyEnc != "" {
			out[tg.ID+"/private_key_enc"] = tg.SSH.PrivateKeyEnc
		}
		if tg.Token != nil && tg.Token.SecretEnc != "" {
			out[tg.ID+"/secret_enc"] = tg.Token.SecretEnc
		}
	}
	return out
}

// stripSecrets blanks every armored block, so two rosters can be compared
// byte for byte on everything else.
func stripSecrets(b []byte) string {
	var out []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "-----BEGIN AGE"):
			in = true
		case strings.HasPrefix(l, "-----END AGE"):
			in = false
			out = append(out, "<secret>")
		case !in:
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// TestRekey_RoundTrip: every secret moves to the new passphrase with its
// plaintext intact and no longer opens with the old one; every other byte
// of the file (a comment, the pins, the sources, the mode) is kept.
func TestRekey_RoundTrip(t *testing.T) {
	path, plain := rekeyRoster(t, "old")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	res, err := Rekey(path, "old", "new")
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if res.Secrets != 3 || res.Targets != 2 {
		t.Errorf("result %+v, want 3 secrets over 2 targets", res)
	}
	after := mustRead(t, path)
	if stripSecrets(after) != stripSecrets(before) {
		t.Errorf("bytes other than the secrets changed:\nbefore:\n%s\nafter:\n%s", stripSecrets(before), stripSecrets(after))
	}
	got := rosterSecrets(t, path)
	if len(got) != len(plain) {
		t.Fatalf("secrets after = %d, want %d", len(got), len(plain))
	}
	for k, enc := range got {
		p, err := DecryptString(enc, "new")
		if err != nil || string(p) != plain[k] {
			t.Errorf("%s: new passphrase opens %q, %v; want %q", k, p, err, plain[k])
		}
		if _, err := DecryptString(enc, "old"); !errors.Is(err, age.ErrIncorrectIdentity) {
			t.Errorf("%s: the old passphrase still opens it (err %v)", k, err)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Errorf("mode after = %v (%v), want 0640 kept", info.Mode().Perm(), err)
	}
	// A rekey back restores what the operator had, and the new passphrase is
	// now the one every writer proves.
	if _, err := ProvePassphrase(path, "a", "old"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("the old passphrase still proves against the rekeyed roster: %v", err)
	}
	if _, err := ProvePassphrase(path, "a", "new"); err != nil {
		t.Errorf("the new passphrase does not prove: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".pveforge-roster-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

// TestRekey_RefusalsWriteNothing: each refusal leaves the file byte-identical
// and names why.
func TestRekey_RefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name      string
		odd       []string
		old, next string
		want      error
		mention   string
	}{
		{"wrong old passphrase", nil, "wrong", "new", ErrWrongPassphrase, ""},
		{"partly readable", []string{"b/token"}, "old", "new", ErrPartlyReadable, "token secret of target b"},
		{"new equals old", nil, "old", "old", ErrSameNewPassphrase, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, _ := rekeyRoster(t, "old", c.odd...)
			before := mustRead(t, path)
			_, err := Rekey(path, c.old, c.next)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.mention != "" && !strings.Contains(err.Error(), c.mention) {
				t.Errorf("err %q does not name %q", err, c.mention)
			}
			if !bytes.Equal(mustRead(t, path), before) {
				t.Error("a refused rekey changed the file")
			}
		})
	}
	t.Run("empty new passphrase", func(t *testing.T) {
		path, _ := rekeyRoster(t, "old")
		before := mustRead(t, path)
		if _, err := Rekey(path, "old", ""); err == nil {
			t.Fatal("an empty new passphrase was accepted")
		}
		if !bytes.Equal(mustRead(t, path), before) {
			t.Error("a refused rekey changed the file")
		}
	})
	t.Run("nothing to rekey", func(t *testing.T) {
		path := writeTempRoster(t, "[[targets]]\nid = \"c\"\nhost = \"h\"\nnode = \"n\"\n")
		before := mustRead(t, path)
		if _, err := Rekey(path, "old", "new"); !errors.Is(err, ErrNothingToRekey) {
			t.Fatalf("err = %v, want ErrNothingToRekey", err)
		}
		if !bytes.Equal(mustRead(t, path), before) {
			t.Error("a refused rekey changed the file")
		}
	})
}

// TestRekey_FailedReplaceLeavesTheOldFile: a replacement that fails (a
// crash between composing and renaming, a full disk) leaves the old file,
// which still opens with the old passphrase.
func TestRekey_FailedReplaceLeavesTheOldFile(t *testing.T) {
	path, plain := rekeyRoster(t, "old")
	before := mustRead(t, path)
	orig := rekeyWriteFn
	t.Cleanup(func() { rekeyWriteFn = orig })
	calls := 0
	rekeyWriteFn = func(p string, data []byte) error {
		calls++
		// What a crash mid-write leaves: a partial temp file beside it.
		_ = os.WriteFile(filepath.Join(filepath.Dir(p), ".pveforge-roster-crash.tmp"), data[:len(data)/2], 0o600)
		return errors.New("disk full")
	}
	if _, err := Rekey(path, "old", "new"); err == nil || !strings.Contains(err.Error(), "the old file is unchanged") {
		t.Fatalf("err = %v, want the replacement's failure", err)
	}
	if calls != 1 {
		t.Fatalf("the replacement ran %d times, want 1: the test did not reach it", calls)
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Fatal("a failed replacement changed the roster")
	}
	for k, enc := range rosterSecrets(t, path) {
		if p, err := DecryptString(enc, "old"); err != nil || string(p) != plain[k] {
			t.Errorf("%s no longer opens with the old passphrase: %v", k, err)
		}
	}
}

// TestRekey_RefusesAFileChangedMeanwhile: the compare-and-set. A roster
// changed between the read and the replacement (by a writer that skips the
// lock, or a hand edit) is refused and kept as it now is.
func TestRekey_RefusesAFileChangedMeanwhile(t *testing.T) {
	path, _ := rekeyRoster(t, "old")
	orig := rekeyComposed
	t.Cleanup(func() { rekeyComposed = orig })
	var edited []byte
	rekeyComposed = func() {
		edited = append(mustRead(t, path), []byte("# edited meanwhile\n")...)
		if err := os.WriteFile(path, edited, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Rekey(path, "old", "new"); !errors.Is(err, ErrRosterChanged) {
		t.Fatalf("err = %v, want ErrRosterChanged", err)
	}
	if edited == nil || !bytes.Equal(mustRead(t, path), edited) {
		t.Error("the file is not the one the concurrent edit wrote")
	}
}

// TestRekey_TakesTheRosterLock: while another writer holds the roster lock,
// rekey waits, then gives up without writing.
func TestRekey_TakesTheRosterLock(t *testing.T) {
	path, _ := rekeyRoster(t, "old")
	before := mustRead(t, path)
	orig := rekeyLockTimeout
	t.Cleanup(func() { rekeyLockTimeout = orig })
	rekeyLockTimeout = 300 * time.Millisecond
	held := flock.New(path + ".lock")
	if err := held.Lock(); err != nil {
		t.Fatal(err)
	}
	defer held.Unlock()
	_, err := Rekey(path, "old", "new")
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for another pveforge process") {
		t.Fatalf("err = %v, want a lock timeout", err)
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Error("rekey wrote while another process held the roster lock")
	}
	held.Unlock()
	if _, err := Rekey(path, "old", "new"); err != nil {
		t.Errorf("rekey after the lock was released: %v", err)
	}
}

// TestVerifyRekey_RefusesEachWrongResult: the check before replacing
// refuses a composed file that changed anything but the ciphertexts, or
// whose new ciphertext is not the one composed, or does not open.
func TestVerifyRekey_RefusesEachWrongResult(t *testing.T) {
	path, plain := rekeyRoster(t, "old")
	data := mustRead(t, path)
	current, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	good, _, err := rekeySecrets(data, current, "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	gr, err := Decode(good)
	if err != nil {
		t.Fatal(err)
	}
	encs := map[string]string{}
	for _, tg := range gr.Targets {
		if tg.SSH != nil {
			encs[tg.ID+"/private_key_enc"] = tg.SSH.PrivateKeyEnc
		}
		if tg.Token != nil {
			encs[tg.ID+"/secret_enc"] = tg.Token.SecretEnc
		}
	}
	want := func(id, key string) ([]byte, string) { return []byte(plain[id+"/"+key]), encs[id+"/"+key] }
	if err := verifyRekey(current, good, "new", want); err != nil {
		t.Fatalf("the good result was refused: %v", err)
	}
	other := sampleArmored(t, "plain-b-token", "other")
	// Opens with the new passphrase to the right plaintext, but is not the
	// ciphertext this rekey composed: something else wrote it.
	foreign := sampleArmored(t, "plain-b-token", "new")
	for name, bad := range map[string][]byte{
		"a host changed":         bytes.Replace(good, []byte(`host = "h-b"`), []byte(`host = "h-x"`), 1),
		"a pin changed":          bytes.Replace(good, []byte("sha256//B"), []byte("sha256//C"), 1),
		"a target dropped":       good[:bytes.LastIndex(good, []byte("[[targets]]"))],
		"a token id changed":     bytes.Replace(good, []byte("ops@pve!ci"), []byte("ops@pve!cj"), 1),
		"a secret under another": bytes.Replace(good, []byte(encs["b/secret_enc"]), []byte(other), 1),
		"a secret not composed":  bytes.Replace(good, []byte(encs["b/secret_enc"]), []byte(foreign), 1),
		"a secret left as it was": bytes.Replace(good, []byte(encs["b/secret_enc"]),
			[]byte(rosterSecrets(t, path)["b/secret_enc"]), 1),
	} {
		if bytes.Equal(bad, good) {
			t.Fatalf("%s: the fixture edit did not apply", name)
		}
		if err := verifyRekey(current, bad, "new", want); err == nil {
			t.Errorf("%s: verifyRekey accepted it", name)
		}
	}
	// The plaintext check itself: a ciphertext that opens with the new
	// passphrase but holds another plaintext.
	swapped := sampleArmored(t, "not the old plaintext", "new")
	encs["b/secret_enc"] = swapped
	bad := bytes.Replace(good, []byte(gr.Targets[1].Token.SecretEnc), []byte(swapped), 1)
	if err := verifyRekey(current, bad, "new", want); err == nil || !strings.Contains(err.Error(), "does not hold the old plaintext") {
		t.Errorf("a new secret with another plaintext: %v", err)
	}
}

// TestRekey_SealsAtTheProductionWorkFactor: a rekeyed secret is sealed at
// the roster's production scrypt work factor, not a lowered one.
func TestRekey_SealsAtTheProductionWorkFactor(t *testing.T) {
	restore := SetScryptWorkFactorForTests(testWorkFactor)
	enc := sampleArmored(t, "s", "old") // cheap to open, for the rekey's own decrypt
	restore()
	if scryptWorkFactorOverride != 0 {
		t.Fatalf("override %d after restore, want production (0)", scryptWorkFactorOverride)
	}
	path := writeTempRoster(t, fmt.Sprintf("[[targets]]\nid = \"b\"\nhost = \"h\"\nnode = \"n\"\n\n[targets.token]\nid = \"ops@pve!ci\"\nsecret_enc = '''\n%s'''\n", enc))
	if _, err := Rekey(path, "old", "new"); err != nil {
		t.Fatal(err)
	}
	logN, found := scryptWorkFactor(t, rosterSecrets(t, path)["b/secret_enc"])
	if !found || logN != productionScryptWorkFactor {
		t.Errorf("rekeyed at logN %d (found %v), want %d", logN, found, productionScryptWorkFactor)
	}
}

// TestCheckRekey: the refusals a command makes before it asks for a new
// passphrase.
func TestCheckRekey(t *testing.T) {
	path, _ := rekeyRoster(t, "old")
	if err := CheckRekey(path, "old"); err != nil {
		t.Errorf("the right passphrase: %v", err)
	}
	if err := CheckRekey(path, "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("a wrong passphrase: %v, want ErrWrongPassphrase", err)
	}
	empty := writeTempRoster(t, "[[targets]]\nid = \"c\"\nhost = \"h\"\nnode = \"n\"\n")
	if err := CheckRekey(empty, "old"); !errors.Is(err, ErrNothingToRekey) {
		t.Errorf("a roster with no secret: %v, want ErrNothingToRekey", err)
	}
}

// withPrompts makes stdin a terminal whose successive reads return entries,
// and counts the reads.
func withPrompts(t *testing.T, terminal bool, entries ...string) *int {
	t.Helper()
	reads := 0
	withTermSeams(t, func(int) ([]byte, error) {
		if reads >= len(entries) {
			return nil, errors.New("no more entries")
		}
		reads++
		return []byte(entries[reads-1]), nil
	})
	orig := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = orig })
	stdinIsTerminal = func(int) bool { return terminal }
	return &reads
}

// TestResolvePassphraseForWrite_ConfirmsOnlyTheFirst: a roster with no
// secret asks twice and refuses two entries that differ; a roster holding
// one asks once; the environment is taken as given.
func TestResolvePassphraseForWrite_ConfirmsOnlyTheFirst(t *testing.T) {
	t.Setenv(PassphraseEnvVar, "")
	empty := writeTempRoster(t, "[[targets]]\nid = \"c\"\nhost = \"h\"\nnode = \"n\"\n")
	held, _ := rekeyRoster(t, "old")

	reads := withPrompts(t, true, "first", "first")
	if p, err := ResolvePassphraseForWriteContext(context.Background(), empty); err != nil || p != "first" || *reads != 2 {
		t.Errorf("new roster, same twice: %q, %v after %d reads; want first after 2", p, err, *reads)
	}
	reads = withPrompts(t, true, "first", "frist")
	if _, err := ResolvePassphraseForWriteContext(context.Background(), empty); !errors.Is(err, ErrPassphraseMismatch) || *reads != 2 {
		t.Errorf("new roster, entries differ: %v after %d reads; want ErrPassphraseMismatch after 2", err, *reads)
	}
	reads = withPrompts(t, true, "old", "old")
	if p, err := ResolvePassphraseForWriteContext(context.Background(), held); err != nil || p != "old" || *reads != 1 {
		t.Errorf("roster with a secret: %q, %v after %d reads; want old after 1", p, err, *reads)
	}
	reads = withPrompts(t, true, "x", "x")
	t.Setenv(PassphraseEnvVar, "from-env")
	if p, err := ResolvePassphraseForWriteContext(context.Background(), empty); err != nil || p != "from-env" || *reads != 0 {
		t.Errorf("environment: %q, %v after %d reads; want from-env and no prompt", p, err, *reads)
	}
}

// TestReadNewPassphrase: a terminal only, twice, equal, non-empty; the
// environment variable is never read for it.
func TestReadNewPassphrase(t *testing.T) {
	t.Setenv(PassphraseEnvVar, "from-env")
	withPrompts(t, false, "n", "n")
	if _, err := ReadNewPassphraseContext(context.Background()); !errors.Is(err, ErrNewPassphraseNeedsTerminal) {
		t.Errorf("no terminal: %v, want ErrNewPassphraseNeedsTerminal (the environment is never used)", err)
	}
	reads := withPrompts(t, true, "n", "n")
	if p, err := ReadNewPassphraseContext(context.Background()); err != nil || p != "n" || *reads != 2 {
		t.Errorf("same twice: %q, %v after %d reads", p, err, *reads)
	}
	withPrompts(t, true, "n", "m")
	if _, err := ReadNewPassphraseContext(context.Background()); !errors.Is(err, ErrPassphraseMismatch) {
		t.Errorf("entries differ: %v, want ErrPassphraseMismatch", err)
	}
	withPrompts(t, true, "", "")
	if _, err := ReadNewPassphraseContext(context.Background()); err == nil {
		t.Error("an empty new passphrase was accepted")
	}
}

// TestRekey_ChecksWhatItSplices: Rekey runs its check on the bytes it is
// about to write. A splice that also changes a host is refused, with the
// file unchanged.
func TestRekey_ChecksWhatItSplices(t *testing.T) {
	path, _ := rekeyRoster(t, "old")
	before := mustRead(t, path)
	orig := rekeyApplyEdits
	t.Cleanup(func() { rekeyApplyEdits = orig })
	rekeyApplyEdits = func(data []byte, edits []edit) ([]byte, error) {
		out, err := orig(data, edits)
		return bytes.Replace(out, []byte(`host = "h-b"`), []byte(`host = "h-x"`), 1), err
	}
	_, err := Rekey(path, "old", "new")
	if err == nil || !strings.Contains(err.Error(), "safety check failed, roster left untouched") {
		t.Fatalf("err = %v, want the check's refusal", err)
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Error("a composed file that failed its check was written")
	}
}
