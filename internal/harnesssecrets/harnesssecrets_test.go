package harnesssecrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Throwaway keys only, made per test; nothing here touches a real identity.

const (
	secretPass   = "sentinel-pass-4e1f 'quoted' $HOME `x` = kept"
	secretNested = "sentinel-nested-9b2c"
)

func plaintext() string {
	return "# harness secrets\n\nPVEFORGE_ROSTER_PASSPHRASE=" + secretPass + "\nPVEFORGE_HARNESS_NESTED_ROOT_PASSWORD=" + secretNested + "\n"
}

type keypair struct {
	identity  string // the private identity, as age-keygen writes it
	recipient string
}

func newX25519(t *testing.T) keypair {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return keypair{"# created: test\n" + id.String() + "\n", id.Recipient().String()}
}

func newHybrid(t *testing.T) keypair {
	t.Helper()
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return keypair{id.String() + "\n", id.Recipient().String()}
}

// harnessDir makes a harness directory with recipients.txt for keys.
func harnessDir(t *testing.T, keys map[string]keypair) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("# test recipients\n\n")
	names := make([]string, 0, len(keys))
	for n := range keys {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		b.WriteString(keys[n].recipient + " # " + n + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// identityFile writes k's identity to a file of mode perm.
func identityFile(t *testing.T, k keypair, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(p, []byte(k.identity), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

type result struct {
	code           int
	stdout, stderr string
}

// runMain runs Main with stdin fed from in (a pipe, so never a terminal
// unless isTerminal is replaced).
func runMain(t *testing.T, environ []string, in string, args ...string) result {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = w.WriteString(in); _ = w.Close() }()
	defer r.Close()
	var out, errOut bytes.Buffer
	code := Main(args, environ, r, &out, &errOut)
	res := result{code, out.String(), errOut.String()}
	for _, s := range []string{secretPass, secretNested, "AGE-SECRET-KEY"} {
		if strings.Contains(res.stdout+res.stderr, s) {
			t.Errorf("output carries secret material %q:\nstdout %q\nstderr %q", s, res.stdout, res.stderr)
		}
	}
	return res
}

// captureExec replaces execve for the test and records its call.
type execCall struct {
	path      string
	argv, env []string
	called    bool
}

func captureExec(t *testing.T) *execCall {
	t.Helper()
	c := &execCall{}
	orig := execve
	t.Cleanup(func() { execve = orig })
	execve = func(path string, argv, env []string) error {
		c.path, c.argv, c.env, c.called = path, argv, env, true
		return errors.New("captured")
	}
	return c
}

func sealed(t *testing.T, dir, env string) {
	t.Helper()
	if res := runMain(t, nil, env, "--dir", dir, "seal"); res.code != 0 {
		t.Fatalf("seal: %+v", res)
	}
}

// --- the env grammar -----------------------------------------------------

func TestParseEnv(t *testing.T) {
	pairs, err := ParseEnv([]byte(plaintext()))
	if err != nil {
		t.Fatal(err)
	}
	want := []Pair{{"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD", secretNested}, {"PVEFORGE_ROSTER_PASSPHRASE", secretPass}}
	if !slices.Equal(pairs, want) {
		t.Errorf("pairs = %q, want %q (sorted, values verbatim)", pairs, want)
	}
	// A value keeps leading and trailing spaces and every '=' after the first.
	if p, err := ParseEnv([]byte("PVEFORGE_ROSTER_PASSPHRASE= a=b \n")); err != nil || p[0].Value != " a=b " {
		t.Errorf("verbatim value: %q, %v", p, err)
	}
	// Every refusal names a line, never its text: an operator who pastes a
	// bare password (no '=') must not see it echoed. Each row carries the
	// marker S3CR3T in the line it refuses.
	for name, in := range map[string]string{
		"a name not allowed":       "PATH=/tmp/S3CR3T\n",
		"LD_PRELOAD":               "LD_PRELOAD=/tmp/S3CR3T.so\n",
		"a lowercase name":         "pveforge_roster_passphrase=S3CR3T\n",
		"a CR in a comment":        "# S3CR3T\r\nPVEFORGE_ROSTER_PASSPHRASE=x\n",
		"a NUL in a comment":       "# S3CR3T\x00\nPVEFORGE_ROSTER_PASSPHRASE=x\n",
		"a CR":                     "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\r\n",
		"a NUL":                    "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\x00b\n",
		"not UTF-8":                "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\xff\n",
		"no '=' (a bare password)": "hunter2-S3CR3T\n",
		"an empty value":           "PVEFORGE_ROSTER_PASSPHRASE=\n# S3CR3T\n",
		"a tab":                    "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\tb\n",
		"an escape":                "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\x1b[31m\n",
		"a repeated name":          "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\nPVEFORGE_ROSTER_PASSPHRASE=S3CR3T\n",
		"no pair":                  "# S3CR3T\n\n",
		"a whitespace-only line":   "PVEFORGE_ROSTER_PASSPHRASE=a\n  S3CR3T\n",
		"export syntax":            "export PVEFORGE_ROSTER_PASSPHRASE=S3CR3T\n",
		"too large":                "PVEFORGE_ROSTER_PASSPHRASE=S3CR3T" + strings.Repeat("a", maxPlaintext) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseEnv([]byte(in))
			if !errors.Is(err, ErrInvalidEnv) {
				t.Fatalf("want ErrInvalidEnv, got %v", err)
			}
			if strings.Contains(err.Error(), "S3CR3T") || strings.Contains(err.Error(), "hunter2") {
				t.Errorf("the error echoes the input: %v", err)
			}
		})
	}
}

func TestAllowedNamesAreExactlyTheTwo(t *testing.T) {
	if want := []string{"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD", "PVEFORGE_ROSTER_PASSPHRASE"}; !slices.Equal(AllowedNames, want) {
		t.Errorf("AllowedNames = %q, want %q: adding a name is a reviewed change", AllowedNames, want)
	}
}

// --- recipients ------------------------------------------------------------

func TestParseRecipients(t *testing.T) {
	x, x2, h, h2 := newX25519(t), newX25519(t), newHybrid(t), newHybrid(t)
	rs, err := ParseRecipients([]byte("# c\n\n" + x.recipient + " # operator\n" + x2.recipient + "\t#\tci-runner-lab1\n"))
	if err != nil || len(rs) != 2 || rs[0].Name != "operator" || rs[1].Name != "ci-runner-lab1" {
		t.Fatalf("recipients = %+v, %v", rs, err)
	}
	if rs, err := ParseRecipients([]byte(h.recipient + " # operator\n" + h2.recipient + " # ci\n")); err != nil || len(rs) != 2 {
		t.Fatalf("hybrid recipients = %+v, %v", rs, err)
	}
	for name, in := range map[string]string{
		"no consumer name":         x.recipient + "\n",
		"an empty name":            x.recipient + " #\n",
		"an ssh key":               "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl # op\n",
		"a plugin recipient":       "age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t # yk\n",
		"a private identity":       strings.TrimSpace(strings.Split(x.identity, "\n")[1]) + " # oops\n",
		"a repeated recipient":     x.recipient + " # a\n" + x.recipient + " # b\n",
		"a repeated name":          x.recipient + " # a\n" + x2.recipient + " # a\n",
		"classic and hybrid mixed": x.recipient + " # a\n" + h.recipient + " # b\n",
		"comments only":            "# nobody yet\n",
		"a broken recipient":       "age1notarecipient # a\n",
		"a name with a space":      x.recipient + " # two words\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecipients([]byte(in)); !errors.Is(err, ErrInvalidRecipients) {
				t.Fatalf("want ErrInvalidRecipients, got %v", err)
			}
		})
	}
}

// --- identity sources -----------------------------------------------------

func TestLoadIdentities(t *testing.T) {
	x, h := newX25519(t), newHybrid(t)
	good := identityFile(t, x, 0o600)
	for name, tc := range map[string]struct {
		env []string
		ok  bool
	}{
		"the file, 0600":        {[]string{IdentityFileVar + "=" + good}, true},
		"the file, 0400":        {[]string{IdentityFileVar + "=" + identityFile(t, x, 0o400)}, true},
		"the content":           {[]string{IdentityVar + "=" + x.identity}, true},
		"a hybrid identity":     {[]string{IdentityVar + "=" + h.identity}, true},
		"both":                  {[]string{IdentityFileVar + "=" + good, IdentityVar + "=" + x.identity}, false},
		"both, one empty":       {[]string{IdentityFileVar + "=" + good, IdentityVar + "="}, false},
		"neither":               {[]string{"HOME=/x"}, false},
		"the file var empty":    {[]string{IdentityFileVar + "="}, false},
		"the content var empty": {[]string{IdentityVar + "="}, false},
		"the file, 0640":        {[]string{IdentityFileVar + "=" + identityFile(t, x, 0o640)}, false},
		"the file, 0604":        {[]string{IdentityFileVar + "=" + identityFile(t, x, 0o604)}, false},
		"the file, 0610":        {[]string{IdentityFileVar + "=" + identityFile(t, x, 0o610)}, false},
		"a missing file":        {[]string{IdentityFileVar + "=/nonexistent/key.txt"}, false},
		"a directory":           {[]string{IdentityFileVar + "=" + t.TempDir()}, false},
		"garbage content":       {[]string{IdentityVar + "=not a key"}, false},
		"a plugin identity":     {[]string{IdentityVar + "=AGE-PLUGIN-YUBIKEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQ"}, false},
		"a passphrase (scrypt)": {[]string{IdentityVar + "=hunter2"}, false},
		"content too large":     {[]string{IdentityVar + "=" + strings.Repeat("#", maxIdentity+1)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			ids, err := LoadIdentities(tc.env)
			if tc.ok != (err == nil) || (tc.ok && len(ids) != 1) {
				t.Fatalf("LoadIdentities = %d ids, %v; want ok=%t", len(ids), err, tc.ok)
			}
			if err != nil && (!errors.Is(err, ErrIdentity) || strings.Contains(err.Error(), "AGE-SECRET-KEY")) {
				t.Errorf("error %v: want ErrIdentity, never the key", err)
			}
		})
	}

	// Each source refusal says which rule refused it: a later parse failure
	// refusing too is not the same guard.
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{[]string{IdentityFileVar + "=" + good, IdentityVar + "=" + x.identity}, "both"},
		{[]string{IdentityFileVar + "=" + good, IdentityVar + "="}, "both"},
		{[]string{"HOME=/x"}, "neither"},
		{[]string{IdentityFileVar + "="}, IdentityFileVar + " is set but empty"},
		{[]string{IdentityVar + "="}, IdentityVar + " is set but empty"},
	} {
		if _, err := LoadIdentities(tc.env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("LoadIdentities(%q) = %v; want an error saying %q", tc.env, err, tc.want)
		}
	}

	// A symlink to a good 0600 file is refused: the link itself is not
	// followed.
	link := filepath.Join(t.TempDir(), "link.txt")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentities([]string{IdentityFileVar + "=" + link}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("a symlinked identity: %v; want a symlink refusal", err)
	}

	// Another owner: no unprivileged test can own a readable 0600 file as
	// someone else, so the effective uid is faked.
	orig := geteuid
	t.Cleanup(func() { geteuid = orig })
	geteuid = func() int { return os.Geteuid() + 1 }
	if _, err := LoadIdentities([]string{IdentityFileVar + "=" + good}); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("a file owned by another user: %v; want refused", err)
	}
}

// --- the child's environment ---------------------------------------------

func TestChildEnv(t *testing.T) {
	pairs := []Pair{{"PVEFORGE_ROSTER_PASSPHRASE", secretPass}}
	env, err := ChildEnv([]string{"HOME=/h", IdentityFileVar + "=/k", IdentityVar + "=AGE-SECRET-KEY-1X", "PATH=/bin"}, pairs)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"HOME=/h", "PATH=/bin", "PVEFORGE_ROSTER_PASSPHRASE=" + secretPass}; !slices.Equal(env, want) {
		t.Errorf("env = %q, want %q: the identity variables removed, the secret added", env, want)
	}
	for _, preset := range []string{"PVEFORGE_ROSTER_PASSPHRASE=other", "PVEFORGE_ROSTER_PASSPHRASE="} {
		if _, err := ChildEnv([]string{preset}, pairs); err == nil || !strings.Contains(err.Error(), "already set") || strings.Contains(err.Error(), "other") {
			t.Errorf("preset %q: %v; want an already-set refusal naming no value", preset, err)
		}
	}
}

// --- the commands --------------------------------------------------------

func TestRun_ExecsWithTheSecretsInTheEnvironmentOnly(t *testing.T) {
	op := newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	sealed(t, dir, plaintext())
	c := captureExec(t)
	env := []string{"PATH=" + os.Getenv("PATH"), IdentityVar + "=" + op.identity}
	res := runMain(t, env, "", "--dir", dir, "run", "--", "true", "arg1")
	if !c.called || res.code != 1 {
		t.Fatalf("exec called %t, result %+v", c.called, res)
	}
	if !slices.Equal(c.argv, []string{"true", "arg1"}) || !strings.HasSuffix(c.path, "/true") {
		t.Errorf("exec %s %q", c.path, c.argv)
	}
	for _, a := range c.argv {
		if strings.Contains(a, "sentinel") {
			t.Errorf("a secret reached argv: %q", c.argv)
		}
	}
	joined := strings.Join(c.env, "\n")
	if !strings.Contains(joined, "PVEFORGE_ROSTER_PASSPHRASE="+secretPass) || !strings.Contains(joined, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD="+secretNested) {
		t.Errorf("the secrets are not in the child's environment: %q", c.env)
	}
	if strings.Contains(joined, IdentityVar) || strings.Contains(joined, "AGE-SECRET-KEY") {
		t.Errorf("the identity reached the child's environment")
	}
	// Without "--" too.
	c2 := captureExec(t)
	runMain(t, env, "", "--dir", dir, "run", "true")
	if !c2.called || !slices.Equal(c2.argv, []string{"true"}) {
		t.Errorf("run without --: %+v", c2)
	}
}

func TestRun_Refusals(t *testing.T) {
	op, other := newX25519(t), newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	sealed(t, dir, plaintext())
	path := "PATH=" + os.Getenv("PATH")
	for name, tc := range map[string]struct {
		env  []string
		args []string
		code int
	}{
		"no identity":               {[]string{path}, []string{"run", "true"}, 1},
		"both identities":           {[]string{path, IdentityVar + "=" + op.identity, IdentityFileVar + "=" + identityFile(t, op, 0o600)}, []string{"run", "true"}, 1},
		"a key not sealed to":       {[]string{path, IdentityVar + "=" + other.identity}, []string{"run", "true"}, 1},
		"a secret name already set": {[]string{path, IdentityVar + "=" + op.identity, "PVEFORGE_ROSTER_PASSPHRASE=x"}, []string{"run", "true"}, 1},
		"no command":                {[]string{path, IdentityVar + "=" + op.identity}, []string{"run", "--"}, 2},
		"no such command":           {[]string{path, IdentityVar + "=" + op.identity}, []string{"run", "no-such-cmd-xyz"}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			c := captureExec(t)
			res := runMain(t, tc.env, "", append([]string{"--dir", dir}, tc.args...)...)
			if res.code != tc.code || c.called {
				t.Errorf("code %d (want %d), exec called %t; stderr %q", res.code, tc.code, c.called, res.stderr)
			}
		})
	}
	// A missing secrets.age.
	empty := harnessDir(t, map[string]keypair{"operator": op})
	c := captureExec(t)
	if res := runMain(t, []string{path, IdentityVar + "=" + op.identity}, "", "--dir", empty, "run", "true"); res.code != 1 || c.called {
		t.Errorf("no secrets.age: %+v", res)
	}
	// A blob carrying a name outside the allowlist, sealed by someone with
	// only the public recipient (age does not authenticate the sender).
	evil := harnessDir(t, map[string]keypair{"operator": op})
	rs, err := ParseRecipients(mustRead(t, filepath.Join(evil, "recipients.txt")))
	if err != nil {
		t.Fatal(err)
	}
	blob := sealRaw(t, rs, "PATH=/tmp/evil\nPVEFORGE_ROSTER_PASSPHRASE=x\n")
	if err := os.WriteFile(filepath.Join(evil, "secrets.age"), blob, 0o644); err != nil {
		t.Fatal(err)
	}
	c = captureExec(t)
	if res := runMain(t, []string{path, IdentityVar + "=" + op.identity}, "", "--dir", evil, "run", "true"); res.code != 1 || c.called || !strings.Contains(res.stderr, "not allowed") {
		t.Errorf("an injected PATH: %+v, exec called %t", res, c.called)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sealRaw encrypts arbitrary plaintext, bypassing ParseEnv, as an attacker
// with only the public recipients could.
func sealRaw(t *testing.T, rs []Recipient, plain string) []byte {
	t.Helper()
	var keys []age.Recipient
	for _, r := range rs {
		keys = append(keys, r.Key)
	}
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, keys...)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(plain))
	_ = w.Close()
	_ = aw.Close()
	return out.Bytes()
}

func TestSeal(t *testing.T) {
	op, runner := newX25519(t), newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op, "ci-runner-lab1": runner})
	res := runMain(t, nil, plaintext(), "--dir", dir, "seal")
	if res.code != 0 || !strings.Contains(res.stdout, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD, PVEFORGE_ROSTER_PASSPHRASE") || !strings.Contains(res.stdout, "2 recipient(s): ci-runner-lab1, operator") {
		t.Fatalf("seal: %+v", res)
	}
	blob := mustRead(t, filepath.Join(dir, "secrets.age"))
	if !bytes.HasPrefix(blob, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) || bytes.Contains(blob, []byte("sentinel")) {
		t.Errorf("secrets.age is not armored ciphertext: %.80q", blob)
	}
	fi, _ := os.Stat(filepath.Join(dir, "secrets.age"))
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("secrets.age mode %v", fi.Mode().Perm())
	}
	// Each recipient opens it; no temporary file is left behind.
	for _, k := range []keypair{op, runner} {
		c := captureExec(t)
		runMain(t, []string{"PATH=" + os.Getenv("PATH"), IdentityVar + "=" + k.identity}, "", "--dir", dir, "run", "true")
		if !c.called {
			t.Errorf("a recipient could not open the sealed blob")
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("harness dir holds %d entries, want recipients.txt and secrets.age only", len(entries))
	}

	for name, tc := range map[string]struct {
		dir, in string
	}{
		"an invalid env":     {dir, "PATH=/x\n"},
		"no recipients file": {t.TempDir(), plaintext()},
		"comments-only recipients": {func() string {
			d := t.TempDir()
			_ = os.WriteFile(filepath.Join(d, "recipients.txt"), []byte("# nobody\n"), 0o644)
			return d
		}(), plaintext()},
	} {
		t.Run(name, func(t *testing.T) {
			before, _ := os.ReadFile(filepath.Join(tc.dir, "secrets.age"))
			if res := runMain(t, nil, tc.in, "--dir", tc.dir, "seal"); res.code != 1 {
				t.Errorf("seal: %+v; want a refusal", res)
			}
			after, _ := os.ReadFile(filepath.Join(tc.dir, "secrets.age"))
			if !bytes.Equal(before, after) {
				t.Errorf("a refused seal changed secrets.age")
			}
		})
	}
}

func TestSeal_Prompt(t *testing.T) {
	op := newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	origT, origR := isTerminal, readSecret
	t.Cleanup(func() { isTerminal, readSecret = origT, origR })
	isTerminal = func(*os.File) bool { return true }
	answers := [][]byte{[]byte(secretNested), []byte(secretNested), []byte(secretPass), []byte(secretPass)}
	readSecret = func(*os.File) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	res := runMain(t, nil, "", "--dir", dir, "seal")
	if res.code != 0 || !strings.Contains(res.stderr, "PVEFORGE_ROSTER_PASSPHRASE again:") {
		t.Fatalf("prompted seal: %+v", res)
	}
	c := captureExec(t)
	runMain(t, []string{"PATH=" + os.Getenv("PATH"), IdentityVar + "=" + op.identity}, "", "--dir", dir, "run", "true")
	if !strings.Contains(strings.Join(c.env, "\n"), "PVEFORGE_ROSTER_PASSPHRASE="+secretPass) {
		t.Errorf("the prompted value did not round-trip")
	}
	// Two entries that differ are refused.
	answers = [][]byte{[]byte("a"), []byte("b")}
	if res := runMain(t, nil, "", "--dir", dir, "seal"); res.code != 1 || !strings.Contains(res.stderr, "differ") {
		t.Errorf("mismatched entries: %+v", res)
	}
}

func TestReseal(t *testing.T) {
	op, gone, added := newX25519(t), newX25519(t), newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op, "ci-runner-old": gone})
	sealed(t, dir, plaintext())
	// Replace the old runner with a new one, then reseal with the operator's
	// identity.
	rec := op.recipient + " # operator\n" + added.recipient + " # ci-runner-new\n"
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runMain(t, []string{IdentityFileVar + "=" + identityFile(t, op, 0o600)}, "", "--dir", dir, "reseal")
	if res.code != 0 || !strings.Contains(res.stdout, "resealed") {
		t.Fatalf("reseal: %+v", res)
	}
	path := "PATH=" + os.Getenv("PATH")
	c := captureExec(t)
	runMain(t, []string{path, IdentityVar + "=" + added.identity}, "", "--dir", dir, "run", "true")
	if !c.called || !strings.Contains(strings.Join(c.env, "\n"), secretNested) {
		t.Errorf("the added recipient cannot open the resealed blob")
	}
	c = captureExec(t)
	if res := runMain(t, []string{path, IdentityVar + "=" + gone.identity}, "", "--dir", dir, "run", "true"); c.called || res.code != 1 {
		t.Errorf("the removed recipient still opens the NEW blob")
	}
	// Reseal needs an identity.
	if res := runMain(t, nil, "", "--dir", dir, "reseal"); res.code != 1 {
		t.Errorf("reseal without an identity: %+v", res)
	}
}

func TestStatus(t *testing.T) {
	op := newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	sealed(t, dir, plaintext())
	res := runMain(t, nil, "", "--dir", dir, "status")
	if res.code != 0 || res.stdout != "recipients: 1 (operator)\nnames: not shown (no identity set)\n" {
		t.Errorf("status without an identity: %+v", res)
	}
	res = runMain(t, []string{IdentityVar + "=" + op.identity}, "", "--dir", dir, "status")
	if res.code != 0 || res.stdout != "recipients: 1 (operator)\nnames: PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD, PVEFORGE_ROSTER_PASSPHRASE\n" {
		t.Errorf("status with an identity: %+v", res)
	}
	if res := runMain(t, []string{IdentityVar + "=" + newX25519(t).identity}, "", "--dir", dir, "status"); res.code != 1 {
		t.Errorf("status with a key not sealed to: %+v", res)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"run"}, {"--dir"}, {"--dir", "", "status"}, {"--dir", "d"}, {"--dir", "d", "bogus"},
		{"--dir", "d", "seal", "PVEFORGE_ROSTER_PASSPHRASE=x"}, {"--dir", "d", "status", "x"}, {"--dir", "d", "reseal", "x"},
	} {
		if res := runMain(t, nil, "", args...); res.code != 2 || !strings.Contains(res.stderr, "usage:") {
			t.Errorf("%q: %+v; want a usage error", args, res)
		}
	}
}

// seal replaces secrets.age by renaming a new file over it, never by
// rewriting it in place (where a reader, or a crash, could see half a blob):
// the file's inode changes.
func TestSeal_ReplacesTheFileAtomically(t *testing.T) {
	op := newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	sealed(t, dir, plaintext())
	before, err := os.Stat(filepath.Join(dir, "secrets.age"))
	if err != nil {
		t.Fatal(err)
	}
	sealed(t, dir, plaintext())
	after, err := os.Stat(filepath.Join(dir, "secrets.age"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Errorf("secrets.age was rewritten in place, not replaced by a rename")
	}
}

func TestWriteAtomic_LeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeAtomic(filepath.Join(dir, "secrets.age"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	// A failed write (the target is a directory) cleans up after itself.
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(dir, "d"), []byte("x")); err == nil {
		t.Fatal("renaming over a directory succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %q; want secrets.age and d only", names)
	}
}

// The prompt leaves out a name answered empty, and a failed read is refused.
func TestSeal_PromptEdges(t *testing.T) {
	op := newX25519(t)
	dir := harnessDir(t, map[string]keypair{"operator": op})
	origT, origR := isTerminal, readSecret
	t.Cleanup(func() { isTerminal, readSecret = origT, origR })
	isTerminal = func(*os.File) bool { return true }
	answers := [][]byte{{}, []byte(secretPass), []byte(secretPass)} // nested left out
	readSecret = func(*os.File) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	if res := runMain(t, nil, "", "--dir", dir, "seal"); res.code != 0 || !strings.Contains(res.stdout, "sealed PVEFORGE_ROSTER_PASSPHRASE to") {
		t.Errorf("a name answered empty: %+v", res)
	}
	for _, failAt := range []int{0, 1} {
		n := 0
		readSecret = func(*os.File) ([]byte, error) {
			if n == failAt {
				return nil, errors.New("tty gone")
			}
			n++
			return []byte("x"), nil
		}
		if res := runMain(t, nil, "", "--dir", dir, "seal"); res.code != 1 || !strings.Contains(res.stderr, "tty gone") {
			t.Errorf("a read failure at %d: %+v", failAt, res)
		}
	}
}

// reseal and status need recipients.txt; an oversized file is refused.
func TestMissingAndOversizedFiles(t *testing.T) {
	op := newX25519(t)
	env := []string{IdentityVar + "=" + op.identity}
	for _, cmd := range []string{"reseal", "status"} {
		if res := runMain(t, env, "", "--dir", t.TempDir(), cmd); res.code != 1 || !strings.Contains(res.stderr, "read recipients") {
			t.Errorf("%s without recipients.txt: %+v", cmd, res)
		}
	}
	dir := harnessDir(t, map[string]keypair{"operator": op})
	if err := os.WriteFile(filepath.Join(dir, "secrets.age"), bytes.Repeat([]byte("a"), maxCiphertext+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runMain(t, env, "", "--dir", dir, "status"); res.code != 1 || !strings.Contains(res.stderr, "larger than") {
		t.Errorf("an oversized secrets.age: %+v", res)
	}
}

// --- no file content ever reaches an error (review H1, M1) -----------------

// markerFile is a file whose content must never appear in any output: it
// stands in for /proc/self/environ, holding a CI identity.
func markerFile(t *testing.T) (path, marker string) {
	t.Helper()
	marker = "MARKER-" + newX25519(t).recipient[5:25]
	path = filepath.Join(t.TempDir(), "environ")
	body := "HOME=/root\x00PVEFORGE_HARNESS_AGE_IDENTITY=AGE-SECRET-KEY-" + marker + "\x00"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, marker
}

func noMarker(t *testing.T, res result, marker, what string) {
	t.Helper()
	if strings.Contains(res.stdout+res.stderr, marker) || strings.Contains(res.stdout+res.stderr, "AGE-SECRET-KEY") {
		t.Errorf("%s: the file's content reached the output:\nstdout %q\nstderr %q", what, res.stdout, res.stderr)
	}
}

// H1: a committed symlink (git stores them) pointing secrets.age or
// recipients.txt at /proc/self/environ is refused before a byte is read,
// for every command that reads the file.
func TestSymlinkedFilesAreRefusedUnread(t *testing.T) {
	op := newX25519(t)
	env := []string{"PATH=" + os.Getenv("PATH"), IdentityVar + "=" + op.identity}
	target, marker := markerFile(t)

	dir := harnessDir(t, map[string]keypair{"operator": op})
	if err := os.Symlink(target, filepath.Join(dir, "secrets.age")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"run", "true"}, {"status"}, {"reseal"}} {
		c := captureExec(t)
		res := runMain(t, env, "", append([]string{"--dir", dir}, args...)...)
		if res.code != 1 || c.called || !strings.Contains(res.stderr, "is a symlink") {
			t.Errorf("secrets.age symlinked, %s: %+v", args[0], res)
		}
		noMarker(t, res, marker, "secrets.age symlinked, "+args[0])
	}

	dir2 := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir2, "recipients.txt")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"seal"}, {"status"}, {"reseal"}} {
		res := runMain(t, env, plaintext(), append([]string{"--dir", dir2}, args...)...)
		if res.code != 1 || !strings.Contains(res.stderr, "is a symlink") {
			t.Errorf("recipients.txt symlinked, %s: %+v", args[0], res)
		}
		noMarker(t, res, marker, "recipients.txt symlinked, "+args[0])
	}
}

// Defence in depth: whatever secrets.age holds, a decrypt failure is one of
// three fixed messages — nothing from the blob, from age or from the armor
// decoder.
func TestDecryptErrorsAreFixedText(t *testing.T) {
	op, other := newX25519(t), newX25519(t)
	env := []string{"PATH=" + os.Getenv("PATH"), IdentityVar + "=" + op.identity}
	_, marker := markerFile(t)
	sealedTo := func(k keypair) []byte {
		d := harnessDir(t, map[string]keypair{"x": k})
		sealed(t, d, plaintext())
		return mustRead(t, filepath.Join(d, "secrets.age"))
	}
	good := sealedTo(op)
	lines := strings.Split(string(good), "\n")
	mid := len(lines) / 2
	corrupt := strings.Join(append(append(append([]string{}, lines[:mid]...), strings.Repeat("A", len(lines[mid]))), lines[mid+1:]...), "\n")
	fixed := map[string]string{
		"the content of another file":   "pveforge-harness-secrets: " + errNotAgeFile.Error() + "\n",
		"an armor header, then garbage": "pveforge-harness-secrets: " + errNotAgeFile.Error() + "\n",
		"a blob sealed to someone else": "pveforge-harness-secrets: " + errNotSealedToYou.Error() + "\n",
		"a corrupted body":              "pveforge-harness-secrets: " + errCorrupt.Error() + "\n",
	}
	blobs := map[string][]byte{
		"the content of another file":   []byte("HOME=/root\x00PVEFORGE_HARNESS_AGE_IDENTITY=AGE-SECRET-KEY-" + marker + "\x00"),
		"an armor header, then garbage": []byte("-----BEGIN AGE ENCRYPTED FILE-----\n" + marker + "\n-----END AGE ENCRYPTED FILE-----\n"),
		"a blob sealed to someone else": sealedTo(other),
		"a corrupted body":              []byte(corrupt),
	}
	for name, blob := range blobs {
		t.Run(name, func(t *testing.T) {
			dir := harnessDir(t, map[string]keypair{"operator": op})
			if err := os.WriteFile(filepath.Join(dir, "secrets.age"), blob, 0o644); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"run", "true"}, {"status"}, {"reseal"}} {
				c := captureExec(t)
				res := runMain(t, env, "", append([]string{"--dir", dir}, args...)...)
				if res.code != 1 || c.called || res.stderr != fixed[name] {
					t.Errorf("%s: stderr %q, want exactly %q", args[0], res.stderr, fixed[name])
				}
				noMarker(t, res, marker, name)
			}
		})
	}
	// recipients.txt: age's own parse error quotes its input; ours does not.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte("age1"+marker+" # a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runMain(t, env, plaintext(), "--dir", dir, "seal")
	if res.code != 1 || !strings.Contains(res.stderr, "line 1 is not a valid X25519 or hybrid age recipient") {
		t.Errorf("a malformed recipient: %+v", res)
	}
	noMarker(t, res, marker, "a malformed recipient")
}

// M1: a FIFO (or device) never blocks the open: every file is opened
// non-blocking and refused as not regular.
func TestFIFOsAreRefusedWithoutBlocking(t *testing.T) {
	op := newX25519(t)
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadIdentities([]string{IdentityFileVar + "=" + fifo})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a FIFO identity: %v; want refused as not regular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO identity file blocked")
	}

	dir := harnessDir(t, map[string]keypair{"operator": op})
	if err := syscall.Mkfifo(filepath.Join(dir, "secrets.age"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := make(chan result, 1)
	go func() { res <- runMain(t, []string{IdentityVar + "=" + op.identity}, "", "--dir", dir, "status") }()
	select {
	case r := <-res:
		if r.code != 1 || !strings.Contains(r.stderr, "not a regular file") {
			t.Errorf("a FIFO secrets.age: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO secrets.age blocked")
	}
	// A device, too.
	if _, err := LoadIdentities([]string{IdentityFileVar + "=/dev/null"}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("/dev/null as the identity: %v", err)
	}
}
