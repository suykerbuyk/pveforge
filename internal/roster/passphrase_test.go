package roster

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/suykerbuyk/pveforge/internal/sourceguard"
)

// The roster passphrase check (pveforge-roster-passphrase-check): a
// passphrase that does not open a secret the roster already holds never
// encrypts a new one into it.

// fxSecret is one secret of a test roster: its target, which subtable, and
// the passphrase it is sealed under ("" for a corrupt one).
type fxSecret struct {
	target, sub, pass string
}

// corruptArmored looks armored, so Decode accepts it, but no passphrase
// opens it and age does not call that an incorrect identity.
const corruptArmored = armor.Header + "\nnot base64 at all!\n" + armor.Footer + "\n"

// passphraseRoster writes a roster holding targets a, b and c (in that
// order) and the given secrets, and returns its path and each secret's
// armored text keyed "target/sub".
func passphraseRoster(t *testing.T, secrets ...fxSecret) (string, map[string]string) {
	t.Helper()
	withTestWorkFactor(t)
	armored := map[string]string{}
	var b strings.Builder
	for _, id := range []string{"a", "b", "c"} {
		fmt.Fprintf(&b, "[[targets]]\nid = %q\nhost = \"h-%s\"\nnode = \"n-%s\"\n", id, id, id)
		for _, sub := range []string{"ssh", "token"} {
			for _, s := range secrets {
				if s.target != id || s.sub != sub {
					continue
				}
				enc := corruptArmored
				if s.pass != "" {
					enc = sampleArmored(t, "plain-"+id+"-"+sub, s.pass)
				}
				armored[id+"/"+sub] = enc
				key := "secret_enc"
				if sub == "ssh" {
					key = "private_key_enc"
					fmt.Fprintf(&b, "\n[targets.ssh]\nuser = \"root\"\n")
				} else {
					fmt.Fprintf(&b, "\n[targets.token]\nid = \"root@pam!t\"\n")
				}
				fmt.Fprintf(&b, "%s = '''\n%s'''\n", key, enc)
			}
		}
		b.WriteString("\n")
	}
	return writeTempRoster(t, b.String()), armored
}

func openedOf(p Passphrase) string {
	p.m.mu.Lock()
	defer p.m.mu.Unlock()
	return p.m.opened
}

// P1: the proof tries the target's own SSH key, then its own token, then
// the other targets' secrets in file order — so the decrypt a command on
// that target needs anyway is the one the proof pays for.
func TestProvePassphrase_ProofOrder(t *testing.T) {
	path, enc := passphraseRoster(t,
		fxSecret{"a", "ssh", "right"}, fxSecret{"a", "token", "right"},
		fxSecret{"b", "token", "right"}, fxSecret{"c", "ssh", "right"})
	for target, want := range map[string]string{
		"a":   enc["a/ssh"],
		"b":   enc["b/token"],
		"c":   enc["c/ssh"],
		"new": enc["a/ssh"], // no secret of its own: the first in file order
	} {
		p, err := ProvePassphrase(path, target, "right")
		if err != nil {
			t.Fatalf("%s: ProvePassphrase: %v", target, err)
		}
		if got := openedOf(p); got != want {
			t.Errorf("%s: the proof opened the wrong secret", target)
		}
	}
}

// P2: a passphrase the first readable secret rejects is ErrWrongPassphrase,
// naming that secret and the environment variable.
func TestProvePassphrase_WrongPassphrase(t *testing.T) {
	path, _ := passphraseRoster(t, fxSecret{"b", "token", "right"})
	_, err := ProvePassphrase(path, "new", "wrong")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("err = %v, want ErrWrongPassphrase", err)
	}
	for _, want := range []string{"token secret of target b", PassphraseEnvVar} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q does not name %q", err, want)
		}
	}
}

// P3 (ruling A): a roster holding no secret accepts any passphrase — the
// first secret written sets it — and proves nothing.
func TestProvePassphrase_NothingToProveAgainst(t *testing.T) {
	path, _ := passphraseRoster(t)
	p, err := ProvePassphrase(path, "a", "anything")
	if err != nil {
		t.Fatalf("ProvePassphrase on a roster with no secret: %v", err)
	}
	if openedOf(p) != "" {
		t.Error("a proof was recorded with nothing to prove against")
	}
}

// sealedBeyondThisBinary is a secret sealed under pass whose scrypt stanza
// claims work factor 23, above the maximum this binary's age accepts (22):
// a pveforge allowing 23 could open it with pass; this one cannot tell
// whether pass is right. Built by rewriting the stanza of a real
// low-factor ciphertext, which age refuses on the factor before it ever
// derives a key.
func sealedBeyondThisBinary(t *testing.T, pass string) string {
	t.Helper()
	raw, err := io.ReadAll(armor.NewReader(strings.NewReader(sampleArmored(t, "beyond", pass))))
	if err != nil {
		t.Fatal(err)
	}
	stanza := regexp.MustCompile(`(?m)^(-> scrypt \S+ )\d+$`)
	if !stanza.Match(raw) {
		t.Fatalf("no scrypt stanza in %q", raw)
	}
	raw = stanza.ReplaceAll(raw, []byte("${1}23"))
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptString(buf.String(), pass); err == nil || errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("control: the rewritten secret must be unreadable here, and not as a wrong passphrase: %v", err)
	}
	return buf.String()
}

// RPC1: a roster that HOLDS secrets, none of which this binary can read, is
// not an empty roster. No passphrase — right or wrong — can be checked
// against it, so none is accepted: ErrNoReadableSecret, naming each secret
// and its cause, and every encrypting write refuses it with the file
// untouched. Otherwise a typo would become the roster's authority and lock
// out its real passphrase.
func TestProvePassphrase_RPC1_AllUnreadableRefuses(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"only corrupt": func(t *testing.T) string {
			path, _ := passphraseRoster(t, fxSecret{"a", "ssh", ""}, fxSecret{"b", "token", ""})
			return path
		},
		"sealed beyond this binary's work factor": func(t *testing.T) string {
			path, enc := passphraseRoster(t, fxSecret{"a", "ssh", ""}, fxSecret{"b", "token", "right"})
			data, _ := os.ReadFile(path)
			data = bytes.Replace(data, []byte(enc["b/token"]), []byte(sealedBeyondThisBinary(t, "right")), 1)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			path := build(t)
			for _, pass := range []string{"right", "a-typo"} {
				_, err := ProvePassphrase(path, "c", pass)
				if !errors.Is(err, ErrNoReadableSecret) || errors.Is(err, ErrWrongPassphrase) {
					t.Fatalf("ProvePassphrase(%q) = %v, want ErrNoReadableSecret (and not ErrWrongPassphrase)", pass, err)
				}
				for _, want := range []string{"ssh private key of target a", "token secret of target b"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal does not name %q: %v", want, err)
					}
				}
			}
			before, _ := os.ReadFile(path)
			err := WriteTokenAuth(path, "c", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, NewPassphrase("a-typo"))
			if !errors.Is(err, ErrNoReadableSecret) {
				t.Errorf("WriteTokenAuth = %v, want ErrNoReadableSecret", err)
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Error("a refused write changed the roster")
			}
		})
	}
}

// RPC3: a proof made on ANOTHER target's secret keeps no plaintext — only
// the fact of the proof — and Decrypt of that secret really decrypts; a
// proof on the target's own secret keeps its plaintext for the decrypt the
// command makes anyway.
func TestProvePassphrase_RPC3_ForeignPlaintextIsNotKept(t *testing.T) {
	path, enc := passphraseRoster(t, fxSecret{"a", "ssh", "right"}, fxSecret{"b", "token", "right"})

	p, err := ProvePassphrase(path, "c", "right") // c holds nothing: proves on a's key
	if err != nil {
		t.Fatal(err)
	}
	p.m.mu.Lock()
	opened, plain := p.m.opened, p.m.plain
	p.m.mu.Unlock()
	if opened != enc["a/ssh"] || plain != nil {
		t.Fatalf("proof on a foreign secret: opened=%v, plain=%q; want a's key recorded and no plaintext", opened == enc["a/ssh"], plain)
	}
	if got, err := p.Decrypt(enc["a/ssh"]); err != nil || string(got) != "plain-a-ssh" {
		t.Errorf("Decrypt of the foreign proven secret = %q, %v; want a real decrypt", got, err)
	}

	own, err := ProvePassphrase(path, "b", "right")
	if err != nil {
		t.Fatal(err)
	}
	own.m.mu.Lock()
	ownPlain := string(own.m.plain)
	own.m.mu.Unlock()
	if ownPlain != "plain-b-token" {
		t.Errorf("proof on the target's own secret kept %q, want its plaintext", ownPlain)
	}
}

// P4: a corrupt secret is skipped; the first readable one after it decides,
// either way.
func TestProvePassphrase_CorruptSecretIsSkipped(t *testing.T) {
	path, enc := passphraseRoster(t, fxSecret{"a", "ssh", ""}, fxSecret{"b", "ssh", "right"})
	p, err := ProvePassphrase(path, "a", "right")
	if err != nil || openedOf(p) != enc["b/ssh"] {
		t.Fatalf("right passphrase: err %v; want b's key proven", err)
	}
	if _, err := ProvePassphrase(path, "a", "wrong"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: err = %v, want ErrWrongPassphrase", err)
	}
}

// P5: Decrypt serves the proven secret from the proof, and only that one:
// any other armored text is really decrypted.
func TestPassphrase_DecryptServesOnlyTheProvenSecret(t *testing.T) {
	path, enc := passphraseRoster(t, fxSecret{"a", "ssh", "right"}, fxSecret{"a", "token", "right"})
	p, err := ProvePassphrase(path, "a", "right")
	if err != nil {
		t.Fatal(err)
	}
	// Mark the memo so a hit is visible: a real decrypt cannot return this.
	p.m.mu.Lock()
	p.m.plain = []byte("from-the-proof")
	p.m.mu.Unlock()
	if got, err := p.Decrypt(enc["a/ssh"]); err != nil || string(got) != "from-the-proof" {
		t.Errorf("Decrypt(proven) = %q, %v; want the proof's plaintext", got, err)
	}
	if got, err := p.Decrypt(enc["a/token"]); err != nil || string(got) != "plain-a-token" {
		t.Errorf("Decrypt(other) = %q, %v; want the real plaintext", got, err)
	}
	// The caller owns what it gets back.
	got, _ := p.Decrypt(enc["a/ssh"])
	got[0] = 'X'
	if again, _ := p.Decrypt(enc["a/ssh"]); string(again) != "from-the-proof" {
		t.Errorf("a caller's edit reached the proof: %q", again)
	}
}

// P6: every encrypting write proves the passphrase under the roster's lock,
// against the file as it is then. A wrong passphrase leaves it untouched.
func TestWriters_RefuseAWrongPassphrase(t *testing.T) {
	path, _ := passphraseRoster(t, fxSecret{"b", "token", "right"})
	before, _ := os.ReadFile(path)
	for name, write := range map[string]func(Passphrase) error{
		"token": func(p Passphrase) error {
			return WriteTokenAuth(path, "a", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, p)
		},
		"ssh": func(p Passphrase) error {
			return WriteSSHAuth(path, "a", SSHWrite{User: "root", PrivateKeyPlaintext: []byte("k")}, p)
		},
	} {
		if err := write(NewPassphrase("wrong")); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want ErrWrongPassphrase", name, err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatalf("%s: a refused write changed the roster", name)
		}
	}
	p := NewPassphrase("right")
	if err := WriteTokenAuth(path, "a", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, p); err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
	// What a write seals is its proof from then on, so the next write
	// derives nothing.
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if openedOf(p) != r.Find("a").Token.SecretEnc {
		t.Error("the written secret is not the passphrase's proof")
	}
}

// P7: the check under the lock sees what changed since the early proof — the
// proven secret resealed under another passphrase, or a secret written into
// a roster that held none — and refuses; the file is untouched.
func TestWriters_ReproveUnderTheLock(t *testing.T) {
	t.Run("the proven secret changed", func(t *testing.T) {
		path, enc := passphraseRoster(t, fxSecret{"b", "token", "right"})
		p, err := ProvePassphrase(path, "a", "right")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		data = bytes.Replace(data, []byte(enc["b/token"]), []byte(sampleArmored(t, "x", "other")), 1)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		err = WriteTokenAuth(path, "a", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, p)
		if !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("err = %v, want ErrWrongPassphrase", err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(data, after) {
			t.Fatal("a refused write changed the roster")
		}
	})
	t.Run("a secret appeared", func(t *testing.T) {
		path, _ := passphraseRoster(t)
		p, err := ProvePassphrase(path, "a", "mine")
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteSSHAuth(path, "b", SSHWrite{User: "root", PrivateKeyPlaintext: []byte("k")}, NewPassphrase("theirs")); err != nil {
			t.Fatalf("the first secret: %v", err)
		}
		before, _ := os.ReadFile(path)
		err = WriteTokenAuth(path, "a", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, p)
		if !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("err = %v, want ErrWrongPassphrase", err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatal("a refused write changed the roster")
		}
	})
}

// P8: a Passphrase never prints what it holds.
func TestPassphrase_Redacted(t *testing.T) {
	path, _ := passphraseRoster(t, fxSecret{"a", "ssh", "hunter2-pass"})
	p, err := ProvePassphrase(path, "a", "hunter2-pass")
	if err != nil {
		t.Fatal(err)
	}
	holder := struct{ P Passphrase }{p}
	out := fmt.Sprintf("%v %+v %#v %s %v %+v %#v", p, p, p, p, holder, holder, holder)
	for _, leak := range []string{"hunter2-pass", "plain-a-ssh"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q printed: %s", leak, out)
		}
	}
}

// The zero Passphrase proves nothing and writes nothing.
func TestPassphrase_ZeroIsRefused(t *testing.T) {
	path, _ := passphraseRoster(t)
	if _, err := ProvePassphrase(path, "a", ""); err == nil {
		t.Error("ProvePassphrase accepted an empty passphrase")
	}
	if err := WriteTokenAuth(path, "a", TokenWrite{TokenID: "root@pam!x", SecretPlaintext: []byte("s")}, Passphrase{}); err == nil {
		t.Error("WriteTokenAuth accepted the zero Passphrase")
	}
}

// TestEncryptString_OnlyTheProvingWritersCallIt: EncryptString does not
// prove the passphrase; WriteTokenAuth and WriteSSHAuth do. So it is named
// nowhere else, in two layers:
//
//   - module-wide (sourceguard): no non-test file outside internal/roster's
//     secrets.go (its declaration) and writeback.go (the writers) names it,
//     bare or qualified;
//   - inside this package, by function: every use is within the body of
//     WriteTokenAuth or WriteSSHAuth. A file-scoped rule alone would let a
//     new function in writeback.go seal a secret and splice it with
//     applySubtableSplice, skipping the proof. Every declaration is walked
//     — package-level vars and their function literals included — so no
//     use can hide outside a function body.
//
// Anti-vacuity: exactly one use in each writer, and the declaration seen.
func TestEncryptString_OnlyTheProvingWritersCallIt(t *testing.T) {
	const decl, writers = "internal/roster/secrets.go", "internal/roster/writeback.go"
	bare := sourceguard.Target{Name: "EncryptString"}
	qualified := sourceguard.Target{ImportPath: "github.com/suykerbuyk/pveforge/internal/roster", Name: "EncryptString"}
	res, err := sourceguard.NonTestReferences(sourceguard.Scope{
		Root:       moduleRoot,
		AllowFiles: []string{decl, writers},
	}, []sourceguard.Target{bare, qualified})
	if err != nil {
		t.Fatalf("NonTestReferences: %v", err)
	}
	for _, ref := range res.Violations() {
		t.Errorf("EncryptString named outside the proving writers: %s", ref)
	}
	if len(res.Allowed(decl, bare)) == 0 || len(res.Allowed(writers, bare)) == 0 {
		t.Error("the guard no longer sees EncryptString's declaration and its writers")
	}
	if !res.Reached("cmd/pveforge/main.go") {
		t.Error("the walk did not cover the module")
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string]int{}
	declSeen := false
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			where := "package level"
			var skip *ast.Ident
			if fd, ok := d.(*ast.FuncDecl); ok {
				where = fd.Name.Name
				if fd.Recv != nil {
					where = "a method " + fd.Name.Name
				}
				if fd.Name.Name == "EncryptString" && fd.Recv == nil {
					skip, declSeen = fd.Name, true
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok || id.Name != "EncryptString" || id == skip {
					return true
				}
				uses[where]++
				if where != "WriteTokenAuth" && where != "WriteSSHAuth" {
					t.Errorf("%s: EncryptString used in %s, outside the proving writers", fset.Position(id.Pos()), where)
				}
				return true
			})
		}
	}
	if !declSeen || uses["WriteTokenAuth"] != 1 || uses["WriteSSHAuth"] != 1 {
		t.Errorf("declaration seen %v, uses %v: want the declaration and exactly one use in each writer — the walk is no longer looking at the real code", declSeen, uses)
	}
}

// P9: a secret Decrypt opens becomes the proof when there is none yet, so a
// caller that decrypts before proving (import's held token) proves for
// free; an existing proof is not replaced.
func TestPassphrase_DecryptBecomesTheProof(t *testing.T) {
	path, enc := passphraseRoster(t, fxSecret{"a", "ssh", "right"}, fxSecret{"b", "token", "right"})
	p := NewPassphrase("right")
	if _, err := p.Decrypt(enc["b/token"]); err != nil {
		t.Fatal(err)
	}
	if openedOf(p) != enc["b/token"] {
		t.Fatal("a decrypted roster secret did not become the proof")
	}
	if err := p.Prove(path, "a"); err != nil || openedOf(p) != enc["b/token"] {
		t.Errorf("Prove after the decrypt: %v; the proof should stand as it was", err)
	}
	if _, err := p.Decrypt(enc["a/ssh"]); err != nil || openedOf(p) != enc["b/token"] {
		t.Errorf("a second decrypt replaced the proof")
	}
	if _, err := NewPassphrase("wrong").Decrypt(enc["a/ssh"]); err == nil {
		t.Error("the wrong passphrase decrypted")
	}
}
