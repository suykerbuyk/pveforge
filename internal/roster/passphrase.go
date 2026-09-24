package roster

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"

	"filippo.io/age"
)

// ErrWrongPassphrase: the passphrase does not open a secret the roster
// already holds. Encrypting a new secret under it would split the roster —
// that secret readable only with this passphrase, the rest only with the
// roster's own — and nothing would say so until the split target was next
// used. Every encrypting write refuses it (WriteTokenAuth, WriteSSHAuth).
var ErrWrongPassphrase = errors.New("wrong roster passphrase")

// ErrNoReadableSecret: the roster holds secrets, but this pveforge can open
// none of them — each is corrupt, or sealed in a way this binary cannot read
// (a scrypt work factor above its maximum, say) — so no passphrase can be
// checked against it. Every encrypting write refuses it: accepting would let
// whatever passphrase came first become the roster's authority, and the
// roster's real passphrase would be refused as wrong from then on. Unlike
// ErrWrongPassphrase it says nothing about the passphrase itself.
var ErrNoReadableSecret = errors.New("no secret in the roster can be read")

// Passphrase is the roster passphrase as the encrypting writers take it.
// Besides the passphrase it carries what proved it: the one secret of the
// roster it was seen to open (or to seal, when this process wrote that
// secret itself), and that secret's plaintext, so the decrypt a command
// needs anyway is the proof and never costs a second scrypt derivation
// (about 0.8s each at the roster's work factor).
//
// Copies share the proof: a proof found by one copy — a write through the
// copy in bootstrap's Options, say — serves every other.
//
// Holding a Passphrase proves NOTHING about it: NewPassphrase wraps any
// string, and the zero value holds none. Only the writers' check under the
// roster's file lock (WriteTokenAuth, WriteSSHAuth) decides whether a
// secret may be sealed under it; ProvePassphrase is the same check made
// early, so a command can refuse before its first side effect.
//
// It keeps a proven secret's plaintext only when the secret is the
// command's own target's — the decrypt that command makes anyway. A proof
// made on another target's secret records which secret, and drops the
// plaintext at once.
//
// It prints as [redacted] under every fmt verb, so a %v of a struct that
// holds one never shows the passphrase or a proven secret.
type Passphrase struct {
	s string
	m *proof
}

type proof struct {
	mu     sync.Mutex
	opened string // the armored secret s is known to open; "" when none
	plain  []byte // opened's plaintext, or nil when it was another target's
}

// NewPassphrase wraps s, not yet proven against anything. A writer given it
// proves it under the roster's file lock; ProvePassphrase proves it earlier,
// before any side effect of the command that will write.
func NewPassphrase(s string) Passphrase { return Passphrase{s: s, m: &proof{}} }

// IsZero reports whether no passphrase is held.
func (p Passphrase) IsZero() bool { return p.s == "" }

// String and GoString redact: see the type's doc.
func (p Passphrase) String() string   { return "[redacted]" }
func (p Passphrase) GoString() string { return "roster.Passphrase{[redacted]}" }

// Decrypt is DecryptString under p. The one secret p's proof opened comes
// back from the proof, with no second derivation, as a copy the caller owns
// — when the proof kept its plaintext (see Passphrase); otherwise it is
// decrypted again.
// A secret it does decrypt becomes p's proof when p has none yet — a caller
// that decrypts a roster secret before proving (import's held token) then
// proves for free, since a proof counts only while that secret is still in
// the roster.
func (p Passphrase) Decrypt(armored string) ([]byte, error) {
	if p.m != nil {
		p.m.mu.Lock()
		if p.m.opened != "" && armored == p.m.opened && p.m.plain != nil {
			out := bytes.Clone(p.m.plain)
			p.m.mu.Unlock()
			return out, nil
		}
		p.m.mu.Unlock()
	}
	out, err := DecryptString(armored, p.s)
	if err == nil && p.m != nil {
		p.m.mu.Lock()
		if p.m.opened == "" {
			p.m.opened, p.m.plain = armored, bytes.Clone(out)
		}
		p.m.mu.Unlock()
	}
	return out, err
}

// remember records that p opens (or sealed) armored, keeping a copy of its
// plaintext.
func (p Passphrase) remember(armored string, plain []byte) {
	if p.m == nil {
		return
	}
	p.m.mu.Lock()
	p.m.opened, p.m.plain = armored, bytes.Clone(plain)
	p.m.mu.Unlock()
}

// rememberProofOnly records that p opens armored, another target's secret,
// and zeroes plain: nothing in this command will ever ask for it, so
// keeping it would only extend its exposure (a core dump, swap). Zeroing is
// best effort in Go — copies the runtime made are beyond reach.
func (p Passphrase) rememberProofOnly(armored string, plain []byte) {
	clear(plain)
	if p.m == nil {
		return
	}
	p.m.mu.Lock()
	p.m.opened, p.m.plain = armored, nil
	p.m.mu.Unlock()
}

// ProvePassphrase proves pass against the roster at path before a command
// that will encrypt into it does anything else, so a wrong passphrase is
// refused before a prompt, a lock, a dial or a mint. See Passphrase.prove
// for the rule; the writers apply the same rule again under the file lock.
func ProvePassphrase(path, targetID, pass string) (Passphrase, error) {
	p := NewPassphrase(pass)
	if err := p.Prove(path, targetID); err != nil {
		return Passphrase{}, err
	}
	return p, nil
}

// Prove is ProvePassphrase for a Passphrase already held: free when p's
// proof still stands in the roster at path.
func (p Passphrase) Prove(path, targetID string) error {
	if p.s == "" {
		return fmt.Errorf("empty roster passphrase")
	}
	r, err := Load(path)
	if err != nil {
		return err
	}
	return p.prove(r, targetID)
}

// secretRef is one encrypted secret of a roster.
type secretRef struct {
	target, what, armored string
}

// secretsInProofOrder lists r's secrets in the order a proof tries them:
// targetID's own SSH key, then its own token — the decrypts a command on
// that target makes anyway, so proving on them is free — then every other
// target's, in file order, SSH key before token.
func secretsInProofOrder(r *Roster, targetID string) []secretRef {
	var own, rest []secretRef
	for _, t := range r.Targets {
		var refs []secretRef
		if t.SSH != nil && t.SSH.PrivateKeyEnc != "" {
			refs = append(refs, secretRef{t.ID, "ssh private key", t.SSH.PrivateKeyEnc})
		}
		if t.Token != nil && t.Token.SecretEnc != "" {
			refs = append(refs, secretRef{t.ID, "token secret", t.Token.SecretEnc})
		}
		if t.ID == targetID {
			own = append(own, refs...)
		} else {
			rest = append(rest, refs...)
		}
	}
	return append(own, rest...)
}

// prove checks p against r's secrets. p is proven when the secret its proof
// already holds is still in r, byte for byte (no derivation). Otherwise the
// secrets are tried in secretsInProofOrder and the first one this binary
// can read decides: it opens (p is proven, and remembers it — its plaintext
// only if it is targetID's own) or it rejects p (ErrWrongPassphrase). A
// secret it cannot read — anything but age's "incorrect identity": corrupt,
// or sealed beyond this binary's limits — is skipped, but only while a
// readable one remains to decide.
//
// A roster holding NO secret accepts p: the first secret written sets the
// roster's passphrase (the operator's ruling). A roster whose secrets are
// ALL unreadable is not that: it is ErrNoReadableSecret, naming each, since
// "unreadable here" is not "unreadable" and accepting would let a typo
// become the roster's authority.
func (p Passphrase) prove(r *Roster, targetID string) error {
	if p.s == "" {
		return fmt.Errorf("empty roster passphrase")
	}
	refs := secretsInProofOrder(r, targetID)
	if p.m != nil {
		p.m.mu.Lock()
		opened := p.m.opened
		p.m.mu.Unlock()
		for _, s := range refs {
			if opened != "" && s.armored == opened {
				return nil
			}
		}
	}
	var unreadable []string
	for _, s := range refs {
		plain, err := DecryptString(s.armored, p.s)
		if err == nil {
			if s.target == targetID {
				p.remember(s.armored, plain)
			} else {
				p.rememberProofOnly(s.armored, plain)
			}
			return nil
		}
		if errors.Is(err, age.ErrIncorrectIdentity) {
			return fmt.Errorf("%w: it does not open the %s of target %s, which the roster already holds; check %s (nothing was changed)",
				ErrWrongPassphrase, s.what, s.target, PassphraseEnvVar)
		}
		unreadable = append(unreadable, fmt.Sprintf("the %s of target %s: %v", s.what, s.target, err))
	}
	if len(unreadable) > 0 {
		return fmt.Errorf("%w: the roster holds %d secret(s) and this pveforge can open none of them, so the passphrase cannot be checked (nothing was changed): %s",
			ErrNoReadableSecret, len(unreadable), strings.Join(unreadable, "; "))
	}
	return nil
}
