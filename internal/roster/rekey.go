package roster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/gofrs/flock"
)

// ErrNothingToRekey: the roster holds no secret, so it has no passphrase
// yet; the first bootstrap or import-token sets one.
var ErrNothingToRekey = errors.New("the roster holds no secret, so there is no passphrase to change")

// ErrSameNewPassphrase: the new passphrase is the old one.
var ErrSameNewPassphrase = errors.New("the new passphrase is the current one")

// ErrPartlyReadable: some of the roster's secrets open with the given
// passphrase and some do not. Rekeying only the ones that open would leave
// the roster split across two passphrases, so nothing is written.
var ErrPartlyReadable = errors.New("the roster's secrets do not all open with this passphrase")

// ErrRosterChanged: the roster file changed while the rekey was composing
// its replacement (a writer that ignores the roster lock, or a hand edit).
var ErrRosterChanged = errors.New("the roster changed while it was being rekeyed")

// RekeyResult reports what Rekey did.
type RekeyResult struct {
	// Secrets is how many secrets were re-encrypted, over Targets targets.
	Secrets, Targets int
}

// Test seams: rekeyWriteFn replaces the roster file, so a test can fail
// the replacement and prove the old file survives it; rekeyComposed runs
// once the replacement is composed and checked, before the compare-and-set
// re-read, so a test can change the file there; rekeyLockTimeout bounds the
// wait for the roster lock.
var (
	rekeyWriteFn     = atomicWrite
	rekeyComposed    = func() {}
	rekeyLockTimeout = 10 * time.Second
	// rekeyApplyEdits splices the new ciphertexts in; a test can corrupt its
	// output to prove the check before replacing runs on it.
	rekeyApplyEdits = applyEdits
)

// Rekey re-encrypts every secret of the roster at path from passphrase old
// to passphrase next. It contacts nothing: it reads and writes the one file.
//
// Under the roster's file lock (the lock every roster writer takes), every
// secret must open with old: if none does, it is ErrWrongPassphrase; if
// only some do, ErrPartlyReadable, naming the rest. Each is sealed afresh
// under next (EncryptString, the production work factor) and spliced over
// its old ciphertext in place, so every other byte of the file is kept.
// Before the file is replaced, the result is decoded and checked: every
// field but the ciphertexts is unchanged, and every new ciphertext opens
// with next to exactly the plaintext it replaces. The file on disk must
// still be the bytes that were read (a compare-and-set against a writer
// that skips the lock). Only then is it replaced atomically (temp file,
// fsync, rename, mode kept). Any refusal or failure leaves the file as it
// was, and no copy under the old passphrase is kept beside it.
func Rekey(path, old, next string) (RekeyResult, error) {
	if old == "" || next == "" {
		return RekeyResult{}, fmt.Errorf("empty roster passphrase")
	}
	if old == next {
		return RekeyResult{}, ErrSameNewPassphrase
	}
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(context.Background(), rekeyLockTimeout)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 50*time.Millisecond)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return RekeyResult{}, fmt.Errorf("lock roster %s: %w", path, err)
	}
	if !locked {
		return RekeyResult{}, fmt.Errorf("lock roster %s: timed out waiting for another pveforge process", path)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return RekeyResult{}, fmt.Errorf("read roster %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	current, err := Decode(data)
	if err != nil {
		return RekeyResult{}, fmt.Errorf("read roster %s: %w", path, err)
	}
	newData, res, err := rekeySecrets(data, current, old, next)
	if err != nil {
		return RekeyResult{}, err
	}
	rekeyComposed()
	now, err := os.ReadFile(path)
	if err != nil {
		return RekeyResult{}, fmt.Errorf("read roster %s: %w", path, err)
	}
	if sha256.Sum256(now) != sum {
		return RekeyResult{}, fmt.Errorf("%w; nothing was written: re-run", ErrRosterChanged)
	}
	if err := rekeyWriteFn(path, newData); err != nil {
		return RekeyResult{}, fmt.Errorf("write roster %s (the old file is unchanged): %w", path, err)
	}
	return res, nil
}

// CheckRekey is Rekey's refusals that need no new passphrase, so a command
// can make them before it prompts for one: a roster that holds no secret
// (ErrNothingToRekey), and an old passphrase that does not open it
// (ErrWrongPassphrase, ErrNoReadableSecret). Rekey checks every secret
// again, under the lock.
func CheckRekey(path, old string) error {
	r, err := Load(path)
	if err != nil {
		return err
	}
	if len(secretsInProofOrder(r, "")) == 0 {
		return ErrNothingToRekey
	}
	return NewPassphrase(old).prove(r, "")
}

// rekeySecrets composes the rekeyed file from data (decoded as current) and
// checks it; it writes nothing.
func rekeySecrets(data []byte, current *Roster, old, next string) ([]byte, RekeyResult, error) {
	type sealed struct {
		plain  []byte
		newEnc string
	}
	// Every secret, keyed by target id and roster key.
	secrets := map[[2]string]sealed{}
	var wrong, unreadable []string
	total, targets := 0, 0
	for _, s := range secretsInProofOrder(current, "") {
		total++
		plain, err := DecryptString(s.armored, old)
		if err != nil {
			if errors.Is(err, age.ErrIncorrectIdentity) {
				wrong = append(wrong, fmt.Sprintf("the %s of target %s", s.what, s.target))
			} else {
				unreadable = append(unreadable, fmt.Sprintf("the %s of target %s: %v", s.what, s.target, err))
			}
			continue
		}
		key := "secret_enc"
		if s.what == "ssh private key" {
			key = "private_key_enc"
		}
		secrets[[2]string{s.target, key}] = sealed{plain: plain}
	}
	defer func() {
		for _, s := range secrets {
			clear(s.plain)
		}
	}()
	switch {
	case total == 0:
		return nil, RekeyResult{}, ErrNothingToRekey
	case len(secrets) == 0 && len(unreadable) == 0:
		return nil, RekeyResult{}, fmt.Errorf("%w: it opens none of the roster's %d secret(s); check %s (nothing was changed)", ErrWrongPassphrase, total, PassphraseEnvVar)
	case len(secrets) == 0:
		return nil, RekeyResult{}, fmt.Errorf("%w: the roster holds %d secret(s) and this pveforge can open none of them (nothing was changed): %s", ErrNoReadableSecret, total, strings.Join(unreadable, "; "))
	case len(wrong)+len(unreadable) > 0:
		return nil, RekeyResult{}, fmt.Errorf("%w: %d of %d open, and these do not: %s (nothing was changed)", ErrPartlyReadable, len(secrets), total, strings.Join(append(wrong, unreadable...), "; "))
	}

	blocks, err := findTargetBlocks(data)
	if err != nil {
		return nil, RekeyResult{}, err
	}
	var edits []edit
	for _, b := range blocks {
		touched := false
		for _, sub := range []struct{ table, key string }{{"token", "secret_enc"}, {"ssh", "private_key_enc"}} {
			k := [2]string{b.id, sub.key}
			s, ok := secrets[k]
			if !ok {
				continue
			}
			span := findSubtable(data, b, sub.table)
			if span == nil {
				return nil, RekeyResult{}, fmt.Errorf("target %s: cannot locate its [targets.%s] table to rewrite (nothing was changed)", b.id, sub.table)
			}
			r, ok := findSubtableFields(data, *span)[sub.key]
			if !ok {
				return nil, RekeyResult{}, fmt.Errorf("target %s: cannot locate its %s to rewrite (nothing was changed)", b.id, sub.key)
			}
			enc, err := EncryptString(s.plain, next)
			if err != nil {
				return nil, RekeyResult{}, fmt.Errorf("encrypt the %s of target %s: %w", sub.key, b.id, err)
			}
			s.newEnc = enc
			secrets[k] = s
			f := field{key: sub.key, value: enc, literal: true}
			edits = append(edits, edit{Start: r.Offset, End: r.Offset + r.Length, Replacement: []byte(f.renderValue())})
			touched = true
		}
		if touched {
			targets++
		}
	}
	if len(edits) != len(secrets) {
		return nil, RekeyResult{}, fmt.Errorf("safety check failed, roster left untouched: located %d of %d secret(s) to rewrite", len(edits), len(secrets))
	}
	newData, err := rekeyApplyEdits(data, edits)
	if err != nil {
		return nil, RekeyResult{}, err
	}
	if err := verifyRekey(current, newData, next, func(id, key string) ([]byte, string) {
		s := secrets[[2]string{id, key}]
		return s.plain, s.newEnc
	}); err != nil {
		return nil, RekeyResult{}, fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}
	return newData, RekeyResult{Secrets: len(secrets), Targets: targets}, nil
}

// verifyRekey decodes newData and requires it to be current with only its
// ciphertexts replaced: the same targets and every other field equal, and
// each new ciphertext the one composed for it, opening with next to the
// plaintext it replaces.
func verifyRekey(current *Roster, newData []byte, next string, want func(id, key string) (plain []byte, enc string)) error {
	nr, err := Decode(newData)
	if err != nil {
		return err
	}
	if len(nr.Targets) != len(current.Targets) {
		return fmt.Errorf("%d targets after, %d before", len(nr.Targets), len(current.Targets))
	}
	for i := range current.Targets {
		a, b := current.Targets[i], nr.Targets[i]
		check := func(key string, before, after *string) error {
			if (*before == "") != (*after == "") {
				return fmt.Errorf("target %s: %s appeared or vanished", a.ID, key)
			}
			if *before == "" {
				return nil
			}
			plain, enc := want(a.ID, key)
			if *after != enc || *after == *before {
				return fmt.Errorf("target %s: %s is not the ciphertext composed for it", a.ID, key)
			}
			got, err := DecryptString(*after, next)
			if err != nil {
				return fmt.Errorf("target %s: the new %s does not open with the new passphrase: %w", a.ID, key, err)
			}
			if !bytes.Equal(got, plain) {
				return fmt.Errorf("target %s: the new %s does not hold the old plaintext", a.ID, key)
			}
			return nil
		}
		// Compare everything else with the ciphertexts blanked on copies.
		ac, bc := a, b
		var aTok, bTok TokenAuth
		var aSSH, bSSH SSHAuth
		if a.Token != nil && b.Token != nil {
			aTok, bTok = *a.Token, *b.Token
			if err := check("secret_enc", &aTok.SecretEnc, &bTok.SecretEnc); err != nil {
				return err
			}
			aTok.SecretEnc, bTok.SecretEnc = "", ""
			ac.Token, bc.Token = &aTok, &bTok
		}
		if a.SSH != nil && b.SSH != nil {
			aSSH, bSSH = *a.SSH, *b.SSH
			if err := check("private_key_enc", &aSSH.PrivateKeyEnc, &bSSH.PrivateKeyEnc); err != nil {
				return err
			}
			aSSH.PrivateKeyEnc, bSSH.PrivateKeyEnc = "", ""
			ac.SSH, bc.SSH = &aSSH, &bSSH
		}
		if !targetDeepEqual(ac, bc) {
			return fmt.Errorf("target %s: a field other than its ciphertexts changed", a.ID)
		}
	}
	return nil
}
