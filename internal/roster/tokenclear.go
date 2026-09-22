package roster

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// ClearTokenAuth deletes the [targets.token] subtable of the target
// identified by targetID, leaving every other byte of the roster alone. A
// target with no token subtable is a no-op (nil). It is the counterpart of
// WriteTokenAuth, and it exactly undoes WriteTokenAuth's append: a token
// block appended by WriteTokenAuth is removed together with the one blank
// separator line the append put in front of it, so write-then-clear
// restores the original bytes.
//
// bootstrap calls this right after it removes the token on PVE, so that a
// crash or failure anywhere later leaves the roster with NO token — never
// pointing at a credential PVE has already revoked.
//
// Same guarantees as the other writers: the per-write <roster>.lock (10 s
// timeout), a decode-both-sides guard (verifyOnlyIntendedChange) that also
// requires the token to be gone afterwards, and an atomic rename. On any
// failure the roster is left untouched.
func ClearTokenAuth(path, targetID string) error {
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock roster %s: %w", path, err)
	}
	if !locked {
		return fmt.Errorf("lock roster %s: timed out waiting for another pveforge process", path)
	}
	defer lock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read roster %s: %w", path, err)
	}
	newData, err := composeClearToken(data, targetID)
	if err != nil {
		return err
	}
	if bytes.Equal(data, newData) {
		return nil
	}
	if err := atomicWrite(path, newData); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// composeClearToken is ClearTokenAuth's pure part: the spliced bytes, already
// checked by the guard.
func composeClearToken(data []byte, targetID string) ([]byte, error) {
	newData, err := applyClearToken(data, targetID)
	if err != nil {
		return nil, fmt.Errorf("clear token of target %q: %w", targetID, err)
	}
	if err := verifyOnlyIntendedChange(data, newData, targetID, "token"); err != nil {
		return nil, fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}
	r, err := Decode(newData)
	if err != nil {
		return nil, fmt.Errorf("safety check failed, roster left untouched: %w", err)
	}
	if tg := r.Find(targetID); tg == nil || tg.Token != nil {
		return nil, fmt.Errorf("safety check failed, roster left untouched: target %q still has a token after the clear", targetID)
	}
	return newData, nil
}

func applyClearToken(data []byte, targetID string) ([]byte, error) {
	match, err := findUniqueTargetBlock(data, targetID)
	if err != nil {
		return nil, err
	}
	sub := findSubtable(data, *match, "token")
	if sub == nil {
		return data, nil
	}
	start := sub.start
	// Also drop the single blank separator line WriteTokenAuth's append
	// writes in front of the header ("\n[targets.token]" after a block that
	// already ends in a newline), so a clear exactly undoes that append.
	if start >= 2 && data[start-1] == '\n' && data[start-2] == '\n' {
		start--
	}
	return applyEdits(data, []edit{{Start: start, End: sub.end, Replacement: nil}})
}

// dryRunPlaceholderTokenID and dryRunPlaceholderSecretEnc are what
// DryRunTokenWrite splices in place of a real token. The secret is NOT a
// real ciphertext: running EncryptString here would cost a production scrypt
// derivation (2^18, 256 MiB) on every bootstrap and would need the
// passphrase. The splice only depends on the text's shape, so this constant
// has an age armor's exact framing and line lengths (64-column base64 body
// lines), and renders through the same multi-line literal path as a real
// secret_enc. TestDryRunPlaceholder_HasArmorShape pins that shape against a
// real EncryptString output.
const dryRunPlaceholderTokenID = "pveforge-dry-run@pam!dry-run"

const dryRunPlaceholderSecretEnc = "-----BEGIN AGE ENCRYPTED FILE-----\n" +
	"YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBkcnlydW5kcnlydW5kcnly\n" +
	"dW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnly\n" +
	"dW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnlydW5kcnly\n" +
	"ZHJ5cnVu\n" +
	"-----END AGE ENCRYPTED FILE-----\n"

func dryRunPlaceholderFields() []field {
	return []field{
		{key: "id", value: dryRunPlaceholderTokenID},
		{key: "secret_enc", value: dryRunPlaceholderSecretEnc, literal: true},
	}
}

// dryRunCompose, when non-nil (tests only), receives each rehearsal's
// composed bytes, in order: "write-alone", then "clear-then-write".
var dryRunCompose func(stage string, composed []byte)

// DryRunTokenWrite rehearses, in memory, every roster write bootstrap may
// perform on this target's token after it has removed a token on PVE, and
// fails if any of them would fail. It writes nothing to the roster.
//
// It must rehearse BOTH sequences, because they run through different code:
//
//   - write-alone: WriteTokenAuth's splice on the bytes as they are now. This
//     is a first mint, or a changed --token-id written over the old token (an
//     in-place edit when a token subtable exists, an append when none does).
//   - clear-then-write: ClearTokenAuth's splice, then WriteTokenAuth's splice
//     on the cleared bytes. This is every path that removes a token (the
//     roster is cleared right after the remove), so the write is always the
//     APPEND path here, whatever the roster looked like before.
//
// Which sequence a run will take is only known after the skip-check, so both
// always run. It also creates and removes one temp file in the roster's
// directory, proving the atomic rename in WriteTokenAuth/ClearTokenAuth can
// happen there. Each step is checked by the same guard the real writers use.
func DryRunTokenWrite(path, targetID string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("roster dry run: read %s: %w", path, err)
	}

	alone, err := composeTokenWrite(data, targetID)
	if err != nil {
		return fmt.Errorf("roster dry run (write-alone): %w", err)
	}
	if dryRunCompose != nil {
		dryRunCompose("write-alone", alone)
	}

	cleared, err := composeClearToken(data, targetID)
	if err != nil {
		return fmt.Errorf("roster dry run (clear-then-write): %w", err)
	}
	afterClear, err := composeTokenWrite(cleared, targetID)
	if err != nil {
		return fmt.Errorf("roster dry run (clear-then-write): %w", err)
	}
	if dryRunCompose != nil {
		dryRunCompose("clear-then-write", afterClear)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".pveforge-roster-dryrun-*.tmp")
	if err != nil {
		return fmt.Errorf("roster dry run: the roster directory is not writable: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	if err := os.Remove(tmpPath); err != nil {
		return fmt.Errorf("roster dry run: remove probe file: %w", err)
	}
	return nil
}

// composeTokenWrite is WriteTokenAuth's splice and guard with the dry-run
// placeholder, on data, returning the composed bytes.
func composeTokenWrite(data []byte, targetID string) ([]byte, error) {
	newData, err := applySubtableSplice(data, targetID, "token", dryRunPlaceholderFields())
	if err != nil {
		return nil, fmt.Errorf("splice token into target %q: %w", targetID, err)
	}
	if err := verifyOnlyIntendedChange(data, newData, targetID, "token"); err != nil {
		return nil, fmt.Errorf("safety check failed: %w", err)
	}
	r, err := Decode(newData)
	if err != nil {
		return nil, fmt.Errorf("safety check failed: %w", err)
	}
	if tg := r.Find(targetID); tg == nil || tg.Token == nil || tg.Token.ID != dryRunPlaceholderTokenID {
		return nil, fmt.Errorf("safety check failed: the rehearsed token write did not land on target %q", targetID)
	}
	return newData, nil
}
