package harnesssecrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// maxCiphertext bounds secrets.age.
const maxCiphertext = 1 << 20

// seal encrypts pairs' canonical plaintext to every recipient, armored.
func seal(pairs []Pair, recipients []Recipient) ([]byte, error) {
	keys := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		keys[i] = r.Key
	}
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, keys...)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if _, err := w.Write(formatEnv(pairs)); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	if err := aw.Close(); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return out.Bytes(), nil
}

// The fixed messages open returns. Nothing from the blob, from age or from
// the armor decoder is ever put in an error: a secrets.age that is really
// some other file (a committed symlink to /proc/self/environ is refused by
// openRegular, but defence in depth) would otherwise print its content.
var (
	errNotSealedToYou = errors.New("decrypt secrets.age: it is not sealed to this identity")
	errNotAgeFile     = errors.New("decrypt secrets.age: not a valid armored age file")
	errCorrupt        = errors.New("decrypt secrets.age: the ciphertext is corrupt or truncated")
)

// open decrypts an armored blob with ids and parses its plaintext, in
// memory only. Its errors are the fixed ones above, or ParseEnv's, which
// carry a line number and at most an allowed NAME.
func open(blob []byte, ids []age.Identity) ([]Pair, error) {
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(blob)), ids...)
	if err != nil {
		if errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, errNotSealedToYou
		}
		return nil, errNotAgeFile
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxPlaintext+1))
	if err != nil {
		return nil, errCorrupt
	}
	return ParseEnv(plain)
}

// readBounded reads a file of at most limit bytes through openRegular: never
// a symlink, a FIFO or a device.
func readBounded(path string, limit int64) ([]byte, error) {
	f, _, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return b, nil
}

// writeAtomic replaces path with data (ciphertext only): a temporary file
// in the same directory, synced, then renamed over path.
func writeAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secrets.age.*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

var errUsage = errors.New("usage")
