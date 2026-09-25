package harnesssecrets

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// The two identity sources. Exactly one must be set.
const (
	// IdentityFileVar names a file holding the consumer's age identity. It
	// must be a regular file (not a symlink), owned by the effective user,
	// with no group or other permission bits (0600 or 0400).
	IdentityFileVar = "PVEFORGE_HARNESS_AGE_IDENTITY_FILE"
	// IdentityVar holds the identity itself, as a CI secret store injects
	// it.
	IdentityVar = "PVEFORGE_HARNESS_AGE_IDENTITY"
)

// geteuid is a seam: no unprivileged test can make a 0600 file it can read
// that another user owns.
var geteuid = os.Geteuid

// maxIdentity bounds an identity file or value.
const maxIdentity = 64 << 10

// ErrIdentity marks an identity that could not be used. Its messages name
// the variable, never the key.
var ErrIdentity = errors.New("age identity")

// lookup is how the identity sources are read: a variable is SET when it is
// present in the environment, even if empty.
func lookup(environ []string, name string) (string, bool) {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v, true
		}
	}
	return "", false
}

// LoadIdentities returns the consumer's identities from exactly one of
// IdentityFileVar and IdentityVar in environ. Both set, neither set, or
// either set but empty, is refused; so is a file that is a symlink, not
// regular, not owned by the effective user, or readable or writable by
// group or others. Only X25519 and hybrid identities are accepted.
func LoadIdentities(environ []string) ([]age.Identity, error) {
	path, fileSet := lookup(environ, IdentityFileVar)
	content, contentSet := lookup(environ, IdentityVar)
	switch {
	case fileSet && contentSet:
		return nil, fmt.Errorf("%w: both %s and %s are set; set exactly one", ErrIdentity, IdentityFileVar, IdentityVar)
	case !fileSet && !contentSet:
		return nil, fmt.Errorf("%w: neither %s nor %s is set", ErrIdentity, IdentityFileVar, IdentityVar)
	case fileSet && path == "":
		return nil, fmt.Errorf("%w: %s is set but empty", ErrIdentity, IdentityFileVar)
	case contentSet && content == "":
		return nil, fmt.Errorf("%w: %s is set but empty", ErrIdentity, IdentityVar)
	}
	if fileSet {
		b, err := readIdentityFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrIdentity, IdentityFileVar, err)
		}
		content = string(b)
	}
	src := IdentityVar
	if fileSet {
		src = IdentityFileVar
	}
	if len(content) > maxIdentity {
		return nil, fmt.Errorf("%w: %s: larger than %d bytes", ErrIdentity, src, maxIdentity)
	}
	ids, err := age.ParseIdentities(strings.NewReader(content))
	if err != nil {
		// age's parse errors do not echo the key material.
		return nil, fmt.Errorf("%w: %s holds no usable age identity", ErrIdentity, src)
	}
	for _, id := range ids {
		switch id.(type) {
		case *age.X25519Identity, *age.HybridIdentity:
		default:
			return nil, fmt.Errorf("%w: %s holds an identity that is not X25519 or hybrid", ErrIdentity, src)
		}
	}
	return ids, nil
}

// readAll reads at most maxIdentity+1 bytes of r.
func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxIdentity+1))
}
