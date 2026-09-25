// Package harnesssecrets is the nested-harness secrets tool behind
// hack/harness/unlock.sh (pveforge-harness-secrets-unlock): an age-encrypted
// env file committed as hack/harness/secrets.age, sealed to the public
// recipients in hack/harness/recipients.txt, and opened with one consumer's
// private identity into a child process's environment only — never onto
// disk, never into argv.
//
// There is no 1Password (or any password-manager) dependency anywhere here.
package harnesssecrets

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AllowedNames are the only variable names a blob may carry. age does not
// authenticate the sender: anyone who can commit can seal a blob to the
// public recipients, so without this list a blob could put PATH, LD_PRELOAD
// or BASH_ENV into every child of `run`. Adding a name is a reviewed code
// change, never data. The nested test root password is stored under its own
// name, never as PVEFORGE_PVE_PASSWORD, which at D5 G4 is the OUTER root
// password; H3 maps it explicitly for the nested bootstrap only.
var AllowedNames = []string{
	"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD",
	"PVEFORGE_ROSTER_PASSPHRASE",
}

// maxPlaintext bounds the env file.
const maxPlaintext = 64 << 10

// Pair is one NAME=value entry.
type Pair struct {
	Name, Value string
}

// ErrInvalidEnv marks a plaintext env file that does not follow the grammar.
// Its messages name a line number and, at most, a variable NAME — never a
// value.
var ErrInvalidEnv = errors.New("invalid secrets env file")

// ParseEnv parses the plaintext env grammar, without eval or a shell:
//
//   - UTF-8 text with LF line ends; a CR or NUL anywhere is refused;
//   - an empty line, or one starting with '#', is skipped;
//   - every other line is NAME=value, split at the first '=': NAME must be
//     one of AllowedNames, and value is the rest of the line verbatim — no
//     quoting, escapes, expansion or trimming — non-empty and free of
//     control characters;
//   - a NAME may appear once; at least one pair is required;
//   - the whole file is at most 64 KiB.
//
// The pairs are returned sorted by name.
func ParseEnv(b []byte) ([]Pair, error) {
	if len(b) > maxPlaintext {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidEnv, maxPlaintext)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrInvalidEnv)
	}
	if bytes.ContainsAny(b, "\r\x00") {
		return nil, fmt.Errorf("%w: contains a CR or NUL byte", ErrInvalidEnv)
	}
	var pairs []Pair
	for i, line := range strings.Split(string(b), "\n") {
		n := i + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: line %d is not NAME=value", ErrInvalidEnv, n)
		}
		if !slices.Contains(AllowedNames, name) {
			return nil, fmt.Errorf("%w: line %d: a name that is not allowed (allowed: %s)", ErrInvalidEnv, n, strings.Join(AllowedNames, ", "))
		}
		if value == "" {
			return nil, fmt.Errorf("%w: line %d: %s has an empty value", ErrInvalidEnv, n, name)
		}
		if strings.ContainsFunc(value, unicode.IsControl) {
			return nil, fmt.Errorf("%w: line %d: %s's value contains a control character", ErrInvalidEnv, n, name)
		}
		if slices.ContainsFunc(pairs, func(p Pair) bool { return p.Name == name }) {
			return nil, fmt.Errorf("%w: line %d: %s appears twice", ErrInvalidEnv, n, name)
		}
		pairs = append(pairs, Pair{name, value})
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("%w: no NAME=value line", ErrInvalidEnv)
	}
	slices.SortFunc(pairs, func(a, b Pair) int { return strings.Compare(a.Name, b.Name) })
	return pairs, nil
}

// formatEnv is the canonical plaintext of pairs: NAME=value lines, sorted,
// no comments. It is what seal and reseal encrypt.
func formatEnv(pairs []Pair) []byte {
	var b bytes.Buffer
	for _, p := range pairs {
		b.WriteString(p.Name + "=" + p.Value + "\n")
	}
	return b.Bytes()
}
