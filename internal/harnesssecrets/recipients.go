package harnesssecrets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"filippo.io/age"
)

// Recipient is one line of recipients.txt: a public age recipient and the
// consumer it belongs to.
type Recipient struct {
	Key  age.Recipient
	Text string // the age1… string, as written
	Name string // the consumer, e.g. operator or ci-runner-lab1
}

// ErrInvalidRecipients marks a recipients.txt that does not follow its
// grammar.
var ErrInvalidRecipients = errors.New("invalid recipients file")

var (
	recipientLineRE = regexp.MustCompile(`^(\S+)[ \t]+#[ \t]*([A-Za-z0-9._-]+)[ \t]*$`)
)

// ParseRecipients parses recipients.txt: an empty line or one starting with
// '#' is skipped; every other line is `<recipient> # <consumer>`. The
// recipient must be an X25519 (age1…) or hybrid post-quantum (age1pq1…)
// recipient — SSH and plugin recipients are refused — and the consumer name
// ([A-Za-z0-9._-]+) is required. Recipients and names are each unique, and
// at least one line is required. All recipients are of one kind, X25519 or
// hybrid: age cannot seal one file to both.
func ParseRecipients(b []byte) ([]Recipient, error) {
	var out []Recipient
	for i, line := range strings.Split(string(b), "\n") {
		n := i + 1
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := recipientLineRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%w: line %d is not `<recipient> # <consumer>`", ErrInvalidRecipients, n)
		}
		var key age.Recipient
		var err error
		switch {
		case strings.HasPrefix(m[1], "age1pq1"):
			key, err = age.ParseHybridRecipient(m[1])
		case strings.HasPrefix(m[1], "age1"):
			key, err = age.ParseX25519Recipient(m[1])
		default:
			err = errors.New("unknown kind")
		}
		if err != nil {
			// A fixed message: age's own error quotes the input.
			return nil, fmt.Errorf("%w: line %d is not a valid X25519 or hybrid age recipient", ErrInvalidRecipients, n)
		}
		for _, r := range out {
			if r.Text == m[1] {
				return nil, fmt.Errorf("%w: line %d repeats the recipient of %s", ErrInvalidRecipients, n, r.Name)
			}
			if r.Name == m[2] {
				return nil, fmt.Errorf("%w: line %d repeats the consumer name %s", ErrInvalidRecipients, n, m[2])
			}
		}
		out = append(out, Recipient{Key: key, Text: m[1], Name: m[2]})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no recipients", ErrInvalidRecipients)
	}
	// age refuses to seal one file to both kinds: a classic recipient would
	// leave it open to a quantum adversary. So every consumer uses one kind.
	pq := strings.HasPrefix(out[0].Text, "age1pq1")
	for _, r := range out[1:] {
		if strings.HasPrefix(r.Text, "age1pq1") != pq {
			return nil, fmt.Errorf("%w: it mixes post-quantum (age1pq1…) and classic (age1…) recipients, which age cannot seal to together; give every consumer the same kind", ErrInvalidRecipients)
		}
	}
	return out, nil
}
