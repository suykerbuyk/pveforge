package idempotent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// pveAnswer is PVE's typed answer (*pve.StatusError) whose text is exactly
// text, which must have the shape every such answer's text has:
// "<what>: pve returned <status line>: <body>". The absence classifiers read
// only typed answers (pve.NotFound), so a fixture standing for one is
// built typed — never as bare text, which they rightly refuse.
//
// It is also the guard that the conversion from bare-text fixtures changed
// no input: it panics unless the typed error's Error() is text, byte for
// byte, so every classifier test still feeds the exact text it always did.
func pveAnswer(text string) error {
	const marker = ": pve returned "
	i := strings.Index(text, marker)
	if i < 0 {
		panic(fmt.Sprintf("pveAnswer: %q is not a PVE answer's text", text))
	}
	what, rest := text[:i], text[i+len(marker):]
	j := strings.Index(rest, ": ")
	if j < 0 {
		panic(fmt.Sprintf("pveAnswer: %q has no status line", text))
	}
	status, body := rest[:j], rest[j+2:]
	code, err := strconv.Atoi(strings.SplitN(status, " ", 2)[0])
	if err != nil {
		panic(fmt.Sprintf("pveAnswer: %q: status %q has no code", text, status))
	}
	se := pve.NewStatusError(what, code, status, []byte(body))
	if se.Error() != text {
		panic(fmt.Sprintf("pveAnswer: the typed answer's text %q differs from the fixture's %q", se.Error(), text))
	}
	return se
}

// fixtureErr is a table fixture's error: PVE's typed answer (pveAnswer)
// when text is an answer's text, and bare text otherwise — a transport
// error, which quotes the request URL and was never a PVE answer, stays
// the untyped error it always was.
func fixtureErr(text string) error {
	if strings.Contains(text, ": pve returned ") {
		return pveAnswer(text)
	}
	return errors.New(text)
}
