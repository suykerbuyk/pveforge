package pve

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	proxmox "github.com/suykerbuyk/go-proxmox"
)

// missingPhrase is the phrase PVE uses for an object that does not exist.
// It is matched case-insensitively.
const missingPhrase = "does not exist"

// Subject picks out the one object a NotFound check is about. Exactly one
// of two rules applies, by which fields are set; a Subject with neither
// matches nothing, so this shared helper can never become a shared
// widening of any caller's match.
//
//   - Fragment (e.g. "qemu-server/100.conf"): PVE's answer must contain the
//     fragment and the phrase, both case-insensitively, anywhere. The
//     fragment is what makes it this object: PVE's unrelated "user 'x@pve'
//     does not exist" also carries the phrase.
//   - Param, Name and Nouns (e.g. "iface", "vmbr1", {"iface",
//     "interface"}): if the answer carries PVE's parameter-verification map
//     ({"errors":{...}}), ONLY Param's entry is read. It must carry the
//     phrase and either quote exactly one name, equal to Name
//     (case-sensitive), or quote none and be the generic phrase alone
//     ("interface does not exist"), which counts as Name because the
//     request named it. The map is never bypassed once present. Otherwise
//     the answer must name Name with one of Nouns, quoted, immediately
//     followed by the phrase: iface 'vmbr1' does not exist. The quotes bound
//     the name, so vmbr1 never matches vmbr10 or vmbr1.100.
type Subject struct {
	Fragment string
	Param    string
	Name     string
	Nouns    []string
}

// NotFound reports whether err is PVE's own answer saying the object s
// picks out does not exist. It fails CLOSED: reading a missing object as
// absent satisfies a destroy, so a false positive turns the destroy into a
// silent no-op that reports success, while a false negative is a loud
// error.
//
// Only a typed answer counts — a *StatusError (RawRequest, the config PUT)
// or go-proxmox's *proxmox.StatusError, anywhere in err's chain. A
// transport failure (whose text quotes the request URL, and so the
// object's name), or any untyped text that merely looks like an answer, is
// never a match.
//
// The status code decides nothing: PVE answers a missing VM config with a
// 500 and a missing interface with a 400. What is matched is the answer's
// text: its status line and its body, as "<Status>: <body>" — the exact
// tail of the error's own message. PVE puts a die() message in the HTTP
// reason phrase, where the body may be only {"data":null}, so the status
// line cannot be left out. UNVERIFIED against a live host: where PVE 9.2
// puts each message, and whether this client's HTTP/2 drops the reason
// phrase. If it does, and the body does not repeat the message, the match
// fails closed.
func NotFound(err error, s Subject) bool {
	answer, ok := pveAnswer(err)
	if !ok {
		return false
	}
	switch {
	case s.Fragment != "":
		lower := strings.ToLower(answer)
		return strings.Contains(lower, strings.ToLower(s.Fragment)) && strings.Contains(lower, missingPhrase)
	case s.Param != "" && s.Name != "" && len(s.Nouns) > 0:
		if entries, structured := parameterErrors(answer); structured {
			return entryNamesTarget(entries[s.Param], s)
		}
		q := regexp.QuoteMeta(s.Name)
		return regexp.MustCompile(`(?i:\b(?:` + nounsPattern(s.Nouns) + `))\s+(?:'` + q + `'|"` + q + `")\s+(?i:` + missingPhrase + `)`).MatchString(answer)
	}
	return false
}

// pveAnswer returns "<Status>: <body>" of the typed PVE answer in err's
// chain, the body trimmed as the error's own message trims it.
func pveAnswer(err error) (string, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status + ": " + strings.TrimSpace(string(se.Body)), true
	}
	var pse *proxmox.StatusError
	if errors.As(err, &pse) {
		return pse.Status + ": " + strings.TrimSpace(string(pse.Body)), true
	}
	return "", false
}

func nounsPattern(nouns []string) string {
	quoted := make([]string, len(nouns))
	for i, n := range nouns {
		quoted[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(quoted, "|")
}

// parameterErrors decodes the "errors" map of a PVE parameter-verification
// body carried in answer. structured reports whether answer carries such a
// body at all; one that mentions "errors" but does not decode is still
// structured, with no usable entries, so it never falls back to the
// unstructured form.
func parameterErrors(answer string) (entries map[string]string, structured bool) {
	i := strings.IndexByte(answer, '{')
	if i < 0 {
		return nil, false
	}
	var body struct {
		Errors map[string]json.RawMessage `json:"errors"`
	}
	if err := json.NewDecoder(strings.NewReader(answer[i:])).Decode(&body); err != nil || body.Errors == nil {
		return nil, strings.Contains(answer[i:], `"errors"`)
	}
	entries = make(map[string]string, len(body.Errors))
	for k, raw := range body.Errors {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			entries[k] = text
		}
	}
	return entries, true
}

var quotedName = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)

// entryNamesTarget reports whether a parameter entry says that s.Name does
// not exist.
func entryNamesTarget(entry string, s Subject) bool {
	if !strings.Contains(strings.ToLower(entry), missingPhrase) {
		return false
	}
	names := quotedName.FindAllStringSubmatch(entry, -1)
	if len(names) == 0 {
		return regexp.MustCompile(`(?i)^\s*(?:(?:` + nounsPattern(s.Nouns) + `)\s+)?` + missingPhrase + `\.?\s*$`).MatchString(entry)
	}
	return len(names) == 1 && names[0][1]+names[0][2] == s.Name
}

// NewStatusError is the *StatusError a request described by what (e.g.
// "raw request") gets when PVE answers code with the status line status and
// body: the same value, and the same text, RawRequest and the config PUT
// return. It exists for fakes outside this package, which cannot otherwise
// build one; production code builds it from the response itself.
func NewStatusError(what string, code int, status string, body []byte) *StatusError {
	return &StatusError{
		Code:   code,
		Status: status,
		Body:   body,
		msg:    what + ": pve returned " + status + ": " + strings.TrimSpace(string(body)),
	}
}
