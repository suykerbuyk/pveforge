// Package kvjson is pveforge's I/O rendering/parsing layer (PRD §3.6): a
// thin conversion between Go values (typically go-proxmox typed structs
// returned by internal/pve's getters) and the CLI's two supported formats
// — plain key=value lines for scriptable one-liners, and JSON as the
// primary structured format for both reading and multi-field writes.
//
// Deliberately dumb: this package knows nothing about roster, pve, or
// what any given field means — it only converts between shapes. Anything
// about what a field means belongs in the object-model or discoverability
// layers, not here.
//
// The kv line contract, for a consumer reading one line at a time:
//
//   - Key: if the line starts with `"`, the key is exactly one JSON string
//     token and the character after its closing quote is `=`. Otherwise the
//     key is everything before the first `=`.
//   - Value: everything after that `=`. If it starts with `"`, it is exactly
//     one JSON string. Otherwise it is literal text.
//
// A key or string value is written as a JSON string only when it could
// otherwise be misread: it contains a control character (C0 or C1), U+2028
// or U+2029 (so no line splitter, Python's str.splitlines included, sees a
// second line), starts or ends with whitespace, or starts with `"`; a key
// also when it contains `=`, a value also when it is exactly "null" (so it
// stays distinct from JSON null, which prints as a bare null). Everything
// else is written as-is. kv does not preserve JSON types — the string
// "true" and the bool true print alike — so use -o json for exact data.
package kvjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Format names one of the two supported I/O formats.
type Format string

const (
	KV   Format = "kv"
	JSON Format = "json"
)

// ParseFormat validates a --output flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case KV, JSON:
		return Format(s), nil
	default:
		return "", fmt.Errorf(`invalid output format %q: must be "kv" or "json"`, s)
	}
}

// Render writes v to w in format f. v is marshaled to JSON exactly once
// (compact) as the single source of truth for both formats: JSON mode
// re-indents that same encoding for display; KV mode flattens its
// top-level fields to sorted "key=value" lines. This means the two modes
// always agree on exactly which fields appear (respecting the underlying
// struct's own `omitempty` tags) and what their values are — KV is a view
// of the same data, not a separately-maintained rendering.
//
// KV lines follow the package doc's line contract: a key or string value
// that could be misread is written as a JSON string (QuoteKey,
// QuoteValue), everything else as-is.
//
// v must marshal to a JSON object at the top level (a struct or
// map[string]...) — Render returns an error for anything else (a slice,
// a bare scalar, null), since KV mode has no defined shape for those. A
// caller holding anything else wraps it under one field first, as
// cmd/pveforge's storage orphan listing and `api` verbs do.
func Render(w io.Writer, f Format, v interface{}) error {
	compact, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("render: marshal: %w", err)
	}

	switch f {
	case JSON:
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, compact, "", "  "); err != nil {
			return fmt.Errorf("render: indent: %w", err)
		}
		// encoding/json escapes C0 and U+2028/9 but writes DEL and C1 raw;
		// escaped here as kv does, the text is still valid JSON decoding
		// to the same value, and a terminal never receives a raw C1.
		_, err := io.WriteString(w, escapeC1(pretty.String())+"\n")
		return err
	case KV:
		return renderKV(w, compact)
	default:
		return fmt.Errorf("render: unknown format %q", f)
	}
}

// renderKV flattens compact (a JSON object) to sorted "key=value" lines,
// following the package doc's line contract: keys through QuoteKey, string
// values through QuoteValue, and any other value as its own compact JSON
// with the C1 range escaped (escapeC1) so it stays on one line.
//
// A top-level null is refused like any other non-object. encoding/json
// unmarshals the literal null into a map as a documented no-op (no error,
// nil map), so without the explicit check below a null would render as no
// output at all and exit successfully — indistinguishable from an empty
// object, and contrary to Render's own contract.
func renderKV(w io.Writer, compact []byte) error {
	var flat map[string]json.RawMessage
	if err := json.Unmarshal(compact, &flat); err != nil {
		return fmt.Errorf("render: kv output requires a JSON object at the top level: %w", err)
	}
	if flat == nil {
		return fmt.Errorf("render: kv output requires a JSON object at the top level, got null")
	}

	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val, err := kvValue(flat[k])
		if err != nil {
			return fmt.Errorf("render: field %q: %w", k, err)
		}
		if _, err := fmt.Fprintf(w, "%s=%s\n", QuoteKey(k), val); err != nil {
			return err
		}
	}
	return nil
}

// kvValue renders one field's JSON value for a kv line: a JSON string
// through QuoteValue, null as a bare null, anything else as its compact
// JSON with escapeC1 applied. Scalar is deliberately NOT changed to do
// this: internal/idempotent compares PVE values through Scalar, and
// quoting there would change what converges.
func kvValue(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", err
		}
		return QuoteValue(s), nil
	}
	s, err := Scalar(raw)
	if err != nil {
		return "", err
	}
	return escapeC1(s), nil
}

// QuoteKey returns k as it should appear before the `=` of a kv line: k
// itself, or its JSON-quoted form when k could be misread — it contains a
// control character, U+2028/U+2029 or `=`, starts or ends with whitespace,
// or starts with `"`. See the package doc for the full line contract.
func QuoteKey(k string) string {
	if needsQuote(k) || strings.Contains(k, "=") {
		return quoteString(k)
	}
	return k
}

// QuoteValue returns v as it should appear after the `=` of a kv line: v
// itself, or its JSON-quoted form when v could be misread — the same
// triggers as QuoteKey except `=` (a value runs to end of line, so `=` in
// it is harmless), plus v == "null", so the string stays distinct from a
// JSON null's bare null.
func QuoteValue(v string) string {
	if needsQuote(v) || v == "null" {
		return quoteString(v)
	}
	return v
}

// LineUnsafe reports whether s, printed bare, could be misread as more or
// other than one kv or text line: the trigger set QuoteKey and QuoteValue
// share (below). A caller that must keep a string out of that set entirely
// — a roster target id, printed unquoted at the start of output lines —
// checks it here rather than keeping a second character list.
func LineUnsafe(s string) bool { return needsQuote(s) }

// needsQuote reports the triggers QuoteKey and QuoteValue share. The
// control test is unicode.IsControl, i.e. the whole Cc category: C0
// (U+0000-U+001F) and U+007F-U+009F, which includes U+0085 (NEL), a line
// break for Python's str.splitlines().
func needsQuote(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, `"`) {
		return true
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return true
	}
	return strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
	})
}

// quoteString JSON-quotes s for a kv line. encoding/json escapes C0 and
// U+2028/U+2029 but leaves U+007F-U+009F raw, so escapeC1 finishes the
// job; HTML escaping is off because kv is read by people and scripts, not
// embedded in HTML, and `<` inside quotes should look like `<`.
func quoteString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return escapeC1(strings.TrimSuffix(b.String(), "\n"))
}

// escapeC1 replaces every rune in U+007F-U+009F with its \u00XX JSON
// escape. It is applied only to JSON text (a quoted string, or a nested
// value's compact JSON, or Render's indented JSON), where those runes can occur only inside string
// literals, so the result is still valid JSON that decodes to the same
// value, and no line splitter finds a break in it.
func escapeC1(s string) string {
	if !strings.ContainsFunc(s, isC1) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if isC1(r) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isC1(r rune) bool { return r >= 0x7f && r <= 0x9f }

// Scalar renders one JSON value as a single comparable/displayable
// string: a JSON string is unquoted; anything else (number, bool, null, a
// nested object/array) is rendered as its own compact JSON text — already
// single-line, since it came from a compact (non-indented) marshal — good
// enough for a nested field like go-proxmox's CPUInfo/RootFS structs
// without inventing a nested key=value dialect. Exported (not just
// Render's own KV-mode helper) because internal/idempotent's
// VMFieldsEnsure needs the identical coercion to compare a raw PVE config
// field's current JSON-typed value against a caller-supplied plain-string
// wanted value (e.g. PVE's own "cores" comes back as a JSON number, not a
// string, but a CLI caller always types "cores=4") — reusing this rather
// than re-deriving the same non-obvious null-handling logic in a second
// package.
//
// Scalar returns the RAW string — never kv's quoted form. That is load-
// bearing: internal/idempotent compares PVE values with it, so quoting
// here would make an already-correct multi-line value look different on
// every run. kv quoting lives in renderKV (kvValue) instead.
//
// null is checked for explicitly, before attempting the string-unmarshal
// below: per encoding/json, unmarshaling the JSON literal null into a
// non-pointer string is a documented no-op (succeeds, leaves the zero
// value "") rather than an error, which would otherwise make a null field
// render identically to a genuinely empty string ("field=" either way) —
// breaking Render's own documented guarantee that KV and JSON mode always
// agree on what a field's value is (JSON mode correctly shows
// `"field": null`). Same class of bug ParseJSONFields below already
// guards against for the parse direction.
func Scalar(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		return "null", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	return trimmed, nil
}

// Pair is one field=value assignment, in caller-specified order.
type Pair struct {
	Field string
	Value string
}

// ParseKVArgs parses ["field1=value1", "field2=value2", ...] — as given
// via trailing positional CLI args — into Pairs, preserving input order.
// Each entry must contain '=' with a non-empty field name; the value may
// be empty (some PVE fields genuinely accept an empty string).
func ParseKVArgs(args []string) ([]Pair, error) {
	pairs := make([]Pair, 0, len(args))
	for _, a := range args {
		field, value, ok := strings.Cut(a, "=")
		if !ok || field == "" {
			return nil, fmt.Errorf("parse kv args: %q is not a valid field=value pair", a)
		}
		pairs = append(pairs, Pair{Field: field, Value: value})
	}
	return pairs, nil
}

// ParseJSONFields parses a flat JSON object (from --json or --json-file)
// into Pairs, ordered by sorted field name. Every value MUST be a JSON
// string — {"cores":"4"}, not {"cores":4} — deliberately no automatic
// coercion of numbers/bools/null; the raw setter this feeds
// (RoutedClient.SetVMConfigField) takes string, string, and this package
// has no business judging how a given field's type should be stringified.
func ParseJSONFields(data []byte) ([]Pair, error) {
	pairs, _, err := parseJSONFields(data, false)
	return pairs, err
}

// ParseJSONFieldsWithDeletes is ParseJSONFields for an input that may also
// remove keys (vm set): a JSON null value means "delete this key", and is
// returned in deletes (sorted, like pairs) rather than as a Pair — never as
// an empty string, which would be a write of an empty value instead. Every
// other non-string value is still refused.
func ParseJSONFieldsWithDeletes(data []byte) (pairs []Pair, deletes []string, err error) {
	return parseJSONFields(data, true)
}

func parseJSONFields(data []byte, allowDelete bool) ([]Pair, []string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("parse json fields: %w", err)
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]Pair, 0, len(keys))
	var deletes []string
	for _, k := range keys {
		// Decoding straight into a string would silently accept a JSON
		// null too: unmarshaling null into any non-pointer/interface/map/
		// slice Go value is a documented no-op in encoding/json (leaves
		// the zero value, returns no error) — exactly the "automatic
		// coercion" this function's contract rules out. Decoding into
		// interface{} first and type-asserting rejects null (and every
		// other non-string JSON type) explicitly instead of silently
		// turning it into "".
		var iface interface{}
		if err := json.Unmarshal(m[k], &iface); err != nil {
			return nil, nil, fmt.Errorf("parse json fields: field %q: %w", k, err)
		}
		if iface == nil && allowDelete {
			deletes = append(deletes, k)
			continue
		}
		s, ok := iface.(string)
		if !ok {
			if allowDelete {
				return nil, nil, fmt.Errorf("parse json fields: field %q: value must be a JSON string, or null to delete the key", k)
			}
			return nil, nil, fmt.Errorf("parse json fields: field %q: value must be a JSON string", k)
		}
		pairs = append(pairs, Pair{Field: k, Value: s})
	}
	return pairs, deletes, nil
}
