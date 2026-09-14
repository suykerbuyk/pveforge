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
package kvjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
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
// v must marshal to a JSON object at the top level (a struct or
// map[string]...) — Render returns an error for anything else (a slice,
// a bare scalar), since KV mode has no defined shape for those. This
// package's callers only ever pass single-object getter results
// (GetNode/GetVM/GetStorage/GetNetworkInterface) — see the task's own
// scope decision to leave list rendering for a later task.
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
		pretty.WriteByte('\n')
		_, err := w.Write(pretty.Bytes())
		return err
	case KV:
		return renderKV(w, compact)
	default:
		return fmt.Errorf("render: unknown format %q", f)
	}
}

// renderKV flattens compact (a JSON object) to sorted "key=value" lines.
func renderKV(w io.Writer, compact []byte) error {
	var flat map[string]json.RawMessage
	if err := json.Unmarshal(compact, &flat); err != nil {
		return fmt.Errorf("render: kv output requires a JSON object at the top level: %w", err)
	}

	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val, err := kvScalar(flat[k])
		if err != nil {
			return fmt.Errorf("render: field %q: %w", k, err)
		}
		if _, err := fmt.Fprintf(w, "%s=%s\n", k, val); err != nil {
			return err
		}
	}
	return nil
}

// kvScalar renders one JSON value as a single line for key=value output:
// a JSON string is unquoted; anything else (number, bool, null, a nested
// object/array) is rendered as its own compact JSON text — already
// single-line, since it came from a compact (non-indented) marshal — good
// enough for a nested field like go-proxmox's CPUInfo/RootFS structs
// without inventing a nested key=value dialect.
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
func kvScalar(raw json.RawMessage) (string, error) {
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
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse json fields: %w", err)
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]Pair, 0, len(keys))
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
			return nil, fmt.Errorf("parse json fields: field %q: %w", k, err)
		}
		s, ok := iface.(string)
		if !ok {
			return nil, fmt.Errorf("parse json fields: field %q: value must be a JSON string", k)
		}
		pairs = append(pairs, Pair{Field: k, Value: s})
	}
	return pairs, nil
}
