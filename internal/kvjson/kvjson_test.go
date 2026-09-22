package kvjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	if f, err := ParseFormat("kv"); err != nil || f != KV {
		t.Errorf("ParseFormat(kv) = %q, %v", f, err)
	}
	if f, err := ParseFormat("json"); err != nil || f != JSON {
		t.Errorf("ParseFormat(json) = %q, %v", f, err)
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("expected an error for an unsupported format")
	}
	if _, err := ParseFormat(""); err == nil {
		t.Error("expected an error for an empty format")
	}
}

type testNode struct {
	Name    string   `json:"name"`
	Uptime  uint64   `json:"uptime"`
	Online  bool     `json:"online"`
	Tags    []string `json:"tags,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

type testNested struct {
	Name string    `json:"name"`
	Info testInner `json:"info"`
}

type testInner struct {
	MHz int `json:"mhz"`
}

func TestRender_KV(t *testing.T) {
	v := testNode{Name: "qa-pve-01", Uptime: 12345, Online: true, Tags: []string{"a", "b"}}
	var buf bytes.Buffer
	if err := Render(&buf, KV, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()

	want := "name=qa-pve-01\nonline=true\ntags=[\"a\",\"b\"]\nuptime=12345\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRender_KV_OmitsEmptyFields(t *testing.T) {
	v := testNode{Name: "qa-pve-01"}
	var buf bytes.Buffer
	if err := Render(&buf, KV, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	if strings.Contains(got, "comment=") || strings.Contains(got, "tags=") {
		t.Fatalf("expected omitempty fields to be absent, got:\n%s", got)
	}
}

func TestRender_KV_NestedStructIsCompactSingleLine(t *testing.T) {
	v := testNested{Name: "qa-pve-01", Info: testInner{MHz: 2400}}
	var buf bytes.Buffer
	if err := Render(&buf, KV, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	want := "info={\"mhz\":2400}\nname=qa-pve-01\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if strings.Count(got, "\n") != 2 {
		t.Fatalf("expected exactly 2 lines, got: %q", got)
	}
}

// testWithNullable has a field that genuinely marshals to JSON null (a
// nil pointer, no omitempty) — distinct from a genuinely empty string.
type testWithNullable struct {
	Name    string  `json:"name"`
	Comment *string `json:"comment"`
}

// TestRender_KV_NullFieldRendersAsLiteralNull guards against the defect
// where Scalar relied on json.Unmarshal(raw, &s) succeeding (a
// documented no-op for JSON null unmarshaled into a non-pointer string,
// per encoding/json) to detect "not a string" — which made a null field
// render identically to a genuinely empty string ("field=" either way),
// even though JSON mode correctly distinguishes them ("field": null vs
// "field": "").
func TestRender_KV_NullFieldRendersAsLiteralNull(t *testing.T) {
	v := testWithNullable{Name: "qa-pve-01", Comment: nil}
	var buf bytes.Buffer
	if err := Render(&buf, KV, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	want := "comment=null\nname=qa-pve-01\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestRender_KVAndJSON_AgreeOnNullField is the cross-mode consistency
// check Render's own doc comment promises: KV and JSON must agree on
// which fields appear and what their values are, including for a null
// field.
func TestRender_KVAndJSON_AgreeOnNullField(t *testing.T) {
	v := testWithNullable{Name: "qa-pve-01", Comment: nil}

	var kvBuf bytes.Buffer
	if err := Render(&kvBuf, KV, v); err != nil {
		t.Fatalf("Render (kv): %v", err)
	}
	if !strings.Contains(kvBuf.String(), "comment=null") {
		t.Fatalf("kv output should show comment=null, got:\n%s", kvBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := Render(&jsonBuf, JSON, v); err != nil {
		t.Fatalf("Render (json): %v", err)
	}
	if !strings.Contains(jsonBuf.String(), `"comment": null`) {
		t.Fatalf(`json output should show "comment": null, got:%s`, jsonBuf.String())
	}
}

func TestRender_JSON(t *testing.T) {
	v := testNode{Name: "qa-pve-01", Uptime: 12345, Online: true}
	var buf bytes.Buffer
	if err := Render(&buf, JSON, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "{\n") {
		t.Fatalf("expected indented JSON, got: %q", got)
	}
	if !strings.Contains(got, `"name": "qa-pve-01"`) {
		t.Fatalf("expected indented field, got: %q", got)
	}
	if !strings.HasSuffix(got, "}\n") {
		t.Fatalf("expected a trailing newline after the closing brace, got: %q", got)
	}
}

func TestRender_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, Format("yaml"), testNode{}); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestRender_KV_RejectsNonObjectTopLevel(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, KV, []testNode{{Name: "a"}, {Name: "b"}}); err == nil {
		t.Fatal("expected an error rendering a slice as kv")
	}
}

// TestRender_KV_RejectsTopLevelNull (K1) pins that a top-level null is a
// non-object like any other in kv mode, both as a nil interface and as a
// raw JSON null — encoding/json would otherwise unmarshal it into a nil map
// without error and print nothing. JSON mode still renders it as null.
func TestRender_KV_RejectsTopLevelNull(t *testing.T) {
	for _, c := range []struct {
		name string
		v    interface{}
	}{
		{"nil", nil},
		{"raw null", json.RawMessage("null")},
	} {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Render(&buf, KV, c.v); err == nil {
				t.Fatal("expected an error rendering a top-level null as kv")
			}
			if buf.Len() != 0 {
				t.Fatalf("expected nothing written, got %q", buf.String())
			}

			buf.Reset()
			if err := Render(&buf, JSON, c.v); err != nil {
				t.Fatalf("JSON mode must still render null: %v", err)
			}
			if got := buf.String(); got != "null\n" {
				t.Fatalf("JSON render = %q, want %q", got, "null\n")
			}
		})
	}
}

// failingWriter always returns an error from Write — used to prove
// Render propagates a downstream write failure instead of swallowing it.
type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

func TestRender_JSON_PropagatesWriteFailure(t *testing.T) {
	if err := Render(failingWriter{}, JSON, testNode{Name: "a"}); err == nil {
		t.Fatal("expected the write failure to propagate")
	}
}

func TestRender_KV_PropagatesWriteFailure(t *testing.T) {
	if err := Render(failingWriter{}, KV, testNode{Name: "a"}); err == nil {
		t.Fatal("expected the write failure to propagate")
	}
}

func TestRender_MarshalFailure(t *testing.T) {
	var buf bytes.Buffer
	// A channel cannot be marshaled to JSON.
	if err := Render(&buf, JSON, make(chan int)); err == nil {
		t.Fatal("expected a marshal error")
	}
}

// TestScalar is a direct table test of Scalar — previously covered only
// indirectly through Render's own KV-mode tests. Exported (not just an
// internal Render helper) since internal/idempotent's VMFieldsEnsure now
// also depends on its exact coercion rules to compare a raw PVE config
// field's current JSON-typed value against a caller-supplied plain-string
// wanted value.
func TestScalar(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"web-01"`, "web-01"},
		{"empty string", `""`, ""},
		{"number", `4`, "4"},
		{"float", `1.5`, "1.5"},
		{"bool true", `true`, "true"},
		{"bool false", `false`, "false"},
		{"null", `null`, "null"},
		{"nested object", `{"a":1}`, `{"a":1}`},
		{"nested array", `[1,2]`, `[1,2]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Scalar(json.RawMessage(c.raw))
			if err != nil {
				t.Fatalf("Scalar(%s): %v", c.raw, err)
			}
			if got != c.want {
				t.Errorf("Scalar(%s) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestParseKVArgs(t *testing.T) {
	pairs, err := ParseKVArgs([]string{"cores=4", "name=web-01", "empty="})
	if err != nil {
		t.Fatalf("ParseKVArgs: %v", err)
	}
	want := []Pair{{"cores", "4"}, {"name", "web-01"}, {"empty", ""}}
	if len(pairs) != len(want) {
		t.Fatalf("got %d pairs, want %d", len(pairs), len(want))
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Errorf("pair %d = %+v, want %+v", i, pairs[i], want[i])
		}
	}
}

func TestParseKVArgs_PreservesInputOrder(t *testing.T) {
	pairs, err := ParseKVArgs([]string{"z=1", "a=2", "m=3"})
	if err != nil {
		t.Fatalf("ParseKVArgs: %v", err)
	}
	gotOrder := []string{pairs[0].Field, pairs[1].Field, pairs[2].Field}
	wantOrder := []string{"z", "a", "m"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("order = %v, want %v", gotOrder, wantOrder)
		}
	}
}

func TestParseKVArgs_InvalidPairs(t *testing.T) {
	cases := []string{"novalue", "=noname", ""}
	for _, c := range cases {
		if _, err := ParseKVArgs([]string{c}); err == nil {
			t.Errorf("ParseKVArgs(%q): expected an error", c)
		}
	}
}

func TestParseKVArgs_ValueContainingEquals(t *testing.T) {
	pairs, err := ParseKVArgs([]string{"args=-device nvme,drive=d0"})
	if err != nil {
		t.Fatalf("ParseKVArgs: %v", err)
	}
	if pairs[0].Field != "args" || pairs[0].Value != "-device nvme,drive=d0" {
		t.Errorf("unexpected split on a value containing '=': %+v", pairs[0])
	}
}

func TestParseJSONFields(t *testing.T) {
	pairs, err := ParseJSONFields([]byte(`{"cores":"4","name":"web-01"}`))
	if err != nil {
		t.Fatalf("ParseJSONFields: %v", err)
	}
	want := []Pair{{"cores", "4"}, {"name", "web-01"}} // sorted by key
	if len(pairs) != len(want) {
		t.Fatalf("got %d pairs, want %d", len(pairs), len(want))
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Errorf("pair %d = %+v, want %+v", i, pairs[i], want[i])
		}
	}
}

func TestParseJSONFields_SortedByKey(t *testing.T) {
	pairs, err := ParseJSONFields([]byte(`{"z":"1","a":"2","m":"3"}`))
	if err != nil {
		t.Fatalf("ParseJSONFields: %v", err)
	}
	gotOrder := []string{pairs[0].Field, pairs[1].Field, pairs[2].Field}
	wantOrder := []string{"a", "m", "z"}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("order = %v, want %v", gotOrder, wantOrder)
		}
	}
}

func TestParseJSONFields_RejectsNonStringValues(t *testing.T) {
	cases := []string{
		`{"cores":4}`,
		`{"enabled":true}`,
		`{"tags":["a","b"]}`,
		`{"nested":{"x":1}}`,
		`{"missing":null}`,
	}
	for _, c := range cases {
		if _, err := ParseJSONFields([]byte(c)); err == nil {
			t.Errorf("ParseJSONFields(%q): expected an error for a non-string value", c)
		}
	}
}

func TestParseJSONFields_InvalidJSON(t *testing.T) {
	if _, err := ParseJSONFields([]byte("not json")); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestParseJSONFields_NonObjectTopLevel(t *testing.T) {
	if _, err := ParseJSONFields([]byte(`["a","b"]`)); err == nil {
		t.Fatal("expected an error for a non-object top-level JSON value")
	}
}

func TestParseJSONFields_Empty(t *testing.T) {
	pairs, err := ParseJSONFields([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseJSONFields: %v", err)
	}
	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs, got %d", len(pairs))
	}
}

// ---- kv line contract: quoting (pveforge-kv-output-newline-forgery) ----

// lineSeps is every code point Python's str.splitlines() breaks on —
// measured, not recalled: 0a 0b 0c 0d 1c 1d 1e 85 2028 2029. A kv line
// must never contain one raw, or a line-oriented consumer reads a forged
// extra line.
var lineSeps = []rune{'\n', '\v', '\f', '\r', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029'}

func isLineSep(r rune) bool {
	for _, s := range lineSeps {
		if r == s {
			return true
		}
	}
	return false
}

// pyLines counts the non-empty lines out splits into under every
// separator in lineSeps — the Go stand-in for len(out.splitlines()).
func pyLines(out string) int { return len(strings.FieldsFunc(out, isLineSep)) }

// parseKVLine is a reference consumer implementing the package doc's two
// rules exactly, so the contract is tested as executable documentation
// rather than re-read. valueQuoted reports whether the value was a JSON
// string token.
func parseKVLine(t *testing.T, line string) (key, value string, valueQuoted bool) {
	t.Helper()
	var rest string
	if strings.HasPrefix(line, `"`) {
		dec := json.NewDecoder(strings.NewReader(line))
		if err := dec.Decode(&key); err != nil {
			t.Fatalf("rule 1: line %q starts with a quote but no JSON string key: %v", line, err)
		}
		rest = line[dec.InputOffset():]
	} else {
		i := strings.IndexByte(line, '=')
		if i < 0 {
			t.Fatalf("rule 1: line %q has no '='", line)
		}
		key, rest = line[:i], line[i:]
	}
	if !strings.HasPrefix(rest, "=") {
		t.Fatalf("rule 1: key of line %q is not followed by '=' (rest %q)", line, rest)
	}
	rest = rest[1:]
	if strings.HasPrefix(rest, `"`) {
		if err := json.Unmarshal([]byte(rest), &value); err != nil {
			t.Fatalf("rule 2: value %q of line %q starts with a quote but is not exactly one JSON string: %v", rest, line, err)
		}
		return key, value, true
	}
	return key, rest, false
}

func renderKVString(t *testing.T, v interface{}) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, KV, v); err != nil {
		t.Fatalf("Render: %v", err)
	}
	return buf.String()
}

// K1-K5, K7: string values that could be misread are written as one JSON
// string; the expected text is spelled out byte for byte.
func TestRender_KV_QuotesMisreadableStringValues(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"K1 newline forging a key", "a\nb=c", `f="a\nb=c"` + "\n"},
		{"K2 carriage return", "a\rb", `f="a\rb"` + "\n"},
		{"K3 tab", "a\tb", `f="a\tb"` + "\n"},
		{"K4 leading space", " x", `f=" x"` + "\n"},
		{"K4 trailing space", "x ", `f="x "` + "\n"},
		{"K5 leading quote", `"q`, `f="\"q"` + "\n"},
		{"K7 U+2028", "x\u2028y", `f="x\u2028y"` + "\n"},
		{"interior quote stays plain", `a"b`, `f=a"b` + "\n"},
		// Non-ASCII whitespace at an edge (unicode.IsSpace, not an ASCII set).
		{"U+00A0 leading", "\u00a0x", "f=\"\u00a0x\"\n"},
		{"U+3000 trailing", "x\u3000", "f=\"x\u3000\"\n"},
		{"interior space stays plain", "a b", "f=a b\n"},
		{"equals in a value stays plain", "a=b", "f=a=b\n"},
		{"empty stays plain", "", "f=\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := renderKVString(t, map[string]string{"f": c.value})
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			if n := pyLines(got); n != 1 {
				t.Fatalf("%q splits into %d lines, want 1", got, n)
			}
			if _, v, _ := parseKVLine(t, strings.TrimSuffix(got, "\n")); v != c.value {
				t.Fatalf("reference parser read value %q, want %q", v, c.value)
			}
		})
	}
}

// K6: the string "null" and JSON null must stay distinguishable in kv.
func TestRender_KV_StringNullIsQuotedJSONNullIsBare(t *testing.T) {
	got := renderKVString(t, map[string]interface{}{"n": nil, "s": "null"})
	want := "n=null\n" + `s="null"` + "\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// K8, K8b: a key containing '=' is quoted, and the reference parser
// recovers both the key and a value that itself contains '='.
func TestRender_KV_QuotesKeysContainingEquals(t *testing.T) {
	got := renderKVString(t, map[string]string{"a=b": "c=d"})
	if want := `"a=b"=c=d` + "\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	k, v, quoted := parseKVLine(t, strings.TrimSuffix(got, "\n"))
	if k != "a=b" || v != "c=d" || quoted {
		t.Fatalf("round trip = (%q, %q, quoted=%v), want (a=b, c=d, false)", k, v, quoted)
	}
}

// A key with non-ASCII whitespace at an edge is quoted like any other
// edge whitespace, and round-trips through the reference parser.
func TestRender_KV_QuotesKeyWithNonASCIIEdgeWhitespace(t *testing.T) {
	k := "\u3000k"
	got := renderKVString(t, map[string]string{k: "v"})
	if want := "\"\u3000k\"=v\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if gk, gv, _ := parseKVLine(t, strings.TrimSuffix(got, "\n")); gk != k || gv != "v" {
		t.Fatalf("round trip (%q, %q), want (%q, v)", gk, gv, k)
	}
}

// A key equal to "null" is deliberately NOT quoted: no consumer can read a
// key as JSON null, so the value-side special case does not apply.
func TestQuoteKey_NullIsNotQuoted(t *testing.T) {
	if got := QuoteKey("null"); got != "null" {
		t.Fatalf("QuoteKey(null) = %q, want null", got)
	}
}

// K9: plain values, numbers, bools and nested structures render exactly as
// before the contract existed.
func TestRender_KV_PlainAndNonStringValuesUnchanged(t *testing.T) {
	got := renderKVString(t, map[string]interface{}{
		"b": true, "n": 4, "o": map[string]interface{}{"a": "x y", "b": []int{1}}, "s": "web-01",
	})
	want := "b=true\nn=4\n" + `o={"a":"x y","b":[1]}` + "\ns=web-01\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// K10: U+0085 (NEL) is a Cc code point, so it triggers quoting, and it is
// escaped as \u0085 — encoding/json alone would leave it raw even inside
// quotes.
func TestRender_KV_NELIsQuotedAndEscaped(t *testing.T) {
	got := renderKVString(t, map[string]string{"f": "x\u0085y"})
	if want := `f="x\u0085y"` + "\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if n := pyLines(got); n != 1 {
		t.Fatalf("%q splits into %d lines, want 1", got, n)
	}
}

// K11: a nested (non-string) value carrying C1 runes stays on one line and
// is still valid JSON that decodes back to the original.
func TestRender_KV_NestedValueEscapesC1AndStaysValidJSON(t *testing.T) {
	in := map[string]interface{}{"s": "x\u0085y\u007fz\u009f"}
	got := renderKVString(t, map[string]interface{}{"o": in})
	if n := pyLines(got); n != 1 {
		t.Fatalf("%q splits into %d lines, want 1", got, n)
	}
	for _, r := range strings.TrimSuffix(got, "\n") {
		if r >= 0x7f && r <= 0x9f {
			t.Fatalf("raw C1 rune %U left in %q", r, got)
		}
	}
	_, v, quoted := parseKVLine(t, strings.TrimSuffix(got, "\n"))
	if quoted {
		t.Fatalf("a nested value must stay literal JSON text, got a quoted string")
	}
	var back map[string]interface{}
	if err := json.Unmarshal([]byte(v), &back); err != nil {
		t.Fatalf("nested value %q is no longer valid JSON: %v", v, err)
	}
	if back["s"] != in["s"] {
		t.Fatalf("decoded %q, want %q", back["s"], in["s"])
	}
}

// K12: every line separator, in a string value and in a key, yields
// exactly one line that round-trips through the reference parser.
func TestRender_KV_EveryLineSeparatorStaysOneLine(t *testing.T) {
	for _, sep := range lineSeps {
		s := "a" + string(sep) + "b"
		t.Run(fmt.Sprintf("value %U", sep), func(t *testing.T) {
			got := renderKVString(t, map[string]string{"f": s})
			if n := pyLines(got); n != 1 {
				t.Fatalf("%q splits into %d lines, want 1", got, n)
			}
			if _, v, _ := parseKVLine(t, strings.TrimSuffix(got, "\n")); v != s {
				t.Fatalf("round trip value %q, want %q", v, s)
			}
		})
		t.Run(fmt.Sprintf("key %U", sep), func(t *testing.T) {
			got := renderKVString(t, map[string]string{s: "v"})
			if n := pyLines(got); n != 1 {
				t.Fatalf("%q splits into %d lines, want 1", got, n)
			}
			if k, v, _ := parseKVLine(t, strings.TrimSuffix(got, "\n")); k != s || v != "v" {
				t.Fatalf("round trip (%q, %q), want (%q, v)", k, v, s)
			}
		})
	}
}

// KRT: a mixed table of hostile keys and values round-trips through the
// reference parser, line by line, in one Render call.
func TestRender_KV_RoundTripsThroughReferenceParser(t *testing.T) {
	in := map[string]string{
		"plain": "web-01", "a=b": "c=d", "lit": `a\nb`, "empty": "", "nul": "null",
		"q": `"`, "lead": " x", "c1": "x\u0085y", "del": "x\u007fy", "ls": "x\u2028y",
		"k\nforged": "v", " sp": "v", `"k`: "v", "html": "<b>&", "nl": "line1\nline2\n",
	}
	got := renderKVString(t, in)
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != len(in) {
		t.Fatalf("%d raw lines for %d fields:\n%s", len(lines), len(in), got)
	}
	if n := pyLines(got); n != len(in) {
		t.Fatalf("splitlines-equivalent sees %d lines for %d fields", n, len(in))
	}
	seen := map[string]string{}
	for _, l := range lines {
		k, v, _ := parseKVLine(t, l)
		seen[k] = v
	}
	for k, want := range in {
		if got, ok := seen[k]; !ok || got != want {
			t.Errorf("key %q: parsed %q (present=%v), want %q", k, got, ok, want)
		}
	}
}

// KHTML: the quoted form does not HTML-escape, so the same characters
// have one spelling whether or not something else triggered quoting.
func TestRender_KV_QuotedFormDoesNotHTMLEscape(t *testing.T) {
	got := renderKVString(t, map[string]string{"a": "<b>&", "b": "<b>&\n"})
	want := "a=<b>&\n" + `b="<b>&\n"` + "\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// KS: Scalar returns the RAW string, never kv's quoted form. It is the
// comparison primitive internal/idempotent converges on; quoting here
// would make an already-correct value look different on every run.
func TestScalar_ReturnsRawStringUnescaped(t *testing.T) {
	for _, want := range []string{"a\nb=c", " x ", "null", `"q`, "x\u0085y"} {
		raw, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Scalar(raw)
		if err != nil {
			t.Fatalf("Scalar(%s): %v", raw, err)
		}
		if got != want {
			t.Errorf("Scalar(%s) = %q, want the raw %q", raw, got, want)
		}
	}
}
