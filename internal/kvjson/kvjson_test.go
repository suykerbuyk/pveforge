package kvjson

import (
	"bytes"
	"encoding/json"
	"errors"
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
