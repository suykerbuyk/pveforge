package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// realisticAPIDocJS builds a fixture shaped like the real apidoc.js: the
// `const apiSchema = [ ... ];` JSON literal (payload substituted in),
// followed by unrelated ExtJS UI code that does NOT parse as JSON on its
// own — proving extraction isolates the array rather than requiring the
// whole file to be valid JSON.
func realisticAPIDocJS(payload string) string {
	return "const apiSchema = " + payload + `;

Ext.define('PVE.APIViewer', {
    extend: 'Ext.container.Container',
    layout: 'fit',
    items: [],
});
`
}

func TestAPIDocTree_Success(t *testing.T) {
	const payload = `[{"path":"/nodes/{node}/qemu/{vmid}/config","text":"config","leaf":1,"info":{"GET":{"parameters":{"properties":{"vmid":{"type":"integer"}}}}}}]`
	var gotPath string
	var gotAuth string
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(realisticAPIDocJS(payload)))
	})
	c := testClient(t, srv)

	raw, err := c.APIDocTree(context.Background())
	if err != nil {
		t.Fatalf("APIDocTree: %v", err)
	}
	if gotPath != apiDocTreePath {
		t.Errorf("request path = %q, want %q", gotPath, apiDocTreePath)
	}
	if gotAuth != "" {
		t.Errorf("expected no Authorization header on the apidoc.js fetch, got %q", gotAuth)
	}

	var got, want interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal returned raw: %v", err)
	}
	if err := json.Unmarshal([]byte(payload), &want); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("APIDocTree returned %s, want %s", gotJSON, wantJSON)
	}
}

// TestAPIDocTree_IgnoresTrailingExtJSJunk proves extraction stops at the
// matching closing bracket rather than depending on the rest of the file
// being parseable at all — the real apidoc.js's trailing UI code is not
// valid JSON top-to-bottom.
func TestAPIDocTree_IgnoresTrailingExtJSJunk(t *testing.T) {
	const payload = `[{"path":"/nodes/{node}","leaf":0,"info":{},"children":[]}]`
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(realisticAPIDocJS(payload) + "\nthis is not JSON at all { [ } ] ("))
	})
	c := testClient(t, srv)

	if _, err := c.APIDocTree(context.Background()); err != nil {
		t.Fatalf("APIDocTree: %v", err)
	}
}

// TestAPIDocTree_BracketInStringValueDoesNotConfuseExtraction proves the
// bracket-matcher is string-aware: a '[' or ']' character inside a JSON
// string value (e.g. a real parameter description like "0,5,8-11" could
// plausibly include brackets in other fields) must not be mistaken for
// array structure.
func TestAPIDocTree_BracketInStringValueDoesNotConfuseExtraction(t *testing.T) {
	const payload = `[{"path":"/x","leaf":1,"info":{"GET":{"description":"see [here] for details, e.g. list[0]"}}}]`
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(realisticAPIDocJS(payload)))
	})
	c := testClient(t, srv)

	raw, err := c.APIDocTree(context.Background())
	if err != nil {
		t.Fatalf("APIDocTree: %v", err)
	}
	if !strings.Contains(string(raw), "see [here] for details") {
		t.Errorf("expected the bracketed description to survive extraction verbatim, got %s", raw)
	}
}

func TestAPIDocTree_MissingMarker(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not the file we expected</html>"))
	})
	c := testClient(t, srv)

	_, err := c.APIDocTree(context.Background())
	if err == nil {
		t.Fatal("expected an error when the apiSchema marker is missing")
	}
	if !strings.Contains(err.Error(), "marker") {
		t.Errorf("expected the error to mention the missing marker, got: %v", err)
	}
}

// TestAPIDocTree_TopLevelObjectDoesNotSearchPastIt proves extraction does
// NOT scan forward past a wrapping top-level structure looking for the
// first '[' — a genuine future apidoc.js format drift to a top-level
// object (whose own fields happen to contain a nested array) must error,
// not silently return that nested array instead.
func TestAPIDocTree_TopLevelObjectDoesNotSearchPastIt(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(apiSchemaMarker + `{"unexpected":"wrapper","nested":[1,2,3]};` + "\nEXTJS"))
	})
	c := testClient(t, srv)

	_, err := c.APIDocTree(context.Background())
	if err == nil {
		t.Fatal("expected an error when the top-level value is an object, not an array")
	}
	if !strings.Contains(err.Error(), "expected a JSON array") {
		t.Errorf("expected the error to say a JSON array was expected, got: %v", err)
	}
}

func TestAPIDocTree_UnbalancedBrackets(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(apiSchemaMarker + `[{"path":"/x","info":{}}` + "\n// truncated, no closing bracket or semicolon"))
	})
	c := testClient(t, srv)

	_, err := c.APIDocTree(context.Background())
	if err == nil {
		t.Fatal("expected an error for unbalanced brackets")
	}
	if !strings.Contains(err.Error(), "unbalanced") {
		t.Errorf("expected the error to mention unbalanced brackets, got: %v", err)
	}
}

func TestAPIDocTree_MalformedJSON(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(apiSchemaMarker + `[{"path": ,}];` + "\nEXTJS"))
	})
	c := testClient(t, srv)

	_, err := c.APIDocTree(context.Background())
	if err == nil {
		t.Fatal("expected an error for malformed JSON inside the array")
	}
	if !strings.Contains(err.Error(), "not a valid JSON array") {
		t.Errorf("expected the error to say the extracted text isn't valid JSON, got: %v", err)
	}
}

func TestAPIDocTree_NonOKStatus(t *testing.T) {
	srv := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	c := testClient(t, srv)

	_, err := c.APIDocTree(context.Background())
	if err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

func TestExtractAPISchemaArray_TopLevelNotArray(t *testing.T) {
	if _, err := extractAPISchemaArray([]byte(apiSchemaMarker + `{"not":"an array"};`)); err == nil {
		t.Fatal("expected an error when the extracted JSON is an object, not an array")
	}
}

func TestMatchingBracketEnd_RequiresOpenBracket(t *testing.T) {
	if _, err := matchingBracketEnd("not a bracket", 0); err == nil {
		t.Fatal("expected an error when s[start] is not '['")
	}
}
