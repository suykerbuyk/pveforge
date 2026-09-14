package pve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// apiDocTreePath is where every PVE host (verified: 9.2.11) serves its own
// full API-doc schema tree — a static asset of the `pve-docs` package,
// NOT a REST endpoint, served unauthenticated by pveproxy itself on the
// same scheme/host/port as the API. See APIDocTree's own doc comment for
// how this was discovered and why it replaced the original OPTIONS-based
// design.
const apiDocTreePath = "/pve-docs/api-viewer/apidoc.js"

// apiSchemaMarker is the literal JS-assignment prefix apiDocTreePath's
// body is verified (live, 9.2.11) to begin its JSON payload with:
// `const apiSchema = [ ... ];` followed by unrelated ExtJS UI code.
// extractAPISchemaArray fails loudly if this exact marker isn't found,
// rather than silently returning an empty tree — see APIDocTree's doc
// comment on why a format drift here must be caught, not masked.
const apiSchemaMarker = "const apiSchema = "

// APIDocTree fetches PVE's own static API-doc schema tree — the same
// tree both `pvesh usage` (read from the local Perl API2 module
// registrations directly) and the web API-viewer (read from this same
// file) are ultimately built from — and returns the embedded JSON array
// verbatim (still json.RawMessage: this method does no vocabulary
// reshaping, only the structural work of pulling the JSON out of its
// surrounding JS/ExtJS wrapper). Each element is one path node, carrying
// a literal TEMPLATED path (e.g. "/nodes/{node}/qemu/{vmid}/config") and
// an "info" object keyed by HTTP method — see internal/discover's
// apitree.go for how a caller indexes into this by path.
//
// # Why this replaced an OPTIONS-based design
//
// This project originally planned (see this method's prior incarnation,
// named OptionsSchema) to fetch a single path's schema by issuing a live
// HTTP OPTIONS request against that path — mirroring, it was assumed,
// the same mechanism pvesh itself uses. That assumption was verified
// FALSE against a live 2-node PVE 9.2.11 cluster on 2026-09-14: PVE's API
// daemon rejects HTTP OPTIONS unconditionally, for every path, before
// auth or routing ever runs. Root-caused in PVE's own source,
// /usr/share/perl5/PVE/APIServer/AnyEvent.pm:
//
//	my $known_methods = { GET => 1, POST => 1, PUT => 1, DELETE => 1 };
//	...
//	if (!$known_methods->{$method}) {
//	    my $resp = HTTP::Response->new(HTTP_NOT_IMPLEMENTED, "method '$method' not available");
//
// Confirmed live: 5/5 probed paths (a real vmid's config, a nonexistent
// vmid's config, a status path, a node-level path, a cluster-level path)
// all returned identical "HTTP/1.1 501 method 'OPTIONS' not available"
// responses — a real vs. fake object id made zero difference, since the
// rejection fires at HTTP-header-parse time, before path routing is even
// reached.
//
// `pvesh usage <path>` does NOT make an HTTP call to itself at all — it
// reads the same Perl API2 module registrations in-process, on the PVE
// host. The actual OVER-THE-WIRE introspection source both `pvesh usage`
// and the web API-viewer are built from at package-build time is this
// static file: confirmed live, unauthenticated GET
// https://<host>:<port>/pve-docs/api-viewer/apidoc.js returns HTTP 200
// with the full API tree, ~4.3MB on a 9.2.11 host (package pve-docs).
//
// This is a bundled doc-generation artifact of the pve-docs package, not
// a versioned public API contract — unlike a REST endpoint, its format
// could change between PVE releases without notice. extractAPISchemaArray
// therefore fails loudly (returns an error) rather than silently
// returning an empty or partial tree if the expected marker or a
// balanced bracket close isn't found, so a future format drift is caught
// by a caller, not masked as "no schema for this path."
//
// Deliberately sends NO Authorization header: apidoc.js is confirmed
// unauthenticated (a token works too, but isn't required), and this
// fetch has nothing to do with this client's own credentials — treating
// it as authenticated would misrepresent what it actually is.
func (c *Client) APIDocTree(ctx context.Context) (json.RawMessage, error) {
	docURL, err := c.apiDocTreeURL()
	if err != nil {
		return nil, fmt.Errorf("api doc tree: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("api doc tree: build request: %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api doc tree: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("api doc tree: read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api doc tree: pve returned %s fetching %s", res.Status, apiDocTreePath)
	}

	raw, err := extractAPISchemaArray(body)
	if err != nil {
		return nil, fmt.Errorf("api doc tree: %w", err)
	}
	return raw, nil
}

// apiDocTreeURL builds apiDocTreePath's full URL from this client's own
// baseURL, preserving scheme/host/port but replacing the path — baseURL
// itself is "https://host:port/api2/json" (or a test's BaseURLOverride,
// which carries no such suffix), and apidoc.js is served at a completely
// different path on that same host, not under /api2/json at all.
func (c *Client) apiDocTreeURL() (string, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	u.Path = apiDocTreePath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// extractAPISchemaArray isolates the `const apiSchema = [ ... ];` JSON
// array embedded in apidoc.js's body (the rest of the file is unrelated
// ExtJS UI code that does not parse as JSON) and validates that it
// actually is a well-formed JSON array before returning it. Fails loudly
// — with an error identifying exactly which expectation broke — rather
// than returning an empty or best-effort result, per APIDocTree's own
// doc comment on why a format drift here must be caught.
func extractAPISchemaArray(body []byte) (json.RawMessage, error) {
	text := string(body)

	markerIdx := strings.Index(text, apiSchemaMarker)
	if markerIdx == -1 {
		return nil, fmt.Errorf("expected marker %q not found in response body — apidoc.js's format may have changed", apiSchemaMarker)
	}
	rest := text[markerIdx+len(apiSchemaMarker):]

	// Skip only whitespace between the marker and the value — NOT an
	// unbounded scan for the first '[' anywhere in rest. Scanning forward
	// would find a '[' nested inside some OTHER top-level value (e.g. a
	// wrapping object's own array-valued field) and silently extract
	// that instead, exactly the kind of unversioned-artifact format
	// drift this function's own doc comment says must be caught, not
	// masked — an object at the top level must error here, not be
	// searched past.
	start := len(rest) - len(strings.TrimLeft(rest, " \t\r\n"))
	if start >= len(rest) || rest[start] != '[' {
		got := "end of input"
		if start < len(rest) {
			got = fmt.Sprintf("%q", string(rest[start]))
		}
		return nil, fmt.Errorf("expected a JSON array (starting with '[') immediately after %q marker, got %s", apiSchemaMarker, got)
	}

	end, err := matchingBracketEnd(rest, start)
	if err != nil {
		return nil, err
	}

	raw := json.RawMessage(rest[start:end])
	var probe []json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("extracted text is not a valid JSON array: %w", err)
	}
	return raw, nil
}

// matchingBracketEnd scans s starting at s[start] (which must be '[')
// for the '[' character's matching ']', tracking string literals (so a
// literal '[' or ']' inside a JSON string value — e.g. a parameter
// description mentioning brackets — is never mistaken for structure) and
// backslash escapes within them. Returns the index one past the matching
// ']', suitable for a Go slice end bound.
func matchingBracketEnd(s string, start int) (int, error) {
	if start >= len(s) || s[start] != '[' {
		return 0, fmt.Errorf("matchingBracketEnd: s[%d] is not '['", start)
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		ch := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return 0, fmt.Errorf("unbalanced brackets: reached end of response before the array starting at offset %d closed", start)
}
