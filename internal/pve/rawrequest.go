package pve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RawRequest issues method against path on this client's own PVE host —
// pveforge-raw-api-escape-hatch's (PRD §3.1) underlying transport for
// `pveforge api get/post/put/delete <path>`: any PVE REST path, verbatim,
// with no dedicated typed command. params are sent as a query string for
// GET and DELETE (PVE's own convention — go-proxmox's own DeleteWithParams
// doc comment confirms "Proxmox DELETE endpoints take options via query
// params, not a request body") and as an application/x-www-form-urlencoded
// body for POST and PUT.
//
// Deliberately builds its own http.Request from c.baseURL/c.httpClient/
// c.authHeader rather than going through go-proxmox — the SAME reason
// vmconfig.go's SetVMConfigFieldCAS bypasses it (see that method's own doc
// comment): go-proxmox's handleResponse discards the response body
// entirely on HTTP 500/501, and PVE uses exactly those statuses for many
// of its own rejection errors (root-only fields, digest conflicts, bad
// parameters). A raw escape hatch's entire value proposition is letting
// the caller see PVE's own diagnostic text when something goes wrong —
// losing it on precisely the statuses most likely to carry a useful error
// would defeat the command's purpose. This also rules out go-proxmox's own
// Post/Put (they JSON-encode the body; PVE's REST API expects form-encoded
// parameters, matching every other write path in this project).
//
// Returns the response body's "data" field unwrapped (see
// unwrapDataEnvelope) — json.RawMessage("null") for an empty body or an
// explicit null, exactly as PVE returns for many successful writes with
// nothing to report. Does no further reshaping: a bare scalar (e.g. PVE
// often returns a UPID task-id string for POST) or null passes through
// as-is: kvjson.Render's own existing contract (object-only for KV output)
// governs what a caller sees for those, not this method.
func (c *Client) RawRequest(ctx context.Context, method, path string, params url.Values) (json.RawMessage, error) {
	if path == "" {
		return nil, fmt.Errorf("raw request: path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("raw request: path %q must start with '/'", path)
	}

	reqURL := c.baseURL + path
	var body io.Reader
	switch method {
	case http.MethodGet, http.MethodDelete:
		if len(params) > 0 {
			reqURL += "?" + params.Encode()
		}
	case http.MethodPost, http.MethodPut:
		body = strings.NewReader(params.Encode())
	default:
		return nil, fmt.Errorf("raw request: unsupported method %q", method)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("raw request: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("Authorization", c.authHeader)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("raw request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("raw request: read response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, newStatusError("raw request", res, respBody)
	}

	raw, err := unwrapDataEnvelope(respBody)
	if err != nil {
		return nil, fmt.Errorf("raw request: %w", err)
	}
	return raw, nil
}

// unwrapDataEnvelope extracts body's top-level "data" field — the same
// envelope every other read on this client already goes through (see
// APIDocTree's own doc comment) — tolerating the two shapes a successful
// PVE write commonly produces that a strict `{"data": ...}` unmarshal
// alone would reject:
//
//   - an entirely EMPTY response body: several PVE write endpoints return
//     HTTP 2xx with nothing at all (observed in this project's own test
//     fixtures for VM config writes) — treated as an explicit JSON null,
//     not a parse error.
//   - `{"data": null}` — PVE's own explicit "nothing to report" shape —
//     also normalized to a plain null rather than left as a
//     present-but-nil json.RawMessage (which would otherwise marshal
//     identically, but this makes the equivalence a documented, tested
//     guarantee rather than an accident of json.RawMessage's zero value).
func unwrapDataEnvelope(body []byte) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return json.RawMessage("null"), nil
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("parse response body: %w", err)
	}
	if len(envelope.Data) == 0 {
		return json.RawMessage("null"), nil
	}
	return envelope.Data, nil
}

// StatusError is PVE's non-2xx answer to one of this client's own HTTP
// requests: RawRequest's, and the synchronous config PUT behind
// SetVMConfigFieldCAS and DeleteVMConfigFieldCAS. Branch on Code, and read
// Body, rather than on the error's text.
//
// Its text is exactly the "<what>: pve returned <Status>: <body>" string
// callers have always seen — the body trimmed of surrounding whitespace —
// because the substring classifiers (idempotent's isMissingVMError and
// isMissingNetworkInterfaceError, IsDigestConflictError) still read it;
// moving them onto Code and Body is pveforge-unify-notfound-classifiers.
//
// A 401 or 403 also satisfies errors.Is(err, ErrNotAuthorized), so the
// grant validator can tell a rejected credential from any other failure.
// It deliberately has no Unwrap and no As: it is not a
// *proxmox.StatusError, so no existing errors.Is/errors.As classification
// of these errors changes.
type StatusError struct {
	// Code is the HTTP status code.
	Code int
	// Status is the status line as net/http reports it, e.g.
	// "500 Internal Server Error". Its reason phrase is PVE's own over
	// HTTP/1.1 but net/http's canonical text over HTTP/2, which carries
	// none: never branch on it.
	Status string
	// Body is the response body exactly as received, untrimmed.
	Body []byte

	msg string
}

// newStatusError is the StatusError for res, whose body was body, with
// what (e.g. "raw request") leading its text.
func newStatusError(what string, res *http.Response, body []byte) *StatusError {
	return &StatusError{
		Code:   res.StatusCode,
		Status: res.Status,
		Body:   body,
		msg:    fmt.Sprintf("%s: pve returned %s: %s", what, res.Status, strings.TrimSpace(string(body))),
	}
}

func (e *StatusError) Error() string { return e.msg }

func (e *StatusError) Is(target error) bool {
	return target == ErrNotAuthorized && (e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden)
}

// HTTPStatus reports the HTTP status code of the StatusError in err's
// chain, if there is one: false for nil, a transport failure, or any
// error that did not come from a non-2xx answer.
func HTTPStatus(err error) (code int, ok bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code, true
	}
	return 0, false
}
