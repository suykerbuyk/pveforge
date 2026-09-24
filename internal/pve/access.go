package pve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// PVE's /access objects, as pveforge reads them. The same JSON arrives from
// the REST list endpoints (GET /access/users?full=1, /access/groups,
// /access/acl) and from `pveum … list --output-format json` over root SSH,
// which prints the same API's answer; ParseAccessUsers, ParseAccessGroups
// and ParseACLEntries read both. They are strict: an entry missing a field
// pveforge decides on is an unverifiable read, never a default.
//
// NOT LIVE-VERIFIED: the field names and value types below are read from
// PVE's API schema (pve-access-control, PVE/API2/User.pm, Group.pm, ACL.pm),
// not observed on a live host; "groups" and "users" are accepted either as
// a comma-joined string or as a JSON array, because the two appear in
// different PVE versions' answers.

// AccessUser is one PVE user.
type AccessUser struct {
	UserID  string
	Enabled bool
	Comment string
	Email   string
	Groups  []string
	// GroupsListed reports whether the answer carried a "groups" field at
	// all (possibly empty), as AccessGroup.UsersListed does for members: a
	// caller deciding on membership requires it.
	GroupsListed bool
}

// AccessGroup is one PVE group and its members.
type AccessGroup struct {
	GroupID string
	Comment string
	Users   []string
	// UsersListed reports whether the answer carried a "users" field at all
	// (possibly empty). A caller deciding on membership requires it: a
	// missing or null field is not "no members".
	UsersListed bool
}

// ACLEntry is one ACL entry: Role on Path for the principal UGID of Type
// ("user", "group" or "token").
type ACLEntry struct {
	Path      string
	Role      string
	Type      string
	UGID      string
	Propagate bool
}

// ListUsers reads every user this client can see, with their groups
// (GET /access/users?full=1). PVE filters the list by the caller's
// privileges: a token without Sys.Audit may get a shorter list with 200.
func (c *Client) ListUsers(ctx context.Context) ([]AccessUser, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/access/users", url.Values{"full": {"1"}})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return ParseAccessUsers(raw)
}

// ListGroups reads every group this client can see (GET /access/groups),
// filtered by the caller's privileges as ListUsers is.
func (c *Client) ListGroups(ctx context.Context) ([]AccessGroup, error) {
	raw, err := c.RawRequest(ctx, http.MethodGet, "/access/groups", nil)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	return ParseAccessGroups(raw)
}

// ParseAccessUsers parses a user list.
func ParseAccessUsers(raw []byte) ([]AccessUser, error) {
	var entries []map[string]json.RawMessage
	if err := parseAccessArray(raw, "user list", &entries); err != nil {
		return nil, err
	}
	out := make([]AccessUser, 0, len(entries))
	seen := map[string]bool{}
	for i, e := range entries {
		id, err := requiredString(e, "userid")
		if err != nil {
			return nil, fmt.Errorf("user list entry %d: %w", i, err)
		}
		if seen[id] {
			return nil, fmt.Errorf("user list: user %s is listed twice: %w", id, ErrUnverifiableRead)
		}
		seen[id] = true
		en, err := requiredBool(e, "enable")
		if err != nil {
			return nil, fmt.Errorf("user list entry %s: %w", id, err)
		}
		u := AccessUser{UserID: id, Enabled: en}
		if u.Comment, err = optionalString(e, "comment"); err != nil {
			return nil, fmt.Errorf("user list entry %s: %w", id, err)
		}
		if u.Email, err = optionalString(e, "email"); err != nil {
			return nil, fmt.Errorf("user list entry %s: %w", id, err)
		}
		if u.Groups, err = optionalList(e, "groups"); err != nil {
			return nil, fmt.Errorf("user list entry %s: %w", id, err)
		}
		if g := repeated(u.Groups); g != "" {
			return nil, fmt.Errorf("user list entry %s: group %s is listed twice: %w", id, g, ErrUnverifiableRead)
		}
		if v, ok := e["groups"]; ok && string(v) != "null" {
			u.GroupsListed = true
		}
		out = append(out, u)
	}
	return out, nil
}

// ParseAccessGroups parses a group list.
func ParseAccessGroups(raw []byte) ([]AccessGroup, error) {
	var entries []map[string]json.RawMessage
	if err := parseAccessArray(raw, "group list", &entries); err != nil {
		return nil, err
	}
	out := make([]AccessGroup, 0, len(entries))
	seen := map[string]bool{}
	for i, e := range entries {
		id, err := requiredString(e, "groupid")
		if err != nil {
			return nil, fmt.Errorf("group list entry %d: %w", i, err)
		}
		if seen[id] {
			return nil, fmt.Errorf("group list: group %s is listed twice: %w", id, ErrUnverifiableRead)
		}
		seen[id] = true
		g := AccessGroup{GroupID: id}
		if g.Comment, err = optionalString(e, "comment"); err != nil {
			return nil, fmt.Errorf("group list entry %s: %w", id, err)
		}
		if g.Users, err = optionalList(e, "users"); err != nil {
			return nil, fmt.Errorf("group list entry %s: %w", id, err)
		}
		if v, ok := e["users"]; ok && string(v) != "null" {
			g.UsersListed = true
		}
		out = append(out, g)
	}
	return out, nil
}

// ParseACLEntries parses an ACL list.
func ParseACLEntries(raw []byte) ([]ACLEntry, error) {
	var entries []map[string]json.RawMessage
	if err := parseAccessArray(raw, "acl list", &entries); err != nil {
		return nil, err
	}
	out := make([]ACLEntry, 0, len(entries))
	for i, e := range entries {
		var a ACLEntry
		var err error
		if a.Path, err = requiredString(e, "path"); err != nil {
			return nil, fmt.Errorf("acl list entry %d: %w", i, err)
		}
		if a.Role, err = requiredString(e, "roleid"); err != nil {
			return nil, fmt.Errorf("acl list entry %d: %w", i, err)
		}
		if a.Type, err = requiredString(e, "type"); err != nil {
			return nil, fmt.Errorf("acl list entry %d: %w", i, err)
		}
		if a.Type != "user" && a.Type != "group" && a.Type != "token" {
			return nil, fmt.Errorf("acl list entry %d: type %q is not user, group or token: %w", i, a.Type, ErrUnverifiableRead)
		}
		if a.UGID, err = requiredString(e, "ugid"); err != nil {
			return nil, fmt.Errorf("acl list entry %d: %w", i, err)
		}
		if a.Propagate, err = requiredBool(e, "propagate"); err != nil {
			return nil, fmt.Errorf("acl list entry %d: %w", i, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// parseAccessArray decodes a JSON array of objects. null, or anything else
// that is not an array of objects, is an unverifiable read: an empty list
// must be [] to mean "none".
func parseAccessArray(raw []byte, what string, out *[]map[string]json.RawMessage) error {
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, "[") {
		return fmt.Errorf("%s: the answer is not a JSON array: %w", what, ErrUnverifiableRead)
	}
	if err := json.Unmarshal([]byte(s), out); err != nil {
		return fmt.Errorf("%s: the answer is not an array of objects: %w", what, ErrUnverifiableRead)
	}
	for i, e := range *out {
		if e == nil {
			return fmt.Errorf("%s: entry %d is null: %w", what, i, ErrUnverifiableRead)
		}
	}
	return nil
}

func requiredString(e map[string]json.RawMessage, key string) (string, error) {
	v, ok := e[key]
	if !ok {
		return "", fmt.Errorf("no %q field: %w", key, ErrUnverifiableRead)
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil || s == "" {
		return "", fmt.Errorf("%q is not a non-empty string: %w", key, ErrUnverifiableRead)
	}
	return s, nil
}

func optionalString(e map[string]json.RawMessage, key string) (string, error) {
	v, ok := e[key]
	if !ok || string(v) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("%q is not a string: %w", key, ErrUnverifiableRead)
	}
	return s, nil
}

// requiredBool reads a PVE boolean: 0 or 1, or a JSON boolean.
func requiredBool(e map[string]json.RawMessage, key string) (bool, error) {
	v, ok := e[key]
	if !ok {
		return false, fmt.Errorf("no %q field: %w", key, ErrUnverifiableRead)
	}
	switch strings.TrimSpace(string(v)) {
	case "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	}
	return false, fmt.Errorf("%q is %s, not 0 or 1: %w", key, v, ErrUnverifiableRead)
}

// repeated returns an entry of list that appears in it more than once, or "".
func repeated(list []string) string {
	seen := map[string]bool{}
	for _, v := range list {
		if seen[v] {
			return v
		}
		seen[v] = true
	}
	return ""
}

// optionalList reads a comma-joined string or an array of strings; absent,
// null or "" is an empty list.
func optionalList(e map[string]json.RawMessage, key string) ([]string, error) {
	v, ok := e[key]
	if !ok || string(v) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		if s == "" {
			return nil, nil
		}
		return strings.Split(s, ","), nil
	}
	var list []string
	if err := json.Unmarshal(v, &list); err != nil {
		return nil, fmt.Errorf("%q is neither a string nor a list of strings: %w", key, ErrUnverifiableRead)
	}
	return list, nil
}

// Principal ids, checked before anything is sent. The shapes follow
// pve-access-control's formats (pve-userid, pve-groupid, pve-tokenid), and
// no id may hold whitespace (Unicode) or a control character, so an id is
// always one shell word and one line of output.
var (
	// userIDRE is "<name>@<realm>". The name may not begin with '-': an id
	// is a positional argument to pveum, which would read it as an option.
	userIDRE = regexp.MustCompile(`^[^\s:/@-][^\s:/@]*@[A-Za-z][A-Za-z0-9._-]+$`)
	// groupIDRE is pve-groupid, not beginning with '-' (as userIDRE).
	groupIDRE = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)
	// tokenNameRE is a token's name, after "<userid>!".
	tokenNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]+$`)
)

// ErrInvalidPrincipal marks a user, group or token id that is not
// well formed. It is refused before anything is sent.
var ErrInvalidPrincipal = errors.New("invalid principal")

// CheckUserID reports whether id is a PVE user id, "<name>@<realm>".
func CheckUserID(id string) error {
	if !userIDRE.MatchString(id) || hasSpaceOrControl(id) {
		return fmt.Errorf("%w: %q is not a user id (<name>@<realm>)", ErrInvalidPrincipal, id)
	}
	return nil
}

// CheckGroupID reports whether id is a PVE group id.
func CheckGroupID(id string) error {
	if !groupIDRE.MatchString(id) {
		return fmt.Errorf("%w: %q is not a group id", ErrInvalidPrincipal, id)
	}
	return nil
}

// CheckTokenID reports whether id is a PVE API token id,
// "<name>@<realm>!<tokenname>".
func CheckTokenID(id string) error {
	user, name, ok := strings.Cut(id, "!")
	if !ok || CheckUserID(user) != nil || !tokenNameRE.MatchString(name) {
		return fmt.Errorf("%w: %q is not a token id (<name>@<realm>!<tokenname>)", ErrInvalidPrincipal, id)
	}
	return nil
}

func hasSpaceOrControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}
