package pve

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidGrant marks a requested Grant (or grant list) that is not well
// formed. It is refused before any request is made, and it is never a
// verdict about a token.
var ErrInvalidGrant = errors.New("invalid grant")

var (
	// aclPathRE is PVE's ACL path charset (normalize_path), anchored at a
	// leading "/". It also checks every path key PVE answers with.
	aclPathRE = regexp.MustCompile(`^/[[:alnum:]._/-]*$`)
	// roleIDRE is PVE's role id format (pve-roleid).
	roleIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// privNameRE accepts every privilege name PVE 9.2.11 defines (e.g.
	// VM.GuestAgent.FileSystemMgmt, SDN.Use) and nothing that could carry
	// a line break, a quote or a separator into a message.
	privNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.]*$`)
)

// Grant is one requested ACL grant for a token: Role on Path, with
// Propagate. Privs, when non-nil, pins the privilege set the grant is
// expected to confer and is used instead of the role's live definition, so
// a role widened on PVE is caught; nil means "the role's live privileges".
type Grant struct {
	Path      string // normalized ACL path (PVE normalize_path form)
	Role      string // role id; always required, even when Privs is pinned
	Propagate bool
	Privs     []string
}

// Check reports whether g is well formed, as ErrInvalidGrant naming the
// field. No request is made.
func (g Grant) Check() error {
	switch {
	case !aclPathRE.MatchString(g.Path):
		return fmt.Errorf("%w: path %q is not an ACL path", ErrInvalidGrant, g.Path)
	case strings.Contains(g.Path, "//") || (g.Path != "/" && strings.HasSuffix(g.Path, "/")):
		return fmt.Errorf("%w: path %q is not normalized", ErrInvalidGrant, g.Path)
	case g.Role == "":
		return fmt.Errorf("%w: role is required", ErrInvalidGrant)
	case !roleIDRE.MatchString(g.Role):
		return fmt.Errorf("%w: role %q is not a role id", ErrInvalidGrant, g.Role)
	case g.Privs != nil && len(g.Privs) == 0:
		return fmt.Errorf("%w: %s: pinned privileges are empty (leave them nil to use the role's own)", ErrInvalidGrant, g.Path)
	}
	seen := make(map[string]bool, len(g.Privs))
	for _, p := range g.Privs {
		if !privNameRE.MatchString(p) {
			return fmt.Errorf("%w: %s: %q is not a privilege name", ErrInvalidGrant, g.Path, p)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s: privilege %s is listed twice", ErrInvalidGrant, g.Path, p)
		}
		seen[p] = true
	}
	return nil
}

// CheckGrants reports whether want is a usable request: non-empty, each
// grant well formed, and no two grants on one path (two roles on one path
// would make a privilege's source ambiguous).
func CheckGrants(want []Grant) error {
	if len(want) == 0 {
		return fmt.Errorf("%w: no grants requested", ErrInvalidGrant)
	}
	paths := make(map[string]bool, len(want))
	for _, g := range want {
		if err := g.Check(); err != nil {
			return err
		}
		if paths[g.Path] {
			return fmt.Errorf("%w: two grants on path %s", ErrInvalidGrant, g.Path)
		}
		paths[g.Path] = true
	}
	return nil
}
