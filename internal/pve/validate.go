package pve

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoGrants indicates the token authenticated successfully but the
// resource list it should be able to see came back empty — the silent
// failure this validation exists to catch: a fresh Proxmox token has zero
// permissions by default until an ACL is explicitly granted, and nothing
// about the token's own authentication surfaces that fact. Hitting a
// version-class endpoint would not catch this, since those don't require
// resource ACLs.
var ErrNoGrants = errors.New("token authenticates but appears to have no working grants (ACL grant likely did not take effect)")

// ErrWrongScope indicates the token's grants exist but don't cover the
// expected node — a narrower failure than ErrNoGrants: the ACL grant was
// made, but scoped to the wrong path/resource.
var ErrWrongScope = errors.New("token's grants do not cover the expected node (ACL likely scoped to the wrong path)")

// ValidateTokenGrants proves a freshly bootstrapped token actually has
// working grants, not just that it authenticates. It lists an ACL-gated
// resource (nodes) and confirms the target's own node is visible in the
// result — catching both "zero grants" and "grants scoped to the wrong
// path" distinctly, per this task's recorded research findings.
func ValidateTokenGrants(ctx context.Context, c *Client, expectNode string) error {
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		return fmt.Errorf("validate token grants: %w", err)
	}
	if len(nodes) == 0 {
		return ErrNoGrants
	}
	for _, n := range nodes {
		if n == expectNode {
			return nil
		}
	}
	return ErrWrongScope
}
