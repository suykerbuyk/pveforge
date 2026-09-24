package sshexec

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// RootOnlyFields is the set of VM config fields empirically confirmed to
// be rejected by Proxmox's REST API from any token, regardless of granted
// privileges, and which must be routed through SetVMConfigField (the
// standing SSH vector) instead of the token-authenticated REST path.
//
// Seeded with only "args" — verified live against PVE 9.2.11 (HTTP 500,
// `"only root can set 'args' config"`). Candidates reported elsewhere
// (rng, affinity, hugepages) are deliberately NOT included: they have not
// been independently verified against a live host the way args was, and
// this project's standing discipline is to verify each field directly
// before trusting a secondhand report — see IsRootOnlyWriteError for the
// runtime safety net that flags a candidate instead of silently
// misreporting a generic write failure. Adding a field here requires the
// same empirical test args received (attempt a token-authenticated write
// with a fully-privileged token against a scoped throwaway object, and
// confirm the exact HTTP status/error).
var RootOnlyFields = map[string]bool{
	"args": true,
}

// rootOnlyErrorSubstring is the exact PVE error text confirmed for the
// args field.
const rootOnlyErrorSubstring = "only root can set"

// IsRootOnlyWriteError reports whether err's message contains the PVE
// error text confirmed for root-only config fields (`"only root can set
// '<field>' config"`). A REST write path should use this to flag an
// unregistered field as a root-only candidate for manual verification,
// rather than surfacing it as a generic write failure — turning a runtime
// failure into a feedback loop for growing RootOnlyFields safely.
func IsRootOnlyWriteError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), rootOnlyErrorSubstring)
}

// QMSetTimeout bounds a `qm set` (SetVMConfigField, DeleteVMConfigField),
// in place of CommandTimeout: qm waits up to 10s for the VM's config lock,
// and on a running VM it then applies every pending change it can
// hotplug, which may take far longer than the write itself (the field
// written here, args, is never hotplugged, but other pending changes are).
var QMSetTimeout = 120 * time.Second

// SetVMConfigField sets a single VM config field via `qm set`, for fields
// in RootOnlyFields that Proxmox's API refuses to accept from any token.
// Runs over c's existing SSH connection, which must be authenticated as a
// user with sufficient privilege on the target node (root, in practice).
func (c *Client) SetVMConfigField(ctx context.Context, vmid int, field, value string) error {
	if !isValidFieldName(field) {
		return fmt.Errorf("set vm config field: invalid field name %q", field)
	}
	cmd := fmt.Sprintf("qm set %s --%s %s", ShellQuote(strconv.Itoa(vmid)), field, ShellQuote(value))
	res, err := c.Run(WithCommandTimeout(ctx, QMSetTimeout), cmd)
	if err != nil {
		return fmt.Errorf("set vm %d field %q: %w", vmid, field, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("set vm %d field %q: qm set exited %d: %s", vmid, field, res.ExitCode, res.Stderr)
	}
	return nil
}

// DeleteVMConfigField removes a single root-only field from vmid's config
// via `qm set <vmid> --delete <field>`: PVE's own delete parameter, the
// counterpart of SetVMConfigField, never a write of an empty value. field
// passes the same name check, and is shell-quoted as the parameter's value.
// Whether qm reports an error for a key that is already absent is NOT
// verified against a live host; callers skip an absent key instead.
func (c *Client) DeleteVMConfigField(ctx context.Context, vmid int, field string) error {
	if !isValidFieldName(field) {
		return fmt.Errorf("delete vm config field: invalid field name %q", field)
	}
	cmd := fmt.Sprintf("qm set %s --delete %s", ShellQuote(strconv.Itoa(vmid)), ShellQuote(field))
	res, err := c.Run(WithCommandTimeout(ctx, QMSetTimeout), cmd)
	if err != nil {
		return fmt.Errorf("delete vm %d field %q: %w", vmid, field, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("delete vm %d field %q: qm set exited %d: %s", vmid, field, res.ExitCode, res.Stderr)
	}
	return nil
}

// isValidFieldName restricts field names to a safe identifier shape before
// they're interpolated (unquoted, as a `--flag` name) into a shell command
// line — defense in depth on top of RootOnlyFields being a fixed,
// software-controlled registry rather than free-form input.
func isValidFieldName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return false
		}
	}
	return true
}
