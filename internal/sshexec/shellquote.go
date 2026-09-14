// Package sshexec is the SSH transport shared by pveforge's bootstrap flow
// (installing a fresh keypair via password auth, then driving pveum over
// it) and the standing root-only-field workaround (SetVMConfigField),
// per the operator's 2026-09-13 decision to retain SSH as a permanent,
// on-demand root-level command vector rather than route everything through
// a hookscript.
package sshexec

import "strings"

// ShellQuote wraps s in single quotes for safe inclusion in a POSIX sh
// command line, escaping any single quote it contains. Used everywhere
// this package builds a remote command line from a value that isn't a
// fixed, trusted literal (an authorized_keys line, a config field value, a
// PVE identifier).
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
