package sshexec

import "testing"

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":       `'plain'`,
		"":            `''`,
		"a'b":         `'a'\''b'`,
		"with space":  `'with space'`,
		"$(rm -rf /)": `'$(rm -rf /)'`,
		"a'b'c":       `'a'\''b'\''c'`,
	}
	for in, want := range cases {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
