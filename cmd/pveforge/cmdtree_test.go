package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runArgs runs a fresh command tree on args through runRoot and returns the
// exit code and what reached stdout and stderr.
func runArgs(args ...string) (code int, stdout, stderr string) {
	root := newRootCmd()
	root.SetArgs(args)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	code = runRoot(root, &errOut)
	return code, out.String(), errOut.String()
}

// Every command group in the tree, root included and cobra's own completion
// group too, refuses to run as anything but a request for its help: an
// unknown subcommand and a bare group both fail, and explicit help succeeds
// on stdout. The walk is over the real tree, so a group added later is
// covered without being listed here.
func TestCommandTree_EveryGroupRefusesToRunWithoutAKnownSubcommand(t *testing.T) {
	var groups [][]string
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if c.HasSubCommands() {
			groups = append(groups, path)
		}
		for _, s := range c.Commands() {
			walk(s, append(append([]string(nil), path...), s.Name()))
		}
	}
	walk(newRootCmd(), nil)

	// Anti-vacuity: the walk reached the root, the nested groups and the
	// group cobra itself adds.
	seen := map[string]bool{}
	for _, g := range groups {
		seen[strings.Join(g, " ")] = true
	}
	for _, want := range []string{"", "vm", "vm snapshot", "network bridge", "completion"} {
		if !seen[want] {
			t.Fatalf("group %q not found in the command tree; groups seen: %v", "pveforge "+want, groups)
		}
	}
	if len(groups) < 15 {
		t.Fatalf("found %d command groups, want at least 15: %v", len(groups), groups)
	}

	for _, g := range groups {
		name := strings.TrimSpace("pveforge " + strings.Join(g, " "))
		t.Run(name, func(t *testing.T) {
			const bogus = "zz-no-such-subcommand"
			code, stdout, stderr := runArgs(append(append([]string(nil), g...), bogus)...)
			if code == 0 || !strings.Contains(stderr, `unknown command "`+bogus+`" for "`+name+`"`) || stdout != "" {
				t.Errorf("%s %s: exit %d, stdout %q, stderr %q; want a non-zero exit naming the unknown command on stderr only", name, bogus, code, stdout, stderr)
			}

			// A bare group is a usage error: an empty-but-set $VERB in
			// `pveforge vm $VERB` must fail closed.
			code, stdout, stderr = runArgs(g...)
			if code == 0 || stdout != "" || !strings.Contains(stderr, "Available Commands:") || !strings.Contains(stderr, name+": a subcommand is required") {
				t.Errorf("%s (bare): exit %d, stdout %q, stderr %q; want a non-zero exit with the help and the usage error on stderr only", name, code, stdout, stderr)
			}

			for _, help := range [][]string{
				append(append([]string(nil), g...), "--help"),
				append(append([]string(nil), g...), "-h"),
				append([]string{"help"}, g...),
			} {
				code, stdout, stderr = runArgs(help...)
				if code != 0 || !strings.Contains(stdout, "Available Commands:") || stderr != "" {
					t.Errorf("pveforge %s: exit %d, stdout %q, stderr %q; want exit 0 with the help on stdout only", strings.Join(help, " "), code, stdout, stderr)
				}
			}
		})
	}

	// Arguments after "--" are arguments too, never a way past the check.
	if code, _, stderr := runArgs("--", "vm", "destroy"); code == 0 || !strings.Contains(stderr, `unknown command "vm" for "pveforge"`) {
		t.Errorf("pveforge -- vm destroy: exit %d, stderr %q; want a non-zero exit naming the unknown command", code, stderr)
	}
}

// A bare group must not leave its help writer pointed at stderr: the same
// tree run again with --help prints the help on stdout. (cmd.SetOut in
// bareGroup persisted on the command.)
func TestCommandTree_BareGroupThenHelpOnTheSameTree(t *testing.T) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)

	root.SetArgs([]string{"vm"})
	if code := runRoot(root, &errOut); code == 0 || out.Len() != 0 || !strings.Contains(errOut.String(), "Available Commands:") {
		t.Fatalf("vm (bare): exit %d, stdout %q, stderr %q; want a non-zero exit with the help on stderr", code, out.String(), errOut.String())
	}

	out.Reset()
	errOut.Reset()
	root.SetArgs([]string{"vm", "--help"})
	if code := runRoot(root, &errOut); code != 0 || !strings.Contains(out.String(), "Available Commands:") || errOut.Len() != 0 {
		t.Errorf("vm --help after a bare vm on the same tree: exit %d, stdout %q, stderr %q; want exit 0 with the help on stdout only", code, out.String(), errOut.String())
	}
}

// The help a bare group writes to stderr is the help --help writes to
// stdout, for every group: bareGroup renders it itself rather than through
// cmd.Help, so this pins the two as the same text.
func TestCommandTree_BareGroupHelpEqualsExplicitHelp(t *testing.T) {
	var groups [][]string
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if c.HasSubCommands() {
			groups = append(groups, path)
		}
		for _, s := range c.Commands() {
			walk(s, append(append([]string(nil), path...), s.Name()))
		}
	}
	walk(newRootCmd(), nil)
	if len(groups) < 15 {
		t.Fatalf("found %d command groups, want at least 15", len(groups))
	}
	for _, g := range groups {
		name := strings.TrimSpace("pveforge " + strings.Join(g, " "))
		_, help, _ := runArgs(append(append([]string(nil), g...), "--help")...)
		_, _, bare := runArgs(g...)
		if want := help + name + ": a subcommand is required\n"; help == "" || bare != want {
			t.Errorf("%s: bare stderr\n%q\nwant the --help text then the usage error\n%q", name, bare, want)
		}
	}
}

// An unknown subcommand gets a suggestion only when there is a real one: a
// near miss is offered its command; an empty argument (every command is
// "near" it) and an argument that is itself the suggestion (`-- vm`, where
// vm is a real command taken as an argument) get none.
func TestCommandTree_UnknownSubcommandSuggestion(t *testing.T) {
	// A prefix, and a typo (Levenshtein distance 1, which cobra's default
	// distance of 2 admits).
	for _, near := range []string{"creat", "crate"} {
		code, _, stderr := runArgs("vm", near)
		if want := `unknown command "` + near + `" for "pveforge vm"; did you mean "create"?` + "\n"; code == 0 || stderr != want {
			t.Errorf("vm %s: exit %d, stderr %q; want %q", near, code, stderr, want)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"vm", ""}, `unknown command "" for "pveforge vm"` + "\n"},
		{[]string{"--", "vm"}, `unknown command "vm" for "pveforge"` + "\n"},
	} {
		code, _, stderr := runArgs(c.args...)
		if code == 0 || stderr != c.want {
			t.Errorf("pveforge %q: exit %d, stderr %q; want %q and no suggestion", c.args, code, stderr, c.want)
		}
	}
}
