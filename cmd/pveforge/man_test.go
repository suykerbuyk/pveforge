package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"
)

// The man pages in docs/man are generated from the command tree by this
// test, never by the binary: cobra/doc (and go-md2man and blackfriday under
// it) is imported only here, and internal/sourceguard's test-support guard
// proves it never reaches a main package's dependencies.
//
//	make man    # go test ./cmd/pveforge -run '^TestManPages$' -update-man
//
// Without -update-man the test is the guard: the pages generated now must
// equal docs/man byte for byte, file for file, so a new command, a changed
// flag or help text, or a removed command fails here until make man is run.

var updateMan = flag.Bool("update-man", false, "regenerate docs/man from the command tree")

const manDir = "../../docs/man"

// manDate is the date the pages carry. It is pinned so a regeneration is
// byte-identical whatever the day: cobra would otherwise stamp the current
// month (or SOURCE_DATE_EPOCH's). Move it forward when the pages change
// materially.
var manDate = time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)

// genManPages writes the pages for the whole tree into dir and returns
// their file names, sorted.
func genManPages(t *testing.T, dir string) []string {
	t.Helper()
	root := newRootCmd()
	// cobra adds these at Execute; the binary has them, so the pages do too.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	var noAutoGen func(c *cobra.Command)
	noAutoGen = func(c *cobra.Command) {
		c.DisableAutoGenTag = true
		for _, s := range c.Commands() {
			noAutoGen(s)
		}
	}
	noAutoGen(root)
	escapeForManMarkdown(root)
	date := manDate
	header := &doc.GenManHeader{Title: "PVEFORGE", Section: "1", Source: "pveforge", Manual: "pveforge manual", Date: &date}
	if err := doc.GenManTree(root, header, dir); err != nil {
		t.Fatalf("GenManTree: %v", err)
	}
	return manFiles(t, dir)
}

// mdSpecial are the characters cobra/doc's markdown pass (go-md2man over
// blackfriday) would read as markup in help text: "<target-id>" as an HTML
// tag, dropped whole; "[x] (y)" as a link, which drops the brackets and
// turns the parentheses into ⟨ ⟩; "*" and "_" as emphasis; "`" as code;
// "\\" as an escape. Each is backslash-escaped, which blackfriday turns
// back into the literal character — but only outside a code block.
var mdSpecial = strings.NewReplacer(`\`, `\\`, "`", "\\`", `*`, `\*`, `_`, `\_`, `<`, `\<`, `>`, `\>`, `[`, `\[`, `]`, `\]`)

// mdEscape escapes s line by line, leaving alone every line of an indented
// code block (a tab or four spaces): markdown prints those verbatim, so an
// escape there would reach the page as a literal backslash and break a
// command copied from it.
func mdEscape(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "\t") || strings.HasPrefix(l, "    ") {
			continue
		}
		lines[i] = mdSpecial.Replace(l)
	}
	return strings.Join(lines, "\n")
}

// escapeForManMarkdown escapes the help text of every command in the tree
// (Use, Short, Long; never Example, which cobra/doc prints as a code block)
// and every flag's usage, once each — a persistent flag is one *pflag.Flag
// shared by every command that inherits it. It edits only this generator's
// own fresh tree, never the binary's.
func escapeForManMarkdown(c *cobra.Command) {
	seen := map[*pflag.Flag]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.Use, c.Short, c.Long = mdEscape(c.Use), mdEscape(c.Short), mdEscape(c.Long)
		for _, fs := range []*pflag.FlagSet{c.LocalNonPersistentFlags(), c.PersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) {
				if !seen[f] {
					seen[f] = true
					f.Usage = mdEscape(f.Usage)
				}
			})
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(c)
}

func manFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// visibleCommands counts the commands a man page is due for: every command
// in the tree that is available (not hidden, not deprecated, not cobra's
// own help command) and not a bare help topic.
func visibleCommands(c *cobra.Command) int {
	n := 0
	if c.IsAvailableCommand() && !c.IsAdditionalHelpTopicCommand() || !c.HasParent() {
		n = 1
	}
	for _, s := range c.Commands() {
		if s.IsAvailableCommand() && !s.IsAdditionalHelpTopicCommand() {
			n += visibleCommands(s)
		}
	}
	return n
}

func TestManPages(t *testing.T) {
	// A generator that fell back to the clock would pick this up: the pages
	// must come out the same even when the environment says it is 1970.
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	gen := t.TempDir()
	names := genManPages(t, gen)

	if *updateMan {
		if err := os.MkdirAll(manDir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, err := filepath.Glob(filepath.Join(manDir, "*.1"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range old {
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(gen, n))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(manDir, n), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("wrote %d pages to docs/man", len(names))
		return
	}

	// Anti-vacuity: one page per visible command, and the pages carry the
	// flags operators reach for.
	root := newRootCmd()
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	if want := visibleCommands(root); len(names) != want || want < 30 {
		t.Fatalf("generated %d pages for %d visible commands", len(names), want)
	}
	for page, flag := range map[string]string{
		"pveforge-vm-set.1":              `\fB--delete\fP`,
		"pveforge-roster-import-token.1": `\fB--replace\fP`,
		"pveforge-bootstrap.1":           `\fB--grant\fP`,
		"pveforge-api-post.1":            `\fB--unsafe-no-lock\fP`,
	} {
		b, err := os.ReadFile(filepath.Join(gen, page))
		if err != nil || !bytes.Contains(b, []byte(flag)) {
			t.Errorf("%s does not document %s (%v)", page, flag, err)
		}
	}

	// No help text is lost or mangled by the markdown pass: every
	// <placeholder>, [bracket] and (parenthesis) group in a command's usage,
	// help or flag text is in its page, literally.
	placeholder := regexp.MustCompile(`<[^<>\n]+>|\[[^\[\]\n]*\]|\([^()\n]*\)`)
	var check func(c *cobra.Command)
	check = func(c *cobra.Command) {
		if c.IsAvailableCommand() && !c.IsAdditionalHelpTopicCommand() || !c.HasParent() {
			text := c.Use + c.Short + c.Long + c.Example
			c.Flags().VisitAll(func(f *pflag.Flag) { text += f.Usage })
			page, err := os.ReadFile(filepath.Join(gen, strings.ReplaceAll(c.CommandPath(), " ", "-")+".1"))
			if err != nil {
				t.Errorf("%s: %v", c.CommandPath(), err)
			}
			for _, ph := range placeholder.FindAllString(text, -1) {
				if !bytes.Contains(page, []byte(ph)) {
					t.Errorf("%s: %q from its help is missing from its man page", c.CommandPath(), ph)
				}
			}
		}
		for _, s := range c.Commands() {
			check(s)
		}
	}
	check(root)
	if b, _ := os.ReadFile(filepath.Join(gen, "pveforge-vm-set.1")); !bytes.Contains(b, []byte("pveforge vm set <target-id> <vmid>")) {
		t.Errorf("vm set's synopsis lost its arguments")
	}
	// Nothing markdown did survives into a page: no link's ⟨ ⟩ (\[la] \[ra]),
	// and no escape of ours left standing, as in a code block.
	leftover := regexp.MustCompile("\\\\\\[la\\]|\\\\\\[ra\\]|\\\\[\\\\`*_<>\\[\\]]")
	for _, n := range names {
		b, _ := os.ReadFile(filepath.Join(gen, n))
		for _, m := range leftover.FindAll(b, -1) {
			t.Errorf("%s: markdown left %q in the page", n, m)
		}
	}

	have := manFiles(t, manDir)
	if !slices.Equal(have, names) {
		t.Fatalf("docs/man has %q\nthe command tree generates %q\nrun make man", have, names)
	}
	for _, n := range names {
		want, _ := os.ReadFile(filepath.Join(gen, n))
		got, _ := os.ReadFile(filepath.Join(manDir, n))
		if !bytes.Equal(got, want) {
			t.Errorf("docs/man/%s is stale: it differs from what the command tree generates; run make man", n)
		}
	}
	for _, n := range names {
		b, _ := os.ReadFile(filepath.Join(gen, n))
		if !bytes.Contains(b, []byte(`"Sep 2026"`)) || strings.Contains(string(b), "Auto generated") {
			t.Errorf("%s: want the pinned date and no auto-generated tag", n)
		}
	}
}
