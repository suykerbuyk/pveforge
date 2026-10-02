package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
	"github.com/suykerbuyk/pveforge/internal/tlspin"
)

// The README states two facts an operator looks for and must be able to
// trust: the environment variables pveforge reads, and its exit statuses.
// These tests derive both from the code and require the README's tables to
// say exactly that, so neither can silently rot.

// readmeTable returns the first backticked cell of every row of the table
// under the README heading "## <section>".
func readmeTable(t *testing.T, section string) []string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(b), "\n## "+section+"\n")
	if !ok {
		t.Fatalf("README has no %q section", section)
	}
	if i := strings.Index(body, "\n## "); i >= 0 {
		body = body[:i]
	}
	var cells []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([^`]+)` \\|").FindAllStringSubmatch(body, -1) {
		cells = append(cells, m[1])
	}
	if len(cells) == 0 {
		t.Fatalf("README's %q section has no table rows", section)
	}
	slices.Sort(cells)
	return cells
}

// TestREADME_EnvironmentVariablesMatchTheCode: the README's Environment
// table names exactly the PVEFORGE_* variables the module's non-test source
// mentions.
func TestREADME_EnvironmentVariablesMatchTheCode(t *testing.T) {
	re := regexp.MustCompile(`PVEFORGE_[A-Z0-9_]+`)
	seen := map[string]bool{}
	files := 0
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && path != "../.." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				for _, v := range re.FindAllString(lit.Value, -1) {
					seen[v] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A name built from constants ("PVEFORGE_" + "X", or a const of one)
	// is no literal of its own: resolve every environment call's name.
	for v := range envCallNames(t) {
		seen[v] = true
	}
	var code []string
	for v := range seen {
		code = append(code, v)
	}
	slices.Sort(code)
	if files < 50 || len(code) == 0 {
		t.Fatalf("walked %d files and found %q: the sweep is not seeing the module", files, code)
	}
	if doc := readmeTable(t, "Environment"); !slices.Equal(doc, code) {
		t.Errorf("README Environment table = %q, but the code reads %q", doc, code)
	}
}

// envCallNames type-checks every module package whose non-test source calls
// os or syscall Getenv, LookupEnv, Setenv or Unsetenv, and returns the
// PVEFORGE_* names those calls use, folded to their constant values. A
// name that is not a constant fails the test: it could be any variable.
func envCallNames(t *testing.T) map[string]bool {
	t.Helper()
	envFuncs := map[string]bool{"Getenv": true, "LookupEnv": true, "Setenv": true, "Unsetenv": true}
	byDir := map[string][]string{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "../.." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			byDir[filepath.Dir(path)] = append(byDir[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	calls := 0
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)
	for dir, paths := range byDir {
		var files []*ast.File
		mentions := false
		for _, p := range paths {
			src, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if regexp.MustCompile(`\b(Getenv|LookupEnv|Setenv|Unsetenv)\(`).Match(src) {
				mentions = true
			}
			f, err := parser.ParseFile(fset, p, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		if !mentions {
			continue
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
		if _, err := (&types.Config{Importer: imp}).Check(dir, fset, files, info); err != nil {
			t.Fatalf("type-check %s: %v", dir, err)
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				fn, ok := info.Uses[sel.Sel].(*types.Func)
				if !ok || fn.Pkg() == nil || (fn.Pkg().Path() != "os" && fn.Pkg().Path() != "syscall") || !envFuncs[fn.Name()] {
					return true
				}
				calls++
				tv := info.Types[call.Args[0]]
				if tv.Value == nil || tv.Value.Kind() != constant.String {
					t.Errorf("%s: %s.%s's variable name is not a constant, so the README's Environment table cannot be checked against it", fset.Position(call.Pos()), fn.Pkg().Name(), fn.Name())
					return true
				}
				if v := constant.StringVal(tv.Value); strings.HasPrefix(v, "PVEFORGE_") {
					names[v] = true
				}
				return true
			})
		}
	}
	if calls < 3 {
		t.Fatalf("found %d environment calls: the type-checked walk is not seeing them", calls)
	}
	return names
}

// TestREADME_ExitStatusesMatchTheCode: the README's Exit status table lists
// exactly the statuses pveforge can exit with: the integer literals runRoot
// returns or assigns to its code, and 128+signum for each signal
// notifyInterrupt catches. main's os.Exit(realMain()) must be the only exit.
func TestREADME_ExitStatusesMatchTheCode(t *testing.T) {
	fset, files, info := checkedPackage(t)
	signums := map[string]syscall.Signal{
		"SIGHUP": syscall.SIGHUP, "SIGINT": syscall.SIGINT, "SIGQUIT": syscall.SIGQUIT,
		"SIGTERM": syscall.SIGTERM, "SIGUSR1": syscall.SIGUSR1, "SIGUSR2": syscall.SIGUSR2,
	}
	codes := map[int]bool{}
	var sawRunRoot, sawExitCode, sawNotify bool
	exits := 0
	// status resolves one exit-status expression: a constant of any
	// spelling (a literal, a named const, a folded expression) is recorded;
	// the signal path (ie.exitCode()) and the variable code itself are
	// accounted for elsewhere; anything else cannot be checked, and fails.
	status := func(e ast.Expr, where string) {
		if tv := info.Types[e]; tv.Value != nil {
			n, ok := constant.Int64Val(tv.Value)
			if !ok {
				t.Errorf("%s: exit status %s is not an integer constant", fset.Position(e.Pos()), types.ExprString(e))
			}
			codes[int(n)] = true
			return
		}
		if id, ok := e.(*ast.Ident); ok && id.Name == "code" && where == "runRoot" {
			return
		}
		if call, ok := e.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "exitCode" {
				return
			}
		}
		if where == "exitCode" {
			return // 128+signum: accounted for from notifyInterrupt's signals
		}
		t.Errorf("%s: exit status %s in %s cannot be resolved to a constant", fset.Position(e.Pos()), types.ExprString(e), where)
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exit" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" {
						exits++
						if inner, ok := call.Args[0].(*ast.CallExpr); !ok || calleeIdent(inner) != "realMain" {
							t.Errorf("%s: an os.Exit other than main's os.Exit(realMain()): its status is not in the README's contract", fset.Position(call.Pos()))
						}
					}
				}
			}
			return true
		})
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			switch name := fd.Name.Name; name {
			case "runRoot", "exitCode":
				if name == "runRoot" {
					sawRunRoot = true
				} else {
					sawExitCode = true
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncLit:
						return false // a closure's returns are not the function's
					case *ast.ReturnStmt:
						for _, r := range x.Results {
							status(r, name)
						}
					case *ast.AssignStmt:
						for i, l := range x.Lhs {
							if id, ok := l.(*ast.Ident); ok && id.Name == "code" && i < len(x.Rhs) {
								status(x.Rhs[i], name)
							}
						}
					}
					return true
				})
			case "notifyInterrupt":
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || calleeIdent(call) != "notifySignals" {
						return true
					}
					sawNotify = true
					for _, a := range call.Args[1:] {
						name := exprName(a)
						s, known := signums[strings.TrimPrefix(name, "syscall.")]
						if !known {
							t.Fatalf("notifyInterrupt catches %s, which this test does not know: add it here and to the README", name)
						}
						codes[128+int(s)] = true
					}
					return true
				})
			}
		}
	}
	if !sawRunRoot || !sawExitCode || !sawNotify || exits != 1 {
		t.Fatalf("runRoot seen %v, exitCode seen %v, notifySignals seen %v, os.Exit calls %d: the walk is not seeing the exit paths", sawRunRoot, sawExitCode, sawNotify, exits)
	}
	var code []string
	for c := range codes {
		code = append(code, strconv.Itoa(c))
	}
	doc := readmeTable(t, "Exit status")
	slices.SortFunc(code, func(a, b string) int { x, _ := strconv.Atoi(a); y, _ := strconv.Atoi(b); return x - y })
	slices.SortFunc(doc, func(a, b string) int { x, _ := strconv.Atoi(a); y, _ := strconv.Atoi(b); return x - y })
	if !slices.Equal(doc, code) {
		t.Errorf("README Exit status table = %q, but the code can exit with %q", doc, code)
	}
}

func calleeIdent(call *ast.CallExpr) string {
	if id, ok := call.Fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// exprName is "pkg.Name" for a qualified identifier, else a placeholder.
func exprName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
	}
	return "an expression"
}

// The operator docs also show command lines, and an operator copies them.
// README.md, docs/operations/secrets-and-keys.md and docs/prd.md are held
// to the real command tree: every pveforge command line in a code block must name a
// runnable command, parse with that command's own flags, and give it an
// argument count its Args accepts; every inline code span that starts with
// pveforge must name only flags that command has. A renamed or removed flag
// therefore fails here, not in an operator's terminal.

// operatorDocs are the files whose command lines are checked, and the least
// number of full command lines each must yield, so a parser that stops
// seeing them cannot pass by finding none.
var operatorDocs = []struct {
	path     string
	minLines int
}{
	{"../../README.md", 5},
	{"../../docs/operations/secrets-and-keys.md", 10},
	{prdPath, 2},
}

// docCommand is one pveforge invocation found in a Markdown file: the
// arguments after the binary, and whether it came from an inline code span
// (flags checked only) rather than a code block (fully checked).
type docCommand struct {
	where string
	args  []string
	span  bool
}

type shellToken struct {
	text   string
	quoted bool
}

// shellTokens splits a line as a shell would, well enough for docs: words
// separated by blanks, with '…' and "…" grouping (quotes removed). An
// unterminated quote runs to the end of the line.
func shellTokens(line string) []shellToken {
	var toks []shellToken
	var cur strings.Builder
	in, quoted, started := byte(0), false, false
	flush := func() {
		if started {
			toks = append(toks, shellToken{cur.String(), quoted})
		}
		cur.Reset()
		quoted, started = false, false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			in, quoted, started = c, true, true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	flush()
	return toks
}

// shellOperator reports whether an unquoted token ends a command.
func shellOperator(t shellToken) bool {
	if t.quoted {
		return false
	}
	switch t.text {
	case "|", "||", "&&", ";", "&":
		return true
	}
	return strings.HasPrefix(t.text, ">") || strings.HasPrefix(t.text, "<") ||
		strings.HasPrefix(t.text, "2>")
}

// shellComment reports whether an unquoted token starts a comment, which
// runs to the end of the line.
func shellComment(t shellToken) bool {
	return !t.quoted && strings.HasPrefix(t.text, "#")
}

// pveforgeBinary reports whether a token names the pveforge binary.
func pveforgeBinary(s string) bool {
	return s == "pveforge" || s == "$PVEFORGE_BIN" || s == "${PVEFORGE_BIN}" || strings.HasSuffix(s, "bin/pveforge")
}

var envAssignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// pveforgeInvocations returns the argument lists of every pveforge command
// on a shell line: the binary must be in command position (first, after an
// operator, after env assignments, or after the `--` of a wrapper such as
// unlock.sh run), and its arguments end at the next operator.
func pveforgeInvocations(line string) [][]string {
	toks := shellTokens(line)
	var out [][]string
	cmdPos := true
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if shellComment(t) {
			break
		}
		if shellOperator(t) {
			cmdPos = true
			continue
		}
		if !t.quoted && t.text == "--" {
			cmdPos = true
			continue
		}
		if cmdPos && !t.quoted && envAssignRE.MatchString(t.text) {
			continue
		}
		if cmdPos && pveforgeBinary(t.text) {
			var args []string
			for i++; i < len(toks) && !shellOperator(toks[i]) && !shellComment(toks[i]); i++ {
				args = append(args, toks[i].text)
			}
			out = append(out, args)
			cmdPos = true
			continue
		}
		cmdPos = false
	}
	return out
}

var codeSpanRE = regexp.MustCompile("`([^`]+)`")

// docCommands finds every pveforge invocation in a Markdown text: in fenced
// code blocks and indented (4+ spaces) code lines, with backslash
// continuations joined, and in inline code spans elsewhere.
func docCommands(name, text string) []docCommand {
	var cmds []docCommand
	lines := strings.Split(text, "\n")
	fenced := false
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fenced = !fenced
			continue
		}
		code := fenced || strings.HasPrefix(l, "    ")
		if code {
			start := i + 1
			for strings.HasSuffix(l, `\`) && i+1 < len(lines) {
				i++
				l = strings.TrimSuffix(l, `\`) + " " + strings.TrimSpace(lines[i])
			}
			for _, args := range pveforgeInvocations(strings.TrimSpace(l)) {
				cmds = append(cmds, docCommand{where: fmt.Sprintf("%s:%d", name, start), args: args})
			}
			continue
		}
		for _, m := range codeSpanRE.FindAllStringSubmatch(l, -1) {
			for _, args := range pveforgeInvocations(m[1]) {
				if len(args) == 0 {
					continue // the binary named in prose, not a command
				}
				cmds = append(cmds, docCommand{where: fmt.Sprintf("%s:%d", name, i+1), args: args, span: true})
			}
		}
	}
	return cmds
}

// docRequiredFlags are the flags a command refuses to run without although
// cobra does not know it: the command checks them itself, with its own
// message. A flag cobra marks required (import-token's --token-id) is held by
// ValidateRequiredFlags instead. TestREADME_DocRequiredFlagsAreRequired proves each entry against
// the real CLI, so the list cannot claim a requirement the command dropped.
var docRequiredFlags = map[string][]string{
	"pveforge bootstrap":           {"grant"},
	"pveforge roster import-token": {"grant"},
}

var docPlaceholderRE = regexp.MustCompile(`<[^<>]*>|…`)

// docFill turns a flag value from the docs into one a parser can check: a
// value that is only an ellipsis stands for a whole value the operator
// supplies, and is skipped; otherwise each <…> placeholder (and any ellipsis)
// becomes dummy, a valid stand-in for that part, so everything the docs
// spell out around it, a prefix or a grant's other fields, is still parsed.
func docFill(v, dummy string) (string, bool) {
	if v == "…" {
		return "", false
	}
	return docPlaceholderRE.ReplaceAllString(v, dummy), true
}

// Valid stand-ins for a placeholder: 43 base64 characters (a SHA-256 host
// key fingerprint's body), 44 with padding (an SPKI pin's), and a name.
var (
	docDummyFingerprint = strings.Repeat("A", 43)
	docDummyPin         = strings.Repeat("A", 43) + "="
	docDummyName        = "x"
)

// checkDocFlagValues parses the values the docs give the flags whose syntax
// pveforge defines, with the parsers the commands use.
func checkDocFlagValues(fs *pflag.FlagSet) error {
	if f := fs.Lookup("grant"); f != nil && f.Changed {
		vals, _ := fs.GetStringArray("grant")
		var real []string
		for _, v := range vals {
			if filled, ok := docFill(v, docDummyName); ok {
				real = append(real, filled)
			}
		}
		if len(real) > 0 {
			if _, err := bootstrap.ParseGrants(real); err != nil {
				return err
			}
		}
	}
	if f := fs.Lookup("expect"); f != nil && f.Changed {
		if v, ok := docFill(f.Value.String(), docDummyPin); ok {
			if _, err := tlspin.Parse(v); err != nil {
				return fmt.Errorf("--expect: %w", err)
			}
		}
	}
	if f := fs.Lookup("host-key-fingerprint"); f != nil && f.Changed {
		if v, ok := docFill(f.Value.String(), docDummyFingerprint); ok {
			if err := sshexec.CheckFingerprint(v); err != nil {
				return fmt.Errorf("--host-key-fingerprint: %w", err)
			}
		}
	}
	return nil
}

// checkDocCommand returns what is wrong with one invocation against a fresh
// command tree, or "" when nothing is.
func checkDocCommand(c docCommand) string {
	root := newRootCmd()
	cur, rest := root, c.args
	find := func(name string) *cobra.Command {
		for _, sub := range cur.Commands() {
			if sub.Name() == name || slices.Contains(sub.Aliases, name) {
				return sub
			}
		}
		return nil
	}
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		next := find(rest[0])
		// Prose may write sibling commands as alternatives in a span
		// ("api post|put|delete"): each must exist, and the first is checked.
		if alts := strings.Split(rest[0], "|"); next == nil && c.span && len(alts) > 1 {
			next = find(alts[0])
			for _, a := range alts[1:] {
				if find(a) == nil {
					next = nil
				}
			}
		}
		if next == nil {
			break
		}
		cur, rest = next, rest[1:]
	}
	if cur == root || !cur.Runnable() || cur.HasSubCommands() {
		return fmt.Sprintf("%s: %q names no pveforge command (a group or nothing)", c.where, strings.Join(c.args, " "))
	}
	if c.span {
		fs := cur.Flags()
		fs.AddFlagSet(cur.InheritedFlags())
		for _, a := range rest {
			if a == "--" {
				break
			}
			var f *pflag.Flag
			switch {
			case strings.HasPrefix(a, "--"):
				name, _, _ := strings.Cut(a[2:], "=")
				f = fs.Lookup(name)
			case strings.HasPrefix(a, "-") && len(a) == 2:
				f = fs.ShorthandLookup(a[1:])
			default:
				continue
			}
			if f == nil {
				return fmt.Sprintf("%s: %s has no flag %s", c.where, cur.CommandPath(), a)
			}
		}
		return ""
	}
	if err := cur.ParseFlags(rest); err != nil {
		return fmt.Sprintf("%s: %s %q: %v", c.where, cur.CommandPath(), strings.Join(rest, " "), err)
	}
	if err := cur.ValidateArgs(cur.Flags().Args()); err != nil {
		return fmt.Sprintf("%s: %s %q: %v", c.where, cur.CommandPath(), strings.Join(rest, " "), err)
	}
	if err := cur.ValidateRequiredFlags(); err != nil {
		return fmt.Sprintf("%s: %s %q: %v", c.where, cur.CommandPath(), strings.Join(rest, " "), err)
	}
	for _, name := range docRequiredFlags[cur.CommandPath()] {
		if f := cur.Flags().Lookup(name); f == nil || !f.Changed {
			return fmt.Sprintf("%s: %s %q: lacks --%s, which the command requires", c.where, cur.CommandPath(), strings.Join(rest, " "), name)
		}
	}
	if err := checkDocFlagValues(cur.Flags()); err != nil {
		return fmt.Sprintf("%s: %s %q: %v", c.where, cur.CommandPath(), strings.Join(rest, " "), err)
	}
	return ""
}

// TestREADME_DocCommandLinesMatchTheCommandTree holds every pveforge command line
// in the operator docs to the command tree. The guide must also still show
// the commands and flags its procedures are about.
func TestREADME_DocCommandLinesMatchTheCommandTree(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range operatorDocs {
		b, err := os.ReadFile(d.path)
		if err != nil {
			t.Fatal(err)
		}
		full := 0
		for _, c := range docCommands(filepath.Base(d.path), string(b)) {
			if !c.span {
				full++
			}
			if p := checkDocCommand(c); p != "" {
				t.Error(p)
				continue
			}
			if strings.HasSuffix(d.path, "secrets-and-keys.md") && !c.span {
				seen[strings.Join(c.args, " ")] = true
			}
		}
		if full < d.minLines {
			t.Errorf("%s: found %d pveforge command lines in code, want at least %d: the scan is not seeing them", d.path, full, d.minLines)
		}
	}
	// What the guide's procedures are about, each on a checked line.
	for _, want := range []string{
		"bootstrap ", "--host-key-fingerprint", "--reprovisioned", "--no-ssh-key",
		"roster pin-tls ", "--print", "--expect", "roster import-token ",
		"roster validate ", "--require-tls-pins", "roster rekey ",
	} {
		found := false
		for line := range seen {
			if strings.HasPrefix(line, want) || strings.Contains(line, " "+want) {
				found = true
			}
		}
		if !found {
			t.Errorf("secrets-and-keys.md: no checked command line shows %q", want)
		}
	}
}

// TestREADME_DocCommandLineCheckerCatchesDrift: the checker itself goes red on
// each kind of drift, and stays green on good lines, so the test above
// cannot pass by checking nothing.
func TestREADME_DocCommandLineCheckerCatchesDrift(t *testing.T) {
	good := "```\n" +
		"pveforge bootstrap t --grant /:PVEAuditor --host-key-fingerprint SHA256:/F+3iwJFiGdTK5cIbh3UT1A+TbBeSvIkj8YhVQf00go\n" +
		"PVEFORGE_ROSTER_PASSPHRASE=x hack/harness/unlock.sh run -- \"$PVEFORGE_BIN\" roster pin-tls t --print\n" +
		"echo s | pveforge roster import-token t --token-id 'a@pve!b' \\\n  --grant /:X --expect sha256//aE4pY00bING+PdbMcVvozNkHmo+YHd21i+uW3eK5YAs= > out.json\n" +
		"pveforge roster validate ./r.toml --require-tls-pins\n" +
		"pveforge bootstrap t --grant /pool/<pool>:PVEVMUser --grant … --host-key-fingerprint SHA256:<console-value>\n" +
		"```\n" +
		"Run `pveforge roster pin-tls <target> --repin` or `pveforge api post|put|delete /access` then.\n"
	cmds := docCommands("good", good)
	if len(cmds) != 7 {
		t.Fatalf("good doc: found %d commands, want 7: %+v", len(cmds), cmds)
	}
	for _, c := range cmds {
		if p := checkDocCommand(c); p != "" {
			t.Errorf("a good line was refused: %s", p)
		}
	}
	for _, bad := range []string{
		"```\npveforge bootstrap t --grant /:X --host-key-fingerprnt SHA256:x\n```",             // misspelled flag
		"```\npveforge roster validate --print\n```",                                            // flag of another command
		"```\npveforge bootstrap --grant /:X\n```",                                              // missing target
		"```\npveforge bootstrap a b --grant /:X\n```",                                          // extra positional
		"```\npveforge roster pin t\n```",                                                       // unknown subcommand
		"```\npveforge roster\n```",                                                             // a group, not a command
		"```\npveforge roster pin-tls t --expect\n```",                                          // flag missing its value
		"```\nsudo x | pveforge roster pin-tls t \\\n  --ssh-tofu\n```",                         // bad flag on a continuation
		"`pveforge bootstrap --reprovision`",                                                    // span with a bad flag
		"`pveforge api post|put|remove /x`",                                                     // span with a bad alternative
		"    pveforge roster init --forse\n",                                                    // indented code block
		"```\npveforge bootstrap t --host-key-fingerprint SHA256:<v>\n```",                      // required --grant removed
		"```\necho s | pveforge roster import-token t --grant /:X\n```",                         // required --token-id removed
		"```\npveforge bootstrap t --grant /:PVEVMAdmin::7\n```",                                // bad grant value
		"```\npveforge roster pin-tls t --expect md5//abc\n```",                                 // bad pin value
		"```\npveforge bootstrap t --grant /:X --host-key-fingerprint MD5:ab\n```",              // bad fingerprint value
		"```\npveforge roster pin-tls t --expect md5//<verified-pin>\n```",                      // bad prefix around a placeholder
		"```\npveforge bootstrap t --grant /:X --host-key-fingerprint MD5:<console-value>\n```", // bad prefix around a placeholder
		"```\npveforge bootstrap t --grant /:PVEVMAdmin::7<x>\n```",                             // bad propagate before a placeholder
		"```\npveforge bootstrap t --grant /pool/<lab>:PVEVMUser:bogus:9\n```",                  // bad field after a placeholder
	} {
		cmds := docCommands("bad", bad)
		if len(cmds) != 1 {
			t.Errorf("%q: found %d commands, want 1", bad, len(cmds))
			continue
		}
		if checkDocCommand(cmds[0]) == "" {
			t.Errorf("%q passed the checker", bad)
		}
	}
}

// TestREADME_GuideNamesOnlyDocumentedVariables: every PVEFORGE_* variable the
// secrets guide or the PRD names is documented: in the README's Environment
// table (which the test above derives from the code) or in the harness
// README.
func TestREADME_GuideNamesOnlyDocumentedVariables(t *testing.T) {
	harness, err := os.ReadFile("../../hack/harness/README.md")
	if err != nil {
		t.Fatal(err)
	}
	env := readmeTable(t, "Environment")
	for _, path := range []string{"../../docs/operations/secrets-and-keys.md", prdPath} {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		names := regexp.MustCompile(`PVEFORGE_[A-Z0-9_]*[A-Z0-9]`).FindAllString(string(doc), -1)
		if len(names) < 5 {
			t.Fatalf("found %d variable mentions in %s: the scan is not seeing them", len(names), path)
		}
		for _, n := range names {
			if !slices.Contains(env, n) && !regexp.MustCompile(`\b`+n+`\b`).Match(harness) {
				t.Errorf("%s names %s, which neither the README's Environment table nor hack/harness/README.md documents", filepath.Base(path), n)
			}
		}
	}
}

// TestREADME_DocRequiredFlagsAreRequired: every entry of docRequiredFlags is
// a flag the real CLI refuses to run without, naming it, so the doc check
// enforces a requirement the command really has.
func TestREADME_DocRequiredFlagsAreRequired(t *testing.T) {
	t.Setenv("PVEFORGE_ROSTER_PASSPHRASE", "x")
	rp := filepath.Join(t.TempDir(), "r.toml")
	if err := os.WriteFile(rp, []byte("[[targets]]\nid = \"t\"\nhost = \"192.0.2.1\"\nnode = \"t\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	full := map[string][]string{
		"pveforge bootstrap":           {"bootstrap", "t", "--roster", rp, "--grant", "/:PVEAuditor"},
		"pveforge roster import-token": {"roster", "import-token", "t", "--roster", rp, "--token-id", "a@pve!b", "--grant", "/:PVEAuditor"},
	}
	names := map[string]string{"grant": "--grant"}
	if len(full) != len(docRequiredFlags) {
		t.Fatalf("docRequiredFlags has %d commands, this test drives %d", len(docRequiredFlags), len(full))
	}
	for path, required := range docRequiredFlags {
		for _, name := range required {
			var args []string
			for i := 0; i < len(full[path]); i++ {
				if full[path][i] == "--"+name {
					i++ // drop the flag and its value
					continue
				}
				args = append(args, full[path][i])
			}
			code, _, stderr := runRootArgs(args...)
			if code == 0 || !strings.Contains(stderr, names[name]) {
				t.Errorf("%s without --%s: exit %d, stderr %q; want a refusal naming %s", path, name, code, stderr, names[name])
			}
		}
	}
}

// TestREADME_GuideHarnessGrantsAreD5s: the guide's reprovision line for the
// harness's outer target gives exactly D5 G4's grants. Grants that differ
// from the held token's are a verdict that revokes it, so a copy that
// drifted from d5/sequence.md would revoke the harness token.
func TestREADME_GuideHarnessGrantsAreD5s(t *testing.T) {
	grants := func(path, target string) []string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		lines := 0
		for _, c := range docCommands(filepath.Base(path), string(b)) {
			if c.span || len(c.args) < 2 || c.args[0] != "bootstrap" || c.args[1] != target {
				continue
			}
			lines++
			for i := 0; i+1 < len(c.args); i++ {
				if c.args[i] == "--grant" {
					out = append(out, c.args[i+1])
				}
			}
		}
		if lines != 1 {
			t.Fatalf("%s: %d bootstrap lines for %s, want exactly 1", path, lines, target)
		}
		slices.Sort(out)
		return out
	}
	d5 := grants("../../hack/harness/d5/sequence.md", "qa-pve-02-harness")
	guide := grants("../../docs/operations/secrets-and-keys.md", "qa-pve-02-harness")
	if len(d5) != 4 || !slices.Equal(guide, d5) {
		t.Errorf("the guide's harness grants %q are not D5 G4's %q", guide, d5)
	}
}

// TestREADME_GuideRootGrantsPropagate: in the guide, every grant on "/" keeps
// propagate 1. Its only such grant is the live token's (PVEVMAdmin on /,
// propagate 1), and the same grant without ::1 reads as too wide, a verdict
// that REVOKES that token for every holder. Checked on the parsed command
// lines and on the raw text, so no copyable form can lose the ::1.
func TestREADME_GuideRootGrantsPropagate(t *testing.T) {
	b, err := os.ReadFile("../../docs/operations/secrets-and-keys.md")
	if err != nil {
		t.Fatal(err)
	}
	root := 0
	for _, c := range docCommands("secrets-and-keys.md", string(b)) {
		for i := 0; i+1 < len(c.args); i++ {
			if c.args[i] != "--grant" {
				continue
			}
			v, ok := docFill(c.args[i+1], docDummyName)
			if !ok {
				continue
			}
			gs, err := bootstrap.ParseGrants([]string{v})
			if err != nil || gs[0].Path != "/" {
				continue
			}
			root++
			if !gs[0].Propagate {
				t.Errorf("%s: --grant %s grants on / without propagate 1: re-run against the live token, it revokes it", c.where, c.args[i+1])
			}
		}
	}
	if root < 2 {
		t.Errorf("found %d command lines granting on /, want at least 2 (procedures 3 and 5): the scan is not seeing them", root)
	}
	for _, m := range regexp.MustCompile("--grant '?/:[^\\s`']*").FindAllString(string(b), -1) {
		if !strings.HasSuffix(m, ":1") {
			t.Errorf("the guide shows %q: a grant on / without ::1", m)
		}
	}
}

// prdPath is the PRD. Its command lines are held by the check above
// (operatorDocs) and its variables by TestREADME_GuideNamesOnlyDocumentedVariables;
// the TestPRD_* tests below hold what else it states that the code can
// answer. Its package map is held by internal/sourceguard's
// TestPRD_PackageMapMatchesGoList, where `go list` already runs.
const prdPath = "../../docs/prd.md"

// prdSection returns the PRD's text after the heading line that starts with
// heading (e.g. "### 4.2 "), up to the next heading of the same or a higher
// level.
func prdSection(t *testing.T, text, heading string) string {
	t.Helper()
	_, body, ok := strings.Cut(text, "\n"+heading)
	if !ok {
		t.Fatalf("docs/prd.md has no heading starting %q", heading)
	}
	level := strings.Index(heading, " ")
	for l := level; l >= 1; l-- {
		if i := strings.Index(body, "\n"+strings.Repeat("#", l)+" "); i >= 0 {
			body = body[:i]
		}
	}
	return body
}

// What the PRD cites in an inline code span is checked, not trusted:
//   - a repository path (under cmd/, internal/, docs/, hack/ or .github/, or
//     a named top-level file) must exist;
//   - a package-qualified symbol, pkg.Name or pkg.Type.Method, whose pkg is
//     one of this module's package names, must be declared in that
//     package's non-test source (Name at top level; Method on Type);
//   - a bare Err* name must be declared at top level in some package's
//     non-test source;
//   - any other bare Go name that cannot be an English word or a flag (camel
//     case, as in servedPin or RootAccess, led by an acronym, as in
//     SSHTransport or NVMeDrive, or a TestX_Y test name) must be
//     declared somewhere in the module, tests included: a top-level name or
//     a method. A name from another module is written package-qualified
//     (proxmox.WithAPIToken), and a qualifier that is not one of this
//     module's packages is not checked.
//
// Line numbers are not cited, so none is checked. A span of any other shape
// (a flag, a PVE path, a roster key) is not a citation and is left alone.
var (
	prdPathSpanRE   = regexp.MustCompile(`^(?:(?:cmd|internal|docs|hack|\.github)/[A-Za-z0-9_./-]*|LICENSE|README\.md|THIRD-PARTY-NOTICES\.md|Makefile)$`)
	prdSymbolSpanRE = regexp.MustCompile(`^([a-z][a-z0-9]*)\.([A-Z][A-Za-z0-9_]*)(?:\.([A-Z][A-Za-z0-9_]*))?$`)
	prdErrSpanRE    = regexp.MustCompile(`^Err[A-Z][A-Za-z0-9_]*$`)
	// prdRoleSpanRE is a PVE role name (PVEVMAdmin, PVEAuditor): PVE's
	// vocabulary, not a Go name, so never looked up.
	prdRoleSpanRE = regexp.MustCompile(`^PVE[A-Z][A-Za-z]*$`)
	prdBareSpanRE = regexp.MustCompile(`^(?:[a-z]+[A-Z][A-Za-z0-9]*|[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+|[A-Z]{2,}[a-z]+(?:[A-Z][A-Za-z0-9]*)+|[A-Z]{2,}[a-z]{2,}[a-z0-9]*|Test[A-Za-z0-9]*_[A-Za-z0-9_]+)$`)
)

// moduleDecls is what the module's non-test source declares, by package
// name: each top-level name, and each method as "Type.Method".
type moduleDecls map[string]map[string]bool

// loadModuleDecls parses every non-test .go file of the module outside
// testdata and hidden directories, and the test files too if withTests.
func loadModuleDecls(t *testing.T, withTests bool) moduleDecls {
	t.Helper()
	decls := moduleDecls{}
	files := 0
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "../.." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || (!withTests && strings.HasSuffix(path, "_test.go")) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		names := decls[f.Name.Name]
		if names == nil {
			names = map[string]bool{}
			decls[f.Name.Name] = names
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					names[d.Name.Name] = true
					continue
				}
				recv := d.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				switch r := recv.(type) {
				case *ast.IndexExpr:
					recv = r.X
				case *ast.IndexListExpr:
					recv = r.X
				}
				if id, ok := recv.(*ast.Ident); ok {
					names[id.Name+"."+d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						names[s.Name.Name] = true
					case *ast.ValueSpec:
						for _, n := range s.Names {
							names[n.Name] = true
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 50 {
		t.Fatalf("parsed %d files: the sweep is not seeing the module", files)
	}
	return decls
}

// bareNames is every name decls declares, in any package: each top-level
// name, each "Type.Method", and each method name alone.
func bareNames(decls moduleDecls) map[string]bool {
	all := map[string]bool{}
	for _, names := range decls {
		for n := range names {
			all[n] = true
			if _, m, ok := strings.Cut(n, "."); ok {
				all[m] = true
			}
		}
	}
	return all
}

// prdCitations is what checkPRDCitations found, by kind, for anti-vacuity.
// An Err name counts as an Err whether bare or package-qualified; a
// qualified one is also a symbol.
type prdCitations struct{ paths, symbols, errs, bare int }

// checkPRDCitations checks every citation in text's inline code spans
// against decls and, for paths, exists (relative to the repository root).
func checkPRDCitations(text string, decls moduleDecls, bare map[string]bool, exists func(string) bool) ([]string, prdCitations) {
	var problems []string
	var n prdCitations
	fenced := false
	for i, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		for _, m := range codeSpanRE.FindAllStringSubmatch(l, -1) {
			span := m[1]
			switch {
			case prdPathSpanRE.MatchString(span):
				n.paths++
				if !exists(span) {
					problems = append(problems, fmt.Sprintf("prd.md:%d: cites %s, which does not exist", i+1, span))
				}
			case prdErrSpanRE.MatchString(span):
				n.errs++
				found := false
				for _, names := range decls {
					if names[span] {
						found = true
					}
				}
				if !found {
					problems = append(problems, fmt.Sprintf("prd.md:%d: cites %s, which no package declares", i+1, span))
				}
			case prdBareSpanRE.MatchString(span) && !prdRoleSpanRE.MatchString(span):
				n.bare++
				if !bare[span] {
					problems = append(problems, fmt.Sprintf("prd.md:%d: cites %s, which nothing in the module declares", i+1, span))
				}
			default:
				sm := prdSymbolSpanRE.FindStringSubmatch(span)
				if sm == nil {
					continue
				}
				names, ok := decls[sm[1]]
				if !ok || sm[1] == "main" {
					continue // not one of this module's packages (e.g. a file name)
				}
				n.symbols++
				if prdErrSpanRE.MatchString(sm[2]) {
					n.errs++
				}
				want := sm[2]
				if sm[3] != "" {
					want = sm[2] + "." + sm[3]
				}
				if !names[want] {
					problems = append(problems, fmt.Sprintf("prd.md:%d: cites %s, but package %s declares no %s", i+1, span, sm[1], want))
				}
			}
		}
	}
	return problems, n
}

// TestPRD_CitationsResolve: every file, Err* name and package-qualified
// symbol the PRD cites exists.
func TestPRD_CitationsResolve(t *testing.T) {
	b, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	exists := func(p string) bool {
		_, err := os.Stat(filepath.Join("../..", p))
		return err == nil
	}
	problems, n := checkPRDCitations(string(b), loadModuleDecls(t, false), bareNames(loadModuleDecls(t, true)), exists)
	for _, p := range problems {
		t.Error(p)
	}
	if n.paths < 15 || n.symbols < 20 || n.errs < 5 || n.bare < 5 {
		t.Errorf("found %d paths, %d symbols, %d Err names and %d bare names cited: the scan is not seeing them", n.paths, n.symbols, n.errs, n.bare)
	}
}

// TestPRD_CitationCheckerCatchesDrift: each kind of stale citation is
// caught, a good one is not, and a span that is not a citation is ignored.
func TestPRD_CitationCheckerCatchesDrift(t *testing.T) {
	decls := moduleDecls{
		"pve":  {"RoutedClient": true, "RoutedClient.SetVMConfigField": true, "ErrTLSPinRequired": true, "servedPin": true, "SSHTransport": true},
		"main": {"newRootCmd": true, "TestPRD_Here": true},
	}
	bare := bareNames(decls)
	exists := func(p string) bool { return p == "internal/pve/routed.go" || p == "docs/man" }
	good := "`internal/pve/routed.go`, `docs/man`, `pve.RoutedClient`, `pve.RoutedClient.SetVMConfigField`,\n" +
		"`pve.ErrTLSPinRequired`, `ErrTLSPinRequired`, `--grant`, `go-proxmox`, `kvjson.go`, `/nodes/{node}/status`,\n" +
		"`servedPin`, `RoutedClient`, `SetVMConfigField`, `TestPRD_Here`, `SSHTransport`, `proxmox.WithAPIToken`, `args`, `safe`, `id`, `UPIDs`, `VMID`, `PVEVMAdmin`\n" +
		"```\n`internal/gone.go` and `goneName` in a fence are not prose\n```\n"
	if problems, n := checkPRDCitations(good, decls, bare, exists); len(problems) != 0 || n != (prdCitations{paths: 2, symbols: 3, errs: 2, bare: 5}) {
		t.Fatalf("good doc: problems %q, counts %+v", problems, n)
	}
	for _, bad := range []string{
		"`internal/pve/gone.go`",             // a file that moved
		"`pve.RoutedClinet`",                 // a misspelled type
		"`pve.RoutedClient.SetVMConfigFeld`", // a renamed method
		"`pve.ErrGone`",                      // a qualified Err that no longer exists
		"`ErrGone`",                          // a bare Err that no longer exists
		"`THIRD-PARTY-NOTICES.md`",           // a top-level file that is not there
		"`servedPinned`",                     // a renamed unexported name
		"`RoutedClients`",                    // a renamed exported name, unqualified
		"`TestPRD_Gone`",                     // a test that no longer exists
		"`SSHTransports`",                    // a renamed acronym-led name
		"`NVMeDrives`",                       // another, acronym then lower case
	} {
		if problems, _ := checkPRDCitations(bad, decls, bare, exists); len(problems) != 1 {
			t.Errorf("%s: got problems %q, want exactly one", bad, problems)
		}
	}
}

// prdTierRowRE is one row of the PRD's tier table (§4.2).
var prdTierRowRE = regexp.MustCompile("(?m)^\\| (safe|mutating|destructive) \\| (.+) \\|$")

// TestPRD_TierTableMatchesTheCommandTree: the PRD's tier table names every
// tiered runnable command exactly once, under the tier its own annotation
// carries, and names no command that does not exist. That every command
// carries a tier at all is TestEveryRunnableCommandCarriesATier's rule, not
// this one's; cobra's help and completion carry none.
func TestPRD_TierTableMatchesTheCommandTree(t *testing.T) {
	b, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	sec := prdSection(t, string(b), "### 4.2 ")
	doc := map[string]string{}
	rows := prdTierRowRE.FindAllStringSubmatch(sec, -1)
	if len(rows) != 3 {
		t.Fatalf("§4.2: found %d tier rows, want 3 (safe, mutating, destructive)", len(rows))
	}
	for _, r := range rows {
		for _, m := range codeSpanRE.FindAllStringSubmatch(r[2], -1) {
			if prev, dup := doc[m[1]]; dup {
				t.Errorf("§4.2 lists %q twice (%s and %s)", m[1], prev, r[1])
			}
			doc[m[1]] = r[1]
		}
	}
	code := map[string]string{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			walk(s)
		}
		path := strings.TrimPrefix(c.CommandPath(), "pveforge ")
		if !c.Runnable() || c.HasSubCommands() || !c.HasParent() || path == "help" || path == "completion" || strings.HasPrefix(path, "completion ") {
			return
		}
		code[path] = c.Annotations[mutationAnnotationKey]
	}
	walk(newRootCmd())
	if len(code) < 30 {
		t.Fatalf("walked %d runnable commands: the walk is not seeing the tree", len(code))
	}
	for path, tier := range code {
		switch {
		case tier == "":
			continue // untiered: TestEveryRunnableCommandCarriesATier fails it
		case doc[path] == "":
			t.Errorf("§4.2's tier table does not list %s (%s)", path, tier)
		case doc[path] != tier:
			t.Errorf("§4.2 lists %s as %s, but the command is %s", path, doc[path], tier)
		}
	}
	for path := range doc {
		if _, ok := code[path]; !ok {
			t.Errorf("§4.2 lists %s, which is not a runnable command", path)
		}
	}
}

// TestPRD_SectionsTheCodeCitesExist: every PRD section cited from outside
// it ("PRD §3.4", "prd.md §3.5" in a source comment or another doc) or from
// within it (a bare "§3.4.2") is a heading of the PRD; every "Layer N" it
// names, or that a citation names after §3.5, is one of §3.5's layers; and
// every "§6 item N" is an item of §6. Renumbering cannot strand a reference.
func TestPRD_SectionsTheCodeCitesExist(t *testing.T) {
	b, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	prd := string(b)
	headings := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^#{2,4} ([0-9]+(?:\.[0-9]+)*)\.? `).FindAllStringSubmatch(prd, -1) {
		headings[m[1]] = true
	}
	layers := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\*\*Layer ([0-9]+) —`).FindAllStringSubmatch(prdSection(t, prd, "### 3.5 "), -1) {
		layers[m[1]] = true
	}
	items := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^([0-9]+)\. `).FindAllStringSubmatch(prdSection(t, prd, "## 6. "), -1) {
		items[m[1]] = true
	}
	if len(headings) < 20 || len(layers) != 3 || len(items) < 6 {
		t.Fatalf("found %d headings, %d §3.5 layers and %d §6 items: the scan is not seeing them", len(headings), len(layers), len(items))
	}
	// check holds one text's references to account; it returns how many it
	// found, for anti-vacuity.
	check := func(where, text string, section *regexp.Regexp) int {
		found := 0
		for _, m := range section.FindAllStringSubmatch(text, -1) {
			found++
			if !headings[m[1]] {
				t.Errorf("%s cites §%s, which is not a heading of docs/prd.md", where, m[1])
			}
		}
		for _, m := range regexp.MustCompile(`§3\.5(?:'s)?,? Layer ([0-9]+)`).FindAllStringSubmatch(text, -1) {
			found++
			if !layers[m[1]] {
				t.Errorf("%s cites §3.5 Layer %s, which §3.5 does not have", where, m[1])
			}
		}
		for _, m := range regexp.MustCompile(`§6,? items? ([0-9]+(?:(?:,? and |,? or |, |–|-)[0-9]+)*)`).FindAllStringSubmatch(text, -1) {
			for _, n := range regexp.MustCompile(`[0-9]+`).FindAllString(m[1], -1) {
				found++
				if !items[n] {
					t.Errorf("%s cites §6 item %s, which §6 does not have", where, n)
				}
			}
		}
		return found
	}
	// Outside the PRD only a citation that names it counts: other docs have
	// sections of their own.
	cited := 0
	err = filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "../.." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || path == prdPath || !(strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".sh")) {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cited += check(path, string(src), regexp.MustCompile(`(?:PRD|prd\.md) ?§([0-9]+(?:\.[0-9]+)*)`))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inside it every § is its own, and every "Layer N" is §3.5's.
	own := check("docs/prd.md", prd, regexp.MustCompile(`§([0-9]+(?:\.[0-9]+)*)`))
	for _, m := range regexp.MustCompile(`\bLayer ([0-9]+)`).FindAllStringSubmatch(prd, -1) {
		own++
		if !layers[m[1]] {
			t.Errorf("docs/prd.md names Layer %s, which §3.5 does not have", m[1])
		}
	}
	if cited < 10 || own < 40 {
		t.Errorf("found %d citations outside the PRD and %d references inside it: the scan is not seeing them", cited, own)
	}
}

// prdWordRE is a span's second word that makes it a command span: a
// subcommand name, or a|b alternatives of them. A placeholder (<noun>) or a
// path is not one.
var prdWordRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\|[a-z][a-z0-9-]*)*$`)

// prdCommandSpans finds the PRD's inline code spans that name a command
// without the binary, the way its prose does ("`vm create --unique-tag X`",
// "`roster pin-tls --repin`"): a span whose first word is a top-level
// command and whose second is a flag or a word (a subcommand, which the
// check then requires to exist). A lone word (`vm`, a noun in a table) and
// a placeholder second word (`discover <noun>`) are not command spans.
func prdCommandSpans(text string) []docCommand {
	root := newRootCmd()
	sub := func(c *cobra.Command, name string) *cobra.Command {
		for _, s := range c.Commands() {
			if s.Name() == name {
				return s
			}
		}
		return nil
	}
	var out []docCommand
	fenced := false
	for i, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			continue
		}
		for _, m := range codeSpanRE.FindAllStringSubmatch(l, -1) {
			var args []string
			for _, tok := range shellTokens(m[1]) {
				args = append(args, tok.text)
			}
			if len(args) < 2 || args[0] == "help" || args[0] == "completion" {
				continue
			}
			top := sub(root, args[0])
			if top == nil {
				continue
			}
			if strings.HasPrefix(args[1], "-") || prdWordRE.MatchString(args[1]) {
				out = append(out, docCommand{where: fmt.Sprintf("prd.md:%d", i+1), args: args, span: true})
			}
		}
	}
	return out
}

// TestPRD_CommandSpansMatchTheCommandTree: every command the PRD's prose
// names without the binary is a runnable command, and every flag it gives
// that command exists, by the same check as the operator docs' spans.
func TestPRD_CommandSpansMatchTheCommandTree(t *testing.T) {
	b, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	spans := prdCommandSpans(string(b))
	for _, c := range spans {
		if p := checkDocCommand(c); p != "" {
			t.Error(p)
		}
	}
	if len(spans) < 40 {
		t.Errorf("found %d command spans in docs/prd.md: the scan is not seeing them", len(spans))
	}
	// The finder itself: what it must take and what it must leave alone.
	for doc, want := range map[string]int{
		"`roster validate --require-tls-pins`": 1,
		"`vm snapshot rollback`":               1,
		"`api post|put|delete`":                1,
		"`vm destroy`":                         1,
		"`vm`":                                 0,
		"`discover <noun> <target-id>`":        0,
		"`export = \"token\"`":                 0,
		"```\n`vm set --bogus`\n```":           0,
	} {
		if got := len(prdCommandSpans(doc)); got != want {
			t.Errorf("%q: found %d command spans, want %d", doc, got, want)
		}
	}
	for _, bad := range []string{"`roster validate --require-tls-pin`", "`vm destroy`", "`roster`  `roster pin`"} {
		cs := prdCommandSpans(bad)
		if len(cs) != 1 || checkDocCommand(cs[0]) == "" {
			t.Errorf("%s passed the command-span check", bad)
		}
	}
}

// prdNumber is a number the PRD states in prose and the code defines: every
// place pattern matches in the PRD (whitespace folded, so a line break
// cannot hide one) must state value in units of unit exactly, and there must
// be at least min of them. The comparison is value == stated*unit, never a
// division: a constant that is not a whole number of the PRD's unit (4500
// bytes against "4 KiB", 90 minutes against "1 hour") fails rather than
// rounding to the PRD's old number.
type prdNumber struct {
	name    string
	pattern string
	value   int64
	unit    int64
	min     int
}

// unexportedIntConst reads an untyped integer constant's literal from a
// non-test file of another package, for a number the PRD states whose
// constant that package does not export.
func unexportedIntConst(t *testing.T, path, name string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if n.Name != name || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.INT {
					v, err := strconv.Atoi(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					return v
				}
			}
		}
	}
	t.Fatalf("%s declares no integer literal constant %s", path, name)
	return 0
}

// prdNumbers are the PRD's numbers that the code defines, each matched by
// the exact wording the PRD uses for it, the way the README's exit-status
// table is held: a number that changes in the code fails here until the
// prose says the new one, and a prose number edited alone fails too.
func prdNumbers(t *testing.T) []prdNumber {
	return []prdNumber{
		{"lock.DefaultWait", "`--lock-wait` defaults to ([0-9]+) minutes", int64(lock.DefaultWait), int64(time.Minute), 1},
		{"lock.MaxWait", "capped at ([0-9]+) hours?", int64(lock.MaxWait), int64(time.Hour), 1},
		{"pve.TaskWaitCeiling", "([0-9]+)-minute task ceiling", int64(pve.TaskWaitCeiling), int64(time.Minute), 3},
		{"sshexec.DialTimeout", "dial is lazy and bounded at ([0-9]+)s", int64(sshexec.DialTimeout), int64(time.Second), 1},
		{"sshexec.CommandTimeout", "a command at ([0-9]+)s", int64(sshexec.CommandTimeout), int64(time.Second), 1},
		{"bootstrap.PVEConfigWriteTimeout", "a `pveum` write at ([0-9]+)s", int64(bootstrap.PVEConfigWriteTimeout), int64(time.Second), 1},
		{"sshexec.QMSetTimeout", "a `qm set` at ([0-9]+)s", int64(sshexec.QMSetTimeout), int64(time.Second), 1},
		{"idempotent maxConflictRetries", "up to ([0-9]+) attempts in all", int64(unexportedIntConst(t, "../../internal/idempotent/op.go", "maxConflictRetries")), 1, 1},
		{"maxErrTextBytes", "elided past ([0-9]+) KiB", maxErrTextBytes, 1024, 1},
		{"tlspin.DefaultCapturePort", "`--capture-port`, default ([0-9]+)", tlspin.DefaultCapturePort, 1, 1},
	}
}

// checkPRDNumbers returns what is wrong with text's statement of each
// number.
func checkPRDNumbers(text string, numbers []prdNumber) []string {
	text = strings.Join(strings.Fields(text), " ")
	var problems []string
	for _, n := range numbers {
		ms := regexp.MustCompile(n.pattern).FindAllStringSubmatch(text, -1)
		if len(ms) < n.min {
			problems = append(problems, fmt.Sprintf("docs/prd.md states %s %d times as %q, want at least %d", n.name, len(ms), n.pattern, n.min))
		}
		for _, m := range ms {
			if v, _ := strconv.ParseInt(m[1], 10, 64); v*n.unit != n.value {
				problems = append(problems, fmt.Sprintf("docs/prd.md says %q, but %s is %d (in units of %d: %d, remainder %d)", m[0], n.name, n.value, n.unit, n.value/n.unit, n.value%n.unit))
			}
		}
	}
	return problems
}

// TestPRD_NumbersMatchTheCode: every number in prdNumbers is stated in the
// PRD, and stated as the code has it.
func TestPRD_NumbersMatchTheCode(t *testing.T) {
	b, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	numbers := prdNumbers(t)
	for _, p := range checkPRDNumbers(string(b), numbers) {
		t.Error(p)
	}
	// The checker itself: a changed number, a number split across lines, and
	// a number no longer stated at all.
	one := []prdNumber{{"x", "defaults to ([0-9]+) minutes", int64(15 * time.Minute), int64(time.Minute), 1}}
	if p := checkPRDNumbers("it defaults to\n  15 minutes", one); len(p) != 0 {
		t.Errorf("a number across a line break was refused: %q", p)
	}
	for _, bad := range []string{"it defaults to 20 minutes", "it defaults to 15 minutes, and later defaults to 16 minutes", "no number here"} {
		if p := checkPRDNumbers(bad, one); len(p) != 1 {
			t.Errorf("%q: got %q, want exactly one problem", bad, p)
		}
	}
	// A value that is not a whole number of the stated unit never rounds to
	// the PRD's number.
	ragged := []prdNumber{{"y", "capped at ([0-9]+) hours?", int64(90 * time.Minute), int64(time.Hour), 1}}
	if p := checkPRDNumbers("capped at 1 hour", ragged); len(p) != 1 {
		t.Errorf("90 minutes stated as 1 hour: got %q, want exactly one problem", p)
	}
}
