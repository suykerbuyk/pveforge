package sourceguard

import (
	"fmt"
	"regexp"
	"strings"
)

// A small static analyser for the release scripts (code review C3/G2): it finds
// every COMMAND a shell script runs and checks it against an ALLOW-LIST, instead of
// denying a list of spellings. A push built from a variable (`cmd=git; "$cmd" push`),
// an `eval`, a `bash -c`, a command substitution, a pipeline stage, a trap handler or a
// `find -exec` is a command like any other and is judged the same way; a command word
// that is an expansion is refused unless it names one of the two programs the scripts
// own. It is not a bash parser: it covers the constructs the release scripts use
// (the plants below prove it fails closed on the evasions the reviewers tried).

type shCmd struct {
	line  int
	words []string
}

var shKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true,
	"while": true, "until": true, "!": true, "time": true, "{": true, "}": true, "esac": true,
}

// shTok is one lexical token: a word (raw text, quotes kept) or an operator.
type shTok struct {
	text string
	op   bool
	line int
}

// lexShell splits script into tokens and collects the bodies of command
// substitutions ($(...), <(...), >(...)) and trap strings as nested scripts.
func lexShell(script string, line0 int, nested *[]struct {
	body string
	line int
}) ([]shTok, []string) {
	var toks []shTok
	var problems []string
	rs := []rune(script)
	line := line0
	i := 0
	var cur strings.Builder
	curLine := line
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, shTok{text: cur.String(), line: curLine})
			cur.Reset()
		}
	}
	op := func(s string) {
		flush()
		toks = append(toks, shTok{text: s, op: true, line: line})
	}
	// subst reads a balanced (...) starting after the opening paren at rs[j-1],
	// returns the body and the index after the closing paren
	subst := func(j int) (string, int) {
		depth := 1
		start := j
		for j < len(rs) && depth > 0 {
			switch rs[j] {
			case '(':
				depth++
			case ')':
				depth--
			case '\'':
				j++
				for j < len(rs) && rs[j] != '\'' {
					j++
				}
			case '"':
				j++
				for j < len(rs) && rs[j] != '"' {
					if rs[j] == '\\' {
						j++
					}
					j++
				}
			}
			j++
		}
		return string(rs[start : j-1]), j
	}
	for i < len(rs) {
		c := rs[i]
		if cur.Len() == 0 {
			curLine = line
		}
		switch {
		case c == '\n':
			op("\n")
			line++
			i++
		case c == ' ' || c == '\t':
			flush()
			i++
		case c == '#' && cur.Len() == 0:
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case c == '\\' && i+1 < len(rs) && rs[i+1] == '\n':
			i += 2
			line++
		case c == '\'':
			cur.WriteRune(c)
			i++
			for i < len(rs) && rs[i] != '\'' {
				if rs[i] == '\n' {
					line++
				}
				cur.WriteRune(rs[i])
				i++
			}
			if i < len(rs) {
				cur.WriteRune('\'')
				i++
			}
		case c == '"':
			cur.WriteRune(c)
			i++
			for i < len(rs) && rs[i] != '"' {
				switch {
				case rs[i] == '\\' && i+1 < len(rs):
					cur.WriteRune(rs[i])
					cur.WriteRune(rs[i+1])
					i += 2
				case rs[i] == '$' && i+2 < len(rs) && rs[i+1] == '(' && rs[i+2] == '(':
					// arithmetic expansion: no commands
					j := i + 3
					depth := 2
					for j < len(rs) && depth > 0 {
						if rs[j] == '(' {
							depth++
						} else if rs[j] == ')' {
							depth--
						}
						j++
					}
					cur.WriteString("$((..))")
					i = j
				case rs[i] == '$' && i+1 < len(rs) && rs[i+1] == '(':
					body, j := subst(i + 2)
					*nested = append(*nested, struct {
						body string
						line int
					}{body, line})
					cur.WriteString("$(..)")
					line += strings.Count(body, "\n")
					i = j
				case rs[i] == '`':
					problems = append(problems, fmt.Sprintf("line %d: a backtick command substitution (not analysed: use $(...))", line))
					i++
				default:
					if rs[i] == '\n' {
						line++
					}
					cur.WriteRune(rs[i])
					i++
				}
			}
			if i < len(rs) {
				cur.WriteRune('"')
				i++
			}
		case c == '`':
			problems = append(problems, fmt.Sprintf("line %d: a backtick command substitution (not analysed: use $(...))", line))
			i++
		case c == '$' && i+1 < len(rs) && rs[i+1] == '{':
			// a parameter expansion is one word part, spaces and all
			j := i + 2
			cur.WriteString("${")
			for j < len(rs) && rs[j] != '}' {
				cur.WriteRune(rs[j])
				j++
			}
			cur.WriteRune('}')
			i = j + 1
		case c == '$' && i+2 < len(rs) && rs[i+1] == '(' && rs[i+2] == '(':
			j := i + 3
			depth := 2
			for j < len(rs) && depth > 0 {
				if rs[j] == '(' {
					depth++
				} else if rs[j] == ')' {
					depth--
				}
				j++
			}
			cur.WriteString("$((..))")
			i = j
		case c == '$' && i+1 < len(rs) && rs[i+1] == '(':
			body, j := subst(i + 2)
			*nested = append(*nested, struct {
				body string
				line int
			}{body, line})
			cur.WriteString("$(..)")
			line += strings.Count(body, "\n")
			i = j
		case (c == '<' || c == '>') && i+1 < len(rs) && rs[i+1] == '(':
			body, j := subst(i + 2)
			*nested = append(*nested, struct {
				body string
				line int
			}{body, line})
			flush()
			toks = append(toks, shTok{text: string(c) + "(..)", line: line})
			i = j
		case c == '=' && cur.Len() > 0 && i+1 < len(rs) && rs[i+1] == '(':
			// an array assignment: the literal is part of the word
			cur.WriteRune('=')
			j := i + 2
			depth := 1
			cur.WriteRune('(')
			for j < len(rs) && depth > 0 {
				if rs[j] == '(' {
					depth++
				} else if rs[j] == ')' {
					depth--
				} else if rs[j] == '\n' {
					line++
				}
				cur.WriteRune(rs[j])
				j++
			}
			i = j
		case c == ';' || c == '|' || c == '&' || c == '(' || c == ')':
			s := string(c)
			if i+1 < len(rs) && (rs[i+1] == c) && (c == ';' || c == '|' || c == '&') {
				s += string(c)
				i++
			}
			// `>&2` and `2>&1`: an & inside a redirection is not a separator
			if c == '&' && cur.Len() > 0 && strings.HasSuffix(cur.String(), ">") {
				cur.WriteRune('&')
				i++
				continue
			}
			if c == '&' && len(toks) > 0 && toks[len(toks)-1].text != "" && (toks[len(toks)-1].text == ">" || toks[len(toks)-1].text == "<") && cur.Len() == 0 {
				cur.WriteRune('&')
				i++
				continue
			}
			op(s)
			i++
		case c == '<' || c == '>':
			// an fd number before a redirection (2>&1) is part of the redirection, not a word
			if s := cur.String(); s != "" && strings.Trim(s, "0123456789") == "" {
				cur.Reset()
			}
			flush()
			s := string(c)
			for i+1 < len(rs) && rs[i+1] == c && len(s) < 3 {
				s += string(c)
				i++
			}
			toks = append(toks, shTok{text: s, op: true, line: line})
			i++
		default:
			cur.WriteRune(c)
			i++
		}
	}
	flush()
	return toks, problems
}

func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j, r := range w[:i] {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (j > 0 && r >= '0' && r <= '9')) {
			return !(j == i-1 && r == '+')
		}
	}
	return true
}

// shellCommands returns every command in script (each with its words), recursing
// into command substitutions and trap strings, and any construct it refuses.
func shellCommands(script string) (cmds []shCmd, problems []string) {
	var nested []struct {
		body string
		line int
	}
	toks, probs := lexShell(script, 1, &nested)
	problems = append(problems, probs...)
	cmdPos := true
	inTest := "" // "]" or "]]"
	skipTo := "" // for/case: skip words until this
	inCase := false
	var cur []string
	curLine := 0
	finish := func() {
		if len(cur) > 0 {
			cmds = append(cmds, shCmd{line: curLine, words: cur})
		}
		cur, cmdPos, inTest = nil, true, ""
		if skipTo != "case-pattern" && skipTo != "case-in" {
			skipTo = ""
		}
	}
	funcNames := map[string]bool{}
	for k := 0; k < len(toks); k++ {
		tk := toks[k]
		if tk.op {
			switch tk.text {
			case "\n", ";", "&&", "||", "|", "&", ";;":
				if inTest != "" && (tk.text == "&&" || tk.text == "||") && inTest == "]]" {
					continue
				}
				if skipTo == "case-in" || (skipTo == "case-pattern" && tk.text == "\n") {
					continue
				}
				finish()
				if tk.text == ";;" && inCase {
					skipTo = "case-pattern"
				}
			case "(", ")":
				if tk.text == ")" && skipTo == "case-pattern" {
					skipTo = ""
					cur, cmdPos = nil, true
					continue
				}
				if tk.text == "(" && k+1 < len(toks) && toks[k+1].text == ")" && len(cur) == 1 {
					// name() { ... }
					funcNames[cur[0]] = true
					cur, cmdPos = nil, true
					k++
					continue
				}
				finish()
			case "<", ">", ">>", "<<", "<<<":
				// a redirection: the next word is a target, not a command
				if k+1 < len(toks) && !toks[k+1].op {
					k++
				}
			}
			continue
		}
		w := tk.text
		if strings.HasPrefix(w, ">") || strings.HasPrefix(w, "<") || strings.HasPrefix(w, "2>") || strings.HasPrefix(w, "1>") {
			continue
		}
		if skipTo == "case-pattern" {
			if w == "esac" {
				skipTo, inCase = "", false
				cmdPos = true
			}
			continue
		}
		if skipTo == "case-in" {
			if w == "in" {
				skipTo = "case-pattern"
			}
			continue
		}
		if skipTo == "do" {
			if w == "do" {
				skipTo = ""
				cmdPos = true
			}
			continue
		}
		if inTest != "" {
			if w == inTest {
				inTest = ""
			}
			cur = append(cur, w)
			continue
		}
		if cmdPos {
			if shKeywords[w] {
				if w == "esac" || w == "fi" || w == "done" {
					finish()
				}
				continue
			}
			if w == "for" {
				skipTo = "do"
				continue
			}
			if w == "case" {
				skipTo, inCase = "case-in", true
				continue
			}
			if isAssignment(w) {
				continue
			}
			curLine = tk.line
			cur = []string{w}
			cmdPos = false
			if w == "[[" {
				inTest = "]]"
			} else if w == "[" {
				inTest = "]"
			}
			continue
		}
		cur = append(cur, w)
	}
	finish()
	for _, n := range nested {
		c2, p2 := shellCommands(n.body)
		for _, c := range c2 {
			c.line += n.line - 1
			cmds = append(cmds, c)
		}
		problems = append(problems, p2...)
	}
	// trap strings are code
	for _, c := range append([]shCmd(nil), cmds...) {
		if len(c.words) >= 2 && c.words[0] == "trap" {
			arg := strings.Trim(c.words[1], `'"`)
			if arg != "" {
				c2, p2 := shellCommands(arg)
				cmds = append(cmds, c2...)
				problems = append(problems, p2...)
			}
		}
	}
	for name := range funcNames {
		cmds = append(cmds, shCmd{words: []string{"\x00func", name}})
	}
	return cmds, problems
}

// ---- the allow-list -----------------------------------------------------------

type shPolicy struct {
	externals map[string]bool // programs the script may run
	builtins  map[string]bool // shell builtins
	variables map[string]bool // command words that are expansions but allowed (the programs the scripts own)
	gitSub    map[string]bool // git subcommands
	goSub     map[string]bool // go subcommands
	paths     []string        // command-word suffixes allowed (the scripts' own helpers)
}

var releaseScriptPolicy = shPolicy{
	externals: setOf("go", "git", "tar", "gzip", "sha256sum", "awk", "sort", "mktemp", "find", "install", "grep", "sed", "tr", "ls", "cmp", "head", "cat", "mkdir", "mv", "rm", "chmod", "env", "dirname", "printf", "echo"),
	builtins:  setOf("cd", "read", "exit", "return", "shift", "set", "export", "unset", "trap", "command", "type", "true", "false", ":", "test", "[", "[[", "local", "declare", "wait", "pwd", "umask", "continue", "break"),
	variables: setOf(`"$STAGE/pveforge"`, `"$B/pveforge"`, `"$ROOT/hack/release/licenses.sh"`),
	gitSub:    setOf("rev-parse", "log", "status", "clone", "checkout", "archive", "tag"),
	goSub:     setOf("build", "list", "env", "version"),
}

var makefileReleasePolicy = shPolicy{
	externals: setOf("go"),
	builtins:  setOf(),
	variables: setOf(),
	gitSub:    setOf(),
	goSub:     setOf("test"),
	paths:     []string{"hack/release/release.sh", "hack/release/verify.sh"},
}

func setOf(s ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}

func unquote(w string) string { return strings.Trim(w, `'"`) }

// checkCommands returns every command that the policy does not allow.
func (p shPolicy) check(script string) []string {
	cmds, problems := shellCommands(script)
	funcs := map[string]bool{}
	for _, c := range cmds {
		if len(c.words) == 2 && c.words[0] == "\x00func" {
			funcs[c.words[1]] = true
		}
	}
	var bad []string
	bad = append(bad, problems...)
	for _, c := range cmds {
		if c.words[0] == "\x00func" {
			continue
		}
		bad = append(bad, p.checkOne(c.line, c.words, funcs)...)
	}
	return bad
}

func (p shPolicy) checkOne(line int, words []string, funcs map[string]bool) []string {
	at := func(f string, a ...any) []string {
		return []string{fmt.Sprintf("line %d: ", line) + fmt.Sprintf(f, a...)}
	}
	w := words[0]
	// DELEGATION (fix round 2): a prefix that runs another command is never allowed
	// unchecked. `command` is allowed ONLY as `command -v <name>` (a lookup, which is
	// the scripts' use); every other delegator is refused outright (an allow-listed
	// program must be invoked directly so its own subcommand rules apply). `env` and
	// `find -exec` are handled below by checking the delegated command.
	if unquote(w) == "command" {
		if len(words) == 3 && words[1] == "-v" {
			return nil
		}
		return at("command runs another command: only `command -v <name>` is allowed (got %s)", strings.Join(words, " "))
	}
	if shDelegators[unquote(w)] {
		return at("%s runs another command (delegation): invoke the program directly", unquote(w))
	}
	if p.variables[w] || funcs[w] || p.builtins[w] {
		return nil
	}
	for _, suf := range p.paths {
		if w == suf || w == `"`+suf+`"` {
			return nil
		}
	}
	if strings.ContainsAny(w, "$`") {
		return at("%s: a command word built from an expansion (an indirect invocation)", w)
	}
	name := unquote(w)
	if !p.externals[name] {
		return at("%q is not an allowed command", name)
	}
	rest := words[1:]
	switch name {
	case "env":
		// skip assignments, options and the quoted array expansion; the next word is the command
		i := 0
		for i < len(rest) && (isAssignment(unquote(rest[i])) || strings.HasPrefix(rest[i], "-") || strings.HasPrefix(rest[i], `"${`) || strings.HasPrefix(rest[i], `"$@`)) {
			i++
		}
		if i >= len(rest) {
			return nil
		}
		return p.checkOne(line, rest[i:], funcs)
	case "git":
		i := 0
		for i < len(rest) && (rest[i] == "-C" || rest[i] == "-c") {
			i += 2
		}
		if i >= len(rest) {
			return at("git with no subcommand")
		}
		sub := unquote(rest[i])
		if !p.gitSub[sub] {
			return at("git %s is not allowed", sub)
		}
		if sub == "tag" {
			after := strings.Join(rest[i+1:], " ")
			if !(strings.HasPrefix(after, "--points-at") || strings.HasPrefix(after, "--list") || strings.HasPrefix(after, "-l ") || after == "-l") {
				return at("git tag may only list (--points-at, --list, -l)")
			}
		}
	case "go":
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i], "-") {
			i++
		}
		if i >= len(rest) {
			return at("go with no subcommand")
		}
		if sub := unquote(rest[i]); !p.goSub[sub] {
			return at("go %s is not allowed", sub)
		}
	case "awk":
		return at0(line, awkRisk(rest))
	case "sed":
		return at0(line, sedRisk(rest))
	case "find":
		for i, a := range rest {
			if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
				if i+1 >= len(rest) {
					return at("find %s with no command", a)
				}
				return p.checkOne(line, rest[i+1:], funcs)
			}
		}
	}
	return nil
}

// shDelegators are programs and builtins whose job is to run another command.
var shDelegators = setOf("exec", "builtin", "xargs", "nohup", "nice", "timeout", "stdbuf", "setsid", "ionice", "sudo", "su", "doas", "watch", "strace", "chroot", "busybox", "parallel", "script", "unbuffer", "eval", "source", ".", "bash", "sh", "zsh", "dash", "ksh")

func at0(line int, msg string) []string {
	if msg == "" {
		return nil
	}
	return []string{fmt.Sprintf("line %d: %s", line, msg)}
}

var awkPipeRE = regexp.MustCompile(`print[f]?\b[^;}\n]*\|`)

// awkRisk returns a reason when an awk invocation can run a command: a program that
// calls system(), pipes to or from a command (print | "cmd", "cmd" | getline, |&), uses
// getline at all (a file or command read the scripts do not need), or is read from a
// file (-f, not inspectable). The -F separator and -v assignments are values, not code.
func awkRisk(args []string) string {
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		raw := unquote(a)
		switch {
		case a == "-v" || a == "-F":
			skip = true
			continue
		case strings.HasPrefix(raw, "-F") || strings.HasPrefix(raw, "-v"):
			continue
		case raw == "-f" || strings.HasPrefix(raw, "-f") || raw == "--file":
			return "awk -f reads its program from a file the pin cannot inspect"
		case strings.HasPrefix(raw, "-"):
			continue
		}
		prog := a
		switch {
		case strings.Contains(prog, "system("):
			return "an awk program calls system()"
		case strings.Contains(prog, "getline"):
			return "an awk program uses getline (a command or file read)"
		case strings.Contains(prog, "|&"):
			return "an awk program uses a coprocess (|&)"
		case awkPipeRE.MatchString(prog):
			return "an awk program pipes print to a command"
		}
	}
	return ""
}

// sedRisk returns a reason when a sed script can run a command or write a file: the e
// command, the e flag of s, and w / W (as a command or an s flag). The scripts use only
// s///, with no such flag.
func sedRisk(args []string) string {
	var scripts []string
	explicit := false
	for i := 0; i < len(args); i++ {
		raw := unquote(args[i])
		switch {
		case raw == "-e" || raw == "--expression":
			explicit = true
			if i+1 < len(args) {
				i++
				scripts = append(scripts, args[i])
			}
		case raw == "-f" || strings.HasPrefix(raw, "-f") || raw == "--file":
			return "sed -f reads its script from a file the pin cannot inspect"
		case strings.HasPrefix(raw, "-") && len(raw) > 1:
			if strings.Contains(raw, "i") && !strings.HasPrefix(raw, "--") {
				continue
			}
		default:
			if !explicit {
				scripts = append(scripts, args[i])
				explicit = true // the first non-option word is the script; later ones are files
			}
		}
	}
	for _, s := range scripts {
		if r := sedScriptRisk(unquote(s)); r != "" {
			return r
		}
	}
	return ""
}

func sedScriptRisk(s string) string {
	rs := []rune(s)
	i := 0
	for i < len(rs) {
		// command position: skip separators and blanks
		for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t' || rs[i] == '\n' || rs[i] == ';' || rs[i] == '{' || rs[i] == '}') {
			i++
		}
		// an address: digits, $, /regex/, \cregexc, commas, steps, !
		for i < len(rs) {
			switch {
			case rs[i] >= '0' && rs[i] <= '9' || rs[i] == '$' || rs[i] == ',' || rs[i] == '~' || rs[i] == '!' || rs[i] == '+':
				i++
				continue
			case rs[i] == '/':
				i++
				for i < len(rs) && rs[i] != '/' {
					if rs[i] == '\\' {
						i++
					}
					i++
				}
				i++
				continue
			}
			break
		}
		for i < len(rs) && rs[i] == ' ' {
			i++
		}
		if i >= len(rs) {
			break
		}
		c := rs[i]
		i++
		switch c {
		case 'e':
			return "a sed script uses the e command (it runs a command)"
		case 'w', 'W':
			return "a sed script uses w/W (it writes a file)"
		case 's':
			if i >= len(rs) {
				return ""
			}
			d := rs[i]
			i++
			for part := 0; part < 2; part++ {
				for i < len(rs) && rs[i] != d {
					if rs[i] == '\\' {
						i++
					}
					i++
				}
				i++
			}
			for i < len(rs) && rs[i] != ';' && rs[i] != '\n' && rs[i] != '}' {
				if rs[i] == 'e' {
					return "a sed s command has the e flag (it runs the result as a command)"
				}
				if rs[i] == 'w' || rs[i] == 'W' {
					return "a sed s command has the w flag (it writes a file)"
				}
				i++
			}
		case 'y':
			if i < len(rs) {
				d := rs[i]
				i++
				for part := 0; part < 2; part++ {
					for i < len(rs) && rs[i] != d {
						i++
					}
					i++
				}
			}
		default:
			for i < len(rs) && rs[i] != ';' && rs[i] != '\n' {
				i++
			}
		}
	}
	return ""
}
