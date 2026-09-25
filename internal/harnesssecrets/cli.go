package harnesssecrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/term"
)

const usageText = `usage: pveforge-harness-secrets --dir <hack/harness> <command>

  run [--] <cmd> [args…]  decrypt secrets.age and exec <cmd> with the values
                          in its environment (never on disk or in argv)
  seal                    encrypt a new env file, read from stdin (or
                          prompted for with no echo on a terminal), to every
                          recipient in recipients.txt
  reseal                  decrypt secrets.age and re-encrypt it to the
                          current recipients.txt (after adding or removing one)
  status                  recipients, and the variable NAMES in secrets.age
                          when an identity is set; never a value

The identity comes from exactly one of ` + IdentityFileVar + ` (a file,
mode 0600 or 0400) and ` + IdentityVar + ` (its content).
`

// Seams for tests.
var (
	execve     = syscall.Exec
	isTerminal = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
	readSecret = func(f *os.File) ([]byte, error) { return term.ReadPassword(int(f.Fd())) }
)

// Main runs the tool and returns its exit status: 0 on success, 1 on a
// refusal or failure, 2 on a usage error. run does not return on success.
func Main(args, environ []string, stdin *os.File, stdout, stderr io.Writer) int {
	err := dispatch(args, environ, stdin, stdout, stderr)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprint(stderr, usageText)
		return 2
	default:
		fmt.Fprintf(stderr, "pveforge-harness-secrets: %v\n", err)
		return 1
	}
}

func dispatch(args, environ []string, stdin *os.File, stdout, stderr io.Writer) error {
	if len(args) < 3 || args[0] != "--dir" || args[1] == "" {
		return errUsage
	}
	d := files{dir: args[1]}
	cmd, rest := args[2], args[3:]
	switch cmd {
	case "run":
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return errUsage
		}
		return run(d, environ, rest)
	case "seal":
		if len(rest) != 0 {
			return errUsage
		}
		return sealCmd(d, stdin, stderr, stdout)
	case "reseal":
		if len(rest) != 0 {
			return errUsage
		}
		return resealCmd(d, environ, stdout)
	case "status":
		if len(rest) != 0 {
			return errUsage
		}
		return statusCmd(d, environ, stdout)
	}
	return errUsage
}

type files struct{ dir string }

func (f files) secrets() string    { return f.dir + "/secrets.age" }
func (f files) recipients() string { return f.dir + "/recipients.txt" }

func (f files) readRecipients() ([]Recipient, error) {
	b, err := readBounded(f.recipients(), maxCiphertext)
	if err != nil {
		return nil, fmt.Errorf("read recipients: %w", err)
	}
	return ParseRecipients(b)
}

func (f files) readSecrets(environ []string) ([]Pair, error) {
	ids, err := LoadIdentities(environ)
	if err != nil {
		return nil, err
	}
	blob, err := readBounded(f.secrets(), maxCiphertext)
	if err != nil {
		return nil, fmt.Errorf("read secrets: %w", err)
	}
	return open(blob, ids)
}

// run decrypts the secrets and replaces this process with argv, its
// environment the current one minus both identity variables and the
// variables that run code in a bash child (ChildEnv), plus the secrets. A secret whose name is already set is refused rather than
// overridden: PVEFORGE_PVE_PASSWORD-style name reuse must never silently
// mix two credentials.
func run(f files, environ, argv []string) error {
	pairs, err := f.readSecrets(environ)
	if err != nil {
		return err
	}
	env, err := ChildEnv(environ, pairs)
	if err != nil {
		return err
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	return fmt.Errorf("run: exec %s: %w", path, execve(path, argv, env))
}

// ChildEnv is the environment run gives its child: environ without the
// identity variables and without the variables through which the
// environment runs code in a bash child (shellCodeVar), plus pairs. A pair
// whose name is already set in environ is refused.
func ChildEnv(environ []string, pairs []Pair) ([]string, error) {
	out := make([]string, 0, len(environ)+len(pairs))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == IdentityFileVar || name == IdentityVar || shellCodeVar(name) {
			continue
		}
		for _, p := range pairs {
			if p.Name == name {
				return nil, fmt.Errorf("run: %s is already set in the environment; unset it first (the secrets never override a value)", name)
			}
		}
		out = append(out, kv)
	}
	for _, p := range pairs {
		out = append(out, p.Name+"="+p.Value)
	}
	return out, nil
}

// shellCodeVar reports whether name is a variable through which the
// environment runs code in, or changes, a bash child before its first line
// can check anything: an exported function (BASH_FUNC_<name>%%, which bash
// imports under ANY name, declare and unset included, so no in-script check
// survives one), shell options (SHELLOPTS, BASHOPTS: xtrace would print a
// secret the moment a script reads it), a startup file (BASH_ENV, ENV), and
// xtrace's prompt (PS4, whose expansions run commands). run drops them all;
// every other variable (PATH, HOME, PVEFORGE_BIN, ...) passes unchanged.
func shellCodeVar(name string) bool {
	switch name {
	case "SHELLOPTS", "BASHOPTS", "BASH_ENV", "ENV", "PS4":
		return true
	}
	return strings.HasPrefix(name, "BASH_FUNC_")
}

func sealCmd(f files, stdin *os.File, prompt, stdout io.Writer) error {
	recipients, err := f.readRecipients()
	if err != nil {
		return err
	}
	var plain []byte
	if isTerminal(stdin) {
		if plain, err = promptEnv(stdin, prompt); err != nil {
			return err
		}
	} else if plain, err = io.ReadAll(io.LimitReader(stdin, maxPlaintext+1)); err != nil {
		return fmt.Errorf("seal: read stdin: %w", err)
	}
	pairs, err := ParseEnv(plain)
	if err != nil {
		return err
	}
	return writeSealed(f, pairs, recipients, stdout, "sealed")
}

func resealCmd(f files, environ []string, stdout io.Writer) error {
	recipients, err := f.readRecipients()
	if err != nil {
		return err
	}
	pairs, err := f.readSecrets(environ)
	if err != nil {
		return err
	}
	return writeSealed(f, pairs, recipients, stdout, "resealed")
}

func writeSealed(f files, pairs []Pair, recipients []Recipient, stdout io.Writer, verb string) error {
	blob, err := seal(pairs, recipients)
	if err != nil {
		return err
	}
	if err := writeAtomic(f.secrets(), blob); err != nil {
		return fmt.Errorf("write secrets: %w", err)
	}
	fmt.Fprintf(stdout, "%s %s to %d recipient(s): %s\n", verb, names(pairs), len(recipients), consumers(recipients))
	return nil
}

// promptEnv asks for each allowed name with no echo, twice; an empty answer
// leaves that name out.
func promptEnv(stdin *os.File, prompt io.Writer) ([]byte, error) {
	var b bytes.Buffer
	for _, name := range AllowedNames {
		fmt.Fprintf(prompt, "%s (empty to leave out): ", name)
		v1, err := readSecret(stdin)
		fmt.Fprintln(prompt)
		if err != nil {
			return nil, fmt.Errorf("seal: read %s: %w", name, err)
		}
		if len(v1) == 0 {
			continue
		}
		fmt.Fprintf(prompt, "%s again: ", name)
		v2, err := readSecret(stdin)
		fmt.Fprintln(prompt)
		if err != nil {
			return nil, fmt.Errorf("seal: read %s: %w", name, err)
		}
		if !bytes.Equal(v1, v2) {
			return nil, fmt.Errorf("seal: the two entries of %s differ", name)
		}
		b.WriteString(name + "=")
		b.Write(v1)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func statusCmd(f files, environ []string, stdout io.Writer) error {
	recipients, err := f.readRecipients()
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "recipients: %d (%s)\n", len(recipients), consumers(recipients))
	_, fileSet := lookup(environ, IdentityFileVar)
	_, contentSet := lookup(environ, IdentityVar)
	if !fileSet && !contentSet {
		fmt.Fprintln(stdout, "names: not shown (no identity set)")
		return nil
	}
	pairs, err := f.readSecrets(environ)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "names: %s\n", names(pairs))
	return nil
}

func names(pairs []Pair) string {
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.Name
	}
	return strings.Join(out, ", ")
}

func consumers(rs []Recipient) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return strings.Join(out, ", ")
}
