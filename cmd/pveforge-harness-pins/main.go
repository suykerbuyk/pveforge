// Command pveforge-harness-pins prints what a roster holds for one target:
// the host it dials and the SSH host key pinned for it
// (pveforge-harness-golden-reset, P2). hack/harness/nested.sh uses it to
// hold the nested harness roster to build.sh's pins: before a bootstrap (a
// target already in the roster must name the configured address and pin),
// and after one, whether it passed or failed.
//
// Usage: pveforge-harness-pins <roster> <target-id>
//
// It reads the roster with pveforge's own loader and needs no passphrase:
// neither field is encrypted. Output, one line: "<host> <fingerprint>", the
// fingerprint "-" when no SSH login is recorded. Exit status: 0 printed, 1
// the roster cannot be read or holds a value that is not one plain word, 2 a
// usage error, 3 the roster holds no such target.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] == "" || args[1] == "" {
		fmt.Fprintln(stderr, "usage: pveforge-harness-pins <roster> <target-id>")
		return 2
	}
	r, err := roster.Load(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "pveforge-harness-pins: %v\n", err)
		return 1
	}
	t := r.Find(args[1])
	if t == nil {
		fmt.Fprintf(stderr, "pveforge-harness-pins: %s holds no target %q\n", args[0], args[1])
		return 3
	}
	fp := "-"
	if t.SSH != nil && t.SSH.HostKeyFingerprint != "" {
		fp = t.SSH.HostKeyFingerprint
	}
	for _, v := range []string{t.Host, fp} {
		if !plainWord(v) {
			fmt.Fprintf(stderr, "pveforge-harness-pins: target %q holds %q, not one plain word\n", args[1], v)
			return 1
		}
	}
	fmt.Fprintf(stdout, "%s %s\n", t.Host, fp)
	return 0
}

// plainWord: non-empty, printable, no space.
func plainWord(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsGraphic(r) || unicode.IsSpace(r) })
}
