package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const armored = "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n"

// nestedRoster: pvh-n1 bootstrapped (an SSH login recorded), pvh-n2 a stub.
func nestedRoster(n1Host, n1Pin string) string {
	return `[[targets]]
id = "pvh-n1"
host = "` + n1Host + `"
node = "pvh-n1"

  [targets.ssh]
  user = "root"
  host_key_fingerprint = "` + n1Pin + `"
  private_key_enc = """
` + armored + `"""

[[targets]]
id = "pvh-n2"
host = "192.0.2.91"
node = "pvh-n2"
`
}

func runPins(t *testing.T, roster string, args ...string) (int, string, string) {
	t.Helper()
	if roster != "" {
		p := filepath.Join(t.TempDir(), "harness-nested.toml")
		if err := os.WriteFile(p, []byte(roster), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append([]string{p}, args...)
	}
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun(t *testing.T) {
	const pin = "SHA256:fnRRof4+Lbegj+qqBH26z1CYnexXFG2ZnLjo8AY7ZdA"
	for _, c := range []struct {
		name, roster string
		args         []string
		code         int
		out, err     string
	}{
		{"a recorded login", nestedRoster("192.0.2.90", pin), []string{"pvh-n1"}, 0, "192.0.2.90 " + pin + "\n", ""},
		{"no login yet", nestedRoster("192.0.2.90", pin), []string{"pvh-n2"}, 0, "192.0.2.91 -\n", ""},
		{"no such target", nestedRoster("192.0.2.90", pin), []string{"pvh-n3"}, 3, "", `holds no target "pvh-n3"`},
		{"a host with a space", nestedRoster("192.0.2.90 x", pin), []string{"pvh-n1"}, 1, "", "not one plain word"},
		{"a pin with a newline", nestedRoster("192.0.2.90", `SHA256:a\nb`), []string{"pvh-n1"}, 1, "", "not one plain word"},
		{"not a roster", "this is = not toml [", []string{"pvh-n1"}, 1, "", "parse roster"},
		{"an unknown key", nestedRoster("192.0.2.90", pin) + "extra = 1\n", []string{"pvh-n1"}, 1, "", "parse roster"},
		{"no roster file", "", []string{"/nonexistent/harness-nested.toml", "pvh-n1"}, 1, "", "read roster"},
		{"one argument", "", []string{"x"}, 2, "", "usage"},
		{"three arguments", "", []string{"x", "y", "z"}, 2, "", "usage"},
		{"an empty target", "", []string{"x", ""}, 2, "", "usage"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := runPins(t, c.roster, c.args...)
			if code != c.code || out != c.out || !strings.Contains(errOut, c.err) {
				t.Errorf("exit %d, stdout %q, stderr %q; want %d, %q, %q", code, out, errOut, c.code, c.out, c.err)
			}
		})
	}
}
