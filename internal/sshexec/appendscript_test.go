package sshexec

import (
	"strings"
	"testing"
)

// Test 8: install's append, executed with sh. A file without a final
// newline gets one before the append, so the previous line stays intact
// and ours is a whole line (a whole-line match can find it again). A run
// that finds the line already present never writes the file, which on PVE
// is the cluster's shared one, even when it has no final newline.
func TestAppendScript_NewlineGuard(t *testing.T) {
	script := buildIdempotentAppendScript(ourLine)
	for name, tc := range map[string]struct {
		body, out, want string
	}{
		"no final newline":                  {operator, "added", operator + "\n" + ourLine + "\n"},
		"a final newline":                   {operator + "\n", "added", operator + "\n" + ourLine + "\n"},
		"an empty file":                     {"", "added", ourLine + "\n"},
		"a final CR":                        {operator + "\r", "added", operator + "\r\n" + ourLine + "\n"},
		"key present, no final newline":     {operator + "\n" + ourLine, "present", operator + "\n" + ourLine},
		"key present, with a final newline": {ourLine + "\n" + operator + "\n", "present", ourLine + "\n" + operator + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newKeyWorld(t, tc.body)
			out, code := w.run(t, "sh", script, "")
			if code != 0 || strings.TrimSpace(out) != tc.out {
				t.Fatalf("exit %d, out %q; want %q", code, out, tc.out)
			}
			if got := w.body(t); got != tc.want {
				t.Errorf("file after %q, want %q", got, tc.want)
			}
			w.assertSymlink(t)
		})
	}
}
