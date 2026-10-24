//go:build unix

package sshexec

import (
	"bufio"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Test 6: a signal mid-run. The program is paused between the sibling
// mktemp and the rename (an mv shim that blocks on a fifo), then its whole
// process group gets the signal, as sshexec's hangup of an abandoned
// session delivers it. dash runs no EXIT trap when it is killed: without
// the HUP INT TERM trap, authorized_keys.tmp.* would be left beside the
// target (on PVE in /etc/pve/priv, replicated to every node) and the
// snapshot in TMPDIR.
func TestRemoveKey_SignalMidRunLeavesNothing(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"HUP": syscall.SIGHUP, "TERM": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) {
			both(t, ourLine, func(t *testing.T, shell, script string) {
				w := newKeyWorld(t, linesBody(operator, ourLine))
				before := w.body(t)
				ready := filepath.Join(t.TempDir(), "ready")
				gate := filepath.Join(t.TempDir(), "gate")
				for _, p := range []string{ready, gate} {
					if err := syscall.Mkfifo(p, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				// The shim never renames: it says it is paused, then blocks
				// until the signal ends it.
				shims := shimDir(t, map[string]string{"mv": "echo paused > " + ready + "\nread x < " + gate + "\nexit 1"})
				cmd := w.cmdFor(shell, script, shims)
				cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				paused := make(chan string, 1)
				go func() {
					f, err := os.Open(ready) // blocks until the shim opens it
					if err != nil {
						paused <- err.Error()
						return
					}
					line, _ := bufio.NewReader(f).ReadString('\n')
					_ = f.Close()
					paused <- line
				}()
				select {
				case line := <-paused:
					if line != "paused\n" {
						t.Fatalf("the shim said %q", line)
					}
				case err := <-done:
					t.Fatalf("the program ended (%v) before it reached the rename", err)
				case <-time.After(10 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					t.Fatal("the program never reached the rename")
				}
				if entries, _ := os.ReadDir(w.priv); len(entries) != 2 {
					t.Fatalf("paused before the rename, the priv directory holds %d entries, want the target and the new file", len(entries))
				}
				if err := syscall.Kill(-cmd.Process.Pid, sig); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("exit 0 after the signal")
					}
				case <-time.After(10 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					t.Fatal("still running 10s after the signal")
				}
				// The whole group, not only the shell waited on: the manual
				// command's own sh, a child of the pasted line's shell, runs
				// its traps after that shell has gone.
				for deadline := time.Now().Add(10 * time.Second); syscall.Kill(-cmd.Process.Pid, 0) == nil; {
					if time.Now().After(deadline) {
						_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
						t.Fatal("the process group still runs 10s after the signal")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if w.body(t) != before {
					t.Error("the target changed")
				}
				w.assertSymlink(t)
				w.assertNoLeftovers(t)
			})
		})
	}
}
