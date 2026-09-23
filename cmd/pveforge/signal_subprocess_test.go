package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// cliChildEnv, when set, makes this test binary run as pveforge itself
// (TestMain dispatches to runCLIChild): the real-signal tests below start it
// as a child and signal it.
const cliChildEnv = "PVEFORGE_TEST_CLI_CHILD"

// cliChildSpec is what a child runs: the pveforge arguments, or (Hang) the
// test-only hang command against Roster.
type cliChildSpec struct {
	Args   []string
	Hang   bool
	Roster string
}

// hangKey is the object the hang command locks.
var hangKey = lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

// runCLIChild runs one child. Args run exactly as the shipped binary does,
// through realMain. The hang command is built the same way — root context
// from notifyInterrupt, report through runRoot — but adds one test-only
// subcommand, since no real command can be made to ignore its context on
// demand without an SSH-backed path.
func runCLIChild(raw string) int {
	var spec cliChildSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		fmt.Fprintln(os.Stderr, "bad child spec:", err)
		return 2
	}
	if !spec.Hang {
		os.Args = append([]string{"pveforge"}, spec.Args...)
		return realMain()
	}
	root := newRootCmd()
	root.AddCommand(newHangCmd(spec.Roster))
	root.SetArgs([]string{"test-hang"})
	root.SetContext(notifyInterrupt(context.Background()))
	return runRoot(root, os.Stderr)
}

// newHangCmd stands in for a command whose work outlives the first signal —
// a detached cleanup such as a network stage revert. It takes hangKey's
// lock with the command's context, says "held", says "interrupted" once the
// context is cancelled (which notifyInterrupt does only AFTER it has
// stopped catching signals), and then keeps holding the lock regardless.
func newHangCmd(rosterPath string) *cobra.Command {
	return &cobra.Command{
		Use: "test-hang",
		RunE: func(cmd *cobra.Command, args []string) error {
			unlock, err := lock.Mutation(cmd.Context(), rosterPath, hangKey)
			if err != nil {
				return err
			}
			defer func() { _ = unlock() }()
			fmt.Println("held")
			go func() {
				<-cmd.Context().Done()
				fmt.Println("interrupted")
			}()
			time.Sleep(time.Minute) // ignores the context, as a detached cleanup does
			return nil
		},
	}
}

// cliChild is a started child with its stdout lines and captured stderr.
type cliChild struct {
	cmd    *exec.Cmd
	lines  chan string
	stderr *syncBuffer
	exited chan struct{}
}

// startCLIChild re-executes this test binary as pveforge running spec. The
// child is killed, if still alive, when the test ends.
func startCLIChild(t *testing.T, spec cliChildSpec) *cliChild {
	t.Helper()
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), cliChildEnv+"="+string(raw))
	c := &cliChild{cmd: cmd, lines: make(chan string, 16), stderr: &syncBuffer{}, exited: make(chan struct{})}
	cmd.Stderr = c.stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		_ = cmd.Wait()
		close(c.exited)
	}()
	t.Cleanup(func() {
		select {
		case <-c.exited:
		default:
			_ = cmd.Process.Kill()
			<-c.exited
		}
	})
	return c
}

// waitLine waits for the child's next stdout line to be want.
func (c *cliChild) waitLine(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-c.lines:
		if got != want {
			t.Fatalf("child said %q, want %q; stderr %q", got, want, c.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("child never said %q; stderr %q", want, c.stderr.String())
	}
}

// waitExit waits up to d for the child to exit and returns its wait status.
func (c *cliChild) waitExit(t *testing.T, d time.Duration) syscall.WaitStatus {
	t.Helper()
	select {
	case <-c.exited:
	case <-time.After(d):
		t.Fatalf("child still running after %v; stderr %q", d, c.stderr.String())
	}
	return c.cmd.ProcessState.Sys().(syscall.WaitStatus)
}

// waitQueued waits until another process holds key's service-queue lock
// under rosterPath: a Mutation parked behind a held resource. The file name
// is internal/lock's (rosterPath + ".locks/<target>__<kind>__<id>.queue.lock").
func waitQueued(t *testing.T, rosterPath string, key lock.ObjectKey) {
	t.Helper()
	probe := flock.New(fmt.Sprintf("%s.locks/%s__%s__%s.queue.lock", rosterPath, key.TargetID, key.Kind, key.ID))
	for deadline := time.Now().Add(15 * time.Second); ; {
		got, err := probe.TryLock()
		if err == nil && !got {
			return
		}
		if got {
			_ = probe.Unlock()
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never queued for the lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRealSignal_InterruptsALockWait (B10): the shipped entry point, in its
// own process, blocked behind a held lock. SIGINT exits it 130 and SIGTERM
// 143 — normal exits, not deaths by signal — with the lock-wait line, and
// the child leaves nothing held.
func TestRealSignal_InterruptsALockWait(t *testing.T) {
	srv := newVMConfigServer(t, "", 0, "", nil)
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	unlockHeld, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		sig  syscall.Signal
		name string
		code int
	}{{syscall.SIGINT, "SIGINT", 130}, {syscall.SIGTERM, "SIGTERM", 143}} {
		child := startCLIChild(t, cliChildSpec{Args: []string{"vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "cores=4"}})
		waitQueued(t, rosterPath, key)
		if err := child.cmd.Process.Signal(tc.sig); err != nil {
			t.Fatal(err)
		}
		ws := child.waitExit(t, 10*time.Second)
		if !ws.Exited() || ws.ExitStatus() != tc.code {
			t.Errorf("%s: child ended %v, want a normal exit with status %d; stderr %q", tc.name, ws, tc.code, child.stderr.String())
		}
		want := "lock qa-pve-01/vm/100: interrupted while waiting for the lock (" + tc.name + "); the operation did not start under it"
		if got := child.stderr.String(); !strings.Contains(got, want) || strings.Count(got, "\n") != 1 {
			t.Errorf("%s: stderr %q, want one line containing %q", tc.name, got, want)
		}
	}

	_ = unlockHeld()
	unlock, err := lock.Mutation(lock.WithWait(context.Background(), time.Second), rosterPath, key)
	if err != nil {
		t.Fatalf("an interrupted child left the lock held: %v", err)
	}
	_ = unlock()
}

// TestRealSignal_SecondSignalKills (B11): a child whose work outlives the
// first SIGINT is killed by the second — by the signal's default
// disposition, restored at the first — and the kernel then releases the
// lock it was holding (the crash release that internal/lock's
// TestCrashRelease_* pin for SIGKILL).
func TestRealSignal_SecondSignalKills(t *testing.T) {
	rosterPath := t.TempDir() + "/roster.toml"
	child := startCLIChild(t, cliChildSpec{Hang: true, Roster: rosterPath})
	child.waitLine(t, "held")

	if err := child.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	child.waitLine(t, "interrupted") // the first signal was handled, and catching stopped
	select {
	case <-child.exited:
		t.Fatalf("the first SIGINT ended a command whose work ignores it; stderr %q", child.stderr.String())
	case <-time.After(300 * time.Millisecond):
	}

	if err := child.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	ws := child.waitExit(t, 10*time.Second)
	if !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Fatalf("child ended %v, want killed by the second SIGINT; stderr %q", ws, child.stderr.String())
	}

	unlock, err := lock.Mutation(lock.WithWait(context.Background(), time.Second), rosterPath, hangKey)
	if err != nil {
		t.Fatalf("the killed child's lock was not released: %v", err)
	}
	_ = unlock()
}
