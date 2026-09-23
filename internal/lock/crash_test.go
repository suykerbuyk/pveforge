package lock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

// The crash-release helper: this test binary, re-executed with
// lockHelperEnv set, takes a lock and then waits to be killed. TestMain
// dispatches to it before any test runs.
const (
	lockHelperEnv       = "PVEFORGE_LOCK_TEST_HELPER"
	lockHelperRosterEnv = "PVEFORGE_LOCK_TEST_HELPER_ROSTER"
)

var crashKey = ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

func TestMain(m *testing.M) {
	if mode := os.Getenv(lockHelperEnv); mode != "" {
		os.Exit(runLockHelper(mode, os.Getenv(lockHelperRosterEnv)))
	}
	os.Exit(m.Run())
}

// runLockHelper holds crashKey until it is killed. "hold" acquires the lock
// and says so on stdout; "queue" calls Mutation while the parent holds the
// resource, so it parks in the queue phase holding the service-queue lock.
// Neither ever unlocks: only the kernel can release them.
func runLockHelper(mode, roster string) int {
	switch mode {
	case "hold":
		if _, err := Mutation(context.Background(), roster, crashKey); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Println("held")
	case "queue":
		go func() { _, _ = Mutation(context.Background(), roster, crashKey) }()
	default:
		return 2
	}
	select {}
}

// startLockHelper starts the helper in mode against roster.
func startLockHelper(t *testing.T, mode, roster string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+mode, lockHelperRosterEnv+"="+roster)
	cmd.Stderr = os.Stderr
	return cmd
}

// requireKilledBySIGKILL kills helper and requires that it died by that
// signal, so no deferred unlock or exit path of its own ran.
func requireKilledBySIGKILL(t *testing.T, helper *exec.Cmd) {
	t.Helper()
	if err := helper.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	_ = helper.Wait()
	ws, ok := helper.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("helper did not die by SIGKILL: %v", helper.ProcessState)
	}
}

// TestCrashRelease_ResourceHolder (B1, absorbing
// pveforge-lock-crash-release-test): a process killed while HOLDING a lock
// leaves nothing held. Control first: while the holder lives, a bounded
// acquire must time out, so the release afterwards is the kill's doing.
func TestCrashRelease_ResourceHolder(t *testing.T) {
	roster := testRoster(t)
	helper := startLockHelper(t, "hold", roster)
	out, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = helper.Process.Kill(); _ = helper.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "held\n" {
		t.Fatalf("helper did not report holding the lock: %q, %v", line, err)
	}

	if _, err := Mutation(backstop(t, 200*time.Millisecond), roster, crashKey); !errors.Is(err, ErrLockWaitTimeout) {
		t.Fatalf("control: while the helper holds the lock, a bounded acquire must time out, got: %v", err)
	}

	requireKilledBySIGKILL(t, helper)
	unlock, err := Mutation(backstop(t, 200*time.Millisecond), roster, crashKey)
	if err != nil {
		t.Fatalf("the lock of a SIGKILLed holder was not released: %v", err)
	}
	_ = unlock()
}

// TestCrashRelease_QueueWaiter (B1): a process killed while parked in the
// queue phase (holding the service-queue lock, waiting for the resource)
// leaves the queue free too.
func TestCrashRelease_QueueWaiter(t *testing.T) {
	roster := testRoster(t)
	if _, err := ensureLockDir(roster, crashKey); err != nil {
		t.Fatal(err)
	}
	kf := filesFor(roster, crashKey)
	resource := flock.New(kf.resource.Path())
	if err := resource.Lock(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resource.Unlock() }()

	helper := startLockHelper(t, "queue", roster)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = helper.Process.Kill(); _ = helper.Wait() })

	probe := flock.New(kf.serviceQueue.Path())
	for deadline := time.Now().Add(10 * time.Second); ; {
		got, err := probe.TryLock()
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			break // the helper holds the queue
		}
		_ = probe.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the helper never took the service queue")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := Mutation(backstop(t, 200*time.Millisecond), roster, crashKey); !errors.Is(err, ErrLockWaitTimeout) {
		t.Fatalf("control: while the helper holds the queue, a bounded acquire must time out, got: %v", err)
	}

	requireKilledBySIGKILL(t, helper)
	got, err := probe.TryLock()
	if err != nil || !got {
		t.Fatalf("the service queue of a SIGKILLed waiter was not released: got=%v err=%v", got, err)
	}
	_ = probe.Unlock()
	_ = resource.Unlock()
	unlock, err := Mutation(backstop(t, 200*time.Millisecond), roster, crashKey)
	if err != nil {
		t.Fatalf("acquire after the waiter's death: %v", err)
	}
	_ = unlock()
}
