package lock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/flock"

	"github.com/suykerbuyk/pveforge/internal/lock/lockguard"
)

func init() {
	// Tests don't need production-scale patience waiting on ctx deadlines.
	pollInterval = 2 * time.Millisecond
}

func testRoster(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "roster.toml")
}

func TestMutation_SerializesConcurrentMutationsOnSameKey(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	var active int32
	var maxObserved int32
	var wg sync.WaitGroup
	const n = 8
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			unlock, err := Mutation(ctx, roster, key)
			if err != nil {
				t.Errorf("Mutation: %v", err)
				return
			}
			defer func() {
				if err := unlock(); err != nil {
					t.Errorf("unlock: %v", err)
				}
			}()

			cur := atomic.AddInt32(&active, 1)
			for {
				old := atomic.LoadInt32(&maxObserved)
				if cur <= old || atomic.CompareAndSwapInt32(&maxObserved, old, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&active, -1)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxObserved); got != 1 {
		t.Fatalf("expected at most 1 concurrent mutation on the same key, observed %d", got)
	}
}

func TestMutation_DoesNotBlockDifferentKeys(t *testing.T) {
	roster := testRoster(t)
	keyA := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	keyB := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "200"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	unlockA, err := Mutation(ctx, roster, keyA)
	if err != nil {
		t.Fatalf("Mutation(A): %v", err)
	}
	defer unlockA()

	// Must acquire promptly: a lock on a DIFFERENT key must never block on
	// keyA's held mutation.
	done := make(chan error, 1)
	go func() {
		unlockB, err := Mutation(ctx, roster, keyB)
		if err != nil {
			done <- err
			return
		}
		done <- unlockB()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Mutation(B): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Mutation on a different key blocked — locks are not per-object")
	}
}

func TestRead_AllowsConcurrentReads(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bothIn := make(chan struct{})
	var once sync.Once
	var entered int32

	readerDone := make(chan error, 2)
	startReader := func() {
		unlock, err := Read(ctx, roster, key)
		if err != nil {
			readerDone <- err
			return
		}
		if atomic.AddInt32(&entered, 1) == 2 {
			once.Do(func() { close(bothIn) })
		}
		select {
		case <-bothIn:
		case <-time.After(2 * time.Second):
		}
		readerDone <- unlock()
	}
	go startReader()
	go startReader()

	for i := 0; i < 2; i++ {
		if err := <-readerDone; err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if atomic.LoadInt32(&entered) != 2 {
		t.Fatal("expected both Read calls to be concurrently held")
	}
}

// TestMutation_TakesPriorityOverLaterRead is the core correctness proof
// of the priority mandate: a Read holding the lock, a Mutation queued
// behind it, and a SECOND Read arriving after the Mutation started
// waiting — the second Read must not acquire the resource lock before the
// Mutation does, even though the Mutation has to wait longer in wall-clock
// terms for the first Read to finish.
func TestMutation_TakesPriorityOverLaterRead(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mu sync.Mutex
	var order []string
	record := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	// R1 takes the read lock and holds it until told to release.
	r1Held := make(chan struct{})
	releaseR1 := make(chan struct{})
	go func() {
		unlock, err := Read(ctx, roster, key)
		if err != nil {
			t.Errorf("R1 Read: %v", err)
			close(r1Held)
			return
		}
		record("r1-acquired")
		close(r1Held)
		<-releaseR1
		if err := unlock(); err != nil {
			t.Errorf("R1 unlock: %v", err)
		}
	}()
	<-r1Held

	// W starts trying to acquire immediately: it grabs the (uncontended)
	// service-queue turnstile right away and then blocks on the
	// (R1-held) resource lock — no artificial delay before starting, so
	// the only sleep needed is enough for W to reach that blocked state.
	wDone := make(chan struct{})
	go func() {
		unlock, err := Mutation(ctx, roster, key)
		if err != nil {
			t.Errorf("W Mutation: %v", err)
			close(wDone)
			return
		}
		record("w-acquired")
		if err := unlock(); err != nil {
			t.Errorf("W unlock: %v", err)
		}
		close(wDone)
	}()
	time.Sleep(30 * time.Millisecond) // let W acquire the turnstile and start blocking on resource

	// R2 arrives while W is still waiting on R1 — it must block at the
	// turnstile (W holds it) rather than slip through to the resource
	// lock ahead of W.
	r2Done := make(chan struct{})
	go func() {
		unlock, err := Read(ctx, roster, key)
		if err != nil {
			t.Errorf("R2 Read: %v", err)
			close(r2Done)
			return
		}
		record("r2-acquired")
		if err := unlock(); err != nil {
			t.Errorf("R2 unlock: %v", err)
		}
		close(r2Done)
	}()

	// Give R2 time to reach (and block at) the turnstile before R1 lets go.
	time.Sleep(30 * time.Millisecond)
	close(releaseR1)

	<-wDone
	<-r2Done

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "r1-acquired" || order[1] != "w-acquired" || order[2] != "r2-acquired" {
		t.Fatalf("expected order [r1-acquired w-acquired r2-acquired], got %v", order)
	}
}

func TestMutation_ContextDeadlineExceeded(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	holderCtx, holderCancel := context.WithCancel(context.Background())
	defer holderCancel()
	unlock, err := Mutation(holderCtx, roster, key)
	if err != nil {
		t.Fatalf("holder Mutation: %v", err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Mutation(ctx, roster, key)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error when the lock is held and ctx expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected a context.DeadlineExceeded-wrapping error, got: %v", err)
	}
	// The caller's own deadline is not the lock-wait bound running out.
	if errors.Is(err, ErrLockWaitTimeout) {
		t.Errorf("a caller's own deadline must not read as ErrLockWaitTimeout, got: %v", err)
	}
	if !strings.Contains(err.Error(), key.String()) {
		t.Errorf("error must name the key %s, got: %v", key, err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Mutation took too long to give up on an expired context: %v", elapsed)
	}
}

func TestSanitizeKey_UnsafeCharactersDoNotEscapeLockDir(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "../../etc", Kind: "vm/../..", ID: "100"}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	unlock, err := Mutation(ctx, roster, key)
	if err != nil {
		t.Fatalf("Mutation with unsafe key characters: %v", err)
	}
	defer unlock()

	locksDir := roster + ".locks"
	entries, err := os.ReadDir(locksDir)
	if err != nil {
		t.Fatalf("read locks dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected lock files inside the locks directory")
	}
	for _, e := range entries {
		if filepath.Dir(filepath.Join(locksDir, e.Name())) != locksDir {
			t.Fatalf("lock file escaped the locks directory: %s", e.Name())
		}
	}
}

// TestMutation_LockDirectoryCreationFailure and its Read sibling exercise
// the error path where rosterPath+".locks" can't be created because
// something already occupies that exact path as a regular file (not a
// directory) — a plausible real scenario (a leftover file, a permissions
// mistake) that MkdirAll must surface clearly rather than panic or hang.
func TestMutation_LockDirectoryCreationFailure(t *testing.T) {
	roster := testRoster(t)
	if err := os.WriteFile(roster+".locks", []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}

	_, err := Mutation(context.Background(), roster, ObjectKey{TargetID: "t", Kind: "vm", ID: "1"})
	if err == nil {
		t.Fatal("expected an error when the locks directory can't be created")
	}
}

func TestRead_LockDirectoryCreationFailure(t *testing.T) {
	roster := testRoster(t)
	if err := os.WriteFile(roster+".locks", []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}

	_, err := Read(context.Background(), roster, ObjectKey{TargetID: "t", Kind: "vm", ID: "1"})
	if err == nil {
		t.Fatal("expected an error when the locks directory can't be created")
	}
}

// TestRead_ContextDeadlineExceeded is Read's sibling to
// TestMutation_ContextDeadlineExceeded: a Read must also give up cleanly
// when a Mutation already holds the resource lock and ctx expires, rather
// than blocking forever.
func TestRead_ContextDeadlineExceeded(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}

	holderCtx, holderCancel := context.WithCancel(context.Background())
	defer holderCancel()
	unlock, err := Mutation(holderCtx, roster, key)
	if err != nil {
		t.Fatalf("holder Mutation: %v", err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Read(ctx, roster, key)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error when the resource is held exclusively and ctx expires")
	}
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLockWaitTimeout) {
		t.Errorf("want the caller's own context.DeadlineExceeded, not ErrLockWaitTimeout, got: %v", err)
	}
	if !strings.Contains(err.Error(), key.String()) {
		t.Errorf("error must name the key %s, got: %v", key, err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Read took too long to give up on an expired context: %v", elapsed)
	}
}

func TestObjectKey_String(t *testing.T) {
	k := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	if got, want := k.String(), "qa-pve-01/vm/100"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// The phase texts, spelled out rather than taken from the constants, so a
// swap of the constants is caught.
const (
	wantQueued = "another mutation is queued for or holds this object"
	wantHeld   = "it is held by another command"
)

// backstop bounds a wait-bound test, so a bound that does not fire fails
// the test by name instead of hanging the package.
func backstop(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return WithWait(ctx, d)
}

// holdMutation takes a Mutation on key for the rest of the test.
func holdMutation(t *testing.T, roster string, key ObjectKey) {
	t.Helper()
	unlock, err := Mutation(context.Background(), roster, key)
	if err != nil {
		t.Fatalf("holder Mutation: %v", err)
	}
	t.Cleanup(func() { _ = unlock() })
}

// requireWaitTimeout fails unless err is ErrLockWaitTimeout naming key,
// the bound, what was waited behind, and the lock file.
func requireWaitTimeout(t *testing.T, err error, key ObjectKey, bound, behind, path string) {
	t.Helper()
	if !errors.Is(err, ErrLockWaitTimeout) {
		t.Fatalf("want ErrLockWaitTimeout, got: %v", err)
	}
	for _, want := range []string{key.String(), "after " + bound, "--lock-wait", behind, "fuser -v '" + path + "' lists"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must contain %q", err, want)
		}
	}
}

// TestMutation_WaitBoundFires: a Mutation behind a held Mutation gives up
// when its lock-wait bound runs out, with ErrLockWaitTimeout, not by
// waiting on forever.
func TestMutation_WaitBoundFires(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	start := time.Now()
	_, err := Mutation(backstop(t, 100*time.Millisecond), roster, key)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the 100ms bound took %v to fire", elapsed)
	}
	requireWaitTimeout(t, err, key, "100ms", wantHeld, filesFor(roster, key).resource.Path())
}

// TestRead_WaitBoundFires is Read's sibling: a Read behind a held Mutation
// gives up at its bound.
func TestRead_WaitBoundFires(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	start := time.Now()
	_, err := Read(backstop(t, 100*time.Millisecond), roster, key)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the 100ms bound took %v to fire", elapsed)
	}
	requireWaitTimeout(t, err, key, "100ms", wantHeld, filesFor(roster, key).resource.Path())
}

// TestWaitBound_OneDeadlineAcrossPhases: Mutation's two phases share one
// bound. The service queue is held for 400ms of a 600ms bound, then
// released while the resource stays held: the call must give up at about
// 600ms in total, not 400ms plus a fresh 600ms.
func TestWaitBound_OneDeadlineAcrossPhases(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	if _, err := ensureLockDir(roster, key); err != nil {
		t.Fatal(err)
	}
	kf := filesFor(roster, key)
	queue, resource := flock.New(kf.serviceQueue.Path()), flock.New(kf.resource.Path())
	if err := resource.Lock(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resource.Unlock() }()
	if err := queue.Lock(); err != nil {
		t.Fatal(err)
	}
	released := time.AfterFunc(400*time.Millisecond, func() { _ = queue.Unlock() })
	defer released.Stop()

	start := time.Now()
	_, err := Mutation(backstop(t, 600*time.Millisecond), roster, key)
	elapsed := time.Since(start)
	requireWaitTimeout(t, err, key, "600ms", wantHeld, kf.resource.Path())
	if elapsed < 550*time.Millisecond || elapsed > 850*time.Millisecond {
		t.Errorf("gave up after %v, want about 600ms: one bound across both phases", elapsed)
	}
}

// TestWaitBound_PhaseText: a wait that runs out in the service queue says a
// mutation is queued for or holds the object and names the queue file; one
// that runs out on the resource says the object is held and names the
// resource file.
func TestWaitBound_PhaseText(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)
	kf := filesFor(roster, key)

	// A second Mutation waits for the resource while holding the queue.
	waiterCtx, stopWaiter := context.WithCancel(context.Background())
	waiterDone := make(chan struct{})
	go func() {
		defer close(waiterDone)
		if unlock, err := Mutation(waiterCtx, roster, key); err == nil {
			_ = unlock()
		}
	}()
	defer func() { stopWaiter(); <-waiterDone }()
	probe := flock.New(kf.serviceQueue.Path())
	for deadline := time.Now().Add(5 * time.Second); ; {
		got, err := probe.TryLock()
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			break // the waiter holds the queue
		}
		_ = probe.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the waiting Mutation never took the service queue")
		}
		time.Sleep(5 * time.Millisecond)
	}

	_, err := Read(backstop(t, 100*time.Millisecond), roster, key)
	requireWaitTimeout(t, err, key, "100ms", wantQueued, kf.serviceQueue.Path())
	if strings.Contains(err.Error(), wantHeld) {
		t.Errorf("a queue-phase timeout must not claim the resource wait: %v", err)
	}
}

// TestWaitBound_DefaultApplies: with no WithWait, or WithWait(ctx, 0), the
// wait is bounded by the default, not unbounded.
func TestWaitBound_DefaultApplies(t *testing.T) {
	orig := defaultWait
	defaultWait = 100 * time.Millisecond
	defer func() { defaultWait = orig }()

	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	for name, ctx := range map[string]context.Context{
		"no WithWait":     context.Background(),
		"WithWait(ctx,0)": WithWait(context.Background(), 0),
	} {
		// A backstop, so a regression fails here rather than hanging.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := Mutation(ctx, roster, key)
		cancel()
		if !errors.Is(err, ErrLockWaitTimeout) || !strings.Contains(err.Error(), "after 100ms") {
			t.Errorf("%s: want ErrLockWaitTimeout after the 100ms default, got: %v", name, err)
		}
	}
}

// TestMutation_ContextCanceled: cancelling the caller's ctx during the
// wait is the caller's cancellation, not ErrLockWaitTimeout.
func TestMutation_ContextCanceled(t *testing.T) {
	roster := testRoster(t)
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	ctx, cancel := context.WithCancel(WithWait(context.Background(), time.Minute))
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := Mutation(ctx, roster, key)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrLockWaitTimeout) {
		t.Errorf("want context.Canceled, not ErrLockWaitTimeout, got: %v", err)
	}
}

// TestWaitBound_FuserPathIsShellQuoted: the fuser command in the timeout
// text survives a copy-paste when the roster path has a space in it.
func TestWaitBound_FuserPathIsShellQuoted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my rosters")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	roster := filepath.Join(dir, "roster.toml")
	key := ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdMutation(t, roster, key)

	_, err := Mutation(backstop(t, 50*time.Millisecond), roster, key)
	want := "fuser -v '" + filesFor(roster, key).resource.Path() + "' lists"
	if !errors.Is(err, ErrLockWaitTimeout) || !strings.Contains(err.Error(), want) {
		t.Errorf("want ErrLockWaitTimeout containing %q, got: %v", want, err)
	}
}

// TestLockCallsUseTheCallersContext: every call that takes an internal/lock
// lock — lock.Mutation, lock.Read, or a function derived as taking one
// (lockguard.TakerFiles) — is given its caller's own context: in
// cmd/pveforge the command's cmd.Context(), elsewhere the enclosing
// function's context.Context parameter. A context.Background() there would
// ignore --lock-wait (and the caller's cancellation). It is a source check,
// so it lives here, in a package whose tests never block on a lock, and
// fails by name within seconds even while such a mutant hangs cmd/pveforge.
func TestLockCallsUseTheCallersContext(t *testing.T) {
	sc, err := lockguard.ScanModule("../..")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	perFile := map[string]int{}
	commandCalls := 0
	for _, c := range sc.Calls {
		perFile[c.Ref.File]++
		if strings.HasPrefix(c.Ref.File, lockguard.CommandDir+"/") {
			commandCalls++
		}
		if c.Problem != "" {
			t.Errorf("%s: %s", c.Ref, c.Problem)
		}
	}
	t.Logf("checked %d lock-taking calls (%d in %s) across %d parsed files", len(sc.Calls), commandCalls, lockguard.CommandDir, len(sc.Parsed))
	// Anti-vacuity: the scan covered the module and still checks the calls
	// it is meant to (13 in cmd/pveforge today, one in each taker file).
	if len(sc.Parsed) < 70 {
		t.Errorf("the scan parsed only %d files: not the whole module", len(sc.Parsed))
	}
	if commandCalls < 13 {
		t.Errorf("checked only %d lock-taking calls in %s, want at least 13", commandCalls, lockguard.CommandDir)
	}
	for file := range lockguard.TakerFiles {
		if perFile[file] == 0 {
			t.Errorf("checked no lock-taking call in %s", file)
		}
	}
	for _, sink := range []string{"github.com/suykerbuyk/pveforge/internal/idempotent.Run", "github.com/suykerbuyk/pveforge/internal/bootstrap.Run"} {
		if !sc.Sinks[sink] {
			t.Errorf("%s is no longer derived as a lock taker", sink)
		}
	}
}
