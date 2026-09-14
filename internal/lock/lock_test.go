package lock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
