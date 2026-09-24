package main

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/lock/lockguard"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// lockWaitBackstop bounds every runRoot call in this file through the root
// command's context (cobra hands a preset context to the subcommand). It is
// far above any bound the tests pass, so reaching it means --lock-wait did
// not take effect.
const lockWaitBackstop = 5 * time.Second

// runRootWithin runs args through runRoot under ctx, returning the exit
// code, stderr and how long it took.
func runRootWithin(ctx context.Context, args ...string) (int, string, time.Duration) {
	root := newRootCmd()
	root.SetContext(ctx)
	root.SetArgs(args)
	root.SetOut(&bytes.Buffer{})
	var stderr bytes.Buffer
	start := time.Now()
	code := runRoot(root, &stderr)
	return code, stderr.String(), time.Since(start)
}

// holdLock takes a lock.Mutation on key for the rest of the test.
func holdLock(t *testing.T, rosterPath string, key lock.ObjectKey) {
	t.Helper()
	unlock, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("hold %s: %v", key, err)
	}
	t.Cleanup(func() { _ = unlock() })
}

// TestLockWait_DefaultExceedsTaskWaitCeiling pins why the default is what it
// is: a legitimate lock holder may spend pve.TaskWaitCeiling in a task wait,
// so a waiter's default must outlast it. The help text says so, from the
// constants themselves.
func TestLockWait_DefaultExceedsTaskWaitCeiling(t *testing.T) {
	if lock.DefaultWait <= pve.TaskWaitCeiling {
		t.Errorf("lock.DefaultWait = %s, want more than pve.TaskWaitCeiling = %s", lock.DefaultWait, pve.TaskWaitCeiling)
	}
	if lock.DefaultWait > lock.MaxWait {
		t.Errorf("lock.DefaultWait = %s exceeds lock.MaxWait = %s", lock.DefaultWait, lock.MaxWait)
	}
	f := newVMSetCmd().Flags().Lookup("lock-wait")
	if f == nil {
		t.Fatal("vm set has no --lock-wait flag")
	}
	for _, want := range []string{lock.DefaultWait.String(), lock.MaxWait.String(), pve.TaskWaitCeiling.String(), "waiting for a PVE task", "legitimate lock holder"} {
		if !strings.Contains(f.Usage, want) {
			t.Errorf("--lock-wait usage %q must contain %q", f.Usage, want)
		}
	}
}

// TestLockWait_FlagBoundsTheWait: with the object's lock held elsewhere,
// --lock-wait makes a locking command give up at its bound with exit 1 and
// one stderr line naming the key — for the idempotent.Run path (vm set), a
// direct lock.Mutation (api post) and a lock.Read (vm get).
func TestLockWait_FlagBoundsTheWait(t *testing.T) {
	srv := newVMConfigServer(t, "", 0, "", nil)
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdLock(t, rosterPath, key)

	cases := map[string][]string{
		"vm set":   {"vm", "set", "--roster", rosterPath, "--lock-wait", "150ms", "qa-pve-01", "100", "cores=4"},
		"api post": {"api", "post", "--roster", rosterPath, "--lock-wait", "150ms", "/nodes/qa-pve-01/qemu/100/config", "qa-pve-01"},
		"vm get":   {"vm", "get", "--roster", rosterPath, "--lock-wait", "150ms", "qa-pve-01", "100"},
	}
	for name, args := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), lockWaitBackstop)
		code, stderr, elapsed := runRootWithin(ctx, args...)
		cancel()
		if code != 1 {
			t.Errorf("%s: exit = %d, want 1; stderr %q", name, code, stderr)
		}
		if strings.Count(stderr, "\n") != 1 {
			t.Errorf("%s: stderr must be one line, got %q", name, stderr)
		}
		for _, want := range []string{key.String(), "timed out waiting for the lock after 150ms", "the lock-wait bound"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s: stderr %q must contain %q", name, stderr, want)
			}
		}
		if elapsed > 2*time.Second {
			t.Errorf("%s: took %v; the 150ms bound did not take effect", name, elapsed)
		}
	}
}

// TestLockWait_DoesNotTruncateAHold: the bound covers acquiring the lock,
// never the work done while holding it. A write that takes 400ms under a
// 100ms --lock-wait still completes.
func TestLockWait_DoesNotTruncateAHold(t *testing.T) {
	srv := newVMConfigServer(t, "", 0, "", func(string, string) { time.Sleep(400 * time.Millisecond) })
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)

	ctx, cancel := context.WithTimeout(context.Background(), lockWaitBackstop)
	defer cancel()
	code, stderr, elapsed := runRootWithin(ctx, "vm", "set", "--roster", rosterPath, "--lock-wait", "100ms", "qa-pve-01", "100", "cores=4")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (a 400ms hold is not a lock wait); stderr %q", code, stderr)
	}
	if elapsed < 400*time.Millisecond {
		t.Errorf("took %v: the slow write was never reached", elapsed)
	}
}

// TestLockWait_Validation: a negative or over-maximum --lock-wait is refused
// before the roster is read, and 0 means the default rather than "do not
// wait".
func TestLockWait_Validation(t *testing.T) {
	missing := t.TempDir() + "/no-such-roster.toml"
	for value, want := range map[string]string{
		"-1s": "--lock-wait must not be negative",
		"2h":  "--lock-wait 2h0m0s exceeds the 1h0m0s maximum",
	} {
		code, stderr, _ := runRootWithin(context.Background(), "vm", "get", "--roster", missing, "--lock-wait", value, "qa-pve-01", "100")
		if code != 1 || !strings.Contains(stderr, want) {
			t.Errorf("--lock-wait %s: exit %d, stderr %q; want exit 1 and %q (before any roster read)", value, code, stderr, want)
		}
	}

	srv := newVMConfigServer(t, "", 0, "", nil)
	defer srv.Close()
	rosterPath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	holdLock(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})

	// 0 is the 15m default: it waits, so the caller's own 300ms deadline
	// ends it, and that is not a lock-wait timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	code, stderr, _ := runRootWithin(ctx, "vm", "get", "--roster", rosterPath, "--lock-wait", "0", "qa-pve-01", "100")
	if code != 1 || !strings.Contains(stderr, "context deadline exceeded") || strings.Contains(stderr, "timed out waiting for the lock") {
		t.Errorf("--lock-wait 0: exit %d, stderr %q; want the caller's deadline, not a lock-wait timeout", code, stderr)
	}
}

// TestBootstrap_LockWaitBoundsTargetLock: bootstrap's per-target lock obeys
// --lock-wait too, and gives up before any SSH. The run is on its own
// goroutine so that a bootstrap which ignored the command's context (and so
// both --lock-wait and the backstop) fails here by name: the lock is then
// released, the run is let finish, and only then do the seams unwind.
func TestBootstrap_LockWaitBoundsTargetLock(t *testing.T) {
	tr := &fakeBootstrapTransport{}
	rosterPath := withBootstrapFakes(t, tr)
	key := lock.ObjectKey{TargetID: "qa-test", Kind: "bootstrap", ID: "token"}
	unlock, err := lock.Mutation(context.Background(), rosterPath, key)
	if err != nil {
		t.Fatalf("hold %s: %v", key, err)
	}

	type result struct {
		code    int
		stderr  string
		elapsed time.Duration
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), lockWaitBackstop)
	defer cancel()
	go func() {
		code, stderr, elapsed := runRootWithin(ctx, "bootstrap", "qa-test", "--host", "h", "--node", "n", "--grant", "/:PVEAuditor", "--lock-wait", "150ms")
		done <- result{code, stderr, elapsed}
	}()

	var r result
	select {
	case r = <-done:
		_ = unlock()
	case <-time.After(2 * lockWaitBackstop):
		_ = unlock()
		<-done
		t.Fatalf("bootstrap was still waiting on %s after %s: it honoured neither --lock-wait nor the command's context", key, 2*lockWaitBackstop)
	}
	if r.code != 1 || !strings.Contains(r.stderr, key.String()) || !strings.Contains(r.stderr, "timed out waiting for the lock after 150ms") {
		t.Errorf("exit %d, stderr %q; want exit 1 and a lock-wait timeout naming %s", r.code, r.stderr, key)
	}
	if tr.calls != 0 {
		t.Errorf("transport calls = %d, want 0: the lock is taken before any SSH", tr.calls)
	}
	if r.elapsed > 2*time.Second {
		t.Errorf("took %v; the 150ms bound did not take effect", r.elapsed)
	}
}

// lockingCommands are the command paths that take an internal/lock lock,
// and so must carry --lock-wait. Pinned by name so a new locking command
// is a deliberate addition here.
var lockingCommands = []string{
	"pveforge api delete",
	"pveforge api get",
	"pveforge api post",
	"pveforge api put",
	"pveforge bootstrap",
	"pveforge group ensure",
	"pveforge network bridge create",
	"pveforge network bridge destroy",
	"pveforge network get",
	"pveforge network set",
	"pveforge node get",
	"pveforge roster import-token",
	"pveforge storage get",
	"pveforge storage orphans",
	"pveforge user ensure",
	"pveforge vm create",
	"pveforge vm get",
	"pveforge vm set",
	"pveforge vm snapshot create",
	"pveforge vm snapshot delete",
	"pveforge vm snapshot list",
	"pveforge vm snapshot rollback",
}

// lockSinks returns every function whose call takes an internal/lock lock,
// from lockguard's one scan of the module (lock.Mutation, lock.Read, and
// every function derived from lockguard.TakerFiles). It fails the test when
// a lock is taken in any other non-test file of the module, or somewhere in
// a taker file no command could be checked against. The scan's other half,
// that each such call is given its caller's own context, is
// internal/lock's TestLockCallsUseTheCallersContext.
func lockSinks(t *testing.T) map[string]bool {
	t.Helper()
	sc, err := lockguard.ScanModule("../..")
	if err != nil {
		t.Fatalf("lockguard scan: %v", err)
	}
	for _, v := range sc.Violations {
		t.Errorf("%s takes an internal/lock lock outside %s and lockguard.TakerFiles: list its file there after review, so the commands reaching it are made to carry --lock-wait", v, lockguard.CommandDir)
	}
	for _, p := range sc.TakerProblems {
		t.Error(p)
	}
	// Anti-vacuity: the walk covered the module and still sees the sites it
	// permits.
	if len(sc.Parsed) < 70 || !sc.Result.Reached("cmd/pveforge/main.go") {
		t.Errorf("walked %d files (reached cmd/pveforge/main.go: %v): not the whole module", len(sc.Parsed), sc.Result.Reached("cmd/pveforge/main.go"))
	}
	for _, tgt := range lockguard.Targets() {
		if len(sc.Result.Allowed("cmd/pveforge/api.go", tgt)) == 0 {
			t.Errorf("%s matched nothing in cmd/pveforge/api.go: the guard no longer sees the code it guards", tgt)
		}
	}
	return sc.Sinks
}

// TestLockingCommandsHaveLockWaitFlag holds "--lock-wait exactly where a
// lock is taken, and it works there":
//
//   - lockSinks: every lock taken in the module is a known sink;
//   - in this package's source: every function that calls a sink also calls
//     addLockWaitFlag and vice versa (that each such call is given the
//     command's own cmd.Context() is internal/lock's
//     TestLockCallsUseTheCallersContext, a pure source check that fails by
//     name even while a context.Background() mutant hangs this package);
//   - on the built tree: the commands carrying the flag are exactly
//     lockingCommands, and on EACH of them --lock-wait 7ms, through the
//     command's own PreRunE, bounds a lock taken with cmd.Context().
//
// A lock taken in a helper function of this package is caught too: the
// helper calls a sink without calling addLockWaitFlag.
func TestLockingCommandsHaveLockWaitFlag(t *testing.T) {
	sinks := lockSinks(t)
	_, files, info := checkedPackage(t)
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Name.Name == "addLockWaitFlag" {
				continue
			}
			var locks, flag bool
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var id *ast.Ident
				switch fn := call.Fun.(type) {
				case *ast.SelectorExpr:
					id = fn.Sel
				case *ast.Ident:
					id = fn
				}
				if id == nil {
					return true
				}
				obj := info.Uses[id]
				if obj == nil || obj.Pkg() == nil {
					return true
				}
				if sinks[obj.Pkg().Path()+"."+obj.Name()] {
					locks = true
				}
				if obj.Name() == "addLockWaitFlag" && obj.Pkg().Name() == "main" {
					flag = true
				}
				return true
			})
			if locks && !flag {
				t.Errorf("%s takes a lock but does not call addLockWaitFlag", fd.Name.Name)
			}
			if flag && !locks {
				t.Errorf("%s calls addLockWaitFlag but takes no lock: the flag would be accepted and mean nothing", fd.Name.Name)
			}
		}
	}

	var flagged []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("lock-wait") != nil {
			flagged = append(flagged, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCmd())
	var got []string
	for _, c := range flagged {
		got = append(got, c.CommandPath())
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(lockingCommands, "\n") {
		t.Errorf("commands with --lock-wait:\n  %s\nwant exactly:\n  %s", strings.Join(got, "\n  "), strings.Join(lockingCommands, "\n  "))
	}

	// Behaviour, on every flagged command, with no server: the flag's value
	// must reach a lock taken with the command's context.
	rosterPath := t.TempDir() + "/roster.toml"
	held := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdLock(t, rosterPath, held)
	for _, c := range flagged {
		requireLockWaitReachesContext(t, c, rosterPath, held)
	}
}

// requireLockWaitReachesContext parses --lock-wait 7ms on c, runs c's own
// PreRunE, and requires a lock on held (a key another holder has) taken with
// c.Context() to give up with ErrLockWaitTimeout after 7ms. The backstop
// makes a flag that never reached the context fail here by name.
func requireLockWaitReachesContext(t *testing.T, c *cobra.Command, rosterPath string, held lock.ObjectKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.SetContext(ctx)
	if err := c.ParseFlags([]string{"--lock-wait", "7ms"}); err != nil {
		t.Errorf("%s: parse --lock-wait 7ms: %v", c.CommandPath(), err)
		return
	}
	if c.PreRunE == nil {
		t.Errorf("%s carries --lock-wait but has no PreRunE to apply it", c.CommandPath())
		return
	}
	if err := c.PreRunE(c, nil); err != nil {
		t.Errorf("%s: PreRunE: %v", c.CommandPath(), err)
		return
	}
	_, err := lock.Mutation(c.Context(), rosterPath, held)
	if !errors.Is(err, lock.ErrLockWaitTimeout) || !strings.Contains(err.Error(), "after 7ms") {
		t.Errorf("%s: --lock-wait 7ms did not reach the command's context: a lock taken with it gave %v", c.CommandPath(), err)
	}
}

// TestAddLockWaitFlag_ChainsAnEarlierPreRunE: a PreRunE the command already
// had still runs, after the bound is on the context, and its error is the
// command's; an invalid --lock-wait stops before it.
func TestAddLockWaitFlag_ChainsAnEarlierPreRunE(t *testing.T) {
	rosterPath := t.TempDir() + "/roster.toml"
	held := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"}
	holdLock(t, rosterPath, held)

	earlier := errors.New("the earlier PreRunE ran")
	var calls int
	var sawBound bool
	c := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
	c.PreRunE = func(cmd *cobra.Command, _ []string) error {
		calls++
		_, err := lock.Mutation(cmd.Context(), rosterPath, held)
		sawBound = errors.Is(err, lock.ErrLockWaitTimeout) && strings.Contains(err.Error(), "after 7ms")
		return earlier
	}
	addLockWaitFlag(c)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c.SetContext(ctx)
	if err := c.ParseFlags([]string{"--lock-wait", "7ms"}); err != nil {
		t.Fatal(err)
	}
	if err := c.PreRunE(c, nil); !errors.Is(err, earlier) || calls != 1 {
		t.Fatalf("PreRunE = %v after %d calls of the earlier hook; want the earlier hook's error, once", err, calls)
	}
	if !sawBound {
		t.Error("the earlier PreRunE ran before the --lock-wait bound was on the context")
	}

	if err := c.ParseFlags([]string{"--lock-wait", "-1s"}); err != nil {
		t.Fatal(err)
	}
	if err := c.PreRunE(c, nil); err == nil || !strings.Contains(err.Error(), "must not be negative") || calls != 1 {
		t.Errorf("PreRunE = %v, earlier hook calls %d; want the validation error with the earlier hook not run", err, calls)
	}
}

// TestLockWait_APIUsageSaysWhenItIsInert: on the api verbs, --lock-wait's
// help says it does nothing where no lock is taken — and says truly where
// that is: a matched path is always locked, --unsafe-no-lock or not
// (newAPIVerbCmd); only an unmatched path is unlocked.
func TestLockWait_APIUsageSaysWhenItIsInert(t *testing.T) {
	for _, verb := range []string{"get", "post", "put", "delete"} {
		root := newRootCmd()
		c, _, err := root.Find([]string{"api", verb})
		if err != nil {
			t.Fatal(err)
		}
		// Find falls back to the nearest parent for an unknown verb, so a
		// missing verb must fail here, by name, rather than nil-panic on the
		// flag lookup below and abort every later test in the binary.
		if c.Name() != verb {
			t.Fatalf("api %s: not registered (Find resolved %q)", verb, c.CommandPath())
		}
		f := c.Flags().Lookup("lock-wait")
		if f == nil {
			t.Fatalf("api %s: has no --lock-wait flag", verb)
		}
		u := f.Usage
		for _, want := range []string{
			"A path that names a pveforge-managed object is always locked, with or without --unsafe-no-lock",
			"On any other path no lock is taken and this flag has no effect",
			"post, put and delete are refused unless --unsafe-no-lock is given",
		} {
			if !strings.Contains(u, want) {
				t.Errorf("api %s: --lock-wait usage %q does not say %q", verb, u, want)
			}
		}
		if strings.Contains(u, "or with --unsafe-no-lock, no lock is taken") {
			t.Errorf("api %s: --lock-wait usage %q claims --unsafe-no-lock skips the lock on a matched path; it does not", verb, u)
		}
	}
	f := newVMSetCmd().Flags().Lookup("lock-wait")
	if f == nil {
		t.Fatal("vm set: has no --lock-wait flag")
	}
	if u := f.Usage; strings.Contains(u, "no effect") {
		t.Errorf("vm set always locks, but its --lock-wait usage says the flag may have no effect: %q", u)
	}
}
