package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// pveforge-root-channel-deadlines: the bound each root command runs under,
// and how a command that ran past it is reported.

// timedOut is the error sshexec.Run returns for a command past its bound.
func timedOut(cmd string) error {
	return &sshexec.CommandTimeoutError{Cmd: cmd, After: PVEConfigWriteTimeout}
}

// bounds records, for every command run (each run separately: the same
// command can run twice under different bounds), the bound sshexec.Run
// would apply to it.
type bounds struct {
	mu sync.Mutex
	m  []boundRun
}

type boundRun struct {
	cmd string
	d   time.Duration
}

func (b *bounds) record(ctx context.Context, cmd string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m = append(b.m, boundRun{cmd, sshexec.CommandTimeoutFor(ctx)})
}

// check requires every recorded command with one of the write prefixes to
// run under PVEConfigWriteTimeout and every other under the default; and,
// as anti-vacuity, EVERY listed write prefix to have been seen, and a read.
func (b *bounds) check(t *testing.T, writes ...string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	sawWrite, sawRead := false, false
	seen := map[string]bool{}
	for _, r := range b.m {
		cmd, d := r.cmd, r.d
		isWrite := false
		for _, w := range writes {
			if strings.HasPrefix(cmd, w) {
				isWrite, seen[w] = true, true
			}
		}
		want := sshexec.CommandTimeout
		if isWrite {
			want, sawWrite = PVEConfigWriteTimeout, true
		} else {
			sawRead = true
		}
		if d != want {
			t.Errorf("%q runs under %s, want %s", cmd, d, want)
		}
	}
	if !sawWrite || !sawRead {
		t.Errorf("saw a write %t, a read %t; the test is not looking at both: %v", sawWrite, sawRead, b.m)
	}
	for _, w := range writes {
		if !seen[w] {
			t.Errorf("no %q command ran: the test is not looking at it (%v)", w, b.m)
		}
	}
}

// B6: 6a's writes run under PVEConfigWriteTimeout, its reads under the
// default.
func TestRootAccess_B6_WritesCarryTheConfigWriteBound(t *testing.T) {
	var b bounds
	sess := grantSession(`[{"path":"/vms/100","roleid":"PVEVMUser","type":"user","ugid":"bob@pve","propagate":0}]`)
	sess.onRun = b.record
	a, _ := newAccess(sess, nil)
	ctx := context.Background()
	comment := "c"
	for name, err := range map[string]error{
		"AddUser":     a.AddUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true}),
		"ModifyUser":  a.ModifyUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true}),
		"AddGroup":    a.AddGroup(ctx, "ops", &comment),
		"ModifyGroup": a.ModifyGroup(ctx, "ops", "c"),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := a.GrantACL(ctx, GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")}); err != nil {
		t.Fatalf("GrantACL: %v", err)
	}
	b.check(t, "pveum user add", "pveum user modify", "pveum group add", "pveum group modify", "pveum acl modify")
}

// B6: bootstrap's token add and acl modify, and the cleanup token remove,
// run under PVEConfigWriteTimeout; its reads under the default.
func TestRun_B6_TokenWritesCarryTheConfigWriteBound(t *testing.T) {
	var b bounds
	session := &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: tokenAddJSON("tok-secret-123")}},
	}, onRun: b.record}
	if _, err := Run(context.Background(), baseOptions(newTestRoster(t, "")), &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	b.check(t, "pveum user token add", "pveum acl modify")

	// A token add whose answer cannot be parsed is removed again: that
	// cleanup remove is a write too.
	var c bounds
	session = &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user token add": {res: RunResult{Stdout: "not json"}},
	}, onRun: c.record}
	_, _ = Run(context.Background(), baseOptions(newTestRoster(t, "")), &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{})
	c.check(t, "pveum user token add", "pveum user token remove")

	// D2: the replace path's remove of the roster-held token (removeHeld).
	var d bounds
	ps, psession, ptr, pv := prior(t, nil)
	psession.onRun = d.record
	ptr.reconnectSession.onRun = d.record
	_, _ = Run(context.Background(), ps.opts, ptr, pv)
	d.check(t, "pveum user token remove", "pveum user token add", "pveum acl modify")
}

// B2: each 6a write that runs past its bound is outcome-unknown, never a
// plain failure, and says a re-run is safe.
func TestRootAccess_B2_ATimedOutWriteIsOutcomeUnknown(t *testing.T) {
	ctx := context.Background()
	comment := "c"
	for prefix, write := range map[string]func(a *RootAccess) error{
		"pveum user add": func(a *RootAccess) error { return a.AddUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true}) },
		"pveum user modify": func(a *RootAccess) error {
			return a.ModifyUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true})
		},
		"pveum group add":    func(a *RootAccess) error { return a.AddGroup(ctx, "ops", &comment) },
		"pveum group modify": func(a *RootAccess) error { return a.ModifyGroup(ctx, "ops", "c") },
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{prefix: {err: timedOut(prefix)}}}
		a, _ := newAccess(sess, nil)
		err := write(a)
		if !errors.Is(err, ErrRootWriteOutcomeUnknown) || !errors.Is(err, sshexec.ErrCommandTimedOut) || !strings.Contains(err.Error(), "re-running is safe") {
			t.Errorf("%s timing out: %v; want ErrRootWriteOutcomeUnknown", prefix, err)
		}
	}
	// A write that failed for another reason stays a plain failure.
	sess := &fakeSession{byCmd: map[string]fakeRunResult{"pveum user add": {err: errors.New("connection reset")}}}
	a, _ := newAccess(sess, nil)
	if err := a.AddUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true}); err == nil || errors.Is(err, ErrRootWriteOutcomeUnknown) {
		t.Errorf("a transport error: %v; want a plain error, not outcome-unknown", err)
	}
}

// B3: a grant that times out part way names what was applied before it and
// says the timed-out one may or may not have been.
func TestRootAccess_B3_GrantTimedOutPartWay(t *testing.T) {
	sess := grantSession(`[]`)
	sess.byCmd["pveum acl modify '/pool/lab'"] = fakeRunResult{err: timedOut("pveum acl")}
	a, _ := newAccess(sess, nil)
	_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser", "/pool/lab:PVEVMUser", "/vms/101:PVEVMUser")})
	want := "grant 2 of 3 (PVEVMUser on /pool/lab) timed out and may or may not have been applied, already applied before it: PVEVMUser on /vms/100"
	if !errors.Is(err, ErrRootWriteOutcomeUnknown) || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v\nwant it to contain %q", err, want)
	}
	for _, c := range sess.commands {
		if strings.HasPrefix(c, "pveum acl modify '/vms/101'") {
			t.Errorf("grant 3 was sent after grant 2's outcome became unknown: %q", c)
		}
	}
}

// B1: a read that times out is an error, and nothing is written after it.
func TestRootAccess_B1_ATimedOutReadWritesNothing(t *testing.T) {
	sess := grantSession(`[]`)
	sess.byCmd["pveum role list --output-format json"] = fakeRunResult{err: &sshexec.CommandTimeoutError{Cmd: "pveum role", After: time.Second}}
	a, _ := newAccess(sess, nil)
	if _, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")}); !errors.Is(err, sshexec.ErrCommandTimedOut) {
		t.Fatalf("err = %v, want the read's timeout", err)
	}
	if _, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"ops"}, false); !errors.Is(err, sshexec.ErrCommandTimedOut) {
		t.Fatalf("CheckGroupJoin err = %v, want the read's timeout", err)
	}
	for _, c := range sess.commands {
		if strings.HasPrefix(c, "pveum acl modify") {
			t.Errorf("a write was sent after a read timed out: %q", c)
		}
	}
}

// B4: a timed-out token add is ambiguous like any transport error: it is
// re-read, never inferred, and the fresh token is cleaned up.
func TestRun_B4_ATimedOutTokenAddIsReRead(t *testing.T) {
	s := seedRoster(t, aliceOwner+"!pveforge", "")
	s.opts.TokenOwner = aliceOwner
	pve := newFakePVEFor(aliceOwner, "pveforge")
	session := ownerSession(map[string]fakeRunResult{
		"pveum user token add": {err: timedOut("pveum user"), applies: true},
	}, pve)
	fresh := ownerSession(nil, pve)
	tr := &fakeTransport{session: session, reconnectSession: fresh}
	res, err := Run(context.Background(), s.opts, tr, &fakeValidator{errs: []error{fmt.Errorf("%w", ErrNoGrants), nil}})
	wantRevoked(t, res, err)
	if !errors.Is(err, sshexec.ErrCommandTimedOut) {
		t.Fatalf("err = %v, want the add's timeout in it", err)
	}
	if res.LeftoverToken != "" || pve.hasName(aliceOwner, "pveforge") {
		t.Fatalf("the timed-out add's token was not re-read and removed: %+v, %v", res, fresh.commands)
	}
}

// B4: a timed-out remove whose re-read cannot reach PVE leaves the prior
// token's state unknown (PriorTokenUnknown), as a transport error does.
func TestRun_B4_ATimedOutRemoveIsUnknown(t *testing.T) {
	s := seedRoster(t, heldID, "")
	orig := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum user token remove": {err: timedOut("pveum user"), applies: true}}}
	tr := &fakeTransport{session: orig, reconnectErrs: []error{nil, errors.New("no route to host")}}
	res, err := Run(context.Background(), s.opts, tr, &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)})
	if !errors.Is(err, ErrPriorTokenRevoked) || res == nil || res.PriorToken != PriorTokenUnknown {
		t.Fatalf("got %+v, %v; want PriorTokenUnknown", res, err)
	}
}

// B4: the cleanup remove of a fresh token timing out, with the re-read
// unreachable, leaves it reported as may-exist.
func TestRun_B4_ATimedOutCleanupRemoveMayExist(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {err: timedOut("pveum user")}}}
	tr.reconnectErrs = []error{nil, errors.New("no route")}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
		t.Fatalf("leftover = %q (%q)", res.LeftoverToken, res.LeftoverState)
	}
}

// B5: RootAccess has exactly one command runner: the only `.Run(` call in
// access.go is inside rootRun, and inventory.go has none, so every root
// command, allRolePrivs's and the inventory's getent included, carries its
// bound and its site guard.
func TestRootAccess_B5_OneCommandRunner(t *testing.T) {
	for file, want := range map[string][]string{"access.go": {"rootRun"}, "inventory.go": nil} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var sites []string
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
						sites = append(sites, fn.Name.Name)
					}
				}
				return true
			})
		}
		if !slices.Equal(sites, want) {
			t.Errorf("%s: `.Run(` is called in %v; want %v", file, sites, want)
		}
	}
}

// S1: after a TIMED-OUT add, a re-read that finds no token is not the last
// word (the killed pveum may still land it): the token may exist. After a
// transport error that is not a timeout, absent stays absent.
func TestRun_S1_ATimedOutAddReReadAbsentMayExist(t *testing.T) {
	s, _, tr, v := prior(t, map[string]fakeRunResult{"pveum user token add": {err: timedOut("pveum user")}})
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
		t.Fatalf("leftover = %q (%q), want %q (%q)", res.LeftoverToken, res.LeftoverState, heldID, LeftoverMayExist)
	}
	s, _, tr, v = prior(t, map[string]fakeRunResult{"pveum user token add": {err: errors.New("connection lost")}})
	res, err = Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != "" {
		t.Fatalf("a non-timeout error: leftover = %q (%q), want none", res.LeftoverToken, res.LeftoverState)
	}
}

// S1: after a TIMED-OUT remove of the held token, a re-read that still
// finds it does not mean pveforge did not revoke it: the remove may still
// land. The prior token's state is unknown.
func TestRun_S1_ATimedOutRemoveReReadPresentIsUnknown(t *testing.T) {
	s := seedRoster(t, heldID, "")
	pve := newFakePVE("pveforge")
	orig := &fakeSession{pve: pve, byCmd: map[string]fakeRunResult{"pveum user token remove": {err: timedOut("pveum user")}}}
	fresh := &fakeSession{pve: pve}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: orig, reconnectSession: fresh}, &fakeValidator{err: fmt.Errorf("%w", ErrNoGrants)})
	if err == nil || strings.Contains(err.Error(), "did not revoke") || !strings.Contains(err.Error(), "may yet take effect") || res == nil || res.PriorToken != PriorTokenUnknown {
		t.Fatalf("got %+v, %v; want PriorTokenUnknown and the remove reported as possibly landing, never \"did not revoke\"", res, err)
	}
	if orig.ran("pveum user token add") || fresh.ran("pveum user token add") {
		t.Fatal("an add ran after the remove's outcome became unknown")
	}
}

// S1: the cleanup remove of a fresh token timing out, then a re-read that
// still finds it: it may exist (the remove may land), not "exists".
func TestRun_S1_ATimedOutCleanupRemoveReReadPresentMayExist(t *testing.T) {
	s, session, tr, v := prior(t, map[string]fakeRunResult{"pveum acl modify": {res: RunResult{ExitCode: 1}}})
	session.seq = map[string][]fakeRunResult{"pveum user token remove": {{}, {err: timedOut("pveum user")}}}
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.LeftoverToken != heldID || res.LeftoverState != LeftoverMayExist {
		t.Fatalf("leftover = %q (%q), want may-exist", res.LeftoverToken, res.LeftoverState)
	}
}

// S3, S4: a write whose caller's own deadline passed after it was sent is
// outcome-unknown too; one that was never sent (sshexec.ErrNoCommandSent:
// the session did not open) is a plain failure, known not applied.
func TestRootAccess_S3_S4_WhatAWriteErrorMeans(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		err     error
		unknown bool
	}{
		"its own timeout":            {timedOut("pveum user"), true},
		"the caller's deadline":      {context.DeadlineExceeded, true},
		"the session open timed out": {&sshexec.SessionOpenTimeoutError{Cmd: "pveum user", After: time.Second}, false},
		"cancelled while opening":    {fmt.Errorf("%w (%w)", context.DeadlineExceeded, sshexec.ErrNoCommandSent), false},
		"the connection was closed":  {sshexec.ErrConnClosedAfterTimeout, false},
		"a transport error":          {errors.New("connection reset"), false},
	} {
		sess := &fakeSession{byCmd: map[string]fakeRunResult{"pveum user add": {err: c.err}}}
		a, _ := newAccess(sess, nil)
		err := a.AddUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true})
		if err == nil || errors.Is(err, ErrRootWriteOutcomeUnknown) != c.unknown {
			t.Errorf("%s: %v; want outcome-unknown %t", name, err, c.unknown)
		}
	}
}
