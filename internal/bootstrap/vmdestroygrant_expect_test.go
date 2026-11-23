package bootstrap

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/roster"
)

// The confirmed-plan guard (ExpectPlan) and the session reuse the two-pass
// operator flow depends on. Every case is a TWIN: the identical fixture with no
// mutation between the passes writes both commands, so a refusal that is
// "zero writes" here is not zero because the run failed early.

func expectAccess(r *enableRun) *RootAccess {
	return NewRootAccess(AccessOptions{
		Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin", OwnToken: r.own,
	}, &grantTransport{sess: r.fake, calls: &r.tr.reconnectCalls})
}

// plan runs the dry pass on a and returns its Planned list.
func expectPlan(t *testing.T, a *RootAccess, r *enableRun) []string {
	t.Helper()
	req := r.req
	req.DryRun = true
	res, err := EnableVMDestroy(context.Background(), a, req)
	if err != nil {
		t.Fatalf("dry pass: %v", err)
	}
	if len(res.Planned) == 0 {
		t.Fatal("vacuous: the dry pass planned nothing")
	}
	if n := len(r.fake.mutating()); n != 0 {
		t.Fatalf("the dry pass wrote: %q", r.fake.mutating())
	}
	return slices.Clone(res.Planned)
}

func writesOf(f *grantFake) int { return len(f.mutating()) }

// R2: ONE RootAccess serves the dry pass and the real pass: one dial, the
// second pass re-reads and writes exactly what was planned.
func TestEnableExpect_TwoPassesShareOneSession(t *testing.T) {
	r := newEnableRun(t, newGrantFake())
	a := expectAccess(r)
	planned := expectPlan(t, a, r)
	req := r.req
	req.ExpectPlan = planned
	res, err := EnableVMDestroy(context.Background(), a, req)
	if err != nil || res.Outcome != EnableUpgraded {
		t.Fatalf("real pass: %+v, %v", res, err)
	}
	if got := r.fake.mutating(); len(got) != 2 || got[0] != planned[0] || got[1] != planned[1] {
		t.Fatalf("wrote %q, planned %q", got, planned)
	}
	if r.tr.reconnectCalls != 1 {
		t.Fatalf("the two passes dialed %d times, want 1", r.tr.reconnectCalls)
	}
}

// F2: the four things that can change between the plan and the lock.
func TestEnableExpect_FourMutationsBetweenThePasses(t *testing.T) {
	type tc struct {
		name    string
		mutate  func(r *enableRun)
		wantErr error
		outcome string
		writes  int // exact count of mutating commands after the real pass
		// nilExpectWrites is the write count with the SAME mutation and no
		// ExpectPlan: it shows the guard, not the fixture, decides.
		nilExpectWrites int
	}
	cases := []tc{
		{name: "control: no mutation", mutate: func(r *enableRun) {}, outcome: EnableUpgraded, writes: 2, nilExpectWrites: 2},
		{name: "role created with the same D", mutate: func(r *enableRun) { r.fake.setRole(DefaultVMDestroyRole, vmD...) },
			wantErr: ErrPlanChangedSinceConfirm, writes: 0, nilExpectWrites: 1},
		{name: "incompatible role edit", mutate: func(r *enableRun) { r.fake.setRole(DefaultVMDestroyRole, vmD[1:]...) },
			wantErr: ErrRoleConflict, writes: 0, nilExpectWrites: 0},
		{name: "concurrent grant", mutate: func(r *enableRun) {
			r.fake.setRole(DefaultVMDestroyRole, vmD...)
			r.fake.addRow("/", DefaultVMDestroyRole, "token", liveToken, true)
		}, outcome: EnableAlreadyEnabled, writes: 0, nilExpectWrites: 0},
		{name: "token rotated", mutate: func(r *enableRun) {
			if err := roster.WriteTokenAuth(r.roster, "qa-pve-01", roster.TokenWrite{TokenID: "root@pam!rotated", SecretPlaintext: []byte("s")}, roster.NewPassphrase("roster-pass")); err != nil {
				t.Fatal(err)
			}
		}, wantErr: ErrTokenChangedUnderLock, writes: 0, nilExpectWrites: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, withExpect := range []bool{true, false} {
				r := newEnableRun(t, newGrantFake())
				a := expectAccess(r)
				planned := expectPlan(t, a, r)
				fired := false
				func() { c.mutate(r); fired = true }()
				if !fired {
					t.Fatal("the mutation hook did not fire")
				}
				req := r.req
				if withExpect {
					req.ExpectPlan = planned
				}
				res, err := EnableVMDestroy(context.Background(), a, req)
				if !withExpect {
					// Same mutation, no guard: only the role-created case differs
					// from the guarded run (it writes the one remaining command).
					if c.nilExpectWrites != 0 && err != nil {
						t.Fatalf("no ExpectPlan: %v", err)
					}
					if got := writesOf(r.fake); got != c.nilExpectWrites {
						t.Fatalf("no ExpectPlan: %d writes %q, want %d", got, r.fake.mutating(), c.nilExpectWrites)
					}
					continue
				}
				if c.wantErr != nil {
					if !errors.Is(err, c.wantErr) || res != nil {
						t.Fatalf("want %v, got %+v, %v", c.wantErr, res, err)
					}
				} else if err != nil || res.Outcome != c.outcome {
					t.Fatalf("want %s, got %+v, %v", c.outcome, res, err)
				}
				if got := writesOf(r.fake); got != c.writes {
					t.Fatalf("%d writes %q, want exactly %d", got, r.fake.mutating(), c.writes)
				}
			}
		})
	}
}

// The role-only path is guarded too: the role appeared between the passes, so
// the confirmed `role add` is no longer what would be sent (nothing is, and
// that is not a mismatch).
func TestEnableExpect_RoleOnly(t *testing.T) {
	r := newEnableRun(t, newGrantFake())
	r.req.RoleOnly = true
	a := expectAccess(r)
	planned := expectPlan(t, a, r)
	r.fake.setRole(DefaultVMDestroyRole, vmD...)
	req := r.req
	req.ExpectPlan = planned
	res, err := EnableVMDestroy(context.Background(), a, req)
	if err != nil || res.Outcome != EnableRoleOnly || res.RoleCreated || writesOf(r.fake) != 0 {
		t.Fatalf("role appeared: %+v, %v, writes %q", res, err, r.fake.mutating())
	}
	// Control: the same plan with the role still absent writes it.
	r2 := newEnableRun(t, newGrantFake())
	r2.req.RoleOnly = true
	a2 := expectAccess(r2)
	req2 := r2.req
	req2.ExpectPlan = expectPlan(t, a2, r2)
	if res, err := EnableVMDestroy(context.Background(), a2, req2); err != nil || !res.RoleCreated || writesOf(r2.fake) != 1 {
		t.Fatalf("control: %+v, %v, writes %q", res, err, r2.fake.mutating())
	}
}

// The comparison itself, called directly: both directions.
func TestCheckExpectedPlan(t *testing.T) {
	a, b := "pveum role add 'R' --privs 'x'", "pveum acl modify '/' --tokens 't' --roles 'R' --propagate 1"
	for _, c := range []struct {
		name   string
		expect []string
		would  []string
		ok     bool
	}{
		{"nil expect compares nothing", nil, []string{a, b}, true},
		{"identical", []string{a, b}, []string{a, b}, true},
		{"one command fewer", []string{a, b}, []string{b}, false},
		{"one command more", []string{b}, []string{a, b}, false},
		{"same count, different text", []string{a, b}, []string{a, b + " "}, false},
		{"order matters", []string{a, b}, []string{b, a}, false},
		{"empty non-nil expect, something to write", []string{}, []string{a}, false},
	} {
		err := checkExpectedPlan(EnableVMDestroyRequest{ExpectPlan: c.expect}, c.would)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrPlanChangedSinceConfirm)) {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
