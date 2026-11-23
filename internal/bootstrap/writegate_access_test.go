package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/dispatch"
)

// The write gate and the S4 refusals (contract plan §3.5): the SAME refusal is
// exit 4 while the run's gate is closed and plain once a write has opened it.
// Each case is run twice, on the same fixture: with a closed gate it must be a
// dispatch.RefusedBeforeWrite and the fake must have seen no mutating command;
// with the gate opened first (what a sent write does) it must still be an error
// but must NOT be marked. A refusal that classified by its sentinel (rather
// than by the gate) would fail the second half.

func gatedCtx(open bool) context.Context {
	ctx, _ := dispatch.With(context.Background())
	if open {
		dispatch.Open(ctx)
	}
	return ctx
}

func TestWriteGate_EnableVMDestroy_RefusalsAreStateNotName(t *testing.T) {
	row := func(f *grantFake, path, role string, prop bool) { f.addRow(path, role, "token", liveToken, prop) }
	cases := []struct {
		name  string
		build func() *grantFake
		req   func(r *EnableVMDestroyRequest)
		want  error
	}{
		{"role name with the pve prefix", newGrantFake, func(r *EnableVMDestroyRequest) { r.Role = "PVEForge" }, ErrRoleName},
		{"role exists with another set", func() *grantFake {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, "VM.Audit")
			return f
		}, nil, ErrRoleConflict},
		{"token without PVEVMAdmin's privileges", func() *grantFake {
			f := newGrantFake()
			f.setRole("VMAuditOnly", "VM.Audit")
			f.acls = nil
			row(f, "/", "VMAuditOnly", true)
			return f
		}, nil, ErrNotVMAdminToken},
		{"would not converge: a descendant extra grant", func() *grantFake {
			f := newGrantFake()
			f.setRole("StorAudit", "Datastore.Audit")
			row(f, "/storage/local", "StorAudit", false)
			return f
		}, nil, ErrUpgradeWouldNotConverge},
		{"would not converge: a NoAccess row", func() *grantFake {
			f := newGrantFake()
			row(f, "/vms/100", "NoAccess", false)
			return f
		}, nil, ErrUpgradeWouldNotConverge},
		{"plan changed since it was confirmed", newGrantFake, func(r *EnableVMDestroyRequest) { r.ExpectPlan = []string{"pveum acl modify something else"} }, ErrPlanChangedSinceConfirm},
		{"PVEVMAdmin would confer an escalating privilege", func() *grantFake {
			f := newGrantFake()
			f.setRole("PVEVMAdmin", append(append([]string{}, vmAdmin23...), "VM.Monitor")...)
			return f
		}, nil, ErrEscalatingRole},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, open := range []bool{false, true} {
				r := newEnableRun(t, c.build())
				if c.req != nil {
					c.req(&r.req)
				}
				a := NewRootAccess(AccessOptions{Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin", OwnToken: r.own},
					&grantTransport{sess: r.fake, calls: &r.tr.reconnectCalls})
				_, err := EnableVMDestroy(gatedCtx(open), a, r.req)
				if err == nil {
					t.Fatalf("open=%v: no refusal", open)
				}
				if !errorsIs(err, c.want) {
					t.Fatalf("open=%v: %v is not %v", open, err, c.want)
				}
				if got := dispatch.IsRefused(err); got == open {
					t.Fatalf("gate open=%v but IsRefused=%v: %v", open, got, err)
				}
				if w := r.fake.mutating(); len(w) != 0 {
					t.Fatalf("open=%v: a refusal wrote %q", open, w)
				}
			}
		})
	}
}

// A refusal that is really a failed read is never marked, gate closed or not:
// a role list that cannot be read is exit 1.
func TestWriteGate_EnableVMDestroy_AFailedReadIsNeverARefusal(t *testing.T) {
	f := newGrantFake()
	f.fail["pveum role list"] = RunResult{ExitCode: 1, Stderr: "boom"}
	r := newEnableRun(t, f)
	a := NewRootAccess(AccessOptions{Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin", OwnToken: r.own},
		&grantTransport{sess: f, calls: &r.tr.reconnectCalls})
	_, err := EnableVMDestroy(gatedCtx(false), a, r.req)
	if err == nil || dispatch.IsRefused(err) {
		t.Fatalf("a failed role-list read: %v (refused=%v), want a plain error", err, dispatch.IsRefused(err))
	}
}

// The two "cannot derive" arms of the role derivation (a role missing from the
// list) are failed reads in substance: never marked, gate closed or not.
func TestWriteGate_EnableVMDestroy_CannotDeriveIsNotARefusal(t *testing.T) {
	f := newGrantFake()
	delete(f.roles, "PVEVMAdmin")
	r := newEnableRun(t, f)
	a := NewRootAccess(AccessOptions{Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin", OwnToken: r.own},
		&grantTransport{sess: f, calls: &r.tr.reconnectCalls})
	_, err := EnableVMDestroy(gatedCtx(false), a, r.req)
	if err == nil || dispatch.IsRefused(err) {
		t.Fatalf("a role list without PVEVMAdmin: %v (refused=%v), want a plain error", err, dispatch.IsRefused(err))
	}
}

// scriptSession answers root commands by prefix, for the GrantACL cases.
type scriptSession struct {
	out  map[string]string
	cmds []string
}

func (s *scriptSession) Run(_ context.Context, cmd string) (RunResult, error) {
	s.cmds = append(s.cmds, cmd)
	for p, o := range s.out {
		if strings.HasPrefix(cmd, p) {
			return RunResult{Stdout: o}, nil
		}
	}
	return RunResult{}, nil
}
func (s *scriptSession) Close() error { return nil }

func TestWriteGate_GrantACLAndGroupJoin_RefusalsAreStateNotName(t *testing.T) {
	roles := `[{"roleid":"PVEVMUser","privs":"VM.Audit,VM.Console"},{"roleid":"Empty","privs":""},{"roleid":"Administrator","privs":"Permissions.Modify,VM.Audit"}]`
	groups := `[{"groupid":"ops","users":"alice@pve"},{"groupid":"admins","users":"root@pam"}]`
	acls := `[{"path":"/","roleid":"Administrator","type":"group","ugid":"ops","propagate":1}]`
	users := `[{"userid":"root@pam","enable":1,"groups":"admins"}]`
	req := func(kind, id string, g ...Grant) GrantRequest {
		return GrantRequest{Principal: Principal{Kind: kind, ID: id}, Grants: g}
	}
	vmu := Grant{Path: "/vms/100", Role: "PVEVMUser"}
	cases := []struct {
		name string
		run  func(ctx context.Context, a *RootAccess) error
		want error
	}{
		{"malformed principal", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "bob", vmu))
			return e
		}, nil},
		{"own token", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("token", "root@pam!pveforge", vmu))
			return e
		}, ErrSelfGrant},
		{"own user", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "root@pam", vmu))
			return e
		}, ErrSelfGrant},
		{"unknown role", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "bob@pve", Grant{Path: "/", Role: "Nope"}))
			return e
		}, ErrUnknownRole},
		{"role with no privileges", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "bob@pve", Grant{Path: "/", Role: "Empty"}))
			return e
		}, ErrRoleHasNoPrivileges},
		{"pinned privileges that differ", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "bob@pve", Grant{Path: "/", Role: "PVEVMUser", Privs: []string{"VM.Audit"}}))
			return e
		}, ErrPinnedPrivsMismatch},
		{"escalating role", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("user", "bob@pve", Grant{Path: "/", Role: "Administrator"}))
			return e
		}, ErrEscalatingRole},
		{"unknown group", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("group", "nogroup", vmu))
			return e
		}, ErrUnknownGroup},
		{"group holding the owner", func(ctx context.Context, a *RootAccess) error {
			_, e := a.GrantACL(ctx, req("group", "admins", vmu))
			return e
		}, ErrSelfGrant},
		{"group join: own user", func(ctx context.Context, a *RootAccess) error {
			_, e := a.CheckGroupJoin(ctx, "root@pam", []string{"ops"}, false)
			return e
		}, ErrSelfGrant},
		{"group join: escalating holding", func(ctx context.Context, a *RootAccess) error {
			_, e := a.CheckGroupJoin(ctx, "bob@pve", []string{"ops"}, false)
			return e
		}, ErrEscalatingRole},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, open := range []bool{false, true} {
				s := &scriptSession{out: map[string]string{"pveum role list": roles, "pveum group list": groups, "pveum acl list": acls, "pveum user list": users}}
				a := NewRootAccess(AccessOptions{Addr: "x:22", OwnToken: "root@pam!pveforge"}, &grantTransport{sess: s, calls: new(int)})
				err := c.run(gatedCtx(open), a)
				if err == nil {
					t.Fatalf("open=%v: no refusal", open)
				}
				if c.want != nil && !errorsIs(err, c.want) {
					t.Fatalf("open=%v: %v is not %v", open, err, c.want)
				}
				if got := dispatch.IsRefused(err); got == open {
					t.Fatalf("gate open=%v but IsRefused=%v: %v", open, got, err)
				}
				for _, cmd := range s.cmds {
					if strings.Contains(cmd, " modify ") || strings.Contains(cmd, " add ") {
						t.Fatalf("a refusal wrote: %q", cmd)
					}
				}
			}
		})
	}
}

func errorsIs(err, target error) bool { return errors.Is(err, target) }
