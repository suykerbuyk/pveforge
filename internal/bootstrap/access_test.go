package bootstrap

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/idempotent"
	"github.com/suykerbuyk/pveforge/internal/pve"
)

// RootAccess, 6a: the root pveum channel for users, groups and ACL grants.
// Every test drives the package's scripted fakeTransport/fakeSession and
// asserts the exact commands root ran, and that no session was opened when
// none should have been.

const accessOwnToken = "pveforge@pve!automation"

// fakeREST is the token's REST view.
type fakeREST struct {
	users    []pve.AccessUser
	groups   []pve.AccessGroup
	err      error
	calls    int
	lastCall string
}

func (f *fakeREST) ListUsers(context.Context) ([]pve.AccessUser, error) {
	f.calls++
	f.lastCall = "users"
	return f.users, f.err
}

func (f *fakeREST) ListGroups(context.Context) ([]pve.AccessGroup, error) {
	f.calls++
	f.lastCall = "groups"
	return f.groups, f.err
}

func newAccess(sess *fakeSession, rest AccessReader) (*RootAccess, *fakeTransport) {
	tr := &fakeTransport{session: sess}
	return NewRootAccess(AccessOptions{
		Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin",
		REST: rest, OwnToken: accessOwnToken,
	}, tr), tr
}

func opened(tr *fakeTransport) int { return tr.reconnectCalls + tr.dialPWCalls + tr.dialCalls }

func TestRootAccess_ListUsers_REST(t *testing.T) {
	rest := &fakeREST{users: []pve.AccessUser{{UserID: "alice@pve", Enabled: true}}}
	a, tr := newAccess(&fakeSession{}, rest)
	users, err := a.ListUsers(context.Background())
	if err != nil || len(users) != 1 || users[0].UserID != "alice@pve" {
		t.Fatalf("ListUsers = %+v, %v", users, err)
	}
	if opened(tr) != 0 {
		t.Errorf("root was dialed for a read the token could make")
	}
}

// Only a 401 or 403 from the token falls back to root; any other failure
// stays an error, and never reads as an empty list.
func TestRootAccess_ListUsers_FallbackOnlyWhenTheTokenIsRefused(t *testing.T) {
	rootList := `[{"userid":"root@pam","enable":1},{"userid":"alice@pve","enable":0}]`
	for _, c := range []struct {
		name     string
		restErr  error
		fallback bool
	}{
		{"403", pve.NewStatusError("list users", 403, "403 Forbidden", nil), true},
		{"401", pve.NewStatusError("list users", 401, "401 Unauthorized", nil), true},
		{"500", pve.NewStatusError("list users", 500, "500 Internal Server Error", nil), false},
		{"transport", errors.New("connection reset"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := &fakeSession{byCmd: map[string]fakeRunResult{"pveum user list --full 1 --output-format json": {res: RunResult{Stdout: rootList}}}}
			a, tr := newAccess(sess, &fakeREST{err: c.restErr})
			users, err := a.ListUsers(context.Background())
			if c.fallback {
				if err != nil || len(users) != 2 || users[1].Enabled {
					t.Fatalf("ListUsers = %+v, %v; want root's list", users, err)
				}
				if !slices.Equal(sess.commands, []string{"pveum user list --full 1 --output-format json"}) {
					t.Errorf("root ran %q", sess.commands)
				}
				return
			}
			if err == nil {
				t.Fatalf("ListUsers = %+v, nil; want the token's error", users)
			}
			if opened(tr) != 0 {
				t.Errorf("root was dialed after a failure that is not a refusal")
			}
		})
	}
}

func TestRootAccess_ListGroups_NoTokenReadsAsRoot(t *testing.T) {
	sess := &fakeSession{byCmd: map[string]fakeRunResult{"pveum group list --output-format json": {res: RunResult{Stdout: `[{"groupid":"ops","users":"alice@pve"}]`}}}}
	a, _ := newAccess(sess, nil)
	groups, err := a.ListGroups(context.Background())
	if err != nil || len(groups) != 1 || groups[0].GroupID != "ops" {
		t.Fatalf("ListGroups = %+v, %v", groups, err)
	}
}

// The exact pveum lines: --enable always stated, groups appended on modify
// and set on add, every value quoted.
func TestRootAccess_UserAndGroupWrites(t *testing.T) {
	comment, email := "Ops team's", "a@example.com"
	sess := &fakeSession{}
	a, _ := newAccess(sess, nil)
	ctx := context.Background()
	for _, err := range []error{
		a.AddUser(ctx, idempotent.UserSpec{UserID: "alice@pve", Enable: true, Comment: &comment, Groups: []string{"dev", "ops"}}),
		a.ModifyUser(ctx, idempotent.UserSpec{UserID: "alice@pve", Enable: false, Email: &email, Groups: []string{"ops"}}),
		a.ModifyUser(ctx, idempotent.UserSpec{UserID: "bob@pve", Enable: true}),
		a.AddGroup(ctx, "ops", &comment),
		a.AddGroup(ctx, "dev", nil),
		a.ModifyGroup(ctx, "ops", "renamed"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		`pveum user add 'alice@pve' --enable 1 --comment 'Ops team'\''s' --groups 'dev,ops'`,
		`pveum user modify 'alice@pve' --enable 0 --email 'a@example.com' --groups 'ops' --append 1`,
		`pveum user modify 'bob@pve' --enable 1`,
		`pveum group add 'ops' --comment 'Ops team'\''s'`,
		`pveum group add 'dev'`,
		`pveum group modify 'ops' --comment 'renamed'`,
	}
	if !slices.Equal(sess.commands, want) {
		t.Errorf("commands =\n%q\nwant\n%q", sess.commands, want)
	}
}

func TestRootAccess_WriteFailureIsAnError(t *testing.T) {
	sess := &fakeSession{byCmd: map[string]fakeRunResult{"pveum user add": {res: RunResult{ExitCode: 255, Stderr: "user 'alice@pve' already exists"}}}}
	a, _ := newAccess(sess, nil)
	err := a.AddUser(context.Background(), idempotent.UserSpec{UserID: "alice@pve", Enable: true})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err = %v", err)
	}
}

// Keyless: the password is asked for only when root is first needed, and
// root is dialed as root with the host key trusted on first use.
func TestRootAccess_KeylessDialsRootWithThePassword(t *testing.T) {
	sess := &fakeSession{}
	tr := &fakeTransport{session: sess}
	asked := 0
	a := NewRootAccess(AccessOptions{Addr: "qa-pve-01:22", Password: func(context.Context) (string, error) { asked++; return "pw", nil }}, tr)
	if asked != 0 {
		t.Fatal("the password was asked for before root was needed")
	}
	if err := a.AddGroup(context.Background(), "ops", nil); err != nil {
		t.Fatal(err)
	}
	_ = a.AddGroup(context.Background(), "dev", nil)
	if asked != 1 || tr.dialPWCalls != 1 || tr.reconnectCalls != 0 {
		t.Errorf("asked %d, password dials %d, key dials %d; want 1, 1, 0", asked, tr.dialPWCalls, tr.reconnectCalls)
	}
	if !slices.Equal(tr.dialPWUsers, []string{"root"}) || !slices.Equal(tr.dialPWPins, []string{""}) || !slices.Equal(tr.dialPWPasswords, []string{"pw"}) {
		t.Errorf("dialed as %q with pins %q and passwords %q", tr.dialPWUsers, tr.dialPWPins, tr.dialPWPasswords)
	}
}

// ---- the grant ----

const (
	roleListAccess = `[{"roleid":"PVEVMUser","privs":"VM.Audit,VM.Console,VM.PowerMgmt"},` +
		`{"roleid":"PVEUserAdmin","privs":"User.Modify,Group.Allocate,Sys.Audit"},` +
		`{"roleid":"Administrator","privs":"Permissions.Modify,Sys.Modify,VM.Audit"},` +
		`{"roleid":"NoAccess","privs":""}]`
	groupListAccess = `[{"groupid":"ops","users":"alice@pve"},{"groupid":"automation","users":"alice@pve,PVEFORGE@pve"}]`
	// userListAccess holds the roster token's owner, in no group.
	userListAccess = `[{"userid":"pveforge@pve","enable":1,"groups":""},{"userid":"alice@pve","enable":1,"groups":"ops,automation"}]`
)

// grantSession answers the grant's reads; aclList is the read-back.
func grantSession(aclList string) *fakeSession {
	return &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum role list --output-format json":          {res: RunResult{Stdout: roleListAccess}},
		"pveum group list --output-format json":         {res: RunResult{Stdout: groupListAccess}},
		"pveum acl list --output-format json":           {res: RunResult{Stdout: aclList}},
		"pveum user list --full 1 --output-format json": {res: RunResult{Stdout: userListAccess}},
	}}
}

func mustGrants(t *testing.T, specs ...string) []Grant {
	t.Helper()
	gs, err := ParseGrants(specs)
	if err != nil {
		t.Fatal(err)
	}
	return gs
}

func TestRootAccess_GrantACL(t *testing.T) {
	acls := `[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0},` +
		`{"path":"/pool/lab","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":1}]`
	sess := grantSession(acls)
	a, _ := newAccess(sess, nil)
	out, err := a.GrantACL(context.Background(), GrantRequest{
		Principal: Principal{Kind: "group", ID: "ops"},
		Grants:    mustGrants(t, "/vms/100:PVEVMUser", "/pool/lab:PVEVMUser::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pveum role list --output-format json",
		"pveum group list --output-format json",
		"pveum user list --full 1 --output-format json",
		"pveum acl modify '/vms/100' --groups 'ops' --roles 'PVEVMUser' --propagate 0",
		"pveum acl modify '/pool/lab' --groups 'ops' --roles 'PVEVMUser' --propagate 1",
		"pveum acl list --output-format json",
	}
	if !slices.Equal(sess.commands, want) {
		t.Errorf("commands =\n%q\nwant\n%q", sess.commands, want)
	}
	if len(out.Entries) != 2 || out.Entries[1].Propagate != true || len(out.Escalating) != 0 {
		t.Errorf("outcome = %+v", out)
	}
}

// The principal flag matches its kind.
func TestRootAccess_GrantACL_PrincipalFlags(t *testing.T) {
	for kind, want := range map[string]string{
		"user":  "pveum acl modify '/vms/100' --users 'bob@pve' --roles 'PVEVMUser' --propagate 0",
		"token": "pveum acl modify '/vms/100' --tokens 'bob@pve!ci' --roles 'PVEVMUser' --propagate 0",
	} {
		id := map[string]string{"user": "bob@pve", "token": "bob@pve!ci"}[kind]
		sess := grantSession(`[{"path":"/vms/100","roleid":"PVEVMUser","type":"` + kind + `","ugid":"` + id + `","propagate":0}]`)
		a, _ := newAccess(sess, nil)
		if _, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{Kind: kind, ID: id}, Grants: mustGrants(t, "/vms/100:PVEVMUser")}); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !slices.Contains(sess.commands, want) {
			t.Errorf("%s: commands %q lack %q", kind, sess.commands, want)
		}
	}
}

// Every refusal leaves the ACLs untouched: no acl modify is ever run. The
// self refusals for a token or its user fire before root is even dialed.
func TestRootAccess_GrantACL_Refusals(t *testing.T) {
	cases := []struct {
		name       string
		principal  Principal
		grants     []string
		allowEsc   bool
		wantIs     error
		wantNoDial bool
	}{
		{"the roster's own token", Principal{"token", accessOwnToken}, []string{"/vms/100:PVEVMUser"}, false, ErrSelfGrant, true},
		{"the roster's own token, other case", Principal{"token", "PVEFORGE@pve!automation"}, []string{"/vms/100:PVEVMUser"}, false, ErrSelfGrant, true},
		{"the user owning it", Principal{"user", "pveforge@pve"}, []string{"/vms/100:PVEVMUser"}, false, ErrSelfGrant, true},
		{"self even with the flag", Principal{"user", "pveforge@pve"}, []string{"/vms/100:PVEVMUser"}, true, ErrSelfGrant, true},
		{"a group holding that user", Principal{"group", "automation"}, []string{"/vms/100:PVEVMUser"}, false, ErrSelfGrant, false},
		{"an unknown group", Principal{"group", "nosuch"}, []string{"/vms/100:PVEVMUser"}, false, ErrUnknownGroup, false},
		{"an escalating role", Principal{"user", "bob@pve"}, []string{"/:Administrator"}, false, ErrEscalatingRole, false},
		{"User.Modify alone escalates", Principal{"user", "bob@pve"}, []string{"/access:PVEUserAdmin"}, false, ErrEscalatingRole, false},
		{"escalating pinned privileges", Principal{"user", "bob@pve"}, []string{"/:Administrator:Permissions.Modify,Sys.Modify,VM.Audit"}, false, ErrEscalatingRole, false},
		{"an unknown role", Principal{"user", "bob@pve"}, []string{"/:NoSuchRole"}, false, ErrUnknownRole, false},
		{"a role with no privileges", Principal{"user", "bob@pve"}, []string{"/:NoAccess"}, false, ErrRoleHasNoPrivileges, false},
		{"pinned privileges not the role's", Principal{"user", "bob@pve"}, []string{"/vms/100:PVEVMUser:VM.Audit"}, false, ErrPinnedPrivsMismatch, false},
		{"a malformed user", Principal{"user", "bob"}, []string{"/vms/100:PVEVMUser"}, false, pve.ErrInvalidPrincipal, true},
		{"a malformed token", Principal{"token", "bob@pve"}, []string{"/vms/100:PVEVMUser"}, false, pve.ErrInvalidPrincipal, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sess := grantSession(`[]`)
			a, tr := newAccess(sess, nil)
			_, err := a.GrantACL(context.Background(), GrantRequest{Principal: c.principal, Grants: mustGrants(t, c.grants...), AllowEscalatingRole: c.allowEsc})
			if !errors.Is(err, c.wantIs) {
				t.Fatalf("err = %v, want %v", err, c.wantIs)
			}
			for _, cmd := range sess.commands {
				if strings.HasPrefix(cmd, "pveum acl modify") {
					t.Errorf("an ACL was changed: %q", cmd)
				}
			}
			if c.wantNoDial && opened(tr) != 0 {
				t.Errorf("root was dialed for a refusal that needs no read")
			}
		})
	}
}

func TestRootAccess_GrantACL_EscalatingAllowed(t *testing.T) {
	sess := grantSession(`[{"path":"/","roleid":"Administrator","type":"user","ugid":"bob@pve","propagate":0}]`)
	a, _ := newAccess(sess, nil)
	out, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/:Administrator"), AllowEscalatingRole: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Escalating) != 1 || !slices.Equal(out.Escalating[0].Privs, []string{"Permissions.Modify", "Sys.Modify"}) {
		t.Errorf("escalating = %+v", out.Escalating)
	}
	if !slices.Contains(sess.commands, "pveum acl modify '/' --users 'bob@pve' --roles 'Administrator' --propagate 0") {
		t.Errorf("commands %q", sess.commands)
	}
}

// The read-back must hold the exact entry: a different propagate, role,
// principal type or path is not the grant.
func TestRootAccess_GrantACL_ReadBackMustBeExact(t *testing.T) {
	for name, acls := range map[string]string{
		"absent":            `[]`,
		"propagate differs": `[{"path":"/vms/100","roleid":"PVEVMUser","type":"user","ugid":"bob@pve","propagate":1}]`,
		"role differs":      `[{"path":"/vms/100","roleid":"PVEVMAdmin","type":"user","ugid":"bob@pve","propagate":0}]`,
		"type differs":      `[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"bob@pve","propagate":0}]`,
		"path differs":      `[{"path":"/vms/101","roleid":"PVEVMUser","type":"user","ugid":"bob@pve","propagate":0}]`,
		"principal differs": `[{"path":"/vms/100","roleid":"PVEVMUser","type":"user","ugid":"carol@pve","propagate":0}]`,
		"unreadable":        `null`,
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := newAccess(grantSession(acls), nil)
			_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")})
			if err == nil {
				t.Fatal("the grant was reported done")
			}
			if name != "unreadable" && !errors.Is(err, ErrGrantNotConfirmed) {
				t.Errorf("err = %v, want ErrGrantNotConfirmed", err)
			}
		})
	}
}

// operatorEscalating is the operator's list (2026-09-24), written out here
// independently of EscalatingPrivileges, so a privilege dropped from the
// code's list cannot take its own test case with it.
var operatorEscalating = []string{
	"Permissions.Modify", "User.Modify", "Sys.Modify", "Realm.Allocate",
	"Sys.Console", "VM.Monitor", "Realm.AllocateUser", "Datastore.Allocate", "Mapping.Modify",
}

func TestEscalatingPrivileges_AreTheOperatorsNine(t *testing.T) {
	got, want := slices.Clone(EscalatingPrivileges), slices.Clone(operatorEscalating)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("EscalatingPrivileges = %q, want exactly the operator's %q", EscalatingPrivileges, operatorEscalating)
	}
}

// Each escalating privilege, on its own, makes a role escalating for a
// grant.
func TestRootAccess_GrantACL_EachEscalatingPrivilege(t *testing.T) {
	for _, priv := range operatorEscalating {
		t.Run(priv, func(t *testing.T) {
			sess := grantSession(`[]`)
			sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"roleid":"OneEsc","privs":"VM.Audit,` + priv + `"}]`}}
			a, _ := newAccess(sess, nil)
			_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:OneEsc")})
			if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), priv) {
				t.Errorf("err = %v, want ErrEscalatingRole naming %s", err, priv)
			}
		})
	}
}

// Each escalating privilege, on its own, makes a group escalating to join.
func TestRootAccess_CheckGroupJoin_EachEscalatingPrivilege(t *testing.T) {
	for _, priv := range operatorEscalating {
		t.Run(priv, func(t *testing.T) {
			sess := grantSession(`[{"path":"/vms/100","roleid":"OneEsc","type":"group","ugid":"ops","propagate":0}]`)
			sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"roleid":"OneEsc","privs":"VM.Audit,` + priv + `"}]`}}
			a, _ := newAccess(sess, nil)
			_, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"ops"}, false)
			if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), priv) {
				t.Errorf("err = %v, want ErrEscalatingRole naming %s", err, priv)
			}
		})
	}
}

// SR4: the roster token's owning user is refused in any case spelling.
func TestRootAccess_GrantACL_OwnerCaseVariant(t *testing.T) {
	sess := grantSession(`[]`)
	a, tr := newAccess(sess, nil)
	_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "PVEFORGE@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")})
	if !errors.Is(err, ErrSelfGrant) || opened(tr) != 0 {
		t.Errorf("err = %v, dials %d; want ErrSelfGrant before any dial", err, opened(tr))
	}
}

// SR2: the group self-check fails closed. A group whose members field is
// missing or null is not "no members"; the owner's own groups, from the full
// user list, are checked too; an owner the user list does not have is a
// refusal.
func TestRootAccess_GrantACL_GroupSelfCheckFailsClosed(t *testing.T) {
	cases := []struct {
		name, groups, users string
		wantSelf            bool
	}{
		{"members field missing", `[{"groupid":"ops"}]`, userListAccess, false},
		{"members field null", `[{"groupid":"ops","users":null}]`, userListAccess, false},
		{"owner listed only on its own user entry", `[{"groupid":"ops","users":""}]`, `[{"userid":"pveforge@pve","enable":1,"groups":"ops"}]`, true},
		{"owner missing from the user list", `[{"groupid":"ops","users":"alice@pve"}]`, `[{"userid":"alice@pve","enable":1}]`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sess := grantSession(`[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0}]`)
			sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: c.groups}}
			sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: c.users}}
			a, _ := newAccess(sess, nil)
			_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"group", "ops"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")})
			if c.wantSelf && !errors.Is(err, ErrSelfGrant) {
				t.Errorf("err = %v, want ErrSelfGrant", err)
			}
			if !c.wantSelf && !errors.Is(err, pve.ErrUnverifiableRead) {
				t.Errorf("err = %v, want an unverifiable read", err)
			}
			for _, cmd := range sess.commands {
				if strings.HasPrefix(cmd, "pveum acl modify") {
					t.Errorf("an ACL was changed: %q", cmd)
				}
			}
		})
	}
}

// SR1: joining a group is a grant.
func TestRootAccess_CheckGroupJoin(t *testing.T) {
	acls := `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1},` +
		`{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0},` +
		`{"path":"/","roleid":"Administrator","type":"user","ugid":"ops","propagate":0}]`
	t.Run("the owner may join no group, before any dial", func(t *testing.T) {
		a, tr := newAccess(grantSession(acls), nil)
		_, err := a.CheckGroupJoin(context.Background(), "PVEFORGE@pve", []string{"ops"}, true)
		if !errors.Is(err, ErrSelfGrant) || opened(tr) != 0 {
			t.Errorf("err = %v, dials %d", err, opened(tr))
		}
	})
	t.Run("a group holding an escalating role", func(t *testing.T) {
		a, _ := newAccess(grantSession(acls), nil)
		_, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"ops", "admins"}, false)
		if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), "admins holds Administrator on /") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("allowed, and reported", func(t *testing.T) {
		a, _ := newAccess(grantSession(acls), nil)
		joins, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"admins"}, true)
		if err != nil || len(joins) != 1 || joins[0].Group != "admins" || !slices.Equal(joins[0].Privs, []string{"Permissions.Modify", "Sys.Modify"}) {
			t.Errorf("joins = %+v, %v", joins, err)
		}
	})
	t.Run("a harmless group; a user entry of the same name is not the group's", func(t *testing.T) {
		a, _ := newAccess(grantSession(acls), nil)
		if joins, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"ops"}, false); err != nil || joins != nil {
			t.Errorf("joins = %+v, %v", joins, err)
		}
	})
	// M5, M13: an escalating role on a path other than / is as much a
	// grant, and every escalating holding of every group is named.
	nonRoot := `[{"path":"/pool/x","roleid":"PVEPoolAdmin","type":"group","ugid":"pooladm","propagate":1},` +
		`{"path":"/vms/100","roleid":"PVEVMAdmin","type":"group","ugid":"vmadm","propagate":0},` +
		`{"path":"/pool/x","roleid":"Administrator","type":"group","ugid":"vmadm","propagate":1}]`
	nonRootRoles := `[{"roleid":"PVEPoolAdmin","privs":"Pool.Allocate,Pool.Audit,Permissions.Modify"},` +
		`{"roleid":"PVEVMAdmin","privs":"VM.Audit,VM.Allocate,Permissions.Modify"},` +
		`{"roleid":"Administrator","privs":"Permissions.Modify,Sys.Modify"}]`
	nonRootSession := func() *fakeSession {
		sess := grantSession(nonRoot)
		sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: nonRootRoles}}
		return sess
	}
	for _, c := range []struct{ group, want string }{
		{"pooladm", "group pooladm holds PVEPoolAdmin on /pool/x, which confers Permissions.Modify"},
		{"vmadm", "group vmadm holds PVEVMAdmin on /vms/100, which confers Permissions.Modify"},
	} {
		t.Run("an escalating role on "+c.group+"'s non-root path", func(t *testing.T) {
			a, _ := newAccess(nonRootSession(), nil)
			_, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{c.group}, false)
			if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want ErrEscalatingRole naming %q", err, c.want)
			}
		})
	}
	t.Run("every escalating holding is refused by name, and reported when allowed", func(t *testing.T) {
		a, _ := newAccess(nonRootSession(), nil)
		_, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"pooladm", "vmadm"}, false)
		for _, want := range []string{"pooladm holds PVEPoolAdmin on /pool/x", "vmadm holds PVEVMAdmin on /vms/100", "vmadm holds Administrator on /pool/x"} {
			if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to name %q", err, want)
			}
		}
		a, _ = newAccess(nonRootSession(), nil)
		joins, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"pooladm", "vmadm"}, true)
		var got []string
		for _, j := range joins {
			got = append(got, j.Group+" "+j.Entry.Role+" "+j.Entry.Path)
		}
		if want := []string{"pooladm PVEPoolAdmin /pool/x", "vmadm PVEVMAdmin /vms/100", "vmadm Administrator /pool/x"}; err != nil || !slices.Equal(got, want) {
			t.Errorf("joins = %q, %v; want %q", got, err, want)
		}
	})
	t.Run("a role the role list lacks", func(t *testing.T) {
		a, _ := newAccess(grantSession(`[{"path":"/","roleid":"Ghost","type":"group","ugid":"ops","propagate":0}]`), nil)
		if _, err := a.CheckGroupJoin(context.Background(), "alice@pve", []string{"ops"}, true); !errors.Is(err, pve.ErrUnverifiableRead) {
			t.Errorf("err = %v", err)
		}
	})
}

// A grant that fails part way says which grants were already applied.
func TestRootAccess_GrantACL_PartialFailureNamesWhatWasApplied(t *testing.T) {
	sess := grantSession(`[]`)
	sess.byCmd["pveum acl modify '/pool/lab'"] = fakeRunResult{res: RunResult{ExitCode: 2, Stderr: "boom"}}
	a, _ := newAccess(sess, nil)
	_, err := a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser", "/pool/lab:PVEVMUser")})
	if err == nil || !strings.Contains(err.Error(), "grant 2 of 2 (PVEVMUser on /pool/lab) failed, already applied: PVEVMUser on /vms/100") {
		t.Errorf("err = %v", err)
	}
	sess2 := grantSession(`[]`)
	sess2.byCmd["pveum acl modify '/vms/100'"] = fakeRunResult{res: RunResult{ExitCode: 2, Stderr: "boom"}}
	a, _ = newAccess(sess2, nil)
	_, err = a.GrantACL(context.Background(), GrantRequest{Principal: Principal{"user", "bob@pve"}, Grants: mustGrants(t, "/vms/100:PVEVMUser")})
	if err == nil || !strings.Contains(err.Error(), "none was applied") {
		t.Errorf("err = %v", err)
	}
}

// An id beginning with '-' would reach pveum as an option.
func TestCheckPrincipal_RefusesALeadingDash(t *testing.T) {
	for _, p := range []Principal{{"user", "-rf@pve"}, {"group", "-g"}, {"token", "-x@pve!ci"}} {
		if err := CheckPrincipal(p); !errors.Is(err, pve.ErrInvalidPrincipal) {
			t.Errorf("%v: %v", p, err)
		}
	}
	for _, p := range []Principal{{"user", "a-b@pve"}, {"group", "a-b"}, {"token", "a@pve!t-1"}} {
		if err := CheckPrincipal(p); err != nil {
			t.Errorf("%v: %v", p, err)
		}
	}
}
