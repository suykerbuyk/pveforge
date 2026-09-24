package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
)

// Inventory, 6b: every list is read as root, never with the token; each
// @pam user is looked up on the node in one getent call.

const (
	invUsers = `[{"userid":"root@pam","enable":1,"groups":"admins"},` +
		`{"userid":"alice@pam","enable":1,"groups":"ops"},` +
		`{"userid":"Bob@pam","enable":0,"groups":""},` +
		`{"userid":"carol@pve","enable":1,"groups":"ops","comment":"Carol"},` +
		`{"userid":"dave@spam","enable":1,"groups":[]}]`
	invGroups = `[{"groupid":"ops","users":"alice@pam,carol@pve"},{"groupid":"admins","users":"root@pam"},{"groupid":"ghost"}]`
	invACLs   = `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1},` +
		`{"path":"/pool/lab","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":1},` +
		`{"path":"/vms/100","roleid":"PVEVMUser","type":"user","ugid":"alice@pam","propagate":0},` +
		`{"path":"/","roleid":"PVEVMAdmin","type":"token","ugid":"root@pam!pveforge","propagate":1}]`
	invRoles = `[{"roleid":"Administrator","privs":"Permissions.Modify,Sys.Modify,VM.Audit"},` +
		`{"roleid":"PVEVMUser","privs":"VM.Audit,VM.Console"},{"roleid":"PVEVMAdmin","privs":"VM.Allocate,VM.Monitor"}]`
	invGetent    = "getent passwd -- 'root' 'alice' 'Bob'"
	invRootLine  = "root:x:0:0:root:/root:/bin/bash\n"
	invAliceLine = "alice:x:1000:1000:Alice,,,:/home/alice:\n"
)

func invSession(getent fakeRunResult) *fakeSession {
	return &fakeSession{byCmd: map[string]fakeRunResult{
		"pveum user list --full 1 --output-format json": {res: RunResult{Stdout: invUsers}},
		"pveum group list --output-format json":         {res: RunResult{Stdout: invGroups}},
		"pveum acl list --output-format json":           {res: RunResult{Stdout: invACLs}},
		"pveum role list --output-format json":          {res: RunResult{Stdout: invRoles}},
		"getent passwd":                                 getent,
	}}
}

func invUser(t *testing.T, inv *AccessInventory, id string) InventoryUser {
	t.Helper()
	i := slices.IndexFunc(inv.Users, func(u InventoryUser) bool { return u.UserID == id })
	if i < 0 {
		t.Fatalf("no user %s in %+v", id, inv.Users)
	}
	return inv.Users[i]
}

// The whole read: exactly these commands, in this order, all reads, and the
// token never asked (a token's view may be a shorter list with 200).
func TestInventory_ReadsEverythingAsRoot(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}})
	rest := &fakeREST{}
	a, _ := newAccess(sess, rest)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pveum user list --full 1 --output-format json",
		"pveum group list --output-format json",
		"pveum acl list --output-format json",
		"pveum role list --output-format json",
		invGetent,
	}
	if !slices.Equal(sess.commands, want) {
		t.Errorf("root ran\n%q\nwant\n%q", sess.commands, want)
	}
	if rest.calls != 0 {
		t.Errorf("the token was asked %d times", rest.calls)
	}
	if len(inv.Users) != 5 || len(inv.Groups) != 3 || len(inv.ACLs) != 4 {
		t.Fatalf("inventory = %d users, %d groups, %d acls", len(inv.Users), len(inv.Groups), len(inv.ACLs))
	}
}

// The OS join: found, absent (exit 2), and not-pam for every other realm,
// including one merely ending in "pam". Names match exactly: Bob is not bob.
func TestInventory_OSAccountJoin(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}})
	a, _ := newAccess(sess, nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	alice := invUser(t, inv, "alice@pam")
	if alice.OSAccountStatus != OSAccountFound || alice.OSAccount == nil ||
		*alice.OSAccount != (OSAccount{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: ""}) {
		t.Errorf("alice = %s %+v", alice.OSAccountStatus, alice.OSAccount)
	}
	if bob := invUser(t, inv, "Bob@pam"); bob.OSAccountStatus != OSAccountAbsent || bob.OSAccount != nil {
		t.Errorf("Bob = %s %+v", bob.OSAccountStatus, bob.OSAccount)
	}
	for _, id := range []string{"carol@pve", "dave@spam"} {
		if u := invUser(t, inv, id); u.OSAccountStatus != OSAccountNotPAM || u.OSAccount != nil {
			t.Errorf("%s = %s %+v", id, u.OSAccountStatus, u.OSAccount)
		}
	}
	if u := invUser(t, inv, "dave@spam"); u.Realm != "spam" {
		t.Errorf("dave's realm = %q", u.Realm)
	}
}

// A @pam account whose name differs only in case is not the user's: the
// node's names are case-sensitive.
func TestInventory_OSJoinIsCaseSensitive(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine + "bob:x:1001:1001::/home/bob:/bin/sh\n", ExitCode: 2}})
	a, _ := newAccess(sess, nil)
	_, err := a.Inventory(context.Background())
	if !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), `"bob", which was not asked for`) {
		t.Fatalf("err = %v; want bob refused as not asked for", err)
	}
}

// getent's exit status must agree with what it printed; any status but 0
// or 2 is an error, never "no accounts".
func TestInventory_GetentExitStatus(t *testing.T) {
	all := invRootLine + invAliceLine + "Bob:x:1002:1002::/home/Bob:/bin/sh\n"
	for _, c := range []struct {
		name   string
		res    RunResult
		ok     bool
		errHas string
	}{
		{"0, all found", RunResult{Stdout: all}, true, ""},
		{"2, some missing", RunResult{Stdout: invRootLine, ExitCode: 2}, true, ""},
		{"2, none found", RunResult{ExitCode: 2}, true, ""},
		{"0 but one missing", RunResult{Stdout: invRootLine + invAliceLine}, false, "exited 0 but printed 2 of the 3"},
		{"2 but none missing", RunResult{Stdout: all, ExitCode: 2}, false, "exited 2 but printed 3 of the 3"},
		{"1", RunResult{Stdout: all, ExitCode: 1, Stderr: "Unknown database"}, false, "getent passwd exited 1: Unknown database"},
		{"127", RunResult{ExitCode: 127, Stderr: "not found"}, false, "exited 127"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, _ := newAccess(invSession(fakeRunResult{res: c.res}), nil)
			inv, err := a.Inventory(context.Background())
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, u := range inv.Users {
					if u.OSAccountStatus == OSAccountFound {
						found++
					}
				}
				if want := strings.Count(c.res.Stdout, "\n"); found != want {
					t.Errorf("found %d accounts, want %d", found, want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("err = %v, want %q", err, c.errHas)
			}
		})
	}
}

func TestInventory_GetentTransportErrorIsAnError(t *testing.T) {
	a, _ := newAccess(invSession(fakeRunResult{err: errors.New("session dropped")}), nil)
	if _, err := a.Inventory(context.Background()); err == nil || !strings.Contains(err.Error(), "session dropped") {
		t.Fatalf("err = %v", err)
	}
}

// A line getent should never print is an unverifiable read, never skipped.
func TestInventory_MalformedPasswdLine(t *testing.T) {
	for name, line := range map[string]string{
		"six fields":  "alice:x:1000:1000:/home/alice:/bin/sh\n",
		"bad uid":     "alice:x:-1:1000::/home/alice:/bin/sh\n",
		"bad gid":     "alice:x:1000:g::/home/alice:/bin/sh\n",
		"not asked":   "mallory:x:0:0::/root:/bin/sh\n",
		"repeated":    invAliceLine + invAliceLine,
		"blank line":  invAliceLine + "\n",
		"eight field": "alice:x:1000:1000::/home/alice:/bin/sh:x\n",
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := newAccess(invSession(fakeRunResult{res: RunResult{Stdout: line, ExitCode: 2}}), nil)
			if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) {
				t.Fatalf("err = %v, want ErrUnverifiableRead", err)
			}
		})
	}
}

// getent runs once for every @pam user together, and not at all when there
// is none.
func TestInventory_GetentCallCount(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}})
	a, _ := newAccess(sess, nil)
	if _, err := a.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(sess.commands, "getent"); n != 1 {
		t.Errorf("getent ran %d times for three @pam users, want 1", n)
	}

	sess = invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"userid":"carol@pve","enable":1,"groups":""}]`}}
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[]`}}
	a, _ = newAccess(sess, nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(sess.commands, "getent"); n != 0 {
		t.Errorf("getent ran %d times with no @pam user, want 0", n)
	}
	if inv.Users[0].OSAccountStatus != OSAccountNotPAM {
		t.Errorf("carol = %s", inv.Users[0].OSAccountStatus)
	}
}

func countPrefix(cmds []string, prefix string) int {
	n := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// A @pam user id that is not a well-formed id is refused before getent.
func TestInventory_MalformedPAMUserRefused(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"userid":"-x@pam","enable":1,"groups":""}]`}}
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[]`}}
	a, _ := newAccess(sess, nil)
	if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrInvalidPrincipal) {
		t.Fatalf("err = %v", err)
	}
	if countPrefix(sess.commands, "getent") != 0 {
		t.Errorf("getent ran: %q", sess.commands)
	}
}

// The ACL joins: a user's own entries, then each of its groups' marked via
// the group; a group's own; every entry, tokens' included, at top level;
// each flagged with the escalating privileges its role confers.
func TestInventory_ACLJoins(t *testing.T) {
	a, _ := newAccess(invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}}), nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vmUser := InventoryACL{Path: "/pool/lab", Role: "PVEVMUser", Type: "group", UGID: "ops", Propagate: true}
	opsVia := vmUser
	opsVia.Via = "ops"
	aliceOwn := InventoryACL{Path: "/vms/100", Role: "PVEVMUser", Type: "user", UGID: "alice@pam"}
	admin := InventoryACL{Path: "/", Role: "Administrator", Type: "group", UGID: "admins", Propagate: true, Escalating: []string{"Permissions.Modify", "Sys.Modify"}}
	adminVia := admin
	adminVia.Via = "admins"
	token := InventoryACL{Path: "/", Role: "PVEVMAdmin", Type: "token", UGID: "root@pam!pveforge", Propagate: true, Escalating: []string{"VM.Monitor"}}

	for _, c := range []struct {
		name string
		got  []InventoryACL
		want []InventoryACL
	}{
		{"alice", invUser(t, inv, "alice@pam").ACLs, []InventoryACL{aliceOwn, opsVia}},
		{"carol", invUser(t, inv, "carol@pve").ACLs, []InventoryACL{opsVia}},
		{"root", invUser(t, inv, "root@pam").ACLs, []InventoryACL{adminVia}},
		{"Bob", invUser(t, inv, "Bob@pam").ACLs, []InventoryACL{}},
		{"group ops", inv.Groups[0].ACLs, []InventoryACL{vmUser}},
		{"group admins", inv.Groups[1].ACLs, []InventoryACL{admin}},
		{"all", inv.ACLs, []InventoryACL{admin, vmUser, aliceOwn, token}},
	} {
		if !aclsEqual(c.got, c.want) {
			t.Errorf("%s: acls =\n%+v\nwant\n%+v", c.name, c.got, c.want)
		}
	}
}

func aclsEqual(a, b []InventoryACL) bool {
	return slices.EqualFunc(a, b, func(x, y InventoryACL) bool {
		return x.Path == y.Path && x.Role == y.Role && x.Type == y.Type && x.UGID == y.UGID &&
			x.Propagate == y.Propagate && x.Via == y.Via && slices.Equal(x.Escalating, y.Escalating)
	})
}

// Every one of the nine escalating privileges is flagged, alone.
func TestInventory_EachEscalatingPrivilegeFlagged(t *testing.T) {
	for _, p := range EscalatingPrivileges {
		sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}})
		sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"roleid":"Administrator","privs":"VM.Audit"},{"roleid":"PVEVMUser","privs":"VM.Audit,` + p + `"},{"roleid":"PVEVMAdmin","privs":"VM.Audit"}]`}}
		a, _ := newAccess(sess, nil)
		inv, err := a.Inventory(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := inv.ACLs[1].Escalating; !slices.Equal(got, []string{p}) {
			t.Errorf("%s: flagged %q", p, got)
		}
		if got := inv.ACLs[0].Escalating; got != nil {
			t.Errorf("%s: a role without it flagged %q", p, got)
		}
	}
}

// A role the role list does not have is an unverifiable read.
func TestInventory_UnknownRole(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"roleid":"PVEVMUser","privs":"VM.Audit"}]`}}
	a, _ := newAccess(sess, nil)
	if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), "Administrator") {
		t.Fatalf("err = %v", err)
	}
}

// Members: null when the group list carried none (unknown), [] when it
// carried an empty list, never one for the other. Groups and ACLs are
// always lists.
func TestInventory_MembersNullWhenUnlisted(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: invRootLine + invAliceLine, ExitCode: 2}})
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"groupid":"ops","users":"alice@pam,carol@pve"},{"groupid":"admins","users":"root@pam"},{"groupid":"empty","users":""},{"groupid":"ghost"}]`}}
	a, _ := newAccess(sess, nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(inv.Groups)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"groupid":"empty","members":[]`, `"groupid":"ghost","members":null`, `"groupid":"ops","members":["alice@pam","carol@pve"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("groups = %s\nwant %s", b, want)
		}
	}
	b, _ = json.Marshal(invUser(t, inv, "Bob@pam"))
	if !strings.Contains(string(b), `"groups":[],"acls":[]`) {
		t.Errorf("Bob = %s", b)
	}
}

// A failed list read fails the inventory; it is never an empty list.
func TestInventory_ListReadFailureIsAnError(t *testing.T) {
	for _, cmd := range []string{
		"pveum user list --full 1 --output-format json",
		"pveum group list --output-format json",
		"pveum acl list --output-format json",
		"pveum role list --output-format json",
	} {
		sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
		sess.byCmd[cmd] = fakeRunResult{res: RunResult{ExitCode: 255, Stderr: "boom"}}
		a, _ := newAccess(sess, nil)
		if _, err := a.Inventory(context.Background()); err == nil {
			t.Errorf("%s failing: no error", cmd)
		}
	}
}

// F1: via-group ACL entries come from the user list's groups field, so a
// user without one, or the two lists disagreeing on membership in either
// direction, is an unverifiable read, never a user shown holding less.
func TestInventory_MembershipMustAgree(t *testing.T) {
	adminACL := `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1}]`
	for _, c := range []struct {
		name, users, groups, errHas string
	}{
		{"user has no groups field (the reviewer's case)",
			`[{"userid":"alice@pve","enable":1}]`, `[{"groupid":"admins","users":"alice@pve"}]`,
			"carries no groups field for alice@pve"},
		{"user has a null groups field",
			`[{"userid":"alice@pve","enable":1,"groups":null}]`, `[{"groupid":"admins","users":""}]`,
			"carries no groups field for alice@pve"},
		{"group lists a member whose groups omit it",
			`[{"userid":"alice@pve","enable":1,"groups":""}]`, `[{"groupid":"admins","users":"alice@pve"}]`,
			"group admins lists member alice@pve, whose groups do not include it"},
		{"group lists a member the user list lacks",
			`[{"userid":"alice@pve","enable":1,"groups":""}]`, `[{"groupid":"admins","users":"mallory@pve"}]`,
			"group admins lists member mallory@pve, which the user list does not have"},
		{"user names a group whose members omit it",
			`[{"userid":"alice@pve","enable":1,"groups":"admins"}]`, `[{"groupid":"admins","users":""}]`,
			"puts alice@pve in group admins, whose members do not include it"},
		{"user names a group the group list lacks",
			`[{"userid":"alice@pve","enable":1,"groups":"admins"}]`, `[]`,
			"puts alice@pve in group admins, which the group list does not have"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
			sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: c.users}}
			sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: c.groups}}
			sess.byCmd["pveum acl list --output-format json"] = fakeRunResult{res: RunResult{Stdout: adminACL}}
			a, _ := newAccess(sess, nil)
			if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("err = %v, want %q", err, c.errHas)
			}
		})
	}
	// Control: agreeing lists, and a group whose members are not listed
	// (null, unknown) checked from the user side alone.
	sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"userid":"alice@pve","enable":1,"groups":"admins,ghost"}]`}}
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"groupid":"admins","users":"alice@pve"},{"groupid":"ghost"}]`}}
	sess.byCmd["pveum acl list --output-format json"] = fakeRunResult{res: RunResult{Stdout: adminACL}}
	a, _ := newAccess(sess, nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if acls := inv.Users[0].ACLs; len(acls) != 1 || acls[0].Via != "admins" || len(acls[0].Escalating) == 0 {
		t.Errorf("alice's acls = %+v", acls)
	}
}

// F2: getent reads a key strtoul parses whole as a UID, so such a name is
// never sent: it is "unchecked". A name merely holding digits is sent.
func TestInventory_NumericNamesUnchecked(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{Stdout: "a1:x:1001:1001::/home/a1:/bin/sh\n"}})
	sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[` +
		`{"userid":"0@pam","enable":1,"groups":""},{"userid":"1000@pam","enable":1,"groups":""},` +
		`{"userid":"+5@pam","enable":1,"groups":""},{"userid":"a1@pam","enable":1,"groups":""}]`}}
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[]`}}
	a, _ := newAccess(sess, nil)
	inv, err := a.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(sess.commands, "getent"); n != 1 || !slices.Contains(sess.commands, "getent passwd -- 'a1'") {
		t.Errorf("root ran %q; want getent for a1 alone", sess.commands)
	}
	for _, id := range []string{"0@pam", "1000@pam", "+5@pam"} {
		if u := invUser(t, inv, id); u.OSAccountStatus != OSAccountUnchecked || u.OSAccount != nil {
			t.Errorf("%s = %s %+v", id, u.OSAccountStatus, u.OSAccount)
		}
	}
	if u := invUser(t, inv, "a1@pam"); u.OSAccountStatus != OSAccountFound {
		t.Errorf("a1 = %s", u.OSAccountStatus)
	}

	// Only numeric @pam users: getent is not run at all.
	sess = invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum user list --full 1 --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[{"userid":"0@pam","enable":1,"groups":""}]`}}
	sess.byCmd["pveum group list --output-format json"] = fakeRunResult{res: RunResult{Stdout: `[]`}}
	a, _ = newAccess(sess, nil)
	if _, err := a.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := countPrefix(sess.commands, "getent"); n != 0 {
		t.Errorf("getent ran for a numeric name alone: %q", sess.commands)
	}
}

func TestNumericKey(t *testing.T) {
	for name, want := range map[string]bool{"0": true, "1000": true, "+5": true, "": false, "+": false, "a1": false, "1a": false, "1.0": false, "0x10": false} {
		if got := numericKey(name); got != want {
			t.Errorf("numericKey(%q) = %v, want %v", name, got, want)
		}
	}
}

// S3: a role listed twice is an unverifiable read, for the inventory and
// for 6a's grant checks alike (allRolePrivs is shared).
func TestInventory_DuplicateRoleRefused(t *testing.T) {
	sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
	sess.byCmd["pveum role list --output-format json"] = fakeRunResult{res: RunResult{Stdout: invRoles[:len(invRoles)-1] + `,{"roleid":"PVEVMUser","privs":"VM.Audit,Permissions.Modify"}]`}}
	a, _ := newAccess(sess, nil)
	if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), "role PVEVMUser is listed twice") {
		t.Fatalf("err = %v", err)
	}
}

// S3: a user or group listed twice, or a group repeated in a user's
// groups, fails the inventory (refused by the shared parsers).
func TestInventory_DuplicatePrincipalsRefused(t *testing.T) {
	for name, c := range map[string]struct{ cmd, out string }{
		"user twice":    {"pveum user list --full 1 --output-format json", `[{"userid":"a@pve","enable":1,"groups":""},{"userid":"a@pve","enable":1,"groups":""}]`},
		"group twice":   {"pveum group list --output-format json", `[{"groupid":"ops","users":""},{"groupid":"ops","users":""}]`},
		"user group x2": {"pveum user list --full 1 --output-format json", `[{"userid":"a@pve","enable":1,"groups":"ops,ops"}]`},
	} {
		sess := invSession(fakeRunResult{res: RunResult{ExitCode: 2}})
		sess.byCmd[c.cmd] = fakeRunResult{res: RunResult{Stdout: c.out}}
		a, _ := newAccess(sess, nil)
		if _, err := a.Inventory(context.Background()); !errors.Is(err, pve.ErrUnverifiableRead) || !strings.Contains(err.Error(), "listed twice") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
