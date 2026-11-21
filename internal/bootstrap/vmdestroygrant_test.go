package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// Tests for `acl enable-vm-destroy` (plan roles-grants-plan-FINAL.md). Each
// named invariant is pinned by a test that calls the guard or screen
// DIRECTLY; the scenario sweep (T2) then proves that no outcome of the whole
// verb sends anything those guards would refuse. Every test asserts a
// positive precondition first (a command ran, a file was hashed) so a green
// result cannot be an empty one.

var (
	vmD       = deriveD() // the derived set for the default fake: vmAdmin23 + Sys.Audit, sorted
	vmDJoined = strings.Join(vmD, ",")
)

// deriveD builds D by hand (not through deriveRoleSet, so a mutant of the
// code under test cannot panic package initialisation and turn a named test
// into an unnamed red package).
func deriveD() []string {
	d := append(slices.Clone(vmAdmin23), "Sys.Audit")
	sort.Strings(d)
	return d
}

func hashFile(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

var allVerdicts = []error{pve.ErrWrongScope, pve.ErrScopeTooWide, pve.ErrNoGrants, pve.ErrNotAuthorized}

// noVerdict asserts err wraps no verdict sentinel, by isVerdict (the function
// bootstrap's token phase asks, in this package) and by errors.Is on each.
func noVerdict(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if isVerdict(err) {
		t.Errorf("%s: isVerdict(err) is true: %v", name, err)
	}
	for _, v := range allVerdicts {
		if errors.Is(err, v) {
			t.Errorf("%s: err wraps %v: %v", name, v, err)
		}
	}
}

// screenedWrites parses every mutating command the fake received with a REAL
// shell and runs the screen on the argv it produced. It returns the number of
// writes of each shape. A mutating command that is not one of the two shapes,
// or that the shell cannot parse as a single pveum call, fails the test.
func screenedWrites(t *testing.T, name string, f *grantFake, p enableParams) (roleAdds, aclMods int) {
	t.Helper()
	for _, c := range f.mutating() {
		argv, err := shArgv(t, c)
		if err != nil {
			t.Errorf("%s: a recorded command does not parse as one pveum call: %q: %v", name, c, err)
			continue
		}
		shape, err := screenEnableArgv(argv, p)
		if err != nil {
			t.Errorf("%s: a mutating command passed no screen: %q (argv %q): %v", name, c, argv, err)
			continue
		}
		if shape == 1 {
			roleAdds++
		} else {
			aclMods++
		}
	}
	return
}

func paramsFor(f *grantFake, role, token string) enableParams {
	return enableParams{role: role, privs: vmD, tokenID: token}
}

// ---- T1: the argv screen, called directly ----

func TestEnable_T1_ScreenAcceptsExactlyTwoShapes(t *testing.T) {
	p := enableParams{role: DefaultVMDestroyRole, privs: vmD, tokenID: liveToken}
	role1 := []string{"pveum", "role", "add", DefaultVMDestroyRole, "--privs", vmDJoined}
	acl2 := []string{"pveum", "acl", "modify", "/", "--tokens", liveToken, "--roles", DefaultVMDestroyRole, "--propagate", "1"}

	if shape, err := screenEnableArgv(role1, p); err != nil || shape != 1 {
		t.Fatalf("shape 1: %d, %v", shape, err)
	}
	if shape, err := screenEnableArgv(acl2, p); err != nil || shape != 2 {
		t.Fatalf("shape 2: %d, %v", shape, err)
	}
	with := func(base []string, extra ...string) []string { return append(slices.Clone(base), extra...) }
	rep := func(base []string, i int, v string) []string { b := slices.Clone(base); b[i] = v; return b }
	privsMinusOne := strings.Join(vmD[1:], ",")
	for name, argv := range map[string][]string{
		"acl modify + --delete 1":            with(acl2, "--delete", "1"),
		"acl modify + --delete=1":            with(acl2, "--delete=1"),
		"acl modify + --delete true":         with(acl2, "--delete", "true"),
		"acl modify + --Delete 1":            with(acl2, "--Delete", "1"),
		"acl modify + -delete":               with(acl2, "-delete"),
		"acl delete":                         {"pveum", "acl", "delete", "/", "--tokens", liveToken, "--roles", DefaultVMDestroyRole},
		"a second --roles":                   with(acl2, "--roles", "Administrator"),
		"a second --tokens":                  with(acl2, "--tokens", "root@pam!other"),
		"propagate 0":                        rep(acl2, 9, "0"),
		"path /nodes":                        rep(acl2, 3, "/nodes"),
		"another token":                      rep(acl2, 5, "root@pam!other"),
		"another role":                       rep(acl2, 7, "Administrator"),
		"role modify":                        {"pveum", "role", "modify", DefaultVMDestroyRole, "--privs", vmDJoined},
		"role modify --append":               {"pveum", "role", "modify", DefaultVMDestroyRole, "--privs", vmDJoined, "--append", "1"},
		"role delete":                        {"pveum", "role", "delete", DefaultVMDestroyRole},
		"user token remove":                  {"pveum", "user", "token", "remove", "root@pam", "pveforge"},
		"user token add":                     {"pveum", "user", "token", "add", "root@pam", "pveforge", "--privsep", "1"},
		"user delete":                        {"pveum", "user", "delete", "root@pam"},
		"role add + extra element":           with(role1, "--comment", "x"),
		"role add, privs with a space":       rep(role1, 5, strings.Replace(vmDJoined, ",", ", ", 1)),
		"role add, privs missing one":        rep(role1, 5, privsMinusOne),
		"role add, privs unsorted":           rep(role1, 5, strings.Join(slices.Concat(vmD[1:2], vmD[0:1], vmD[2:]), ",")),
		"role add another role":              rep(role1, 3, "Other"),
		"first word + suffix":                rep(role1, 0, "pveum;"),
		"an allowed word plus a suffix":      rep(acl2, 2, "modify;"),
		"empty":                              {},
		"role add for the acl shape's words": {"pveum", "role", "add", "/", "--tokens", liveToken},
	} {
		if _, err := screenEnableArgv(argv, p); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		} else if !errors.Is(err, ErrEnableScreen) {
			t.Errorf("%s: refusal is not ErrEnableScreen: %v", name, err)
		}
	}

	// The screen also refuses its own parameters: a PVE-prefixed or unclean
	// role, an unclean token id, a privilege list that is empty or unsorted.
	for name, bad := range map[string]enableParams{
		"PVE-prefixed role":     {role: "PVEForge", privs: vmD, tokenID: liveToken},
		"mixed-case PVE prefix": {role: "PveForge", privs: vmD, tokenID: liveToken},
		"role with a quote":     {role: "a'b", privs: vmD, tokenID: liveToken},
		"role with a space":     {role: "a b", privs: vmD, tokenID: liveToken},
		"token id with a quote": {role: "R", privs: vmD, tokenID: "root@pam!a'b"},
		"no privileges":         {role: "R", privs: nil, tokenID: liveToken},
		"unsorted privileges":   {role: "R", privs: []string{"VM.Audit", "Sys.Audit"}, tokenID: liveToken},
		"bad privilege name":    {role: "R", privs: []string{"Sys.Audit", "x y"}, tokenID: liveToken},
	} {
		if _, err := screenEnableArgv(enableRoleArgv(bad), bad); err == nil {
			t.Errorf("%s: parameters accepted", name)
		}
	}
	// With no token a shape-2 argv is refused outright.
	noTok := enableParams{role: DefaultVMDestroyRole, privs: vmD}
	if _, err := screenEnableArgv(acl2, noTok); err == nil {
		t.Error("an acl modify was accepted for a roster with no token")
	}
}

// T1 render equality: the string that reaches the session is byte-for-byte
// the expected one, every value single-quoted, and none of the three values
// needs escaping (so the string round-trips through the shell as the argv).
func TestEnable_T1_RenderEquality(t *testing.T) {
	p := enableParams{role: DefaultVMDestroyRole, privs: []string{"Sys.Audit", "VM.Audit"}, tokenID: liveToken}
	if got, want := renderEnable(1, p), `pveum role add 'ForgeVMAdminAudit' --privs 'Sys.Audit,VM.Audit'`; got != want {
		t.Errorf("shape 1 = %q, want %q", got, want)
	}
	if got, want := renderEnable(2, p), `pveum acl modify '/' --tokens 'root@pam!pveforge' --roles 'ForgeVMAdminAudit' --propagate 1`; got != want {
		t.Errorf("shape 2 = %q, want %q", got, want)
	}
	for _, v := range []string{DefaultVMDestroyRole, vmDJoined, liveToken, "/"} {
		if sshexec.ShellQuote(v) != "'"+v+"'" {
			t.Errorf("%q needs shell escaping, so the render would not round-trip", v)
		}
	}
	// A real shell reads each rendered command back as exactly its argv.
	for shape, argv := range map[int][]string{1: enableRoleArgv(p), 2: enableACLArgv(p)} {
		got, err := shArgv(t, renderEnable(shape, p))
		if err != nil || !slices.Equal(got, argv) {
			t.Errorf("shape %d: sh parsed %q (%v), want %q", shape, got, err, argv)
		}
	}
}

// ---- T4: the role set is live-derived and validated ----

func TestEnable_T4_DeriveRoleSet(t *testing.T) {
	admin := allPrivs()
	t.Run("D is PVEVMAdmin plus Sys.Audit, sorted, from the roles it is given", func(t *testing.T) {
		// A PVEVMAdmin that is NOT the documented 23: one fewer, one extra.
		live := append(slices.Clone(vmAdmin23[1:]), "Pool.Audit")
		d, err := deriveRoleSet(map[string][]string{"PVEVMAdmin": live, "Administrator": admin})
		if err != nil {
			t.Fatal(err)
		}
		want := append(slices.Clone(live), "Sys.Audit")
		sort.Strings(want)
		if !slices.Equal(d, want) {
			t.Fatalf("D = %v, want %v (a hard-coded list would differ)", d, want)
		}
		if slices.Contains(d, vmAdmin23[0]) {
			t.Errorf("D still holds %s, which the live PVEVMAdmin lacks", vmAdmin23[0])
		}
		if !slices.Contains(d, "Sys.Audit") {
			t.Error("D lacks Sys.Audit")
		}
	})
	t.Run("a privilege Administrator does not hold is refused", func(t *testing.T) {
		_, err := deriveRoleSet(map[string][]string{"PVEVMAdmin": append(slices.Clone(vmAdmin23), "Sys.Bogus"), "Administrator": admin})
		if !errors.Is(err, ErrUnknownPrivilege) || !strings.Contains(err.Error(), "Sys.Bogus") {
			t.Fatalf("want ErrUnknownPrivilege naming Sys.Bogus, got %v", err)
		}
	})
	t.Run("Sys.Audit itself must be one PVE knows", func(t *testing.T) {
		noAudit := slices.DeleteFunc(slices.Clone(admin), func(p string) bool { return p == "Sys.Audit" })
		if _, err := deriveRoleSet(map[string][]string{"PVEVMAdmin": vmAdmin23, "Administrator": noAudit}); !errors.Is(err, ErrUnknownPrivilege) {
			t.Fatalf("want ErrUnknownPrivilege, got %v", err)
		}
	})
	t.Run("a PVEVMAdmin that gained an escalating privilege makes the verb refuse", func(t *testing.T) {
		_, err := deriveRoleSet(map[string][]string{"PVEVMAdmin": append(slices.Clone(vmAdmin23), "VM.Monitor"), "Administrator": admin})
		if !errors.Is(err, ErrEscalatingRole) || !strings.Contains(err.Error(), "VM.Monitor") {
			t.Fatalf("want ErrEscalatingRole naming VM.Monitor, got %v", err)
		}
	})
	t.Run("the standard set passes the escalation screen (Sys.Audit is not escalating)", func(t *testing.T) {
		if _, err := deriveRoleSet(map[string][]string{"PVEVMAdmin": vmAdmin23, "Administrator": admin}); err != nil {
			t.Fatalf("the standard D was refused: %v", err)
		}
	})
	t.Run("a missing or empty PVEVMAdmin or Administrator is an error", func(t *testing.T) {
		for name, roles := range map[string]map[string][]string{
			"no PVEVMAdmin":    {"Administrator": admin},
			"empty PVEVMAdmin": {"PVEVMAdmin": {}, "Administrator": admin},
			"no Administrator": {"PVEVMAdmin": vmAdmin23},
			"empty Administr.": {"PVEVMAdmin": vmAdmin23, "Administrator": {}},
			"nothing at all":   {},
		} {
			if _, err := deriveRoleSet(roles); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

// T4b (codex C3): a recognised privilege that is NOT in EscalatingPrivileges
// is added to PVEVMAdmin. The token-upgrade path must still widen the token by
// exactly {Sys.Audit}: it already holds the new privilege through its own
// PVEVMAdmin row. The role-only path creates R with it (accepted, D10: R is
// inert until granted, and prints D).
func TestEnable_T4b_NewNonEscalatingPrivilegeInPVEVMAdmin(t *testing.T) {
	grown := func() *grantFake {
		f := newGrantFake()
		f.setRole("PVEVMAdmin", append(slices.Clone(vmAdmin23), "Sys.Syslog")...)
		return f
	}
	t.Run("token upgrade widens by exactly Sys.Audit", func(t *testing.T) {
		f := grown()
		before := f.effective(liveToken)
		r := newEnableRun(t, f)
		res, err := r.do()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(res.Privileges, "Sys.Syslog") {
			t.Fatalf("R was not derived from the live PVEVMAdmin: %v", res.Privileges)
		}
		if got := widenedBy(before, f.effective(liveToken)); !slices.Equal(got, []string{"Sys.Audit"}) {
			t.Fatalf("the token widened by %v, want exactly [Sys.Audit]", got)
		}
	})
	t.Run("role-only creates R with it and writes no ACL", func(t *testing.T) {
		f := grown()
		f.tokens = map[string]bool{}
		f.acls = nil
		r := newEnableRun(t, f)
		r.setOwn("")
		res, err := r.do()
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != EnableRoleOnly || !slices.Contains(f.roles[DefaultVMDestroyRole], "Sys.Syslog") || f.count(cmdACLModify) != 0 {
			t.Fatalf("outcome %q, role %v, acl writes %d", res.Outcome, f.roles[DefaultVMDestroyRole], f.count(cmdACLModify))
		}
	})
	t.Run("an escalating privilege refuses with zero writes", func(t *testing.T) {
		f := newGrantFake()
		f.setRole("PVEVMAdmin", append(slices.Clone(vmAdmin23), "VM.Monitor")...)
		r := newEnableRun(t, f)
		_, err := r.do()
		if !errors.Is(err, ErrEscalatingRole) || len(f.mutating()) != 0 {
			t.Fatalf("err %v, writes %q", err, f.mutating())
		}
	})
}

// ---- T5: role create / no-op / refuse; the name screen; the re-read parse ----

func TestEnable_T5_RoleNamesRefusedBeforeAnyDial(t *testing.T) {
	for _, name := range []string{"PVEForgeVMAdminAudit", "PveForgeVMAdminAudit", "pveforgevmadminaudit", "pVeX", "PVE", "pve", "", "a b", "a'b", "x/y", "a;b"} {
		f := newGrantFake()
		r := newEnableRun(t, f)
		r.req.Role = name
		if name == "" {
			continue // "" means the default
		}
		_, err := r.do()
		if !errors.Is(err, ErrRoleName) {
			t.Errorf("%q: want ErrRoleName, got %v", name, err)
		}
		if r.tr.reconnectCalls != 0 || len(f.commands) != 0 {
			t.Errorf("%q: the host was reached before the name was refused (dials %d, commands %q)", name, r.tr.reconnectCalls, f.commands)
		}
		noVerdict(t, name, err)
	}
	// A legal override is used.
	f := newGrantFake()
	r := newEnableRun(t, f)
	r.req.Role = "ForgeDestroy2"
	if res, err := r.do(); err != nil || res.Role != "ForgeDestroy2" || f.roles["ForgeDestroy2"] == nil {
		t.Fatalf("override: %+v, %v", res, err)
	}
}

func TestEnable_T5_SplitPrivList(t *testing.T) {
	for in, want := range map[string][]string{
		"A,B": {"A", "B"}, "A, B": {"A", "B"}, "A;B": {"A", "B"}, "A B": {"A", "B"}, "A\tB\nC": {"A", "B", "C"},
		"": nil, ",": nil, "A,": {"A"}, ",A": {"A"}, " A , B ": {"A", "B"},
	} {
		if got := splitPrivList(in); !slices.Equal(got, want) {
			t.Errorf("splitPrivList(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnable_T5_RoleStates(t *testing.T) {
	t.Run("absent: one role add with the sorted derived set", func(t *testing.T) {
		f := newGrantFake()
		r := newEnableRun(t, f)
		res, err := r.do()
		if err != nil {
			t.Fatal(err)
		}
		if !res.RoleCreated || f.count(cmdRoleAdd) != 1 || !slices.Equal(f.roles[DefaultVMDestroyRole], vmD) {
			t.Fatalf("created %v, role adds %d, role %v", res.RoleCreated, f.count(cmdRoleAdd), f.roles[DefaultVMDestroyRole])
		}
	})
	t.Run("equal: no role write", func(t *testing.T) {
		f := newGrantFake()
		f.setRole(DefaultVMDestroyRole, vmD...)
		r := newEnableRun(t, f)
		res, err := r.do()
		if err != nil || res.RoleCreated || f.count(cmdRoleAdd) != 0 {
			t.Fatalf("err %v created %v role adds %d", err, res.RoleCreated, f.count(cmdRoleAdd))
		}
	})
	for name, set := range map[string][]string{
		"subset":   vmD[1:],
		"superset": append(slices.Clone(vmD), "Pool.Audit"),
		"disjoint": {"Datastore.Audit"},
		"empty":    {},
	} {
		t.Run("conflict: "+name+" refuses and writes nothing", func(t *testing.T) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, set...)
			before := slices.Clone(f.roles[DefaultVMDestroyRole])
			r := newEnableRun(t, f)
			_, err := r.do()
			if !errors.Is(err, ErrRoleConflict) {
				t.Fatalf("want ErrRoleConflict, got %v", err)
			}
			if len(f.mutating()) != 0 || !slices.Equal(f.roles[DefaultVMDestroyRole], before) {
				t.Fatalf("a conflicting role was touched: writes %q", f.mutating())
			}
			noVerdict(t, name, err)
		})
	}
	t.Run("a role list that spaces its privs reads as equal (split_list)", func(t *testing.T) {
		f := newGrantFake()
		f.setRole(DefaultVMDestroyRole, vmD...)
		a := NewRootAccess(AccessOptions{Addr: "x:22", SSHUser: "root", PrivateKeyPEM: []byte("K"), HostKeyFingerprint: "SHA256:p", OwnToken: liveToken},
			&grantTransport{sess: &spacedRoles{f}, calls: new(int)})
		res, err := EnableVMDestroy(context.Background(), a, EnableVMDestroyRequest{RosterPath: seedRoster(t, liveToken, "").path, TargetID: "qa-pve-01"})
		if err != nil || res.RoleCreated {
			t.Fatalf("%+v, %v", res, err)
		}
	})
}

// spacedRoles answers `role list` with ", "-joined privilege lists, a join PVE
// accepts on write (split_list) and could legally print.
type spacedRoles struct{ *grantFake }

func (s *spacedRoles) Run(ctx context.Context, cmd string) (RunResult, error) {
	res, err := s.grantFake.Run(ctx, cmd)
	if err != nil || !strings.HasPrefix(cmd, "pveum role list") {
		return res, err
	}
	var list []map[string]any
	if jerr := json.Unmarshal([]byte(res.Stdout), &list); jerr != nil {
		return res, jerr
	}
	for _, e := range list {
		e["privs"] = strings.ReplaceAll(e["privs"].(string), ",", ", ")
	}
	b, _ := json.Marshal(list)
	res.Stdout = string(b)
	return res, nil
}

// A race on the role: another writer creates R with the same set between the
// read and the create. The create fails "already exists"; the re-read is equal;
// that is success. With a different set it is a conflict.
func TestEnable_T5_RoleCreateRace(t *testing.T) {
	for name, tc := range map[string]struct {
		set     []string
		wantErr error
	}{"same set": {vmD, nil}, "different set": {vmD[1:], ErrRoleConflict}} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFake()
			f.before = func(cmd string) {
				if strings.HasPrefix(cmd, cmdRoleAdd+" ") {
					f.setRole(DefaultVMDestroyRole, tc.set...)
				}
			}
			r := newEnableRun(t, f)
			res, err := r.do()
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || res.RoleCreated {
				t.Fatalf("a racing writer with the same set: %+v, %v", res, err)
			}
		})
	}
}

// ---- T7: the whole-tree precondition and already_enabled, row by row ----

type enableCase struct {
	name string
	// build returns the fake, and the token id the roster holds ("" for none).
	build   func() (*grantFake, string)
	wantErr error // errors.Is; nil means success
	// writes: the expected number of acl modify commands.
	aclWrites int
	outcome   string
	contains  string // text the error must hold
	// notes: the row is allowed to succeed with informational notes (the
	// predictor is not exact there by design); every other success asserts none.
	notes bool
}

func enableCases() []enableCase { return append(baseEnableCases(), fix1Cases()...) }

func baseEnableCases() []enableCase {
	row := func(f *grantFake, path, role string, prop bool) { f.addRow(path, role, "token", liveToken, prop) }
	return []enableCase{
		{name: "path B: PVEVMAdmin@/ only (the operator's token)", build: func() (*grantFake, string) { return newGrantFake(), liveToken },
			aclWrites: 1, outcome: EnableUpgraded},
		{name: "already enabled: role == D, exact token row, effective holds D", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD...)
			row(f, "/", DefaultVMDestroyRole, true)
			return f, liveToken
		}, aclWrites: 0, outcome: EnableAlreadyEnabled},
		{name: "descendant extra grant: own row Datastore.Audit@/storage/local", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("StorAudit", "Datastore.Audit")
			row(f, "/storage/local", "StorAudit", false)
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "/storage/local"},
		{name: "root@pam token, no row, not privilege-separated (Administrator everywhere)", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.tokens[liveToken] = false
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge},
		{name: "limited token: only VM.Audit", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("VMAuditOnly", "VM.Audit")
			f.acls = nil
			row(f, "/", "VMAuditOnly", true)
			return f, liveToken
		}, wantErr: ErrNotVMAdminToken, contains: "VM.Allocate"},
		{name: "empty token: privilege-separated, no rows", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			return f, liveToken
		}, wantErr: ErrNotVMAdminToken, contains: "VM.Allocate"},
		{name: "a different custom role holding D, no R row: not already_enabled, R row written", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("Other", vmD...)
			f.acls = nil
			row(f, "/", "Other", true)
			f.setRole(DefaultVMDestroyRole, vmD...)
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "R row with propagate 0 beside PVEVMAdmin: not already_enabled; propagate-1 row written", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD...)
			row(f, "/", DefaultVMDestroyRole, false)
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "a NoAccess row on the walk", build: func() (*grantFake, string) {
			f := newGrantFake()
			row(f, "/vms/100", "NoAccess", false)
			return f, liveToken
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "NoAccess"},
		{name: "a user row for the same user does not help a token (groups and users never apply)", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil // token has nothing of its own
			f.addRow("/", "PVEVMAdmin", "user", "root@pam", true)
			return f, liveToken
		}, wantErr: ErrNotVMAdminToken},
		{name: "a descendant row that only narrows within D is fine (override holds D\\Sys.Audit)", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("VMOnly", vmAdmin23...)
			row(f, "/vms/100", "VMOnly", false)
			return f, liveToken
		}, aclWrites: 1, outcome: EnableUpgraded},
		{name: "role R exists with a drifted set", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD[1:]...)
			return f, liveToken
		}, wantErr: ErrRoleConflict},
		{name: "non-root owner lacking Sys.Audit: refused before any write, owner named", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.tokens["alice@pve!tok1"] = true
			f.addRow("/", "PVEVMAdmin", "user", "alice@pve", true)
			f.addRow("/", "PVEVMAdmin", "token", "alice@pve!tok1", true)
			return f, "alice@pve!tok1"
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "alice@pve"},
		{name: "exact R row exists but the effective set lacks Sys.Audit (owner lacks it): the row alone is not enabled", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.tokens["alice@pve!tok1"] = true
			f.setRole(DefaultVMDestroyRole, vmD...)
			f.addRow("/", "PVEVMAdmin", "user", "alice@pve", true)
			f.addRow("/", "PVEVMAdmin", "token", "alice@pve!tok1", true)
			f.addRow("/", DefaultVMDestroyRole, "token", "alice@pve!tok1", true)
			return f, "alice@pve!tok1"
		}, wantErr: ErrUpgradeWouldNotConverge, contains: "alice@pve"},
		{name: "non-root owner holding the role's privileges: upgraded, flags ANDed", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			f.tokens["alice@pve!tok1"] = true
			f.setRole("OwnerRole", vmD...)
			f.addRow("/", "OwnerRole", "user", "alice@pve", true)
			f.addRow("/", "PVEVMAdmin", "token", "alice@pve!tok1", true)
			return f, "alice@pve!tok1"
		}, aclWrites: 1, outcome: EnableUpgraded},
	}
}

func TestEnable_T7_WholeTreePrecondition(t *testing.T) {
	for _, tc := range enableCases() {
		t.Run(tc.name, func(t *testing.T) {
			f, token := tc.build()
			r := newEnableRun(t, f)
			r.setOwn(token)
			rosterBefore := hashFile(t, r.roster)
			var before map[string]map[string]bool
			if token != "" {
				before = f.effective(token)
			}
			res, err := r.do()
			if h := hashFile(t, r.roster); h != rosterBefore {
				t.Fatal("the roster file changed")
			}
			noVerdict(t, tc.name, err)
			if got := f.count(cmdACLModify); got != tc.aclWrites {
				t.Fatalf("acl modify commands = %d, want %d (log %q)", got, tc.aclWrites, f.commands)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
				if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
					t.Errorf("the error does not name %q: %v", tc.contains, err)
				}
				if len(f.mutating()) != 0 {
					t.Fatalf("a refusal wrote: %q", f.mutating())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if res.Outcome != tc.outcome {
				t.Fatalf("outcome %q, want %q", res.Outcome, tc.outcome)
			}
			// Where the predictor is supposed to be exact (every success row of
			// this table), actual == predicted: no note. A note means the
			// prediction missed something the invariant then forgave.
			if !tc.notes && len(res.Notes) != 0 {
				t.Fatalf("a success row where prediction should be exact carries notes: %q", res.Notes)
			}
			if token == "" {
				return
			}
			// INV-2 in the fixture: the diff over the independent port of PVE's
			// role walk. A write widens by exactly {Sys.Audit}, or by nothing
			// if the token already held it; a no-write run widens by nothing.
			after := f.effective(token)
			got := widenedBy(before, after)
			switch {
			case tc.aclWrites == 0 && len(got) != 0:
				t.Fatalf("a run that wrote nothing widened the token by %v", got)
			case !(len(got) == 0 || slices.Equal(got, []string{"Sys.Audit"})):
				t.Fatalf("the token widened by %v, want at most [Sys.Audit]", got)
			}
			if tc.aclWrites == 1 && token == liveToken && tc.name == "path B: PVEVMAdmin@/ only (the operator's token)" && !slices.Equal(got, []string{"Sys.Audit"}) {
				t.Fatalf("path B must widen by exactly [Sys.Audit], got %v", got)
			}
			// After an upgrade the token is what `bootstrap --grant /:R::1`
			// accepts (T11's row): the real comparison on the fake's own tree.
			if tc.aclWrites == 1 || tc.outcome == EnableAlreadyEnabled {
				if err := judgeAgainstRole(after, DefaultVMDestroyRole, vmD); err != nil {
					t.Fatalf("after the verb, /:R::1 is not accepted: %v", err)
				}
			}
		})
	}
}

// judgeAgainstRole runs the validator's own comparison (pve.JudgeTree, the
// code bootstrap's `reused` rests on) over a tree and a role's privileges.
func judgeAgainstRole(tree map[string]map[string]bool, role string, privs []string) error {
	set := map[string]bool{}
	for _, p := range privs {
		set[p] = true
	}
	held := map[string]map[string]bool{"/": tree["/"]}
	return pve.JudgeTree(context.Background(), []pve.Grant{{Path: "/", Role: role, Propagate: true}}, []map[string]bool{set}, tree, nil, held,
		func(context.Context, string) (bool, error) { return false, errors.New("unexpected existence check") },
		func(_ context.Context, p string) (map[string]bool, error) { return tree[p], nil })
}

// ---- T7b / the window: edits that land between the read and the write ----

func TestEnable_T7_InRunWindow(t *testing.T) {
	repair := "pveum acl delete / --tokens 'root@pam!pveforge' --roles 'ForgeVMAdminAudit'"
	t.Run("the role is widened after the pre-write read: detected, the repair is named, nothing is deleted", func(t *testing.T) {
		f := newGrantFake()
		f.setRole(DefaultVMDestroyRole, vmD...)
		f.before = func(cmd string) {
			if strings.HasPrefix(cmd, cmdACLModify+" ") {
				f.setRole(DefaultVMDestroyRole, append(slices.Clone(vmD), "Sys.Syslog")...)
			}
		}
		r := newEnableRun(t, f)
		_, err := r.do()
		if !errors.Is(err, ErrRoleChangedDuringGrant) || !strings.Contains(err.Error(), repair) {
			t.Fatalf("want ErrRoleChangedDuringGrant naming %q, got %v", repair, err)
		}
		if f.count("pveum acl delete") != 0 || f.count(cmdACLModify) != 1 {
			t.Fatalf("the verb deleted something or wrote twice: %q", f.mutating())
		}
		noVerdict(t, "window", err)
	})
	t.Run("the role gains an ESCALATING privilege after the read: set-equal, not superset, catches it", func(t *testing.T) {
		f := newGrantFake()
		f.setRole(DefaultVMDestroyRole, vmD...)
		f.before = func(cmd string) {
			if strings.HasPrefix(cmd, cmdACLModify+" ") {
				f.setRole(DefaultVMDestroyRole, append(slices.Clone(vmD), "VM.Monitor")...)
			}
		}
		_, err := newEnableRun(t, f).do()
		if !errors.Is(err, ErrRoleChangedDuringGrant) {
			t.Fatalf("a superset must still be a drift: got %v", err)
		}
	})
	t.Run("a concurrent ACL change on the token: actual is not predicted", func(t *testing.T) {
		f := newGrantFake()
		f.setRole(DefaultVMDestroyRole, vmD...)
		f.setRole("StorAudit", "Datastore.Audit")
		f.before = func(cmd string) {
			if strings.HasPrefix(cmd, cmdACLModify+" ") {
				f.addRow("/storage/local", "StorAudit", "token", liveToken, false)
			}
		}
		_, err := newEnableRun(t, f).do()
		if !errors.Is(err, ErrPostWriteInvariant) || !strings.Contains(err.Error(), repair) || !strings.Contains(err.Error(), "/storage/local") {
			t.Fatalf("want ErrPostWriteInvariant naming /storage/local and the repair, got %v", err)
		}
		if f.count("pveum acl delete") != 0 {
			t.Fatal("the verb deleted an ACL")
		}
	})
	t.Run("the owner loses Sys.Audit in the window: granted but not effective", func(t *testing.T) {
		f := newGrantFake()
		f.acls = nil
		f.tokens["alice@pve!tok1"] = true
		f.setRole("OwnerRole", vmD...)
		f.addRow("/", "OwnerRole", "user", "alice@pve", true)
		f.addRow("/", "PVEVMAdmin", "token", "alice@pve!tok1", true)
		f.before = func(cmd string) {
			if strings.HasPrefix(cmd, cmdACLModify+" ") {
				f.setRole("OwnerRole", vmAdmin23...) // the owner no longer holds Sys.Audit
			}
		}
		r := newEnableRun(t, f)
		r.setOwn("alice@pve!tok1")
		_, err := r.do()
		if !errors.Is(err, ErrGrantNotEffective) || !strings.Contains(err.Error(), "alice@pve") {
			t.Fatalf("want ErrGrantNotEffective naming the owner, got %v", err)
		}
		noVerdict(t, "not effective", err)
	})
}

// ---- T2: every outcome of the whole verb sends only screened writes ----

func TestEnable_T2_ScenarioSweep(t *testing.T) {
	type sc struct {
		name  string
		build func() (*grantFake, string)
		req   func(*EnableVMDestroyRequest)
		// wantRoleAdds / wantACL: the expected screened writes; mustWrite says
		// the scenario is one in which a write has to have happened.
		wantRoleAdds, wantACL int
		wantErr               func(error) bool
		dialFails             bool
	}
	errIs := func(target error) func(error) bool { return func(e error) bool { return errors.Is(e, target) } }
	anyErr := func(e error) bool { return e != nil }
	scs := []sc{
		{name: "success: path B", build: func() (*grantFake, string) { return newGrantFake(), liveToken }, wantRoleAdds: 1, wantACL: 1},
		{name: "success: role exists, row missing", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD...)
			return f, liveToken
		}, wantACL: 1},
		{name: "already enabled", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD...)
			f.addRow("/", DefaultVMDestroyRole, "token", liveToken, true)
			return f, liveToken
		}},
		{name: "role-only (the roster holds no token)", build: func() (*grantFake, string) { return newGrantFake(), "" }, wantRoleAdds: 1},
		{name: "role conflict", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, "VM.Audit")
			return f, liveToken
		}, wantErr: errIs(ErrRoleConflict)},
		{name: "role add fails (e.g. no quorum)", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.fail[cmdRoleAdd] = RunResult{ExitCode: 255, Stderr: "create role failed: cluster not ready - no quorum?"}
			return f, liveToken
		}, wantRoleAdds: 1, wantErr: anyErr},
		{name: "acl modify fails", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.fail[cmdACLModify] = RunResult{ExitCode: 255, Stderr: "ACL update failed: cluster not ready - no quorum?"}
			return f, liveToken
		}, wantRoleAdds: 1, wantACL: 1, wantErr: anyErr},
		{name: "acl modify times out: outcome unknown, re-running is safe", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.failErr[cmdACLModify] = timedOut(cmdACLModify)
			return f, liveToken
		}, wantRoleAdds: 1, wantACL: 1, wantErr: errIs(ErrRootWriteOutcomeUnknown)},
		{name: "post-write role drift", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole(DefaultVMDestroyRole, vmD...)
			f.before = func(cmd string) {
				if strings.HasPrefix(cmd, cmdACLModify+" ") {
					f.setRole(DefaultVMDestroyRole, append(slices.Clone(vmD), "Sys.Syslog")...)
				}
			}
			return f, liveToken
		}, wantACL: 1, wantErr: errIs(ErrRoleChangedDuringGrant)},
		{name: "refused: descendant extra grant", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("StorAudit", "Datastore.Audit")
			f.addRow("/storage/local", "StorAudit", "token", liveToken, false)
			return f, liveToken
		}, wantErr: errIs(ErrUpgradeWouldNotConverge)},
		{name: "refused: limited token", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.acls = nil
			return f, liveToken
		}, wantErr: errIs(ErrNotVMAdminToken)},
		{name: "refused: escalating PVEVMAdmin", build: func() (*grantFake, string) {
			f := newGrantFake()
			f.setRole("PVEVMAdmin", append(slices.Clone(vmAdmin23), "VM.Monitor")...)
			return f, liveToken
		}, wantErr: errIs(ErrEscalatingRole)},
		{name: "dry run writes nothing", build: func() (*grantFake, string) { return newGrantFake(), liveToken },
			req: func(r *EnableVMDestroyRequest) { r.DryRun = true }},
		{name: "root dial fails", build: func() (*grantFake, string) { return newGrantFake(), liveToken }, dialFails: true, wantErr: anyErr},
	}
	for _, c := range scs {
		t.Run(c.name, func(t *testing.T) {
			f, token := c.build()
			r := newEnableRun(t, f)
			r.setOwn(token)
			if c.req != nil {
				c.req(&r.req)
			}
			rosterBefore := hashFile(t, r.roster)
			var err error
			if c.dialFails {
				a := NewRootAccess(AccessOptions{Addr: "x:22", SSHUser: "root", PrivateKeyPEM: []byte("K"), HostKeyFingerprint: "SHA256:p", OwnToken: token},
					&grantTransport{sess: f, calls: new(int), dialErr: errors.New("connection refused")})
				_, err = EnableVMDestroy(context.Background(), a, r.req)
			} else {
				_, err = r.do()
			}
			if hashFile(t, r.roster) != rosterBefore {
				t.Fatal("INV-1.2: the roster file changed")
			}
			if c.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != nil && (err == nil || !c.wantErr(err)) {
				t.Fatalf("unexpected error: %v", err)
			}
			noVerdict(t, c.name, err)
			roleAdds, acls := screenedWrites(t, c.name, f, enableParams{role: DefaultVMDestroyRole, privs: derivedFor(f), tokenID: token})
			if roleAdds != c.wantRoleAdds || acls != c.wantACL {
				t.Fatalf("screened writes: role add %d (want %d), acl modify %d (want %d); log %q", roleAdds, c.wantRoleAdds, acls, c.wantACL, f.commands)
			}
			// success has exactly one acl modify of the allowed shape (and never
			// more than one role add)
			if err == nil && token != "" && c.name != "already enabled" && !strings.HasPrefix(c.name, "dry run") && acls != 1 {
				t.Fatalf("a successful upgrade must send exactly one acl modify, sent %d", acls)
			}
			for _, cmd := range f.commands {
				for _, banned := range []string{"user token", "acl delete", "role delete", "role modify", "user delete"} {
					if strings.Contains(cmd, banned) {
						t.Errorf("INV-1: a command contains %q: %q", banned, cmd)
					}
				}
			}
			if len(f.commands) == 0 && !c.dialFails {
				t.Fatal("vacuous: the verb sent no command at all")
			}
		})
	}
}

// derivedFor is D as the fake's live PVEVMAdmin gives it, for screening.
func derivedFor(f *grantFake) []string {
	d, err := deriveRoleSet(f.roles)
	if err != nil {
		return vmD
	}
	return d
}

// ---- T8: idempotence ----

func TestEnable_T8_SecondRunWritesNothing(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	if _, err := r.do(); err != nil {
		t.Fatal(err)
	}
	if f.count(cmdACLModify) != 1 || f.count(cmdRoleAdd) != 1 {
		t.Fatalf("first run: %q", f.mutating())
	}
	f.commands = nil
	res, err := r.do()
	if err != nil || res.Outcome != EnableAlreadyEnabled {
		t.Fatalf("second run: %+v, %v", res, err)
	}
	if len(f.mutating()) != 0 || len(f.commands) == 0 {
		t.Fatalf("second run wrote or read nothing: %q", f.commands)
	}
}

// ---- dry run ----

func TestEnable_DryRunPlansAndWritesNothing(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	r.req.DryRun = true
	res, err := r.do()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`pveum role add 'ForgeVMAdminAudit' --privs '` + vmDJoined + `'`,
		`pveum acl modify '/' --tokens 'root@pam!pveforge' --roles 'ForgeVMAdminAudit' --propagate 1`,
	}
	if !slices.Equal(res.Planned, want) || !res.DryRun {
		t.Fatalf("planned %q, want %q", res.Planned, want)
	}
	if len(f.mutating()) != 0 || len(f.commands) == 0 {
		t.Fatalf("dry run wrote (or read nothing): %q", f.commands)
	}
	if !slices.Equal(res.Widened, []string{"Sys.Audit"}) {
		t.Fatalf("predicted widening %v", res.Widened)
	}
}

// ---- T11: the real comparison agrees with the verb ----

func TestEnable_T11_ValidatorAgrees(t *testing.T) {
	// C5's three rows, on the fake's own independently computed trees.
	b := newGrantFake()
	before := b.effective(liveToken) // PVEVMAdmin only
	if err := judgeAgainstRole(before, DefaultVMDestroyRole, vmD); !errors.Is(err, pve.ErrWrongScope) {
		t.Fatalf("row 2 (PVEVMAdmin only vs /:R::1): want ErrWrongScope, got %v", err)
	}
	r := newEnableRun(t, b)
	if _, err := r.do(); err != nil {
		t.Fatal(err)
	}
	after := b.effective(liveToken)
	if err := judgeAgainstRole(after, DefaultVMDestroyRole, vmD); err != nil {
		t.Fatalf("row 1 (PVEVMAdmin + R vs /:R::1) must be nil: %v", err)
	}
	if err := judgeAgainstRole(after, "PVEVMAdmin", vmAdmin23); !errors.Is(err, pve.ErrScopeTooWide) {
		t.Fatalf("row 3 (PVEVMAdmin + R vs /:PVEVMAdmin::1): want ErrScopeTooWide, got %v", err)
	}
	if err := judgeAgainstRole(before, "PVEVMAdmin", vmAdmin23); err != nil {
		t.Fatalf("PVEVMAdmin only vs /:PVEVMAdmin::1 must be nil: %v", err)
	}

	// judgePredicted on the five predicted trees of plan §3.5.4d.
	cases := map[string]struct {
		build   func() *grantFake
		wantErr error
	}{
		"limited: nil from the validator alone, refused by the widening half": {func() *grantFake {
			f := newGrantFake()
			f.setRole("VMAuditOnly", "VM.Audit")
			f.acls = nil
			f.addRow("/", "VMAuditOnly", "token", liveToken, true)
			return f
		}, ErrNotVMAdminToken},
		"empty": {func() *grantFake { f := newGrantFake(); f.acls = nil; return f }, ErrNotVMAdminToken},
		"descendant override": {func() *grantFake {
			f := newGrantFake()
			f.setRole("StorAudit", "Datastore.Audit")
			f.addRow("/storage/local", "StorAudit", "token", liveToken, false)
			return f
		}, ErrUpgradeWouldNotConverge},
		"root, no row, non-privsep": {func() *grantFake {
			f := newGrantFake()
			f.acls = nil
			f.tokens[liveToken] = false
			return f
		}, ErrUpgradeWouldNotConverge},
		"path B": {newGrantFake, nil},
	}
	for name, c := range cases {
		f := c.build()
		tree := f.effective(liveToken)
		pred, err := predictTree(tree, nil, f.acls, liveToken, vmD)
		if err != nil {
			t.Fatalf("%s: predict: %v", name, err)
		}
		got := judgePredicted(pred, tree, DefaultVMDestroyRole, vmD)
		if (c.wantErr == nil) != (got == nil) || (c.wantErr != nil && !errors.Is(got, c.wantErr)) {
			t.Errorf("%s: judgePredicted = %v, want %v", name, got, c.wantErr)
		}
		noVerdict(t, name, got)
	}
	// The validator ALONE accepts a limited and an empty token's prediction:
	// that is why the widening half exists (plan §3.5.4d, executed).
	for _, name := range []string{"limited: nil from the validator alone, refused by the widening half", "empty"} {
		f := cases[name].build()
		tree := f.effective(liveToken)
		pred, _ := predictTree(tree, nil, f.acls, liveToken, vmD)
		if err := judgeAgainstRole(pred, DefaultVMDestroyRole, vmD); err != nil {
			t.Errorf("%s: the validator was expected to accept the predicted tree, got %v", name, err)
		}
	}
	// A group can never confer anything on a token: with Sys.Audit only through
	// a group, the token's tree is unchanged by it, and it is not enabled.
	g := newGrantFake()
	g.groups["ops"] = []string{liveToken}
	g.setRole("AuditOnly", "Sys.Audit")
	g.addRow("/", "AuditOnly", "group", "ops", true)
	if tr := g.effective(liveToken); tr["/"]["Sys.Audit"] {
		t.Fatalf("the fake let a group confer Sys.Audit on a token: %v", tr["/"])
	}
}

// ---- T13: the lock is held across the write AND the effective read-back ----

func TestEnable_T13_LockHeldAcrossWriteAndReadBack(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	key := lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"}
	blocked := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		unlock, err := lock.Mutation(ctx, r.roster, key)
		if err == nil {
			_ = unlock()
			return false
		}
		return true
	}
	var atWrite, atReadBack, readsAfterWrite int
	wrote := false
	f.before = func(cmd string) {
		switch {
		case strings.HasPrefix(cmd, cmdACLModify+" "):
			wrote = true
			if blocked() {
				atWrite++
			}
		case wrote && strings.HasPrefix(cmd, "pveum user permissions"):
			readsAfterWrite++
			if blocked() {
				atReadBack++
			}
		}
	}
	if _, err := r.do(); err != nil {
		t.Fatal(err)
	}
	if atWrite != 1 || readsAfterWrite == 0 || atReadBack != readsAfterWrite {
		t.Fatalf("lock held at the acl modify %d/1, at the effective read-back %d/%d", atWrite, atReadBack, readsAfterWrite)
	}
	if blocked() {
		t.Fatal("the lock was still held after the verb returned")
	}
}

// A dry run reads only and takes no lock.
func TestEnable_DryRunTakesNoLock(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	r.req.DryRun = true
	unlock, err := lock.Mutation(context.Background(), r.roster, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a := NewRootAccess(AccessOptions{Addr: "x:22", SSHUser: "root", PrivateKeyPEM: []byte("K"), HostKeyFingerprint: "SHA256:p", OwnToken: liveToken}, &grantTransport{sess: f, calls: new(int)})
	if _, err := EnableVMDestroy(ctx, a, r.req); err != nil {
		t.Fatalf("a dry run must not wait for the lock: %v", err)
	}
}

// With the lock held by someone else, a real run fails on it and writes nothing.
func TestEnable_LockHeldElsewhereBlocksTheWrite(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	unlock, err := lock.Mutation(context.Background(), r.roster, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "bootstrap", ID: "token"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	a := NewRootAccess(AccessOptions{Addr: "x:22", SSHUser: "root", PrivateKeyPEM: []byte("K"), HostKeyFingerprint: "SHA256:p", OwnToken: liveToken}, &grantTransport{sess: f, calls: new(int)})
	_, err = EnableVMDestroy(ctx, a, r.req)
	if err == nil || !strings.Contains(err.Error(), "qa-pve-01/bootstrap/token") {
		t.Fatalf("want a lock error naming the key, got %v", err)
	}
	if len(f.commands) != 0 {
		t.Fatalf("the host was touched without the lock: %q", f.commands)
	}
}

// The request needs the lock identity unless it is a dry run.
func TestEnable_NeedsLockIdentity(t *testing.T) {
	f := newGrantFake()
	r := newEnableRun(t, f)
	r.req.RosterPath = ""
	if _, err := r.do(); err == nil || len(f.commands) != 0 {
		t.Fatalf("err %v, commands %q", err, f.commands)
	}
}
