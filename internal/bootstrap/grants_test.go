package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// ---- the single want: issued, skip-checked and validated as one value ----

// R18 / R6h-b: the grant bootstrap issues is exactly want[0], built from the
// NORMALIZED --acl-path, and the post-mint validator gets that same want.
func TestRun_R18_IssuedGrantIsTheValidatedWant(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.ACLPath = "pool/p/"
	session := &fakeSession{}
	v := &fakeValidator{}
	if _, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []Grant{{Path: "/pool/p", Role: "PVEVMAdmin", Propagate: true}}
	if len(v.wants) != 1 || !reflect.DeepEqual(v.wants[0], want) {
		t.Fatalf("validated wants = %#v, want [%#v]", v.wants, want)
	}
	var grants []string
	for _, c := range session.commands {
		if strings.HasPrefix(c, "pveum acl modify") {
			grants = append(grants, c)
		}
	}
	if len(grants) != 1 || grants[0] != "pveum acl modify '/pool/p' --tokens 'root@pam!pveforge' --roles 'PVEVMAdmin' --propagate 1" {
		t.Fatalf("issued grants = %q", grants)
	}
}

// R19: the skip-check and the post-mint validation get the same want.
func TestRun_R19_SkipCheckAndPostMintShareWant(t *testing.T) {
	s := seedRoster(t, heldID, "")
	s.opts.ACLPath = "/pool/p"
	session := &fakeSession{pve: newFakePVE("pveforge")}
	v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrScopeTooWide), nil}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	if err != nil || res.TokenOutcome != OutcomeReplaced {
		t.Fatalf("Run: %+v, %v", res, err)
	}
	want := []Grant{{Path: "/pool/p", Role: "PVEVMAdmin", Propagate: true}}
	if len(v.wants) != 2 || !reflect.DeepEqual(v.wants[0], want) || !reflect.DeepEqual(v.wants[1], want) {
		t.Fatalf("wants = %#v", v.wants)
	}
}

// R6i (S2): want is checked before any SSH: a role id PVE could never
// accept is refused with nothing touched.
func TestRun_R6i_WantCheckedBeforeSSH(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.ACLRole = "bad role"
	tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
	if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant, got %v", err)
	}
	if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 || len(tr.session.attempted) != 0 {
		t.Fatal("SSH was touched")
	}
}

// MP1 / MP2: grantACL always states the grant's propagation.
func TestGrantACL_StatesPropagate(t *testing.T) {
	for prop, flag := range map[bool]string{true: "--propagate 1", false: "--propagate 0"} {
		s := &fakeSession{}
		if err := grantACL(context.Background(), s, "root@pam!t", Grant{Path: "/storage/s", Role: "R", Propagate: prop}); err != nil {
			t.Fatal(err)
		}
		want := "pveum acl modify '/storage/s' --tokens 'root@pam!t' --roles 'R' " + flag
		if len(s.commands) != 1 || s.commands[0] != want {
			t.Fatalf("propagate %v: %q, want %q", prop, s.commands, want)
		}
	}
}

// ---- R13k: a constant ErrWrongScope after a remove exhausts to a verdict ----

func TestRun_R13k_WrongScopeExhaustsAfterRemove(t *testing.T) {
	fastRetries(t)
	ws := fmt.Errorf("%w", ErrWrongScope)
	s, session, tr, v := prior(t, nil, ws, ws, ws, nil)
	res, err := Run(context.Background(), s.opts, tr, v)
	wantRevoked(t, res, err)
	if res.Validation != ValidationFailed || v.calls != 1+postMintAttempts || session.count("pveum user token remove") != 2 {
		t.Fatalf("result = %+v, calls = %d, commands = %v", res, v.calls, session.commands)
	}
	noToken(t, s.path)
}

// ---- R6e-b / R6e-c: the requested role's privileges, strictly ----

func TestRun_R6e_RolePrivileges(t *testing.T) {
	for name, tc := range map[string]struct {
		role, list string
		want       error // nil: a non-verdict preflight error
	}{
		"R6e-b NoAccess":             {"NoAccess", `[{"privs":"","roleid":"NoAccess","special":1}]`, ErrRoleHasNoPrivileges},
		"R6e-c a bad privilege name": {"R", `[{"privs":"A\nB","roleid":"R","special":0}]`, nil},
		"R6e-c no privs field":       {"R", `[{"roleid":"R","special":0}]`, nil},
		"R6e-c an empty name":        {"R", `[{"privs":"A,,B","roleid":"R","special":0}]`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			s := seedRoster(t, heldID, "")
			s.opts.ACLRole = tc.role
			session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: tc.list}}}}
			v := &fakeValidator{err: fmt.Errorf("%w", ErrWrongScope)}
			_, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if isVerdict(err) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("a verdict, or a multi-line error: %q", err)
			}
			if session.ran("pveum user token") || v.calls != 0 {
				t.Fatalf("got past the preflight: %v", session.commands)
			}
		})
	}
	// Only the REQUESTED roles are parsed strictly: a malformed unrelated
	// role does not block a run.
	path := newTestRoster(t, "")
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: `[{"privs":"x y","roleid":"Other"},{"privs":"VM.Allocate","roleid":"PVEVMAdmin"}]`}}}}
	if _, err := Run(context.Background(), baseOptions(path), &fakeTransport{installFingerprint: "SHA256:abc", session: session}, &fakeValidator{}); err != nil {
		t.Fatalf("an unrequested role blocked the run: %v", err)
	}
}

// ---- R20: the owner check (B1, S4) ----

const aliceRoles = `[{"privs":"VM.Allocate,VM.Audit","roleid":"PVEVMAdmin","special":1}]`

func userList(owner string, enable, expire int64) string {
	return fmt.Sprintf(`[{"enable":1,"expire":0,"userid":"root@pam"},{"enable":%d,"expire":%d,"userid":%q}]`, enable, expire, owner)
}

type ownerRun struct {
	res     *Result
	err     error
	session *fakeSession
	v       *fakeValidator
	changed bool // the roster changed
}

// runOwner runs a reconnect for owner, whose held token is present on PVE
// and whose skip-check would say ErrWrongScope (then nil), with the given
// owner answers layered over the role list and a healthy user list.
func runOwner(t *testing.T, owner string, byCmd map[string]fakeRunResult) ownerRun {
	t.Helper()
	s := seedRoster(t, owner+"!pveforge", "")
	s.opts.PVEUsername = owner
	before := rosterBytes(t, s.path)
	cmds := map[string]fakeRunResult{
		"pveum role list": {res: RunResult{Stdout: aliceRoles}},
		"pveum user list": {res: RunResult{Stdout: userList(owner, 1, 0)}},
	}
	for k, r := range byCmd {
		cmds[k] = r
	}
	session := &fakeSession{pve: newFakePVE("pveforge"), byCmd: cmds}
	v := &fakeValidator{errs: []error{fmt.Errorf("%w", ErrWrongScope), nil}}
	res, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, v)
	return ownerRun{res: res, err: err, session: session, v: v, changed: !bytes.Equal(before, rosterBytes(t, s.path))}
}

func perms(stdout string) fakeRunResult { return fakeRunResult{res: RunResult{Stdout: stdout}} }

// untouched asserts the run stopped in the preflight: no validator call, no
// token or ACL command, the roster byte-identical.
func (o ownerRun) untouched(t *testing.T) {
	t.Helper()
	if o.v.calls != 0 || len(o.session.mutating()) != 0 || o.session.ran("pveum user token list") || o.changed {
		t.Fatalf("the run got past the owner check: calls=%d commands=%v changed=%v", o.v.calls, o.session.commands, o.changed)
	}
	if isVerdict(o.err) {
		t.Fatalf("the owner check's error is a verdict: %v", o.err)
	}
}

func TestRun_R20_OwnerCheck(t *testing.T) {
	t.Run("R20 the owner lacks a privilege: abort before the skip-check, nothing removed", func(t *testing.T) {
		o := runOwner(t, "alice@pam", map[string]fakeRunResult{"pveum user permissions": perms(`{"/":{"VM.Allocate":1}}`)})
		if !errors.Is(o.err, ErrOwnerLacksPrivileges) || !strings.Contains(o.err.Error(), "lacks [VM.Audit]") || !strings.Contains(o.err.Error(), "alice@pam") {
			t.Fatalf("want ErrOwnerLacksPrivileges naming VM.Audit, got %v", o.err)
		}
		o.untouched(t)
		if got := o.session.commands; !contains(got, "pveum user permissions 'alice@pam' --path '/' --output-format json") {
			t.Fatalf("the owner command was not issued, shell-quoted: %v", got)
		}
	})
	t.Run("R20 row MO4: a root-prefixed owner is not exempt", func(t *testing.T) {
		o := runOwner(t, "rootless@pam", map[string]fakeRunResult{"pveum user permissions": perms(`{"/":{"VM.Allocate":1}}`)})
		if !errors.Is(o.err, ErrOwnerLacksPrivileges) {
			t.Fatalf("want ErrOwnerLacksPrivileges, got %v", o.err)
		}
		o.untouched(t)
	})
	t.Run("R20b held only without propagate, for a propagating grant", func(t *testing.T) {
		o := runOwner(t, "alice@pam", map[string]fakeRunResult{"pveum user permissions": perms(`{"/":{"VM.Allocate":0,"VM.Audit":false}}`)})
		if !errors.Is(o.err, ErrOwnerLacksPrivileges) || !strings.Contains(o.err.Error(), "without propagate [VM.Allocate,VM.Audit]") {
			t.Fatalf("want ErrOwnerLacksPrivileges naming both as flag-only, got %v", o.err)
		}
		o.untouched(t)
	})
	for name, answer := range map[string]fakeRunResult{
		"keyed by another path": perms(`{"/other":{"VM.Allocate":1,"VM.Audit":1}}`),
		"an extra key":          perms(`{"/":{"VM.Allocate":1,"VM.Audit":1},"/x":{}}`),
		"null":                  perms(`null`),
		"null set":              perms(`{"/":null}`),
		"not JSON":              perms(`VM.Allocate`),
		"a bad flag":            perms(`{"/":{"VM.Allocate":2,"VM.Audit":1}}`),
		"a bad name":            perms(`{"/":{"VM Allocate":1,"VM.Audit":1}}`),
		"exit 1":                {res: RunResult{ExitCode: 1, Stderr: "no such user"}},
		"transport error":       {err: errors.New("connection lost")},
	} {
		t.Run("R20d "+name, func(t *testing.T) {
			o := runOwner(t, "alice@pam", map[string]fakeRunResult{"pveum user permissions": answer})
			if o.err == nil || errors.Is(o.err, ErrOwnerLacksPrivileges) {
				t.Fatalf("want a non-verdict read error, got %v", o.err)
			}
			o.untouched(t)
		})
	}
	for name, list := range map[string]string{
		"not in the list":      `[{"enable":1,"expire":0,"userid":"root@pam"}]`,
		"no enable field":      `[{"expire":0,"userid":"alice@pam"}]`,
		"no expire field":      `[{"enable":1,"userid":"alice@pam"}]`,
		"the list is not JSON": `nope`,
	} {
		t.Run("R20d user list "+name, func(t *testing.T) {
			o := runOwner(t, "alice@pam", map[string]fakeRunResult{"pveum user list": perms(list)})
			if o.err == nil || errors.Is(o.err, ErrOwnerDisabled) {
				t.Fatalf("want a non-verdict read error, got %v", o.err)
			}
			o.untouched(t)
		})
	}
	for name, list := range map[string]string{
		"disabled": userList("alice@pam", 0, 0),
		"expired":  userList("alice@pam", 1, 1),
	} {
		t.Run("R20h (S4) "+name, func(t *testing.T) {
			o := runOwner(t, "alice@pam", map[string]fakeRunResult{
				"pveum user list":        perms(list),
				"pveum user permissions": perms(`{"/":{"VM.Allocate":1,"VM.Audit":1}}`),
			})
			if !errors.Is(o.err, ErrOwnerDisabled) {
				t.Fatalf("want ErrOwnerDisabled, got %v", o.err)
			}
			o.untouched(t)
			if o.session.ran("pveum user permissions") {
				t.Fatal("permissions were read for an inactive owner")
			}
		})
	}
	t.Run("R20e the owner covers everything: the run proceeds", func(t *testing.T) {
		o := runOwner(t, "alice@pam", map[string]fakeRunResult{
			"pveum user list":        perms(userList("alice@pam", 1, 4102444800)), // expires in 2100
			"pveum user permissions": perms(`{"/":{"VM.Allocate":1,"VM.Audit":1,"Sys.Audit":1}}`),
		})
		if o.err != nil || o.res.TokenOutcome != OutcomeReplaced {
			t.Fatalf("Run: %+v, %v", o.res, o.err)
		}
		if o.session.count("pveum user permissions") != 1 || o.session.count("pveum user list") != 1 {
			t.Fatalf("want one owner read each: %v", o.session.commands)
		}
	})
	t.Run("R20c root@pam: nothing is read about the owner", func(t *testing.T) {
		s := seedRoster(t, heldID, "")
		session := &fakeSession{pve: newFakePVE("pveforge")}
		if _, err := Run(context.Background(), s.opts, &fakeTransport{session: session}, &fakeValidator{}); err != nil {
			t.Fatal(err)
		}
		if session.ran("pveum user permissions") || session.ran("pveum user list") {
			t.Fatalf("an owner read was issued for root@pam: %v", session.commands)
		}
	})
	t.Run("R20f a first bootstrap: abort before any add", func(t *testing.T) {
		opts := baseOptions(newTestRoster(t, ""))
		opts.PVEUsername = "alice@pam"
		session := &fakeSession{byCmd: map[string]fakeRunResult{
			"pveum role list":        {res: RunResult{Stdout: aliceRoles}},
			"pveum user list":        perms(userList("alice@pam", 1, 0)),
			"pveum user permissions": perms(`{"/":{}}`), // L1: an owner with nothing at the path
		}}
		v := &fakeValidator{}
		_, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
		if !errors.Is(err, ErrOwnerLacksPrivileges) || !strings.Contains(err.Error(), "lacks [VM.Allocate,VM.Audit]") {
			t.Fatalf("want ErrOwnerLacksPrivileges, got %v", err)
		}
		if len(session.mutating()) != 0 || v.calls != 0 {
			t.Fatalf("got past the preflight: %v", session.commands)
		}
	})
	t.Run("R20g today's SSH mode: pveum refuses a non-root user at the role list", func(t *testing.T) {
		o := runOwner(t, "alice@pam", map[string]fakeRunResult{
			"pveum role list": {res: RunResult{ExitCode: 255, Stderr: "please run as root"}},
		})
		if o.err == nil || !strings.Contains(o.err.Error(), "please run as root") {
			t.Fatalf("want the role list's refusal, got %v", o.err)
		}
		o.untouched(t)
		if o.session.ran("pveum user") {
			t.Fatalf("an owner read ran after the refusal: %v", o.session.commands)
		}
	})
}

// ownerCovers, directly: a pinned set is used as given.
func TestOwnerCovers(t *testing.T) {
	missing, flagOnly := ownerCovers(map[string]bool{"A": true, "B": false}, Grant{Path: "/p", Propagate: true}, []string{"C", "B", "A"})
	if strings.Join(missing, ",") != "C" || strings.Join(flagOnly, ",") != "B" {
		t.Fatalf("missing=%v flagOnly=%v", missing, flagOnly)
	}
	missing, flagOnly = ownerCovers(map[string]bool{"A": true, "B": false}, Grant{Path: "/p"}, []string{"A", "B"})
	if missing != nil || flagOnly != nil {
		t.Fatalf("a non-propagating grant needs no flag: missing=%v flagOnly=%v", missing, flagOnly)
	}
}

// ---- R21: a bare user name is canonical everywhere ----

func TestRun_R21_BareRootIsRootAtPam(t *testing.T) {
	opts := baseOptions(newTestRoster(t, ""))
	opts.PVEUsername = "root"
	session := &fakeSession{}
	v := &fakeValidator{}
	res, err := Run(context.Background(), opts, &fakeTransport{installFingerprint: "SHA256:abc", session: session}, v)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TokenID != "root@pam!pveforge" || v.lastCfg.TokenID != "root@pam!pveforge" {
		t.Fatalf("token id = %q / %q", res.TokenID, v.lastCfg.TokenID)
	}
	for _, c := range session.commands {
		if strings.Contains(c, "'root'") || strings.Contains(c, "root!") {
			t.Fatalf("a command used the bare name: %q", c)
		}
		if strings.HasPrefix(c, "pveum user permissions") || strings.HasPrefix(c, "pveum user list") {
			t.Fatalf("an owner read was issued for root@pam: %q", c)
		}
	}
	if !session.ran("pveum user token add 'root@pam' 'pveforge'") {
		t.Fatalf("commands = %v", session.commands)
	}
}

// An empty user name is refused before any SSH, bare or with @pam.
func TestRun_EmptyUserNameRefused(t *testing.T) {
	for _, u := range []string{"@pam", "@"} {
		opts := baseOptions(newTestRoster(t, ""))
		opts.PVEUsername = u
		tr := &fakeTransport{installFingerprint: "SHA256:abc", session: &fakeSession{}}
		if _, err := Run(context.Background(), opts, tr, &fakeValidator{}); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("%q: want an empty-name refusal, got %v", u, err)
		}
		if tr.installCalls+tr.dialCalls+tr.reconnectCalls != 0 {
			t.Fatalf("%q: SSH was touched", u)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- R3: the multi-grant seams, driven directly ----

// fakeOwner is a scriptable ownerReader: perms per path, every read
// recorded in order.
type fakeOwner struct {
	active bool
	perms  map[string]map[string]bool
	reads  []string
}

func (f *fakeOwner) ownerActive(context.Context, string) (bool, error) { return f.active, nil }

func (f *fakeOwner) ownerPerms(_ context.Context, _ string, path string) (map[string]bool, error) {
	f.reads = append(f.reads, path)
	p, ok := f.perms[path]
	if !ok {
		return nil, fmt.Errorf("unexpected owner read at %s", path)
	}
	return p, nil
}

// twoGrants: distinct paths, distinct roles with disjoint privileges, the
// first pinned to a strict subset of its role, the second unpinned.
var twoGrants = []Grant{
	{Path: "/pool/p", Role: "RoleA", Privs: []string{"A1"}},
	{Path: "/storage/s", Role: "RoleB"},
}

const twoRoleList = `[{"privs":"A1,A2","roleid":"RoleA","special":0},{"privs":"B1,B2","roleid":"RoleB","special":0}]`

func runPreflight(t *testing.T, roleList string, owner *fakeOwner) error {
	t.Helper()
	orig := dryRunTokenWrite
	dryRunTokenWrite = func(string, string) error { return nil }
	t.Cleanup(func() { dryRunTokenWrite = orig })
	opts := baseOptions("unused")
	opts.PVEUsername = "alice@pam"
	session := &fakeSession{byCmd: map[string]fakeRunResult{"pveum role list": {res: RunResult{Stdout: roleList}}}}
	_, err := preflight(context.Background(), session, opts, twoGrants, owner)
	return err
}

func TestPreflight_R3_TwoGrants(t *testing.T) {
	covers := func() *fakeOwner {
		return &fakeOwner{active: true, perms: map[string]map[string]bool{
			"/pool/p":    {"A1": false}, // the pinned set only: not A2
			"/storage/s": {"B1": false, "B2": false},
		}}
	}
	t.Run("the owner holds exactly each grant's set: accepted, each path read once, in order", func(t *testing.T) {
		o := covers()
		if err := runPreflight(t, twoRoleList, o); err != nil {
			t.Fatal(err)
		}
		if strings.Join(o.reads, " ") != "/pool/p /storage/s" {
			t.Fatalf("owner reads = %v", o.reads)
		}
	})
	t.Run("the owner lacks a privilege of the SECOND grant's role", func(t *testing.T) {
		o := covers()
		o.perms["/storage/s"] = map[string]bool{"B1": false}
		err := runPreflight(t, twoRoleList, o)
		if !errors.Is(err, ErrOwnerLacksPrivileges) || !strings.Contains(err.Error(), "at /storage/s lacks [B2]") {
			t.Fatalf("want ErrOwnerLacksPrivileges at /storage/s naming B2, got %v", err)
		}
	})
	t.Run("the owner lacks the FIRST grant's pinned privilege", func(t *testing.T) {
		o := covers()
		o.perms["/pool/p"] = map[string]bool{"A2": false}
		err := runPreflight(t, twoRoleList, o)
		if !errors.Is(err, ErrOwnerLacksPrivileges) || !strings.Contains(err.Error(), "at /pool/p lacks [A1]") {
			t.Fatalf("want ErrOwnerLacksPrivileges at /pool/p naming A1, got %v", err)
		}
	})
	t.Run("the second role is absent from the role list", func(t *testing.T) {
		err := runPreflight(t, `[{"privs":"A1,A2","roleid":"RoleA","special":0}]`, covers())
		if !errors.Is(err, ErrUnknownRole) || !strings.Contains(err.Error(), `"RoleB"`) {
			t.Fatalf("want ErrUnknownRole naming RoleB, got %v", err)
		}
	})
	t.Run("the second role grants nothing", func(t *testing.T) {
		err := runPreflight(t, `[{"privs":"A1,A2","roleid":"RoleA"},{"privs":"","roleid":"RoleB"}]`, covers())
		if !errors.Is(err, ErrRoleHasNoPrivileges) || !strings.Contains(err.Error(), "RoleB") {
			t.Fatalf("want ErrRoleHasNoPrivileges naming RoleB, got %v", err)
		}
	})
}

// checkOwner reads each distinct path once, even when two grants share it.
func TestCheckOwner_OneReadPerDistinctPath(t *testing.T) {
	o := &fakeOwner{active: true, perms: map[string]map[string]bool{"/pool/p": {"A": true}}}
	want := []Grant{{Path: "/pool/p", Role: "R", Privs: []string{"A"}}, {Path: "/pool/p", Role: "S", Privs: []string{"A"}}}
	if err := checkOwner(context.Background(), o, "alice@pam", want, nil); err != nil {
		t.Fatal(err)
	}
	if len(o.reads) != 1 {
		t.Fatalf("owner reads = %v", o.reads)
	}
}

// grantAll issues every grant, in order, each with its own propagation,
// and stops at the first failure.
func TestGrantAll_OrderAndStop(t *testing.T) {
	want := []Grant{
		{Path: "/pool/p", Role: "R1"},
		{Path: "/storage/s", Role: "R2", Propagate: true},
		{Path: "/sdn/zones/z", Role: "R3"},
	}
	s := &fakeSession{}
	if err := grantAll(context.Background(), s, "u@pam!t", want); err != nil {
		t.Fatal(err)
	}
	wantCmds := []string{
		"pveum acl modify '/pool/p' --tokens 'u@pam!t' --roles 'R1' --propagate 0",
		"pveum acl modify '/storage/s' --tokens 'u@pam!t' --roles 'R2' --propagate 1",
		"pveum acl modify '/sdn/zones/z' --tokens 'u@pam!t' --roles 'R3' --propagate 0",
	}
	if !reflect.DeepEqual(s.commands, wantCmds) {
		t.Fatalf("commands = %q", s.commands)
	}
	s = &fakeSession{byCmd: map[string]fakeRunResult{"pveum acl modify '/storage/s'": {res: RunResult{ExitCode: 1, Stderr: "no"}}}}
	if err := grantAll(context.Background(), s, "u@pam!t", want); err == nil {
		t.Fatal("want the second grant's failure")
	}
	if !reflect.DeepEqual(s.commands, wantCmds[:2]) {
		t.Fatalf("did not stop at the first failure: %q", s.commands)
	}
}
