package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// `user ensure`, `group ensure` and `acl grant` through the whole CLI: the
// token's REST view is a route fake, and root is the real SSH transport
// against internal/pvefake's SSH server, dialed at the fake's address in
// place of <host>:22. The fixture roster's own token is root@pam!pveforge.

// addrRewrite is the production transport with every address replaced.
type addrRewrite struct {
	inner bootstrap.SSHTransport
	addr  string
}

func (a addrRewrite) InstallPubkeyViaPassword(ctx context.Context, _, user, password, line, pin string) (string, error) {
	return a.inner.InstallPubkeyViaPassword(ctx, a.addr, user, password, line, pin)
}

func (a addrRewrite) DialWithKey(ctx context.Context, _, user string, key []byte, fp string) (bootstrap.SSHSession, error) {
	return a.inner.DialWithKey(ctx, a.addr, user, key, fp)
}

func (a addrRewrite) DialWithPassword(ctx context.Context, _, user, password, pin string) (bootstrap.SSHSession, string, error) {
	return a.inner.DialWithPassword(ctx, a.addr, user, password, pin)
}

func (a addrRewrite) ReconnectWithPinnedKey(ctx context.Context, _, user string, key []byte, fp string) (bootstrap.SSHSession, error) {
	return a.inner.ReconnectWithPinnedKey(ctx, a.addr, user, key, fp)
}

// rootAt points the access commands' SSH dials at fs for this test.
func rootAt(t *testing.T, fs *pvefake.SSHServer) {
	orig := newAccessTransport
	t.Cleanup(func() { newAccessTransport = orig })
	newAccessTransport = func() bootstrap.SSHTransport { return addrRewrite{inner: bootstrap.NewSSHTransport(), addr: fs.Addr()} }
}

// pveumFake answers the pveum commands root runs; everything else succeeds
// silently.
func pveumFake(answers map[string]string) func(cmd string) (string, string, int) {
	return func(cmd string) (string, string, int) {
		for prefix, out := range answers {
			if strings.HasPrefix(cmd, prefix) {
				return out, "", 0
			}
		}
		return "", "", 0
	}
}

const (
	usersWithoutAlice = `{"data":[{"userid":"root@pam","enable":1}]}`
	usersWithAlice    = `{"data":[{"userid":"root@pam","enable":1},{"userid":"alice@pve","enable":1,"groups":"ops"}]}`
	cliRoleList       = `[{"roleid":"PVEVMUser","privs":"VM.Audit,VM.Console"},{"roleid":"Administrator","privs":"Permissions.Modify,Sys.Modify,VM.Audit"}]`
	cliGroupList      = `[{"groupid":"ops","users":"alice@pve"},{"groupid":"admins","users":"root@pam"}]`
	cliUserList       = `[{"userid":"root@pam","enable":1,"groups":"admins"},{"userid":"alice@pve","enable":1,"groups":"ops"}]`
)

// accessSetup starts a REST fake and an SSH fake with its keyed roster.
func accessSetup(t *testing.T, routes map[string]string, answers map[string]string) (string, *pvefake.SSHServer, *routeFake) {
	t.Helper()
	return accessSetupExec(t, routes, pveumFake(answers))
}

// accessSetupExec is accessSetup with root's commands answered by exec.
func accessSetupExec(t *testing.T, routes map[string]string, exec func(cmd string) (string, string, int)) (string, *pvefake.SSHServer, *routeFake) {
	t.Helper()
	srv, rf := newRouteFake(t, routes)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(exec)
	path := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return path, fs, rf
}

// isPveumWrite reports whether root's command is a pveum user or group
// write (add or modify).
func isPveumWrite(cmd string) bool {
	for _, p := range []string{"pveum user add ", "pveum user modify ", "pveum group add ", "pveum group modify "} {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return false
}

// accessSetupWrites is accessSetup with a REST fake that reflects root's
// writes: each route answers from before until root has run a pveum user or
// group write, then from after where after has the route. Without it the
// post-write re-read sees the old list, and user/group ensure's read-back
// check (PostApply) rightly reports a mismatch.
func accessSetupWrites(t *testing.T, before, after, answers map[string]string) (string, *pvefake.SSHServer, *routeFake) {
	t.Helper()
	var written atomic.Bool
	answer := pveumFake(answers)
	srv, rf := newRouteFakeFunc(t, func(key string) (string, bool) {
		if body, ok := after[key]; ok && written.Load() {
			return body, true
		}
		body, ok := before[key]
		return body, ok
	})
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if isPveumWrite(cmd) {
			written.Store(true)
		}
		return answer(cmd)
	})
	path := newTestRosterWithSSHTarget(t, srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return path, fs, rf
}

func TestUserEnsure_CreatesAsRoot(t *testing.T) {
	path, fs, rf := accessSetupWrites(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice},
		map[string]string{"GET /api2/json/access/users": `{"data":[{"userid":"root@pam","enable":1},{"userid":"alice@pve","enable":1,"comment":"Ops","groups":"ops"}]}`}, map[string]string{
			"pveum role list": cliRoleList,
			"pveum acl list":  `[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0}]`,
		})
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "ops", "--comment", "Ops")
	if code != 0 || stdout != "qa-pve-01: user alice@pve created\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := "notice: qa-pve-01: user alice@pve has no password: it cannot log in until one is set with pveum passwd\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	// Joining ops is a grant: its ACLs and their roles are read as root first.
	if want := []string{"pveum role list --output-format json", "pveum acl list --output-format json", "pveum user add 'alice@pve' --enable 1 --comment 'Ops' --groups 'ops'"}; !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q, want %q", fs.Commands(), want)
	}
	// The decision read and the post-write re-read, both over the token.
	requireHits(t, rf, "GET /api2/json/access/users", "GET /api2/json/access/users")
}

// A user already as asked is left alone, and root is never connected to.
func TestUserEnsure_AlreadyAsAskedNeverOpensRoot(t *testing.T) {
	path, fs, _ := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithAlice}, nil)
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--enable", "--group", "ops")
	if code != 0 || stdout != "qa-pve-01: user alice@pve unchanged\n" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if len(fs.Commands()) != 0 {
		t.Errorf("root ran %q", fs.Commands())
	}
}

// A token that may not read users (403): root's list decides instead.
func TestUserEnsure_TokenRefusedReadsAsRoot(t *testing.T) {
	forbidden := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission check failed", http.StatusForbidden)
	}))
	t.Cleanup(forbidden.Close)
	fs := pvefake.NewSSHServer(t)
	// Root's list reflects root's own modify, as PVE's would.
	var modified atomic.Bool
	fs.HandleExec(func(cmd string) (string, string, int) {
		if isPveumWrite(cmd) {
			modified.Store(true)
		}
		if strings.HasPrefix(cmd, "pveum user list") {
			if modified.Load() {
				return `[{"userid":"alice@pve","enable":0}]`, "", 0
			}
			return `[{"userid":"alice@pve","enable":1}]`, "", 0
		}
		return "", "", 0
	})
	path := newTestRosterWithSSHTarget(t, forbidden, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--disable")
	if code != 0 || stdout != "qa-pve-01: user alice@pve updated\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := "notice: qa-pve-01: user alice@pve is disabled: it cannot log in, and its API tokens stop working\n"; stderr != want {
		t.Errorf("stderr = %q", stderr)
	}
	want := []string{"pveum user list --full 1 --output-format json", "pveum user modify 'alice@pve' --enable 0", "pveum user list --full 1 --output-format json"}
	if !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q\nwant %q", fs.Commands(), want)
	}
}

func TestUserEnsure_RefusesToDisablePveforgesOwnUser(t *testing.T) {
	path, fs, rf := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil)
	code, _, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "root@pam", "--disable")
	if code != 1 || !strings.Contains(stderr, "owns the roster's own token root@pam!pveforge") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if len(fs.Commands()) != 0 || len(rf.got()) != 0 {
		t.Errorf("reached PVE: root %q, REST %q", fs.Commands(), rf.got())
	}
}

func TestUserEnsure_BadInputRefusedBeforeAnything(t *testing.T) {
	path, fs, rf := accessSetup(t, map[string]string{}, nil)
	for _, args := range [][]string{
		{"alice"},
		{"alice@pve", "--enable", "--disable"},
		{"alice@pve", "--comment", "two\nlines"},
		{"alice@pve", "--group", "bad group"},
	} {
		code, _, stderr := runRootArgs(append([]string{"user", "ensure", "--roster", path, "qa-pve-01"}, args...)...)
		if code != 1 {
			t.Errorf("%q: exit %d, stderr %q", args, code, stderr)
		}
	}
	if len(fs.Commands()) != 0 || len(rf.got()) != 0 {
		t.Errorf("reached PVE: root %q, REST %q", fs.Commands(), rf.got())
	}
}

func TestGroupEnsure_CreatesAsRoot(t *testing.T) {
	path, fs, _ := accessSetupWrites(t, map[string]string{"GET /api2/json/access/groups": `{"data":[{"groupid":"dev"}]}`},
		map[string]string{"GET /api2/json/access/groups": `{"data":[{"groupid":"dev"},{"groupid":"ops","comment":"Ops team"}]}`}, nil)
	code, stdout, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops", "--comment", "Ops team")
	if code != 0 || stdout != "qa-pve-01: group ops created\n" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := []string{"pveum group add 'ops' --comment 'Ops team'"}; !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q", fs.Commands())
	}
}

func TestACLGrant_GrantsAsRootAndReadsBack(t *testing.T) {
	path, fs, rf := accessSetup(t, nil, map[string]string{
		"pveum role list":  cliRoleList,
		"pveum group list": cliGroupList,
		"pveum user list":  cliUserList,
		"pveum acl list":   `[{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0}]`,
	})
	code, stdout, stderr := runRootArgs("acl", "grant", "--roster", path, "qa-pve-01", "--group", "ops", "--grant", "/vms/100:PVEVMUser")
	if code != 0 || stdout != "qa-pve-01: granted PVEVMUser on /vms/100 to group ops (propagate 0)\n" || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	want := []string{
		"pveum role list --output-format json",
		"pveum group list --output-format json",
		"pveum user list --full 1 --output-format json",
		"pveum acl modify '/vms/100' --groups 'ops' --roles 'PVEVMUser' --propagate 0",
		"pveum acl list --output-format json",
	}
	if !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q\nwant %q", fs.Commands(), want)
	}
	if len(rf.got()) != 0 {
		t.Errorf("the grant used the token: %q", rf.got())
	}
}

// Every refusal: exit 1, and no ACL changed. The self refusals, and bad
// input, never open root at all.
func TestACLGrant_Refusals(t *testing.T) {
	answers := map[string]string{"pveum role list": cliRoleList, "pveum group list": cliGroupList, "pveum user list": cliUserList, "pveum acl list": `[]`}
	cases := []struct {
		name   string
		args   []string
		has    string
		noRoot bool
	}{
		{"the roster's own token", []string{"--token", "root@pam!pveforge", "--grant", "/:PVEVMUser"}, "the roster's own token", true},
		{"the user owning it", []string{"--user", "root@pam", "--grant", "/:PVEVMUser"}, "owns the roster's token", true},
		{"a group holding that user", []string{"--group", "admins", "--grant", "/:PVEVMUser"}, "holds root@pam", false},
		{"an escalating role", []string{"--user", "bob@pve", "--grant", "/:Administrator"}, "--allow-escalating-role", false},
		{"no principal", []string{"--grant", "/:PVEVMUser"}, "exactly one of", true},
		{"two principals", []string{"--user", "bob@pve", "--group", "ops", "--grant", "/:PVEVMUser"}, "exactly one of", true},
		{"no grant", []string{"--user", "bob@pve"}, "at least one --grant", true},
		{"a malformed grant", []string{"--user", "bob@pve", "--grant", "/:PVEVMUser:1"}, "PATH:ROLE::1", true},
		{"read-back missing", []string{"--user", "bob@pve", "--grant", "/vms/100:PVEVMUser"}, "not in the ACL list", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, fs, _ := accessSetup(t, nil, answers)
			code, stdout, stderr := runRootArgs(append([]string{"acl", "grant", "--roster", path, "qa-pve-01"}, c.args...)...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, c.has) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 1 naming %q", code, stdout, stderr, c.has)
			}
			for _, cmd := range fs.Commands() {
				if strings.HasPrefix(cmd, "pveum acl modify") && c.name != "read-back missing" {
					t.Errorf("an ACL was changed: %q", cmd)
				}
			}
			if c.noRoot && len(fs.Commands()) != 0 {
				t.Errorf("root ran %q", fs.Commands())
			}
		})
	}
}

func TestACLGrant_EscalatingRoleAllowedWarns(t *testing.T) {
	path, _, _ := accessSetup(t, nil, map[string]string{
		"pveum role list": cliRoleList, "pveum group list": cliGroupList, "pveum user list": cliUserList,
		"pveum acl list": `[{"path":"/","roleid":"Administrator","type":"user","ugid":"bob@pve","propagate":0}]`,
	})
	code, stdout, stderr := runRootArgs("acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/:Administrator", "--allow-escalating-role")
	if code != 0 || stdout != "qa-pve-01: granted Administrator on / to user bob@pve (propagate 0)\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := "warning: qa-pve-01: Administrator on /, granted to user bob@pve, confers Permissions.Modify,Sys.Modify: its holder can widen its own or anyone's access\n"; stderr != want {
		t.Errorf("stderr = %q\nwant     %q", stderr, want)
	}
}

// A target holding no SSH key is refused without --no-ssh-key, and with it
// root is dialed with the PVE password.
func TestAccess_KeylessTarget(t *testing.T) {
	srv, _ := newRouteFake(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`})
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "root-pw")
	fs.Start()
	path := writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)

	code, _, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops")
	if code != 1 || !strings.Contains(stderr, "holds no SSH key: pass --no-ssh-key") {
		t.Fatalf("without the flag: exit %d, stderr %q", code, stderr)
	}
	t.Setenv(pvePasswordEnvVar, "root-pw")
	code, stdout, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops", "--no-ssh-key")
	if code != 0 || stdout != "qa-pve-01: group ops created\n" {
		t.Fatalf("with the flag: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := []string{"pveum group add 'ops'"}; !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q", fs.Commands())
	}
}

// SR1, the reviewer's case: the roster token's owner may join no group, in
// any spelling, and nothing reaches PVE.
func TestUserEnsure_OwnerMayJoinNoGroup(t *testing.T) {
	for _, id := range []string{"root@pam", "ROOT@pam"} {
		path, fs, rf := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil)
		code, _, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", id, "--group", "admins", "--allow-escalating-role")
		if code != 1 || !strings.Contains(stderr, "refusing --group for "+id) {
			t.Errorf("%s: exit %d, stderr %q", id, code, stderr)
		}
		if len(fs.Commands()) != 0 || len(rf.got()) != 0 {
			t.Errorf("%s reached PVE: root %q, REST %q", id, fs.Commands(), rf.got())
		}
	}
}

// SR1: joining a group that holds an escalating role is a grant of it:
// refused without --allow-escalating-role (nothing written), and with it
// done and warned about.
func TestUserEnsure_JoiningAnEscalatingGroup(t *testing.T) {
	answers := map[string]string{
		"pveum role list": cliRoleList,
		"pveum acl list":  `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1}]`,
	}
	path, fs, _ := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, answers)
	code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "admins")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "group admins holds Administrator on /") || !strings.Contains(stderr, "--allow-escalating-role") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := []string{"pveum role list --output-format json", "pveum acl list --output-format json"}; !slices.Equal(fs.Commands(), want) {
		t.Errorf("root ran %q, want only the reads", fs.Commands())
	}

	path, fs, _ = accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, answers)
	code, stdout, stderr = runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "admins", "--allow-escalating-role")
	if code != 0 || stdout != "qa-pve-01: user alice@pve created\n" {
		t.Fatalf("allowed: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if want := "warning: qa-pve-01: user alice@pve joined group admins, which holds Administrator on / conferring Permissions.Modify,Sys.Modify: the user can widen its own or anyone's access\n"; !strings.Contains(stderr, want) {
		t.Errorf("stderr %q lacks %q", stderr, want)
	}
	if !slices.Contains(fs.Commands(), "pveum user add 'alice@pve' --enable 1 --groups 'admins'") {
		t.Errorf("root ran %q", fs.Commands())
	}
}

// M5, M13: escalating holdings on paths other than /, in two groups: the
// refusal names each, and when allowed every one is warned about, one line
// each.
func TestUserEnsure_EveryEscalatingJoinIsWarned(t *testing.T) {
	answers := map[string]string{
		"pveum role list": cliRoleList,
		"pveum acl list": `[{"path":"/pool/x","roleid":"Administrator","type":"group","ugid":"admins","propagate":1},` +
			`{"path":"/vms/100","roleid":"Administrator","type":"group","ugid":"ops","propagate":0},` +
			`{"path":"/vms/100","roleid":"PVEVMUser","type":"group","ugid":"ops","propagate":0}]`,
	}
	path, fs, _ := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, answers)
	code, _, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "admins", "--group", "ops")
	if code != 1 || !strings.Contains(stderr, "group admins holds Administrator on /pool/x") || !strings.Contains(stderr, "group ops holds Administrator on /vms/100") {
		t.Fatalf("refused: exit %d, stderr %q", code, stderr)
	}
	for _, cmd := range fs.Commands() {
		if strings.HasPrefix(cmd, "pveum user") {
			t.Errorf("refused, but root ran %q", cmd)
		}
	}

	path, _, _ = accessSetupWrites(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice},
		map[string]string{"GET /api2/json/access/users": `{"data":[{"userid":"root@pam","enable":1},{"userid":"alice@pve","enable":1,"groups":"admins,ops"}]}`}, answers)
	code, _, stderr = runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "admins", "--group", "ops", "--allow-escalating-role")
	if code != 0 {
		t.Fatalf("allowed: exit %d, stderr %q", code, stderr)
	}
	var warnings []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, "warning:") {
			warnings = append(warnings, l)
		}
	}
	want := []string{
		"warning: qa-pve-01: user alice@pve joined group admins, which holds Administrator on /pool/x conferring Permissions.Modify,Sys.Modify: the user can widen its own or anyone's access",
		"warning: qa-pve-01: user alice@pve joined group ops, which holds Administrator on /vms/100 conferring Permissions.Modify,Sys.Modify: the user can widen its own or anyone's access",
	}
	if !slices.Equal(warnings, want) {
		t.Errorf("warnings = %q\nwant %q", warnings, want)
	}
}

// The README names every escalating privilege the checks use.
func TestREADME_NamesEveryEscalatingPrivilege(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range bootstrap.EscalatingPrivileges {
		if !strings.Contains(string(b), "`"+p+"`") {
			t.Errorf("README does not name %s", p)
		}
	}
}

// ---- access inventory (6b) ----

const (
	invCLIUsers = `[{"userid":"root@pam","enable":1,"groups":"admins"},{"userid":"alice@pve","enable":1,"groups":"ops","comment":"line one\nline two"}]`
	invCLIACLs  = `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1},{"path":"/","roleid":"PVEVMUser","type":"token","ugid":"root@pam!pveforge","propagate":0}]`
)

// inventoryExec answers inventory's root reads, getent included.
func inventoryExec(cmd string) (string, string, int) {
	if strings.HasPrefix(cmd, "getent passwd") {
		return "root:x:0:0:root:/root:/bin/bash\n", "", 0
	}
	return pveumFake(map[string]string{
		"pveum user list":  invCLIUsers,
		"pveum group list": cliGroupList,
		"pveum acl list":   invCLIACLs,
		"pveum role list":  cliRoleList,
	})(cmd)
}

var inventoryCommands = []string{
	"pveum user list --full 1 --output-format json",
	"pveum group list --output-format json",
	"pveum acl list --output-format json",
	"pveum role list --output-format json",
	"getent passwd -- 'root'",
}

// Every read goes over root; the token's REST view is never asked, even
// though the target holds a token. kv output keeps every key on one line,
// a comment holding a line break included.
func TestAccessInventory_ReadsAsRootKV(t *testing.T) {
	path, fs, rf := accessSetupExec(t, nil, inventoryExec)
	code, stdout, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !slices.Equal(fs.Commands(), inventoryCommands) {
		t.Errorf("root ran %q", fs.Commands())
	}
	if len(rf.got()) != 0 {
		t.Errorf("the token was asked: %q", rf.got())
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	var keys []string
	for _, l := range lines {
		k, _, _ := strings.Cut(l, "=")
		keys = append(keys, k)
	}
	if !slices.Equal(keys, []string{"acls", "groups", "target", "users"}) {
		t.Fatalf("kv keys = %q\nstdout %q", keys, stdout)
	}
	if !strings.Contains(stdout, `"comment":"line one\nline two"`) || !strings.Contains(stdout, `"os_account_status":"found"`) ||
		!strings.Contains(stdout, `"escalating":["Permissions.Modify","Sys.Modify"]`) {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestAccessInventory_JSON(t *testing.T) {
	path, _, _ := accessSetupExec(t, nil, inventoryExec)
	code, stdout, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01", "-o", "json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	var got struct {
		Target string `json:"target"`
		Users  []struct {
			UserID    string `json:"userid"`
			Status    string `json:"os_account_status"`
			OSAccount *struct {
				UID int `json:"uid"`
			} `json:"os_account"`
			ACLs []struct {
				Via string `json:"via"`
			} `json:"acls"`
		} `json:"users"`
		ACLs []struct {
			Type string `json:"type"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	if got.Target != "qa-pve-01" || len(got.Users) != 2 || got.Users[0].Status != "found" || got.Users[0].OSAccount == nil ||
		got.Users[1].Status != "not-pam" || got.Users[1].OSAccount != nil ||
		len(got.Users[0].ACLs) != 1 || got.Users[0].ACLs[0].Via != "admins" || len(got.ACLs) != 2 || got.ACLs[1].Type != "token" {
		t.Errorf("json = %s", stdout)
	}
}

// --no-ssh-key reaches the root session: without it a keyless target is
// refused, with it root is dialed with the password.
func TestAccessInventory_KeylessTarget(t *testing.T) {
	srv, rf := newRouteFake(t, nil)
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "root-pw")
	fs.HandleExec(inventoryExec)
	fs.Start()
	path := writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)

	code, _, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01")
	if code != 1 || !strings.Contains(stderr, "holds no SSH key: pass --no-ssh-key") {
		t.Fatalf("without the flag: exit %d, stderr %q", code, stderr)
	}
	t.Setenv(pvePasswordEnvVar, "root-pw")
	code, _, stderr = runRootArgs("access", "inventory", "--roster", path, "qa-pve-01", "--no-ssh-key")
	if code != 0 {
		t.Fatalf("with the flag: exit %d, stderr %q", code, stderr)
	}
	if !slices.Equal(fs.Commands(), inventoryCommands) || len(rf.got()) != 0 {
		t.Errorf("root ran %q, REST %q", fs.Commands(), rf.got())
	}
}

// A failed read is a failed command with nothing on stdout.
func TestAccessInventory_ReadFailure(t *testing.T) {
	path, _, _ := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
		if strings.HasPrefix(cmd, "pveum acl list") {
			return "", "permission denied", 13
		}
		return inventoryExec(cmd)
	})
	code, stdout, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "exited 13: permission denied") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// S2 through runRoot: free text PVE holds (a comment) reaches -o json with
// DEL and C1 escaped, never raw, and decodes back unchanged.
func TestAccessInventory_JSONEscapesC1(t *testing.T) {
	comment := "x\u0085y\u009b[31mz\u007f"
	users := `[{"userid":"root@pam","enable":1,"groups":"admins"},{"userid":"alice@pve","enable":1,"groups":"ops","comment":"x\u0085y\u009b[31mz\u007f"}]`
	path, _, _ := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
		if strings.HasPrefix(cmd, "pveum user list") {
			return users, "", 0
		}
		return inventoryExec(cmd)
	})
	code, stdout, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01", "-o", "json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if strings.ContainsFunc(stdout, func(r rune) bool { return r >= 0x7f && r <= 0x9f }) {
		t.Errorf("raw DEL or C1 on stdout: %q", stdout)
	}
	var got struct {
		Users []struct {
			Comment string `json:"comment"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil || len(got.Users) != 2 || got.Users[1].Comment != comment {
		t.Errorf("decoded %+v, %v; want comment %q", got, err, comment)
	}
}

// S4: inventory never builds the token client, so it never decrypts the
// token's secret: with a secret sealed under another passphrase it still
// runs, while group ensure, which does use the token, fails on it.
func TestAccessInventory_NeverDecryptsTheToken(t *testing.T) {
	path, fs, _ := accessSetupExec(t, nil, inventoryExec)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	head, rest, ok := strings.Cut(string(b), "secret_enc = '''\n")
	_, tail, ok2 := strings.Cut(rest, "'''")
	if !ok || !ok2 {
		t.Fatalf("no secret_enc block in %s", b)
	}
	sealed, err := fixtureEncrypt([]byte("test-secret"), "a different passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(head+"secret_enc = '''\n"+sealed+"'''"+tail), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops")
	if code == 0 || !strings.Contains(stderr, "decrypt") {
		t.Fatalf("control: group ensure exit %d, stderr %q; want a failure to decrypt the token, or the test proves nothing", code, stderr)
	}
	code, _, stderr = runRootArgs("access", "inventory", "--roster", path, "qa-pve-01")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !slices.Equal(fs.Commands(), inventoryCommands) {
		t.Errorf("root ran %q", fs.Commands())
	}
}
