package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// Family S4 (the root-SSH access verbs: user ensure, group ensure, acl grant,
// acl enable-vm-destroy) against the exit-4 contract (plan §3.5, AC-W2/W3/W5):
// every refusal boundary is a fixture that reads all THREE write logs (the fake
// PVE's non-GET requests, the root-SSH WRITE commands, the roster snapshot) and
// the run's write gate, and wants exit 4 with all three empty; every boundary
// has a POST-WRITE TWIN that must really have written and must not exit 4.

// isRootWrite reports whether a root command is a pveum WRITE: a user, group
// or role add/modify, or an acl modify. Everything else the access verbs run
// (list, permissions, pvesh get) is a read, legal before a refusal.
func isRootWrite(cmd string) bool {
	for _, p := range []string{"pveum user add ", "pveum user modify ", "pveum group add ", "pveum group modify ", "pveum acl modify ", "pveum role add "} {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return false
}

func rootWrites(cmds []string) []string {
	var out []string
	for _, c := range cmds {
		if isRootWrite(c) {
			out = append(out, c)
		}
	}
	return out
}

// nonGET keeps the requests of a "METHOD path ..." log that are not GET/HEAD.
func nonGET(hits []string) []string {
	var out []string
	for _, h := range hits {
		if !strings.HasPrefix(h, "GET ") && !strings.HasPrefix(h, "HEAD ") {
			out = append(out, h)
		}
	}
	return out
}

// accessWriteEnv wires the three logs of an accessSetup fixture.
func accessWriteEnv(path string, fs *pvefake.SSHServer, rf *routeFake) writeEnv {
	return writeEnv{
		roster:     path,
		restWrites: func() []string { return nonGET(rf.got()) },
		sshWrites:  func() []string { return rootWrites(fs.Commands()) },
	}
}

// flowWriteEnv wires the three logs of an enable-vm-destroy fixture.
func flowWriteEnv(e *flowEnv) writeEnv {
	return writeEnv{
		roster: e.roster,
		restWrites: func() []string {
			var hits []string
			for _, ev := range e.log() {
				if rest, ok := strings.CutPrefix(ev, "rest: "); ok {
					hits = append(hits, rest)
				}
			}
			return nonGET(hits)
		},
		sshWrites: func() []string { return rootWrites(strings.Split(strings.Join(sshOf(e.log()), "\n"), "\n")) },
	}
}

func sshOf(events []string) []string {
	var out []string
	for _, ev := range events {
		if c, ok := strings.CutPrefix(ev, "ssh: "); ok {
			out = append(out, c)
		}
	}
	return out
}

// ---- user ensure ----

var wantLogsEmpty = func(t *testing.T, o writeObservation) { t.Helper(); o.wantRefusedBeforeAnyWrite(t) }

func TestWriteGate_UserEnsure_Refusals(t *testing.T) {
	adminAnswers := map[string]string{
		"pveum role list": cliRoleList,
		"pveum acl list":  `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1}]`,
	}
	cases := []struct {
		name    string
		answers map[string]string
		args    []string
		keyless bool
		wantErr string
	}{
		{"bad user id", nil, []string{"alice"}, false, "not a user id"},
		{"enable and disable", nil, []string{"alice@pve", "--enable", "--disable"}, false, "mutually exclusive"},
		{"comment with a line break", nil, []string{"alice@pve", "--comment", "two\nlines"}, false, "must not hold a control character"},
		{"bad group id", nil, []string{"alice@pve", "--group", "bad group"}, false, "--group:"},
		{"disable the token's own user", nil, []string{"root@pam", "--disable"}, false, "owns the roster's own token"},
		{"own user joins a group", nil, []string{"root@pam", "--group", "admins", "--allow-escalating-role"}, false, "refusing --group for root@pam"},
		{"a group holding an escalating role", adminAnswers, []string{"alice@pve", "--group", "admins"}, false, "--allow-escalating-role"},
		{"keyless target without --no-ssh-key", nil, []string{"alice@pve"}, true, "holds no SSH key"},
		{"fingerprint that is not the stored pin", nil, []string{"alice@pve", "--host-key-fingerprint", "SHA256:" + strings.Repeat("W", 43)}, false, "is not the host key target"},
		{"malformed fingerprint", nil, []string{"alice@pve", "--host-key-fingerprint", "SHA256:short"}, false, "as ssh-keygen -l -E sha256 prints it"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string]string{"GET /api2/json/access/users": usersWithoutAlice}
			var path string
			var fs *pvefake.SSHServer
			var rf *routeFake
			if c.keyless {
				srv, f := newRouteFake(t, routes)
				fs = pvefake.NewSSHServer(t)
				fs.Start()
				path = writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
				t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
				rootAt(t, fs)
				rf = f
			} else {
				path, fs, rf = accessSetup(t, routes, c.answers)
			}
			env := accessWriteEnv(path, fs, rf)
			o := env.observe(t, append([]string{"user", "ensure", "--roster", path, "qa-pve-01"}, c.args...)...)
			wantLogsEmpty(t, o)
			if !strings.Contains(o.stderr, c.wantErr) {
				t.Fatalf("stderr %q lacks %q (a different refusal fired)", o.stderr, c.wantErr)
			}
		})
	}
}

// A refusal that sits behind a lock: the lock-wait timeout is raised before
// the verb's first write, with only bookkeeping (the lock files) touched.
func TestWriteGate_UserEnsure_LockWaitTimeoutIsARefusal(t *testing.T) {
	path, fs, rf := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil)
	holdLock(t, path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "user", ID: "alice@pve"})
	env := accessWriteEnv(path, fs, rf)
	o := env.observe(t, "user", "ensure", "--roster", path, "--lock-wait", "150ms", "qa-pve-01", "alice@pve")
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "timed out waiting for the lock") {
		t.Fatalf("stderr %q", o.stderr)
	}
}

// The post-write twins of user ensure: the same fixture advanced past its
// first write exits anything but 4, and the write is on the SSH log.
func TestWriteGate_UserEnsure_PostWriteTwins(t *testing.T) {
	t.Run("the escalating group allowed: same fixture, the write happens", func(t *testing.T) {
		answers := map[string]string{
			"pveum role list": cliRoleList,
			"pveum acl list":  `[{"path":"/","roleid":"Administrator","type":"group","ugid":"admins","propagate":1}]`,
		}
		path, fs, rf := accessSetupWrites(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice},
			map[string]string{"GET /api2/json/access/users": `{"data":[{"userid":"root@pam","enable":1},{"userid":"alice@pve","enable":1,"groups":"admins"}]}`}, answers)
		o := accessWriteEnv(path, fs, rf).observe(t, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "admins", "--allow-escalating-role")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("pveum user add fails after it was sent: exit 1", func(t *testing.T) {
		path, fs, rf := accessSetupExec(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, func(cmd string) (string, string, int) {
			if strings.HasPrefix(cmd, "pveum user add ") {
				return "", "permission denied", 1
			}
			return "", "", 0
		})
		o := accessWriteEnv(path, fs, rf).observe(t, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("read-back does not show the user: a warning after the write, never 4", func(t *testing.T) {
		// the REST list never reflects root's write
		path, fs, rf := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil)
		o := accessWriteEnv(path, fs, rf).observe(t, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 || !strings.Contains(o.stderr, "does not read back as requested") {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a write that hangs: exit 3, the write is on the log", func(t *testing.T) {
		lowerRootBounds(t)
		path, fs, started := hangingRoot(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil, "pveum user add")
		_ = started
		env := writeEnv{roster: path, restWrites: noLog, sshWrites: func() []string { return rootWrites(fs.Commands()) }}
		var o writeObservation
		within(t, 5*time.Second, func() { o = env.observe(t, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve") })
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3 (a root write sent and timed out); stderr %q", o.code, o.stderr)
		}
	})
}

// A read that hangs is exit 1: the gate is closed and nothing was written.
func TestWriteGate_UserEnsure_AHungReadIsNotARefusalNorUnobserved(t *testing.T) {
	lowerRootBounds(t)
	answers := map[string]string{"pveum acl list": `[]`}
	path, fs, _ := hangingRoot(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, answers, "pveum role list")
	env := writeEnv{roster: path, restWrites: noLog, sshWrites: func() []string { return rootWrites(fs.Commands()) }}
	var o writeObservation
	within(t, 5*time.Second, func() {
		o = env.observe(t, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--group", "ops")
	})
	if o.code != 1 || o.wrote() || o.opened {
		t.Fatalf("exit %d (want 1), writes rest=%q ssh=%q gate=%v; stderr %q", o.code, o.rest, o.ssh, o.opened, o.stderr)
	}
}

// ---- group ensure ----

func TestWriteGate_GroupEnsure_Refusals(t *testing.T) {
	cases := []struct {
		name, wantErr string
		args          []string
		keyless       bool
	}{
		{"bad group id", "is not a group id", []string{"bad group"}, false},
		{"comment with a line break", "must not hold a control character", []string{"ops", "--comment", "a\nb"}, false},
		{"keyless target without --no-ssh-key", "holds no SSH key", []string{"ops"}, true},
		{"fingerprint that is not the stored pin", "is not the host key target", []string{"ops", "--host-key-fingerprint", "SHA256:" + strings.Repeat("W", 43)}, false},
		{"malformed fingerprint", "as ssh-keygen -l -E sha256 prints it", []string{"ops", "--host-key-fingerprint", "SHA256:short"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}
			var path string
			var fs *pvefake.SSHServer
			var rf *routeFake
			if c.keyless {
				srv, f := newRouteFake(t, routes)
				fs = pvefake.NewSSHServer(t)
				fs.Start()
				path = writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
				t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
				rootAt(t, fs)
				rf = f
			} else {
				path, fs, rf = accessSetup(t, routes, nil)
			}
			o := accessWriteEnv(path, fs, rf).observe(t, append([]string{"group", "ensure", "--roster", path, "qa-pve-01"}, c.args...)...)
			o.wantRefusedBeforeAnyWrite(t)
			if !strings.Contains(o.stderr, c.wantErr) {
				t.Fatalf("stderr %q lacks %q", o.stderr, c.wantErr)
			}
		})
	}
}

func TestWriteGate_GroupEnsure_LockWaitTimeoutIsARefusal(t *testing.T) {
	path, fs, rf := accessSetup(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}, nil)
	holdLock(t, path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "group", ID: "ops"})
	o := accessWriteEnv(path, fs, rf).observe(t, "group", "ensure", "--roster", path, "--lock-wait", "150ms", "qa-pve-01", "ops")
	o.wantRefusedBeforeAnyWrite(t)
}

func TestWriteGate_GroupEnsure_PostWriteTwins(t *testing.T) {
	t.Run("the same fixture, valid: the write happens and exits 0", func(t *testing.T) {
		path, fs, rf := accessSetupWrites(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`},
			map[string]string{"GET /api2/json/access/groups": `{"data":[{"groupid":"ops"}]}`}, nil)
		o := accessWriteEnv(path, fs, rf).observe(t, "group", "ensure", "--roster", path, "qa-pve-01", "ops")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("pveum group add fails after it was sent: exit 1", func(t *testing.T) {
		path, fs, rf := accessSetupExec(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}, func(cmd string) (string, string, int) {
			if strings.HasPrefix(cmd, "pveum group add ") {
				return "", "no", 2
			}
			return "", "", 0
		})
		o := accessWriteEnv(path, fs, rf).observe(t, "group", "ensure", "--roster", path, "qa-pve-01", "ops")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a write that hangs: exit 3", func(t *testing.T) {
		lowerRootBounds(t)
		path, fs, _ := hangingRoot(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}, nil, "pveum group add")
		env := writeEnv{roster: path, restWrites: noLog, sshWrites: func() []string { return rootWrites(fs.Commands()) }}
		var o writeObservation
		within(t, 5*time.Second, func() { o = env.observe(t, "group", "ensure", "--roster", path, "qa-pve-01", "ops") })
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
}

// ---- acl grant ----

func TestWriteGate_ACLGrant_Refusals(t *testing.T) {
	answers := map[string]string{"pveum role list": cliRoleList + "", "pveum group list": cliGroupList, "pveum user list": cliUserList, "pveum acl list": `[]`}
	roleList := `[{"roleid":"PVEVMUser","privs":"VM.Audit,VM.Console"},{"roleid":"Empty","privs":""},{"roleid":"Administrator","privs":"Permissions.Modify,Sys.Modify,VM.Audit"}]`
	cases := []struct {
		name, wantErr string
		args          []string
		roles         string
		keyless       bool
	}{
		{"own token", "the roster's own token", []string{"--token", "root@pam!pveforge", "--grant", "/:PVEVMUser"}, "", false},
		{"the user owning the token", "owns the roster's token", []string{"--user", "root@pam", "--grant", "/:PVEVMUser"}, "", false},
		{"a group holding the owner", "holds root@pam", []string{"--group", "admins", "--grant", "/:PVEVMUser"}, "", false},
		{"an escalating role", "--allow-escalating-role", []string{"--user", "bob@pve", "--grant", "/:Administrator"}, "", false},
		{"no principal", "exactly one of", []string{"--grant", "/:PVEVMUser"}, "", false},
		{"two principals", "exactly one of", []string{"--user", "bob@pve", "--group", "ops", "--grant", "/:PVEVMUser"}, "", false},
		{"no grant", "at least one --grant", []string{"--user", "bob@pve"}, "", false},
		{"a malformed grant", "PATH:ROLE::1", []string{"--user", "bob@pve", "--grant", "/:PVEVMUser:1"}, "", false},
		{"a malformed principal", "not a user id", []string{"--user", "bob", "--grant", "/:PVEVMUser"}, "", false},
		{"an unknown role", "does not exist on PVE", []string{"--user", "bob@pve", "--grant", "/:NoSuchRole"}, "", false},
		{"a role with no privileges", "no privileges", []string{"--user", "bob@pve", "--grant", "/:Empty"}, roleList, false},
		{"pinned privileges that are not the role's", "pinned but not in the role", []string{"--user", "bob@pve", "--grant", "/:PVEVMUser:VM.Audit"}, "", false},
		{"an unknown group", "no such group", []string{"--group", "nogroup", "--grant", "/:PVEVMUser"}, "", false},
		{"keyless target without --no-ssh-key", "holds no SSH key", []string{"--user", "bob@pve", "--grant", "/:PVEVMUser"}, "", true},
		{"fingerprint that is not the stored pin", "is not the host key target", []string{"--user", "bob@pve", "--grant", "/:PVEVMUser", "--host-key-fingerprint", "SHA256:" + strings.Repeat("W", 43)}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ans := map[string]string{}
			for k, v := range answers {
				ans[k] = v
			}
			if c.roles != "" {
				ans["pveum role list"] = c.roles
			}
			var path string
			var fs *pvefake.SSHServer
			var rf *routeFake
			if c.keyless {
				srv, f := newRouteFake(t, nil)
				fs = pvefake.NewSSHServer(t)
				fs.Start()
				path = writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
				t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
				rootAt(t, fs)
				rf = f
			} else {
				path, fs, rf = accessSetup(t, nil, ans)
			}
			o := accessWriteEnv(path, fs, rf).observe(t, append([]string{"acl", "grant", "--roster", path, "qa-pve-01"}, c.args...)...)
			o.wantRefusedBeforeAnyWrite(t)
			if !strings.Contains(o.stderr, c.wantErr) {
				t.Fatalf("stderr %q lacks %q (a different refusal fired)", o.stderr, c.wantErr)
			}
		})
	}
}

func TestWriteGate_ACLGrant_PostWriteTwins(t *testing.T) {
	grantAnswers := func(acl string) map[string]string {
		return map[string]string{"pveum role list": cliRoleList, "pveum group list": cliGroupList, "pveum user list": cliUserList, "pveum acl list": acl}
	}
	t.Run("the same fixture, valid and read back: exit 0", func(t *testing.T) {
		path, fs, rf := accessSetup(t, nil, grantAnswers(`[{"path":"/vms/100","roleid":"PVEVMUser","type":"user","ugid":"bob@pve","propagate":0}]`))
		o := accessWriteEnv(path, fs, rf).observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("the escalating role allowed: the same fixture writes", func(t *testing.T) {
		path, fs, rf := accessSetup(t, nil, grantAnswers(`[{"path":"/","roleid":"Administrator","type":"user","ugid":"bob@pve","propagate":0}]`))
		o := accessWriteEnv(path, fs, rf).observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/:Administrator", "--allow-escalating-role")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("read-back missing after the write: exit 1", func(t *testing.T) {
		path, fs, rf := accessSetup(t, nil, grantAnswers(`[]`))
		o := accessWriteEnv(path, fs, rf).observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "not in the ACL list") {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("acl modify fails after it was sent: exit 1", func(t *testing.T) {
		ans := pveumFake(grantAnswers(`[]`))
		path, fs, rf := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
			if strings.HasPrefix(cmd, "pveum acl modify ") {
				return "", "denied", 2
			}
			return ans(cmd)
		})
		o := accessWriteEnv(path, fs, rf).observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "failed, none was applied") {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("the second of two grants fails after the first was applied: exit 1", func(t *testing.T) {
		ans := pveumFake(grantAnswers(`[]`))
		n := 0
		var mu sync.Mutex
		path, fs, rf := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
			if strings.HasPrefix(cmd, "pveum acl modify ") {
				mu.Lock()
				n++
				k := n
				mu.Unlock()
				if k == 2 {
					return "", "denied", 2
				}
			}
			return ans(cmd)
		})
		o := accessWriteEnv(path, fs, rf).observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser", "--grant", "/vms/101:PVEVMUser")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "already applied") {
			t.Fatalf("exit %d, stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a grant that hangs: exit 3", func(t *testing.T) {
		lowerRootBounds(t)
		path, fs, _ := hangingRoot(t, nil, grantAnswers(`[]`), "pveum acl modify")
		env := writeEnv{roster: path, restWrites: noLog, sshWrites: func() []string { return rootWrites(fs.Commands()) }}
		var o writeObservation
		within(t, 5*time.Second, func() {
			o = env.observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
		})
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
}

// A hung READ before the grant (the role list) is exit 1, with the gate closed
// and nothing written: neither a refusal nor an unobserved dispatch.
func TestWriteGate_ACLGrant_AHungReadIsExit1(t *testing.T) {
	lowerRootBounds(t)
	path, fs, _ := hangingRoot(t, nil, map[string]string{"pveum group list": cliGroupList}, "pveum role list")
	env := writeEnv{roster: path, restWrites: noLog, sshWrites: func() []string { return rootWrites(fs.Commands()) }}
	var o writeObservation
	within(t, 5*time.Second, func() {
		o = env.observe(t, "acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
	})
	if o.code != 1 || o.wrote() || o.opened || !strings.Contains(o.stderr, "timed out") {
		t.Fatalf("exit %d (want 1), writes rest=%q ssh=%q gate=%v; stderr %q", o.code, o.rest, o.ssh, o.opened, o.stderr)
	}
}

// ---- acl enable-vm-destroy ----

// newHookedFlowEnv is newFlowEnv with a hook that answers a root command
// before the enableHost does (handled = true), so a fixture can bend what root
// reads (the ACL list, the token's permission tree) or hang a command.
func newHookedFlowEnv(t *testing.T, hook func(e *flowEnv, cmd string) (out, errOut string, code int, handled bool)) *flowEnv {
	t.Helper()
	e := &flowEnv{t: t, host: newEnableHost(), vmPrivs: []string{"VM.PowerMgmt", "VM.Allocate"}}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(e.serveREST))
	t.Cleanup(e.srv.Close)
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		e.record("ssh: " + cmd)
		if hook != nil {
			if out, errOut, code, handled := hook(e, cmd); handled {
				return out, errOut, code
			}
		}
		return e.host.exec(cmd)
	})
	e.roster = newTestRosterWithSSHTarget(t, e.srv, fs)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return e
}

// wroteACL reports whether the host has run an acl modify (the host log).
func wroteACL(e *flowEnv) bool {
	for _, w := range e.sshWrites() {
		if strings.HasPrefix(w, "pveum acl modify") {
			return true
		}
	}
	return false
}

func TestWriteGate_EnableVMDestroy_Refusals(t *testing.T) {
	type fix struct {
		name, wantErr string
		args          []string
		tty           string // "" = no terminal; otherwise the answers typed
		setup         func(e *flowEnv)
		hook          func(e *flowEnv, cmd string) (string, string, int, bool)
		changeBetween bool
	}
	noAccessRow := func(e *flowEnv, cmd string) (string, string, int, bool) {
		if strings.HasPrefix(cmd, "pveum acl list") {
			return `[{"path":"/","roleid":"PVEVMAdmin","type":"token","ugid":"root@pam!pveforge","propagate":1},{"path":"/storage/local","roleid":"NoAccess","type":"token","ugid":"root@pam!pveforge","propagate":0}]`, "", 0, true
		}
		return "", "", 0, false
	}
	limitedToken := func(e *flowEnv, cmd string) (string, string, int, bool) {
		// the token's tree lacks VM.Allocate: adding the role would widen it
		// by more than Sys.Audit
		if strings.HasPrefix(cmd, "pveum user permissions") {
			var priv []string
			for _, p := range enableVMAdmin {
				if p != "VM.Allocate" {
					priv = append(priv, p)
				}
			}
			m := ""
			for i, p := range priv {
				if i > 0 {
					m += ","
				}
				m += `"` + p + `":1`
			}
			tree := `{"/":{` + m + `},"/nodes":{` + m + `},"/vms":{` + m + `}}`
			return tree, "", 0, true
		}
		return "", "", 0, false
	}
	cases := []fix{
		{name: "role name with the pve prefix", wantErr: "refusing this role name", args: []string{"--role", "PVEForge"}},
		{name: "role name starting with a dash", wantErr: "refusing this role name", args: []string{"--role=--delete"}},
		{name: "role that exists with another privilege set", wantErr: "exists with a different privilege set", args: []string{"--role", "VMOnly"}, setup: func(e *flowEnv) {
			e.host.mu.Lock()
			e.host.roles["VMOnly"] = []string{"VM.Audit"}
			e.host.mu.Unlock()
		}},
		{name: "vmid that is not a decimal vmid", wantErr: "vmid", args: []string{"--vmid", "0691"}},
		{name: "token without PVEVMAdmin's privileges", wantErr: "does not already hold", hook: limitedToken},
		{name: "a NoAccess row: the result would not converge", wantErr: "would not leave a token", hook: noAccessRow},
		{name: "role conflict under --yes (the locked real pass)", wantErr: "exists with a different privilege set", args: []string{"--yes", "--role", "VMOnly"}, setup: func(e *flowEnv) {
			e.host.mu.Lock()
			e.host.roles["VMOnly"] = []string{"VM.Audit"}
			e.host.mu.Unlock()
		}},
		{name: "not-vm-admin token under --yes", wantErr: "does not already hold", args: []string{"--yes"}, hook: limitedToken},
		{name: "no terminal and no --yes", wantErr: "no terminal to ask on"},
		{name: "declined at the prompt", wantErr: "not confirmed", tty: "n\n"},
		{name: "the plan changed between the passes", wantErr: "the plan changed since it was confirmed", tty: "y\n", changeBetween: true},
		{name: "dry-run of a refused plan (role conflict)", wantErr: "exists with a different privilege set", args: []string{"--dry-run", "--role", "VMOnly"}, setup: func(e *flowEnv) {
			e.host.mu.Lock()
			e.host.roles["VMOnly"] = []string{"VM.Audit"}
			e.host.mu.Unlock()
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.tty == "" {
				setNoTTY(t)
			} else {
				setTTY(t, c.tty)
			}
			e := newHookedFlowEnv(t, c.hook)
			if c.setup != nil {
				c.setup(e)
			}
			if c.changeBetween {
				real := confirmAsk
				confirmAsk = func(ctx context.Context, in io.Reader, w io.Writer) (bool, error) {
					d := append(slices.Clone(enableVMAdmin), "Sys.Audit")
					e.host.mu.Lock()
					e.host.roles["ForgeVMAdminAudit"] = d
					e.host.mu.Unlock()
					return real(ctx, in, w)
				}
				t.Cleanup(func() { confirmAsk = real })
			}
			args := append([]string{"acl", "enable-vm-destroy", "--roster", e.roster, "-o", "json"}, c.args...)
			args = append(args, flowTarget)
			o := flowWriteEnv(e).observe(t, args...)
			o.wantRefusedBeforeAnyWrite(t)
			if !strings.Contains(o.stderr, c.wantErr) {
				t.Fatalf("stderr %q lacks %q (a different refusal fired)", o.stderr, c.wantErr)
			}
		})
	}
}

// The bootstrap lock the verb takes for the real pass: its wait timeout is
// raised before the first write (bookkeeping only), exit 4.
func TestWriteGate_EnableVMDestroy_BootstrapLockTimeoutIsARefusal(t *testing.T) {
	setNoTTY(t)
	e := newHookedFlowEnv(t, nil)
	holdLock(t, e.roster, lock.ObjectKey{TargetID: flowTarget, Kind: "bootstrap", ID: "token"})
	o := flowWriteEnv(e).observe(t, "acl", "enable-vm-destroy", "--roster", e.roster, "-o", "json", "--yes", "--lock-wait", "150ms", flowTarget)
	o.wantRefusedBeforeAnyWrite(t)
	if !strings.Contains(o.stderr, "timed out waiting for the lock") {
		t.Fatalf("stderr %q", o.stderr)
	}
}

// The post-write twins of enable-vm-destroy: errors raised AFTER the first
// pveum write are exit 1 (or 3), never 4.
func TestWriteGate_EnableVMDestroy_PostWriteTwins(t *testing.T) {
	run := func(t *testing.T, e *flowEnv, args ...string) writeObservation {
		t.Helper()
		full := append([]string{"acl", "enable-vm-destroy", "--roster", e.roster, "-o", "json"}, args...)
		full = append(full, flowTarget)
		return flowWriteEnv(e).observe(t, full...)
	}
	t.Run("the same fixture with --yes: both writes happen, exit 0", func(t *testing.T) {
		setNoTTY(t)
		e := newHookedFlowEnv(t, nil)
		o := run(t, e, "--yes")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 0 || len(o.ssh) != 2 {
			t.Fatalf("exit %d, writes %q, stderr %q", o.code, o.ssh, o.stderr)
		}
	})
	t.Run("ErrPostWriteInvariant: the token's tree widened beyond Sys.Audit after the write", func(t *testing.T) {
		setNoTTY(t)
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum user permissions") && wroteACL(e) {
				// after the acl modify: every path also holds a privilege the
				// role does not confer
				e.host.mu.Lock()
				priv := ""
				for _, p := range e.host.roles["PVEVMAdmin"] {
					priv += `"` + p + `":1,`
				}
				e.host.mu.Unlock()
				m := priv + `"Sys.Audit":1,"Datastore.AllocateSpace":1,"Pool.Allocate":1`
				return `{"/":{` + m + `},"/nodes":{` + m + `},"/vms":{` + m + `}}`, "", 0, true
			}
			return "", "", 0, false
		})
		o := run(t, e, "--yes")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "break the invariant") {
			t.Fatalf("exit %d, want 1 naming the invariant; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("ErrRoleChangedDuringGrant: the role no longer holds the granted set after the write", func(t *testing.T) {
		setNoTTY(t)
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum role list") && wroteACL(e) {
				e.host.mu.Lock()
				e.host.roles["ForgeVMAdminAudit"] = append(slices.Clone(e.host.roles["ForgeVMAdminAudit"]), "Sys.Modify")
				e.host.mu.Unlock()
			}
			return "", "", 0, false
		})
		o := run(t, e, "--yes")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 || !strings.Contains(o.stderr, "the role changed while it was being granted") {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a write that fails after it was sent: exit 1", func(t *testing.T) {
		setNoTTY(t)
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum acl modify") {
				return "", "permission denied", 2, true
			}
			return "", "", 0, false
		})
		o := run(t, e, "--yes")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("written but not ready (the verdict): exit 1", func(t *testing.T) {
		setNoTTY(t)
		e := newHookedFlowEnv(t, nil)
		e.statusCode = 403
		o := run(t, e, "--yes")
		o.wantNotRefusedAfterWrite(t)
		if o.code != 1 {
			t.Fatalf("exit %d, want 1; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a write that hangs: exit 3", func(t *testing.T) {
		setNoTTY(t)
		lowerRootBounds(t)
		release := make(chan struct{})
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum acl modify") {
				<-release
				return "", "", 0, true
			}
			return "", "", 0, false
		})
		t.Cleanup(func() { close(release) })
		var o writeObservation
		within(t, 5*time.Second, func() { o = run(t, e, "--yes") })
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a role add that hangs (role-only): exit 3", func(t *testing.T) {
		setNoTTY(t)
		lowerRootBounds(t)
		release := make(chan struct{})
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum role add") {
				<-release
				return "", "", 0, true
			}
			return "", "", 0, false
		})
		t.Cleanup(func() { close(release) })
		var o writeObservation
		within(t, 5*time.Second, func() { o = run(t, e, "--yes", "--role-only") })
		o.wantNotRefusedAfterWrite(t)
		if o.code != 3 {
			t.Fatalf("exit %d, want 3; stderr %q", o.code, o.stderr)
		}
	})
	t.Run("a role-list READ that hangs: exit 1, nothing written, gate closed", func(t *testing.T) {
		setNoTTY(t)
		lowerRootBounds(t)
		release := make(chan struct{})
		e := newHookedFlowEnv(t, func(e *flowEnv, cmd string) (string, string, int, bool) {
			if strings.HasPrefix(cmd, "pveum role list") {
				<-release
				return "", "", 0, true
			}
			return "", "", 0, false
		})
		t.Cleanup(func() { close(release) })
		var o writeObservation
		within(t, 5*time.Second, func() { o = run(t, e, "--yes") })
		if o.code != 1 || o.wrote() || o.opened || !strings.Contains(o.stderr, "timed out") {
			t.Fatalf("exit %d (want 1), rest=%q ssh=%q gate=%v; stderr %q", o.code, o.rest, o.ssh, o.opened, o.stderr)
		}
	})
}
