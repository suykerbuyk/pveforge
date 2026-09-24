package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/lock"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
	"github.com/suykerbuyk/pveforge/internal/sshexec"
)

// pveforge-root-channel-deadlines, through runRoot: a root command that
// hangs ends at its bound, is reported as outcome-unknown with exit 1, and
// releases the pveforge lock it ran under; only a real signal exits
// 130/143; and a password is never asked for while a lock is held.

// lowerRootBounds shortens every root-command bound for one test.
func lowerRootBounds(t *testing.T) {
	t.Helper()
	cmdT, writeT, qmT := sshexec.CommandTimeout, bootstrap.PVEConfigWriteTimeout, sshexec.QMSetTimeout
	t.Cleanup(func() {
		sshexec.CommandTimeout, bootstrap.PVEConfigWriteTimeout, sshexec.QMSetTimeout = cmdT, writeT, qmT
	})
	sshexec.CommandTimeout, bootstrap.PVEConfigWriteTimeout, sshexec.QMSetTimeout = 200*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond
}

// hangingRoot is accessSetup whose root commands starting with hang never
// answer until the test ends; started receives each such command as it
// begins.
func hangingRoot(t *testing.T, routes, answers map[string]string, hang string) (string, *pvefake.SSHServer, chan string) {
	t.Helper()
	srv, _ := newRouteFake(t, routes)
	release := make(chan struct{})
	started := make(chan string, 16)
	fs := pvefake.NewSSHServer(t)
	answer := pveumFake(answers)
	fs.HandleExec(func(cmd string) (string, string, int) {
		if strings.HasPrefix(cmd, hang) {
			started <- cmd
			<-release
			return "", "", 0
		}
		return answer(cmd)
	})
	path := newTestRosterWithSSHTarget(t, srv, fs)
	t.Cleanup(func() { close(release) }) // before the server's own cleanup
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	rootAt(t, fs)
	return path, fs, started
}

// lockIsFree requires key to be takeable at once: the run that timed out
// released it.
func lockIsFree(t *testing.T, rosterPath string, key lock.ObjectKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := lock.Mutation(lock.WithWait(ctx, 500*time.Millisecond), rosterPath, key)
	if err != nil {
		t.Fatalf("%s is still held after the run ended: %v", key, err)
	}
	_ = unlock()
}

// timedOutText requires stderr to be one line reporting an unknown outcome
// after a timeout, and not an interruption.
func timedOutText(t *testing.T, code int, stderr string, want ...string) {
	t.Helper()
	if code != 1 || strings.Count(stderr, "\n") != 1 || strings.Contains(stderr, "interrupted") {
		t.Fatalf("exit %d, stderr %q; want exit 1 and one line, not an interruption", code, stderr)
	}
	for _, w := range append([]string{"timed out"}, want...) {
		if !strings.Contains(stderr, w) {
			t.Errorf("stderr %q lacks %q", stderr, w)
		}
	}
}

// C1: user ensure whose root write hangs.
func TestUserEnsure_C1_AHungWriteIsOutcomeUnknown(t *testing.T) {
	lowerRootBounds(t)
	path, _, _ := hangingRoot(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil, "pveum user add")
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve")
		timedOutText(t, code, stderr, "may or may not have been applied", "re-running is safe")
	})
	lockIsFree(t, path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "user", ID: "alice@pve"})
}

// C2: group ensure whose root write hangs.
func TestGroupEnsure_C2_AHungWriteIsOutcomeUnknown(t *testing.T) {
	lowerRootBounds(t)
	path, _, _ := hangingRoot(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}, nil, "pveum group add")
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops")
		timedOutText(t, code, stderr, "may or may not have been applied")
	})
	lockIsFree(t, path, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "group", ID: "ops"})
}

// C3: acl grant whose `acl modify` hangs.
func TestACLGrant_C3_AHungGrantIsOutcomeUnknown(t *testing.T) {
	lowerRootBounds(t)
	path, _, _ := hangingRoot(t, nil, map[string]string{
		"pveum role list": cliRoleList, "pveum group list": cliGroupList, "pveum user list": cliUserList,
	}, "pveum acl modify")
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("acl", "grant", "--roster", path, "qa-pve-01", "--user", "bob@pve", "--grant", "/vms/100:PVEVMUser")
		timedOutText(t, code, stderr, "grant 1 of 1 (PVEVMUser on /vms/100) timed out and may or may not have been applied")
	})
}

// C8 (condition c): the same hang cut short by a real signal is an
// interruption, 130 with runRoot's note, and never reported as a timeout.
func TestUserEnsure_C8_ASignalIsNotATimeout(t *testing.T) {
	lowerRootBounds(t)
	sshexec.CommandTimeout, bootstrap.PVEConfigWriteTimeout = 5*time.Second, 5*time.Second
	path, _, started := hangingRoot(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice}, nil, "pveum user add")
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		<-started
		cancel(interruptError{sig: syscall.SIGINT})
	}()
	within(t, 4*time.Second, func() {
		code, _, stderr := runRootInterruptible(ctx, "user", "ensure", "--roster", path, "qa-pve-01", "alice@pve")
		if code != 130 || !strings.Contains(stderr, "interrupted (SIGINT)") || !strings.Contains(stderr, "may or may not have been applied") || strings.Contains(stderr, "timed out") {
			t.Fatalf("exit %d, stderr %q; want 130 and the interruption, not a timeout", code, stderr)
		}
	})
}

// C4: with --no-ssh-key, the password is asked for before the object's
// lock: with the lock held elsewhere, a missing password is what is
// reported, and the lock is never waited for.
func TestEnsure_C4_ThePasswordComesBeforeTheLock(t *testing.T) {
	for _, c := range []struct {
		args []string
		key  lock.ObjectKey
	}{
		{[]string{"user", "ensure"}, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "user", ID: "alice@pve"}},
		{[]string{"group", "ensure"}, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "group", ID: "ops"}},
	} {
		t.Run(c.args[0], func(t *testing.T) {
			srv, _ := newRouteFake(t, map[string]string{"GET /api2/json/access/users": usersWithoutAlice, "GET /api2/json/access/groups": `{"data":[]}`})
			path := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
			t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
			t.Setenv(pvePasswordEnvVar, "")
			unlock, err := lock.Mutation(context.Background(), path, c.key)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unlock() }()
			id := c.key.ID
			code, _, stderr := runRootArgs(append(c.args, "--roster", path, "qa-pve-01", id, "--no-ssh-key", "--lock-wait", "20ms")...)
			if code != 1 || !strings.Contains(stderr, "no PVE password available") || strings.Contains(stderr, "lock") {
				t.Fatalf("exit %d, stderr %q; want the password's failure, not the lock's", code, stderr)
			}
		})
	}
}

// C5: a run with nothing to change never connects as root, with a key or
// keyless (the password is resolved, the dial never made).
func TestUserEnsure_C5_ANoOpNeverConnects(t *testing.T) {
	path, fs, _ := accessSetup(t, map[string]string{"GET /api2/json/access/users": usersWithAlice}, nil)
	before := fs.Connections()
	if code, stdout, stderr := runRootArgs("user", "ensure", "--roster", path, "qa-pve-01", "alice@pve", "--enable", "--group", "ops"); code != 0 || stdout != "qa-pve-01: user alice@pve unchanged\n" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if n := fs.Connections() - before; n != 0 {
		t.Errorf("a no-op run connected as root %d time(s)", n)
	}

	srv, _ := newRouteFake(t, map[string]string{"GET /api2/json/access/users": usersWithAlice})
	kfs := pvefake.NewSSHServer(t)
	kfs.AllowPassword("root", "root-pw")
	kfs.Start()
	rootAt(t, kfs)
	kpath := newTestRosterWithTLSTarget(t, srv, "qa-pve-01", "qa-pve-01")
	t.Setenv(pvePasswordEnvVar, "root-pw")
	if code, _, stderr := runRootArgs("user", "ensure", "--roster", kpath, "qa-pve-01", "alice@pve", "--enable", "--no-ssh-key"); code != 0 {
		t.Fatalf("keyless no-op: exit %d, stderr %q", code, stderr)
	}
	if n := kfs.Connections(); n != 0 {
		t.Errorf("a keyless no-op run connected as root %d time(s)", n)
	}
}

// C6: vm set of a root-only field whose `qm set` hangs ends at
// QMSetTimeout, exit 1, outcome unknown, and the VM's lock is released.
func TestVMSet_C6_AHungQMSetIsOutcomeUnknown(t *testing.T) {
	lowerRootBounds(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if answerNothingPending(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"digest":"d1","cores":"2"}}`))
	}))
	defer srv.Close()
	release := make(chan struct{})
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		<-release
		return "", "", 0
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Cleanup(func() { close(release) })
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("vm", "set", "--roster", rosterPath, "qa-pve-01", "100", "args=-cpu host")
		timedOutText(t, code, stderr, "whether it took effect is unknown")
	})
	lockIsFree(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "vm", ID: "100"})
}

// C7: a network Op whose SSH link read hangs ends at CommandTimeout, exit
// 1, and the network lock is released.
func TestNetworkBridgeCreate_C7_AHungLinkReadIsBounded(t *testing.T) {
	lowerRootBounds(t)
	const node, mgmt, iface = "qa-pve-01", "vmbr0", "vmbr1"
	rest := pvefake.NewBridgeREST(t, node)
	rest.MgmtFields = `{"iface":"vmbr0","type":"bridge","bridge_ports":"eth0","cidr":"10.0.0.5/24"}`
	rest.IfaceResponses = []string{pvefake.IfaceAbsent, pvefake.IfaceAbsent}
	srv := rest.Server()
	defer srv.Close()
	release := make(chan struct{})
	fs := pvefake.NewSSHServer(t)
	fs.HandleExec(func(cmd string) (string, string, int) {
		<-release
		return "", "", 0
	})
	rosterPath := newTestRosterWithSSHTarget(t, srv, fs)
	t.Cleanup(func() { close(release) })
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	within(t, 5*time.Second, func() {
		code, _, stderr := runRootArgs("network", "bridge", "create", "--roster", rosterPath,
			"--management-bridge", mgmt, "qa-pve-01", iface, "type=bridge", "bridge_ports=eth1")
		if code != 1 || !strings.Contains(stderr, "timed out") || strings.Contains(stderr, "interrupted") {
			t.Fatalf("exit %d, stderr %q; want exit 1 and the timeout", code, stderr)
		}
	})
	if got := fs.Commands(); len(got) == 0 || got[0] != pvefake.LinkShowCmd(mgmt) {
		t.Errorf("SSH commands %q; want the hung link read first", got)
	}
	lockIsFree(t, rosterPath, lock.ObjectKey{TargetID: "qa-pve-01", Kind: "network", ID: node})
}

// access inventory (6b), through runRoot: a root read that hangs, the
// first pveum list or the getent of the @pam accounts, ends at
// CommandTimeout with exit 1 and a timeout message, never 130, and prints
// no partial inventory.
func TestAccessInventory_AHungReadTimesOut(t *testing.T) {
	lowerRootBounds(t)
	for _, hang := range []string{"pveum user list", "getent passwd"} {
		t.Run(hang, func(t *testing.T) {
			release := make(chan struct{})
			path, _, _ := accessSetupExec(t, nil, func(cmd string) (string, string, int) {
				if strings.HasPrefix(cmd, hang) {
					<-release
					return "", "", 0
				}
				return inventoryExec(cmd)
			})
			t.Cleanup(func() { close(release) }) // before the server's own cleanup
			within(t, 5*time.Second, func() {
				code, stdout, stderr := runRootArgs("access", "inventory", "--roster", path, "qa-pve-01")
				if code != 1 || stdout != "" || strings.Contains(stderr, "interrupted") ||
					!strings.Contains(stderr, "timed out") || !strings.Contains(stderr, hang) {
					t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1, no output, and %q timed out", code, stdout, stderr, hang)
				}
			})
		})
	}
}
