package main

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// --host-key-fingerprint, through runRoot (hazard 12: a flag can be a
// no-op while every test that sets Options directly still passes).

var wrongFP = "SHA256:" + strings.Repeat("W", 43)

// HK1: bootstrap's flag reaches the pubkey install's pin and the keyless
// dial's pin; a malformed value is refused before any dial.
func TestBootstrap_HostKeyFingerprintReachesThePasswordDials(t *testing.T) {
	for _, keyless := range []bool{false, true} {
		tr := &fakeBootstrapTransport{installErr: errors.New("stop here")}
		withBootstrapFakes(t, tr)
		args := []string{"bootstrap", "qa-test", "--host", "h", "--node", "n", "--grant", "/:PVEVMAdmin::1", "--host-key-fingerprint", wrongFP}
		if keyless {
			args = append(args, "--no-ssh-key")
		}
		root := newRootCmd()
		root.SetArgs(args)
		var stderr bytes.Buffer
		runRoot(root, &stderr)
		got := tr.installPins
		if keyless {
			got = tr.pwPins
		}
		if !reflect.DeepEqual(got, []string{wrongFP}) {
			t.Errorf("keyless %t: pins %q, want [%s]: the flag did not reach the password dial", keyless, got, wrongFP)
		}
	}
	tr := &fakeBootstrapTransport{}
	withBootstrapFakes(t, tr)
	root := newRootCmd()
	root.SetArgs([]string{"bootstrap", "qa-test", "--host", "h", "--node", "n", "--grant", "/:PVEVMAdmin::1", "--host-key-fingerprint", "SHA256:abc"})
	var stderr bytes.Buffer
	if code := runRoot(root, &stderr); code != 1 || tr.calls != 0 || !strings.Contains(stderr.String(), "as ssh-keygen -l -E sha256 prints it") {
		t.Errorf("malformed: exit %d, calls %d, stderr %q", code, tr.calls, stderr.String())
	}
}

// HK2: against a real SSH server whose host key is not the pin, bootstrap,
// keyed or keyless, is refused before the password is sent: the server saw
// no password attempt at all.
func TestBootstrap_WrongHostKeyNeverSeesThePassword(t *testing.T) {
	for _, keyless := range []bool{false, true} {
		fs := pvefake.NewSSHServer(t)
		fs.AllowPassword("root", "test-pve-pass")
		fs.Start()
		withBootstrapFakes(t, &fakeBootstrapTransport{})
		newBootstrapTransport = bootstrap.NewSSHTransport
		args := []string{"bootstrap", "qa-test", "--host", "127.0.0.1", "--node", "qa-test", "--ssh-port", strconv.Itoa(fs.Port(t)), "--grant", "/:PVEVMAdmin::1", "--host-key-fingerprint", wrongFP}
		if keyless {
			args = append(args, "--no-ssh-key")
		}
		code, _, stderr := runRootArgs(args...)
		if code != 1 || !strings.Contains(stderr, "host key mismatch") {
			t.Fatalf("keyless %t: exit %d, stderr %q", keyless, code, stderr)
		}
		if fs.PasswordAttempts() != 0 || fs.Connections() != 0 {
			t.Errorf("keyless %t: the server saw %d password attempts, %d connections", keyless, fs.PasswordAttempts(), fs.Connections())
		}
		// The right pin gets past the host key: the password is sent.
		args[len(args)-1-boolInt(keyless)] = fs.HostKeyFingerprint()
		_, _, stderr = runRootArgs(args...)
		if strings.Contains(stderr, "host key mismatch") || fs.PasswordAttempts() == 0 {
			t.Errorf("keyless %t, the right pin: password attempts %d, stderr %q", keyless, fs.PasswordAttempts(), stderr)
		}
	}
}

// HK3: the keyless access commands take the same pin: a wrong one is refused
// before the password is sent, the right one connects; on a key target a pin
// other than the stored one is refused before anything is dialed.
func TestAccess_HostKeyFingerprint(t *testing.T) {
	srv, _ := newRouteFake(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`, "GET /api2/json/access/users": usersWithoutAlice})
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "root-pw")
	fs.Start()
	path := writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	t.Setenv(pvePasswordEnvVar, "root-pw")
	rootAt(t, fs)
	for _, verb := range [][]string{
		{"group", "ensure", "--roster", path, "qa-pve-01", "ops"},
		{"user", "ensure", "--roster", path, "qa-pve-01", "alice@pve"},
		{"acl", "grant", "--roster", path, "qa-pve-01", "--group", "ops", "--grant", "/:PVEAuditor"},
		{"access", "inventory", "--roster", path, "qa-pve-01"},
	} {
		code, _, stderr := runRootArgs(append(verb, "--no-ssh-key", "--host-key-fingerprint", wrongFP)...)
		if code != 1 || !strings.Contains(stderr, "host key mismatch") {
			t.Errorf("%s: exit %d, stderr %q", verb[0], code, stderr)
		}
	}
	if fs.PasswordAttempts() != 0 || len(fs.Commands()) != 0 {
		t.Fatalf("a wrong pin: %d password attempts, commands %q", fs.PasswordAttempts(), fs.Commands())
	}
	code, stdout, stderr := runRootArgs("group", "ensure", "--roster", path, "qa-pve-01", "ops", "--no-ssh-key", "--host-key-fingerprint", fs.HostKeyFingerprint())
	if code != 0 || stdout != "qa-pve-01: group ops created\n" || !slices.Equal(fs.Commands(), []string{"pveum group add 'ops'"}) {
		t.Fatalf("the right pin: exit %d, stdout %q, stderr %q, commands %q", code, stdout, stderr, fs.Commands())
	}

	keyPath, kfs, _ := accessSetup(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`}, nil)
	before := kfs.Connections() // the roster's own pin was captured by a dial
	code, _, stderr = runRootArgs("group", "ensure", "--roster", keyPath, "qa-pve-01", "ops", "--host-key-fingerprint", wrongFP)
	if code != 1 || !strings.Contains(stderr, "--host-key-fingerprint "+wrongFP+" is not the host key target \"qa-pve-01\" is pinned to") || kfs.Connections() != before {
		t.Errorf("a key target, another pin: exit %d, connections %d, stderr %q", code, kfs.Connections(), stderr)
	}
	if code, _, stderr := runRootArgs("group", "ensure", "--roster", keyPath, "qa-pve-01", "ops", "--host-key-fingerprint", "SHA256:short"); code != 1 || !strings.Contains(stderr, "as ssh-keygen -l -E sha256 prints it") || kfs.Connections() != before {
		t.Errorf("malformed: exit %d, stderr %q", code, stderr)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// HK4 (the review's two-server shape): the roster pins fake A's host key,
// and every connection is redirected to fake B, which takes root's
// password. A target holding a pin is pinned to it on EVERY connection,
// --no-ssh-key included: with no flag the stored pin refuses B; a flag
// naming B is refused before anything is dialed; either way B never sees
// the password. Each of the five commands that dial root.
func TestRootAccess_StoredPinBindsEveryDial(t *testing.T) {
	routes := map[string]string{"GET /api2/json/access/groups": `{"data":[]}`, "GET /api2/json/access/users": usersWithoutAlice}
	for _, tc := range []struct {
		name string
		args func(path string) []string
		// setup builds the roster pinned to its own server A and returns
		// its path, and that server
		setup func(t *testing.T) (string, *pvefake.SSHServer)
	}{
		{"group ensure", func(p string) []string { return []string{"group", "ensure", "--roster", p, "qa-pve-01", "ops"} }, nil},
		{"user ensure", func(p string) []string { return []string{"user", "ensure", "--roster", p, "qa-pve-01", "alice@pve"} }, nil},
		{"acl grant", func(p string) []string {
			return []string{"acl", "grant", "--roster", p, "qa-pve-01", "--group", "ops", "--grant", "/:PVEAuditor"}
		}, nil},
		{"access inventory", func(p string) []string { return []string{"access", "inventory", "--roster", p, "qa-pve-01"} }, nil},
		{"vm create --unique-tag", func(p string) []string {
			return []string{"vm", "create", "--roster", p, "qa-pve-01", "101", "tags=x", "--unique-tag", "x"}
		}, func(t *testing.T) (string, *pvefake.SSHServer) {
			f := newTagCluster(nil)
			return f.start(t), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			if tc.setup != nil {
				path, _ = tc.setup(t)
			} else {
				path, _, _ = accessSetup(t, routes, nil)
			}
			b := pvefake.NewSSHServer(t)
			b.AllowPassword("root", "root-pw")
			b.Start()
			rootAt(t, b)
			t.Setenv(pvePasswordEnvVar, "root-pw")

			// No flag: the stored pin, not trust on first use.
			code, _, stderr := runRootArgs(append(tc.args(path), "--no-ssh-key")...)
			if code != 1 || !strings.Contains(stderr, "host key mismatch") {
				t.Fatalf("--no-ssh-key, no flag: exit %d, stderr %q", code, stderr)
			}
			// A flag naming B: refused before any connection.
			code, _, stderr = runRootArgs(append(tc.args(path), "--no-ssh-key", "--host-key-fingerprint", b.HostKeyFingerprint())...)
			if code != 1 || !strings.Contains(stderr, "is not the host key target \"qa-pve-01\" is pinned to") {
				t.Fatalf("--no-ssh-key, a flag naming B: exit %d, stderr %q", code, stderr)
			}
			if b.PasswordAttempts() != 0 || len(b.Commands()) != 0 {
				t.Errorf("B saw %d password attempts, commands %q", b.PasswordAttempts(), b.Commands())
			}
			// The same flag without --no-ssh-key: refused before any connection.
			before := b.Connections()
			code, _, stderr = runRootArgs(append(tc.args(path), "--host-key-fingerprint", b.HostKeyFingerprint())...)
			if code != 1 || !strings.Contains(stderr, "is not the host key target \"qa-pve-01\" is pinned to") || b.Connections() != before {
				t.Errorf("a key target, a flag naming B: exit %d, stderr %q", code, stderr)
			}
		})
	}
}

// HK5: keyless against the pinned server itself: the stored pin is accepted
// and the password is sent there.
func TestRootAccess_StoredPinAcceptsItsHost(t *testing.T) {
	srv, _ := newRouteFake(t, map[string]string{"GET /api2/json/access/groups": `{"data":[]}`})
	a := pvefake.NewSSHServer(t)
	a.AllowPassword("root", "root-pw")
	a.HandleExec(pveumFake(nil))
	path := newTestRosterWithSSHTarget(t, srv, a)
	t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
	t.Setenv(pvePasswordEnvVar, "root-pw")
	rootAt(t, a)
	for _, flag := range [][]string{nil, {"--host-key-fingerprint", a.HostKeyFingerprint()}} {
		code, stdout, stderr := runRootArgs(append([]string{"group", "ensure", "--roster", path, "qa-pve-01", "ops", "--no-ssh-key"}, flag...)...)
		if code != 0 || !strings.Contains(stdout, "group ops") {
			t.Fatalf("%q: exit %d, stdout %q, stderr %q", flag, code, stdout, stderr)
		}
	}
	if a.PasswordAttempts() != 2 {
		t.Errorf("password attempts %d, want 2", a.PasswordAttempts())
	}
}

// HK6: vm create's pin applies only with --unique-tag: alone it is refused,
// as --no-ssh-key is, before anything is sent.
func TestVMCreate_HostKeyFingerprintNeedsUniqueTag(t *testing.T) {
	f := newTagCluster(nil)
	rp := f.start(t)
	code, _, stderr := createTagged(rp, 101, "x", "--host-key-fingerprint", "SHA256:"+strings.Repeat("A", 43))
	if code != 1 || !strings.Contains(stderr, "--host-key-fingerprint only applies with --unique-tag") || f.sent() != 0 {
		t.Fatalf("exit %d, %d sent, stderr %q", code, f.sent(), stderr)
	}
}

// HK7: a mismatch names the key type the client negotiated.
func TestHostKeyMismatchNamesTheNegotiatedType(t *testing.T) {
	fs := pvefake.NewSSHServer(t)
	fs.AllowPassword("root", "root-pw")
	fs.Start()
	withBootstrapFakes(t, &fakeBootstrapTransport{})
	newBootstrapTransport = bootstrap.NewSSHTransport
	_, _, stderr := runRootArgs("bootstrap", "qa-test", "--host", "127.0.0.1", "--node", "qa-test", "--ssh-port", strconv.Itoa(fs.Port(t)), "--grant", "/:PVEVMAdmin::1", "--no-ssh-key", "--host-key-fingerprint", wrongFP)
	if !strings.Contains(stderr, "host key mismatch for") || !strings.Contains(stderr, "got ED25519 "+fs.HostKeyFingerprint()) || !strings.Contains(stderr, "pveforge compares the key type it negotiates") {
		t.Errorf("stderr %q", stderr)
	}
}
