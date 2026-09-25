package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/bootstrap"
	"github.com/suykerbuyk/pveforge/internal/pvefake"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// A --host-key-fingerprint that was GIVEN is checked, an empty value
// included: internal/bootstrap reads "" as trust on first use, so an empty
// flag (an unset shell variable, say) must be refused, never read as "no
// pin". For every command that carries the flag, through runRoot, before
// anything is dialed.

var badPins = map[string]string{"empty": "", "malformed": "SHA256:short"}

const pinRefusal = "--host-key-fingerprint: host key fingerprint"

func TestBootstrap_AGivenPinMustBeOne(t *testing.T) {
	for _, keyless := range []bool{false, true} {
		for name, pin := range badPins {
			fs := pvefake.NewSSHServer(t)
			fs.AllowPassword("root", "test-pve-pass")
			fs.Start()
			withBootstrapFakes(t, &fakeBootstrapTransport{})
			newBootstrapTransport = bootstrap.NewSSHTransport
			args := []string{"bootstrap", "qa-test", "--host", "127.0.0.1", "--node", "qa-test", "--ssh-port", strconv.Itoa(fs.Port(t)), "--grant", "/:PVEVMAdmin::1", "--host-key-fingerprint", pin}
			if keyless {
				args = append(args, "--no-ssh-key")
			}
			code, _, stderr := runRootArgs(args...)
			if code != 1 || !strings.Contains(stderr, pinRefusal) {
				t.Errorf("keyless %t, %s: exit %d, stderr %q", keyless, name, code, stderr)
			}
			if fs.Connections() != 0 || fs.PasswordAttempts() != 0 {
				t.Errorf("keyless %t, %s: %d connections, %d password attempts", keyless, name, fs.Connections(), fs.PasswordAttempts())
			}
		}
	}
}

func TestRootAccess_AGivenPinMustBeOne(t *testing.T) {
	verbs := map[string]func(path string) []string{
		"group ensure": func(p string) []string { return []string{"group", "ensure", "--roster", p, "qa-pve-01", "ops"} },
		"user ensure":  func(p string) []string { return []string{"user", "ensure", "--roster", p, "qa-pve-01", "alice@pve"} },
		"acl grant": func(p string) []string {
			return []string{"acl", "grant", "--roster", p, "qa-pve-01", "--group", "ops", "--grant", "/:PVEAuditor"}
		},
		"access inventory": func(p string) []string { return []string{"access", "inventory", "--roster", p, "qa-pve-01"} },
	}
	routes := map[string]string{"GET /api2/json/access/groups": `{"data":[]}`, "GET /api2/json/access/users": usersWithoutAlice}
	for verb, args := range verbs {
		for name, pin := range badPins {
			// A keyless target: without the check, "" would mean trust on
			// first use for root's password.
			srv, _ := newRouteFake(t, routes)
			fs := pvefake.NewSSHServer(t)
			fs.AllowPassword("root", "root-pw")
			fs.Start()
			path := writeTestRoster(t, srv, "qa-pve-01", "qa-pve-01", "")
			t.Setenv(roster.PassphraseEnvVar, rosterPassphrase)
			t.Setenv(pvePasswordEnvVar, "root-pw")
			rootAt(t, fs)
			code, _, stderr := runRootArgs(append(args(path), "--no-ssh-key", "--host-key-fingerprint", pin)...)
			if code != 1 || !strings.Contains(stderr, pinRefusal) || fs.Connections() != 0 || fs.PasswordAttempts() != 0 {
				t.Errorf("%s, keyless, %s: exit %d, %d connections, %d password attempts, stderr %q", verb, name, code, fs.Connections(), fs.PasswordAttempts(), stderr)
			}
			// A key target: "" would silently fall back to the stored pin; a
			// given value is checked all the same.
			keyPath, kfs, _ := accessSetup(t, routes, nil)
			before := kfs.Connections() // the roster's own pin was captured by a dial
			code, _, stderr = runRootArgs(append(args(keyPath), "--host-key-fingerprint", pin)...)
			if code != 1 || !strings.Contains(stderr, pinRefusal) || kfs.Connections() != before {
				t.Errorf("%s, key target, %s: exit %d, connections %d (was %d), stderr %q", verb, name, code, kfs.Connections(), before, stderr)
			}
		}
	}
}

func TestVMCreate_AGivenPinMustBeOne(t *testing.T) {
	for name, pin := range badPins {
		f := newTagCluster(nil)
		rp := f.start(t)
		t.Setenv(pvePasswordEnvVar, "root-pw")
		code, _, stderr := createTagged(rp, 101, "x", "--unique-tag", "x", "--no-ssh-key", "--host-key-fingerprint", pin)
		if code != 1 || !strings.Contains(stderr, pinRefusal) || f.sent() != 0 {
			t.Errorf("%s: exit %d, %d sent, stderr %q", name, code, f.sent(), stderr)
		}
	}
}
