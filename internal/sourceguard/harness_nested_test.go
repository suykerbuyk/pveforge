package sourceguard

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// nested.sh (pveforge-harness-golden-reset, P2): the nested bootstrap and the
// bridge, run offline against the fake pveforge (roster init, bootstrap,
// network bridge create), the fake ssh (the pinned login), a fake ssh-keygen
// (the pins' fingerprints) and a fake accept. ssh and accept write their
// calls into pveforge's argv.log too, so the order across all three shows.

const (
	nestedOuter = "/nonexistent/outer-roster.toml"
	nestedGrant = "/:Administrator::1"
)

// ecdsaKey is the ECDSA host key VM v's sshd serves: the type pveforge's SSH
// client negotiates (build.sh pins the ed25519 one, hostKey).
func ecdsaKey(v string) string {
	return "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEcdsa" + v
}

// ecdsaFP is the fingerprint the fake ssh-keygen gives ecdsaKey(v): the first
// 43 hex digits of the key blob's sha256 (the real form is 43 base64
// characters; hex digits are among them).
func ecdsaFP(v string) string {
	sum := sha256.Sum256([]byte(strings.Fields(ecdsaKey(v))[1]))
	return "SHA256:" + hex.EncodeToString(sum[:])[:43]
}

// keyscanKey is the fake ssh's answer key for the served-key read.
const keyscanCmd = "ssh-keyscan -t ecdsa 127.0.0.1"

// serveECDSA makes the node at dest answer the served-key read with body.
func serveECDSA(t *testing.T, home, dest, body string) {
	t.Helper()
	writeFile(t, filepath.Join(filepath.Dir(home), "fake", "ssh", "host", fakeKey(dest), "resp", fakeKey(keyscanCmd)), body, 0o600)
}

func bootstrapJSON(fp string) string {
	return `{"target":"x","token_id":"root@pam!pveforge","host_key_fingerprint":"` + fp + `","token_outcome":"minted","validation":"verified"}`
}

// nestedWorld: build.sh pinned all three hosts; each pinned login works, and
// bootstrap pins the same host keys.
func nestedWorld(t *testing.T, mode string) probeSpec {
	t.Helper()
	fakeSSH, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-ssh.sh"))
	if err != nil {
		t.Fatal(err)
	}
	accept, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-accept.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := filepath.Abs(filepath.Join(harnessDir, "test", "fake-pins.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := probeSpec{
		script: "nested.sh",
		args:   []string{mode},
		env: map[string]string{
			"PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD": nestedPw,
			"PVEFORGE_HARNESS_OUTER_ROSTERS":        nestedOuter,
			"HARNESS_ACCEPT_BIN":                    accept,
			"HARNESS_PINS_BIN":                      pins,
		},
		resp: map[string]string{
			"bootstrap pvh-n1": bootstrapJSON(ecdsaFP("690")),
			"bootstrap pvh-n2": bootstrapJSON(ecdsaFP("691")),
		},
		stubs: map[string]string{
			"ssh":        "#!/usr/bin/env bash\nprintf 'ssh %s\\n' \"${*: -2:1}\" >>\"$FAKE_PVEFORGE_DIR/argv.log\"\nenv >>\"$FAKE_PVEFORGE_DIR/ssh.env\"\nFAKE_SSH_DIR=$FAKE_PVEFORGE_DIR/ssh exec bash " + fakeSSH + " \"$@\"\n",
			"ssh-keygen": "#!/usr/bin/env bash\nenv >>\"$FAKE_PVEFORGE_DIR/keygen.env\"\n[ \"$*\" = '-l -E sha256 -f /dev/stdin' ] || exit 97\nread -r ip typ blob\nh=$(printf '%s' \"$blob\" | sha256sum)\nprintf '256 SHA256:%s %s (ED25519)\\n' \"${h:0:43}\" \"$ip\"\n",
		},
		setup: func(t *testing.T, home string) {
			cfg := filepath.Join(home, ".config/pveforge")
			writeFile(t, filepath.Join(cfg, "harness-build.env"), exampleEnv(t), 0o600)
			writeFile(t, filepath.Join(cfg, "harness-nested_ed25519"), "fake private key\n", 0o600)
			writeFile(t, filepath.Join(cfg, "harness-nested.known_hosts"), hostKey("690")+"\n"+hostKey("691")+"\n"+hostKey("692")+"\n", 0o600)
			fake := filepath.Join(filepath.Dir(home), "fake")
			for _, d := range []string{"env", "ssh/calls", "ssh/resp", "ssh/rc"} {
				if err := os.MkdirAll(filepath.Join(fake, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// Each node serves one ECDSA key (and keyscan's comment line).
			serveECDSA(t, home, "root@192.0.2.90", "# 127.0.0.1:22 SSH-2.0-OpenSSH_10.0\n127.0.0.1 "+ecdsaKey("690")+"\n")
			serveECDSA(t, home, "root@192.0.2.91", "127.0.0.1 "+ecdsaKey("691")+"\n")
			// What the roster records once each node is bootstrapped.
			setPins(t, home, "pvh-n1", "192.0.2.90 "+ecdsaFP("690"))
			setPins(t, home, "pvh-n2", "192.0.2.91 "+ecdsaFP("691"))
		},
	}
	if mode == "bootstrap" {
		// A fresh roster: each node's first read, before its bootstrap, finds
		// no target.
		s = withSetup(s, func(t *testing.T, home string) {
			setPinsN(t, home, "pvh-n1", 1, "absent")
			setPinsN(t, home, "pvh-n2", 1, "absent")
		})
	}
	if mode == "bridge" {
		prev := s.setup
		s.setup = func(t *testing.T, home string) {
			prev(t, home)
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.toml"), "# the nested roster\n", 0o600)
		}
	}
	return s
}

// setPins makes the fake pins tool answer rec for node ("" for no such
// target).
func setPins(t *testing.T, home, node, rec string) {
	t.Helper()
	p := filepath.Join(filepath.Dir(home), "fake", "pins", node)
	if rec == "" {
		os.Remove(p)
		return
	}
	writeFile(t, p, rec+"\n", 0o600)
}

// setPinsN makes the fake pins tool answer rec to call n for node.
func setPinsN(t *testing.T, home, node string, n int, rec string) {
	t.Helper()
	writeFile(t, filepath.Join(filepath.Dir(home), "fake", "pins", node+"."+strconv.Itoa(n)), rec+"\n", 0o600)
}

// withSetup adds f to s's setup.
func withSetup(s probeSpec, f func(t *testing.T, home string)) probeSpec {
	prev := s.setup
	s.setup = func(t *testing.T, home string) {
		prev(t, home)
		f(t, home)
	}
	return s
}

// nestedCalls are the run's calls, pveforge's, ssh's and accept's, in order,
// with $HOME written ~.
func nestedCalls(r probeResult) []string {
	var c []string
	for _, l := range r.calls {
		c = append(c, strings.ReplaceAll(l, r.home, "~"))
	}
	return c
}

func nestedEvidence(t *testing.T, r probeResult, mode, name string) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/nested-"+mode+"/*"))
	if len(dirs) != 1 {
		t.Fatalf("nested-%s evidence directories = %q, want exactly one", mode, dirs)
	}
	b, err := os.ReadFile(filepath.Join(dirs[0], name))
	if err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	return string(b)
}

// childEnv is the environment pveforge's call n (1-based line of argv.log)
// ran with.
func childEnv(t *testing.T, r probeResult, n int) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(r.home), "fake", "env", strconv.Itoa(n)))
	if err != nil {
		t.Fatalf("no environment saved for call %d: %v", n, err)
	}
	return string(b)
}

func bootstrapCall(node, ip, v string) string {
	return "bootstrap " + node + " --roster ~/.config/pveforge/harness-nested.toml --host " + ip + " --node " + node + " --insecure-tls --grant " + nestedGrant + " --host-key-fingerprint " + ecdsaFP(v) + " -o json"
}

func bridgeCall(node string) string {
	return "network bridge create " + node + " pvhbr1 --management-bridge vmbr0 --roster ~/.config/pveforge/harness-nested.toml"
}

func pinsCall(node string) string {
	return "pins ~/.config/pveforge/harness-nested.toml " + node
}

// nestedBootstrapCalls: for each node, the pinned login (which reads the
// served ECDSA key), the roster's record before and after its bootstrap.
var nestedBootstrapCalls = []string{
	"roster init ~/.config/pveforge/harness-nested.toml",
	"ssh root@192.0.2.90", pinsCall("pvh-n1"), bootstrapCall("pvh-n1", "192.0.2.90", "690"), pinsCall("pvh-n1"),
	"ssh root@192.0.2.91", pinsCall("pvh-n2"), bootstrapCall("pvh-n2", "192.0.2.91", "691"), pinsCall("pvh-n2"),
}

// preflightPins are the reads of a roster that exists before the run.
var preflightPins = []string{pinsCall("pvh-n1"), pinsCall("pvh-n2")}

// noPasswordLeaked: the password is in no output, no evidence file, and no
// child's environment but bootstrap's.
func noPasswordLeaked(t *testing.T, r probeResult, mode string) {
	t.Helper()
	if strings.Contains(r.stdout+r.stderr, nestedPw) {
		t.Error("the password was printed")
	}
	root := filepath.Join(r.home, ".config/pveforge/harness-evidence")
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), nestedPw) {
				t.Errorf("the password is in the evidence: %s", p)
			}
		}
		return nil
	})
	for _, f := range []string{"ssh.env", "accept.env", "pins.env"} {
		if strings.Contains(fakeLog(r, f), nestedPw) || strings.Contains(fakeLog(r, f), "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD") {
			t.Errorf("the password reached %s's environment", strings.TrimSuffix(f, ".env"))
		}
	}
	for i, c := range r.calls {
		if strings.HasPrefix(c, "ssh ") || strings.HasPrefix(c, "accept ") || strings.HasPrefix(c, "pins ") {
			continue
		}
		env := childEnv(t, r, i+1)
		if strings.Contains(env, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD") {
			t.Errorf("call %q inherited PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD", c)
		}
		isBootstrap := strings.HasPrefix(c, "bootstrap ")
		if got := strings.Contains(env, "\nPVEFORGE_PVE_PASSWORD="+nestedPw+"\n") || strings.HasPrefix(env, "PVEFORGE_PVE_PASSWORD="+nestedPw+"\n"); got != isBootstrap {
			t.Errorf("call %q: the password in its environment = %v, want %v", c, got, isBootstrap)
		}
		if !isBootstrap && strings.Contains(env, nestedPw) {
			t.Errorf("call %q saw the password", c)
		}
	}
}

// N1: a first bootstrap: the roster is made, each node proves its pinned key
// before its bootstrap, the password reaches bootstrap's environment only,
// the grant is /:Administrator::1, and the pins agree.
func TestNested_Bootstrap(t *testing.T) {
	r := runProbe(t, nestedWorld(t, "bootstrap"))
	if r.code != 0 {
		t.Fatalf("exit %d:\n%s", r.code, r.stderr)
	}
	equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls)
	noPasswordLeaked(t, r, "bootstrap")
	for i, c := range r.calls {
		if strings.HasPrefix(c, "bootstrap ") && !strings.Contains(childEnv(t, r, i+1), "\nPVEFORGE_ROSTER_PASSPHRASE=not-a-secret\n") {
			t.Errorf("%q ran without the roster passphrase", c)
		}
	}
	// The pinned login: build.sh's key and pins, and nothing else.
	calls := sshCalls(t, r)
	if len(calls) != 2 {
		t.Fatalf("ssh calls: %d", len(calls))
	}
	for _, c := range calls {
		o := strings.Join(c.opts, " ")
		for _, want := range []string{"-F /dev/null", "-o IdentitiesOnly=yes", "-o BatchMode=yes", "-o StrictHostKeyChecking=yes", "-o GlobalKnownHostsFile=/dev/null",
			"-i " + filepath.Join(r.home, ".config/pveforge/harness-nested_ed25519")} {
			if !strings.Contains(o, want) {
				t.Errorf("%s: options %q lack %q", c.dest, o, want)
			}
		}
		checkOneLineKnownHosts(t, r, c)
		if c.cmd != keyscanCmd {
			t.Errorf("%s ran %q", c.dest, c.cmd)
		}
	}
	res := nestedEvidence(t, r, "bootstrap", "result.txt")
	for _, want := range []string{"PASS roster init", "the ECDSA key it serves is " + ecdsaFP("690"),
		"PASS bootstrap pvh-n1: grant " + nestedGrant + ", host key " + ecdsaFP("690") + " verified before the password", "PASS bootstrap pvh-n2: grant " + nestedGrant + ", host key " + ecdsaFP("691"), "RESULT phase=nested-bootstrap fail=0"} {
		if !strings.Contains(res, want) {
			t.Errorf("result.txt lacks %q:\n%s", want, res)
		}
	}
	if b, err := os.ReadFile(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); err != nil || len(b) == 0 {
		t.Errorf("the nested roster was not made: %v", err)
	}
}

// N2: a second bootstrap keeps the roster it finds.
func TestNested_BootstrapAgainKeepsTheRoster(t *testing.T) {
	s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
		writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.toml"), "# the nested roster\n", 0o600)
		// Both nodes bootstrapped before: every read finds their pins.
		os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n1.1"))
		os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n2.1"))
	})
	s.resp["bootstrap pvh-n1"] = strings.Replace(bootstrapJSON(ecdsaFP("690")), `"minted"`, `"reused"`, 1)
	s.resp["bootstrap pvh-n2"] = strings.Replace(bootstrapJSON(ecdsaFP("691")), `"minted"`, `"reused"`, 1)
	r := runProbe(t, s)
	if r.code != 0 {
		t.Fatalf("exit %d:\n%s", r.code, r.stderr)
	}
	equalCalls(t, "calls", nestedCalls(r), append(append([]string{}, preflightPins...), nestedBootstrapCalls[1:]...))
	if b, _ := os.ReadFile(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); string(b) != "# the nested roster\n" {
		t.Errorf("the roster was rewritten: %q", b)
	}
}

// N3: a pin bootstrap reports that is not build.sh's stops the run, and the
// roster holding it is moved aside, so nothing can use it.
func TestNested_APinMismatchIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		node, answer string
		calls        int
	}{
		"pvh-n1 another key": {"pvh-n1", bootstrapJSON(ecdsaFP("692")), 5},
		"pvh-n2 another key": {"pvh-n2", bootstrapJSON(ecdsaFP("690")), 9},
		"pvh-n2 no key":      {"pvh-n2", `{"target":"pvh-n2","token_id":"root@pam!pveforge"}`, 9},
		"pvh-n1 not JSON":    {"pvh-n1", `token_id=root@pam!pveforge`, 5},
	} {
		t.Run(name, func(t *testing.T) {
			s := nestedWorld(t, "bootstrap")
			s.resp["bootstrap "+tc.node] = tc.answer
			r := runProbe(t, s)
			if r.code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stderr)
			}
			equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:tc.calls])
			if !strings.Contains(r.stdout, "refused; the roster is now ") {
				t.Errorf("the refusal is not reported:\n%s", r.stdout)
			}
			if _, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); !os.IsNotExist(err) {
				t.Errorf("the roster holding the refused pin is still in place: %v", err)
			}
			if m, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-nested.toml.refused-*")); len(m) != 1 {
				t.Errorf("the roster was not moved aside: %q", m)
			}
			if !strings.Contains(nestedEvidence(t, r, "bootstrap", "result.txt"), "RESULT phase=nested-bootstrap fail=1") {
				t.Error("the evidence does not end red")
			}
			noPasswordLeaked(t, r, "bootstrap")
		})
	}
}

// N4: a host that cannot prove build.sh's pin is never sent the password; a
// failed bootstrap stops the run before the next node.
func TestNested_BootstrapStopsWhereItFails(t *testing.T) {
	t.Run("pvh-n2 fails its pinned login", func(t *testing.T) {
		s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
			d := filepath.Join(filepath.Dir(home), "fake", "ssh", "host", fakeKey("root@192.0.2.91"), "rc")
			writeFile(t, filepath.Join(d, fakeKey(keyscanCmd)), "255", 0o600)
		})
		r := runProbe(t, s)
		if r.code != 1 || !strings.Contains(r.stdout, "no password was sent") {
			t.Fatalf("exit %d, want 1:\n%s\n%s", r.code, r.stdout, r.stderr)
		}
		equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:6])
		noPasswordLeaked(t, r, "bootstrap")
	})
	// A failed bootstrap: the roster stays only while no SSH login is
	// recorded; once one is, its pin was never compared, so it goes aside.
	for name, tc := range map[string]struct {
		rec, want string
		kept      bool
	}{
		"no target yet":            {"", "no SSH login recorded, the roster kept", true},
		"a target without login":   {"192.0.2.90 -", "no SSH login recorded, the roster kept", true},
		"after the login, the pin": {"192.0.2.90 " + ecdsaFP("690"), "failed after its SSH login was recorded", false},
		"after the login, another": {"192.0.2.90 " + ecdsaFP("692"), "failed after its SSH login was recorded", false},
		"a roster it cannot read":  {"unreadable", "failed after its SSH login was recorded ('unreadable')", false},
	} {
		t.Run("pvh-n1's bootstrap fails, "+name, func(t *testing.T) {
			s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
				setPins(t, home, "pvh-n1", tc.rec)
			})
			s.rc = map[string]map[int]int{"bootstrap pvh-n1": {0: 1}}
			r := runProbe(t, s)
			if r.code != 1 || !strings.Contains(r.stdout, "RED bootstrap pvh-n1 (exit 1)") || !strings.Contains(r.stdout, tc.want) {
				t.Fatalf("exit %d, want 1 and %q:\n%s", r.code, tc.want, r.stdout)
			}
			equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:5])
			_, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.toml"))
			if kept := err == nil; kept != tc.kept {
				t.Errorf("the roster kept = %v, want %v", kept, tc.kept)
			}
			noPasswordLeaked(t, r, "bootstrap")
		})
	}
	for name, answer := range map[string]string{
		"an unverified token": strings.Replace(bootstrapJSON(ecdsaFP("691")), `"verified"`, `"unverified"`, 1),
		"a discarded token":   strings.Replace(bootstrapJSON(ecdsaFP("691")), `"minted"`, `"discarded"`, 1),
		"no validation":       strings.Replace(bootstrapJSON(ecdsaFP("691")), `,"validation":"verified"`, "", 1),
	} {
		t.Run("pvh-n2 "+name, func(t *testing.T) {
			s := nestedWorld(t, "bootstrap")
			s.resp["bootstrap pvh-n2"] = answer
			r := runProbe(t, s)
			if r.code != 1 || !strings.Contains(r.stdout, "RED bootstrap pvh-n2: token_outcome/validation is") {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
			}
			// The pin was right: the roster stays.
			if _, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); err != nil {
				t.Errorf("the roster: %v", err)
			}
		})
	}
	for _, outcome := range []string{"reused", "replaced"} {
		t.Run("pvh-n1 "+outcome, func(t *testing.T) {
			s := nestedWorld(t, "bootstrap")
			s.resp["bootstrap pvh-n1"] = strings.Replace(bootstrapJSON(ecdsaFP("690")), `"minted"`, `"`+outcome+`"`, 1)
			r := runProbe(t, s)
			if r.code != 0 || !strings.Contains(r.stdout, "token "+outcome+" and verified") {
				t.Fatalf("exit %d, want 0:\n%s", r.code, r.stdout)
			}
		})
	}
	t.Run("roster init fails", func(t *testing.T) {
		s := nestedWorld(t, "bootstrap")
		s.rc = map[string]map[int]int{"roster init": {0: 1}}
		r := runProbe(t, s)
		if r.code != 1 || !strings.Contains(r.stdout, "RED roster init") {
			t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
		}
		equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:1])
	})
}

// N5: every refusal comes before anything is run or sent.
func TestNested_RefusedBeforeAnything(t *testing.T) {
	type tc struct {
		mode string
		f    func(s *probeSpec)
		want string
	}
	home := func(f func(t *testing.T, home string)) func(s *probeSpec) {
		return func(s *probeSpec) { *s = withSetup(*s, f) }
	}
	cfg := func(home string) string { return filepath.Join(home, ".config/pveforge") }
	for name, c := range map[string]tc{
		"no mode":                 {"", func(s *probeSpec) { s.args = nil }, "usage: nested.sh bootstrap|bridge"},
		"an unknown mode":         {"", func(s *probeSpec) { s.args = []string{"golden"} }, "usage: nested.sh bootstrap|bridge"},
		"an extra argument":       {"", func(s *probeSpec) { s.args = append(s.args, "--force") }, "one argument"},
		"no password":             {"bootstrap", func(s *probeSpec) { s.env["PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"] = "-" }, "PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD is not set"},
		"a control character":     {"bootstrap", func(s *probeSpec) { s.env["PVEFORGE_HARNESS_NESTED_ROOT_PASSWORD"] = "pw\x01x" }, "holds a control character"},
		"PVEFORGE_PVE_PASSWORD":   {"bootstrap", func(s *probeSpec) { s.env["PVEFORGE_PVE_PASSWORD"] = "other" }, "PVEFORGE_PVE_PASSWORD is set"},
		"PVEFORGE_PVE_PASSWORD b": {"bridge", func(s *probeSpec) { s.env["PVEFORGE_PVE_PASSWORD"] = "other" }, "PVEFORGE_PVE_PASSWORD is set"},
		"no roster passphrase":    {"bootstrap", func(s *probeSpec) { s.env["PVEFORGE_ROSTER_PASSPHRASE"] = "-" }, "PVEFORGE_ROSTER_PASSPHRASE is not set"},
		"xtrace":                  {"bootstrap", func(s *probeSpec) { s.bashArgs = []string{"-x"} }, "include xtrace, verbose, allexport, functrace or errtrace"},
		"BASH_ENV":                {"bootstrap", func(s *probeSpec) { s.env["BASH_ENV"] = "/dev/null" }, "BASH_ENV or ENV is set"},
		"a relative PVEFORGE_BIN": {"bootstrap", func(s *probeSpec) { s.env["PVEFORGE_BIN"] = "pveforge" }, "PVEFORGE_BIN must be the absolute path"},
		"another nested roster":   {"bridge", func(s *probeSpec) { s.env["PVEFORGE_HARNESS_ROSTER"] = "/tmp/other.toml" }, "the nested harness roster is"},
		"no pin for pvh-n2": {"bootstrap", home(func(t *testing.T, h string) {
			writeFile(t, filepath.Join(cfg(h), "harness-nested.known_hosts"), hostKey("690")+"\n"+hostKey("692")+"\n", 0o600)
		}), "must pin exactly one ed25519 host key for 192.0.2.91 (pvh-n2)"},
		"two pins for pvh-n1": {"bootstrap", home(func(t *testing.T, h string) {
			writeFile(t, filepath.Join(cfg(h), "harness-nested.known_hosts"), hostKey("690")+"\n"+hostKey("691")+"\n"+hostKey("690")+"x\n", 0o600)
		}), "must pin exactly one ed25519 host key for 192.0.2.90 (pvh-n1)"},
		"an open known_hosts": {"bootstrap", home(func(t *testing.T, h string) {
			os.Chmod(filepath.Join(cfg(h), "harness-nested.known_hosts"), 0o644)
		}), "has mode 644, want 600"},
		"a symlinked nested key": {"bootstrap", home(func(t *testing.T, h string) {
			k := filepath.Join(cfg(h), "harness-nested_ed25519")
			os.Rename(k, k+".real")
			os.Symlink(k+".real", k)
		}), "harness-nested_ed25519 does not exist or is not a regular file"},
		"a symlinked known_hosts": {"bootstrap", home(func(t *testing.T, h string) {
			k := filepath.Join(cfg(h), "harness-nested.known_hosts")
			os.Rename(k, k+".real")
			os.Symlink(k+".real", k)
		}), "harness-nested.known_hosts does not exist or is not a regular file"},
		// A relative path that names a real executable, from the working
		// directory: refused for being relative, not for being missing.
		"a relative pins tool": {"bootstrap", func(s *probeSpec) {
			*s = withSetup(*s, func(t *testing.T, h string) {
				writeFile(t, filepath.Join(filepath.Dir(h), "work", "pins"), "#!/bin/sh\nexit 0\n", 0o700)
			})
			s.env["HARNESS_PINS_BIN"] = "pins"
		}, "HARNESS_PINS_BIN must be the absolute path"},
		"no nested key": {"bootstrap", home(func(t *testing.T, h string) {
			os.Remove(filepath.Join(cfg(h), "harness-nested_ed25519"))
		}), "harness-nested_ed25519 does not exist"},
		"an open nested roster": {"bootstrap", home(func(t *testing.T, h string) {
			writeFile(t, filepath.Join(cfg(h), "harness-nested.toml"), "#\n", 0o644)
		}), "harness-nested.toml has mode 644, want 600"},
		"a nested roster symlink": {"bootstrap", home(func(t *testing.T, h string) {
			os.Symlink("/dev/null", filepath.Join(cfg(h), "harness-nested.toml"))
		}), "harness-nested.toml is not a regular file"},
		"bridge without a roster": {"bridge", home(func(t *testing.T, h string) {
			os.Remove(filepath.Join(cfg(h), "harness-nested.toml"))
		}), "run 'nested.sh bootstrap' first"},
		"bridge without outer rosters": {"bridge", func(s *probeSpec) { s.env["PVEFORGE_HARNESS_OUTER_ROSTERS"] = "-" }, "PVEFORGE_HARNESS_OUTER_ROSTERS must list the outer rosters"},
		"a relative accept tool":       {"bridge", func(s *probeSpec) { s.env["HARNESS_ACCEPT_BIN"] = "accept" }, "HARNESS_ACCEPT_BIN must be the absolute path"},
	} {
		t.Run(name, func(t *testing.T) {
			mode := c.mode
			if mode == "" {
				mode = "bootstrap"
			}
			s := nestedWorld(t, mode)
			c.f(&s)
			r := runProbe(t, s)
			if r.code != 2 || !strings.Contains(r.stderr, c.want) {
				t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, c.want, r.stderr)
			}
			if len(r.calls) != 0 {
				t.Errorf("a refused run ran %q", r.calls)
			}
			if strings.Contains(r.stdout+r.stderr, nestedPw) {
				t.Error("the password was printed")
			}
			if m, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/*")); len(m) != 0 {
				t.Errorf("a refused run opened evidence: %q", m)
			}
		})
	}
}

// N6: another harness script holding the lock stops this one before anything.
func TestNested_TheLock(t *testing.T) {
	s := nestedWorld(t, "bootstrap")
	s.stubs["flock"] = "#!/usr/bin/env bash\nexit 1\n"
	r := runProbe(t, s)
	if r.code != 2 || !strings.Contains(r.stderr, "another harness script holds") || len(r.calls) != 0 {
		t.Fatalf("exit %d, calls %q:\n%s", r.code, r.calls, r.stderr)
	}
}

// B1: the bridge: acceptance first, through the nested roster and without
// the password, then pvhbr1 on each node.
func TestNested_Bridge(t *testing.T) {
	r := runProbe(t, nestedWorld(t, "bridge"))
	if r.code != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	equalCalls(t, "calls", nestedCalls(r), append(append([]string{}, preflightPins...), "accept -deadline 5m", bridgeCall("pvh-n1"), bridgeCall("pvh-n2")))
	noPasswordLeaked(t, r, "bridge")
	env := fakeLog(r, "accept.env")
	for _, want := range []string{
		"\nPVEFORGE_HARNESS_ROSTER=" + filepath.Join(r.home, ".config/pveforge/harness-nested.toml") + "\n",
		"\nPVEFORGE_HARNESS_OUTER_ROSTERS=" + nestedOuter + "\n",
	} {
		if !strings.Contains("\n"+env, want) {
			t.Errorf("acceptance's environment lacks %q", strings.TrimSpace(want))
		}
	}
	res := nestedEvidence(t, r, "bridge", "result.txt")
	for _, want := range []string{"PASS acceptance", "PASS bridge pvhbr1 on pvh-n1 (management bridge vmbr0)", "PASS bridge pvhbr1 on pvh-n2", "RESULT phase=nested-bridge fail=0"} {
		if !strings.Contains(res, want) {
			t.Errorf("result.txt lacks %q:\n%s", want, res)
		}
	}
}

// B2: a nested cluster that is not whole gets no bridge; a failed bridge stops
// the run before the next node.
func TestNested_BridgeStopsWhereItFails(t *testing.T) {
	for _, rc := range []string{"1", "143"} {
		t.Run("acceptance exits "+rc, func(t *testing.T) {
			s := withSetup(nestedWorld(t, "bridge"), func(t *testing.T, home string) {
				writeFile(t, filepath.Join(filepath.Dir(home), "fake", "accept.rc"), rc, 0o600)
			})
			r := runProbe(t, s)
			if r.code != 1 || !strings.Contains(r.stdout, "RED acceptance (exit "+rc+")") || !strings.Contains(r.stdout, "no bridge was touched") {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
			}
			equalCalls(t, "calls", nestedCalls(r), append(append([]string{}, preflightPins...), "accept -deadline 5m"))
		})
	}
	t.Run("pvh-n1's bridge fails", func(t *testing.T) {
		s := nestedWorld(t, "bridge")
		s.rc = map[string]map[int]int{"network bridge create pvh-n1 pvhbr1": {0: 1}}
		r := runProbe(t, s)
		if r.code != 1 || !strings.Contains(r.stdout, "RED bridge pvhbr1 on pvh-n1") {
			t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
		}
		equalCalls(t, "calls", nestedCalls(r), append(append([]string{}, preflightPins...), "accept -deadline 5m", bridgeCall("pvh-n1")))
	})
}

// The pins are compared as ssh-keygen prints them and pveforge records them:
// both are SHA256:<unpadded base64 of the key blob's sha256>, the form
// golang.org/x/crypto/ssh.FingerprintSHA256 gives (internal/sshexec).
func TestNested_FingerprintFormsAgree(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatalf("ssh-keygen is required to test nested.sh's pin comparison: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// ECDSA P-256: the type pveforge negotiates with a stock PVE node, and so
	// the one nested.sh actually pins.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]any{"ED25519": edPub, "ECDSA P-256": &ecPriv.PublicKey} {
		key, err := ssh.NewPublicKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		line := "192.0.2.90 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		cmd := exec.Command(keygen, "-l", "-E", "sha256", "-f", "/dev/stdin")
		cmd.Stdin = strings.NewReader(line + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: ssh-keygen: %v", name, err)
		}
		f := strings.Fields(string(out))
		if len(f) < 2 || f[1] != ssh.FingerprintSHA256(key) || !strings.HasSuffix(strings.TrimSpace(string(out)), "("+strings.Fields(name)[0]+")") {
			t.Errorf("%s: ssh-keygen printed %q; pveforge records %s", name, out, ssh.FingerprintSHA256(key))
		}
	}
}

// The refusals of inherited code (TestPasswordScripts_RefuseInheritedCode)
// hold for nested.sh too.
func TestNested_RefusesInheritedCode(t *testing.T) {
	spy := `() {  builtin echo "$@" >>captured; builtin printf "$@"; }`
	for name, tc := range map[string]struct {
		env     map[string]string
		bashEnv string
		want    string
	}{
		"an inherited printf": {env: map[string]string{"BASH_FUNC_printf%%": spy}, want: "shell functions already defined (inherited from the environment)"},
		"a disabled builtin":  {bashEnv: "enable -n printf\nunset BASH_ENV\n", want: "shell builtins are disabled: enable -n printf"},
		"a BASH_ENV function": {bashEnv: "cat() { builtin echo \"$@\" >>captured; }\nunset BASH_ENV\n", want: "shell functions already defined"},
	} {
		t.Run(name, func(t *testing.T) {
			s := nestedWorld(t, "bootstrap")
			for k, v := range tc.env {
				s.env[k] = v
			}
			if tc.bashEnv != "" {
				body := tc.bashEnv
				s = withSetup(s, func(t *testing.T, home string) {
					writeFile(t, filepath.Join(filepath.Dir(home), "work", "benv.sh"), body, 0o600)
				})
				s.env["BASH_ENV"] = "benv.sh"
			}
			r := runProbe(t, s)
			if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			if b, err := os.ReadFile(filepath.Join(filepath.Dir(r.home), "work", "captured")); err == nil {
				t.Errorf("the spy ran: %q", b)
			}
			if strings.Contains(r.stdout+r.stderr, nestedPw) || len(r.calls) != 0 {
				t.Error("a refused run printed the password or ran something")
			}
		})
	}
}

// checkOneLineKnownHosts: the pinned login trusts a file holding only
// build.sh's one line for that node.
func checkOneLineKnownHosts(t *testing.T, r probeResult, c sshCall) {
	t.Helper()
	v := map[string]string{"root@192.0.2.90": "690", "root@192.0.2.91": "691"}[c.dest]
	var file string
	for i, o := range c.opts {
		if i > 0 && c.opts[i-1] == "-o" && strings.HasPrefix(o, "UserKnownHostsFile=") {
			file = strings.TrimPrefix(o, "UserKnownHostsFile=")
		}
	}
	dir := filepath.Dir(file)
	if m, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/nested-bootstrap/*")); len(m) != 1 || dir != m[0] {
		t.Errorf("%s: UserKnownHostsFile=%q is not in this run's evidence", c.dest, file)
	}
	b, err := os.ReadFile(file)
	if err != nil || string(b) != hostKey(v)+"\n" {
		t.Errorf("%s: %s holds %q (%v), want only %q", c.dest, file, b, err, hostKey(v))
	}
	if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("%s: %s mode: %v %v", c.dest, file, st, err)
	}
}

// N7: a "*" pattern line (which ssh would trust for any host) and a line for
// another address are never trusted: the pinned login sees only the node's
// own validated line.
func TestNested_OnlyTheValidatedPinIsTrusted(t *testing.T) {
	s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
		writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.known_hosts"),
			"* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnyHostAnyHost\n"+hostKey("690")+"\n192.0.2.9* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPattern\n"+hostKey("691")+"\n"+hostKey("692")+"\n", 0o600)
	})
	r := runProbe(t, s)
	if r.code != 0 {
		t.Fatalf("exit %d:\n%s", r.code, r.stderr)
	}
	calls := sshCalls(t, r)
	if len(calls) != 2 {
		t.Fatalf("ssh calls: %d", len(calls))
	}
	for _, c := range calls {
		checkOneLineKnownHosts(t, r, c)
	}
}

// N8: after bootstrap, the roster's own record must be the pin bootstrap was
// given, at the configured address, whatever bootstrap reported; otherwise
// the roster goes.
func TestNested_TheRosterRecordIsCompared(t *testing.T) {
	for name, rec := range map[string]string{
		"another pin":     "192.0.2.90 " + ecdsaFP("692"),
		"the ed25519 pin": "192.0.2.90 SHA256:" + strings.Repeat("e", 43),
		"another host":    "192.0.2.99 " + ecdsaFP("690"),
		"no login":        "192.0.2.90 -",
		"no target":       "",
		"cannot be read":  "unreadable",
	} {
		t.Run(name, func(t *testing.T) {
			s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
				setPins(t, home, "pvh-n1", rec)
			})
			r := runProbe(t, s)
			if r.code != 1 || !strings.Contains(r.stdout, "the roster records pvh-n1 as") || !strings.Contains(r.stdout, "refused; the roster is now") {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
			}
			equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:5])
			if _, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); !os.IsNotExist(err) {
				t.Errorf("the roster is still in place: %v", err)
			}
		})
	}
}

// N9: a roster that already holds a node at another address is refused before
// anything is sent; bridge needs both nodes bootstrapped.
func TestNested_AStaleRosterIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		mode, node, rec, want string
	}{
		"another address":         {"bootstrap", "pvh-n1", "192.0.2.99 " + ecdsaFP("690"), "holds pvh-n1 as '192.0.2.99 "},
		"not a pin":               {"bootstrap", "pvh-n1", "192.0.2.90 md5:ab", "holds pvh-n1 as '192.0.2.90 md5:ab'"},
		"a roster it cannot read": {"bootstrap", "pvh-n1", "unreadable", "holds pvh-n1 as 'unreadable'"},
		"bridge, another address": {"bridge", "pvh-n2", "192.0.2.99 " + ecdsaFP("691"), "move it aside"},
		"bridge, pvh-n2 absent":   {"bridge", "pvh-n2", "", "holds no bootstrapped pvh-n2 (absent)"},
		"bridge, pvh-n2 no login": {"bridge", "pvh-n2", "192.0.2.91 -", "holds no bootstrapped pvh-n2"},
	} {
		t.Run(name, func(t *testing.T) {
			s := withSetup(nestedWorld(t, tc.mode), func(t *testing.T, home string) {
				writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.toml"), "# the nested roster\n", 0o600)
				// The roster exists: no read finds it fresh.
				os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n1.1"))
				os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n2.1"))
				setPins(t, home, tc.node, tc.rec)
			})
			r := runProbe(t, s)
			if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Fatalf("exit %d, want 2 and %q:\n%s", r.code, tc.want, r.stderr)
			}
			for _, c := range r.calls {
				if !strings.HasPrefix(c, "pins ") {
					t.Errorf("a refused run ran %q", c)
				}
			}
			if m, _ := filepath.Glob(filepath.Join(r.home, ".config/pveforge/harness-evidence/*")); len(m) != 0 {
				t.Errorf("a refused run opened evidence: %q", m)
			}
		})
	}
}

// PW2 (all three scripts that hold the nested root password): the shell
// options lib.sh refuses are refused before the password is read. allexport,
// from SHELLOPTS in the environment or bash -a, would export the password
// into every program the script runs.
func TestPasswordScripts_RefuseShellOptions(t *testing.T) {
	for _, script := range []string{"prepare-iso", "cluster", "nested"} {
		for name, set := range map[string]func(s *probeSpec){
			"SHELLOPTS=allexport": func(s *probeSpec) { s.env["SHELLOPTS"] = "allexport" },
			"bash -a":             func(s *probeSpec) { s.bashArgs = []string{"-a"} },
			"SHELLOPTS=functrace": func(s *probeSpec) { s.env["SHELLOPTS"] = "functrace" },
			"SHELLOPTS=errtrace":  func(s *probeSpec) { s.env["SHELLOPTS"] = "errtrace" },
			"bash -v":             func(s *probeSpec) { s.bashArgs = []string{"-v"} },
		} {
			t.Run(script+"/"+name, func(t *testing.T) {
				var s probeSpec
				switch script {
				case "cluster":
					s = clusterWorld().spec(t)
				case "nested":
					s = nestedWorld(t, "bootstrap")
				default:
					s = isoWorld(t, nestedPw, nil)
				}
				set(&s)
				r := runProbe(t, s)
				if r.code != 2 || !strings.Contains(r.stderr, "include xtrace, verbose, allexport, functrace or errtrace") {
					t.Fatalf("exit %d, want 2:\n%s", r.code, r.stderr)
				}
				if strings.Contains(r.stdout+r.stderr, nestedPw) {
					t.Error("the password was printed")
				}
				if len(r.calls) != 0 || fakeLog(r, "openssl.argv") != "" || fakeLog(r, "ssh.env") != "" {
					t.Error("a refused run ran something")
				}
			})
		}
	}
}

// N10: a roster that records another pin for a node (one from before
// build.sh --repin) is refused once the node's served key is read, before any
// password; so is a node that does not serve exactly one ECDSA key, the type
// pveforge negotiates.
func TestNested_ThePinBootstrapIsGiven(t *testing.T) {
	t.Run("a pin from before --repin", func(t *testing.T) {
		s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
			writeFile(t, filepath.Join(home, ".config/pveforge/harness-nested.toml"), "# the nested roster\n", 0o600)
			os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n1.1"))
			os.Remove(filepath.Join(filepath.Dir(home), "fake", "pins", "pvh-n2.1"))
			setPins(t, home, "pvh-n2", "192.0.2.91 "+ecdsaFP("692"))
		})
		r := runProbe(t, s)
		if r.code != 1 || !strings.Contains(r.stdout, "records pvh-n2 as '192.0.2.91 "+ecdsaFP("692")+"', but 192.0.2.91 serves "+ecdsaFP("691")) ||
			!strings.Contains(r.stdout, "move it aside and bootstrap again") {
			t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
		}
		want := append(append([]string{}, preflightPins...), nestedBootstrapCalls[1:7]...)
		equalCalls(t, "calls", nestedCalls(r), want)
		if _, err := os.Stat(filepath.Join(r.home, ".config/pveforge/harness-nested.toml")); err != nil {
			t.Errorf("the roster: %v (a refusal before bootstrap leaves it for the operator)", err)
		}
		noPasswordLeaked(t, r, "bootstrap")
	})
	for name, body := range map[string]string{
		"no ECDSA key":        "# 127.0.0.1:22 SSH-2.0-OpenSSH_10.0\n",
		"two ECDSA keys":      "127.0.0.1 " + ecdsaKey("691") + "\n127.0.0.1 " + ecdsaKey("692") + "\n",
		"an ed25519 key":      "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKey691\n",
		"another host's line": "192.0.2.91 " + ecdsaKey("691") + "\n",
	} {
		t.Run("pvh-n2 serves "+name, func(t *testing.T) {
			s := withSetup(nestedWorld(t, "bootstrap"), func(t *testing.T, home string) {
				serveECDSA(t, home, "root@192.0.2.91", body)
			})
			r := runProbe(t, s)
			if r.code != 1 || !strings.Contains(r.stdout, "pvh-n2 serves no single ECDSA host key") || !strings.Contains(r.stdout, "no password was sent") {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stdout)
			}
			equalCalls(t, "calls", nestedCalls(r), nestedBootstrapCalls[:6])
			noPasswordLeaked(t, r, "bootstrap")
		})
	}
}

// N-FP: nested.sh's check of ssh-keygen's output (nested.sh, the SHA256
// form) is all that stands between a fingerprint it could not read and a
// bootstrap whose pin would be empty, a password dial trusting whatever
// answers. Whatever ssh-keygen prints instead, nothing, garbage, an MD5 form,
// a SHA256 one of the wrong length, the node is refused, no bootstrap runs,
// and the password reaches no program.
func TestNested_ABadFingerprintIsRefused(t *testing.T) {
	for name, out := range map[string]string{
		"nothing":           "",
		"a blank line":      "\n",
		"garbage":           "256 not-a-fingerprint 192.0.2.90 (ECDSA)\n",
		"an MD5 form":       "256 MD5:12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0 192.0.2.90 (ECDSA)\n",
		"SHA256, too short": "256 SHA256:" + strings.Repeat("A", 42) + " 192.0.2.90 (ECDSA)\n",
		"SHA256, too long":  "256 SHA256:" + strings.Repeat("A", 44) + " 192.0.2.90 (ECDSA)\n",
		"lower-case sha256": "256 sha256:" + strings.Repeat("A", 43) + " 192.0.2.90 (ECDSA)\n",
		"a failing keygen":  "EXIT1",
	} {
		t.Run(name, func(t *testing.T) {
			s := nestedWorld(t, "bootstrap")
			body := "#!/usr/bin/env bash\nenv >>\"$FAKE_PVEFORGE_DIR/keygen.env\"\ncat >/dev/null\n"
			if out == "EXIT1" {
				body += "exit 1\n"
			} else {
				body += "printf '%s' '" + out + "'\n"
			}
			s.stubs["ssh-keygen"] = strings.ReplaceAll(body, "\\n", "\n")
			r := runProbe(t, s)
			if r.code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", r.code, r.stderr)
			}
			for _, c := range r.calls {
				if strings.HasPrefix(c, "bootstrap ") {
					t.Fatalf("bootstrap ran after ssh-keygen printed %q: %q", out, c)
				}
			}
			res := nestedEvidence(t, r, "bootstrap", "result.txt")
			if !strings.Contains(res, "RED ssh-keygen") || !strings.Contains(res, "pvh-n1") {
				t.Errorf("result.txt:\n%s", res)
			}
			noPasswordLeaked(t, r, "bootstrap")
			if strings.Contains(fakeLog(r, "keygen.env"), nestedPw) {
				t.Error("the password reached ssh-keygen")
			}
		})
	}
}

// N-PASS: the roster passphrase reaches pveforge and the accept tool, each in
// its own environment, and no other program nested.sh runs: not ssh, not
// ssh-keygen, not the pins tool.
func TestNested_ThePassphraseReachesOnlyPveforgeAndAccept(t *testing.T) {
	for _, mode := range []string{"bootstrap", "bridge"} {
		t.Run(mode, func(t *testing.T) {
			r := runProbe(t, nestedWorld(t, mode))
			if r.code != 0 {
				t.Fatalf("exit %d:\n%s", r.code, r.stderr)
			}
			for _, f := range []string{"ssh.env", "keygen.env", "pins.env"} {
				if strings.Contains(fakeLog(r, f), "PVEFORGE_ROSTER_PASSPHRASE") {
					t.Errorf("%s holds the roster passphrase", f)
				}
			}
			if mode == "bootstrap" && fakeLog(r, "keygen.env") == "" {
				t.Error("ssh-keygen's environment was not captured: the check above proves nothing")
			}
			if mode == "bridge" && !strings.Contains(fakeLog(r, "accept.env"), "PVEFORGE_ROSTER_PASSPHRASE=not-a-secret\n") {
				t.Error("the accept tool ran without the roster passphrase")
			}
			n := 0
			for i, c := range r.calls {
				if strings.HasPrefix(c, "ssh ") || strings.HasPrefix(c, "accept ") || strings.HasPrefix(c, "pins ") {
					continue
				}
				n++
				if !strings.Contains(childEnv(t, r, i+1), "PVEFORGE_ROSTER_PASSPHRASE=not-a-secret\n") {
					t.Errorf("pveforge %q ran without the roster passphrase", c)
				}
			}
			if n == 0 {
				t.Error("no pveforge call was checked")
			}
		})
	}
}
