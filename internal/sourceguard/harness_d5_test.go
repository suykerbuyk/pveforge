package sourceguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// The D5 scripts (hack/harness/d5) run offline here: a fake ssh answers each
// root read from a fixture world, U1's fake pveforge answers the token's, and
// every check is shown to pass on a consistent world and to go red, by name,
// when its own piece of that world is wrong. The printed sequence and revert
// are held to the same pinned fixtures the checks read.

const (
	d5Dir      = "../../hack/harness/d5"
	d5Fixtures = "../pve/testdata/permissions"
	d5User     = "pveforge-harness@pve"
	d5Token    = "pveforge-harness@pve!build"
	d5SSHHost  = "ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com "
	// d5SSHArgs is how every root read must be sent, as the fake ssh logs it.
	d5SSHArgs = "-o BatchMode=yes -o ConnectTimeout=15 root@qa-pve-02.lab.quantum.com "
)

var d5V4Paths = []string{"/", "/vms", "/vms/105", "/vms/101", "/vms/600", "/nodes", "/nodes/qa-pve-02", "/storage", "/storage/local-lvm", "/storage/qa-dev-01-image-pool", "/sdn/zones/localnetwork/vmbr0/100", "/access", "/pool"}

type d5Row struct {
	Path      string `json:"path"`
	Propagate int    `json:"propagate"`
	RoleID    string `json:"roleid"`
	UGID      string `json:"ugid"`
}

func d5ReadJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d5Fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func d5Roles(t *testing.T) map[string][]string {
	var r map[string][]string
	d5ReadJSON(t, "d5r3-expected-roles.json", &r)
	return r
}

func d5Rows(t *testing.T) []d5Row {
	var r []d5Row
	d5ReadJSON(t, "d5r3-expected-acl-rows.json", &r)
	return r
}

func d5Tree(t *testing.T, which string) map[string]map[string]int {
	var r map[string]map[string]int
	d5ReadJSON(t, "d5r3-expected-tree-"+which+"-build.json", &r)
	return r
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// d5World is the root side's answers, by remote command.
type d5World map[string]string

// d5WorldAt builds a consistent cluster at a phase: p0 (nothing of the
// harness), roles, owner, granted, token, post. It carries unrelated state a
// pristine-cluster check would trip on: a custom role, a group with an ACL
// row, another pool.
func d5WorldAt(t *testing.T, phase string) d5World {
	t.Helper()
	order := map[string]int{"p0": 0, "roles": 1, "owner": 2, "granted": 3, "token": 4, "post": 5}
	at, ok := order[phase]
	if !ok {
		t.Fatalf("unknown phase %q", phase)
	}
	acl := []map[string]any{
		{"path": "/", "propagate": 1, "roleid": "Administrator", "type": "user", "ugid": "johns@pve"},
		{"path": "/", "propagate": 1, "roleid": "PVEVMAdmin", "type": "token", "ugid": "root@pam!pveforge"},
		{"path": "/vms/105", "propagate": 1, "roleid": "PVEVMUser", "type": "group", "ugid": "ops"},
	}
	roles := []map[string]any{
		{"roleid": "NoAccess", "privs": "", "special": 1},
		{"roleid": "PVEVMAdmin", "privs": "VM.Allocate,VM.Audit", "special": 1},
		{"roleid": "OpsRole", "privs": "VM.Audit", "special": 0},
	}
	users := []map[string]any{{"userid": "root@pam", "enable": 1, "expire": 0}, {"userid": "johns@pve", "enable": 1, "expire": 0}}
	groups := []map[string]any{{"groupid": "ops", "users": "johns@pve"}}
	pools := []map[string]any{{"poolid": "other-pool"}}
	pool := []map[string]any{}
	w := d5World{
		"true": "",
		"pvesh get /nodes/qa-pve-02/storage/pveforge-harness/status --output-format json": `{"active":1,"enabled":1,"type":"zfspool"}`,
		// datacenter.cfg with no user-tag-access set: user-allow defaults to
		// free, and there are no registered tags.
		"pvesh get /cluster/options --output-format json": `{"keyboard":"en-us"}`,
	}
	if at >= 1 {
		for name, privs := range d5Roles(t) {
			roles = append(roles, map[string]any{"roleid": name, "privs": strings.Join(privs, ","), "special": 0})
		}
	}
	if at >= 2 {
		users = append(users, map[string]any{"userid": d5User, "enable": 1, "expire": 0})
		pools = append(pools, map[string]any{"poolid": "pveforge-harness"})
		members := []map[string]any{}
		if at >= 5 {
			for _, v := range []int{690, 691, 692} {
				members = append(members, map[string]any{"id": fmt.Sprintf("qemu/%d", v), "type": "qemu", "vmid": v, "node": "qa-pve-02"})
			}
		}
		pool = append(pool, map[string]any{"poolid": "pveforge-harness", "comment": "pveforge nested harness (D5)", "members": members})
	}
	tree := d5Tree(t, "pre")
	if at >= 5 {
		tree = d5Tree(t, "post")
	}
	for _, r := range d5Rows(t) {
		isToken := r.UGID == d5Token
		if (!isToken && at >= 3) || (isToken && at >= 4) {
			typ := "user"
			if isToken {
				typ = "token"
			}
			acl = append(acl, map[string]any{"path": r.Path, "propagate": r.Propagate, "roleid": r.RoleID, "type": typ, "ugid": r.UGID})
		}
	}
	if at >= 3 {
		w["pveum user permissions "+d5User+" --output-format json"] = mustJSON(tree)
	}
	if at >= 4 {
		w["pveum user token list "+d5User+" --output-format json"] = `[{"tokenid":"build","privsep":1,"expire":0}]`
		w["pveum user token permissions "+d5User+" build --output-format json"] = mustJSON(tree)
		for _, p := range d5V4Paths {
			w["pveum user token permissions "+d5User+" build --path "+p+" --output-format json"] = mustJSON(map[string]any{p: map[string]any{}})
		}
	}
	w["pveum acl list --output-format json"] = mustJSON(acl)
	w["pveum role list --output-format json"] = mustJSON(roles)
	w["pveum user list --output-format json"] = mustJSON(users)
	w["pveum group list --output-format json"] = mustJSON(groups)
	w["pvesh get /pools --output-format json"] = mustJSON(pools)
	w["pvesh get /pools --poolid pveforge-harness --output-format json"] = mustJSON(pool)
	return w
}

// d5Mutate rewrites one answer of the world with a jq program.
func d5Mutate(t *testing.T, w d5World, cmd, prog string) {
	t.Helper()
	in, ok := w[cmd]
	if !ok {
		t.Fatalf("no answer for %q to mutate", cmd)
	}
	c := exec.Command("jq", "-c", prog)
	c.Stdin = strings.NewReader(in)
	out, err := c.Output()
	if err != nil {
		t.Fatalf("jq %s: %v", prog, err)
	}
	w[cmd] = strings.TrimSpace(string(out))
}

// d5Keys generates an ECDSA and an ED25519 host key in dir, for the fake
// ssh-keyscan to serve, and returns each one's fingerprint by type.
func d5Keys(t *testing.T, dir string) map[string]string {
	t.Helper()
	fps := map[string]string{}
	for _, typ := range []string{"ecdsa", "ed25519"} {
		k := filepath.Join(dir, typ)
		if out, err := exec.Command("ssh-keygen", "-q", "-t", typ, "-N", "", "-f", k).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %s: %v %s", typ, err, out)
		}
		out, err := exec.Command("ssh-keygen", "-lf", k+".pub").Output()
		if err != nil {
			t.Fatal(err)
		}
		fps[typ] = strings.Fields(string(out))[1]
	}
	return fps
}

// d5KeyscanLines is what ssh-keyscan prints for the given key types in dir.
func d5KeyscanLines(t *testing.T, dir string, types ...string) string {
	t.Helper()
	var lines []string
	for _, typ := range types {
		b, err := os.ReadFile(filepath.Join(dir, typ+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(string(b))
		lines = append(lines, "qa-pve-02.lab.quantum.com "+f[0]+" "+f[1])
	}
	return strings.Join(lines, "\n") + "\n"
}

// d5PinRoster is a roster whose qa-pve-02 target pins pin; qa-pve-01, first,
// pins something else, and a token id sits between, so the parse must follow
// the tables.
func d5PinRoster(pin string) string {
	return `[[targets]]
id = "qa-pve-01"
host = "qa-pve-01.lab.quantum.com"
node = "qa-pve-01"

  [targets.ssh]
  host_key_fingerprint = "SHA256:not-the-one-for-qa-pve-02"

[[targets]]
id = "qa-pve-02"
host = "qa-pve-02.lab.quantum.com"
node = "qa-pve-02"

  [targets.token]
  id = "root@pam!pveforge"

  [targets.ssh]
  user = "root"
  host_key_fingerprint = "` + pin + `"
`
}

type d5Case struct {
	name, script, phase string
	world               d5World           // root side
	token               map[string]string // token side (fake pveforge), by key
	tokenRC             map[string]int
	sshRC               map[string]int
	keyscanTypes        []string // the host keys the fake serves; nil = both
	pin                 string   // "" = the ECDSA key's fingerprint
	noPinRoster         bool
	noP0, p0Exists      bool
	evidenceExists      bool
	noEvidenceVar       bool

	wantCode int
	wantPass int      // exact PASS count; -1 = not checked
	wantRed  []string // exact set of RED check names (their first word)
	wantErr  string
}

type d5Result struct {
	code             int
	stderr, result   string
	pass             int
	red              []string
	sshLog, evidence string
	p0Dir            string
}

func d5PATH(t *testing.T, fakeBin string) string {
	t.Helper()
	seen := map[string]bool{fakeBin: true}
	dirs := []string{fakeBin}
	for _, tool := range []string{"bash", "jq", "flock", "stat", "sha256sum", "tr", "cat", "awk", "tee", "mkdir", "install", "dirname", "ssh-keygen"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s is required to test the D5 scripts: %v", tool, err)
		}
		if d := filepath.Dir(p); !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	return strings.Join(dirs, ":")
}

func runD5(t *testing.T, c d5Case) d5Result {
	t.Helper()
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fps := d5Keys(t, keyDir)
	home := filepath.Join(tmp, "home")
	cfg := filepath.Join(home, ".config", "pveforge")
	sshDir := filepath.Join(tmp, "ssh")
	pveDir := filepath.Join(tmp, "pve")
	bin := filepath.Join(tmp, "bin")
	for _, d := range []string{cfg, filepath.Join(sshDir, "resp"), filepath.Join(sshDir, "rc"), filepath.Join(pveDir, "resp"), filepath.Join(pveDir, "rc"), bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"ssh": "fake-ssh.sh", "ssh-keyscan": "fake-ssh-keyscan.sh"} {
		if err := os.Symlink(abs(filepath.Join(harnessDir, "test", target)), filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	for cmd, ans := range c.world {
		write(filepath.Join(sshDir, "resp", fakeKey(cmd)), ans+"\n", 0o600)
	}
	for cmd, rc := range c.sshRC {
		write(filepath.Join(sshDir, "rc", fakeKey(cmd)), fmt.Sprint(rc), 0o600)
	}
	types := c.keyscanTypes
	if types == nil {
		types = []string{"ecdsa", "ed25519"}
	}
	write(filepath.Join(sshDir, "keyscan.txt"), d5KeyscanLines(t, keyDir, types...), 0o600)
	for k, v := range c.token {
		write(filepath.Join(pveDir, "resp", fakeKey(k)), v+"\n", 0o600)
	}
	for k, v := range c.tokenRC {
		write(filepath.Join(pveDir, "rc", fakeKey(k)), fmt.Sprint(v), 0o600)
	}
	pin := c.pin
	switch pin {
	case "":
		pin = fps["ecdsa"]
	case "-": // the qa-pve-02 target pins nothing
		pin = ""
	}
	pinRoster := filepath.Join(tmp, "pveforge.toml")
	if !c.noPinRoster {
		write(pinRoster, d5PinRoster(pin), 0o600)
	}
	write(filepath.Join(cfg, "harness-outer.toml"), "# test roster\n", 0o600)
	p0 := filepath.Join(cfg, "harness-outer.p0")
	if (c.phase != "p0" && !c.noP0) || c.p0Exists {
		if err := os.Mkdir(p0, 0o700); err != nil {
			t.Fatal(err)
		}
		base := d5WorldAt(t, "p0")
		for f, cmd := range map[string]string{"acl": "pveum acl list --output-format json", "roles": "pveum role list --output-format json", "users": "pveum user list --output-format json", "groups": "pveum group list --output-format json", "pools": "pvesh get /pools --output-format json"} {
			write(filepath.Join(p0, f+".json"), base[cmd]+"\n", 0o600)
		}
	}
	evidence := filepath.Join(tmp, "evidence", "run")
	if c.evidenceExists {
		if err := os.MkdirAll(evidence, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{
		"PATH=" + d5PATH(t, bin), "HOME=" + home,
		"FAKE_SSH_DIR=" + sshDir, "FAKE_PVEFORGE_DIR=" + pveDir,
		"PVEFORGE_BIN=" + abs(filepath.Join(harnessDir, "test", "fake-pveforge.sh")),
		"PVEFORGE_ROSTER_PASSPHRASE=not-a-secret", "D5_PIN_ROSTER=" + pinRoster,
	}
	if !c.noEvidenceVar {
		env = append(env, "HARNESS_EVIDENCE="+evidence)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", abs(filepath.Join(d5Dir, c.script)), c.phase)
	cmd.Dir = tmp
	cmd.Env = env
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	cmd.Stdout = &errOut
	err := cmd.Run()
	r := d5Result{stderr: errOut.String(), evidence: evidence, p0Dir: p0}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		t.Fatalf("run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(evidence, "result.txt")); err == nil {
		r.result = string(b)
		for _, l := range strings.Split(r.result, "\n") {
			switch {
			case strings.HasPrefix(l, "PASS "):
				r.pass++
			case strings.HasPrefix(l, "RED "):
				r.red = append(r.red, strings.Fields(l)[1])
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(sshDir, "ssh.log")); err == nil {
		r.sshLog = string(b)
	}
	return r
}

func checkD5(t *testing.T, c d5Case, r d5Result) {
	t.Helper()
	if r.code != c.wantCode {
		t.Errorf("exit %d, want %d\noutput:\n%s", r.code, c.wantCode, r.stderr)
	}
	if c.wantPass >= 0 && r.pass != c.wantPass {
		t.Errorf("%d PASS lines, want %d:\n%s", r.pass, c.wantPass, r.result)
	}
	sort.Strings(r.red)
	want := append([]string(nil), c.wantRed...)
	sort.Strings(want)
	if strings.Join(r.red, " ") != strings.Join(want, " ") {
		t.Errorf("RED checks %v, want %v:\n%s", r.red, want, r.result)
	}
	if c.wantErr != "" && !strings.Contains(r.stderr, c.wantErr) {
		t.Errorf("output does not contain %q:\n%s", c.wantErr, r.stderr)
	}
}

// Green runs: each phase passes every one of its checks on a consistent
// world, and the number of checks is pinned, so a deleted check shows.
func d5GreenCases(t *testing.T) []d5Case {
	tokenWorld := d5TokenWorld(t, "pre")
	return []d5Case{
		{name: "p0", script: "verify-root.sh", phase: "p0", world: d5WorldAt(t, "p0"), wantPass: 16},
		{name: "p0, user-allow list naming the tag", script: "verify-root.sh", phase: "p0", world: d5WithOptions(t, `{"user-tag-access":{"user-allow":"list","user-allow-list":["other","pveforge-harness"]}}`), wantPass: 16},
		{name: "roles", script: "verify-root.sh", phase: "roles", world: d5WorldAt(t, "roles"), wantPass: 4},
		{name: "owner", script: "verify-root.sh", phase: "owner", world: d5WorldAt(t, "owner"), wantPass: 6},
		{name: "granted", script: "verify-root.sh", phase: "granted", world: d5WorldAt(t, "granted"), wantPass: 6},
		{name: "token", script: "verify-root.sh", phase: "token", world: d5WorldAt(t, "token"), wantPass: 7 + 9 + 2*len(d5V4Paths) + 1},
		{name: "pre", script: "verify-root.sh", phase: "pre", world: d5WorldAt(t, "token"), wantPass: 7 + 8 + 2*len(d5V4Paths) + 1},
		{name: "post", script: "verify-root.sh", phase: "post", world: d5WorldAt(t, "post"), wantPass: 7 + 8 + 2*len(d5V4Paths) + 1},
		{name: "reverted", script: "verify-root.sh", phase: "reverted", world: d5WorldAt(t, "p0"), wantPass: 14},
		{name: "token pre", script: "verify-token.sh", phase: "pre", token: tokenWorld, wantPass: 2 + 2*4 + 2 + 3 + 2},
		{name: "token post", script: "verify-token.sh", phase: "post", token: d5TokenWorld(t, "post"), wantPass: 2 + 2*4 + 2 + 3 + 2},
	}
}

// d5WithOptions is the p0 world with the given /cluster/options answer.
func d5WithOptions(t *testing.T, options string) d5World {
	w := d5WorldAt(t, "p0")
	w["pvesh get /cluster/options --output-format json"] = options
	return w
}

// d5TokenWorld is the token side's answers, keyed like the fake pveforge.
func d5TokenWorld(t *testing.T, phase string) map[string]string {
	t.Helper()
	tree := d5Tree(t, "pre")
	members := []map[string]any{}
	if phase == "post" {
		tree = d5Tree(t, "post")
		for _, v := range []int{690, 691, 692} {
			members = append(members, map[string]any{"type": "qemu", "vmid": v, "node": "qa-pve-02"})
		}
	}
	w := map[string]string{
		"get /access/permissions":                         mustJSON(tree),
		"get /access/acl":                                 "[]",
		"get /pools poolid=pveforge-harness":              mustJSON([]map[string]any{{"poolid": "pveforge-harness", "members": members}}),
		"get /access/permissions path=/storage/local-lvm": `{"/storage/local-lvm":{}}`,
	}
	for name, privs := range d5Roles(t) {
		m := map[string]int{}
		for _, p := range privs {
			m[p] = 1
		}
		w["get /access/roles/"+name] = mustJSON(m)
	}
	return w
}

func TestD5Verify_Green(t *testing.T) {
	cases := d5GreenCases(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runD5(t, c)
			checkD5(t, c, r)
			// Every root read goes out non-interactive, key-based: S0's whole
			// purpose is lost if one call drops BatchMode.
			for _, l := range strings.Split(strings.TrimSpace(r.sshLog), "\n") {
				if l != "" && !strings.HasPrefix(l, d5SSHArgs) {
					t.Errorf("an ssh call without BatchMode or the pinned host: %q", l)
				}
			}
			if !strings.Contains(r.result, "RESULT phase=") {
				t.Errorf("no RESULT line:\n%s", r.result)
			}
			if st, err := os.Stat(r.evidence); err != nil || st.Mode().Perm() != 0o700 {
				t.Errorf("evidence directory: %v %v, want mode 700", st, err)
			}
			if _, err := os.Stat(filepath.Join(r.evidence, "MANIFEST.sha256")); err != nil {
				t.Errorf("no MANIFEST.sha256: %v", err)
			}
			if c.phase == "p0" {
				// G4 copies the pin K1 verified, exactly.
				pin, err := os.ReadFile(filepath.Join(r.evidence, "pin.txt"))
				want := "PIN host_key_fingerprint=" + strings.TrimSpace(string(pin)) + " (verified by K1; G4 passes it as --host-key-fingerprint)\n"
				if err != nil || len(pin) < len("SHA256:") || !strings.Contains(r.result, want) {
					t.Errorf("K1's pin is not printed for G4 (%v): want %q in\n%s", err, want, r.result)
				}
				for _, f := range []string{"acl", "roles", "users", "groups", "pools"} {
					if _, err := os.Stat(filepath.Join(r.p0Dir, f+".json")); err != nil {
						t.Errorf("P0 baseline %s not written: %v", f, err)
					}
				}
				if !strings.Contains(r.result, "pinned key type: (ECDSA)") && !strings.Contains(r.stderr, "(ECDSA)") {
					t.Logf("result:\n%s", r.result)
				}
				if first := strings.SplitN(r.sshLog, "\n", 2)[0]; first != d5SSHArgs+"true" {
					t.Errorf("the first ssh call was %q; the BatchMode check must come first", first)
				}
			}
		})
	}
}

// Red runs: each check goes red, alone, when its piece of the world is wrong.
func TestD5Verify_EachCheckGoesRed(t *testing.T) {
	type red struct {
		name, script, phase, worldAt string
		mutate                       map[string]string // command -> jq program
		token                        map[string]string // token-side overrides
		tokenRC                      map[string]int
		sshRC                        map[string]int
		keyscanTypes                 []string
		pin                          string
		want                         []string
	}
	const (
		acl     = "pveum acl list --output-format json"
		roles   = "pveum role list --output-format json"
		users   = "pveum user list --output-format json"
		groups  = "pveum group list --output-format json"
		pools   = "pvesh get /pools --output-format json"
		pool    = "pvesh get /pools --poolid pveforge-harness --output-format json"
		store   = "pvesh get /nodes/qa-pve-02/storage/pveforge-harness/status --output-format json"
		options = "pvesh get /cluster/options --output-format json"
		tokens  = "pveum user token list " + d5User + " --output-format json"
		ttree   = "pveum user token permissions " + d5User + " build --output-format json"
		utree   = "pveum user permissions " + d5User + " --output-format json"
	)
	v4 := func(p string) string {
		return "pveum user token permissions " + d5User + " build --path " + p + " --output-format json"
	}
	userRow := `{"path":"/pool/pveforge-harness","propagate":0,"roleid":"ForgeHarness","type":"user","ugid":"pveforge-harness@pve"}`
	reds := []red{
		{name: "P1 a harness role exists", phase: "p0", worldAt: "p0", mutate: map[string]string{roles: `. + [{"roleid":"ForgeHarnessX","privs":"","special":0}]`}, want: []string{"P1"}},
		{name: "P2 the pool exists", phase: "p0", worldAt: "p0", mutate: map[string]string{pools: `. + [{"poolid":"pveforge-harness"}]`}, want: []string{"P2"}},
		{name: "P3 the user exists", phase: "p0", worldAt: "p0", mutate: map[string]string{users: `. + [{"userid":"pveforge-harness@pve","enable":1,"expire":0}]`}, want: []string{"P3"}},
		{name: "P4 a row for the user exists", phase: "p0", worldAt: "p0", mutate: map[string]string{acl: `. + [` + userRow + `]`}, want: []string{"P4"}},
		{name: "P5 storage inactive", phase: "p0", worldAt: "p0", mutate: map[string]string{store: `.active = 0`}, want: []string{"P5"}},
		{name: "P6 the tag is registered (privileged)", phase: "p0", worldAt: "p0", mutate: map[string]string{options: `. + {"registered-tags":["pveforge-harness"]}`}, want: []string{"P6"}},
		{name: "P6 user-allow none", phase: "p0", worldAt: "p0", mutate: map[string]string{options: `. + {"user-tag-access":{"user-allow":"none","user-allow-list":["pveforge-harness"]}}`}, want: []string{"P6"}},
		{name: "P6 user-allow list without the tag", phase: "p0", worldAt: "p0", mutate: map[string]string{options: `. + {"user-tag-access":{"user-allow":"list","user-allow-list":["other"]}}`}, want: []string{"P6"}},
		{name: "P6 user-allow existing", phase: "p0", worldAt: "p0", mutate: map[string]string{options: `. + {"user-tag-access":{"user-allow":"existing"}}`}, want: []string{"P6"}},
		{name: "K1 the pinned key is not served", phase: "p0", worldAt: "p0", keyscanTypes: []string{"ed25519"}, want: []string{"K1"}},
		{name: "K1 pin is another key", phase: "p0", worldAt: "p0", pin: "SHA256:someone-else", want: []string{"K1"}},
		{name: "V0 a harness role widened", phase: "roles", worldAt: "roles", mutate: map[string]string{roles: `map(if .roleid == "ForgeHarnessIso" then .privs = "Datastore.Audit,Datastore.AllocateTemplate" else . end)`}, want: []string{"V0"}},
		{name: "V0b another custom role changed", phase: "roles", worldAt: "roles", mutate: map[string]string{roles: `map(if .roleid == "OpsRole" then .privs = "VM.Audit,VM.Allocate" else . end)`}, want: []string{"V0b"}},
		{name: "L1b a harness role marked special", phase: "roles", worldAt: "roles", mutate: map[string]string{roles: `map(if .roleid == "ForgeHarnessNet" then .special = 1 else . end)`}, want: []string{"L1b"}},
		{name: "L1b privs as an array", phase: "roles", worldAt: "roles", mutate: map[string]string{roles: `map(if .roleid == "ForgeHarnessNet" then .privs = ["SDN.Use"] else . end)`}, want: []string{"V0", "L1b"}},
		{name: "O1 the pool has a member", phase: "owner", worldAt: "owner", mutate: map[string]string{pool: `.[0].members = [{"type":"qemu","vmid":105,"node":"qa-pve-02"}]`}, want: []string{"O1"}},
		{name: "O2 the user expires", phase: "owner", worldAt: "owner", mutate: map[string]string{users: `map(if .userid == "pveforge-harness@pve" then .expire = 1893456000 else . end)`}, want: []string{"O2"}},
		{name: "O1 two pools answered", phase: "owner", worldAt: "owner", mutate: map[string]string{pool: `. + [{"poolid":"pveforge-harness","members":[]}]`}, want: []string{"O1"}},
		{name: "O1 another pool answered", phase: "owner", worldAt: "owner", mutate: map[string]string{pool: `map(.poolid = "other-pool")`}, want: []string{"O1"}},
		{name: "O2 the user disabled", phase: "owner", worldAt: "owner", mutate: map[string]string{users: `map(if .userid == "pveforge-harness@pve" then .enable = 0 else . end)`}, want: []string{"O2"}},
		{name: "O3 the user already holds a row", phase: "owner", worldAt: "owner", mutate: map[string]string{acl: `. + [` + userRow + `]`}, want: []string{"O3"}},
		{name: "V1u a user row propagates", phase: "granted", worldAt: "granted", mutate: map[string]string{acl: `map(if .ugid == "pveforge-harness@pve" and .path == "/storage/local" then .propagate = 1 else . end)`}, want: []string{"V1u"}},
		{name: "V1b a foreign row added (granted)", phase: "granted", worldAt: "granted", mutate: map[string]string{acl: `. + [{"path":"/nodes","propagate":1,"roleid":"PVEAuditor","type":"user","ugid":"johns@pve"}]`}, want: []string{"V1b"}},
		{name: "V1c a foreign row on a harness VM", phase: "granted", worldAt: "granted", mutate: map[string]string{acl: `. + [{"path":"/vms/695","propagate":0,"roleid":"PVEVMUser","type":"user","ugid":"johns@pve"}]`}, want: []string{"V1b", "V1c"}},
		{name: "V5 the user's tree widened (granted)", phase: "granted", worldAt: "granted", mutate: map[string]string{utree: `. + {"/":{"Sys.Audit":0}}`}, want: []string{"V5"}},
		{name: "V1 a token row missing", phase: "token", worldAt: "token", mutate: map[string]string{acl: `map(select(.ugid != "pveforge-harness@pve!build" or .path != "/storage/local"))`}, want: []string{"V1"}},
		{name: "V1b a foreign row added (token)", phase: "token", worldAt: "token", mutate: map[string]string{acl: `. + [{"path":"/nodes","propagate":1,"roleid":"PVEAuditor","type":"user","ugid":"johns@pve"}]`}, want: []string{"V1b"}},
		{name: "V1c a foreign row on the pool", phase: "pre", worldAt: "token", mutate: map[string]string{acl: `. + [{"path":"/pool/pveforge-harness","propagate":0,"roleid":"PVEVMUser","type":"group","ugid":"ops"}]`}, want: []string{"V1c"}},
		{name: "V2 the token without privsep", phase: "token", worldAt: "token", mutate: map[string]string{tokens: `map(.privsep = 0)`}, want: []string{"V2"}},
		{name: "V2b the owner joined a group", phase: "token", worldAt: "token", mutate: map[string]string{groups: `map(.users += ",pveforge-harness@pve")`}, want: []string{"V2b"}},
		{name: "V3 the token's tree widened", phase: "token", worldAt: "token", mutate: map[string]string{ttree: `. + {"/":{"Sys.Audit":0}}`}, want: []string{"V3"}},
		{name: "V5 the user's tree widened (token)", phase: "token", worldAt: "token", mutate: map[string]string{utree: `.["/storage/local"] += {"Datastore.AllocateTemplate":0}`}, want: []string{"V5"}},
		{name: "V4 the token holds something at /", phase: "token", worldAt: "token", mutate: map[string]string{v4("/"): `{"/":{"VM.Audit":1}}`}, want: []string{"V4"}},
		{name: "V4 a bare {} answer", phase: "token", worldAt: "token", mutate: map[string]string{v4("/storage/local-lvm"): `{}`}, want: []string{"V4"}},
		{name: "V7 two pools answered", phase: "pre", worldAt: "token", mutate: map[string]string{pool: `. + [{"poolid":"pveforge-harness","members":[]}]`}, want: []string{"V7"}},
		{name: "V7 another pool answered", phase: "pre", worldAt: "token", mutate: map[string]string{pool: `map(.poolid = "other-pool")`}, want: []string{"V7"}},
		{name: "V4 an extra path in the answer", phase: "token", worldAt: "token", mutate: map[string]string{v4("/"): `{"/":{},"/vms":{}}`}, want: []string{"V4"}},
		{name: "V7 a foreign member", phase: "pre", worldAt: "token", mutate: map[string]string{pool: `.[0].members = [{"type":"qemu","vmid":105,"node":"qa-pve-02"}]`}, want: []string{"V7"}},
		{name: "V7 a storage member", phase: "post", worldAt: "post", mutate: map[string]string{pool: `.[0].members += [{"type":"storage","storage":"local"}]`}, want: []string{"V7"}},
		{name: "V7 a member missing (post)", phase: "post", worldAt: "post", mutate: map[string]string{pool: `.[0].members |= map(select(.vmid != 691))`}, want: []string{"V7"}},
		{name: "RV1 an ACL row left", phase: "reverted", worldAt: "p0", mutate: map[string]string{acl: `. + [{"path":"/nodes","propagate":1,"roleid":"PVEAuditor","type":"user","ugid":"johns@pve"}]`}, want: []string{"RV1"}},
		{name: "RV2 a custom role left", phase: "reverted", worldAt: "p0", mutate: map[string]string{roles: `. + [{"roleid":"Leftover","privs":"VM.Audit","special":0}]`}, want: []string{"RV2"}},
		{name: "RV3 a user left", phase: "reverted", worldAt: "p0", mutate: map[string]string{users: `. + [{"userid":"left@pve","enable":1,"expire":0}]`}, want: []string{"RV3"}},
		{name: "RV4 a group left", phase: "reverted", worldAt: "p0", mutate: map[string]string{groups: `. + [{"groupid":"left","users":""}]`}, want: []string{"RV4"}},
		{name: "RV5 a pool left", phase: "reverted", worldAt: "p0", mutate: map[string]string{pools: `. + [{"poolid":"left"}]`}, want: []string{"RV5"}},
		{name: "RV P4 a harness row left", phase: "reverted", worldAt: "p0", mutate: map[string]string{acl: `. + [` + userRow + `]`}, want: []string{"P4", "RV1"}},
		{name: "V3t the token's tree", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /access/permissions": `{"/":{"Sys.Audit":0}}`}, want: []string{"V3t"}},
		{name: "V0t a role widened", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /access/roles/ForgeHarnessNet": `{"SDN.Use":1,"SDN.Audit":1}`}, want: []string{"V0t"}},
		{name: "V1t the token sees a row", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /access/acl": `[{"path":"/vms/690","ugid":"x@pve","roleid":"PVEVMUser"}]`}, want: []string{"V1t"}},
		{name: "V7t a foreign member", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /pools poolid=pveforge-harness": `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":105,"node":"qa-pve-02"}]}]`}, want: []string{"V7t"}},
		{name: "V7t-node a member elsewhere", script: "verify-token.sh", phase: "post", token: map[string]string{"get /pools poolid=pveforge-harness": `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-01"},{"type":"qemu","vmid":691,"node":"qa-pve-02"},{"type":"qemu","vmid":692,"node":"qa-pve-02"}]}]`}, want: []string{"V7t-node"}},
		{name: "V7t a storage member", script: "verify-token.sh", phase: "post", token: map[string]string{"get /pools poolid=pveforge-harness": `[{"poolid":"pveforge-harness","members":[{"type":"qemu","vmid":690,"node":"qa-pve-02"},{"type":"qemu","vmid":691,"node":"qa-pve-02"},{"type":"qemu","vmid":692,"node":"qa-pve-02"},{"type":"storage","storage":"local","node":"qa-pve-02"}]}]`}, want: []string{"V7t"}},
		{name: "K1 no pin for qa-pve-02", phase: "p0", worldAt: "p0", pin: "-", want: []string{"K1"}},
		{name: "Z0 an extra path in the answer", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /access/permissions path=/storage/local-lvm": `{"/storage/local-lvm":{},"/x":{}}`}, want: []string{"Z0"}},
		{name: "Z0 a bare {} for a path held nothing on", script: "verify-token.sh", phase: "pre", token: map[string]string{"get /access/permissions path=/storage/local-lvm": `{}`}, want: []string{"Z0"}},
		{name: "a failed token read is red, and so is its check", script: "verify-token.sh", phase: "pre", tokenRC: map[string]int{"get /access/acl": 1}, want: []string{"fetch", "V1t"}},
		{name: "a failed root read is red, and so are its checks", phase: "token", worldAt: "token", sshRC: map[string]int{tokens: 1}, want: []string{"fetch", "V2"}},
	}
	for _, rc := range reds {
		t.Run(rc.name, func(t *testing.T) {
			c := d5Case{name: rc.name, script: rc.script, phase: rc.phase, wantCode: 1, wantPass: -1, wantRed: rc.want, pin: rc.pin, tokenRC: rc.tokenRC, sshRC: rc.sshRC}
			if c.script == "" {
				c.script = "verify-root.sh"
			}
			if c.script == "verify-token.sh" {
				c.token = d5TokenWorld(t, rc.phase)
				for k, v := range rc.token {
					c.token[k] = v
				}
			} else {
				c.world = d5WorldAt(t, rc.worldAt)
				for cmd, prog := range rc.mutate {
					d5Mutate(t, c.world, cmd, prog)
				}
			}
			c.keyscanTypes = rc.keyscanTypes
			r := runD5(t, c)
			checkD5(t, c, r)
			if rc.phase == "p0" {
				if _, err := os.Stat(r.p0Dir); err == nil {
					t.Error("a red p0 wrote the P0 baseline")
				}
				// A pin K1 did not verify is never offered to G4.
				if slices.Contains(rc.want, "K1") && strings.Contains(r.result, "PIN host_key_fingerprint=") {
					t.Errorf("K1 is red, yet the pin was printed for G4:\n%s", r.result)
				}
			}
		})
	}
}

// Usage errors and the one fatal check: nothing is read, or nothing past it.
func TestD5Verify_RefusalsAndTheBatchModeGate(t *testing.T) {
	cases := []struct {
		c       d5Case
		wantLog string // exact ssh log; "-" = not checked
	}{
		{c: d5Case{name: "root ssh not key-based", script: "verify-root.sh", phase: "p0", world: d5WorldAt(t, "p0"), sshRC: map[string]int{"true": 255}, wantCode: 1, wantPass: 0, wantRed: []string{"S0"}, wantErr: "need non-interactive, key-based root ssh"}, wantLog: d5SSHArgs + "true\n"},
		{c: d5Case{name: "no HARNESS_EVIDENCE", script: "verify-root.sh", phase: "p0", world: d5WorldAt(t, "p0"), noEvidenceVar: true, wantCode: 2, wantPass: 0, wantErr: "HARNESS_EVIDENCE must name a new directory"}, wantLog: ""},
		{c: d5Case{name: "evidence directory exists", script: "verify-root.sh", phase: "roles", world: d5WorldAt(t, "roles"), evidenceExists: true, wantCode: 2, wantPass: 0, wantErr: "evidence is never overwritten"}, wantLog: ""},
		{c: d5Case{name: "unknown phase", script: "verify-root.sh", phase: "t0", world: d5WorldAt(t, "p0"), wantCode: 2, wantPass: 0, wantErr: "usage"}, wantLog: ""},
		{c: d5Case{name: "p0 when P0 exists", script: "verify-root.sh", phase: "p0", world: d5WorldAt(t, "p0"), p0Exists: true, wantCode: 2, wantPass: 0, wantErr: "never overwritten"}, wantLog: ""},
		{c: d5Case{name: "p0 without a pin roster", script: "verify-root.sh", phase: "p0", world: d5WorldAt(t, "p0"), noPinRoster: true, wantCode: 2, wantPass: 0, wantErr: "D5_PIN_ROSTER"}, wantLog: ""},
		{c: d5Case{name: "a later phase without P0", script: "verify-root.sh", phase: "granted", world: d5WorldAt(t, "granted"), noP0: true, wantCode: 2, wantPass: 0, wantErr: "run phase p0 first"}, wantLog: ""},
		{c: d5Case{name: "token side unknown phase", script: "verify-token.sh", phase: "token", wantCode: 2, wantPass: 0, wantErr: "usage"}, wantLog: "-"},
	}
	for _, tc := range cases {
		t.Run(tc.c.name, func(t *testing.T) {
			r := runD5(t, tc.c)
			checkD5(t, tc.c, r)
			if tc.wantLog != "-" && r.sshLog != tc.wantLog {
				t.Errorf("ssh log %q, want %q", r.sshLog, tc.wantLog)
			}
		})
	}
}

// The pre-build tree is the post-build tree without the three members.
func TestD5Fixtures_PreBuildIsPostBuildWithoutMembers(t *testing.T) {
	pre, post := d5Tree(t, "pre"), d5Tree(t, "post")
	for _, m := range []string{"/vms/690", "/vms/691", "/vms/692"} {
		if _, ok := post[m]; !ok {
			t.Fatalf("post-build tree lacks %s", m)
		}
		delete(post, m)
	}
	if mustJSON(pre) != mustJSON(post) {
		t.Errorf("pre-build tree\n%s\n!= post-build tree without members\n%s", mustJSON(pre), mustJSON(post))
	}
}

// d5Commands returns the ssh-wrapped remote commands in a printed file's code
// blocks, and every other code line.
func d5Commands(t *testing.T, file string) (remote, local []string, text string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d5Dir, file))
	if err != nil {
		t.Fatal(err)
	}
	text = string(b)
	in := false
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "```") {
			in = !in
			continue
		}
		if !in || strings.TrimSpace(l) == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(l, d5SSHHost); ok {
			if len(rest) < 2 || (rest[0] != '\'' && rest[0] != '"') || rest[len(rest)-1] != rest[0] {
				t.Fatalf("%s: remote command not quoted as one argument: %s", file, l)
			}
			// An interactive bash or zsh history-expands ! even inside double
			// quotes; only single quotes protect it.
			if rest[0] == '"' && strings.Contains(rest, "!") {
				t.Errorf("%s: a ! inside a double-quoted remote command is history-expanded by an interactive shell: %s", file, l)
			}
			remote = append(remote, rest[1:len(rest)-1])
			continue
		}
		local = append(local, l)
	}
	return remote, local, text
}

// The printed sequence and revert say exactly what the checks expect: the
// same four roles and privileges, the same eight rows, the same grants, the
// revert undoing each in a safe order, and step 11 left to the operator.
func TestD5Sequence_MatchesTheFixtures(t *testing.T) {
	roles, rows := d5Roles(t), d5Rows(t)
	remote, local, text := d5Commands(t, "sequence.md")

	roleAdd := regexp.MustCompile(`^pveum role add (\S+) --privs "([^"]*)"$`)
	aclMod := regexp.MustCompile(`^pveum acl modify (\S+) --users (\S+) --roles (\S+) --propagate ([01])$`)
	gotRoles := map[string][]string{}
	var gotRows []d5Row
	var other []string
	for _, c := range remote {
		if m := roleAdd.FindStringSubmatch(c); m != nil {
			privs := strings.Split(m[2], ",")
			sort.Strings(privs)
			gotRoles[m[1]] = privs
			continue
		}
		if m := aclMod.FindStringSubmatch(c); m != nil {
			p := 0
			if m[4] == "1" {
				p = 1
			}
			gotRows = append(gotRows, d5Row{Path: m[1], UGID: m[2], RoleID: m[3], Propagate: p})
			continue
		}
		other = append(other, c)
	}
	wantRoles := map[string][]string{}
	for k, v := range roles {
		s := append([]string(nil), v...)
		sort.Strings(s)
		wantRoles[k] = s
	}
	if mustJSON(gotRoles) != mustJSON(wantRoles) {
		t.Errorf("role add lines give %s\nwant %s", mustJSON(gotRoles), mustJSON(wantRoles))
	}
	var wantUserRows []d5Row
	for _, r := range rows {
		if r.UGID == d5User {
			wantUserRows = append(wantUserRows, r)
		}
	}
	sortRows := func(rs []d5Row) {
		sort.Slice(rs, func(i, j int) bool { return rs[i].Path+rs[i].UGID < rs[j].Path+rs[j].UGID })
	}
	sortRows(gotRows)
	sortRows(wantUserRows)
	if mustJSON(gotRows) != mustJSON(wantUserRows) {
		t.Errorf("acl modify lines give %s\nwant %s", mustJSON(gotRows), mustJSON(wantUserRows))
	}
	wantOther := []string{
		`pveum pool add pveforge-harness --comment "pveforge nested harness (D5)"`,
		`pveum user add pveforge-harness@pve --enable 1 --expire 0 --comment "pveforge harness token owner; no password"`,
	}
	if strings.Join(other, "\n") != strings.Join(wantOther, "\n") {
		t.Errorf("other root writes:\n%s\nwant:\n%s", strings.Join(other, "\n"), strings.Join(wantOther, "\n"))
	}

	// Step 11's grants: one per user row, each pinned to its role's privileges.
	var boot string
	for _, l := range local {
		if strings.HasPrefix(l, "pveforge bootstrap ") {
			if boot != "" {
				t.Fatal("more than one bootstrap line")
			}
			boot = l
		}
	}
	if boot == "" {
		t.Fatal("no bootstrap line")
	}
	if !strings.HasSuffix(boot, ` -o json > "$E/g4-bootstrap.json"`) {
		t.Errorf("the bootstrap line does not end with a quoted evidence redirect: %s", boot)
	}
	if !strings.Contains(text, `echo "E=$E"`) {
		t.Error("G0 does not print the evidence path for the operator's G4 terminal")
	}
	for _, flag := range []string{"bootstrap qa-pve-02-harness ", "--roster ~/.config/pveforge/harness-outer.toml ", "--node qa-pve-02 ", "--no-ssh-key ", `--host-key-fingerprint "$PIN" `, "--token-owner pveforge-harness@pve ", "--token-id build ", "-o json "} {
		if !strings.Contains(boot, flag) {
			t.Errorf("bootstrap line lacks %q", flag)
		}
	}
	grant := regexp.MustCompile(`--grant '([^:']+):([^:']+):([^:']*):([01])'`)
	var gotGrants []d5Row
	for _, m := range grant.FindAllStringSubmatch(boot, -1) {
		privs := strings.Split(m[3], ",")
		sort.Strings(privs)
		if mustJSON(privs) != mustJSON(wantRoles[m[2]]) {
			t.Errorf("grant on %s pins %v, want role %s's %v", m[1], privs, m[2], wantRoles[m[2]])
		}
		p := 0
		if m[4] == "1" {
			p = 1
		}
		gotGrants = append(gotGrants, d5Row{Path: m[1], RoleID: m[2], UGID: d5User, Propagate: p})
	}
	sortRows(gotGrants)
	if mustJSON(gotGrants) != mustJSON(wantUserRows) {
		t.Errorf("grants give %s\nwant (as the token's rows) %s", mustJSON(gotGrants), mustJSON(wantUserRows))
	}

	// The gates, in order, with step 11 left to the operator and root ssh
	// checked first.
	var gates []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "## G") {
			gates = append(gates, l)
		}
	}
	if len(gates) != 6 {
		t.Fatalf("gates %q, want G0-G5", gates)
	}
	for i, g := range gates {
		if !strings.HasPrefix(g, fmt.Sprintf("## G%d:", i)) {
			t.Errorf("gate %d is %q", i, g)
		}
	}
	if !strings.Contains(gates[4], "OPERATOR-RUN") {
		t.Errorf("G4 %q is not marked OPERATOR-RUN", gates[4])
	}
	if !strings.Contains(text, "`ssh -o BatchMode=yes root@qa-pve-02.lab.quantum.com true`") {
		t.Error("G0 does not name the BatchMode root ssh check")
	}
}

func TestD5Revert_UndoesTheSequenceInOrder(t *testing.T) {
	roles, rows := d5Roles(t), d5Rows(t)
	remote, _, text := d5Commands(t, "revert.md")
	// A partial D5 has its own row: which R-steps to run for each gate reached.
	for _, row := range []string{"| G0 ", "| G1 ", "| G2 ", "| G3 ", "| G4 `discarded` ", "| G4 `unverified`, G4 `minted`, or G5 "} {
		if !strings.Contains(text, row) {
			t.Errorf("revert.md has no row for %q", row)
		}
	}
	del := regexp.MustCompile(`^pveum acl delete (\S+) --(users|tokens) "?([^" ]+)"? --roles (\S+)$`)
	var gotRows []string
	step := map[string]int{}
	for i, c := range remote {
		if m := del.FindStringSubmatch(c); m != nil {
			gotRows = append(gotRows, m[1]+" "+m[3]+" "+m[4])
			step["acl"] = i
			continue
		}
		switch {
		case c == "pveum user token remove pveforge-harness@pve build":
			step["token"] = i
		case c == "pveum user delete pveforge-harness@pve":
			step["user"] = i
		case c == "pveum pool delete pveforge-harness":
			step["pool"] = i
		case strings.HasPrefix(c, "pveum role delete "):
			r := strings.TrimPrefix(c, "pveum role delete ")
			if _, ok := roles[r]; !ok {
				t.Errorf("revert deletes role %s, which D5 never made", r)
			}
			delete(roles, r)
			if _, seen := step["role"]; !seen {
				step["role"] = i
			}
		default:
			t.Errorf("unexpected revert command: %s", c)
		}
	}
	if len(roles) != 0 {
		t.Errorf("revert leaves roles %v", roles)
	}
	var wantRows []string
	for _, r := range rows {
		wantRows = append(wantRows, r.Path+" "+r.UGID+" "+r.RoleID)
	}
	sort.Strings(gotRows)
	sort.Strings(wantRows)
	if strings.Join(gotRows, "\n") != strings.Join(wantRows, "\n") {
		t.Errorf("revert deletes rows:\n%s\nwant:\n%s", strings.Join(gotRows, "\n"), strings.Join(wantRows, "\n"))
	}
	// Rows, then the token, then its user, then the pool, then the roles.
	order := []string{"acl", "token", "user", "pool", "role"}
	for i := 1; i < len(order); i++ {
		a, oka := step[order[i-1]]
		b, okb := step[order[i]]
		if !oka || !okb || a >= b {
			t.Errorf("revert order: %s (step %d) must come before %s (step %d)", order[i-1], a, order[i], b)
		}
	}
}

// PVE's own ID rules, as pve-access-control (dff26b45) and pve-manager
// (4f6e0ac8) state them:
//   - a role ID: pve-roleid, src/PVE/AccessControl.pm:1341
//     m/^[A-Za-z0-9\.\-_]+\z/; and create_role, src/PVE/API2/Role.pm:96,
//     refuses $role =~ /^PVE/i ("cannot use role ID starting with the
//     (case-insensitive) 'PVE' namespace"). G1 went red on exactly this.
//   - a pool ID: pve-poolid, src/PVE/AccessControl.pm:1353-1367, at most 3
//     levels, m!^[A-Za-z0-9\.\-_]+(?:/[A-Za-z0-9\.\-_]+){0,2}\z!; no
//     reserved prefix (pve-manager PVE/API2/Pool.pm uses only the format).
//   - a user ID: src/PVE/Auth/Plugin.pm:121-147, 3 to 64 characters,
//     m!^(${user_regex})\@(${realm_regex})\z! with user_regex [^\s:/]+ and
//     realm_regex [A-Za-z][A-Za-z0-9\.\-_]+ (Plugin.pm:34-35); no reserved
//     prefix.
var (
	pveRoleIDFormat = regexp.MustCompile(`^[A-Za-z0-9.\-_]+$`)
	pveRoleReserved = regexp.MustCompile(`(?i)^PVE`)
	pvePoolIDFormat = regexp.MustCompile(`^[A-Za-z0-9.\-_]+(?:/[A-Za-z0-9.\-_]+){0,2}$`)
	pveUserIDFormat = regexp.MustCompile(`^[^\s:/]+@[A-Za-z][A-Za-z0-9.\-_]+$`)
)

// pveRoleIDValid is PVE's whole rule for a role ID pveum role add accepts.
func pveRoleIDValid(id string) bool {
	return pveRoleIDFormat.MatchString(id) && !pveRoleReserved.MatchString(id)
}

// The rule itself, against the IDs it must refuse and accept.
func TestPVERoleIDRule(t *testing.T) {
	for id, want := range map[string]bool{
		"ForgeHarness": true, "ForgeHarnessSpace": true, "my.role-1_x": true,
		"PveforgeHarness": false, "PVEVMAdmin": false, "pveX": false, "pVe": false,
		"Forge Harness": false, "Forge/Harness": false, "": false, "Forge\n": false,
	} {
		if got := pveRoleIDValid(id); got != want {
			t.Errorf("pveRoleIDValid(%q) = %v, want %v", id, got, want)
		}
	}
}

// Every role ID the D5 tooling names (sequence.md's role adds and G4's
// grants, and the roles fixture) is one PVE accepts; so are the pool and the
// user it creates.
func TestD5Sequence_IDsArePVEValid(t *testing.T) {
	remote, local, _ := d5Commands(t, "sequence.md")
	roleAdd := regexp.MustCompile(`^pveum role add (\S+) `)
	var added []string
	for _, c := range remote {
		if m := roleAdd.FindStringSubmatch(c); m != nil {
			added = append(added, m[1])
		}
	}
	grant := regexp.MustCompile(`--grant '[^:']+:([^:']+):`)
	var granted []string
	for _, l := range local {
		for _, m := range grant.FindAllStringSubmatch(l, -1) {
			granted = append(granted, m[1])
		}
	}
	var fixture []string
	for id := range d5Roles(t) {
		fixture = append(fixture, id)
	}
	for what, ids := range map[string][]string{"role add": added, "--grant": granted, "roles fixture": fixture} {
		if len(ids) != 4 {
			t.Errorf("%s names %d roles %q, want the 4 harness roles", what, len(ids), ids)
		}
		for _, id := range ids {
			if !pveRoleIDValid(id) {
				t.Errorf("%s: role ID %q is one PVE refuses (pve-roleid, or the reserved 'PVE' namespace)", what, id)
			}
		}
	}
	var pools, users []string
	for _, c := range remote {
		if m := regexp.MustCompile(`^pveum pool add (\S+) `).FindStringSubmatch(c); m != nil {
			pools = append(pools, m[1])
		}
		if m := regexp.MustCompile(`^pveum user add (\S+) `).FindStringSubmatch(c); m != nil {
			users = append(users, m[1])
		}
	}
	if len(pools) != 1 || !pvePoolIDFormat.MatchString(pools[0]) {
		t.Errorf("pool add names %q, want one pve-poolid", pools)
	}
	if len(users) != 1 || len(users[0]) < 3 || len(users[0]) > 64 || !pveUserIDFormat.MatchString(users[0]) {
		t.Errorf("user add names %q, want one user ID PVE accepts", users)
	}
}
