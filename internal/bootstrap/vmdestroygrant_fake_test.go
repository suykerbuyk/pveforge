package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pve"
	"github.com/suykerbuyk/pveforge/internal/roster"
)

// grantFake is a small PVE host for the enable-vm-destroy verb. Its
// `effective` is a LITERAL PORT of PVE's role walk (AccessControl.pm roles()
// and RPCEnvironment.pm compile_acl_path), computed from ACL ROWS, ROLE
// DEFINITIONS and the OWNER, and deliberately not from anything the verb's
// predictor uses: the predictor is a delta over a tree the verb READ, this is
// a from-scratch rebuild, so `predicted == actual` (T7) ties two independent
// derivations rather than one object to itself. Both are still ours; only
// the live nested harness ties either to real PVE (plan §5.3 item 6b).
type grantFake struct {
	roles map[string][]string // role id -> privileges (the fake keeps them sorted)
	acls  []pve.ACLEntry
	// tokens maps a full token id to whether it is privilege-separated.
	tokens map[string]bool
	// groups maps a group id to its member user ids.
	groups map[string][]string
	// pools are resource pools: their members are listed in a permission tree
	// whether or not any ACL names them (RPCEnvironment.pm
	// get_effective_permissions), and a principal's roles on /pool/<id> flow to
	// each member path at flag 0 (compile_acl_path).
	pools map[string]fakePool

	commands []string
	// before runs before every command, with its text. A hook that edits
	// the fake here models a concurrent root editor at exactly that point.
	before func(cmd string)
	// fail answers a command with a failure instead of executing it, keyed by
	// prefix.
	fail map[string]RunResult
	// failErr likewise, as a transport error.
	failErr map[string]error
	closed  bool
}

// fakePool is a pool's members: guests, storages and SDN vnets ("zone/vnet").
type fakePool struct {
	vms     []int
	storage []string
	vnets   []string
}

var vmAdmin23 = []string{
	"VM.Allocate", "VM.Audit", "VM.Backup", "VM.Clone", "VM.Config.CDROM", "VM.Config.CPU",
	"VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network",
	"VM.Config.Options", "VM.Console", "VM.GuestAgent.Audit", "VM.GuestAgent.FileRead",
	"VM.GuestAgent.FileSystemMgmt", "VM.GuestAgent.FileWrite", "VM.GuestAgent.Unrestricted", "VM.Migrate",
	"VM.PowerMgmt", "VM.Replicate", "VM.Snapshot", "VM.Snapshot.Rollback",
}

const (
	liveToken = "root@pam!pveforge"
	ownerRoot = "root@pam"
)

// allPrivs is the fake's "every valid privilege": Administrator's set.
func allPrivs() []string {
	extra := []string{"Sys.Audit", "Sys.Modify", "Sys.Console", "Sys.Syslog", "Permissions.Modify", "VM.Monitor",
		"Datastore.Audit", "Datastore.Allocate", "Datastore.AllocateSpace", "Pool.Audit", "Pool.Allocate", "User.Modify", "SDN.Use"}
	out := slices.Clone(vmAdmin23)
	out = append(out, extra...)
	sort.Strings(out)
	return out
}

// newGrantFake is the operator's cluster: PVEVMAdmin only on /, propagate 1
// (path B), no custom role yet.
func newGrantFake() *grantFake {
	f := &grantFake{
		roles: map[string][]string{
			"PVEVMAdmin":    slices.Clone(vmAdmin23),
			"PVEAuditor":    {"Datastore.Audit", "Pool.Audit", "Sys.Audit", "VM.Audit"},
			"Administrator": allPrivs(),
			"NoAccess":      {},
		},
		tokens:  map[string]bool{liveToken: true},
		groups:  map[string][]string{},
		pools:   map[string]fakePool{},
		fail:    map[string]RunResult{},
		failErr: map[string]error{},
	}
	f.acls = []pve.ACLEntry{{Path: "/", Role: "PVEVMAdmin", Type: "token", UGID: liveToken, Propagate: true}}
	return f
}

func (f *grantFake) clone() *grantFake { // shares nothing mutable
	g := &grantFake{roles: map[string][]string{}, tokens: map[string]bool{}, groups: map[string][]string{}, pools: map[string]fakePool{}, fail: map[string]RunResult{}, failErr: map[string]error{}}
	for k, v := range f.roles {
		g.roles[k] = slices.Clone(v)
	}
	for k, v := range f.tokens {
		g.tokens[k] = v
	}
	for k, v := range f.groups {
		g.groups[k] = slices.Clone(v)
	}
	for k, v := range f.pools {
		g.pools[k] = v
	}
	g.acls = slices.Clone(f.acls)
	return g
}

func (f *grantFake) setRole(id string, privs ...string) {
	privs = slices.Clone(privs)
	sort.Strings(privs)
	f.roles[id] = privs
}

func (f *grantFake) addRow(path, role, typ, ugid string, propagate bool) {
	f.acls = append(f.acls, pve.ACLEntry{Path: path, Role: role, Type: typ, UGID: ugid, Propagate: propagate})
}

// universe is every path PVE lists in a tree: the default top paths and every
// ACL path (get_effective_permissions).
func (f *grantFake) universe() []string {
	set := map[string]bool{}
	for _, p := range defaultTopPaths {
		set[p] = true
	}
	for _, e := range f.acls {
		set[e.Path] = true
	}
	for _, p := range f.pools {
		for _, v := range p.vms {
			set[fmt.Sprintf("/vms/%d", v)] = true
		}
		for _, st := range p.storage {
			set["/storage/"+st] = true
		}
		for _, vn := range p.vnets {
			set["/sdn/zones/"+vn] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// nodePaths is the chain of ACL nodes from / down to path: "/", "/a", "/a/b".
func nodePaths(path string) []string {
	if path == "/" {
		return []string{"/"}
	}
	out := []string{"/"}
	cur := ""
	for _, c := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		cur += "/" + c
		out = append(out, cur)
	}
	return out
}

// rolesAt ports AccessControl.pm roles(): the roles (role -> propagate flag) a
// principal holds at path, for a user or a privilege-separated token.
func (f *grantFake) rolesAt(kind, id, path string) map[string]bool {
	roles := map[string]bool{}
	chain := nodePaths(path)
	for i, node := range chain {
		final := i == len(chain)-1
		apply := func(match func(e pve.ACLEntry) bool) map[string]bool {
			var n map[string]bool
			for _, e := range f.acls {
				if e.Path == node && match(e) && (final || e.Propagate) {
					if n == nil {
						n = map[string]bool{}
					}
					n[e.Role] = e.Propagate
				}
			}
			return n
		}
		if n := apply(func(e pve.ACLEntry) bool { return e.Type == "token" && kind == "token" && e.UGID == id }); n != nil {
			roles = n
			continue
		}
		if kind == "user" {
			if n := apply(func(e pve.ACLEntry) bool { return e.Type == "user" && e.UGID == id }); n != nil {
				roles = n
				continue
			}
			if n := apply(func(e pve.ACLEntry) bool {
				return e.Type == "group" && slices.Contains(f.groups[e.UGID], id)
			}); n != nil {
				roles = n
				continue
			}
		}
	}
	if _, no := roles["NoAccess"]; no {
		return map[string]bool{"NoAccess": roles["NoAccess"]}
	}
	return roles
}

// poolsOf lists the pools a member path belongs to.
func (f *grantFake) poolsOf(path string) []string {
	var out []string
	for id, p := range f.pools {
		member := false
		for _, v := range p.vms {
			member = member || path == fmt.Sprintf("/vms/%d", v)
		}
		for _, st := range p.storage {
			member = member || path == "/storage/"+st
		}
		for _, vn := range p.vnets {
			member = member || path == "/sdn/zones/"+vn
		}
		if member {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// rolesFull ports compile_acl_path's role step: the walk's roles, then the
// roles the principal holds on /pool/<id> for each pool the path is a member
// of, added at flag 0 where the walk did not already set them; NoAccess is
// never trumped by a pool role, and a pool NoAccess trumps the walk's.
func (f *grantFake) rolesFull(kind, id, path string) map[string]bool {
	roles := f.rolesAt(kind, id, path)
	pool := map[string]bool{}
	for _, pid := range f.poolsOf(path) {
		for role := range f.rolesAt(kind, id, "/pool/"+pid) {
			pool[role] = true
		}
	}
	if len(pool) == 0 {
		return roles
	}
	if _, no := roles["NoAccess"]; no {
		return roles
	}
	if pool["NoAccess"] {
		return map[string]bool{"NoAccess": false}
	}
	out := map[string]bool{}
	for r, fl := range roles {
		out[r] = fl
	}
	for r := range pool {
		if _, set := out[r]; !set {
			out[r] = false
		}
	}
	return out
}

// privsAt ports compile_acl_path's role->privilege step: a privilege's flag is
// the OR of the flags of the roles holding it.
func (f *grantFake) privsAt(roles map[string]bool) map[string]bool {
	out := map[string]bool{}
	for role, flag := range roles {
		for _, p := range f.roles[role] {
			out[p] = out[p] || flag
		}
	}
	return out
}

// effective is a user's or token's whole permission tree, as PVE would print
// it: root@pam is Administrator everywhere; a privilege-separated token is its
// own roles intersected with its owner's (flags ANDed); a non-privsep token is
// its owner's.
func (f *grantFake) effective(id string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	user, _, isToken := strings.Cut(id, "!")
	for _, path := range f.universe() {
		var privs map[string]bool
		switch {
		case !isToken && id == ownerRoot:
			privs = map[string]bool{}
			for _, p := range f.roles["Administrator"] {
				privs[p] = true
			}
		case !isToken:
			privs = f.privsAt(f.rolesFull("user", id, path))
		default:
			if _, known := f.tokens[id]; !known {
				// RPCEnvironment.pm permissions(): `return {} if !$token_info`.
				break
			}
			owner := f.effectiveAt(user, path)
			if !f.tokens[id] { // not privilege-separated
				privs = owner
				break
			}
			tok := f.privsAt(f.rolesFull("token", id, path))
			privs = map[string]bool{}
			for p, flag := range tok {
				if user == ownerRoot {
					privs[p] = flag
				} else if of, held := owner[p]; held {
					privs[p] = of && flag
				}
			}
		}
		if len(privs) > 0 {
			out[path] = privs
		}
	}
	return out
}

func (f *grantFake) effectiveAt(user, path string) map[string]bool {
	if user == ownerRoot {
		m := map[string]bool{}
		for _, p := range f.roles["Administrator"] {
			m[p] = true
		}
		return m
	}
	return f.privsAt(f.rolesFull("user", user, path))
}

func treeJSON(t map[string]map[string]bool) string {
	m := map[string]map[string]int{}
	for p, s := range t {
		m[p] = map[string]int{}
		for k, v := range s {
			if v {
				m[p][k] = 1
			} else {
				m[p][k] = 0
			}
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// shellFields splits a recorded command the way the fake needs to execute it:
// single-quoted words, as renderEnable and aclModify emit them. (The T2 screen
// uses a REAL sh instead; this is only the fake's own executor.)
func shellFields(cmd string) []string {
	var out []string
	var cur strings.Builder
	in, started := false, false
	for _, r := range cmd {
		switch {
		case r == '\'':
			in, started = !in, true
		case r == ' ' && !in:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

func flagValue(f []string, name string) string {
	i := slices.Index(f, name)
	if i < 0 || i+1 >= len(f) {
		return ""
	}
	return f[i+1]
}

func (f *grantFake) Run(ctx context.Context, cmd string) (RunResult, error) {
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if f.before != nil {
		f.before(cmd)
	}
	f.commands = append(f.commands, cmd)
	for prefix, err := range f.failErr {
		if strings.HasPrefix(cmd, prefix) {
			return RunResult{}, err
		}
	}
	for prefix, r := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return r, nil
		}
	}
	w := shellFields(cmd)
	switch {
	case strings.HasPrefix(cmd, "pveum role list"):
		ids := make([]string, 0, len(f.roles))
		for id := range f.roles {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var list []map[string]any
		for _, id := range ids {
			list = append(list, map[string]any{"roleid": id, "privs": strings.Join(f.roles[id], ","), "special": 0})
		}
		b, _ := json.Marshal(list)
		return RunResult{Stdout: string(b)}, nil
	case strings.HasPrefix(cmd, "pveum acl list"):
		list := []map[string]any{}
		for _, e := range f.acls {
			p := 0
			if e.Propagate {
				p = 1
			}
			list = append(list, map[string]any{"path": e.Path, "roleid": e.Role, "type": e.Type, "ugid": e.UGID, "propagate": p})
		}
		b, _ := json.Marshal(list)
		return RunResult{Stdout: string(b)}, nil
	case strings.HasPrefix(cmd, "pveum user permissions"):
		if len(w) < 4 {
			return RunResult{ExitCode: 2, Stderr: "usage"}, nil
		}
		return RunResult{Stdout: treeJSON(f.effective(w[3]))}, nil
	case strings.HasPrefix(cmd, cmdRoleAdd+" "):
		role := w[3]
		if pvePrefixRE.MatchString(role) {
			return RunResult{ExitCode: 255, Stderr: "400 Parameter verification failed.\nroleid: cannot use role ID starting with the (case-insensitive) 'PVE' namespace"}, nil
		}
		if _, ok := f.roles[role]; ok {
			return RunResult{ExitCode: 255, Stderr: "create role failed: role '" + role + "' already exists"}, nil
		}
		valid := map[string]bool{}
		for _, p := range f.roles["Administrator"] {
			valid[p] = true
		}
		privs := splitPrivList(flagValue(w, "--privs"))
		for _, p := range privs {
			if !valid[p] {
				return RunResult{ExitCode: 255, Stderr: "create role failed: invalid privilege '" + p + "'"}, nil
			}
		}
		f.setRole(role, privs...)
		return RunResult{}, nil
	case strings.HasPrefix(cmd, cmdACLModify+" "):
		tok, role := flagValue(w, "--tokens"), flagValue(w, "--roles")
		if tok == "" || w[3] != "/" {
			return RunResult{ExitCode: 255, Stderr: "unsupported by this fake"}, nil
		}
		if _, ok := f.tokens[tok]; !ok {
			return RunResult{ExitCode: 255, Stderr: "ACL update failed: no such token"}, nil
		}
		if _, ok := f.roles[role]; !ok {
			return RunResult{ExitCode: 255, Stderr: "ACL update failed: role '" + role + "' does not exist"}, nil
		}
		prop := flagValue(w, "--propagate") == "1"
		replaced := false
		for i := range f.acls {
			e := &f.acls[i]
			if e.Path == "/" && e.Type == "token" && e.UGID == tok && e.Role == role {
				e.Propagate, replaced = prop, true
			}
		}
		if !replaced {
			f.addRow("/", role, "token", tok, prop)
		}
		return RunResult{}, nil
	}
	return RunResult{ExitCode: 127, Stderr: "unknown command in the fake: " + w[0]}, nil
}

func (f *grantFake) Close() error { f.closed = true; return nil }

// isMutatingCmd: a command is a read only if it is one of the verb's three
// reads; anything else counts as mutating, so a new kind of command can never
// slip past the screen by being unrecognised.
func isMutatingCmd(cmd string) bool {
	for _, r := range []string{"pveum role list", "pveum acl list", "pveum user permissions"} {
		if strings.HasPrefix(cmd, r) {
			return false
		}
	}
	return true
}

func (f *grantFake) mutating() []string {
	var out []string
	for _, c := range f.commands {
		if isMutatingCmd(c) {
			out = append(out, c)
		}
	}
	return out
}

func (f *grantFake) count(prefix string) int {
	n := 0
	for _, c := range f.commands {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// shArgv parses a recorded command with a REAL shell, as the remote end does:
// pveum is a shell function that prints its own arguments NUL-separated, and
// PATH is empty, so a second command smuggled in after `;` or `&&` is "not
// found" and fails the parse instead of running. (A hand-rolled splitter would
// be a second parser able to agree with the renderer on the legal shapes and
// disagree on a mutant.)
func shArgv(t *testing.T, cmd string) ([]string, error) {
	t.Helper()
	c := exec.Command("sh", "-c", "pveum() { printf '%s\\0' \"$@\"; }; "+cmd)
	c.Env = []string{"PATH=/nonexistent"}
	out, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sh: %w: %q", err, out)
	}
	parts := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	return append([]string{"pveum"}, parts...), nil
}

// enableRun is one verb run against a fake.
type enableRun struct {
	t      *testing.T
	fake   *grantFake
	tr     *fakeTransport
	roster string
	req    EnableVMDestroyRequest
	own    string
}

func newEnableRun(t *testing.T, f *grantFake) *enableRun {
	t.Helper()
	// The roster holds the live token, as the operator's does: the verb
	// re-reads it under the lock and refuses if it differs from the run's.
	path := seedRoster(t, liveToken, "").path
	return &enableRun{
		t: t, fake: f, tr: &fakeTransport{}, roster: path, own: liveToken,
		req: EnableVMDestroyRequest{RosterPath: path, TargetID: "qa-pve-01"},
	}
}

// setOwn makes both the run and the roster hold token ("" for none): the roster
// token id is read before the lock and again under it, and they must agree.
func (r *enableRun) setOwn(token string) {
	r.t.Helper()
	r.own = token
	var err error
	if token == "" {
		err = roster.ClearTokenAuth(r.roster, "qa-pve-01")
	} else {
		err = roster.WriteTokenAuth(r.roster, "qa-pve-01", roster.TokenWrite{TokenID: token, SecretPlaintext: []byte("s")}, roster.NewPassphrase("roster-pass"))
	}
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *enableRun) do() (*EnableVMDestroyResult, error) {
	r.t.Helper()
	a := NewRootAccess(AccessOptions{
		Addr: "qa-pve-01:22", SSHUser: "root", PrivateKeyPEM: []byte("KEY"), HostKeyFingerprint: "SHA256:pin", OwnToken: r.own,
	}, &grantTransport{sess: r.fake, calls: &r.tr.reconnectCalls})
	return EnableVMDestroy(context.Background(), a, r.req)
}

// grantTransport hands a session out as the root connection; it counts dials
// in *calls and can refuse them.
type grantTransport struct {
	fakeTransport
	sess    SSHSession
	calls   *int
	dialErr error
}

func (g *grantTransport) ReconnectWithPinnedKey(context.Context, string, string, []byte, string) (SSHSession, error) {
	*g.calls++
	if g.dialErr != nil {
		return nil, g.dialErr
	}
	return g.sess, nil
}
