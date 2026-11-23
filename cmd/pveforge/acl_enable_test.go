package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// `acl enable-vm-destroy` through the whole CLI (runRoot): flag -> request
// wiring (a flag a unit is named after can be a no-op while every test of the
// package passes, so each flag is pinned here by a run that would differ),
// the tier, the output, and that nothing is written on a dry run or a
// refused name.

var enableVMAdmin = []string{
	"VM.Allocate", "VM.Audit", "VM.Backup", "VM.Clone", "VM.Config.CDROM", "VM.Config.CPU",
	"VM.Config.Cloudinit", "VM.Config.Disk", "VM.Config.HWType", "VM.Config.Memory", "VM.Config.Network",
	"VM.Config.Options", "VM.Console", "VM.GuestAgent.Audit", "VM.GuestAgent.FileRead",
	"VM.GuestAgent.FileSystemMgmt", "VM.GuestAgent.FileWrite", "VM.GuestAgent.Unrestricted", "VM.Migrate",
	"VM.PowerMgmt", "VM.Replicate", "VM.Snapshot", "VM.Snapshot.Rollback",
}

// enableHost is a tiny stateful root: PVEVMAdmin only on /, the way the
// operator's token is, and it records every command.
type enableHost struct {
	mu    sync.Mutex
	roles map[string][]string
	rows  []string // extra roles on / for the token
	log   []string
	// nodeOverride adds the token's own flag-0 row for a role holding only
	// PVEVMAdmin's privileges on /nodes/pve1: the role it gets on / never
	// reaches that path, so Sys.Audit stays absent there after the upgrade.
	nodeOverride bool
}

func newEnableHost() *enableHost {
	admin := append(slices.Clone(enableVMAdmin), "Sys.Audit", "Sys.Modify", "Permissions.Modify", "VM.Monitor")
	sort.Strings(admin)
	return &enableHost{roles: map[string][]string{"PVEVMAdmin": slices.Clone(enableVMAdmin), "Administrator": admin, "VMOnly": slices.Clone(enableVMAdmin)}}
}

func (h *enableHost) exec(cmd string) (string, string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log = append(h.log, cmd)
	switch {
	case strings.HasPrefix(cmd, "pveum role list"):
		var ids []string
		for id := range h.roles {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var list []map[string]any
		for _, id := range ids {
			list = append(list, map[string]any{"roleid": id, "privs": strings.Join(h.roles[id], ",")})
		}
		b, _ := json.Marshal(list)
		return string(b), "", 0
	case strings.HasPrefix(cmd, "pveum acl list"):
		rows := []map[string]any{{"path": "/", "roleid": "PVEVMAdmin", "type": "token", "ugid": "root@pam!pveforge", "propagate": 1}}
		for _, r := range h.rows {
			rows = append(rows, map[string]any{"path": "/", "roleid": r, "type": "token", "ugid": "root@pam!pveforge", "propagate": 1})
		}
		if h.nodeOverride {
			rows = append(rows, map[string]any{"path": "/nodes/pve1", "roleid": "VMOnly", "type": "token", "ugid": "root@pam!pveforge", "propagate": 0})
		}
		b, _ := json.Marshal(rows)
		return string(b), "", 0
	case strings.HasPrefix(cmd, "pveum user permissions"):
		priv := map[string]int{}
		for _, p := range h.roles["PVEVMAdmin"] {
			priv[p] = 1
		}
		for _, r := range h.rows {
			for _, p := range h.roles[r] {
				priv[p] = 1
			}
		}
		tree := map[string]map[string]int{}
		for _, p := range []string{"/", "/access", "/access/groups", "/nodes", "/pool", "/sdn", "/storage", "/vms"} {
			tree[p] = priv
		}
		if h.nodeOverride {
			only := map[string]int{}
			for _, p := range h.roles["VMOnly"] {
				only[p] = 1
			}
			tree["/nodes/pve1"] = only
		}
		b, _ := json.Marshal(tree)
		return string(b), "", 0
	case strings.HasPrefix(cmd, "pveum role add "):
		f := strings.Fields(cmd)
		id := strings.Trim(f[3], "'")
		h.roles[id] = strings.Split(strings.Trim(f[5], "'"), ",")
		return "", "", 0
	case strings.HasPrefix(cmd, "pveum acl modify "):
		f := strings.Fields(cmd)
		for i, w := range f {
			if w == "--roles" {
				h.rows = append(h.rows, strings.Trim(f[i+1], "'"))
			}
		}
		return "", "", 0
	}
	return "", "unknown command", 127
}

func (h *enableHost) writes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, c := range h.log {
		if strings.HasPrefix(c, "pveum role add") || strings.HasPrefix(c, "pveum acl modify") {
			out = append(out, c)
		}
	}
	return out
}

func enableSetup(t *testing.T) (string, *enableHost) {
	t.Helper()
	// Every real run is non-interactive here and ends in the verdict, which
	// reads the token's REST side: flowEnv serves it, coupled to root's writes.
	setNoTTY(t)
	e := newFlowEnv(t)
	return e.roster, e.host
}

func TestACLEnableVMDestroy_DryRunWritesNothing(t *testing.T) {
	path, h := enableSetup(t)
	code, stdout, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--dry-run", "qa-pve-01")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got := h.writes(); len(got) != 0 {
		t.Fatalf("--dry-run wrote: %q", got)
	}
	if len(h.log) == 0 {
		t.Fatal("vacuous: root ran nothing")
	}
	for _, want := range []string{"dry_run=true", "pveum role add 'ForgeVMAdminAudit'", "pveum acl modify '/' --tokens 'root@pam!pveforge' --roles 'ForgeVMAdminAudit' --propagate 1", `widened=["Sys.Audit"]`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

// Without --dry-run the same run writes, in order, then is a no-op.
func TestACLEnableVMDestroy_WritesThenIsIdempotent(t *testing.T) {
	path, h := enableSetup(t)
	code, stdout, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--yes", "qa-pve-01")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	w := h.writes()
	if len(w) != 2 || !strings.HasPrefix(w[0], "pveum role add 'ForgeVMAdminAudit' --privs 'Sys.Audit,VM.Allocate,") ||
		w[1] != "pveum acl modify '/' --tokens 'root@pam!pveforge' --roles 'ForgeVMAdminAudit' --propagate 1" {
		t.Fatalf("writes = %q", w)
	}
	if !strings.Contains(stdout, "outcome=upgraded") || !strings.Contains(stdout, `widened=["Sys.Audit"]`) || strings.Contains(stdout, "dry_run") {
		t.Errorf("stdout:\n%s", stdout)
	}
	code, stdout, stderr = runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--yes", "qa-pve-01")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "outcome=already_enabled") || len(h.writes()) != 2 {
		t.Fatalf("second run: exit %d, stdout %q, stderr %q, writes %q", code, stdout, stderr, h.writes())
	}
}

// --role reaches the request: the written commands carry it. And a PVE-prefixed
// role is refused before root is dialed (no command at all).
func TestACLEnableVMDestroy_RoleFlagIsWired(t *testing.T) {
	path, h := enableSetup(t)
	code, stdout, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--yes", "--role", "ForgeCustomRole", "qa-pve-01")
	if code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	w := h.writes()
	if len(w) != 2 || !strings.Contains(w[0], "'ForgeCustomRole'") || !strings.Contains(w[1], "--roles 'ForgeCustomRole'") {
		t.Fatalf("--role did not reach the commands: %q", w)
	}
	for _, bad := range []string{"PVEForgeVMAdminAudit", "PveForge", "pveforge"} {
		path2, h2 := enableSetup(t)
		code, _, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path2, "--role", bad, "qa-pve-01")
		if code == 0 || !strings.Contains(stderr, "refusing this role name") {
			t.Errorf("%s: exit %d, stderr %q", bad, code, stderr)
		}
		if len(h2.log) != 0 {
			t.Errorf("%s: root ran %q before the name was refused", bad, h2.log)
		}
	}
}

func TestACLEnableVMDestroy_TierAndFlags(t *testing.T) {
	cmd := newACLEnableVMDestroyCmd()
	if got := cmd.Annotations[mutationAnnotationKey]; got != mutationDestructive {
		t.Fatalf("tier = %q, want destructive", got)
	}
	for _, f := range []string{"role", "dry-run", "role-only", "yes", "vmid", "output", "no-ssh-key", "host-key-fingerprint", "roster", "lock-wait"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("flag --%s is missing", f)
		}
	}
	// the help states the invariants the operator needs
	help := strings.Join(strings.Fields(cmd.Long), " ")
	for _, want := range []string{"--grant /:ForgeVMAdminAudit::1", "REVOKE", "never widens", "pveum acl delete", "dry-run"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

// T12: no document names a role PVE cannot create. PVE refuses a new role whose
// id starts with PVE in any case, so a doc that tells an operator to
// `pveum role add PVEForgeVMAdminAudit` (procedure 11 once did) teaches a
// command that fails. A builtin role (PVEVMAdmin, ...) is fine wherever it is
// USED; what may never appear is a PVE-prefixed name that is not a builtin, or
// any PVE-prefixed name after `role add` / `--role`.
func TestDocs_T12_NoIllegalRoleNames(t *testing.T) {
	builtin := map[string]bool{}
	for _, r := range []string{"PVEAdmin", "PVEAuditor", "PVEDatastoreAdmin", "PVEDatastoreUser", "PVEMappingAdmin", "PVEMappingUser",
		"PVEPasswdMod", "PVEPoolAdmin", "PVEPoolUser", "PVEPVEAdmin", "PVERealmAdmin", "PVERealmUser", "PVESDNAdmin", "PVESDNUser",
		"PVESysAdmin", "PVETemplateUser", "PVEUserAdmin", "PVEVMAdmin", "PVEVMUser"} {
		builtin[r] = true
	}
	any := regexp.MustCompile(`(?i)\bpve[a-z]*vmadminaudit\b|\bPVEForge[A-Z]\w*`)
	created := regexp.MustCompile("(?i)(?:role add|--role)[ =]+['\"]?(pve\\w*)")
	scanned := 0
	for _, p := range []string{"../../README.md", "../../docs/operations/secrets-and-keys.md", "../../docs/prd.md", "../../hack/harness/README.md"} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		scanned += len(b)
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range any.FindAllString(line, -1) {
				if !builtin[m] {
					t.Errorf("%s:%d names %q, a role PVE refuses to create", p, i+1, m)
				}
			}
			for _, m := range created.FindAllStringSubmatch(line, -1) {
				t.Errorf("%s:%d creates the role %q: PVE refuses any new role id starting with PVE", p, i+1, m[1])
			}
		}
	}
	if scanned == 0 {
		t.Fatal("vacuous: no document was read")
	}
	// The checker catches what it is for.
	for _, bad := range []string{"pveum role add PVEForgeVMAdminAudit --privs x", "--roles PVEForgeVMAdminAudit", "pveum role add pveforge --privs x"} {
		if !any.MatchString(bad) && !created.MatchString(bad) {
			t.Errorf("the checker misses %q", bad)
		}
	}
}

// --role-only reaches the request: the run writes only the role, and the log
// holds no ACL write and no read of the token's tree, though the roster holds
// a token and the host would let it be upgraded.
func TestACLEnableVMDestroy_RoleOnlyFlagIsWired(t *testing.T) {
	path, h := enableSetup(t)
	code, stdout, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--yes", "--role-only", "qa-pve-01")
	if code != 0 || stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	w := h.writes()
	if len(w) != 1 || !strings.HasPrefix(w[0], "pveum role add 'ForgeVMAdminAudit'") {
		t.Fatalf("writes = %q", w)
	}
	for _, c := range h.log {
		if strings.HasPrefix(c, "pveum acl") || strings.HasPrefix(c, "pveum user permissions") {
			t.Errorf("--role-only read or wrote the token's side: %q", c)
		}
	}
	if !strings.Contains(stdout, "next=mint the token with: pveforge bootstrap qa-pve-01 --grant /:ForgeVMAdminAudit::1") {
		t.Errorf("stdout:\n%s", stdout)
	}
}

// A role id starting with '-' is refused before root is dialed.
func TestACLEnableVMDestroy_LeadingDashRoleRefused(t *testing.T) {
	path, h := enableSetup(t)
	code, _, stderr := runRootArgs("acl", "enable-vm-destroy", "--roster", path, "--role=--delete", "qa-pve-01")
	if code == 0 || !strings.Contains(stderr, "refusing this role name") || len(h.log) != 0 {
		t.Fatalf("exit %d, stderr %q, root ran %q", code, stderr, h.log)
	}
}
