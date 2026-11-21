package main

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/suykerbuyk/pveforge/internal/pvefake"
)

// These tests drive `pveforge doctor` THROUGH runRoot against pvefake's VMREST
// over TLS. Every "zero" assertion has a control that is non-zero on a positive
// path: the status read is counted, and the non-GET counter is checked beside a
// request counter that is greater than zero.

const doctorBody = "PVE-BODY-MUST-NOT-APPEAR"

func heldTree() map[string]map[string]bool {
	return map[string]map[string]bool{
		"/":                {"Sys.Audit": true},
		"/nodes/" + dNode:  {"Sys.Audit": true},
		"/vms/691":         {"VM.PowerMgmt": true, "VM.Allocate": true},
		"/vms/692":         {"VM.Audit": true},
		"/storage/unrelat": {"Datastore.Audit": true},
	}
}

func doctorEnv(t *testing.T, mut func(*pvefake.VMREST)) *dEnv {
	t.Helper()
	return newDEnv(t, func(s *pvefake.VMREST) {
		s.Permissions = heldTree()
		if mut != nil {
			mut(s)
		}
	})
}

func (e *dEnv) doctor(args ...string) dRes {
	e.t.Helper()
	full := append([]string{"doctor", "--roster", e.roster, "-o", "json"}, args...)
	full = append(full, dTarget)
	code, out, errOut := runRootArgs(full...)
	return parseDRes(e.t, code, out, errOut)
}

func (r dRes) rows() map[string]map[string]any {
	out := map[string]map[string]any{}
	rs, _ := r.m["rows"].([]any)
	for _, x := range rs {
		row := x.(map[string]any)
		out[row["requirement"].(string)] = row
	}
	return out
}

const (
	rowNode    = "Sys.Audit on /nodes/" + dNode
	rowCluster = "Sys.Audit on /"
	rowPower   = "VM.PowerMgmt on /vms/691"
	rowAlloc   = "VM.Allocate on /vms/691"
)

func verdicts(t *testing.T, r dRes) [4]string {
	t.Helper()
	rows := r.rows()
	var out [4]string
	for i, k := range []string{rowNode, rowCluster, rowPower, rowAlloc} {
		row, ok := rows[k]
		if !ok {
			t.Fatalf("no row %q in %s", k, r.stdout)
		}
		out[i], _ = row["verdict"].(string)
	}
	return out
}

func TestDoctor_AllHeldWithVMID_ExitsZero_AndNeverWrites(t *testing.T) {
	e := doctorEnv(t, nil)
	before, _ := os.ReadFile(e.roster)
	r := e.doctor("--vmid", "691")
	if r.code != 0 {
		t.Fatalf("exit %d, want 0: %s %s", r.code, r.stdout, r.stderr)
	}
	if got := verdicts(t, r); got != [4]string{"held", "held", "held", "held"} {
		t.Fatalf("verdicts %v: %s", got, r.stdout)
	}
	if r.has("fix") {
		t.Errorf("a fix command with every row held: %s", r.stdout)
	}
	// Control: requests were made at all, so the zero below is not vacuous.
	if n := len(e.s.Requests()); n == 0 {
		t.Fatal("doctor made no request")
	}
	if w := e.s.Writes(); len(w) != 0 {
		t.Errorf("doctor issued non-GET requests: %v", w)
	}
	after, _ := os.ReadFile(e.roster)
	if string(before) != string(after) {
		t.Error("doctor changed the roster file")
	}
}

// M14d: the verdict is the status read's. Without that read there is no node
// verdict at all.
func TestDoctor_IssuesTheStatusRead_AndTheMemberListRead(t *testing.T) {
	e := doctorEnv(t, nil)
	e.doctor("--vmid", "691")
	if n := e.s.Count("GET", "/api2/json/nodes/"+dNode+"/status"); n < 1 {
		t.Errorf("doctor never issued GET /nodes/%s/status", dNode)
	}
	if n := e.s.Count("GET", "/api2/json/cluster/config/nodes"); n < 1 {
		t.Error("doctor never issued GET /cluster/config/nodes")
	}
}

func TestDoctor_NodeStatusMatrix(t *testing.T) {
	cases := []struct {
		status  int
		want    string
		exit    int
		fix     bool
		hasCode string
	}{
		{0, "held", 0, false, ""},
		{http.StatusForbidden, "missing", 4, true, "HTTP 403"},
		{http.StatusUnauthorized, "unknown", 4, false, "HTTP 401"},
		{http.StatusInternalServerError, "unknown", 4, false, "HTTP 500"},
	}
	for _, c := range cases {
		e := doctorEnv(t, func(s *pvefake.VMREST) { s.NodeStatus = c.status })
		r := e.doctor("--vmid", "691")
		if r.code != c.exit {
			t.Errorf("status %d: exit %d, want %d: %s", c.status, r.code, c.exit, r.stdout)
		}
		row := r.rows()[rowNode]
		if row["verdict"] != c.want {
			t.Errorf("status %d: verdict %v, want %s", c.status, row["verdict"], c.want)
		}
		if c.hasCode != "" && row["detail"] != c.hasCode {
			t.Errorf("status %d: detail %v, want %s", c.status, row["detail"], c.hasCode)
		}
		if r.has("fix") != c.fix {
			t.Errorf("status %d: fix present = %v, want %v", c.status, r.has("fix"), c.fix)
		}
		if w := e.s.Writes(); len(w) != 0 {
			t.Errorf("status %d: non-GET requests %v", c.status, w)
		}
	}
}

func TestDoctor_MemberListMatrix(t *testing.T) {
	cases := []struct {
		status int
		want   string
		exit   int
		fix    bool
	}{
		{0, "held", 0, false},
		{http.StatusForbidden, "missing", 4, true},
		{http.StatusUnauthorized, "unknown", 4, false},
		{http.StatusInternalServerError, "unknown", 4, false},
	}
	for _, c := range cases {
		e := doctorEnv(t, func(s *pvefake.VMREST) { s.ClusterNodesStatus = c.status })
		r := e.doctor("--vmid", "691")
		if r.code != c.exit {
			t.Errorf("member list %d: exit %d, want %d: %s", c.status, r.code, c.exit, r.stdout)
		}
		if got := r.rows()[rowCluster]["verdict"]; got != c.want {
			t.Errorf("member list %d: verdict %v, want %s", c.status, got, c.want)
		}
		if r.has("fix") != c.fix {
			t.Errorf("member list %d: fix present = %v, want %v", c.status, r.has("fix"), c.fix)
		}
	}
}

func TestDoctor_FixCommandIsExactlyTheEnableVerb(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) { s.NodeStatus = http.StatusForbidden })
	r := e.doctor("--vmid", "691")
	if got, want := r.str("fix"), "pveforge acl enable-vm-destroy "+dTarget; got != want {
		t.Errorf("fix = %q, want %q", got, want)
	}
}

// M14: a 403 on the permission read must never read as held.
func TestDoctor_VMRows_PermissionRead403IsUnknown_NotHeld(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) { s.PermissionsStatus = http.StatusForbidden })
	r := e.doctor("--vmid", "691")
	got := verdicts(t, r)
	if got[2] != "unknown" || got[3] != "unknown" {
		t.Fatalf("VM rows with a 403 permission read = %v, want unknown: %s", got, r.stdout)
	}
	if r.code != 4 {
		t.Errorf("exit %d, want 4", r.code)
	}
	if r.has("fix") {
		t.Errorf("a fix command beside an unknown row: %s", r.stdout)
	}
}

func TestDoctor_VMRows_MissingPrivilegeIsMissing_WithNoFix(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) {
		s.Permissions["/vms/691"] = map[string]bool{"VM.PowerMgmt": true}
	})
	r := e.doctor("--vmid", "691")
	got := verdicts(t, r)
	if got[2] != "held" || got[3] != "missing" || r.code != 4 {
		t.Fatalf("verdicts %v exit %d: %s", got, r.code, r.stdout)
	}
	if r.has("fix") {
		t.Errorf("a fix command for a VM row: %s", r.stdout)
	}
}

// M14b: the tree is a hint. A tree that says "held" cannot outvote a 403, and a
// tree that says nothing cannot outvote a 200.
func TestDoctor_TheTreeIsAHint_TheProbeDecides(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) { s.NodeStatus = http.StatusForbidden })
	r := e.doctor("--vmid", "691")
	row := r.rows()[rowNode]
	if row["verdict"] != "missing" || !strings.Contains(row["hint"].(string), "tree: held") {
		t.Fatalf("403 with a tree that says held: %v", row)
	}
	if !strings.Contains(row["hint"].(string), "disagrees") {
		t.Errorf("a disagreement is not shown: %v", row)
	}

	e = doctorEnv(t, func(s *pvefake.VMREST) { delete(s.Permissions, "/nodes/"+dNode) })
	r = e.doctor("--vmid", "691")
	row = r.rows()[rowNode]
	if row["verdict"] != "held" || !strings.Contains(row["hint"].(string), "tree: absent") {
		t.Fatalf("200 with a tree that says absent: %v", row)
	}
}

// "not checked exits 0" and "no-vmid fix command" mutants: both probes 200, no
// --vmid. The run must exit 4, the VM rows must say not checked, no fix, and
// nothing under /vms may have been read.
func TestDoctor_NoVMID_BothProbes200_ExitsFour(t *testing.T) {
	e := doctorEnv(t, nil)
	r := e.doctor()
	if r.code != 4 {
		t.Fatalf("exit %d, want 4: %s %s", r.code, r.stdout, r.stderr)
	}
	rows := r.rows()
	if rows[rowNode]["verdict"] != "held" || rows[rowCluster]["verdict"] != "held" {
		t.Fatalf("the two probes were 200 and must be held: %s", r.stdout)
	}
	n := 0
	for k, row := range rows {
		if strings.HasPrefix(k, "VM.") {
			n++
			if row["verdict"] != "not checked" {
				t.Errorf("%s = %v, want not checked", k, row["verdict"])
			}
		}
	}
	if n != 2 {
		t.Errorf("%d VM rows, want 2: %s", n, r.stdout)
	}
	if r.has("fix") {
		t.Errorf("a fix command for an unchecked run: %s", r.stdout)
	}
	for _, q := range e.s.Requests() {
		if strings.Contains(q, "/vms/") {
			t.Errorf("read a VM path without --vmid: %s", q)
		}
	}
	if !strings.Contains(r.stderr, "--vmid") {
		t.Errorf("the refusal does not tell the operator to pass --vmid: %q", r.stderr)
	}
}

func TestDoctor_NoSecretAndNoPVEBodyInAnyOutput(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) {
		s.NodeStatus = http.StatusUnauthorized
		s.ClusterNodesStatus = http.StatusUnauthorized
	})
	r := e.doctor("--vmid", "691")
	if r.code != 4 {
		t.Fatalf("exit %d, want 4", r.code)
	}
	for _, out := range []string{r.stdout, r.stderr} {
		for _, bad := range []string{"test-secret", rosterPassphrase, doctorBody, "Authorization", "PVEAPIToken"} {
			if strings.Contains(out, bad) {
				t.Errorf("output contains %q:\n%s", bad, out)
			}
		}
	}
}

func TestDoctor_VMIDMustBeCanonical_ExitsOneBeforeAnyContact(t *testing.T) {
	e := doctorEnv(t, nil)
	r := e.doctor("--vmid", "0100")
	if r.code != 1 || len(e.s.Requests()) != 0 {
		t.Errorf("exit %d with %d requests, want 1 and 0", r.code, len(e.s.Requests()))
	}
}

func TestDoctor_IsSafeTier(t *testing.T) {
	cmd := newDoctorCmd()
	if got := cmd.Annotations[mutationAnnotationKey]; got != mutationSafe {
		t.Errorf("doctor tier = %q, want %q", got, mutationSafe)
	}
}

// The exit-4 entry in the README's Exit status table and the PRD's Exit status
// bullet must name `doctor` and its remedy. The README's table is already held
// to runRoot's constants; this holds the PROSE of the 4 row, and the PRD's, to
// the one thing the constants cannot say: which command exits 4 here, and what
// to do about it.
func TestDoctor_ExitFourIsDocumentedWithItsRemedy(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, l := range strings.Split(string(readme), "\n") {
		if strings.HasPrefix(l, "| `4` |") {
			row = l
		}
	}
	if row == "" {
		t.Fatal("README's Exit status table has no `4` row")
	}
	prd, err := os.ReadFile(prdPath)
	if err != nil {
		t.Fatal(err)
	}
	_, bullet, ok := strings.Cut(string(prd), "- **Exit status.**")
	if !ok {
		t.Fatal("PRD has no Exit status bullet")
	}
	bullet, _, _ = strings.Cut(bullet, "\n- **")
	bullet = strings.Join(strings.Fields(bullet), " ")
	for name, text := range map[string]string{"README exit 4 row": row, "PRD exit status bullet": bullet} {
		for _, must := range []string{"`doctor`", "--vmid", "grant what is missing"} {
			if !strings.Contains(text, must) {
				t.Errorf("%s does not contain %q:\n%s", name, must, text)
			}
		}
	}
}

// A PVE error body planted on the member-list read must reach neither stream:
// doctor names the failed read, never PVE's text. ClusterNodes' own Detail
// carries the error text for a non-403, so a report that printed it would leak.
func TestDoctor_AMemberListErrorBodyIsNeverPrinted(t *testing.T) {
	const marker = "MEMBER-LIST-BODY-7731"
	e := doctorEnv(t, func(s *pvefake.VMREST) {
		s.Script = map[string][]pvefake.Reply{
			"GET /cluster/config/nodes": {{Code: http.StatusInternalServerError, Message: marker}},
		}
	})
	r := e.doctor("--vmid", "691")
	// Control: the planted failure was delivered and judged unknown.
	if r.code != 4 || r.rows()[rowCluster]["verdict"] != "unknown" {
		t.Fatalf("the planted 500 did not arrive as unknown/exit 4: exit %d, %s", r.code, r.stdout)
	}
	if e.s.Count("GET", "/api2/json/cluster/config/nodes") < 1 {
		t.Fatal("the member-list read was never made")
	}
	for name, out := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
		if strings.Contains(out, marker) {
			t.Errorf("%s carries the PVE body:\n%s", name, out)
		}
	}
}

// VM.PowerMgmt and VM.Allocate at /vms/<id> with propagate flag 0 are HELD.
// PVE's check on DELETE /nodes/<n>/qemu/<id> and POST .../status/stop tests the
// privilege's DEFINEDNESS after roles() (RPCEnvironment.pm permissions; a
// privilege that arrives only through a pool role is merged with flag 0 by
// compile_acl_path, lines 115-118, and is still defined), never its propagate
// flag. Doctor's tree read therefore keys on presence, not on the flag. This
// fixture pins that no behaviour change creeps in: a reader that required the
// flag would call these missing while destroy would pass.
func TestDoctor_VMRows_PropagateFlagZeroIsHeld(t *testing.T) {
	e := doctorEnv(t, func(s *pvefake.VMREST) {
		s.Permissions["/vms/691"] = map[string]bool{"VM.PowerMgmt": false, "VM.Allocate": false}
	})
	r := e.doctor("--vmid", "691")
	if got := verdicts(t, r); got != [4]string{"held", "held", "held", "held"} || r.code != 0 {
		t.Fatalf("flag-0 VM privileges: verdicts %v exit %d: %s", got, r.code, r.stdout)
	}
}
